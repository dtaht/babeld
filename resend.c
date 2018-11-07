/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "babeld.h"
#include "util.h"
#include "interface.h"
#include "neighbour.h"
#include "resend.h"
#include "message.h"
#include "configuration.h"
#include "uthash.h"

struct timeval resend_time[2] = {};
struct resend *to_resend[2] = {};

struct resend dummy;

static const int keylen =  offsetof(struct resend, src_prefix)
             /* last key field offset */
             + sizeof(dummy.src_prefix)             /* size of last key field */
             - offsetof(struct resend,plen);  /* offset of first key field */

/* This is called by neigh.c when a neighbour is flushed */

void
flush_resends(struct neighbour *neigh)
{
    /* Nothing for now */
}

static struct resend *
find_resend(int kind, const unsigned char *prefix, unsigned char plen,
            const unsigned char *src_prefix, unsigned char src_plen)
{
    struct resend *result;
    struct resend r;
    /* Not having datum support complicates this */
    r.kind = kind;
    r.plen = plen;
    r.src_plen = src_plen;
    if(prefix == NULL)
        memset(&r.prefix, 0, 16);
    else
        memcpy(&r.prefix, prefix, 16);

    if(src_prefix == NULL)
        memset(&r.src_prefix, 0, 16);
    else
        memcpy(&r.src_prefix, src_prefix, 16);

    HASH_FIND( hh, to_resend[kind], &r.plen, keylen, result);
    return result;
}

struct resend *
find_request(const unsigned char *prefix, unsigned char plen,
             const unsigned char *src_prefix, unsigned char src_plen)
{
    return find_resend(RESEND_REQUEST, prefix, plen, src_prefix, src_plen);
}

int
record_resend(int kind, const unsigned char *prefix, unsigned char plen,
              const unsigned char *src_prefix, unsigned char src_plen,
              unsigned short seqno, const unsigned char *id,
              struct interface *ifp, int delay)
{
    struct resend *resend;
    unsigned int ifindex = ifp ? ifp->ifindex : 0;

    if((kind == RESEND_REQUEST &&
        input_filter(NULL, prefix, plen, src_prefix, src_plen, NULL,
                     ifindex) >=
        INFINITY) ||
       (kind == RESEND_UPDATE &&
        output_filter(NULL, prefix, plen, src_prefix, src_plen, ifindex) >=
        INFINITY))
        return 0;

    if(delay >= 0xFFFF)
        delay = 0xFFFF;

    resend = find_resend(kind, prefix, plen, src_prefix, src_plen);
    if(resend) {
        if(resend->delay && delay)
            resend->delay = MIN(resend->delay, delay);
        else if(delay)
            resend->delay = delay;
        resend->time = now;
        resend->max = RESEND_MAX;
        if(id && memcmp(resend->id, id, 8) == 0 &&
           seqno_compare(resend->seqno, seqno) > 0) {
            return 0;
        }
        if(id)
            memcpy(resend->id, id, 8);
        else
            memset(resend->id, 0, 8);
        resend->seqno = seqno;
        if(resend->ifp != ifp)
            resend->ifp = NULL;
    } else {
        resend = calloc(1, sizeof(struct resend));
        if(resend == NULL)
            return -1;
        resend->kind = kind;
        resend->max = RESEND_MAX;
        resend->delay = delay;
        memcpy(resend->prefix, prefix, 16);
        resend->plen = plen;
        memcpy(resend->src_prefix, src_prefix, 16);
        resend->src_plen = src_plen;
        resend->seqno = seqno;
        if(id)
            memcpy(resend->id, id, 8);
        resend->ifp = ifp;
        resend->time = now;
        HASH_ADD(hh, to_resend[kind], plen, keylen, resend);
    }

    if(resend->delay) {
        struct timeval timeout;
        timeval_add_msec(&timeout, &resend->time, resend->delay);
        timeval_min(&resend_time[kind], &timeout);
    }
    return 1;
}

static int
resend_expired(struct resend *resend)
{
    switch(resend->kind) {
    case RESEND_REQUEST:
        return timeval_minus_msec(&now, &resend->time) >= REQUEST_TIMEOUT;
    default:
        return resend->max <= 0;
    }
}

int
unsatisfied_request(const unsigned char *prefix, unsigned char plen,
                    const unsigned char *src_prefix, unsigned char src_plen,
                    unsigned short seqno, const unsigned char *id)
{
    struct resend *request;

    request = find_request(prefix, plen, src_prefix, src_plen);
    if(request == NULL || resend_expired(request))
        return 0;

    if(memcmp(request->id, id, 8) != 0 ||
       seqno_compare(request->seqno, seqno) <= 0)
        return 1;

    return 0;
}

/* Determine whether a given request should be forwarded. */
int
request_redundant(struct interface *ifp,
                  const unsigned char *prefix, unsigned char plen,
                  const unsigned char *src_prefix, unsigned char src_plen,
                  unsigned short seqno, const unsigned char *id)
{
    struct resend *request;

    request = find_request(prefix, plen, src_prefix, src_plen);
    if(request == NULL || resend_expired(request))
        return 0;

    if(memcmp(request->id, id, 8) == 0 &&
       seqno_compare(request->seqno, seqno) > 0)
        return 0;

    if(request->ifp != NULL && request->ifp != ifp)
        return 0;

    if(request->max > 0)
        /* Will be resent. */
        return 1;

    if(timeval_minus_msec(&now, &request->time) <
       (ifp ? MIN(ifp->hello_interval, 1000) : 1000))
        /* Fairly recent. */
        return 1;

    return 0;
}

int
satisfy_request(const unsigned char *prefix, unsigned char plen,
                const unsigned char *src_prefix, unsigned char src_plen,
                unsigned short seqno, const unsigned char *id,
                struct interface *ifp)
{
    struct resend *request = find_request(prefix, plen, src_prefix, src_plen);
    if(request == NULL)
        return 0;

    if(ifp != NULL && request->ifp != ifp)
        return 0;

    if(memcmp(request->id, id, 8) != 0 ||
       seqno_compare(request->seqno, seqno) <= 0) {
        /* We cannot remove the request, as we may be walking the list right
           now.  Mark it as expired, so that expire_resend will remove it. */
        request->max = 0;
        request->time.tv_sec = 0;
        recompute_resend_time(request->kind); // ouch!!!!
        return 1;
    }

    return 0;
}

void
expire_resend()
{
    int recompute = 0;
    struct resend *request, *tmp;
    for(int i = 0; i < 2; i++) {
    HASH_ITER(hh, to_resend[i], request, tmp) {
        if(resend_expired(request)) {
		HASH_DEL(to_resend[i], request);
		free (request);
             	recompute++;
             }
       }
    if(recompute) {
	fprintf(stderr,"Bulk Expired %d routes\n", recompute);
	recompute_resend_time(i);
	}
    }
}

void
recompute_resend_time(int kind)
{
    struct timeval resend = {0, 0};
    struct resend *request, *tmp;

    HASH_ITER(hh, to_resend[kind], request, tmp) {
       if(!resend_expired(request) && request->delay > 0 && request->max > 0) {
          struct timeval timeout;
          timeval_add_msec(&timeout, &request->time, request->delay);
          timeval_min(&resend, &timeout);
      }
    }
    resend_time[kind] = resend;
}

void
do_resend(int kind)
{
    struct resend *resend, *tmp;
    int recompute = 0;

    HASH_ITER(hh, to_resend[kind], resend, tmp) {
        if(!resend_expired(resend) && resend->delay > 0 && resend->max > 0) {
            struct timeval timeout;
            timeval_add_msec(&timeout, &resend->time, resend->delay);
            if(timeval_compare(&now, &timeout) >= 0) {
                switch(resend->kind) {
                case RESEND_REQUEST:
                    send_multicast_multihop_request(resend->ifp,
                                                    resend->prefix, resend->plen,
                                                    resend->src_prefix,
                                                    resend->src_plen,
                                                    resend->seqno, resend->id,
                                                    127);
                    break;
                case RESEND_UPDATE:
                    send_update(resend->ifp, 1,
                                resend->prefix, resend->plen,
                                resend->src_prefix, resend->src_plen);
                    break;
                default: abort();
                }
                resend->delay = MIN(0xFFFF, resend->delay * 2);
                resend->max--;
            }
	}
        if(resend_expired(resend)) {
	    HASH_DEL(to_resend[kind], resend);
	    free (resend);
	    recompute++;
        }
    }

    if(recompute) {
        fprintf(stderr,"Expired %d routes during do_resend\n", recompute);
    }
    recompute_resend_time(kind);
}
