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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "babeld.h"
#include "kernel.h"
#include "interface.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "xroute.h"
#include "util.h"
#include "configuration.h"
#include "local.h"

struct xroute *xroutes;
static int numxroutes = 0;
static struct xroute dummy;

static const int keylen =  offsetof(struct xroute, src_prefix)
             /* last key field offset */
             + sizeof(dummy.src_prefix)      /* size of last key field */
             - offsetof(struct xroute,plen); /* offset of first key field */

struct xroute *
find_xroute(const unsigned char *prefix, unsigned char plen,
            const unsigned char *src_prefix, unsigned char src_plen)
{
    struct xroute *result;
    struct xroute r;
    /* Not having datum support complicates this */
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

    HASH_FIND( hh, xroutes, &r.plen, keylen, result);
    return result;
}

void
flush_xroute(struct xroute *xroute)
{
    local_notify_xroute(xroute, LOCAL_FLUSH);
    HASH_DEL(xroutes, xroute);
    numxroutes--;
}

int
add_xroute(unsigned char prefix[16], unsigned char plen,
           unsigned char src_prefix[16], unsigned char src_plen,
           unsigned short metric, unsigned int ifindex, int proto)
{
    struct xroute *r;
    struct xroute *xroute = find_xroute(prefix, plen, src_prefix, src_plen);
    if(xroute) {
        if(xroute->metric <= metric)
            return 0;
        xroute->metric = metric;
        local_notify_xroute(xroute, LOCAL_CHANGE);
        return 1;
    }

    r = calloc(1,sizeof(struct xroute));
    if(!r) return 0;
   
    memcpy(&r->prefix, prefix, 16);
    r->plen = plen;
    memcpy(&r->src_prefix, src_prefix, 16);
    r->src_plen = src_plen;
    r->metric = metric;
    r->ifindex = ifindex;
    r->proto = proto;
    HASH_ADD(hh, xroutes, plen, keylen, r);
    numxroutes++;
    local_notify_xroute(r, LOCAL_ADD);
    return 1;
}

/* Returns an overestimate of the number of xroutes. */
int
xroutes_estimate()
{
    return numxroutes;
}

static int
filter_route(struct kernel_route *route, void *data) {
    void **args = (void**)data;
    int maxroutes = *(int*)args[0];
    struct kernel_route *routes = (struct kernel_route *)args[1];
    int *found = (int*)args[2];

    if(*found >= maxroutes)
        return -1;

    if(martian_prefix(route->prefix, route->plen) ||
       martian_prefix(route->src_prefix, route->src_plen))
        return 0;

    routes[*found] = *route;
    ++ *found;

    return 0;
}

static int
kernel_routes(struct kernel_route *routes, int maxroutes)
{
    int found = 0;
    void *data[3] = { &maxroutes, routes, &found };
    struct kernel_filter filter = {0};
    filter.route = filter_route;
    filter.route_closure = data;

    kernel_dump(CHANGE_ROUTE, &filter);

    return found;
}

static int
filter_address(struct kernel_addr *addr, void *data) {
    void **args = (void **)data;
    int maxroutes = *(int *)args[0];
    struct kernel_route *routes = (struct kernel_route*)args[1];
    int *found = (int *)args[2];
    int ifindex = *(int*)args[3];
    int ll = args[4] ? !!*(int*)args[4] : 0;
    struct kernel_route *route = NULL;

    if(*found >= maxroutes)
        return 0;

    if(ll == !IN6_IS_ADDR_LINKLOCAL(&addr->addr))
        return 0;

    /* ifindex may be 0 -- see kernel_addresses */
    if(ifindex && addr->ifindex != ifindex)
        return 0;

    route = &routes[*found];
    memcpy(route->prefix, addr->addr.s6_addr, 16);
    route->plen = 128;
    route->metric = 0;
    route->ifindex = addr->ifindex;
    route->proto = RTPROT_BABEL_LOCAL;
    memset(route->gw, 0, 16);
    ++ *found;

    return 1;
}

/* ifindex is 0 for all interfaces.  ll indicates whether we are
   interested in link-local or global addresses. */
int
kernel_addresses(int ifindex, int ll, struct kernel_route *routes,
                 int maxroutes)
{
    int found = 0;
    void *data[5] = { &maxroutes, routes, &found, &ifindex, &ll };
    struct kernel_filter filter = {0};
    filter.addr = filter_address;
    filter.addr_closure = data;

    kernel_dump(CHANGE_ADDR, &filter);

    return found;
}

int
check_xroutes(int send_updates)
{
    int i, j, metric, export, change = 0, rc;
    struct kernel_route *routes;
    struct filter_result filter_result;
    int numroutes, numaddresses;
    struct xroute *xroute, *tmp;
    static int maxroutes = 8;
    const int maxmaxroutes = 256 * 1024;

    debugf("\nChecking kernel routes.\n");

 again:
    routes = calloc(maxroutes, sizeof(struct kernel_route));
    if(routes == NULL)
        return -1;

    rc = kernel_addresses(0, 0, routes, maxroutes);
    if(rc < 0) {
        perror("kernel_addresses");
        numroutes = 0;
    } else {
        numroutes = rc;
    }

    if(numroutes >= maxroutes)
        goto resize;

    numaddresses = numroutes;

    rc = kernel_routes(routes + numroutes, maxroutes - numroutes);
    if(rc < 0)
        fprintf(stderr, "Couldn't get kernel routes.\n");
    else
        numroutes += rc;

    if(numroutes >= maxroutes)
        goto resize;

    /* Apply filter to kernel routes (e.g. change the source prefix). */

    for(i = numaddresses; i < numroutes; i++) {
        redistribute_filter(routes[i].prefix, routes[i].plen,
                            routes[i].src_prefix, routes[i].src_plen,
                            routes[i].ifindex, routes[i].proto,
                            &filter_result);
        if(filter_result.src_prefix) {
            memcpy(routes[i].src_prefix, filter_result.src_prefix, 16);
            routes[i].src_plen = filter_result.src_plen;
        }

    }

    /* Check for any routes that need to be flushed */

    HASH_ITER(hh, xroutes, xroute, tmp) {
        export = 0;
        metric = redistribute_filter(xroute->prefix, xroute->plen,
                                     xroute->src_prefix, xroute->src_plen,
                                     xroute->ifindex, xroute->proto,
                                     NULL);
        if(metric < INFINITY && metric == xroute->metric) {
	  /* FIXME this is our nlogn bad boy. Which we can't fix yet,
	     cause we have to hash everything */
	        for(j = 0; j < numroutes; j++) {
                if(xroute->plen == routes[j].plen &&
                   memcmp(&xroute->prefix, routes[j].prefix, 16) == 0 &&
                   xroute->ifindex == routes[j].ifindex &&
                   xroute->proto == routes[j].proto) {
                    export = 1;
                    break;
                }
            }
        }

        if(!export) {
            unsigned char prefix[16], plen;
            unsigned char src_prefix[16], src_plen;
            struct babel_route *route;
            memcpy(prefix, &xroute->prefix, 16);
            plen = xroute->plen;
            memcpy(src_prefix, &xroute->src_prefix, 16);
            src_plen = xroute->src_plen;
            flush_xroute(xroute);
            route = find_best_route(prefix, plen, src_prefix, src_plen, 1,NULL);
            if(route)
                install_route(route);
            /* send_update_resend only records the prefix, so the update
               will only be sent after we perform all of the changes. */
            if(send_updates)
                send_update_resend(NULL, prefix, plen, src_prefix, src_plen);
            change = 1;
        } else {
	  i++; // I am confuzzled here. Do we keep matching?
        }
    }

    /* Add any new routes */

    for(i = 0; i < numroutes; i++) {
        if(martian_prefix(routes[i].prefix, routes[i].plen))
            continue;
        metric = redistribute_filter(routes[i].prefix, routes[i].plen,
                                     routes[i].src_prefix, routes[i].src_plen,
                                     routes[i].ifindex, routes[i].proto, NULL);
        if(metric < INFINITY) {
            rc = add_xroute(routes[i].prefix, routes[i].plen,
                            routes[i].src_prefix, routes[i].src_plen,
                            metric, routes[i].ifindex, routes[i].proto);
            if(rc > 0) {
                struct babel_route *route;
                route = find_installed_route(routes[i].prefix, routes[i].plen,
                                             routes[i].src_prefix,
                                             routes[i].src_plen);
                if(route) {
                    if(allow_duplicates < 0 ||
                       routes[i].metric < allow_duplicates)
                        uninstall_route(route);
                }
                change = 1;
                if(send_updates)
                    send_update(NULL, 0, routes[i].prefix, routes[i].plen,
                                routes[i].src_prefix, routes[i].src_plen);
            }
        }
    }

    free(routes);
    /* Set up maxroutes for the next call. */
    maxroutes = MIN(numroutes + 8, maxmaxroutes);
    return change;

 resize:
    free(routes);
    if(maxroutes >= maxmaxroutes)
        return -1;
    maxroutes = MIN(maxmaxroutes, 2 * maxroutes);
    goto again;
}
