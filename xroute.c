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
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "xroute.h"
#include "util.h"
#include "configuration.h"
#include "interface.h"
#include "local.h"

static struct xroute *xroutes;
static int numxroutes = 0, maxxroutes = 0;

struct xroute *
find_xroute(const struct datum *dt)
{
    int i;
    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].dt.plen == dt->plen &&
           memcmp(xroutes[i].dt.prefix, dt->prefix, 16) == 0 &&
           xroutes[i].dt.src_plen == dt->src_plen &&
           memcmp(xroutes[i].dt.src_prefix, dt->src_prefix, 16) == 0)
            return &xroutes[i];
    }
    return NULL;
}

void
flush_xroute(struct xroute *xroute)
{
    int i;

    i = xroute - xroutes;
    assert(i >= 0 && i < numxroutes);

    local_notify_xroute(xroute, LOCAL_FLUSH);

    if(i != numxroutes - 1)
        memcpy(xroutes + i, xroutes + numxroutes - 1, sizeof(struct xroute));
    numxroutes--;
    VALGRIND_MAKE_MEM_UNDEFINED(xroutes + numxroutes, sizeof(struct xroute));

    if(numxroutes == 0) {
        free(xroutes);
        xroutes = NULL;
        maxxroutes = 0;
    } else if(maxxroutes > 8 && numxroutes < maxxroutes / 4) {
        struct xroute *new_xroutes;
        int n = maxxroutes / 2;
        new_xroutes = realloc(xroutes, n * sizeof(struct xroute));
        if(new_xroutes == NULL)
            return;
        xroutes = new_xroutes;
        maxxroutes = n;
    }
}

int
add_xroute(struct datum dt, unsigned short metric, unsigned int ifindex,
           int proto)
{
    struct xroute *xroute = find_xroute(&dt);
    if(xroute) {
        if(xroute->metric <= metric)
            return 0;
        xroute->metric = metric;
        local_notify_xroute(xroute, LOCAL_CHANGE);
        return 1;
    }

    if(numxroutes >= maxxroutes) {
        struct xroute *new_xroutes;
        int n = maxxroutes < 1 ? 8 : 2 * maxxroutes;
        new_xroutes = realloc(xroutes, n * sizeof(struct xroute));
        if(new_xroutes == NULL)
            return -1;
        maxxroutes = n;
        xroutes = new_xroutes;
    }

    memcpy(xroutes[numxroutes].dt.prefix, dt.prefix, 16);
    xroutes[numxroutes].dt.plen = dt.plen;
    memcpy(xroutes[numxroutes].dt.src_prefix, dt.src_prefix, 16);
    xroutes[numxroutes].dt.src_plen = dt.src_plen;
    xroutes[numxroutes].metric = metric;
    xroutes[numxroutes].ifindex = ifindex;
    xroutes[numxroutes].proto = proto;
    numxroutes++;
    local_notify_xroute(&xroutes[numxroutes - 1], LOCAL_ADD);
    return 1;
}

/* Returns an overestimate of the number of xroutes. */
int
xroutes_estimate()
{
    return numxroutes;
}

struct xroute_stream {
    int index;
};

struct
xroute_stream *
xroute_stream()
{
    struct xroute_stream *stream = calloc(1, sizeof(struct xroute_stream));
    if(stream == NULL)
        return NULL;

    return stream;
}


struct xroute *
xroute_stream_next(struct xroute_stream *stream)
{
    if(stream->index < numxroutes)
        return &xroutes[stream->index++];
    else
        return NULL;
}

void
xroute_stream_done(struct xroute_stream *stream)
{
    free(stream);
}

static int
filter_route(struct kernel_route *route, void *data) {
    void **args = (void**)data;
    int maxroutes = *(int*)args[0];
    struct kernel_route *routes = (struct kernel_route *)args[1];
    int *found = (int*)args[2];

    if(*found >= maxroutes)
        return -1;

    if(martian_prefix(route->dt.prefix, route->dt.plen) ||
       martian_prefix(route->dt.src_prefix, route->dt.src_plen))
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
    memcpy(route->dt.prefix, addr->addr.s6_addr, 16);
    route->dt.plen = 128;
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
    struct filter_result filter_result = {0};
    int numroutes, numaddresses;
    static int maxroutes = 8;
    const int maxmaxroutes = 16 * 1024;

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
        filter_result.src_prefix = NULL;
        redistribute_filter(&routes[i].dt, routes[i].ifindex, routes[i].proto,
                            &filter_result);
        if(filter_result.src_prefix) {
            memcpy(routes[i].dt.src_prefix, filter_result.src_prefix, 16);
            routes[i].dt.src_plen = filter_result.src_plen;
        }

    }

    /* Check for any routes that need to be flushed */

    i = 0;
    while(i < numxroutes) {
        export = 0;
        metric = redistribute_filter(&xroutes[i].dt, xroutes[i].ifindex,
                                     xroutes[i].proto, NULL);
        if(metric < INFINITY && metric == xroutes[i].metric) {
            for(j = 0; j < numroutes; j++) {
                if(xroutes[i].dt.plen == routes[j].dt.plen &&
                   xroutes[i].dt.src_plen == routes[j].dt.src_plen &&
                   memcmp(xroutes[i].dt.prefix, routes[j].dt.prefix, 16) == 0 &&
                   memcmp(xroutes[i].dt.src_prefix,
                          routes[j].dt.src_prefix, 16) == 0 &&
                   xroutes[i].ifindex == routes[j].ifindex &&
                   xroutes[i].proto == routes[j].proto) {
                    export = 1;
                    break;
                }
            }
        }

        if(!export) {
            struct datum dt;
            struct babel_route *route;
            memcpy(&dt, &xroutes[i].dt, sizeof(struct datum));
            flush_xroute(&xroutes[i]);
            route = find_best_route(&dt, 1,NULL);
            if(route)
                install_route(route);
            /* send_update_resend only records the prefix, so the update
               will only be sent after we perform all of the changes. */
            if(send_updates)
                send_update_resend(NULL, &dt);
            change = 1;
        } else {
            i++;
        }
    }

    /* Add any new routes */

    for(i = 0; i < numroutes; i++) {
        if(martian_prefix(routes[i].dt.prefix, routes[i].dt.plen))
            continue;
        metric = redistribute_filter(&routes[i].dt, routes[i].ifindex,
                                     routes[i].proto, NULL);
        if(metric < INFINITY) {
            rc = add_xroute(routes[i].dt, metric, routes[i].ifindex,
                            routes[i].proto);
            if(rc > 0) {
                struct babel_route *route;
                route = find_installed_route(&routes[i].dt);
                if(route) {
                    if(allow_duplicates < 0 ||
                       routes[i].metric < allow_duplicates)
                        uninstall_route(route);
                }
                change = 1;
                if(send_updates)
                    send_update(NULL, 0, &routes[i].dt, 0);
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
