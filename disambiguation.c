/*
Copyright (c) 2014 by Matthieu Boutier and Juliusz Chroboczek.

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
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "babeld.h"
#include "util.h"
#include "interface.h"
#include "kernel.h"
#include "route.h"
#include "source.h"
#include "neighbour.h"
#include "rule.h"
#include "disambiguation.h"

struct zone {
    const unsigned char *dst_prefix;
    unsigned char dst_plen;
    const unsigned char *src_prefix;
    unsigned char src_plen;
};

/* This function assumes rt1 and rt2 non disjoint. */
static int
rt_cmp(const struct babel_route *rt1, const struct babel_route *rt2)
{
    enum prefix_status dst_st, src_st;
    const struct datum *r1 = &rt1->src->dt, *r2 = &rt2->src->dt;
    dst_st = prefix_cmp(r1->prefix, r1->plen, r2->prefix, r2->plen);
    if(dst_st == PST_MORE_SPECIFIC)
        return -1;
    else if(dst_st == PST_LESS_SPECIFIC)
        return 1;
    src_st = prefix_cmp(r1->src_prefix, r1->src_plen,
                        r2->src_prefix, r2->src_plen);
    if(src_st == PST_MORE_SPECIFIC)
        return -1;
    else if(src_st == PST_LESS_SPECIFIC)
        return 1;
    return 0;
}

static const struct babel_route *
min_route(const struct babel_route *r1, const struct babel_route *r2)
{
    int rc;
    if(!r1) return r2;
    if(!r2) return r1;
    rc = rt_cmp(r1, r2);
    return rc <= 0 ? r1 : r2;
}

static int
conflicts(const struct babel_route *rt, const struct babel_route *rt1)
{
    enum prefix_status dst_st, src_st;
    const struct datum *r = &rt->src->dt, *r1 = &rt1->src->dt;
    dst_st = prefix_cmp(r->prefix, r->plen, r1->prefix, r1->plen);
    if(dst_st == PST_DISJOINT || dst_st == PST_EQUALS)
        return 0;
    src_st = prefix_cmp(r->src_prefix, r->src_plen,
                        r1->src_prefix, r1->src_plen);
    return ((dst_st == PST_LESS_SPECIFIC && src_st == PST_MORE_SPECIFIC) ||
            (dst_st == PST_MORE_SPECIFIC && src_st == PST_LESS_SPECIFIC));
}

static const struct zone*
to_zone(const struct babel_route *rt, struct zone *zone)
{
    zone->dst_prefix = rt->src->dt.prefix;
    zone->dst_plen = rt->src->dt.plen;
    zone->src_prefix = rt->src->dt.src_prefix;
    zone->src_plen = rt->src->dt.src_plen;
    return zone;
}

/* fill zone with rt cap rt1, and returns a pointer to zone, or NULL if the
   intersection is empty. */
static const struct zone*
inter(const struct babel_route *rt, const struct babel_route *rt1,
      struct zone *zone)
{
    enum prefix_status dst_st, src_st;
    const struct datum *r = &rt->src->dt, *r1 = &rt1->src->dt;
    dst_st = prefix_cmp(r->prefix, r->plen, r1->prefix, r1->plen);
    if(dst_st == PST_DISJOINT)
        return NULL;
    src_st = prefix_cmp(r->src_prefix, r->src_plen,
                        r1->src_prefix, r1->src_plen);
    if(src_st == PST_DISJOINT)
        return NULL;
    if(dst_st == PST_MORE_SPECIFIC || dst_st == PST_EQUALS) {
        zone->dst_prefix = r->prefix;
        zone->dst_plen = r->plen;
    } else {
        zone->dst_prefix = r1->prefix;
        zone->dst_plen = r1->plen;
    }
    if(src_st == PST_MORE_SPECIFIC || src_st == PST_EQUALS) {
        zone->src_prefix = r->src_prefix;
        zone->src_plen = r->src_plen;
    } else {
        zone->src_prefix = r1->src_prefix;
        zone->src_plen = r1->src_plen;
    }
    return zone;
}

static int
zone_equal(const struct zone *z1, const struct zone *z2)
{
    return z1 && z2 && z1->dst_plen == z2->dst_plen &&
        memcmp(z1->dst_prefix, z2->dst_prefix, 16) == 0 &&
        z1->src_plen == z2->src_plen &&
        memcmp(z1->src_prefix, z2->src_prefix, 16) == 0;
}

static const struct babel_route *
min_conflict(const struct zone *zone, const struct babel_route *rt)
{
    struct babel_route *rt1 = NULL;
    const struct babel_route *min = NULL;
    struct route_stream *stream = NULL;
    struct zone curr_zone;
    stream = route_stream(ROUTE_INSTALLED);
    if(!stream) {
        fprintf(stderr, "Couldn't allocate route stream.\n");
        return NULL;
    }
    while(1) {
        rt1 = route_stream_next(stream);
        if(rt1 == NULL) break;
        if(!(conflicts(rt, rt1) &&
             zone_equal(inter(rt, rt1, &curr_zone), zone)))
            continue;
        min = min_route(rt1, min);
    }
    route_stream_done(stream);
    return min;
}

static const struct babel_route *
conflict_solution(const struct babel_route *rt)
{
    const struct babel_route *rt1 = NULL, *rt2 = NULL;
    struct route_stream *stream1 = NULL;
    struct route_stream *stream2 = NULL;
    const struct babel_route *min = NULL; /* == solution */
    struct zone zone;
    struct zone tmp;
    /* Having a conflict requires at least one specific route. */
    stream1 = route_stream(ROUTE_SS_INSTALLED);
    if(!stream1) {
        return NULL;
    }
    while(1) {
        rt1 = route_stream_next(stream1);
        if(rt1 == NULL) break;

        stream2 = route_stream(ROUTE_INSTALLED);
        if(!stream2) {
            route_stream_done(stream1);
            fprintf(stderr, "Couldn't allocate route stream.\n");
            return NULL;
        }

        while(1) {
            rt2 = route_stream_next(stream2);
            if(rt2 == NULL) break;
            if(!(conflicts(rt1, rt2) &&
                 zone_equal(inter(rt1, rt2, &tmp), to_zone(rt, &zone)) &&
                 rt_cmp(rt1, rt2) < 0))
                continue;
            min = min_route(rt1, min);
        }
        route_stream_done(stream2);
    }
    route_stream_done(stream1);
    return min;
}

static int
is_installed(struct zone *zone)
{
    struct datum dt;
    memcpy(dt.prefix, zone->dst_prefix, 16);
    dt.plen = zone->dst_plen;
    memcpy(dt.src_prefix, zone->src_prefix, 16);
    dt.src_plen = zone->src_plen;
    return zone != NULL && find_installed_route(&dt) != NULL;
}

static int
kernel_route_add(const struct zone *zone, const struct babel_route *route)
{
    int table = find_table(zone->dst_prefix, zone->dst_plen,
                           zone->src_prefix, zone->src_plen);
    return kernel_route(ROUTE_ADD, table, zone->dst_prefix, zone->dst_plen,
                        zone->src_prefix, zone->src_plen,
                        route->nexthop,
                        route->neigh->ifp->ifindex,
                        metric_to_kernel(route_metric(route)), NULL, 0, 0, 0);
}

static int
kernel_route_flush(const struct zone *zone, const struct babel_route *route)
{
    int table = find_table(zone->dst_prefix, zone->dst_plen,
                           zone->src_prefix, zone->src_plen);
    return kernel_route(ROUTE_FLUSH, table, zone->dst_prefix, zone->dst_plen,
                        zone->src_prefix, zone->src_plen,
                        route->nexthop,
                        route->neigh->ifp->ifindex,
                        metric_to_kernel(route_metric(route)), NULL, 0, 0, 0);
}

static int
kernel_route_modify(const struct zone *zone, const struct babel_route *old,
                    const struct babel_route *new)
{
    int table = find_table(zone->dst_prefix, zone->dst_plen,
                           zone->src_prefix, zone->src_plen);
    return kernel_route(ROUTE_MODIFY, table, zone->dst_prefix, zone->dst_plen,
                        zone->src_prefix, zone->src_plen,
                        old->nexthop, old->neigh->ifp->ifindex,
                        metric_to_kernel(route_metric(old)),
                        new->nexthop, new->neigh->ifp->ifindex,
                        metric_to_kernel(route_metric(new)), table);
}

static int
kernel_route_modify_metric(const struct zone *zone,
                           const struct babel_route *route,
                           int old_metric, int new_metric)
{
    int table = find_table(zone->dst_prefix, zone->dst_plen,
                           zone->src_prefix, zone->src_plen);
    return kernel_route(ROUTE_MODIFY, table, zone->dst_prefix, zone->dst_plen,
                        zone->src_prefix, zone->src_plen,
                        route->nexthop, route->neigh->ifp->ifindex,
                        old_metric,
                        route->nexthop, route->neigh->ifp->ifindex,
                        new_metric, table);
}

static int
not_any_specific_route(void) {
    struct route_stream *stream = NULL;
    int no_route;
    stream = route_stream(ROUTE_SS_INSTALLED);
    if(!stream) {
        fprintf(stderr, "Couldn't allocate route stream.\n");
        return -1;
    }
    no_route = (route_stream_next(stream) != NULL);
    route_stream_done(stream);
    return no_route;
}

int
disambiguate_install(const struct babel_route *route)
{
    int rc;
    struct zone zone;
    const struct babel_route *rt1 = NULL;
    const struct babel_route *rt2 = NULL;
    struct route_stream *stream = NULL;
    int v4 = v4mapped(route->nexthop);

    debugf("install_route(%s from %s)\n",
           format_prefix(route->src->dt.prefix, route->src->dt.plen),
           format_prefix(route->src->dt.src_prefix, route->src->dt.src_plen));
    if(kernel_disambiguate(v4) ||
       (is_default(route->src->dt.src_prefix, route->src->dt.src_plen) &&
        not_any_specific_route())) {
        /* no disambiguation */
        to_zone(route, &zone);
        rc = kernel_route_add(&zone, route);
        goto end;
    }

    /* Install completion routes */
    stream = route_stream(ROUTE_INSTALLED);
    if(!stream) {
        fprintf(stderr, "Couldn't allocate route stream.\n");
        return -1;
    }
    while(1) {
        rt1 = route_stream_next(stream);
        if(rt1 == NULL) break;

        inter(route, rt1, &zone);
        if(!(conflicts(route, rt1) &&
             !is_installed(&zone) &&
             rt_cmp(rt1, min_conflict(&zone, route)) == 0))
            continue;
        rt2 = min_conflict(&zone, rt1);
        if(rt2 == NULL)
            kernel_route_add(&zone, min_route(route, rt1));
        else if(rt_cmp(route, rt2) < 0 && rt_cmp(route, rt1) < 0)
            kernel_route_modify(&zone, rt2, route);
    }
    route_stream_done(stream);

    /* Install the route, or change if the route solve a conflict. */
    to_zone(route, &zone);
    rt1 = conflict_solution(route);
    if(rt1 == NULL)
        rc = kernel_route_add(&zone, route);
    else
        rc = kernel_route_modify(&zone, rt1, route);
 end:
    if(rc < 0) {
        int save = errno;
        fprintf(stderr, "kernel_route(ADD %s from %s dev %u metric %u): %s\n",
                format_prefix(route->src->dt.prefix, route->src->dt.plen),
                format_prefix(route->src->dt.src_prefix,
                              route->src->dt.src_plen),
                route->neigh->ifp->ifindex,
                metric_to_kernel(route_metric(route)), strerror(errno));
        if(save != EEXIST)
            return -1;
    }
    return 0;
}

int
disambiguate_uninstall(const struct babel_route *route)
{
    int rc;
    struct zone zone;
    const struct babel_route *rt1 = NULL, *rt2 = NULL;
    struct route_stream *stream = NULL;
    int v4 = v4mapped(route->nexthop);

    debugf("uninstall_route(%s from %s)\n",
           format_prefix(route->src->dt.prefix, route->src->dt.plen),
           format_prefix(route->src->dt.src_prefix, route->src->dt.src_plen));
    to_zone(route, &zone);
    if(kernel_disambiguate(v4) ||
       (is_default(route->src->dt.src_prefix, route->src->dt.src_plen) &&
        not_any_specific_route())) {
        /* no disambiguation */
        rc = kernel_route_flush(&zone, route);
        if(rc < 0)
            fprintf(stderr,
                    "kernel_route(FLUSH %s from %s dev %u metric %u): %s\n",
                    format_prefix(route->src->dt.prefix, route->src->dt.plen),
                    format_prefix(route->src->dt.src_prefix,
                                  route->src->dt.src_plen),
                    route->neigh->ifp->ifindex,
                    metric_to_kernel(route_metric(route)), strerror(errno));
        return rc;
    }
    /* Remove the route, or change if the route was solving a conflict. */
    rt1 = conflict_solution(route);
    if(rt1 == NULL)
        rc = kernel_route_flush(&zone, route);
    else
        rc = kernel_route_modify(&zone, route, rt1);
    if(rc < 0)
        fprintf(stderr, "kernel_route(FLUSH %s from %s dev %u metric %u): %s\n",
                format_prefix(route->src->dt.prefix, route->src->dt.plen),
                format_prefix(route->src->dt.src_prefix,
                              route->src->dt.src_plen),
                route->neigh->ifp->ifindex,
                metric_to_kernel(route_metric(route)), strerror(errno));

    /* Remove completion routes */
    stream = route_stream(ROUTE_INSTALLED);
    if(!stream) {
        fprintf(stderr, "Couldn't allocate route stream.\n");
        return -1;
    }
    while(1) {
        rt1 = route_stream_next(stream);
        if(rt1 == NULL) break;

        inter(route, rt1, &zone);
        if(!(conflicts(route, rt1) &&
             !is_installed(&zone) &&
             rt_cmp(rt1, min_conflict(&zone, route)) == 0))
            continue;
        rt2 = min_conflict(&zone, rt1);
        if(rt2 == NULL)
            kernel_route_flush(&zone, min_route(route, rt1));
        else if(rt_cmp(route, rt2) < 0 && rt_cmp(route, rt1) < 0)
            kernel_route_modify(&zone, route, rt2);
    }
    route_stream_done(stream);

    return rc;
}

int
disambiguate_switch(const struct babel_route *old, const struct babel_route *new)
{
    int rc;
    struct zone zone;
    struct babel_route *rt1 = NULL;
    struct route_stream *stream = NULL;

    debugf("switch_routes(%s from %s)\n",
           format_prefix(old->src->dt.prefix, old->src->dt.plen),
           format_prefix(old->src->dt.src_prefix, old->src->dt.src_plen));
    to_zone(old, &zone);
    rc = kernel_route_modify(&zone, old, new);
    if(rc < 0) {
        fprintf(stderr, "kernel_route(MODIFY %s from %s dev %u metric %u "
                "TO %s from %s dev %u metric %u): %s\n",
                format_prefix(old->src->dt.prefix, old->src->dt.plen),
                format_prefix(old->src->dt.src_prefix,
                              old->src->dt.src_plen),
                old->neigh->ifp->ifindex, metric_to_kernel(route_metric(old)),
                format_prefix(new->src->dt.prefix, new->src->dt.plen),
                format_prefix(new->src->dt.src_prefix,
                              new->src->dt.src_plen),
                new->neigh->ifp->ifindex,
                metric_to_kernel(route_metric(new)), strerror(errno));
        return -1;
    }

    /* switch completion routes */
    if(!kernel_disambiguate(v4mapped(old->nexthop)) &&
       !not_any_specific_route()) {
        stream = route_stream(ROUTE_INSTALLED);
        if(!stream) {
            fprintf(stderr, "Couldn't allocate route stream.\n");
            return -1;
        }
        while(1) {
            rt1 = route_stream_next(stream);
            if(rt1 == NULL) break;

            inter(old, rt1, &zone);
            if(!(conflicts(old, rt1) &&
                 !is_installed(&zone) &&
                 rt_cmp(rt1, min_conflict(&zone, old)) == 0 &&
                 rt_cmp(old, rt1) < 0 &&
                 rt_cmp(old, min_conflict(&zone, rt1)) == 0))
                continue;
            kernel_route_modify(&zone, old, new);
        }
        route_stream_done(stream);
    }

    return rc;
}

int
disambiguate_change_metric(const struct babel_route *route, int old_metric,
                           int new_metric)
{
    int rc;
    struct babel_route *rt1 = NULL;
    struct route_stream *stream = NULL;
    struct zone zone;

    debugf("change_route_metric(%s from %s, %d -> %d)\n",
           format_prefix(route->src->dt.prefix, route->src->dt.plen),
           format_prefix(route->src->dt.src_prefix, route->src->dt.src_plen),
           old_metric, new_metric);
    to_zone(route, &zone);
    rc = kernel_route_modify_metric(&zone, route, old_metric, new_metric);
    if(rc < 0) {
        fprintf(stderr, "kernel_route(MODIFY %s from %s dev %u metric "
                "[%u TO %u]): %s\n",
                format_prefix(route->src->dt.prefix, route->src->dt.plen),
                format_prefix(route->src->dt.src_prefix,
                              route->src->dt.src_plen),
                route->neigh->ifp->ifindex, old_metric, new_metric,
                strerror(errno));
        return -1;
    }

    /* change completion routes metric */
    if(!kernel_disambiguate(v4mapped(route->nexthop)) &&
       !not_any_specific_route()) {
        stream = route_stream(ROUTE_INSTALLED);
        if(!stream) {
            fprintf(stderr, "Couldn't allocate route stream.\n");
            return -1;
        }
        while(1) {
            rt1 = route_stream_next(stream);
            if(rt1 == NULL) break;

            inter(route, rt1, &zone);
            if(!(conflicts(route, rt1) &&
                 !is_installed(&zone) &&
                 rt_cmp(rt1, min_conflict(&zone, route)) == 0 &&
                 rt_cmp(route, rt1) < 0 &&
                 rt_cmp(route, min_conflict(&zone, rt1)) == 0))
                continue;
            kernel_route_modify_metric(&zone, route, old_metric, new_metric);
        }
        route_stream_done(stream);
    }

    return rc;
}
