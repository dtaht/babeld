/*
Copyright (c) 2018 by Clara Dô and Weronika Kolodziejak

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
#include "anm.h"
#include "util.h"
#include "configuration.h"
#include "local.h"

static struct anm *anms;
static int numanms = 0, maxanms = 0;

struct anm *
find_anm(const unsigned char *from, const struct interface *ifp)
{
    int i;
    for(i = 0; i < numanms; i++) {
      if(memcmp(anms[i].from, from, 16) == 0 && anms[i].ifp == ifp)
            return &anms[i];
    }
    return NULL;
}

struct anm *
add_anm(const unsigned char *from, struct interface *ifp,
	unsigned char *last_tspc)
{
    struct anm *anm = find_anm(from, ifp);
    if(anm) {
        memcpy(anm->last_tspc, last_tspc, 6);
        return anm;
    }

    if(numanms >= maxanms) {
        struct anm *new_anms;
        int n = maxanms < 1 ? 8 : 2 * maxanms;
        new_anms = realloc(anms, n * sizeof(struct anm));
        if(new_anms == NULL)
            return NULL;
        maxanms = n;
        anms = new_anms;
    }

    memcpy(anms[numanms].from, from, 16);
    anms[numanms].ifp = ifp;
    memcpy(anms[numanms].last_tspc, last_tspc, 6);
    numanms++;
    return &anms[numanms - 1];
}
