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

#define DO_NTOHS(_d, _s) \
    do { unsigned short _dd; \
         memcpy(&(_dd), (_s), 2); \
         _d = ntohs(_dd); } while(0)
#define DO_NTOHL(_d, _s) \
    do { unsigned int _dd; \
         memcpy(&(_dd), (_s), 4); \
         _d = ntohl(_dd); } while(0)
#define DO_HTONS(_d, _s) \
    do { unsigned short _dd; \
         _dd = htons(_s); \
         memcpy((_d), &(_dd), 2); } while(0)
#define DO_HTONL(_d, _s) \
    do { unsigned _dd; \
         _dd = htonl(_s); \
         memcpy((_d), &(_dd), 4); } while(0)

static inline int
seqno_compare(unsigned short s1, unsigned short s2)
{
    if(s1 == s2)
        return 0;
    else
        return ((s2 - s1) & 0x8000) ? 1 : -1;
}

static inline short
seqno_minus(unsigned short s1, unsigned short s2)
{
    return (short)((s1 - s2) & 0xFFFF);
}

static inline unsigned short
seqno_plus(unsigned short s, int plus)
{
    return ((s + plus) & 0xFFFF);
}

/* Returns a time in microseconds on 32 bits (thus modulo 2^32,
   i.e. about 4295 seconds). */
static inline unsigned int
time_us(const struct timeval t)
{
    return (unsigned int) (t.tv_sec * 1000000 + t.tv_usec);
}

int roughly(int value);
void timeval_minus(struct timeval *d,
                   const struct timeval *s1, const struct timeval *s2);
unsigned timeval_minus_msec(const struct timeval *s1, const struct timeval *s2)
    ATTRIBUTE ((pure));
void timeval_add_msec(struct timeval *d,
                      const struct timeval *s, int msecs);
int timeval_compare(const struct timeval *s1, const struct timeval *s2)
    ATTRIBUTE ((pure));
void timeval_min(struct timeval *d, const struct timeval *s);
void timeval_min_sec(struct timeval *d, time_t secs);
int parse_nat(const char *string) ATTRIBUTE ((pure));
int parse_thousands(const char *string) ATTRIBUTE ((pure));
void do_debugf(int level, const char *format, ...)
    ATTRIBUTE ((format (printf, 2, 3))) COLD;
int in_prefix(const unsigned char *restrict address,
              const unsigned char *restrict prefix, unsigned char plen)
    ATTRIBUTE ((pure));
unsigned char *normalize_prefix(unsigned char *restrict ret,
                                const unsigned char *restrict prefix,
                                unsigned char plen);
const char *format_address(const unsigned char *address);
const char *format_prefix(const unsigned char *address, unsigned char prefix);
const char *format_eui64(const unsigned char *eui);
const char *format_thousands(unsigned int value);
int parse_address(const char *address, unsigned char *addr_r, int *af_r);
int parse_net(const char *net, unsigned char *prefix_r, unsigned char *plen_r,
              int *af_r);
int parse_eui64(const char *eui, unsigned char *eui_r);
int wait_for_fd(int direction, int fd, int msecs);
int martian_prefix(const unsigned char *prefix, int plen) ATTRIBUTE ((pure));
void v4tov6(unsigned char *dst, const unsigned char *src);
int daemonise(void);
int set_src_prefix(unsigned char *src_addr, unsigned char *src_plen);

/* Most of the time we only care if things are equal or unequal.
   So we can use xor logic rather than memcmp. The tricky part is
   that C considers any non-zero value to be true and 0 to be false,
   where a simple XOR creates non-zero values for not equal */

extern const unsigned char llprefix[16];
extern const unsigned char v4prefix[16];

#define bool int

#ifdef OLDVERSION
static inline bool xor4(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,4) != 0;
}

static inline bool xnor4(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,4) == 0 ;
}

static inline bool xor12(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,12) != 0;
}

static inline bool xnor12(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,12) == 0;
}

static inline bool xor8(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,8) != 0;
}

static inline bool xnor8(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,8) == 0;
}

static inline bool xor16(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,16) != 0;
}

static inline bool xnor16(const unsigned char *a, const unsigned char *b) {
	return memcmp(a,b,16) == 0;
}
#else

// #define HAVE_64BIT_ARCH 1

static inline bool xor4(const unsigned char *a, const unsigned char *b) {
        const unsigned int *up1 = (const unsigned int *)a;
        const unsigned int *up2 = (const unsigned int *)b;
	return up1[0] ^ up2[0];
}

static inline bool xnor4(const unsigned char *a, const unsigned char *b) {
	return !xor4(a,b);
}

static inline size_t xor16 (const unsigned char *p1,
			    const unsigned char *p2)
{
#ifdef  HAVE_64BIT_ARCH
        const unsigned long *up1 = (const unsigned long *)p1;
        const unsigned long *up2 = (const unsigned long *)p2;

        return ((up1[0] ^ up2[0]) | (up1[1] ^ up2[1]));
#else
        const unsigned int *up1 = (const unsigned int *)p1;
        const unsigned int *up2 = (const unsigned int *)p2;
	return ((up1[0] ^ up2[0]) |
                (up1[1] ^ up2[1]) |
                (up1[2] ^ up2[2]) |
                (up1[3] ^ up2[3]));
#endif
}

static inline size_t xor12 (const unsigned char *p1,
			    const unsigned char *p2)
{
#ifdef  HAVE_64BIT_ARCH
        const unsigned long *up1 = (const unsigned long *)p1;
        const unsigned long *up2 = (const unsigned long *)p2;
	const unsigned int *sp1 = (const unsigned int *) &p1[8];
	const unsigned int *sp2 = (const unsigned int *) &p2[8];
	
        return ((up1[0] ^ up2[0]) | (sp1[0] ^ sp2[0]));
#else
        const unsigned int *up1 = (const unsigned int *)p1;
        const unsigned int *up2 = (const unsigned int *)p2;
	return ((up1[0] ^ up2[0]) | (up1[1] ^ up2[1]) |
                (up1[2] ^ up2[2]));
#endif
}
static inline size_t xor8(const unsigned char *p1,
			  const unsigned char *p2)
{
#ifdef  HAVE_64BIT_ARCH
        const unsigned long *up1 = (const unsigned long *)p1;
        const unsigned long *up2 = (const unsigned long *)p2;
        return (up1[0] ^ up2[0]);
#else
        const unsigned int *up1 = (const unsigned int *)p1;
        const unsigned int *up2 = (const unsigned int *)p2;
	return ((up1[0] ^ up2[0]) |
                (up1[1] ^ up2[1]));
#endif
}

static inline size_t xnor12(const unsigned char *p1,
			    const unsigned char *p2)
{
  return !xor12(p1,p2);
}


static inline size_t xnor8(const unsigned char *p1,
			   const unsigned char *p2)
{
  return !xor8(p1,p2);
}

static inline size_t xnor16(const unsigned char *p1,
			    const unsigned char *p2)
{
  return !xor16(p1,p2);
}

#endif

static inline int
linklocal(const unsigned char *address)
{
    return xnor8(address, llprefix);
}

static inline int
v4mapped(const unsigned char *address)
{
    return xnor12(address, v4prefix);
}

static inline int
is_default(const unsigned char *prefix, int plen)
{
    return plen == 0 || (plen == 96 && v4mapped(prefix));
}

enum prefix_status {
    PST_EQUALS = 0,
    PST_DISJOINT,
    PST_MORE_SPECIFIC,
    PST_LESS_SPECIFIC
};

enum prefix_status
prefix_cmp(const unsigned char *p1, unsigned char plen1,
           const unsigned char *p2, unsigned char plen2);

/* If debugging is disabled, we want to avoid calling format_address
   for every omitted debugging message.  So debug is a macro.  But
   vararg macros are not portable. */
#if defined NO_DEBUG

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#define debugf(...) do {} while(0)
#define kdebugf(...) do {} while(0)
#elif defined __GNUC__
#define debugf(_args...) do {} while(0)
#define kdebugf(_args...) do {} while(0)
#else
static inline void debugf(const char *format, ...) { return; }
static inline void kdebugf(const char *format, ...) { return; }
#endif

#else

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#define debugf(...) \
    do { \
        if(UNLIKELY(debug >= 2)) do_debugf(2, __VA_ARGS__);     \
    } while(0)
#define kdebugf(...) \
    do { \
        if(UNLIKELY(debug >= 3)) do_debugf(3, __VA_ARGS__);     \
    } while(0)
#elif defined __GNUC__
#define debugf(_args...) \
    do { \
        if(UNLIKELY(debug >= 2)) do_debugf(2, _args);   \
    } while(0)
#define kdebugf(_args...) \
    do { \
        if(UNLIKELY(debug >= 3)) do_debugf(3, _args);   \
    } while(0)
#else
static inline void debugf(const char *format, ...) { return; }
static inline void kdebugf(const char *format, ...) { return; }
#endif

#endif

