/* Actual20F66 PosterBoard method identity and bounded preview geometry.
 * Derived from the user's verified cache; no Apple binary/code bytes here.
 */
#ifndef POLARIS_POSTER_PREVIEW_H
#define POLARIS_POSTER_PREVIEW_H
#include <math.h>
#include <stdint.h>
#include <stdbool.h>
#define PPP_TEXT UINT64_C(0x1c099e000)
#define PPP_METHOD UINT64_C(0x1c0a0f8fc)
#define PPP_METHOD_BYTES 756u
#define PPP_UUID {0x9c,0x21,0x36,0xc2,0xe6,0x40,0x31,0xc9,0x8b,0x01,0xde,0xe1,0xa4,0xe3,0x92,0x6a}
#define PPP_SHA {0x43,0xc3,0xff,0x53,0x96,0xff,0xf8,0xcb,0x92,0x50,0x2a,0x8b,0xee,0x68,0xab,0x4b,0x54,0x09,0x41,0x72,0x1e,0xd0,0x7a,0xa1,0xb0,0x53,0x49,0xb9,0xa2,0x28,0x84,0x89}
static inline bool ppp_dimensions(double w,double h,double scale,uint32_t *pw,uint32_t *ph)
{
    if(!pw || !ph || !isfinite(w) || !isfinite(h) || !isfinite(scale) ||
       w<=0 || h<=0 || w>16384 || h>16384 || scale<=0 || scale>4)return false;
    double x=floor(w*scale),y=floor(h*scale);
    if(!isfinite(x) || !isfinite(y) || x<1 || y<1 || x>4096 || y>4096 ||
       x*y>8*1024*1024)return false;
    *pw=(uint32_t)x;*ph=(uint32_t)y;return true;
}
#endif
