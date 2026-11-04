/* Separate GLINK translation unit: no original firmware or kernel allocation.
 * The native owner supplies these three functions. Darwin errno values match
 * the public kernel transport ABI; no host OS interfaces are linked. */
#ifndef POLARIS_WIFI_GLINK_FREESTANDING_H
#define POLARIS_WIFI_GLINK_FREESTANDING_H
#include <stdint.h>
#include <stddef.h>
void *pwfg_alloc(size_t);
void pwfg_free(void *,size_t);
uintptr_t pwfg_thread(void);
#define PWF_ALLOC(n) pwfg_alloc(n)
#define PWF_FREE(p,n) pwfg_free(p,n)
#define PWF_THREAD_ID() pwfg_thread()
#define EIO 5
#define ENOMEM 12
#define EBUSY 16
#define EINVAL 22
#define ENOSPC 28
#define EAGAIN 35
#define EADDRINUSE 48
#define ENODEV 19
#define EPROTO 100
#define EALREADY 37
#define EMSGSIZE 40
#define ENOBUFS 55
#define ENOTCONN 57
#define ETIMEDOUT 60
static inline void *pwfg_copy(void *d,const void *s,size_t n)
{for(size_t i=0;i<n;i++)((unsigned char*)d)[i]=((const unsigned char*)s)[i];return d;}
static inline void *pwfg_set(void *d,int c,size_t n)
{for(size_t i=0;i<n;i++)((unsigned char*)d)[i]=(unsigned char)c;return d;}
static inline int pwfg_compare(const void *a,const void *b,size_t n)
{for(size_t i=0;i<n;i++){unsigned x=((const unsigned char*)a)[i],y=((const unsigned char*)b)[i];if(x!=y)return x<y?-1:1;}return 0;}
#define memcpy pwfg_copy
#define memset pwfg_set
#define memcmp pwfg_compare
#endif
