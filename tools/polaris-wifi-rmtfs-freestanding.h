/* Native RMTFS uses a separately retained shadow arena and current CPU owner.
 * Scalar hashing is supplied by that owner; no libc/kernel/crypto framework. */
#ifndef POLARIS_WIFI_RMTFS_FREESTANDING_H
#define POLARIS_WIFI_RMTFS_FREESTANDING_H
#include "polaris-wifi-glink-freestanding.h"
void *pwfr_alloc(size_t);
void pwfr_free(void *,size_t);
uintptr_t pwfr_thread(void);
bool pwfr_hash(const void *,uint32_t,const uint8_t[32]);
#define PWR_ALLOC(n) pwfr_alloc(n)
#define PWR_FREE(p,n) pwfr_free(p,n)
#define PWR_THREAD() pwfr_thread()
#define EACCES 13
#define ESTALE 70
static inline size_t pwfr_length(const char*s){size_t n=0;while(s[n])n++;return n;}
static inline void*pwfr_find(const void*s,int c,size_t n)
{for(size_t i=0;i<n;i++)if(((const unsigned char*)s)[i]==(unsigned char)c)return (void*)((const unsigned char*)s+i);return NULL;}
#define strlen pwfr_length
#define memchr pwfr_find
#endif
