/* Finite SNonce pool consumer. Native parent must authenticate the exact
 * uploaded bundle and bind its once-consumed host candidate BEFORE open.
 * No device entropy, persistent replay protection or PRNG is inferred here. */
#ifndef POLARIS_WIFI_NONCE_POOL_H
#define POLARIS_WIFI_NONCE_POOL_H
#include "polaris-wifi-wpa-crypto.h"
#define PWNP_COUNT 64u
#define PWNP_HEADER 80u
#define PWNP_BYTES (PWNP_HEADER+PWNP_COUNT*32u)
struct pwnp_state {
    uint64_t epoch;uint32_t opened,closed,used;
    uint8_t session[16],nonce[PWNP_COUNT][32];
};
static inline unsigned pwnp_u32(const uint8_t*p)
{return p[0]|((unsigned)p[1]<<8)|((unsigned)p[2]<<16)|((unsigned)p[3]<<24);}
static inline unsigned pwnp_nonzero(const uint8_t*p,unsigned bytes)
{unsigned v=0;for(unsigned n=0;n<bytes;n++)v|=p[n];return v!=0;}
static inline int pwnp_open(struct pwnp_state*s,const uint8_t*raw,unsigned bytes,uint64_t epoch)
{
    if(!s||!raw||bytes!=PWNP_BYTES||!epoch)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    const uint8_t magic[8]={'P','W','N','P','O','O','L','1'};
    for(unsigned n=0;n<8;n++)if(raw[n]!=magic[n]||raw[72+n])return 0;
    if(pwnp_u32(raw+8)!=1||pwnp_u32(raw+12)!=PWNP_COUNT||pwnp_u32(raw+16)!=32||pwnp_u32(raw+20)||!pwnp_nonzero(raw+24,16))return 0;
    for(unsigned n=0;n<PWNP_COUNT;n++){
        const uint8_t*p=raw+PWNP_HEADER+32*n;if(!pwnp_nonzero(p,32))return 0;
        for(unsigned j=0;j<n;j++){unsigned difference=0;for(unsigned k=0;k<32;k++)difference|=p[k]^raw[PWNP_HEADER+32*j+k];if(!difference)return 0;}
    }
    pwch_copy(s->session,raw+24,16);pwch_copy((uint8_t*)s->nonce,raw+PWNP_HEADER,PWNP_COUNT*32);s->epoch=epoch;s->opened=1;return 1;
}
/* Consume before association. Even failed association burns the entry. */
static inline int pwnp_take(struct pwnp_state*s,uint64_t epoch,uint8_t out[32])
{
    if(!s||!out||!s->opened||s->closed||s->epoch!=epoch||s->used>=PWNP_COUNT)return 0;
    pwch_copy(out,s->nonce[s->used],32);pwch_wipe(s->nonce[s->used],32);s->used++;return 1;
}
static inline void pwnp_stop(struct pwnp_state*s)
{if(!s)return;s->closed=1;pwch_wipe(s->nonce,sizeof(s->nonce));}
#endif
