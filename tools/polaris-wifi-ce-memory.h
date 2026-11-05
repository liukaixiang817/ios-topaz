/* WCN3990 host ring layout. Only offsets inside a new independent allocation;
 * no physical address is taken from firmware, DT or a previous boot. */
#ifndef POLARIS_WIFI_CE_MEMORY_H
#define POLARIS_WIFI_CE_MEMORY_H
#include "polaris-wifi-wcn3990-config.h"
#define PWDM_LIMIT (UINT64_C(1)<<35)
#define PWDM_USABLE 0x800000u
#define PWDM_BYTES (PWDM_USABLE+8192u)
struct pwdm_pipe {
    uint32_t source,destination,source_buffers,destination_buffers;
    uint16_t sources,destinations,buffer_bytes,flags;
};
struct pwdm_layout {uint64_t allocation;uint32_t bytes,used,rri,reserved;struct pwdm_pipe pipe[12];};
struct pwdm_descriptor {uint64_t address;uint16_t bytes,flags;uint32_t hash;};
_Static_assert(sizeof(struct pwdm_descriptor)==16,"WCN3990 64-bit CE descriptor");
static inline int pwdm_region(struct pwdm_layout*l,uint32_t bytes,uint32_t*out)
{
    if(!bytes){*out=0;return 1;}
    uint32_t at=(l->used+4095u)&~4095u;
    if(at<l->used||at>4096+PWDM_USABLE||bytes>4096+PWDM_USABLE-at)return 0;
    *out=at;l->used=at+bytes;return 1;
}
/* A page at each end is retained outside all DMA ranges. Every ring and pool
 * begins on its own page; buffers have the primary host table's exact stride.
 * CE6 has no host ring. One RRI page holds twelve little-endian32 indices. */
static inline int pwdm_plan(struct pwdm_layout*l,uint64_t allocation)
{
    if(!l||!allocation||(allocation&4095)||allocation>PWDM_LIMIT-PWDM_BYTES)return 0;
    const uint8_t*b=(const uint8_t*)l;for(unsigned n=0;n<sizeof(*l);n++)if(b[n])return 0;
    l->allocation=allocation;l->bytes=PWDM_BYTES;l->used=4096;
    if(!pwdm_region(l,4096,&l->rri))return 0;
    for(unsigned n=0;n<12;n++){
        struct pwdm_pipe*p=&l->pipe[n];const struct pwcn_host_pipe*h=&polaris_wcn3990_host[n];
        p->sources=h->source_entries;p->destinations=h->destination_entries;p->buffer_bytes=h->bytes;p->flags=h->flags;
        if(!pwdm_region(l,16u*p->sources,&p->source)||!pwdm_region(l,16u*p->destinations,&p->destination)||
           !pwdm_region(l,(uint32_t)p->sources*p->buffer_bytes,&p->source_buffers)||
           !pwdm_region(l,(uint32_t)p->destinations*p->buffer_bytes,&p->destination_buffers))return 0;
    }
    return l->used<=4096+PWDM_USABLE;
}
#endif
