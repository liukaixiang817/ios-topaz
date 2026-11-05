/* Actual copied-segment verification for the resident Wi-Fi handoff. This
 * neither starts a CPU nor admits runtime authority. It consumes the loader's
 * already admitted payload and compares every file/BSS byte before channel
 * initialization may deliberately modify kernel DATA. */
#ifndef POLARIS_UEFI_WIFI_KERNEL_STAGE_H
#define POLARIS_UEFI_WIFI_KERNEL_STAGE_H
#include "payload.h"
#include "../../tools/polaris-wifi-firmware-identity.h"
struct pwks_image {
    uint64_t source,source_bytes,base,span,virtual_base,entry,verified_bytes;
    uint32_t attempted,unknown,error,segments,completed,complete;
    uint8_t header_digest[32],image_digest[32];struct pwfi_sha256 hash;
};
static inline int pwks_fail(struct pwks_image*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pwks_same(const uint8_t*a,const uint8_t*b,unsigned n)
{for(unsigned k=0;k<n;k++)if(a[k]!=b[k])return 0;return 1;}
static inline void pwks_hash(const void*p,size_t n,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);for(size_t k=0;k<n;k++)pwfi_byte(&h,((const volatile uint8_t*)p)[k]);pwfi_final(&h,out);}
static inline int pwks_disjoint(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return a<=UINT64_MAX-n&&b<=UINT64_MAX-z&&(a+n<=b||b+z<=a);}
static inline int pwks_begin(struct pwks_image*s,const struct polaris_payload*p,uint64_t bytes)
{
    if(!s||!p)return 0;for(unsigned k=0;k<sizeof(*s);k++)if(((const uint8_t*)s)[k])return 0;
    s->attempted=1;
    if(bytes<sizeof(*p)||bytes>POLARIS_PAYLOAD_LIMIT||!p->nsegs||p->nsegs>64||
       sizeof(*p)+(uint64_t)p->nsegs*sizeof(struct polaris_segment)>bytes||
       !p->phys_base||!p->mem_size||p->phys_base>UINT64_MAX-p->mem_size||
       p->kernel_end<=p->virt_base||p->kernel_end-p->virt_base>p->mem_size||
       p->entry_va<p->virt_base||p->entry_va>=p->kernel_end||
       !pwks_disjoint((uintptr_t)p,bytes,p->phys_base,p->mem_size)||
       !pwks_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)p,bytes)||
       !pwks_disjoint((uintptr_t)s,sizeof(*s),p->phys_base,p->mem_size))return pwks_fail(s,1);
    uint64_t header=sizeof(*p)+(uint64_t)p->nsegs*sizeof(struct polaris_segment);
    for(unsigned n=0;n<p->nsegs;n++){
        const struct polaris_segment*q=&p->segs[n];
        if(q->vmaddr<p->virt_base||!q->vmsize||
           q->vmaddr>=p->kernel_end||q->vmsize>p->kernel_end-q->vmaddr||
           q->file_size>q->vmsize||q->file_off<header||q->file_off>bytes||q->file_size>bytes-q->file_off)return pwks_fail(s,1);
        for(unsigned j=0;j<n;j++)if(!pwks_disjoint(q->vmaddr,q->vmsize,
            p->segs[j].vmaddr,p->segs[j].vmsize))return pwks_fail(s,1);
    }
    s->source=(uintptr_t)p;s->source_bytes=bytes;s->base=p->phys_base;s->span=p->kernel_end-p->virt_base;
    s->virtual_base=p->virt_base;s->entry=p->entry_va;s->segments=p->nsegs;
    pwks_hash(p,header,s->header_digest);pwfi_init(&s->hash);return 1;
}
static inline int pwks_verify(struct pwks_image*s,unsigned index)
{
    if(!s||!s->attempted||s->unknown||s->error||s->complete)return 0;
    if(index!=s->completed||index>=s->segments)return pwks_fail(s,4);
    const struct polaris_payload*p=(const void*)(uintptr_t)s->source;uint8_t hash[32];
    pwks_hash(p,sizeof(*p)+(uint64_t)s->segments*sizeof(struct polaris_segment),hash);
    if(!pwks_same(hash,s->header_digest,32))return pwks_fail(s,2);
    const struct polaris_segment*q=&p->segs[index];
    const volatile uint8_t*source=(const void*)(uintptr_t)(s->source+q->file_off);
    const volatile uint8_t*target=(const void*)(uintptr_t)(s->base+q->vmaddr-s->virtual_base);
    for(uint64_t n=0;n<q->vmsize;n++){
        uint8_t got=target[n],want=n<q->file_size?source[n]:0;
        if(got!=want)return pwks_fail(s,3);
        pwfi_byte(&s->hash,got);s->verified_bytes++;
    }
    s->completed++;
    if(s->completed==s->segments){pwfi_final(&s->hash,s->image_digest);s->complete=1;}
    return 1;
}
#endif
