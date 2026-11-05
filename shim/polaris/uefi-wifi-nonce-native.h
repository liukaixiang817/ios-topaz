/* Host-generated, image-bound SNonce pool for one temporary boot. The boot
 * helper's digest-wide consumption ledger is a REQUIRED external boundary.
 * This does not manufacture device entropy or permit persistent image reuse. */
#ifndef POLARIS_UEFI_WIFI_NONCE_NATIVE_H
#define POLARIS_UEFI_WIFI_NONCE_NATIVE_H
#include "uefi-wifi-wmi-native.h"
#include "../../tools/polaris-wifi-nonce-pool.h"
#ifndef EFI_XNU_WIFI_NONCE_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_NONCE_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_NONCE_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_WMI_NATIVE_AVAILABLE
#error Native nonce pool requires actual WMI owner
#endif
struct pmnp_state {
    uint64_t wmi,owner,opening,source;struct pwnp_state pool;
    struct pwmc_translation translation[2];uint8_t raw[PWNP_BYTES],digest[32];
    uint32_t attempted,ready,unknown,error,pages;
};
static inline int pmnp_fail(struct pmnp_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;pwnp_stop(&s->pool);pwch_wipe(s->raw,sizeof(s->raw));return 0;}
static inline int pmnp_live(struct pmnp_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->pool.closed||s->pool.epoch!=s->opening)return 0;
    struct pmwi_state*w=(void*)(uintptr_t)s->wmi;
    return w->nonce==(uintptr_t)s&&w->owner==s->owner&&w->opening==s->opening&&pmwi_live(w);
}
/* raw and expected are compiled, image-resident inputs of the NEW candidate.
 * Authenticate the private copy, never follow a digest from the blob itself. */
static inline int pmnp_begin(struct pmnp_state*s,struct pmwi_state*w,const uint8_t*raw,const uint8_t expected[32])
{
    if(!s||!w||!raw||!expected||!pwmc_zero(s,sizeof(*s))||!pmwi_live(w)||w->client.phase!=4||w->nonce)return 0;
    struct pmhc_state*h=(void*)(uintptr_t)w->htc;struct pmsc_owner*o=(void*)(uintptr_t)w->owner;
    const struct pweh_result*r=(const void*)(uintptr_t)o->retained;
    if(!pmwi_child(h,(uintptr_t)s,sizeof(*s))||!pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)w,sizeof(*w))||
       !pmsi_image_range(r->input.early,&r->map,(uintptr_t)raw,PWNP_BYTES)||
       !pmsi_image_range(r->input.early,&r->map,(uintptr_t)expected,32)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)raw,PWNP_BYTES)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)expected,32))return 0;
    s->wmi=(uintptr_t)w;s->owner=w->owner;s->opening=w->opening;s->source=(uintptr_t)raw;s->attempted=1;
    /* Consume the unique producer before reads. Failure cannot open a second
     * state against the same candidate to replay previously emitted entries. */
    w->nonce=(uintptr_t)s;
    uint64_t first=(uintptr_t)raw&~UINT64_C(4095),end=((uintptr_t)raw+PWNP_BYTES+4095)&~UINT64_C(4095);
    for(uint64_t page=first;page<end;page+=4096){
        if(s->pages==2||!pmwi_live(w))return pmnp_fail(s,1);
        struct pwmc_translation*t=&s->translation[s->pages++];t->page=page;
        if(!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||t->page!=page||!pmwi_live(w))return pmnp_fail(s,1);
    }
    /* expected lives in the same image but may occupy another page. Its exact
     * source access is independently translated; no pointer comes from raw. */
    struct pwmc_translation check={0};check.page=(uintptr_t)expected&~UINT64_C(4095);
    if(((uintptr_t)expected&4095)>4064||!pwmc_actual_translate(&check)||!pwmc_translation_valid(&check)||
       check.page!=((uintptr_t)expected&~UINT64_C(4095))||!pmwi_live(w))return pmnp_fail(s,1);
    for(unsigned n=0;n<PWNP_BYTES;n++)s->raw[n]=((const volatile uint8_t*)raw)[n];
    pweh_digest(s->raw,PWNP_BYTES,s->digest);
    if(!pgcd_equal(s->digest,expected,32)||!pmwi_live(w))return pmnp_fail(s,2);
    uint8_t body_hash[32];pweh_digest(s->raw+PWNP_HEADER,PWNP_COUNT*32,body_hash);
    if(!pgcd_equal(body_hash,s->raw+40,32)||!pwnp_open(&s->pool,s->raw,PWNP_BYTES,s->opening)||!pmwi_live(w))return pmnp_fail(s,2);
    pwch_wipe(s->raw,sizeof(s->raw));s->ready=1;return pmnp_live(s);
}
static inline int pmnp_take(struct pmnp_state*s,uint8_t out[32])
{
    if(!pmnp_live(s)||!out)return 0;
    /* Caller is native code with its own retained output; never a raw kernel
     * or host pointer accepted by this boundary. No original service call. */
    return pwnp_take(&s->pool,s->opening,out)&&pmnp_live(s);
}
#endif
#endif
