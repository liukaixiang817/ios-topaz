/* Polaris c7cb50c1 MP_ASSIGN wire buffers, independently implemented from
 * secure_buffer.{c,h}/scm.{c,h} ABI facts. Not an allocation or owner grant.
 * No device call is made here. A future caller must establish allocation,
 * mappings, cache maintenance, original owners, serialization and retirement.
 * Neither a source VMID list nor a successful return proves DMA has stopped. */
#ifndef POLARIS_WIFI_MEM_ASSIGN_H
#define POLARIS_WIFI_MEM_ASSIGN_H
#include <stdint.h>
#include <stddef.h>
#define PWMA_FN UINT64_C(0x42000c16)
#define PWMA_ARGS UINT64_C(0x1117)
#define PWMA_PAGE_BYTES 4096u
#define PWMA_SOURCE_OFFSET 0u
#define PWMA_REGION_OFFSET 64u
#define PWMA_DEST_OFFSET 128u
#define PWMA_EXTRA_OFFSET 256u
#define PWMA_MAX_VMS 3u
enum pwma_vmid {PWMA_HLOS=3,PWMA_MSS_MSA=15,PWMA_WLAN=24,PWMA_WLAN_CE=25};
enum pwma_perm {PWMA_RW=6,PWMA_RWX=7};
struct pwma_destination {uint32_t vmid,permissions;};
struct pwma_spec {
    uint64_t descriptor_pa,region_pa,region_bytes;
    uint32_t sources,destinations;
    uint32_t source[PWMA_MAX_VMS];
    struct pwma_destination destination[PWMA_MAX_VMS];
};
struct pwma_page {uint8_t data[PWMA_PAGE_BYTES];} __attribute__((aligned(4096)));
struct pwma_registers {uint64_t x[7];};
_Static_assert(sizeof(struct pwma_page)==4096,"one retained descriptor page");
_Static_assert(sizeof(struct pwma_registers)==56,"exact x0..x6 round");
static inline void pwma_put(uint8_t*out,uint64_t v,unsigned bytes)
{for(unsigned n=0;n<bytes;n++)out[n]=(uint8_t)(v>>(8*n));}
static inline int pwma_vm(uint32_t v)
{return v==PWMA_HLOS||v==PWMA_MSS_MSA||v==PWMA_WLAN||v==PWMA_WLAN_CE;}
static inline int pwma_span(uint64_t at,uint64_t bytes)
{return at&&bytes&&at<=UINT64_MAX-bytes;}
static inline int pwma_overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{return a<b+m&&b<a+n;}
/* Argument-only construction. Inputs contain proposed, not observed owners.
 * The caller retains this page outside the transferred interval for the whole
 * secure call, including every interrupted continuation. No silent rounding,
 * arbitrary VMIDs, default physical address, no-op owner inference or retry. */
static inline int pwma_encode_profile(struct pwma_page*page,struct pwma_registers*regs,
    const struct pwma_spec*input,unsigned modem)
{
    if(!page||!regs||!input||((uintptr_t)page&4095)||
       !pwma_span((uintptr_t)page,sizeof(*page))||!pwma_span((uintptr_t)regs,sizeof(*regs))||
       !pwma_span((uintptr_t)input,sizeof(*input))||
       pwma_overlap((uintptr_t)page,sizeof(*page),(uintptr_t)regs,sizeof(*regs))||
       pwma_overlap((uintptr_t)page,sizeof(*page),(uintptr_t)input,sizeof(*input))||
       pwma_overlap((uintptr_t)regs,sizeof(*regs),(uintptr_t)input,sizeof(*input)))return 0;
    struct pwma_spec s=*input;
    /* Own hyp_assign_phys uses ONE scatterlist entry. Its batch loop takes
     * that first entry whole before considering the 2MiB aggregation limit.
     * A separate profile admits only the own120MiB/1MiB-aligned modem bank
     * and its two startup transitions (profile1), or its exact MSS->HLOS
     * return (profile2), never arbitrary large WLAN regions. */
    if(modem){
        if(modem>2||s.region_bytes!=0x7800000||(s.region_pa&0xfffff))return 0;
        unsigned share=s.sources==1&&s.source[0]==PWMA_HLOS&&s.destinations==2&&
            s.destination[0].vmid==PWMA_HLOS&&s.destination[0].permissions==PWMA_RW&&
            s.destination[1].vmid==PWMA_MSS_MSA&&s.destination[1].permissions==PWMA_RW;
        unsigned exclusive=s.sources==2&&s.source[0]==PWMA_HLOS&&s.source[1]==PWMA_MSS_MSA&&
            s.destinations==1&&s.destination[0].vmid==PWMA_MSS_MSA&&s.destination[0].permissions==PWMA_RW;
        unsigned handback=s.sources==1&&s.source[0]==PWMA_MSS_MSA&&s.destinations==1&&
            s.destination[0].vmid==PWMA_HLOS&&s.destination[0].permissions==PWMA_RWX;
        if(modem==1?(!share&&!exclusive):!handback)return 0;
    }
    if((s.descriptor_pa&4095)||!pwma_span(s.descriptor_pa,sizeof(*page))||
       (s.region_pa&4095)||(s.region_bytes&4095)||!s.region_bytes||(!modem&&s.region_bytes>0x200000)||
       s.region_pa<UINT64_C(0x80000000)||s.region_pa>=UINT64_C(0x100000000)||
       s.region_bytes>UINT64_C(0x100000000)-s.region_pa||
       pwma_overlap(s.descriptor_pa,sizeof(*page),s.region_pa,s.region_bytes)||
       !s.sources||s.sources>PWMA_MAX_VMS||!s.destinations||s.destinations>PWMA_MAX_VMS)return 0;
    for(unsigned n=0;n<PWMA_MAX_VMS;n++){
        if(n<s.sources){
            if(!pwma_vm(s.source[n]))return 0;
            for(unsigned j=0;j<n;j++)if(s.source[j]==s.source[n])return 0;
        }else if(s.source[n])return 0;
        if(n<s.destinations){
            const struct pwma_destination*d=&s.destination[n];
            if(!pwma_vm(d->vmid)||(d->permissions!=PWMA_RW&&
               !(d->vmid==PWMA_HLOS&&d->permissions==PWMA_RWX)))return 0;
            for(unsigned j=0;j<n;j++)if(s.destination[j].vmid==d->vmid)return 0;
        }else if(s.destination[n].vmid||s.destination[n].permissions)return 0;
    }
    /* Caller must supply fresh storage; never overwrite a pending request. */
    for(unsigned n=0;n<sizeof(*page);n++)if(page->data[n])return 0;
    for(unsigned n=0;n<7;n++)if(regs->x[n])return 0;
    pwma_put(page->data+PWMA_REGION_OFFSET,s.region_pa,8);
    pwma_put(page->data+PWMA_REGION_OFFSET+8,s.region_bytes,8);
    for(unsigned n=0;n<s.sources;n++)pwma_put(page->data+PWMA_SOURCE_OFFSET+4*n,s.source[n],4);
    for(unsigned n=0;n<s.destinations;n++){
        uint8_t*d=page->data+PWMA_DEST_OFFSET+24*n;
        pwma_put(d,s.destination[n].vmid,4);pwma_put(d+4,s.destination[n].permissions,4);
        /* 64-bit context, 32-bit context size and four ABI padding bytes stay zero. */
    }
    pwma_put(page->data+PWMA_EXTRA_OFFSET,4*s.sources,8);
    pwma_put(page->data+PWMA_EXTRA_OFFSET+8,s.descriptor_pa+PWMA_DEST_OFFSET,8);
    pwma_put(page->data+PWMA_EXTRA_OFFSET+16,24*s.destinations,8);
    /* Extended arguments 6..9 remain zero, including the unused tail. */
    regs->x[0]=PWMA_FN;regs->x[1]=PWMA_ARGS;
    regs->x[2]=s.descriptor_pa+PWMA_REGION_OFFSET;regs->x[3]=16;
    regs->x[4]=s.descriptor_pa+PWMA_SOURCE_OFFSET;regs->x[5]=s.descriptor_pa+PWMA_EXTRA_OFFSET;
    return 1;
}
static inline int pwma_encode(struct pwma_page*page,struct pwma_registers*regs,const struct pwma_spec*input)
{return pwma_encode_profile(page,regs,input,0);}
static inline int pwma_encode_modem(struct pwma_page*page,struct pwma_registers*regs,const struct pwma_spec*input)
{return pwma_encode_profile(page,regs,input,1);}
static inline int pwma_encode_modem_return(struct pwma_page*page,struct pwma_registers*regs,const struct pwma_spec*input)
{return pwma_encode_profile(page,regs,input,2);}
enum pwma_return {PWMA_RETURN_UNKNOWN,PWMA_RETURN_INTERRUPTED,PWMA_RETURN_ZERO};
/* Preserve all returned registers separately. x0==1 continues the SAME
 * request with returned x1..x6, never a new request or busy resubmission.
 * The own vendor checks x0; conservatively require x1==0 as well until actual
 * secure results establish its meaning. ZERO is not a DMA retirement result. */
static inline enum pwma_return pwma_classify(const struct pwma_registers*r)
{
    if(!r)return PWMA_RETURN_UNKNOWN;
    if(r->x[0]==1)return PWMA_RETURN_INTERRUPTED;
    return !r->x[0]&&!r->x[1]?PWMA_RETURN_ZERO:PWMA_RETURN_UNKNOWN;
}
#endif
