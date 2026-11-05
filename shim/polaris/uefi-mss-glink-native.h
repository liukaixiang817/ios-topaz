/* Native GLINK adapter in the continuous MSS owner. Separate protocol TU uses
 * the bounded private arena below, never original EFI allocation/timers. */
#ifndef POLARIS_UEFI_MSS_GLINK_NATIVE_H
#define POLARIS_UEFI_MSS_GLINK_NATIVE_H
#include "uefi-mss-channel-native.h"
#include "polaris-wifi-cap.h"
#ifndef EFI_XNU_MSS_GLINK_NATIVE_AVAILABLE
#define EFI_XNU_MSS_GLINK_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_GLINK_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE
#error Native GLINK requires the actual SMP2P handshake
#endif
#define PMSG_UNITS 16384u
#define PMSG_UNIT 256u
struct pmsg_state {
    uint64_t channel,owner,opening,started,next_poll;
    uint32_t attempted,unknown,error,ready,polls,allocations,frees;
    struct polaris_glink_layout layout;
    struct polaris_glink_workspace inventory;
    struct polaris_glink_witness selected[5];
    uint32_t entry_offset;uint8_t entry[48],partition[12],digest[32];
    struct polaris_wifi_glink_cfg cfg;
    struct polaris_wifi_glink *transport;
    struct polaris_wifi_cap_client identity;
    uint16_t units[PMSG_UNITS];
    _Alignas(16) uint8_t arena[PMSG_UNITS*PMSG_UNIT];
};
static struct pmsg_state *pmsg_runtime;
static inline int pmsg_fail(struct pmsg_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;if(s->channel)pmsx_fail((void*)(uintptr_t)s->channel,6);return 0;}
static inline int pmsg_live(struct pmsg_state*s)
{
    if(!s||!s->attempted||s->unknown||s->error||pmsg_runtime!=s)return 0;
    struct pmsx_state*x=(void*)(uintptr_t)s->channel;
    return x->owner==s->owner&&x->opening==s->opening&&pmsx_live(x);
}
/* Every covering word is within the previously validated item. Physical reads
 * retain Normal-NC AT/GCD checks, including the tail of an unaligned payload. */
static inline bool pmsg_read_raw(void*ctx,uint32_t offset,void*out,size_t bytes)
{
    struct pmsg_state*s=ctx;if(!out||!bytes||offset>=PMSQ_BYTES||bytes>PMSQ_BYTES-offset||!pmsg_live(s))return false;
    unsigned at=offset&~3u,end=(offset+(unsigned)bytes+3)&~3u;
    while(at<end){unsigned n=end-at;if(n>PMSQ_CHUNK)n=PMSQ_CHUNK;
        const uint8_t*p=pmsx_read((void*)(uintptr_t)s->channel,at,n);if(!p)return false;
        unsigned first=at<offset?offset-at:0,last=at+n>offset+bytes?(unsigned)(offset+bytes-at):n;
        pgcd_copy((uint8_t*)out+(at+first-offset),p+first,last-first);at+=n;
    }return pmsg_live(s);
}
static inline bool pmsg_scope(void*ctx,uint64_t epoch,const struct polaris_glink_layout*layout)
{
    struct pmsg_state*s=ctx;if(!pmsg_live(s)||!s->ready||epoch!=s->opening||!layout||!pgcd_equal(layout,&s->layout,sizeof(*layout)))return false;
    uint8_t hash[32],raw[48];pweh_digest(&s->layout,offsetof(struct pmsg_state,digest)-offsetof(struct pmsg_state,layout),hash);
    if(!pgcd_equal(hash,s->digest,32)||!pmsx_negotiated((void*)(uintptr_t)s->channel))return pmsg_fail(s,1);
    for(unsigned n=0;n<5;n++)if(!pmsg_read_raw(s,s->selected[n].offset,raw,16)||!pgcd_equal(raw,s->selected[n].bytes,16))return pmsg_fail(s,1);
    if(!pmsg_read_raw(s,s->layout.partition,raw,12)||!pgcd_equal(raw,s->partition,12)||
       !pmsg_read_raw(s,s->entry_offset,raw,48)||!pgcd_equal(raw,s->entry,48))return pmsg_fail(s,1);
    return pmsg_live(s);
}
static inline int pmsg_inside(unsigned at,unsigned n,const struct polaris_glink_item*i)
{return at>=i->offset&&at-i->offset<=i->bytes&&n<=i->bytes-(at-i->offset);}
static inline bool pmsg_read(void*ctx,uint32_t at,void*out,uint32_t n)
{
    struct pmsg_state*s=ctx;
    if(!n||(!pmsg_inside(at,n,&s->layout.descriptor)&&!pmsg_inside(at,n,&s->layout.rx))||!pmsg_scope(s,s->opening,&s->layout))return false;
    return pmsg_read_raw(s,at,out,n)?true:pmsg_fail(s,2);
}
static inline bool pmsg_write(void*ctx,uint32_t at,uint32_t value)
{
    struct pmsg_state*s=ctx;if(!pmsg_scope(s,s->opening,&s->layout))return false;
    struct pmsx_state*x=(void*)(uintptr_t)s->channel;unsigned item;
    if(at==s->layout.descriptor.offset+4||at==s->layout.descriptor.offset+8)item=1;
    else if(pmsg_inside(at,4,&s->layout.tx))item=2;else return pmsg_fail(s,3);
    return pmsx_write(x,item,at-x->item[item].data,value)?true:pmsg_fail(s,3);
}
static inline bool pmsg_order(void*ctx)
{struct pmsg_state*s=ctx;if(!pmsg_live(s))return false;pmsq_order();return pmsg_live(s);}
static inline bool pmsg_invalidate(void*ctx,uint32_t at,uint32_t n)
{
    struct pmsg_state*s=ctx;if(!n||!pmsg_inside(at,n,&s->layout.rx)||!pmsg_live(s))return false;
    /* SMEM cached-heap flag is allocation geometry, not CPU cacheability.
     * Every subsequent read proves Normal-NC; no CIVAC on an unproven mapping. */
    return pmsg_order(s);
}
static inline bool pmsg_ring(void*ctx)
{struct pmsg_state*s=ctx;return pmsg_scope(s,s->opening,&s->layout)&&pmsx_ring((void*)(uintptr_t)s->channel,1);}
static inline uint64_t pmsg_now(void*ctx)
{struct pmsg_state*s=ctx;if(!pmsg_live(s)){pmsg_fail(s,4);return UINT64_MAX;}struct pmsc_owner*o=(void*)(uintptr_t)s->owner;return o->last*5/96;}
static inline void pmsg_sleep(void*ctx,uint32_t us)
{
    struct pmsg_state*s=ctx;if(us>5000000||!pmsg_live(s)){pmsg_fail(s,4);return;}
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;uint64_t start=o->last,ticks=((uint64_t)us*96+4)/5;
    while(pmsg_live(s)){if(o->last<start){pmsg_fail(s,4);return;}if(o->last-start>=ticks)return;}
    pmsg_fail(s,4);
}
/* One CPU0 instance; no allocator reset or reuse after an uncertain epoch. */
uintptr_t pwfg_thread(void){return pmsg_live(pmsg_runtime)?(uintptr_t)pmsg_runtime:0;}
void*pwfg_alloc(size_t bytes)
{
    struct pmsg_state*s=pmsg_runtime;if(!bytes||bytes>sizeof(s->arena)||!pmsg_live(s))return 0;
    unsigned count=(unsigned)((bytes+PMSG_UNIT-1)/PMSG_UNIT),run=0;
    for(unsigned n=0;n<PMSG_UNITS;n++){
        run=s->units[n]?0:run+1;if(run!=count)continue;unsigned first=n+1-count;
        s->units[first]=(uint16_t)count;for(unsigned j=1;j<count;j++)s->units[first+j]=UINT16_MAX;
        uint8_t*p=s->arena+first*PMSG_UNIT;for(size_t j=0;j<bytes;j++)p[j]=0;s->allocations++;return p;
    }return 0;
}
void pwfg_free(void*pointer,size_t bytes)
{
    struct pmsg_state*s=pmsg_runtime;if(!pmsg_live(s))return;
    uintptr_t at=(uintptr_t)pointer,base=(uintptr_t)s->arena;
    if(!bytes||bytes>sizeof(s->arena)||at<base||at-base>=sizeof(s->arena)||(at-base)%PMSG_UNIT){pmsg_fail(s,5);return;}
    unsigned first=(unsigned)((at-base)/PMSG_UNIT),count=(unsigned)((bytes+PMSG_UNIT-1)/PMSG_UNIT);
    if(count>PMSG_UNITS-first||s->units[first]!=count){pmsg_fail(s,5);return;}
    for(unsigned n=1;n<count;n++)if(s->units[first+n]!=UINT16_MAX){pmsg_fail(s,5);return;}
    for(unsigned n=0;n<count;n++)s->units[first+n]=0;s->frees++;
}
static inline int pmsg_begin(struct pmsg_state*s,struct pmsx_state*x)
{
    if(!s||!x||pmsg_runtime||!pwmc_zero(s,sizeof(*s))||!pmsx_negotiated(x))return 0;
    struct pmsn_state*a=(void*)(uintptr_t)x->auth;struct pmsa_state*m=(void*)(uintptr_t)x->allocation;
    if(!pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    const uint64_t at[]={(uintptr_t)x,(uintptr_t)a,a->records,a->copy,a->segments,(uintptr_t)m,x->smem,m->lock,x->negotiation};
    const uint64_t bytes[]={sizeof(*x),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,sizeof(*m),sizeof(struct pmsq_state),sizeof(struct pmsl_lock),sizeof(struct pmsy_state)};
    for(unsigned n=0;n<9;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    s->channel=(uintptr_t)x;s->owner=x->owner;s->opening=x->opening;s->attempted=1;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;s->started=o->last;pmsg_runtime=s;return pmsg_live(s);
}
/* 0=sticky refusal,1=wait for remote480 publication,2=protocol created/started.
 * Bounded10s discovery inside the existing180s owner, with no timer renewal. */
static inline int pmsg_step(struct pmsg_state*s)
{
    if(!pmsg_live(s))return 0;if(s->ready)return pmsg_scope(s,s->opening,&s->layout)?2:0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmsx_state*x=(void*)(uintptr_t)s->channel;
    if(o->last<s->started||o->last-s->started>PMSY_TOTAL)return pmsg_fail(s,6);
    if(o->last<s->next_poll)return 1;if(s->polls++==1024)return pmsg_fail(s,6);s->next_poll=o->last+PMSY_POLL;
    struct polaris_smem_reader reader={pmsg_read_raw,s,PMSQ_BYTES};
    if(!polaris_glink_inventory(&reader,1,&s->layout,&s->inventory))return pmsg_live(s)?1:pmsg_fail(s,7);
    if(s->layout.partition!=0xb9000||s->layout.partition_bytes!=0x7c000||
       s->layout.descriptor.offset!=x->item[1].data||s->layout.tx.offset!=x->item[2].data||s->layout.tx.bytes!=16384)return pmsg_fail(s,7);
    unsigned partition_found=0;
    for(unsigned n=0;n<s->inventory.inventory.count;n++){
        const struct polaris_smem_part*p=&s->inventory.inventory.parts[n];if(p->offset!=s->layout.partition)continue;
        if(p->cacheline!=32||p->bytes!=0x7c000||!p->accessible||p->flags||p->exclusions[0]||p->exclusions[1]||p->exclusions[2]||p->exclusions[3])return pmsg_fail(s,7);
        s->entry_offset=PMSQ_BYTES-PSM_TABLE_BYTES+32+p->index*48;
        pgcd_copy(s->entry,s->inventory.smem.table+32+p->index*48,48);partition_found++;
    }
    if(partition_found!=1)return pmsg_fail(s,7);
    unsigned found=0;struct pmsy_state*y=(void*)(uintptr_t)x->negotiation;
    for(unsigned n=0;n<s->inventory.count;n++){
        const struct polaris_glink_witness*h=&s->inventory.headers[n];int selected=-1;
        for(unsigned j=0;j<3;j++)if(h->offset==x->item[j].header){if(!pgcd_equal(h->bytes,x->item[j].wire,16))return pmsg_fail(s,7);selected=(int)j;}
        if(h->offset==y->in_header){if(!pgcd_equal(h->bytes,y->header,16))return pmsg_fail(s,7);selected=3;}
        unsigned rxheader=s->layout.rx.cached?s->layout.rx.offset+psm_u32(h->bytes+4):s->layout.rx.offset-16;
        if(psm_u16(h->bytes+2)==480&&h->offset==rxheader)selected=4;
        if(selected>=0){if(found&(1u<<selected))return pmsg_fail(s,7);s->selected[selected]=*h;found|=1u<<selected;}
    }
    if(found!=31||!pmsg_read_raw(s,s->layout.partition,s->partition,12))return pmsg_fail(s,7);
    pweh_digest(&s->layout,offsetof(struct pmsg_state,digest)-offsetof(struct pmsg_state,layout),s->digest);s->ready=1;
    s->cfg=(struct polaris_wifi_glink_cfg){.epoch=s->opening,.smem_phys=PMSQ_BASE,.smem_bytes=PMSQ_BYTES,.local_node=1,
        .receive_startup=true,.layout=s->layout,.scope=pmsg_scope,.smem_read=pmsg_read,.smem_write32=pmsg_write,
        .invalidate=pmsg_invalidate,.order=pmsg_order,.ring=pmsg_ring,.sleep_us=pmsg_sleep,.now_us=pmsg_now,.ctx=s};
    s->transport=polaris_wifi_glink_create(&s->cfg);
    if(!s->transport||polaris_wifi_glink_start(s->transport))return pmsg_fail(s,8);return 2;
}
/* Creating/starting GLINK is not a completed QRTR HELLO. RMTFS/WLFW need
 * the actual remote node. Use the original discovery window and poll budget,
 * without renewing either when the transport object becomes available. */
static inline int pmsg_peer_step(struct pmsg_state*s)
{
    if(!s||!pmsg_scope(s,s->opening,&s->layout))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;uint32_t node=0;
    if(o->last<s->started||o->last-s->started>PMSY_TOTAL)return pmsg_fail(s,9);
    if(!polaris_wifi_glink_qrtr_peer(s->transport,&node))
        return node&&node<0xfffffffe?2:pmsg_fail(s,9);
    if(o->last<s->next_poll)return 1;
    if(s->polls++>=1024)return pmsg_fail(s,9);s->next_poll=o->last+PMSY_POLL;
    if(polaris_wifi_glink_poll_once(s->transport)||!pmsg_scope(s,s->opening,&s->layout))return pmsg_fail(s,9);
    if(polaris_wifi_glink_qrtr_peer(s->transport,&node))return 1;
    return node&&node<0xfffffffe?2:pmsg_fail(s,9);
}
#endif
#endif
