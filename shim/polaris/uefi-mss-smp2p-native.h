/* Native version1/SSR-ACK negotiation over freshly allocated APPS item428.
 * Remote435 discovery is read-only and bounded. Matches are protocol evidence,
 * not a nonce-based proof of remote execution; actual MSS reset/auth supplies
 * the generation. ERROR_READY may arrive after GLINK/RMTFS startup. */
#ifndef POLARIS_UEFI_MSS_SMP2P_NATIVE_H
#define POLARIS_UEFI_MSS_SMP2P_NATIVE_H
#include "uefi-mss-channel-native.h"
#if EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE && EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE
#define PMSY_TOTAL UINT64_C(192000000)
#define PMSY_POLL UINT64_C(192000)
struct pmsy_state {
    uint64_t channel,owner,opening,started,next_poll;
    struct polaris_glink_workspace inventory;
    uint32_t in_offset,in_bytes,in_header,in_index,in_flags;
    uint8_t header[16],out[340],in[340],again[340];
    uint32_t attempted,unknown,error,phase,polls,complete;
    uint8_t digest[32];uint8_t current_out[340],current_in[340];uint32_t checks;
};
static inline int pmsy_fail(struct pmsy_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;if(s->channel)pmsx_fail((void*)(uintptr_t)s->channel,5);return 0;}
static inline int pmsy_live(struct pmsy_state*s)
{
    if(!s||!s->attempted||s->unknown||s->error)return 0;struct pmsx_state*x=(void*)(uintptr_t)s->channel;
    return x->negotiation==(uintptr_t)s&&x->owner==s->owner&&x->opening==s->opening&&pmsx_live(x);
}
static inline bool pmsy_read(void*context,uint32_t offset,void*out,size_t bytes)
{
    struct pmsy_state*s=context;if(!pmsy_live(s)||!out||!bytes||((offset|bytes)&3))return false;
    for(size_t at=0;at<bytes;){unsigned n=(unsigned)(bytes-at);if(n>PMSQ_CHUNK)n=PMSQ_CHUNK;
        const uint8_t*raw=pmsx_read((void*)(uintptr_t)s->channel,offset+(unsigned)at,n);if(!raw)return false;
        pgcd_copy((uint8_t*)out+at,raw,n);at+=n;
    }return pmsy_live(s);
}
static inline int pmsy_begin(struct pmsy_state*s,struct pmsx_state*x)
{
    if(!s||!x||!pwmc_zero(s,sizeof(*s))||!pmsx_live(x)||x->negotiation||x->negotiated||x->pending||x->writes||x->rings)return 0;
    struct pmsn_state*a=(void*)(uintptr_t)x->auth;struct pmsa_state*m=(void*)(uintptr_t)x->allocation;
    if(!pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    const uint64_t at[]={(uintptr_t)x,(uintptr_t)a,a->records,a->copy,a->segments,(uintptr_t)m,x->smem,m->lock};
    const uint64_t bytes[]={sizeof(*x),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,sizeof(*m),sizeof(struct pmsq_state),sizeof(struct pmsl_lock)};
    for(unsigned n=0;n<8;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    s->channel=(uintptr_t)x;s->owner=x->owner;s->opening=x->opening;s->attempted=1;s->phase=1;x->negotiation=(uintptr_t)s;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;s->started=o->last;return pmsy_live(s);
}
/* Metadata may be in transition while the remote allocates its entry. No
 * entry address escapes until the selected allocation/header has been read
 * again; native faults remain sticky in the underlying reader/channel. */
static inline int pmsy_find(struct pmsy_state*s)
{
    struct polaris_glink_workspace*w=&s->inventory;for(unsigned n=0;n<sizeof(*w);n++)((uint8_t*)w)[n]=0;
    struct polaris_smem_reader reader={pmsy_read,s,PMSQ_BYTES};
    if(!polaris_smem_inventory(&reader,&w->inventory,&w->smem))return 0;
    const struct polaris_smem_part*p=0;
    for(unsigned n=0;n<w->inventory.count;n++){
        const struct polaris_smem_part*q=&w->inventory.parts[n];
        if(q->accessible&&((!q->host0&&q->host1==1)||(!q->host1&&q->host0==1))){if(p)return 0;p=q;}
    }
    if(!p||p->offset!=0xb9000||p->bytes!=0x7c000||p->cacheline!=32||p->flags||
       p->exclusions[0]||p->exclusions[1]||p->exclusions[2]||p->exclusions[3]||
       !pgl_headers(&reader,p,w,false)||!pgl_headers(&reader,p,w,true))return 0;
    struct pmsx_state*x=(void*)(uintptr_t)s->channel;unsigned own=0,found=0;
    uint32_t in=0,in_header=0;uint8_t selected[16];
    for(unsigned n=0;n<w->count;n++){
        const struct polaris_glink_witness*h=&w->headers[n];unsigned id=psm_u16(h->bytes+2);
        for(unsigned j=0;j<PMSA_ITEMS;j++)if(id==x->item[j].id){
            if(h->offset!=x->item[j].header||!pgcd_equal(h->bytes,x->item[j].wire,16))return 0;own++;
        }
        if(id!=435)continue;
        if(h->offset>=p->offset+p->uncached_end||psm_u32(h->bytes+4)!=344||psm_u16(h->bytes+8)!=4||psm_u16(h->bytes+10))return 0;
        in=h->offset+16;in_header=h->offset;pgcd_copy(selected,h->bytes,16);found++;
    }
    uint8_t again[32];
    if(own!=PMSA_ITEMS||found!=1||!pmsy_read(s,in_header,again,16)||!pgcd_equal(again,selected,16)||
       !pmsy_read(s,p->offset,again,32)||!pgcd_equal(again,w->smem.part_headers[p->index],32))return 0;
    s->in_offset=in;s->in_bytes=340;s->in_header=in_header;pgcd_copy(s->header,selected,16);return 1;
}
/* 0=sticky refusal,1=bounded wait/work,2=matched version/features and named
 * local/remote entries. Real counter, existing180s owner, no time renewal. */
static inline int pmsy_step(struct pmsy_state*s)
{
    if(!pmsy_live(s))return 0;struct pmsx_state*x=(void*)(uintptr_t)s->channel;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(s->complete)return pmsy_current(s,x)?2:0;
    if(o->last<s->started||o->last-s->started>PMSY_TOTAL)return pmsy_fail(s,1);
    if(s->phase==1){
        if(!pmsy_read(s,x->item[0].data,s->out,340)||!pwmc_zero(s->out,340))return pmsy_fail(s,2);
        const uint32_t offsets[]={0,8,12,16,4,4},values[]={0x504d5324,0x10000,16,0,0x100,0x101};
        for(unsigned n=0;n<6;n++)if(!pmsx_write(x,0,offsets[n],values[n]))return pmsy_fail(s,2);
        if(!pmsx_ring(x,0))return pmsy_fail(s,2);s->phase=2;
    }
    if(o->last<s->next_poll)return 1;
    if(s->polls==1024)return pmsy_fail(s,1);s->polls++;s->next_poll=o->last+PMSY_POLL;
    if(!s->in_offset&&!pmsy_find(s))return pmsy_live(s)?1:pmsy_fail(s,3);
    if(!pmsy_read(s,s->in_offset,s->in,340)||!pmsy_read(s,s->in_offset,s->again,340))return pmsy_fail(s,3);
    if(!pgcd_equal(s->in,s->again,340))return 1;
    if(!(pms_u32(s->in+4)&255)||!(pms_u32(s->in+12)>>16))return 1;
    struct pms_view in;if(!pms_parse(s->in,1,&in)||(in.value&9))return pmsy_fail(s,4);
    if(in.flags&2)return 1; /* New APPS has restart_done0; wait for matching remote ACK. */
    s->in_index=in.index;s->in_flags=in.flags;
    if(!pmsx_write(x,0,16,(in.flags&1)?2:0))return pmsy_fail(s,4);
    static const uint8_t name[16]="master-kernel";
    for(unsigned n=0;n<4;n++)if(!pmsx_write(x,0,20+4*n,pms_u32(name+4*n)))return pmsy_fail(s,4);
    if(!pmsx_write(x,0,12,0x10010)||!pmsx_ring(x,0)||!pmsy_read(s,x->item[0].data,s->out,340)||
       !pmsy_read(s,s->in_offset,s->again,340))return pmsy_fail(s,4);
    struct pms_view out,latest;
    if(!pms_parse(s->out,0,&out)||out.index||out.value||out.valid!=1||out.flags!=((in.flags&1)?2u:0u)||
       !pms_parse(s->again,1,&latest)||latest.index!=in.index||latest.flags!=in.flags||(latest.value&9))return pmsy_fail(s,4);
    s->phase=3;s->complete=1;pweh_digest(s,offsetof(struct pmsy_state,digest),s->digest);x->negotiated=1;return 2;
}
static inline int pmsy_current(struct pmsy_state*s,struct pmsx_state*x)
{
    if(!s||!x||s->channel!=(uintptr_t)x||s->complete!=1||s->phase!=3||x->negotiated!=1||!pmsy_live(s))return 0;
    uint8_t hash[32];pweh_digest(s,offsetof(struct pmsy_state,digest),hash);
    if(!pgcd_equal(hash,s->digest,32)||!pmsy_read(s,x->item[0].data,s->current_out,340)||
       !pmsy_read(s,s->in_offset,s->current_in,340))return pmsy_fail(s,5);
    struct pms_view in;
    if(!pgcd_equal(s->current_out,s->out,340)||!pms_parse(s->current_in,1,&in)||in.index!=s->in_index||
       in.flags!=s->in_flags||(in.value&9))return pmsy_fail(s,5);
    s->checks++;return 1;
}
#endif
#endif
