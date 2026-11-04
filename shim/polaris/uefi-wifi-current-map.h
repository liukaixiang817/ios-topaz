/* Later parent evidence at its EXISTING opening/retirement GetMap. This captures
 * real payload/global/source inputs, not an allocation/IRQ/remote-memory
 * capability. Initial GetMap transitive work still requires qualification. */
#ifndef POLARIS_UEFI_WIFI_CURRENT_MAP_H
#define POLARIS_UEFI_WIFI_CURRENT_MAP_H
#include "uefi-wifi-remote-memory.h"
#include "uefi-wifi-parent-images.h"
#include "payload.h"
#define PCMP_HEADER_CAP (sizeof(struct polaris_payload)+64*sizeof(struct polaris_segment))
enum pcmp_path {PCMP_QUERY_PAIR,PCMP_PREPARATION_PAIR,PCMP_CLIENT_OPEN};
#define PCMP_PARENT_CONTEXTS 6u
struct pcmp_payload {
    uint64_t address,bytes,header_bytes;struct polaris_plan plan;
    uint32_t attempted,complete,unknown,reserved;
    uint8_t header[PCMP_HEADER_CAP],digest[32];
};
struct pcmp_input {
    struct pgcd_context*context;const struct efi_loaded*image;
    const struct ppli_result*images;const struct pcmp_payload*payload_binding;
    const volatile uint32_t*native_flag,*load_state;
    uint8_t*const volatile*payload_slot;uint8_t*const volatile*log_slot;
    const volatile uint64_t*received,*payload_count;const struct polaris_plan*plan;
    uint64_t image_handle,bank,bank_bytes,log_bytes;
};
struct pcmp_result {
    struct pcmp_input input;struct pgcd_io original_io;
    struct pgcd_context context_before;struct pgcd_lifetime ticket_before;
    struct pgcd_result source_before;struct pcmp_payload payload_before;struct ppli_result images_before;
    uint64_t payload,log,received,payload_count;uint32_t load_state,native,slot,path;
    struct polaris_plan plan;uint64_t boot_address;uint8_t BS_before[PWMC_BS_BYTES];struct efi_loaded image_before;
    uint8_t images_digest[32],binding_digest[32];
    struct pwmc_parent_map call;
    struct ppli_at header_AT;struct pgcd_arch final_arch;
    uint8_t header[PCMP_HEADER_CAP];
    uint32_t attempted,complete,unknown,error,header_bytes,arch_issued,arch_returned,map_issued,map_returned;
    uint8_t digest[32];
};
_Static_assert(PCMP_HEADER_CAP==2728&&PCMP_HEADER_CAP<=4096,"complete bounded payload metadata fits the one admitted source page");
_Static_assert(sizeof(struct pcmp_payload)==2832,"validated payload metadata raw ABI");
_Static_assert(sizeof(struct pcmp_input)==120&&sizeof(struct pcmp_result)==356688,"later parent input and full raw ABI");
_Static_assert(offsetof(struct pcmp_result,call)==286496&&offsetof(struct pcmp_result,digest)==356652,"separate later-parent decoder offsets");
static inline int pcmp_payload_bind(struct pcmp_payload*r,const void*payload,uint64_t bytes,const struct polaris_plan*plan)
{
    if(!r||!payload||!plan||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=r->unknown=1;
    if((uintptr_t)payload&4095||bytes<sizeof(struct polaris_payload)||bytes>POLARIS_PAYLOAD_LIMIT)return 0;
    const struct polaris_payload*p=payload;
    if(!p->nsegs||p->nsegs>64||sizeof(*p)+p->nsegs*sizeof(p->segs[0])>bytes)return 0;
    r->address=(uintptr_t)payload;r->bytes=bytes;r->header_bytes=sizeof(*p)+p->nsegs*sizeof(p->segs[0]);r->plan=*plan;
    pgcd_copy(r->header,payload,r->header_bytes);r->complete=1;r->unknown=0;
    ppli_sha(r,offsetof(struct pcmp_payload,digest),r->digest);return 1;
}
static inline int pcmp_fail(struct pcmp_result*r,unsigned e)
{if(!r->error)r->error=e;r->unknown=1;return 0;}
struct pcmp_live {
    struct pcmp_result*r;struct pcmp_input input;struct pgcd_io original_io;
    const struct pcmp_input*caller_input;const struct pgcd_io*caller_io;
    uint8_t seal[32],call_digest[32];unsigned map_copied,map_issued,map_returned,header_started,header_copied;
};
#if defined(POLARIS_WIFI_CURRENT_GRAPH_INPUT)
/* Defined by the actual parent, while this caller's stack is still active. */
static int pcmp_parent_graph(struct pcmp_live*,int(*)(struct ppli_at*));
#endif
static inline int pcmp_source_equal(const struct pcmp_live*l)
{
    const struct pgcd_result*now=l->input.context->record,*old=&l->r->source_before;
    if(!l->map_copied)return pgcd_equal(now,old,sizeof(*old));
    const size_t start=offsetof(struct pgcd_result,maps)+l->r->slot*PGCD_MAP_CAP,tail=start+PGCD_MAP_CAP;
    const struct pwmc_parent_map*call=&l->r->call;
    return pgcd_equal(now,old,start)&&pgcd_equal((const uint8_t*)now+tail,(const uint8_t*)old+tail,sizeof(*old)-tail)&&
        call->map.bytes<=PGCD_MAP_CAP&&pgcd_equal(now->maps[l->r->slot],call->data,call->map.bytes)&&
        pgcd_equal(now->maps[l->r->slot]+call->map.bytes,old->maps[l->r->slot]+call->map.bytes,PGCD_MAP_CAP-call->map.bytes);
}
/* Compare typed pointer bytes before following a context potentially changed
 * by a callback. Local copies select the original pointers and function ABI. */
/* DATA closure is shared with the later graph. Native admission remains
 * at the original guarded reader: pcmp_stable samples its original flag;
 * the graph records the shared walk's own pre/post native reads instead of
 * silently adding unrecorded native samples at every DATA comparison. */
static inline int pcmp_source_prefix(const struct pcmp_live*l)
{
    const struct pcmp_input*i=&l->input;struct pcmp_result*r=l->r;uint8_t actual[32];
    ppli_sha(r,offsetof(struct pcmp_result,binding_digest),actual);
    if(!pgcd_equal(actual,l->seal,32)||!pgcd_equal(r->binding_digest,l->seal,32)||
       !pgcd_equal(&r->input,i,sizeof(*i))||!pgcd_equal(&r->original_io,&l->original_io,sizeof(l->original_io))||
       !pgcd_equal(l->caller_input,i,sizeof(*i))||!pgcd_equal(l->caller_io,&l->original_io,sizeof(l->original_io))||
       !pgcd_equal(i->context,&r->context_before,sizeof(r->context_before)))return 0;
    if(l->map_copied){ppli_sha(&r->call,offsetof(struct pwmc_parent_map,digest),actual);if(!pgcd_equal(actual,l->call_digest,32))return 0;}
    if(!pgcd_equal(i->context->ticket,&r->ticket_before,sizeof(r->ticket_before))||!pcmp_source_equal(l)||
       !pgcd_equal(i->payload_binding,&r->payload_before,sizeof(r->payload_before))||
       !pgcd_equal(i->images,&r->images_before,sizeof(r->images_before)))return 0;
    return 1;
}
static inline int pcmp_source_suffix(const struct pcmp_live*l)
{
    const struct pcmp_input*i=&l->input;const struct pcmp_result*r=l->r;
    if(*i->load_state!=r->load_state||
       (uintptr_t)*i->payload_slot!=r->payload||(uintptr_t)*i->log_slot!=r->log||
       *i->received!=r->received||*i->payload_count!=r->payload_count||!pgcd_equal(i->plan,&r->plan,sizeof(r->plan)))return 0;
    if((uintptr_t)l->original_io.system->boot!=r->boot_address||
       !pgcd_equal((const void*)(uintptr_t)r->boot_address,r->BS_before,PWMC_BS_BYTES)||
       !pgcd_equal(i->image,&r->image_before,sizeof(r->image_before)))return 0;
    if(!l->header_started&&!pwmc_zero(&r->header_AT,sizeof(r->header_AT)))return 0;
    if(!l->header_copied){
        if(r->header_bytes||r->arch_issued||r->arch_returned||!pwmc_zero(&r->final_arch,sizeof(r->final_arch))||
           !pwmc_zero(r->header,sizeof(r->header)))return 0;
    }else if(r->header_bytes!=r->payload_before.header_bytes||!pgcd_equal(r->header,r->payload_before.header,r->header_bytes)||
        !pwmc_zero(r->header+r->header_bytes,PCMP_HEADER_CAP-r->header_bytes)||r->header_AT.page!=r->payload||
        r->header_AT.saved!=r->header_AT.restored||r->header_AT.issued!=1||r->header_AT.returned!=1||
        r->header_AT.par!=(UINT64_C(0xff00000000000b80)|r->payload)||r->header_AT.native_issued!=3||r->header_AT.native_returned!=3||
        !pwmc_zero(r->header_AT.native,sizeof(r->header_AT.native)))return 0;
    return r->attempted==1&&r->unknown==1&&!r->complete&&!r->error&&r->map_issued==l->map_issued&&r->map_returned==l->map_returned;
}
static inline int pcmp_source_stable(const struct pcmp_live*l)
{return pcmp_source_prefix(l)&&pcmp_source_suffix(l);}
static inline int pcmp_stable(const struct pcmp_live*l)
{return pcmp_source_prefix(l)&&!*l->input.native_flag&&pcmp_source_suffix(l);}
/* The actual relay control is still on this caller's stack. Compare its
 * complete bytes after a callback before following any pointer it contains. */
static inline int pcmp_arch(void*opaque,struct pgcd_arch*a)
{
    struct pcmp_live*l=opaque;if(!pcmp_stable(l))return 0;
    struct pcmp_result*r=l->r;uint8_t before[32],after[32];ppli_sha(l,sizeof(*l),before);
    int ok=l->original_io.arch(l->original_io.opaque,a);
    ppli_sha(l,sizeof(*l),after);if(!pgcd_equal(before,after,32))return pcmp_fail(r,8);
    if(!pcmp_stable(l)||!ok)return 0;
    uint64_t opening=l->r->source_before.before.cpu.ticks;
    return opening&&a->cpu.ticks>=opening&&a->cpu.ticks-opening<=PGCD_FRESH_TICKS;
}
static inline int pcmp_save(void*opaque,struct pgcd_fp_guard*g)
{
    struct pcmp_live*l=opaque;if(!pcmp_stable(l))return 0;
    struct pcmp_result*r=l->r;uint8_t before[32],after[32];ppli_sha(l,sizeof(*l),before);
    int ok=l->original_io.fp_save(l->original_io.opaque,g);
    ppli_sha(l,sizeof(*l),after);if(!pgcd_equal(before,after,32))return pcmp_fail(r,8);
    return pcmp_stable(l)&&ok;
}
static inline int pcmp_restore(void*opaque,struct pgcd_fp_guard*g)
{
    struct pcmp_live*l=opaque;if(!pcmp_stable(l))return 0;
    struct pcmp_result*r=l->r;uint8_t before[32],after[32];ppli_sha(l,sizeof(*l),before);
    int ok=l->original_io.fp_restore(l->original_io.opaque,g);
    ppli_sha(l,sizeof(*l),after);if(!pgcd_equal(before,after,32))return pcmp_fail(r,8);
    return pcmp_stable(l)&&ok;
}
static inline int pcmp_map(void*opaque,struct efi_system*s,struct pgcd_map*m,void*data)
{
    struct pcmp_live*l=opaque;if(!pcmp_stable(l)||l->map_issued)return 0;
    l->map_issued=l->r->map_issued=1;
    struct pcmp_result*r=l->r;uint8_t before[32],after[32];ppli_sha(l,sizeof(*l),before);
    int ok=l->original_io.map(l->original_io.opaque,s,m,data);
    ppli_sha(l,sizeof(*l),after);if(!pgcd_equal(before,after,32))return pcmp_fail(r,8);
    if(!pcmp_stable(l))return 0;l->map_returned=l->r->map_returned=ok?1:0;return pcmp_stable(l)&&ok;
}
static inline void pcmp_order(void*opaque)
{
    struct pcmp_live*l=opaque;if(!pcmp_stable(l))return;
    struct pcmp_result*r=l->r;uint8_t before[32],after[32];ppli_sha(l,sizeof(*l),before);
    l->original_io.order(l->original_io.opaque);ppli_sha(l,sizeof(*l),after);
    if(!pgcd_equal(before,after,32)){
        (void)pcmp_fail(r,8);(void)pwmc_parent_fail(&r->call,PWMC_CONTEXT);
    }
}
static inline int pcmp_in_self(const struct efi_loaded*self,const volatile void*p,uint64_t bytes)
{return pwmc_parent_in_image(self,(uintptr_t)p,bytes);}
static __attribute__((noinline)) int pcmp_post(struct pcmp_live*live,int(*page_read)(struct ppli_at*))
{
    struct pcmp_result*r=live->r;struct pcmp_input in=live->input;uint8_t hash[32];
    ppli_sha(&r->call,offsetof(struct pwmc_parent_map,digest),live->call_digest);
    if(!pgcd_equal(live->call_digest,r->call.digest,32))return pcmp_fail(r,4);
    live->map_copied=1;if(!pcmp_stable(live))return pcmp_fail(r,4);
    if(!pwmc_zero(&r->header_AT,sizeof(r->header_AT))||!pwmc_zero(&r->final_arch,sizeof(r->final_arch))||
       !pwmc_zero(r->header,sizeof(r->header))||!pwmc_zero(r->digest,sizeof(r->digest))||r->header_bytes||r->arch_issued||r->arch_returned)return pcmp_fail(r,4);
    uint8_t call_digest[32];ppli_sha(&r->call,offsetof(struct pwmc_parent_map,digest),call_digest);
    if(!pgcd_equal(call_digest,r->call.digest,32))return pcmp_fail(r,4);
    live->header_started=1;r->header_AT=(struct ppli_at){.page=r->payload,.native_issued=1,.native_returned=1};
    r->header_AT.native[0]=*in.native_flag;if(r->header_AT.native[0])return pcmp_fail(r,5);
    uint8_t control[32],control_after[32];ppli_sha(live,sizeof(*live),control);
    int translated=page_read(&r->header_AT);
    ppli_sha(live,sizeof(*live),control_after);if(!pgcd_equal(control,control_after,32))return pcmp_fail(r,8);
    if(!pcmp_stable(live)||!translated||r->header_AT.page!=r->payload||r->header_AT.saved!=r->header_AT.restored||
       r->header_AT.issued!=1||r->header_AT.returned!=1||r->header_AT.par!=(UINT64_C(0xff00000000000b80)|r->payload)||
       r->header_AT.native_issued!=1||r->header_AT.native_returned!=1||r->header_AT.native[0]||r->header_AT.native[1]||
       r->header_bytes||r->arch_issued||r->arch_returned||!pwmc_zero(&r->final_arch,sizeof(r->final_arch))||
       !pwmc_zero(r->header,sizeof(r->header)))return pcmp_fail(r,5);
    r->header_AT.native_issued=3;r->header_AT.native[1]=*in.native_flag;r->header_AT.native_returned=3;
    if(r->header_AT.native[1])return pcmp_fail(r,5);
    r->header_bytes=(uint32_t)r->payload_before.header_bytes;pgcd_copy(r->header,(const void*)(uintptr_t)r->payload,r->header_bytes);
    if(!pgcd_equal(r->header,r->payload_before.header,r->header_bytes)||!pwmc_zero(r->header+r->header_bytes,PCMP_HEADER_CAP-r->header_bytes))return pcmp_fail(r,5);
    live->header_copied=1;uint8_t header_digest[32];struct pwfi_sha256 hh;pwfi_init(&hh);
    for(size_t n=0;n<sizeof(r->header_AT);n++)pwfi_byte(&hh,((const uint8_t*)&r->header_AT)[n]);
    for(size_t n=0;n<sizeof(r->header);n++)pwfi_byte(&hh,r->header[n]);pwfi_final(&hh,header_digest);
    r->arch_issued=1;int observed=pcmp_arch(live,&r->final_arch);r->arch_returned=observed?1:0;
    if(!observed||!pcmp_stable(live)||!pwfc_arch_stable(&r->call.before.cpu,&r->final_arch.cpu)||r->final_arch.cpacr!=r->call.before.cpacr||
       r->final_arch.cpu.daif||r->final_arch.cpu.group1!=1||r->final_arch.cpu.ticks<r->source_before.before.cpu.ticks||
       r->final_arch.cpu.ticks-r->source_before.before.cpu.ticks>PGCD_FRESH_TICKS)return pcmp_fail(r,6);
    pwfi_init(&hh);for(size_t n=0;n<sizeof(r->header_AT);n++)pwfi_byte(&hh,((const uint8_t*)&r->header_AT)[n]);
    for(size_t n=0;n<sizeof(r->header);n++)pwfi_byte(&hh,r->header[n]);pwfi_final(&hh,hash);
    if(!pgcd_equal(hash,header_digest,32)||r->header_bytes!=r->payload_before.header_bytes||r->arch_issued!=1||r->arch_returned!=1)return pcmp_fail(r,6);
    ppli_sha(in.images,offsetof(struct ppli_result,digest),hash);if(!pgcd_equal(hash,r->images_digest,32))return pcmp_fail(r,6);
    ppli_sha(&r->call,offsetof(struct pwmc_parent_map,digest),hash);if(!pgcd_equal(hash,call_digest,32))return pcmp_fail(r,6);
#if defined(POLARIS_WIFI_CURRENT_GRAPH_INPUT)
    if(!pcmp_parent_graph(live,page_read))return pcmp_fail(r,7);
#endif
    return 1;
}
static inline int pcmp_read_path(struct pcmp_result*r,const struct pcmp_input*input,const struct pgcd_io*original_io,
    struct pgcd_map*output,void*data,int(*page_read)(struct ppli_at*),unsigned path)
{
    if(!r||!input||!original_io||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=r->unknown=1;
    struct pcmp_input in=*input;struct pgcd_io io=*original_io;
    r->input=in;r->original_io=io;
    if(!in.context||!in.image||!in.images||!in.payload_binding||!in.native_flag||!in.load_state||!in.payload_slot||!in.log_slot||
       !in.received||!in.payload_count||!in.plan||!in.image_handle||!page_read||!io.system||!io.arch||!io.map||!io.fp_save||!io.fp_restore||!io.order)return pcmp_fail(r,1);
    const struct efi_loaded*self=in.image;struct pgcd_context*c=in.context;
    if(self->revision!=0x1000||self->system!=io.system||self->code_type!=3||self->data_type!=4||
       !pcmp_in_self(self,r,sizeof(*r))||!pcmp_in_self(self,c,sizeof(*c))||!pcmp_in_self(self,c->record,sizeof(*c->record))||
       !pcmp_in_self(self,c->ticket,sizeof(*c->ticket))||!pcmp_in_self(self,in.images,sizeof(*in.images))||
       !pcmp_in_self(self,in.payload_binding,sizeof(*in.payload_binding))||!pcmp_in_self(self,in.native_flag,4)||
       !pcmp_in_self(self,in.load_state,4)||!pcmp_in_self(self,in.payload_slot,8)||!pcmp_in_self(self,in.log_slot,8)||
       !pcmp_in_self(self,in.received,8)||!pcmp_in_self(self,in.payload_count,8)||!pcmp_in_self(self,in.plan,sizeof(*in.plan)))return pcmp_fail(r,1);
    r->context_before=*c;r->ticket_before=*c->ticket;r->source_before=*c->record;
    struct pgcd_io expected=io;expected.map=c->io.map;
    unsigned slot=output==&c->record->map[0]?0:output==&c->record->map[1]?1:2;
    if(path>PCMP_CLIENT_OPEN||slot>1||(path==PCMP_CLIENT_OPEN&&slot)||c->stage!=2||c->opened!=slot||
       c->finished!=(path==PCMP_QUERY_PAIR?slot:0)||c->ticket->spent!=1||c->ticket->result!=(uintptr_t)c->record||
       c->record->attempted!=1||c->record->uncertain||c->record->error||c->record->phase!=slot||!c->record->before.cpu.ticks||
       c->io.map==io.map||!pgcd_equal(&c->io,&expected,sizeof(expected))||c->record->self_bound!=1||
       c->record->self_owner_address!=(uintptr_t)in.image||!pgcd_equal(&c->record->self_owner,in.image,sizeof(*in.image))||
       c->record->outstanding!=0x20000u+slot||data!=c->record->maps[slot]||
       output->issued!=1||output->returned||output->valid||output->bytes!=PGCD_MAP_CAP||
       !c->record->map_guard[slot].entered||!c->record->map_guard[slot].unknown||!c->record->map_guard[slot].fp.saved||
       (slot&&(c->record->pre_mask!=(path==PCMP_QUERY_PAIR?15u:0u)||c->record->post_mask!=(path==PCMP_QUERY_PAIR?15u:0u)||c->record->map[0].valid!=1||
        c->record->map[0].status||!c->record->map[0].key||c->record->map[0].version!=1||
        c->record->map[0].issued!=1||c->record->map[0].returned!=1)))return pcmp_fail(r,2);
    r->payload_before=*in.payload_binding;r->images_before=*in.images;r->payload=(uintptr_t)*in.payload_slot;r->log=(uintptr_t)*in.log_slot;
    if(path!=PCMP_QUERY_PAIR&&(c->record->pre_mask||c->record->post_mask||c->record->prestart_count||
       !pwmc_zero(c->record->query,sizeof(c->record->query))))return pcmp_fail(r,2);
    r->received=*in.received;r->payload_count=*in.payload_count;r->load_state=*in.load_state;r->native=*in.native_flag;r->plan=*in.plan;r->slot=slot;r->path=path;
    r->boot_address=(uintptr_t)io.system->boot;
    if(r->boot_address<0x1b800||((r->boot_address-0x1b800)&4095))return pcmp_fail(r,3);
    pgcd_copy(r->BS_before,io.system->boot,PWMC_BS_BYTES);r->image_before=*in.image;
    uint8_t hash[32];ppli_sha(in.images,offsetof(struct ppli_result,digest),hash);
    if(!in.images->complete||in.images->unknown||in.images->error||!in.images->count||in.images->count>PPLI_MAX||in.images->own_handle!=in.image_handle||
       in.images->native_flag!=(uintptr_t)in.native_flag||!pgcd_equal(hash,in.images->digest,32))return pcmp_fail(r,3);
    unsigned own=0;
    for(unsigned n=0;n<in.images->count;n++)if(in.images->entry[n].handle==in.image_handle){
        own++;if(in.images->entry[n].address!=(uintptr_t)in.image||!pgcd_equal(&in.images->entry[n].image[1],in.image,sizeof(*in.image)))return pcmp_fail(r,3);
    }
    if(own!=1)return pcmp_fail(r,3);
    pgcd_copy(r->images_digest,hash,32);ppli_sha(&r->payload_before,offsetof(struct pcmp_payload,digest),hash);
    if(r->native||r->load_state!=2||!r->payload_count||r->payload_count!=r->received||r->payload_count>POLARIS_PAYLOAD_LIMIT||
       r->payload_before.attempted!=1||r->payload_before.complete!=1||r->payload_before.unknown||
       r->payload_before.address!=r->payload||r->payload_before.bytes!=r->payload_count||!pgcd_equal(hash,r->payload_before.digest,32)||
       !pgcd_equal(&r->payload_before.plan,&r->plan,sizeof(r->plan))||r->payload_before.header_bytes<sizeof(struct polaris_payload)||
       r->payload_before.header_bytes>PCMP_HEADER_CAP)return pcmp_fail(r,3);
    struct pcmp_live live={.r=r,.input=in,.original_io=io,.caller_input=input,.caller_io=original_io};
    ppli_sha(r,offsetof(struct pcmp_result,binding_digest),live.seal);pgcd_copy(r->binding_digest,live.seal,32);
    const struct pwmc_parent_input call={.system=io.system,.image=in.image,.native_flag=in.native_flag,.output=data,.capacity=PGCD_MAP_CAP,
        .image_handle=in.image_handle,.phase=3,.bank=in.bank,.bank_bytes=in.bank_bytes,
        .payload=r->payload,.payload_bytes=r->payload_count,.log_snapshot=r->log,.log_snapshot_bytes=in.log_bytes};
    const struct pgcd_io relay={.opaque=&live,.system=io.system,.arch=pcmp_arch,.map=pcmp_map,.fp_save=pcmp_save,.fp_restore=pcmp_restore,.order=pcmp_order};
    if(!pwmc_parent_map_call(&r->call,&call,&relay))return pcmp_fail(r,4);
    if(!pcmp_post(&live,page_read))return 0;
    *output=r->call.map;r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pcmp_result,digest),r->digest);return 1;
}
static inline int pcmp_read(struct pcmp_result*r,const struct pcmp_input*input,const struct pgcd_io*original_io,
    struct pgcd_map*output,void*data,int(*page_read)(struct ppli_at*))
{return pcmp_read_path(r,input,original_io,output,data,page_read,PCMP_QUERY_PAIR);}
/* The real preparation/client constructors copy final->io, but bind their own
 * source and spent-once ticket. Select by the parent's closed object list BEFORE
 * following context->record/ticket. A foreign map never selects a fallback. */
struct pcmp_route {
    struct pgcd_context*context;struct pgcd_result*source;struct pgcd_lifetime*ticket;
    struct pcmp_result*frames;uint32_t path,reserved;
};
struct pcmp_route_fault {
    uint64_t opaque,system,map,data;uint32_t attempted,unknown,index,slot;
};
_Static_assert(sizeof(struct pcmp_route)==40&&sizeof(struct pcmp_route_fault)==48,"complete parent dispatch layout");
static inline int pcmp_select(const struct pcmp_route*routes,unsigned count,const struct pgcd_map*map,const void*data,
    unsigned*index,unsigned*slot)
{
    if(!routes||count!=PCMP_PARENT_CONTEXTS||!index||!slot)return 0;
    unsigned matches=0,chosen=0,part=0;
    for(unsigned n=0;n<count;n++){
        const struct pcmp_route*a=&routes[n];
        if(!a->context||!a->source||!a->ticket||!a->frames||a->path>PCMP_CLIENT_OPEN||a->reserved)return 0;
        for(unsigned j=0;j<n;j++)if(a->context==routes[j].context||a->source==routes[j].source||
            a->ticket==routes[j].ticket||a->frames==routes[j].frames)return 0;
        for(unsigned k=0;k<2;k++)if(map==&a->source->map[k]){matches++;chosen=n;part=k;}
    }
    if(matches!=1||data!=routes[chosen].source->maps[part]||(part&&routes[chosen].path==PCMP_CLIENT_OPEN))return 0;
    *index=chosen;*slot=part;return 1;
}
static inline int pcmp_route_read(const struct pcmp_route*route,unsigned slot,const struct pcmp_input*common,
    const struct pgcd_io*original_io,struct pgcd_map*map,void*data,int(*page_read)(struct ppli_at*))
{
    if(!route||!common||!original_io||slot>1)return 0;
    struct pgcd_context*c=route->context;struct pgcd_result*s=route->source;
    if(c->record!=s||c->ticket!=route->ticket||s->self_owner_address!=(uintptr_t)common->image||
       map!=&s->map[slot]||data!=s->maps[slot]||route->path>PCMP_CLIENT_OPEN||route->reserved||
       (route->path==PCMP_CLIENT_OPEN&&slot))return 0;
    if(slot){
        const struct pcmp_result*first=&route->frames[0];uint8_t hash[32];
        ppli_sha(first,offsetof(struct pcmp_result,digest),hash);
        if(first->attempted!=1||first->complete!=1||first->unknown||first->error||first->slot||first->path!=route->path||
           !pgcd_equal(hash,first->digest,32)||first->input.context!=c||first->context_before.record!=s||
           first->context_before.ticket!=route->ticket||!pgcd_equal(&first->ticket_before,route->ticket,sizeof(*route->ticket))||
           !pgcd_equal(&first->source_before.before,&s->before,sizeof(s->before)))return 0;
    }
    struct pcmp_input input=*common;input.context=c;
    return pcmp_read_path(&route->frames[slot],&input,original_io,map,data,page_read,route->path);
}
#endif
