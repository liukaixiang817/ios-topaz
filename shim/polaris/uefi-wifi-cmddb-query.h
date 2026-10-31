/* Source-bound original CmdDb query adapter for the next RPMh transaction.
 * It is deliberately NOT a standalone boot feature. The power caller must
 * include its result in the same lifetime/UNKNOWN gate before any command.
 * Query has a This argument and separate EFI64 / CmdDb32 results. No Init,
 * SMEM getter/allocator, map attribute change, radio or power action here. */
#ifndef POLARIS_UEFI_WIFI_CMDDB_QUERY_H
#define POLARIS_UEFI_WIFI_CMDDB_QUERY_H
#ifndef EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE
#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-rpmh-readonly.h"
#include "../../tools/polaris-wifi-cmddb-identity.h"
#define PWCD_DB_BYTES 0x20000u
/* Original0154 live CmdDb cached AND platform pointers, with five source
 * hashes and relocated protocol table verified, identify this separate RO
 * namespace. Android's cmd-db node uses c3f000c indirection; its node name
 * is not a physical mapping. This singleton does not change own SMEM bounds
 * or grant a read before the original GCD + exact NS/WB AT checks below. */
#define PWCD_UEFI_DB_BASE UINT64_C(0x85fe0000)
#define PWCD_PAGES (PWCD_DB_BYTES/4096u)
#define PWCD_RESOURCES 3u
#define PWCD_CALLS (2u*(2u+PWCD_PAGES+PWCD_RESOURCES))
struct pwcd_message {uint8_t query[24],response[32],aux[32];uint32_t result;uint64_t EFI_status;};
struct pwcd_resource {uint32_t entry,aux_offset,address,priority[2],length,version,index;uint8_t entry_raw[24],aux[32];};
struct pwcd_result {
    uint32_t attempted,error,unknown,outstanding,issued,returned,owner_matches,stable;
    uint64_t image,owner_address,protocol[2],protocol_status[2],database[2],identity_address,identity_par;
    struct efi_loaded owner;struct paic_arch before,after;
    struct paic_map_sample maps[2];uint8_t map_raw[2][4096],protocol_raw[2][72],globals[2][72];
    /* Per pass: one source read + three immediate pre-query checkpoints;
     * slot8 is the final post-query checkpoint. Every digest is retained. */
    uint8_t hashes[9][5][32];uint32_t hash_count[9],hash_failed[9],database_bytes[2],verified_bytes[2],rereads[2];
    struct pgcd_service_guard guard[PWCD_CALLS];
    struct pgcd_observation namespace[2][PWCD_PAGES];
    uint32_t descriptor_page[2][PWCD_PAGES];
    struct pwcd_resource resources[2][PWCD_RESOURCES];struct pwcd_message messages[2][PWCD_RESOURCES];
    uint8_t database_raw[2][PWCD_DB_BYTES];
};
_Static_assert(sizeof(struct pwcd_result)==345248,"CmdDb transaction-preflight complete raw extent");
_Static_assert(sizeof(struct pwcd_message)==104,"CmdDb query/status public ABI extent");
struct pwcd_io {
    struct pwrph_io original;
    int (*query)(void *,uint64_t,uint64_t,uint8_t *,uint8_t *,uint8_t *,uint32_t *,uint64_t *);
};
enum pwcd_error {PWCD_OK,PWCD_STAGE,PWCD_BASELINE,PWCD_OWNER,PWCD_SOURCE,PWCD_MAP,PWCD_DATABASE,
    PWCD_BOUNDS,PWCD_RESOURCE,PWCD_QUERY,PWCD_CHANGED,PWCD_GUARD,PWCD_TIME};
static const char pwcd_names[3][9]={"cx.lvl","mx.lvl","mss.lvl"};
static const uint32_t pwcd_addresses[3]={0x30000,0x30010,0x30060};
static inline void pwcd_fail(struct pwcd_result *r,unsigned e,int unknown)
{if(!r->error)r->error=e;if(unknown)r->unknown=1;paic_actual_order(0);}
static inline int pwcd_unknown(const struct pwcd_result *r){return r->unknown||r->outstanding;}
static inline int pwcd_fresh(const struct paic_io *io,struct pwcd_result *r)
{
    if(!io->arch(io->context,&r->after)||!paic_arch_stable(&r->before,&r->after)||
       r->after.ticks-r->before.ticks>PGCD_FRESH_TICKS){pwcd_fail(r,PWCD_TIME,0);return 0;}return 1;
}
/* Only the hosted software peer translates own physical addresses. Never
 * allow this fixture path in either freestanding firmware target. */
#if defined(POLARIS_CMDDB_SOFTWARE_TEST)
#if !defined(__STDC_HOSTED__) || !__STDC_HOSTED__
#error CmdDb software address translation must not enter a firmware object
#endif
static uint8_t pwcd_test_load(uint64_t);
#define PWCD_LOAD(at) pwcd_test_load(at)
#else
#define PWCD_LOAD(at) (*(const volatile uint8_t *)(uintptr_t)(at))
#endif
static inline int pwcd_overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return a>UINT64_MAX-n||b>UINT64_MAX-z||(a<b+z&&b<a+n);}
static inline int pwcd_owned(const struct paic_io *io,struct pwcd_result *r,const struct pwrph_work *w,uint64_t at,uint32_t n)
{
    if(!at||!n||at>UINT64_MAX-n||at+n>UINT64_MAX-4095)return 0;
    for(uint64_t p=at&~UINT64_C(4095);p<at+n;p+=4096)
        if(!polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,3)&&
           !polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,4))return 0;
    return io->identity(io->context,at,n,&r->identity_address,&r->identity_par);
}
static inline int pwcd_copy(const struct paic_io *io,struct pwcd_result *r,const struct pwrph_work *w,void *out,uint64_t at,uint32_t n)
{if(!pwcd_owned(io,r,w,at,n))return 0;for(uint32_t k=0;k<n;k++)((uint8_t*)out)[k]=((const volatile uint8_t*)(uintptr_t)at)[k];return 1;}
static inline int pwcd_enter(struct pgcd_context *g,struct pwcd_result *r,unsigned op)
{
    if(op>=PWCD_CALLS||r->guard[op].entered||!pgcd_service_enter(g,&r->guard[op])){pwcd_fail(r,PWCD_GUARD,1);return 0;}
    r->outstanding=op+1;r->issued++;paic_actual_order(0);return 1;
}
static inline int pwcd_leave(struct pgcd_context *g,struct pwcd_result *r,unsigned op,int returned)
{
    if(returned)r->returned++;paic_actual_order(0);
    if(!pgcd_service_leave(g,&r->guard[op],returned)){pwcd_fail(r,PWCD_GUARD,1);return 0;}
    r->outstanding=0;paic_actual_order(0);return 1;
}
/* This is a shared immutable namespace READ classification, not allocated
 * RAM, MPU/VMID or SMEM-write permission. Own SMEM bounds stay fixed. */
static inline int pwcd_database_read(const struct pwcd_io *ops,struct pgcd_context *g,
    struct pwcd_result *r,struct pwrph_work *w,unsigned pass,unsigned first)
{
    const struct paic_io *io=&ops->original.memory;uint64_t base=r->database[pass];
    if(base!=PWCD_UEFI_DB_BASE)return 0;
    unsigned prior=0;
    for(unsigned k=0;k<PWCD_PAGES;k++){
        if(!pwcd_fresh(io,r))return 0;
        uint64_t p=base+4096*k;struct pgcd_observation *q=&r->namespace[pass][k];q->page=p;q->status=UINT64_MAX;
        /* One original descriptor may cover many pages. Reuse only its exact
         * admitted extent in this pass; still check every page's map and AT.
         * Unissued observations are explicitly linked to the source page. */
        const struct pgcd_descriptor *old=k?&r->namespace[pass][prior].descriptor:0;
        if(k&&old->base<=p&&old->length<=UINT64_MAX-old->base&&old->base+old->length>=p+4096){
            q->descriptor=*old;q->status=r->namespace[pass][prior].status;
        }else{
            prior=k;
            if(!pwcd_enter(g,r,first+k))return 0;
            q->issued=q->unknown=1;q->before_ticks=r->guard[first+k].before.cpu.ticks;
            int returned=g->io.query(g->io.opaque,g->record->get_descriptor,p,&q->descriptor,&q->status);
            q->returned=returned?1:0;paic_actual_order(0);
            if(!pwcd_leave(g,r,first+k,returned))return 0;
            q->guard=r->guard[first+k];q->after_ticks=q->guard.after.cpu.ticks;q->unknown=0;
        }
        r->descriptor_page[pass][k]=prior;
        const struct pgcd_descriptor *d=&q->descriptor;
        if(q->status||d->type!=2||!(d->capabilities&8)||d->attributes!=8||
           !d->length||d->base>p||d->base>UINT64_MAX-d->length||p+4096>d->base+d->length||
           (!polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,0)&&
            !polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,4)))return 0;
        if(!io->identity(io->context,p,4096,&r->identity_address,&r->identity_par)||r->identity_address!=p||
           r->identity_par!=(UINT64_C(0xff00000000000b80)|p))return 0;
    }
    for(unsigned k=0;k<PWCD_DB_BYTES;k++){
        if(!(k&4095)&&!pwcd_fresh(io,r))return 0;
        r->database_raw[pass][k]=PWCD_LOAD(base+k);r->database_bytes[pass]=k+1;
    }return 1;
}
static inline int pwcd_query_matches(const struct pwcd_message *q,const struct pwcd_resource *x,unsigned k)
{
    for(unsigned j=0;j<24;j++)if(q->query[j]!=(j<9?(uint8_t)pwcd_names[k][j]:0))return 0;
    if(q->EFI_status||q->result||!pgcd_equal(q->response,pwcd_names[k],9)||
       q->response[9]||q->response[10]||q->response[11]||q->response[30]||q->response[31]||
       pwfi_le(q->response+12,4)!=x->address||pwfi_le(q->response+16,4)!=x->priority[0]||
       pwfi_le(q->response+20,4)!=x->priority[1]||pwfi_le(q->response+24,4)!=32||
       pwfi_le(q->response+28,2)!=x->version||!pgcd_equal(q->aux,x->aux,32))return 0;
    return 1;
}
static inline int pwcd_checkpoint(const struct paic_io *io,struct pwcd_result *r,
    const struct pwrph_work *w,unsigned pass,unsigned slot)
{
    struct efi_loaded current;uint8_t table[72],globals[72];
    if(!pwcd_fresh(io,r)||!pwcd_copy(io,r,w,&current,r->owner_address,sizeof(current))||!pgcd_equal(&current,&r->owner,sizeof(current))||
       !pwcd_owned(io,r,w,r->image,PWCDI_IMAGE_BYTES)||!pwcdi_verify((const void*)(uintptr_t)r->image,r->image,r->hashes[slot],&r->hash_count[slot],&r->hash_failed[slot])||
       !pwcd_copy(io,r,w,table,r->protocol[pass],72)||!pgcd_equal(table,r->protocol_raw[pass],72)||
       !pwcd_copy(io,r,w,globals,r->image+0x5158,72)||!pgcd_equal(globals,r->globals[pass],72)){
        pwcd_fail(r,PWCD_SOURCE,0);return 0;}
    return pwcd_fresh(io,r);
}
static inline int pwcd_database_same(const struct paic_io *io,struct pwcd_result *r,unsigned pass)
{
    r->verified_bytes[pass]=0;
    for(unsigned j=0;j<PWCD_DB_BYTES;j++){
        if(!(j&4095)&&!pwcd_fresh(io,r))return 0;
        if(PWCD_LOAD(r->database[pass]+j)!=r->database_raw[pass][j]){pwcd_fail(r,PWCD_CHANGED,0);return 0;}
        r->verified_bytes[pass]=j+1;
    }r->rereads[pass]++;return 1;
}
/* Validate the exact footprint the ORIGINAL query will follow, then select
 * only the three own ARC resources. No direct shared-memory stores exist. */
static inline int pwcd_select(struct pwcd_result *r,unsigned pass)
{
    const uint8_t *b=r->database_raw[pass];unsigned found[3]={0,0,0};
    if(pwfi_le(b,4)!=1||pwfi_le(b+4,4)!=0x0c0330db)return 0;
    for(unsigned group=0;group<8;group++){
        const uint8_t *h=b+8+16*group;unsigned id=(unsigned)pwfi_le(h,2),off=(unsigned)pwfi_le(h+2,2),aux=(unsigned)pwfi_le(h+4,2),count=(unsigned)pwfi_le(h+6,2);
        if(!count)continue;
        if(id<3||id>5||count>512||off>PWCD_DB_BYTES-144||count>(PWCD_DB_BYTES-144-off)/24)return 0;
        for(unsigned i=0;i<count;i++){
            unsigned at=144+off+24*i;const uint8_t *e=b+at;
            for(unsigned k=0;k<3;k++)if(pgcd_equal(e,pwcd_names[k],8)){
                struct pwcd_resource *x=&r->resources[pass][k];if(++found[k]!=1||id!=3)return 0;
                x->entry=at;x->aux_offset=144+aux+(unsigned)pwfi_le(e+22,2);x->address=(uint32_t)pwfi_le(e+16,4);
                x->priority[0]=(uint32_t)pwfi_le(e+8,4);x->priority[1]=(uint32_t)pwfi_le(e+12,4);x->length=(unsigned)pwfi_le(e+20,2);x->version=(unsigned)pwfi_le(h+8,2);
                pgcd_copy(x->entry_raw,e,24);
                /* Priority bits are provider scheduling data, not permission
                 * or ownership. Preserve both words without inventing a
                 * required DRV2 bit or interpreting them as a power lease. */
                if(x->address!=pwcd_addresses[k]||x->length!=32||x->aux_offset>PWCD_DB_BYTES-32)return 0;
                pgcd_copy(x->aux,b+x->aux_offset,32);
                unsigned ended=0;uint32_t previous=0;x->index=UINT32_MAX;
                for(unsigned j=0;j<16;j++){
                    uint32_t level=(uint32_t)pwfi_le(x->aux+2*j,2);
                    if(j&&level==0)ended=1;
                    if(ended){if(level)return 0;continue;}
                    if((j==0&&level!=0)||level<previous)return 0;
                    previous=level;if(level>=384&&x->index==UINT32_MAX)x->index=j;
                }
                if(x->index==UINT32_MAX)return 0;
            }
        }
    }return found[0]==1&&found[1]==1&&found[2]==1;
}
static inline int pwcd_collect(const struct pwcd_io *ops,const struct paic_result *enumeration,
    struct pgcd_context *g,struct pwcd_result *r,struct pwrph_work *w)
{
    if(!r||r->attempted)return 0;r->attempted=1;
    if(!ops||!ops->query||!w||!g||!g->record||!g->ticket||g->stage!=2||!g->opened||g->finished||
       !pwrph_context_ready(g)){pwcd_fail(r,PWCD_BASELINE,1);return 0;}
    const struct paic_io *io=&ops->original.memory;
    if(!io->arch||!io->identity||!io->order||!io->system||!io->system->boot||io->system!=g->io.system||!g->io.query||
       !ops->original.locate||!ops->original.map||!enumeration||enumeration->error||
       !enumeration->cache_consistent||enumeration->owner_matches!=1||!enumeration->handle_count||enumeration->handle_count>PAIC_HANDLES||
       !pgcd_in_self(g->record,(uintptr_t)r,sizeof(*r))||!pgcd_in_self(g->record,(uintptr_t)w,sizeof(*w))||
       !io->arch(io->context,&r->before)||!paic_arch_admitted(&r->before)){pwcd_fail(r,PWCD_BASELINE,0);return 0;}
    static const efi_guid guid={0x1c34f691,0xd33d,0x4e14,{0xb8,0xf8,0x32,0xc6,0xc0,0x29,0xe9,0x5b}};
    for(unsigned pass=0;pass<2;pass++){
        unsigned op=pass*(2+PWCD_PAGES+3);void *table=0;r->protocol_status[pass]=UINT64_MAX;
        if(!pwcd_enter(g,r,op))return 0;
        int returned=ops->original.locate(io->context,io->system,&guid,&table,&r->protocol_status[pass]);r->protocol[pass]=(uintptr_t)table;
        if(!pwcd_leave(g,r,op++,returned))return 0;
        if(r->protocol_status[pass]||!table){pwcd_fail(r,PWCD_SOURCE,0);return 0;}
        r->maps[pass]=(struct paic_map_sample){UINT64_MAX,0,sizeof(w->map),0,0};
        if(!pwcd_enter(g,r,op))return 0;
        returned=ops->original.map(io->context,io->system,w->map,&r->maps[pass]);pgcd_copy(r->map_raw[pass],w->map,sizeof(w->map));
        if(!pwcd_leave(g,r,op++,returned))return 0;
        const struct paic_map_sample *m=&r->maps[pass];struct polaris_efi_memory checked;
        if(m->status||!m->key||m->version!=1||!polaris_efi_memory_check(w->map,m->bytes,sizeof(w->map),m->stride,&checked)){pwcd_fail(r,PWCD_MAP,0);return 0;}
        w->bytes=m->bytes;w->stride=m->stride;
        if(!pwcd_owned(io,r,w,(uintptr_t)r,sizeof(*r))||!pwcd_owned(io,r,w,(uintptr_t)w,sizeof(*w))){pwcd_fail(r,PWCD_OWNER,0);return 0;}
        if(!pass){for(unsigned k=0;k<enumeration->handle_count;k++){
            struct efi_loaded candidate;if(enumeration->handle_status[k]||!pwcd_copy(io,r,w,&candidate,enumeration->loaded_address[k],sizeof(candidate))){pwcd_fail(r,PWCD_OWNER,0);return 0;}
            uint64_t base=(uintptr_t)candidate.base;if(base>UINT64_MAX-0x5088||base+0x5088!=r->protocol[0])continue;
            r->owner_matches++;r->image=base;r->owner=candidate;r->owner_address=enumeration->loaded_address[k];
            if(candidate.revision!=0x1000||candidate.system!=io->system||candidate.bytes!=PWCDI_IMAGE_BYTES||candidate.code_type!=3||candidate.data_type!=4||(base&4095)){pwcd_fail(r,PWCD_OWNER,0);return 0;}
        }if(r->owner_matches!=1||pwcd_overlap(r->image,PWCDI_IMAGE_BYTES,g->record->self_base,g->record->self_bytes)||pwcd_overlap(r->image,PWCDI_IMAGE_BYTES,g->record->core,PGCI_IMAGE_BYTES)){pwcd_fail(r,PWCD_OWNER,0);return 0;}}
        struct efi_loaded current;
        if(r->protocol[pass]!=r->protocol[0]||!pwcd_copy(io,r,w,&current,r->owner_address,sizeof(current))||!pgcd_equal(&current,&r->owner,sizeof(current))||
           !pwcd_owned(io,r,w,r->image,PWCDI_IMAGE_BYTES)||!pwcdi_verify((const void*)(uintptr_t)r->image,r->image,r->hashes[pass*4],&r->hash_count[pass*4],&r->hash_failed[pass*4])||
           !pwcd_copy(io,r,w,r->protocol_raw[pass],r->protocol[pass],72)||!pwcd_copy(io,r,w,r->globals[pass],r->image+0x5158,72)){pwcd_fail(r,PWCD_SOURCE,0);return 0;}
        static const uint32_t entries[8]={0x1878,0x18cc,0x1914,0x195c,0x19a8,0x19f0,0x1a38,0x1a90};
        if(pwfi_le(r->protocol_raw[pass],8)!=0x10000){pwcd_fail(r,PWCD_SOURCE,0);return 0;}
        for(unsigned k=0;k<8;k++)if(pwfi_le(r->protocol_raw[pass]+8+8*k,8)!=r->image+entries[k]){pwcd_fail(r,PWCD_SOURCE,0);return 0;}
        r->database[pass]=pwfi_le(r->globals[pass],8);
        if(!r->database[pass]||r->database[pass]!=pwfi_le(r->globals[pass]+64,8)||!pwcd_database_read(ops,g,r,w,pass,op)){if(!r->error)pwcd_fail(r,PWCD_DATABASE,0);return 0;}op+=PWCD_PAGES;
        if(!pwcd_select(r,pass)){pwcd_fail(r,PWCD_RESOURCE,0);return 0;}
        for(unsigned k=0;k<3;k++,op++){
            if(!pwcd_checkpoint(io,r,w,pass,pass*4+k+1))return 0;
            struct pwcd_message *q=&r->messages[pass][k];pgcd_copy(q->query,pwcd_names[k],9);q->response[24]=32;q->result=UINT32_MAX;q->EFI_status=UINT64_MAX;
            if(!pwcd_enter(g,r,op))return 0;
            returned=ops->query(io->context,r->image+0x1878,r->protocol[pass],q->query,q->response,q->aux,&q->result,&q->EFI_status);
            if(!pwcd_leave(g,r,op,returned))return 0;
            if(!pwcd_query_matches(q,&r->resources[pass][k],k)){
                pwcd_fail(r,PWCD_QUERY,0);return 0;}
            /* An unexpected shared mutation after any query prevents the
             * next call; do not follow a newly malformed live footprint. */
            if(!pwcd_database_same(io,r,pass))return 0;
        }
        if(!pwcd_fresh(io,r))return 0;
    }
    if(r->maps[0].key!=r->maps[1].key||r->maps[0].bytes!=r->maps[1].bytes||r->maps[0].stride!=r->maps[1].stride||r->database[0]!=r->database[1]||
       !pgcd_equal(r->map_raw[0],r->map_raw[1],r->maps[0].bytes)||!pgcd_equal(r->protocol_raw[0],r->protocol_raw[1],72)||
       !pgcd_equal(r->globals[0],r->globals[1],72)||!pgcd_equal(r->database_raw[0],r->database_raw[1],PWCD_DB_BYTES)||
       !pgcd_equal(r->resources[0],r->resources[1],sizeof(r->resources[0]))){pwcd_fail(r,PWCD_CHANGED,0);return 0;}
    if(!pwcd_checkpoint(io,r,w,1,8))return 0;
    r->stable=1;return 1;
}
static inline int pwcd_actual_query(void *ctx,uint64_t fn,uint64_t This,uint8_t *q,uint8_t *resp,uint8_t *aux,uint32_t *result,uint64_t *EFI_status)
{(void)ctx;*EFI_status=((uint64_t(*)(void*,void*,void*,void*,uint32_t*))(uintptr_t)fn)((void*)(uintptr_t)This,q,resp,aux,result);return 1;}
#endif
#endif
