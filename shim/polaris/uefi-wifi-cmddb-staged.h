/* Four independently completed source-bound RO preparation phases. Each
 * captures64KiB with its own unopened/spent-once Core ticket and original
 * 200ms window. No client exists between or during these phases. Snapshots
 * are evidence at their read intervals, never a continuous hardware lease. */
#ifndef POLARIS_UEFI_WIFI_CMDDB_STAGED_H
#define POLARIS_UEFI_WIFI_CMDDB_STAGED_H
#ifndef EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE
#define EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#if !EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY || !EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE || EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP || EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION
#error Staged preparation requires its distinct full RO scope, never an old budget or first-node policy
#endif
#define PWSP_PHASES 4u
#define PWSP_PIECE_BYTES 65536u
#define PWSP_PAGES 16u
#define PWSP_RAW_BYTES 1660544u
struct pwsp_source {
    uint64_t table,status,image,owner_address,database;
    uint32_t owner_matches,locate_issued,locate_returned,outstanding;
    struct pgcd_service_guard guard;
    struct efi_loaded owner[2];
    uint8_t protocol[2][72],globals[2][72],hashes[2][5][32];
    uint32_t hash_count[2],hash_failed[2];
};
struct pwsp_phase {
    uint32_t attempted,error,unknown,outstanding,retired,complete,refused,index;
    uint32_t offset,bytes,preflight_pages,native_before,native_after;
    uint32_t native_reads,native_last,native_before_valid,native_after_valid;
    uint64_t native_flag;
    struct pgcd_result core;
    struct pgcd_lifetime ticket;
    struct pgcd_context context;
    struct pgcd_arch after;
    struct pgns_ro_owner reader;
    struct pwsp_source source;
    struct pgns_result namespace;
    struct pgcd_descriptor descriptor[PWSP_PAGES];
    struct pgns_translation page_AT[PWSP_PAGES];
    struct pgns_target target[PWSP_PAGES+1];
    uint8_t data[PWSP_PIECE_BYTES];
};
struct pwsp_result {
    uint32_t attempted,error,unknown,retired,complete,known_refusal,active,parts;
    uint32_t assembled[2],parsed[2];
    struct pwsp_phase phase[PWSP_PHASES];
    uint8_t database[2][PWCD_DB_BYTES];
    struct pwcd_resource resources[2][PWCD_RESOURCES];
};
struct pwsp_io {
    const struct paic_io *memory;
    void *context;
    int (*locate)(void *,struct efi_system *,const efi_guid *,void **,uint64_t *);
    int (*translate)(void *,struct pgns_translation *);
};
_Static_assert(sizeof(struct pwsp_result)==PWSP_RAW_BYTES,"complete staged RO raw ABI");
_Static_assert(sizeof(struct pwsp_phase)==349456,"complete independent RO phase ABI");
enum pwsp_error {PWSP_OK,PWSP_ARGUMENT,PWSP_CONTEXT,PWSP_SOURCE,PWSP_NAMESPACE,PWSP_TARGET,
    PWSP_RESTORE,PWSP_CHANGED,PWSP_RESOURCE};
static struct pwsp_result pwsp_record;
static inline int pwsp_unsafe(const struct pwsp_result *r)
{
    if(r->unknown||(r->attempted&&!r->retired))return 1;
    for(unsigned k=0;k<PWSP_PHASES;k++){
        const struct pwsp_phase *s=&r->phase[k];
        if(s->unknown||s->outstanding||s->source.outstanding||s->reader.outstanding||s->core.uncertain||
           s->core.outstanding||pgns_unsafe(&s->namespace)||(s->attempted&&!s->retired))return 1;
        for(unsigned j=0;j<PWSP_PAGES+1;j++)if(s->target[j].attempted&&!s->target[j].complete)return 1;
    }return 0;
}
static inline int pwsp_fail(struct pwsp_phase *s,unsigned e)
{if(!s->error)s->error=e;s->unknown=1;paic_actual_order(0);return 0;}
static inline int pwsp_live(struct pwsp_phase *s)
{
    struct pgcd_context *g=&s->context;
    if(g->record!=&s->core||!pwrph_context_ready(g)||!pgcd_live(g,&s->after,0)||
       !pgcd_cached_owner_stable(g)||!pgcd_in_self(&s->core,s->native_flag,4)||
       !pgcd_owned(g,0,s->native_flag,4)||
       pwfi_le((const void*)(uintptr_t)(s->core.core+0x1b098),8)!=4||
       !pgcd_equal(s->core.DS_raw[0],(const void*)(uintptr_t)s->core.DS,168))return pwsp_fail(s,PWSP_CONTEXT);
    s->native_last=*(const volatile uint32_t*)(uintptr_t)s->native_flag;s->native_reads++;
    if(s->native_last)return pwsp_fail(s,PWSP_CONTEXT);return 1;
}
static inline int pwsp_copy(struct pwsp_phase *s,void *out,uint64_t at,uint32_t bytes)
{
    if(!pwsp_live(s)||!pgcd_owned(&s->context,0,at,bytes))return pwsp_fail(s,PWSP_SOURCE);
    s->outstanding=1;paic_actual_order(0);pgcd_copy(out,(const void*)(uintptr_t)at,bytes);
    paic_actual_order(0);s->outstanding=0;return pwsp_live(s);
}
static inline int pwsp_source_snapshot(struct pwsp_phase *s,unsigned slot)
{
    struct pwsp_source *r=&s->source;
    if(slot>1||!pwsp_copy(s,&r->owner[slot],r->owner_address,sizeof(struct efi_loaded))||
       !pgcd_equal(&r->owner[slot],&r->owner[0],sizeof(struct efi_loaded))||
       !pgcd_owned(&s->context,0,r->image,PWCDI_IMAGE_BYTES)||
       !pwcdi_verify((const void*)(uintptr_t)r->image,r->image,r->hashes[slot],&r->hash_count[slot],&r->hash_failed[slot])||
       !pwsp_copy(s,r->protocol[slot],r->table,72)||!pwsp_copy(s,r->globals[slot],r->image+0x5158,72))return pwsp_fail(s,PWSP_SOURCE);
    static const uint32_t entries[8]={0x1878,0x18cc,0x1914,0x195c,0x19a8,0x19f0,0x1a38,0x1a90};
    if(pwfi_le(r->protocol[slot],8)!=0x10000)return pwsp_fail(s,PWSP_SOURCE);
    for(unsigned k=0;k<8;k++)if(pwfi_le(r->protocol[slot]+8+8*k,8)!=r->image+entries[k])return pwsp_fail(s,PWSP_SOURCE);
    if(slot&&(!pgcd_equal(r->protocol[0],r->protocol[1],72)||!pgcd_equal(r->globals[0],r->globals[1],72)))return pwsp_fail(s,PWSP_CHANGED);
    if(pwfi_le(r->globals[slot],8)!=pwfi_le(r->globals[slot]+64,8))return pwsp_fail(s,PWSP_CHANGED);
    if(!slot)r->database=pwfi_le(r->globals[slot],8);
    return pwsp_live(s);
}
static inline int pwsp_source_open(const struct pwsp_io *io,struct pwsp_phase *s)
{
    struct pwsp_source *r=&s->source;struct pgcd_context *g=&s->context;void *table=0;
    static const efi_guid guid={0x1c34f691,0xd33d,0x4e14,{0xb8,0xf8,0x32,0xc6,0xc0,0x29,0xe9,0x5b}};
    r->status=UINT64_MAX;
    if(!pwsp_live(s)||!pgcd_service_enter(g,&r->guard))return pwsp_fail(s,PWSP_CONTEXT);
    r->locate_issued=r->outstanding=1;paic_actual_order(0);
    int returned=io->locate(io->context,io->memory->system,&guid,&table,&r->status);r->table=(uintptr_t)table;
    r->locate_returned=returned?1:0;paic_actual_order(0);
    if(!pgcd_service_leave(g,&r->guard,returned))return pwsp_fail(s,PWSP_CONTEXT);
    r->outstanding=0;
    if(r->status||!table)return pwsp_fail(s,PWSP_SOURCE);
    return 1;
}
static inline int pwsp_find_source(struct pwsp_phase *s)
{
    struct pwsp_source *r=&s->source;
    for(unsigned k=0;k<s->reader.image_count;k++){
        const struct efi_loaded *p=&s->reader.image[0][k];uint64_t b=(uintptr_t)p->base;
        if(b>UINT64_MAX-0x5088||b+0x5088!=r->table)continue;
        r->owner_matches++;r->image=b;r->owner_address=s->reader.address[k];r->owner[0]=*p;
        if(p->bytes!=PWCDI_IMAGE_BYTES||p->code_type!=3||p->data_type!=4||(b&4095))return pwsp_fail(s,PWSP_SOURCE);
    }
    if(r->owner_matches!=1||pwrcl_overlap(r->image,PWCDI_IMAGE_BYTES,s->core.self_base,s->core.self_bytes)||
       pwrcl_overlap(r->image,PWCDI_IMAGE_BYTES,s->core.core,PGCI_IMAGE_BYTES))return pwsp_fail(s,PWSP_SOURCE);
    return pwsp_source_snapshot(s,0);
}
static inline int pwsp_close(const struct pwsp_io *io,struct pwsp_phase *s,struct pgcd_context *final)
{
    struct pgcd_context *g=&s->context;struct pgcd_result *r=&s->core;
    if(!pwrcl_final_unopened(final)||!pwsp_live(s)||s->source.outstanding||s->outstanding||pgns_unsafe(&s->namespace)||
       !pgcd_map_read(g,1)||!pgcd_snapshot(g,1)||!pwsp_live(s)||
       r->pre_mask||r->post_mask||r->prestart_count||r->map[0].key!=r->map[1].key||
       r->map[0].bytes!=r->map[1].bytes||r->map[0].stride!=r->map[1].stride||
       !pgcd_equal(r->maps[0],r->maps[1],r->map[0].bytes)||
       !pgcd_equal(r->GCD_lock_raw[0],r->GCD_lock_raw[1],24)||
       !pwrcl_final_unopened(final))return pwsp_fail(s,PWSP_RESTORE);
    /* The final source/head/target/loaded-header check follows the LAST
     * foreign service. No GetMap/Locate/callback can intervene afterwards. */
    if(s->bytes){
        const struct pgns_io nsio={io->memory,io->context,io->translate};struct pgcd_descriptor last;
        if(!pgns_target_guard_ro(&nsio,g,&s->namespace,PWCD_UEFI_DB_BASE+s->offset,
           &s->target[PWSP_PAGES],&last,&s->reader)||!pgcd_equal(&last,&s->descriptor[0],sizeof(last)))return pwsp_fail(s,PWSP_RESTORE);
    }
    if(!pwsp_source_snapshot(s,1)||!pgns_ro_owner_close(g,&s->reader)||!pwsp_live(s)||
       !pwrcl_final_unopened(final))return pwsp_fail(s,PWSP_RESTORE);
    s->native_after=s->native_last;s->native_after_valid=1;
    r->TPL_final=4;r->phase=3;g->finished=1;s->retired=1;paic_actual_order(0);return 1;
}
static inline int pwsp_piece(const struct pwsp_io *io,const struct paic_result *enumeration,
    unsigned index,struct pgcd_context *final,const volatile uint32_t *native_on,struct pwsp_phase *s)
{
    if(s->attempted)return pwsp_fail(s,PWSP_ARGUMENT);s->attempted=1;s->index=index;s->offset=(index&1)*PWSP_PIECE_BYTES;
    if(index>=PWSP_PHASES||!pwrcl_final_unopened(final)||s->context.record||s->context.opened||s->context.finished||
       s->ticket.spent||s->ticket.result||!pgcd_bind(&s->core,&final->record->self_owner))return pwsp_fail(s,PWSP_ARGUMENT);
    s->core.self_owner_address=final->record->self_owner_address;s->native_flag=(uintptr_t)native_on;
    if(!pgcd_in_self(&s->core,(uintptr_t)s,sizeof(*s))||!pgcd_in_self(&s->core,s->native_flag,4))return pwsp_fail(s,PWSP_ARGUMENT);
    struct pgcd_context *g=&s->context;g->io=final->io;g->record=&s->core;g->ticket=&s->ticket;g->stage=2;
    if(!pgcd_open(g)||!pgcd_owned(g,0,(uintptr_t)s,sizeof(*s))||!pwsp_live(s))return pwsp_fail(s,PWSP_CONTEXT);
    s->native_before=s->native_last;s->native_before_valid=1;
    if(!pwsp_source_open(io,s)||!pgns_ro_owner_open(enumeration,g,&s->reader)||!pwsp_find_source(s))return pwsp_fail(s,PWSP_SOURCE);
    if(s->source.database!=PWCD_UEFI_DB_BASE){s->refused=PWSP_TARGET;return pwsp_close(io,s,final);}
    const struct pgns_io nsio={io->memory,io->context,io->translate};
    if(!pgns_collect_ro(&nsio,g,&s->namespace,&s->reader))return pwsp_fail(s,PWSP_NAMESPACE);
    /* Preserve complete per-page preflight AND immediate page/source/target
     * guard. A stable but unsupported descriptor is a known RO refusal only
     * after full source/map/owner retirement; it grants no target load. */
    for(unsigned k=0;k<PWSP_PAGES;k++){
        uint64_t page=PWCD_UEFI_DB_BASE+s->offset+4096*k;struct pgcd_descriptor *d=&s->descriptor[k];
        if(!pwsp_live(s))return 0;
        if(!pgns_descriptor(&s->namespace,page,d)||d->type!=2||!(d->capabilities&8)||d->attributes!=8||
           !d->length||d->base>page||d->base>UINT64_MAX-d->length||page+4096>d->base+d->length||
           (!polaris_efi_range_owned(s->core.maps[0],s->core.map[0].bytes,s->core.map[0].stride,page,4096,0)&&
            !polaris_efi_range_owned(s->core.maps[0],s->core.map[0].bytes,s->core.map[0].stride,page,4096,4))){
            s->refused=PWSP_TARGET;return pwsp_close(io,s,final);
        }
        struct pgns_translation *t=&s->page_AT[k];t->page=page;s->outstanding=2;paic_actual_order(0);
        int returned=io->translate(io->context,t);paic_actual_order(0);
        if(!returned||t->issued!=1||t->returned!=1||t->saved!=t->restored||t->page!=page||
           t->par!=(UINT64_C(0xff00000000000b80)|page))return pwsp_fail(s,PWSP_TARGET);
        s->outstanding=0;s->preflight_pages=k+1;
    }
    for(unsigned page=0;page<PWSP_PAGES;page++){
        unsigned start=page*4096;struct pgcd_descriptor current;
        if(!pwsp_live(s)||!pgns_target_guard_ro(&nsio,g,&s->namespace,PWCD_UEFI_DB_BASE+s->offset+start,
           &s->target[page],&current,&s->reader)||!pgcd_equal(&current,&s->descriptor[page],sizeof(current)))return pwsp_fail(s,PWSP_TARGET);
        s->outstanding=3;paic_actual_order(0);
        for(unsigned j=0;j<4096;j++){unsigned k=start+j;s->data[k]=PWCD_LOAD(PWCD_UEFI_DB_BASE+s->offset+k);s->bytes=k+1;}
        paic_actual_order(0);s->outstanding=0;
    }
    if(!pwsp_close(io,s,final))return pwsp_fail(s,PWSP_RESTORE);
    s->complete=1;return 1;
}
static inline int pwsp_namespace_equal(const struct pgns_result *a,const struct pgns_result *b)
{
    if(!a->stable||!b->stable||a->core!=b->core||a->pass[1].count!=b->pass[1].count||
       !pgcd_equal(a->pass[1].head_raw[1],b->pass[1].head_raw[1],16)||
       !pgcd_equal(a->pass[1].lock_raw[1],b->pass[1].lock_raw[1],24)||
       !pgcd_equal(a->pass[1].template_raw[1],b->pass[1].template_raw[1],80))return 0;
    for(unsigned k=0;k<a->pass[1].count;k++)if(a->pass[1].node[k].address!=b->pass[1].node[k].address||
       !pgcd_equal(a->pass[1].node[k].raw,b->pass[1].node[k].raw,80))return 0;
    return 1;
}
static inline int pwsp_run(const struct pwsp_io *io,const struct paic_result *enumeration,unsigned stage,
    struct pgcd_context *final,const volatile uint32_t *native_on,struct pwsp_result *r)
{
    if(!r)return 0;if(r->attempted){r->unknown=1;r->error=PWSP_ARGUMENT;return 0;}r->attempted=1;
    if(stage!=2||!io||!io->memory||!io->locate||!io->translate||!native_on||!pwrcl_final_unopened(final)||
       io->memory->system!=final->io.system||pwrcl_record.attempted||pwrcl_unsafe()||
       !pgcd_in_self(final->record,(uintptr_t)r,sizeof(*r))){r->unknown=1;r->error=PWSP_ARGUMENT;return 0;}
    for(unsigned k=0;k<PWSP_PHASES;k++){
        r->active=k;
        if(!pwsp_piece(io,enumeration,k,final,native_on,&r->phase[k])){r->unknown=1;r->error=r->phase[k].error;return 0;}
        if(k){
            const struct pwsp_phase *a=&r->phase[0],*b=&r->phase[k];
            if(a->core.core!=b->core.core||a->core.map[1].key!=b->core.map[0].key||
               a->core.map[1].bytes!=b->core.map[0].bytes||a->core.map[1].stride!=b->core.map[0].stride||
               !pgcd_equal(a->core.maps[1],b->core.maps[0],a->core.map[1].bytes)||
               a->reader.image_count!=b->reader.image_count||
               !pgcd_equal(a->reader.address,b->reader.address,sizeof(a->reader.address))||
               !pgcd_equal(a->reader.image[1],b->reader.image[0],a->reader.image_count*sizeof(struct efi_loaded))||
               a->source.image!=b->source.image||a->source.table!=b->source.table||a->source.owner_address!=b->source.owner_address||
               !pgcd_equal(a->source.protocol[1],b->source.protocol[0],72)||!pgcd_equal(a->source.globals[1],b->source.globals[0],72)||
               !pwsp_namespace_equal(&a->namespace,&b->namespace)){r->unknown=1;r->error=PWSP_CHANGED;return 0;}
        }
        if(r->phase[k].refused){r->known_refusal=1;r->error=r->phase[k].refused;r->retired=1;return 1;}
        if(!r->phase[k].retired||!r->phase[k].complete||r->phase[k].bytes!=PWSP_PIECE_BYTES){r->unknown=1;r->error=PWSP_RESTORE;return 0;}
        unsigned pass=k/2,offset=(k&1)*PWSP_PIECE_BYTES;
        pgcd_copy(r->database[pass]+offset,r->phase[k].data,PWSP_PIECE_BYTES);r->assembled[pass]+=PWSP_PIECE_BYTES;r->parts=k+1;
    }
    if(!pwrcl_final_unopened(final)||!pgcd_equal(r->database[0],r->database[1],PWCD_DB_BYTES)){
        r->unknown=1;r->error=PWSP_CHANGED;return 0;
    }
    for(unsigned k=0;k<2;k++){
        if(!pwcd_select_bytes(r->database[k],r->resources[k])){
            r->known_refusal=1;r->error=PWSP_RESOURCE;r->retired=1;return 1;
        }r->parsed[k]=1;
    }
    if(!pgcd_equal(r->resources[0],r->resources[1],sizeof(r->resources[0]))){r->unknown=1;r->error=PWSP_CHANGED;return 0;}
    r->complete=r->retired=1;paic_actual_order(0);return 1;
}
#endif
#endif
