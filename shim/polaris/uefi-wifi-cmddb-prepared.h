/* Current selected ARC bytes in the SAME real private-client interval.
 * A completed full RO preparation supplies a comparison database, never a
 * lease. Re-read the whole header and each selected entry/auxiliary table
 * through a new complete current namespace with immediate source/AT guards.
 * No Query/API status is fabricated and no provider method is invoked. */
#ifndef POLARIS_UEFI_WIFI_CMDDB_PREPARED_H
#define POLARIS_UEFI_WIFI_CMDDB_PREPARED_H
#ifndef EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
#define EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-cmddb-staged.h"
#if !EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE || !EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE
#error Prepared power requires complete staged RO preparation and bounded current namespace
#endif
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
#include "uefi-wifi-vrm-domain.h"
#define PWCP_RANGES 11u
#else
#define PWCP_RANGES 7u
#endif
#define PWCP_PAGES 13u
struct pwcp_range {uint32_t offset,bytes,read[3];uint8_t raw[3][144];};
struct pwcp_source {
    uint32_t owner_bytes,table_bytes,global_bytes,hash_count,hash_failed,complete;
    struct efi_loaded owner;uint8_t table[72],globals[72],hashes[5][32];
};
struct pwcp_result {
    uint32_t attempted,error,unknown,outstanding,complete,stable,owner_matches,pages,close_attempted,closed;
    uint64_t provider,core,preparation,image,owner_address,protocol,status,database;
    struct paic_arch before,after,bound_after,closed_after;
    struct pgcd_service_guard locate;
    struct pwcp_source source[4];
    struct pgns_result namespace;
    uint64_t page[PWCP_PAGES];struct pgcd_descriptor descriptor[PWCP_PAGES];
    struct pgns_target target[4][PWCP_PAGES];
    struct pwcp_range range[PWCP_RANGES];
    struct pwcd_resource resources[2][3];
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    struct pwcd_resource VRM[2][4];
#endif
};
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
_Static_assert(sizeof(struct pwcp_result)==236032,"complete current ARC plus four VRM binding ABI");
#else
_Static_assert(sizeof(struct pwcp_result)==233520,"complete current prepared binding ABI");
#endif
struct pwcp_io {const struct paic_io *memory;void *context;
    int (*locate)(void *,struct efi_system *,const efi_guid *,void **,uint64_t *);
    int (*translate)(void *,struct pgns_translation *);};
enum pwcp_error {PWCP_OK,PWCP_ARGUMENT,PWCP_PREPARATION,PWCP_CONTEXT,PWCP_SOURCE,
    PWCP_NAMESPACE,PWCP_TARGET,PWCP_CHANGED,PWCP_PARTIAL};
static inline int pwcp_fail(struct pwcp_result *r,unsigned e)
{if(!r->error)r->error=e;r->unknown=1;paic_actual_order(0);return 0;}
static inline int pwcp_unsafe(const struct pwcp_result *r)
{
    if(r->unknown||r->outstanding||(r->attempted&&!r->complete)||pgns_unsafe(&r->namespace))return 1;
    for(unsigned k=0;k<4;k++)for(unsigned j=0;j<PWCP_PAGES;j++)
        if(r->target[k][j].attempted&&!r->target[k][j].complete)return 1;
    return 0;
}
static inline int pwcp_live(const struct pwcp_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,struct pwcp_result *r)
{
    struct pgcd_arch now;
    if(io->memory->system!=g->io.system||r->provider!=(uintptr_t)p||r->core!=(uintptr_t)g||
       !p->reader.stable||p->reader.error||p->reader.unknown||p->reader.outstanding||
       !p->client_held||p->client_returned||p->retired||p->unknown||p->outstanding||
       g->record!=&p->core||!pwrph_context_ready(g)||!pgcd_live(g,&now,0)||!pgcd_cached_owner_stable(g)||
       !pwrcl_fresh(io->memory,p)||!io->memory->arch(io->memory->context,&r->after)||
       !pwfc_arch_admitted(&now.cpu)||now.cpu.daif||now.cpu.group1!=1||
       !pwrcl_owned(io->memory,p,w,(uintptr_t)r,sizeof(*r)))return pwcp_fail(r,PWCP_CONTEXT);
    if(!r->before.frequency)r->before=r->after;
    if(!paic_arch_stable(&r->before,&r->after)||r->after.ticks<g->record->before.cpu.ticks||
       r->after.ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS)return pwcp_fail(r,PWCP_CONTEXT);
    return 1;
}
static inline int pwcp_source(const struct pwcp_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,const struct pwsp_result *prepared,struct pwcp_result *r,unsigned slot)
{
    if(slot>3||r->source[slot].complete||!pwcp_live(io,p,w,g,r))return pwcp_fail(r,PWCP_SOURCE);
    struct pwcp_source *s=&r->source[slot];const struct pwsp_source *old=&prepared->phase[3].source;
    r->outstanding=0x100+slot;paic_actual_order(0);
    if(!pwrcl_copy(io->memory,p,w,&s->owner,r->owner_address,sizeof(s->owner),&s->owner_bytes)||
       !pgcd_equal(&s->owner,&old->owner[1],sizeof(s->owner))||
       !pwrcl_copy(io->memory,p,w,s->table,r->protocol,72,&s->table_bytes)||!pgcd_equal(s->table,old->protocol[1],72)||
       !pwrcl_copy(io->memory,p,w,s->globals,r->image+0x5158,72,&s->global_bytes)||!pgcd_equal(s->globals,old->globals[1],72)||
       !pwrcl_owned(io->memory,p,w,r->image,PWCDI_IMAGE_BYTES)||
       !pwcdi_verify((const void*)(uintptr_t)r->image,r->image,s->hashes,&s->hash_count,&s->hash_failed))return pwcp_fail(r,PWCP_SOURCE);
    r->outstanding=0;if(!pwcp_live(io,p,w,g,r))return 0;s->complete=1;return 1;
}
static inline int pwcp_preparation(const struct pwcp_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,const struct pwsp_result *s,struct pwcp_result *r)
{
    if(!s||s->attempted!=1||s->error||pwsp_unsafe(s)||!s->complete||!s->retired||s->known_refusal||s->parts!=4||
       s->assembled[0]!=PWCD_DB_BYTES||s->assembled[1]!=PWCD_DB_BYTES||!s->parsed[0]||!s->parsed[1]||
       !pgcd_in_self(&p->core,(uintptr_t)s,sizeof(*s))||!pwrcl_owned(io->memory,p,w,(uintptr_t)s,sizeof(*s))||
       !pgcd_equal(s->database[0],s->database[1],PWCD_DB_BYTES)||
       !pgcd_equal(s->resources[0],s->resources[1],sizeof(s->resources[0])))return pwcp_fail(r,PWCP_PREPARATION);
    for(unsigned k=0;k<4;k++){
        const struct pwsp_phase *a=&s->phase[k];
        if(!a->complete||!a->retired||a->bytes!=65536||!a->reader.closed||!a->context.finished||
           a->core.phase!=3||a->ticket.spent!=1||a->ticket.result!=(uintptr_t)&a->core||
           a->context.record!=&a->core||a->context.ticket!=&a->ticket||
           a->after.cpu.ticks>g->record->before.cpu.ticks)return pwcp_fail(r,PWCP_PREPARATION);
    }
    if(!pwcd_select_bytes(s->database[1],r->resources[0])||
       !pgcd_equal(s->resources[1],r->resources[0],sizeof(r->resources[0])))return pwcp_fail(r,PWCP_PREPARATION);
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    if(!pwv_select_bytes(s->database[1],r->VRM[0]))return pwcp_fail(r,PWCP_PREPARATION);
#endif
    r->preparation=(uintptr_t)s;return 1;
}
static inline int pwcp_targets(const struct pwcp_io *io,struct pwrcl_result *p,struct pwrph_work *w,
    struct pgcd_context *g,struct pwcp_result *r,unsigned pass)
{
    const struct pgns_io nsio={io->memory,io->context,io->translate};
    if(pass>3||!pwcp_live(io,p,w,g,r))return pwcp_fail(r,PWCP_TARGET);
    for(unsigned j=0;j<r->pages;j++){
        struct pgcd_descriptor current;
        if(!pgns_target_guard(&nsio,p,w,g,&r->namespace,r->page[j],&r->target[pass][j],&current)||
           !pgcd_equal(&current,&r->descriptor[j],sizeof(current)))return pwcp_fail(r,PWCP_TARGET);
    }return pwcp_live(io,p,w,g,r);
}
static inline int pwcp_read_pass(const struct pwcp_io *io,struct pwrcl_result *p,struct pwrph_work *w,
    struct pgcd_context *g,const struct pwsp_result *prepared,struct pwcp_result *r,unsigned pass)
{
    const struct pgns_io nsio={io->memory,io->context,io->translate};
    if(pass>2)return pwcp_fail(r,PWCP_TARGET);
    for(unsigned page=0;page<r->pages;page++){
        struct pgcd_descriptor current;
        if(!pwcp_live(io,p,w,g,r)||!pgns_target_guard(&nsio,p,w,g,&r->namespace,r->page[page],
           &r->target[pass==2?3:pass][page],&current)||!pgcd_equal(&current,&r->descriptor[page],sizeof(current)))return pwcp_fail(r,PWCP_TARGET);
        /* The full source/head/lock/node/target check immediately precedes
         * this page's selected loads. No API, other page or unrelated guard
         * intervenes. Sorted pages preserve each range's partial prefix. */
        uint32_t first=(uint32_t)(r->page[page]-PWCD_UEFI_DB_BASE),last=first+4096;
        for(unsigned index=0;index<PWCP_RANGES;index++){
            struct pwcp_range *q=&r->range[index];uint32_t begin=q->offset>first?q->offset:first;
            uint32_t end=q->offset+q->bytes<last?q->offset+q->bytes:last;
            if(begin>=end)continue;
            if(!pwcp_live(io,p,w,g,r)||q->read[pass]!=begin-q->offset)return pwcp_fail(r,PWCP_PARTIAL);
            r->outstanding=1+pass*PWCP_RANGES+index;paic_actual_order(0);
            for(unsigned at=begin;at<end;at++){
                unsigned k=at-q->offset;q->raw[pass][k]=PWCD_LOAD(PWCD_UEFI_DB_BASE+at);q->read[pass]=k+1;
                if(q->raw[pass][k]!=prepared->database[1][at])return pwcp_fail(r,PWCP_CHANGED);
            }
            paic_actual_order(0);r->outstanding=0;if(!pwcp_live(io,p,w,g,r))return 0;
        }
    }
    for(unsigned index=0;index<PWCP_RANGES;index++)if(r->range[index].read[pass]!=r->range[index].bytes)return pwcp_fail(r,PWCP_PARTIAL);
    return 1;
}
static inline int pwcp_collect(const struct pwcp_io *io,struct pwrcl_result *p,struct pwrph_work *w,
    struct pgcd_context *g,const struct pwsp_result *prepared,struct pwcp_result *r)
{
    if(!r)return 0;if(r->attempted)return pwcp_fail(r,PWCP_ARGUMENT);r->attempted=1;
    if(!io||!io->memory||!io->memory->arch||!io->locate||!io->translate||!p||!w||!g||
       !pgcd_in_self(&p->core,(uintptr_t)r,sizeof(*r)))return pwcp_fail(r,PWCP_ARGUMENT);
    r->provider=(uintptr_t)p;r->core=(uintptr_t)g;r->status=UINT64_MAX;
    if(!pwcp_live(io,p,w,g,r)||!pwcp_preparation(io,p,w,g,prepared,r))return 0;
    static const efi_guid guid={0x1c34f691,0xd33d,0x4e14,{0xb8,0xf8,0x32,0xc6,0xc0,0x29,0xe9,0x5b}};void *table=0;
    if(!pgcd_service_enter(g,&r->locate))return pwcp_fail(r,PWCP_CONTEXT);
    r->outstanding=0x1000;paic_actual_order(0);int returned=io->locate(io->context,io->memory->system,&guid,&table,&r->status);
    r->protocol=(uintptr_t)table;paic_actual_order(0);
    if(!pgcd_service_leave(g,&r->locate,returned))return pwcp_fail(r,PWCP_CONTEXT);r->outstanding=0;
    const struct pwsp_source *old=&prepared->phase[3].source;
    if(r->status||r->protocol!=old->table)return pwcp_fail(r,PWCP_SOURCE);
    r->image=old->image;r->owner_address=old->owner_address;r->database=PWCD_UEFI_DB_BASE;
    for(unsigned k=0;k<p->exclusion_count;k++)if(p->exclusions[k].base==r->image&&p->exclusions[k].bytes==PWCDI_IMAGE_BYTES)r->owner_matches++;
    if(r->owner_matches!=1||!pwcp_source(io,p,w,g,prepared,r,0))return pwcp_fail(r,PWCP_SOURCE);
    const struct pgns_io nsio={io->memory,io->context,io->translate};
    if(!pgns_collect(&nsio,p,w,g,&r->namespace))return pwcp_fail(r,PWCP_NAMESPACE);
    r->range[0].offset=0;r->range[0].bytes=144;
    for(unsigned k=0;k<3;k++){
        r->range[1+2*k].offset=r->resources[0][k].entry;r->range[1+2*k].bytes=24;
        r->range[2+2*k].offset=r->resources[0][k].aux_offset;r->range[2+2*k].bytes=32;
    }
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    for(unsigned k=0;k<4;k++){r->range[7+k].offset=r->VRM[0][k].entry;r->range[7+k].bytes=24;}
#endif
    for(unsigned k=0;k<PWCP_RANGES;k++){
        const struct pwcp_range *q=&r->range[k];
        if(!q->bytes||q->bytes>144||q->offset>PWCD_DB_BYTES-q->bytes)return pwcp_fail(r,PWCP_TARGET);
        for(uint64_t page=(PWCD_UEFI_DB_BASE+q->offset)&~UINT64_C(4095);page<PWCD_UEFI_DB_BASE+q->offset+q->bytes;page+=4096){
            unsigned j;for(j=0;j<r->pages&&r->page[j]!=page;j++){}
            if(j==r->pages){
                if(j==PWCP_PAGES)return pwcp_fail(r,PWCP_TARGET);struct pgcd_descriptor *d=&r->descriptor[j];
                if(!pgns_descriptor(&r->namespace,page,d)||d->type!=2||!(d->capabilities&8)||d->attributes!=8||
                   (!polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,0)&&
                    !polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,4)))return pwcp_fail(r,PWCP_TARGET);
                r->page[r->pages++]=page;
            }
        }
    }
    for(unsigned k=1;k<r->pages;k++)for(unsigned j=k;j&&r->page[j]<r->page[j-1];j--){
        uint64_t page=r->page[j];r->page[j]=r->page[j-1];r->page[j-1]=page;
        struct pgcd_descriptor d=r->descriptor[j];r->descriptor[j]=r->descriptor[j-1];r->descriptor[j-1]=d;
    }
    for(unsigned pass=0;pass<2;pass++){
        if(!pwcp_read_pass(io,p,w,g,prepared,r,pass))return 0;
        if(!pwcp_source(io,p,w,g,prepared,r,pass+1))return 0;
    }
    if(!pwcp_targets(io,p,w,g,r,2)||!pwcp_live(io,p,w,g,r))return 0;
    pgcd_copy(r->resources[1],r->resources[0],sizeof(r->resources[0]));r->bound_after=r->after;r->stable=r->complete=1;paic_actual_order(0);
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    pgcd_copy(r->VRM[1],r->VRM[0],sizeof(r->VRM[0]));
#endif
    return 1;
}
static inline int pwcp_finish(const struct pwcp_io *io,struct pwrcl_result *p,struct pwrph_work *w,
    struct pgcd_context *g,const struct pwsp_result *prepared,struct pwcp_result *r)
{
    if(!r->complete||!r->stable||pwcp_unsafe(r)||r->close_attempted||r->closed||
       r->provider!=(uintptr_t)p||r->core!=(uintptr_t)g||r->preparation!=(uintptr_t)prepared)return pwcp_fail(r,PWCP_ARGUMENT);
    r->close_attempted=1;
    /* After the last original descriptor service, selected bytes receive
     * another immediate per-page guard/read, followed by complete CmdDb
     * source/owner/table/globals closure. No old raw slot is overwritten. */
    if(!pwcp_read_pass(io,p,w,g,prepared,r,2)||!pwcp_source(io,p,w,g,prepared,r,3)||
       !pwcp_live(io,p,w,g,r))return 0;
    r->closed_after=r->after;r->closed=1;paic_actual_order(0);return 1;
}
#endif
#endif
