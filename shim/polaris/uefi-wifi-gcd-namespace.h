/* Bounded original-Core GCD namespace RAM reader. Default OFF; no original
 * descriptor API, lock, TPL service, allocation, SMC or MMIO operation.
 * This is source namespace evidence, never an MPU/VMID/EE grant. */
#ifndef POLARIS_UEFI_WIFI_GCD_NAMESPACE_H
#define POLARIS_UEFI_WIFI_GCD_NAMESPACE_H
#ifndef EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE
#define EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE 0
#endif
#ifndef EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP
#define EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP 0
#endif
#if EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-rpmh-client.h"
#include "uefi-wifi-gcd-namespace-binding.h"
#define PGNS_NODES 512u
struct pgns_translation {uint64_t page,saved,par,restored;uint32_t issued,returned;};
struct pgns_node {uint64_t address;uint32_t bytes,pages;uint8_t raw[PGNS_NODE_BYTES];struct pgns_translation AT[2];};
struct pgns_pass {
    uint32_t attempted,complete,visited,count,head_bytes[2],lock_bytes[2],template_bytes[2];
    uint32_t hash_count[2],hash_failed[2];uint64_t head;
    struct pgcd_arch before,after;
    uint8_t head_raw[2][16],lock_raw[2][24],template_raw[2][80],template_hash[2][32],source_hash[2][5][32];
    struct pgns_translation checkpoint_AT[2][3][2];uint32_t checkpoint_pages[2][3];
    struct pgns_node node[PGNS_NODES];
};
struct pgns_result {uint32_t attempted,error,unknown,outstanding,stable,phase,returned;uint64_t core;struct pgns_pass pass[2];};
struct pgns_target {
    uint32_t attempted,complete,index,head_bytes,lock_bytes,pages[2];uint64_t page;
    uint32_t hash_count,hash_failed;uint8_t source_hash[5][32];
    struct pgcd_arch before,after;uint8_t head[16],lock[24];
    struct pgns_translation AT[2][2],target_AT;struct pgns_node node;
};
struct pgns_io {const struct paic_io *memory;void *context;int (*translate)(void *,struct pgns_translation *);};
enum pgns_error {PGNS_OK,PGNS_ARGUMENT,PGNS_REENTRY,PGNS_CONTEXT,PGNS_SOURCE,PGNS_LOCK,
    PGNS_RAM,PGNS_TRANSLATION,PGNS_LIMIT,PGNS_CYCLE,PGNS_LINK,PGNS_RANGE,PGNS_CHANGED,PGNS_TIME,PGNS_FIRST_NODE_STOP};
static inline int pgns_fail(struct pgns_result *r,unsigned e,int unknown)
{if(!r->error)r->error=e;if(unknown)r->unknown=1;r->returned=1;paic_actual_order(0);return 0;}
static inline int pgns_unsafe(const struct pgns_result *r){return r->unknown||r->outstanding||(r->attempted&&!r->returned);}
static inline int pgns_live(struct pgcd_context *g,struct pgns_result *r,struct pgcd_arch *a)
{
    if(!pwrph_context_ready(g)||pgcd_uncertain(g)||r->core!=g->record->core||
       !pgcd_live(g,a,0)||!pgcd_cached_owner_stable(g)||
       pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8)!=4||
       !pgcd_equal(g->record->DS_raw[0],(const void*)(uintptr_t)g->record->DS,168))return pgns_fail(r,PGNS_CONTEXT,1);
    return 1;
}
static inline int pgns_copy(const struct pgns_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,struct pgns_result *r,void *out,uint64_t at,uint32_t bytes,uint32_t *done,
    struct pgns_translation *trace,uint32_t *pages,int heap)
{
    struct pgcd_arch current;*done=0;
    if(!pgns_live(g,r,&current)||!bytes||at>UINT64_MAX-bytes||at+bytes>UINT64_MAX-4095||
       (heap?((at&7)||!pwrcl_heap(io->memory,p,w,at,bytes)):!pwrcl_owned(io->memory,p,w,at,bytes)))
        return pgns_fail(r,PGNS_RAM,1);
    unsigned k=0;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096){
        if(k==2)return pgns_fail(r,PGNS_RANGE,0);
        struct pgns_translation temporary,*t=trace?&trace[k]:&temporary;
        *t=(struct pgns_translation){.page=page};r->outstanding=1;paic_actual_order(0);
        int returned=io->translate(io->context,t);paic_actual_order(0);
        if(!returned||t->page!=page||t->issued!=1||t->returned!=1||t->saved!=t->restored||
           t->par!=(UINT64_C(0xff00000000000b80)|page))return pgns_fail(r,PGNS_TRANSLATION,1);
        r->outstanding=0;k++;if(pages)*pages=k;
    }
    if(!pgns_live(g,r,&current))return 0;
    r->outstanding=2;paic_actual_order(0);
    for(uint32_t k=0;k<bytes;k++){((uint8_t*)out)[k]=((const volatile uint8_t*)(uintptr_t)at)[k];*done=k+1;}
    paic_actual_order(0);r->outstanding=0;return pgns_live(g,r,&current);
}
static inline int pgns_checkpoint(const struct pgns_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,struct pgns_result *r,struct pgns_pass *s,unsigned slot)
{
    if(!pgns_live(g,r,&s->after)||!pwrcl_owned(io->memory,p,w,r->core,PGCI_IMAGE_BYTES)||
       !pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,
       s->source_hash[slot],&s->hash_failed[slot],&s->hash_count[slot]))return pgns_fail(r,PGNS_SOURCE,1);
    if(!pgns_copy(io,p,w,g,r,s->template_raw[slot],r->core+PGNS_TEMPLATE_RVA,80,&s->template_bytes[slot],s->checkpoint_AT[slot][0],&s->checkpoint_pages[slot][0],0)||
       !pgns_copy(io,p,w,g,r,s->lock_raw[slot],r->core+PGNS_LOCK_RVA,24,&s->lock_bytes[slot],s->checkpoint_AT[slot][1],&s->checkpoint_pages[slot][1],0)||
       !pgns_copy(io,p,w,g,r,s->head_raw[slot],s->head,16,&s->head_bytes[slot],s->checkpoint_AT[slot][2],&s->checkpoint_pages[slot][2],0))return 0;
    struct pwfi_sha256 hash;pwfi_init(&hash);for(unsigned k=0;k<80;k++)pwfi_byte(&hash,s->template_raw[slot][k]);pwfi_final(&hash,s->template_hash[slot]);
    if(!pgcd_equal(s->template_hash[slot],pgns_template_SHA256,32))return pgns_fail(r,PGNS_SOURCE,1);
    /* Released1 is observed, never acquired or interpreted as exclusivity.
     * OwnerTPL is retained even though it may be a prior caller's value. */
    if(pwfi_le(s->lock_raw[slot],8)!=16||pwfi_le(s->lock_raw[slot]+8,8)>16||
       pwfi_le(s->lock_raw[slot]+16,8)!=1)return pgns_fail(r,PGNS_LOCK,0);
    return pgns_live(g,r,&s->after);
}
static inline int pgns_collect(const struct pgns_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,struct pgns_result *r)
{
    if(!r)return 0;if(r->attempted)return pgns_fail(r,PGNS_REENTRY,1);r->attempted=1;
    if(!io||!io->memory||!io->translate||!p||!w||!g||!g->record||g->record!=&p->core||
       !p->client_held||p->client_returned||p->unknown||p->outstanding||!p->exclusion_count||p->exclusion_count>PAIC_HANDLES||
       !pgcd_in_self(g->record,(uintptr_t)r,sizeof(*r))||!pwrcl_owned(io->memory,p,w,(uintptr_t)r,sizeof(*r)))
        return pgns_fail(r,PGNS_ARGUMENT,0);
    r->core=g->record->core;
    for(unsigned pass=0;pass<2;pass++){
        struct pgns_pass *s=&r->pass[pass];s->attempted=1;s->head=r->core+PGNS_HEAD_RVA;r->phase=pass+1;
        if(!pgns_live(g,r,&s->before)||!pgns_checkpoint(io,p,w,g,r,s,0))return 0;
        uint64_t cursor=pwfi_le(s->head_raw[0],8),previous=s->head,end=0;
        if(!cursor||!pwfi_le(s->head_raw[0]+8,8)||cursor==s->head)return pgns_fail(r,PGNS_LINK,0);
        while(cursor!=s->head){
            if(s->count==PGNS_NODES)return pgns_fail(r,PGNS_LIMIT,1);
            if(cursor<8||(cursor&7))return pgns_fail(r,PGNS_LINK,1);
            uint64_t address=cursor-8;
            for(unsigned k=0;k<s->count;k++)if(pwrcl_overlap(address,80,s->node[k].address,80))return pgns_fail(r,PGNS_CYCLE,1);
            struct pgns_node *n=&s->node[s->count];n->address=address;s->visited=s->count+1;
            if(!pgns_copy(io,p,w,g,r,n->raw,address,80,&n->bytes,n->AT,&n->pages,1))return 0;
#if EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP
            /* Explicit raw-read cutpoint BEFORE interpreting node fields.
             * Owned RAM/exclusion/AT/PAR/source/context/time gates still cover
             * the entire80B. This partial record never admits the namespace
             * or any database load, even if its signature/fields differ. */
            s->count=1;
            if(!pgns_checkpoint(io,p,w,g,r,s,1))return 0;
            if(!pgcd_equal(s->head_raw[0],s->head_raw[1],16)||!pgcd_equal(s->lock_raw[0],s->lock_raw[1],24)||
               !pgcd_equal(s->template_raw[0],s->template_raw[1],80))return pgns_fail(r,PGNS_CHANGED,1);
            return pgns_fail(r,PGNS_FIRST_NODE_STOP,0);
#else
            uint64_t base=pwfi_le(n->raw+24,8),last=pwfi_le(n->raw+32,8);
            if(pwfi_le(n->raw,8)!=PGNS_SIGNATURE||pwfi_le(n->raw+16,8)!=previous||!pwfi_le(n->raw+8,8)||
               last<base||pwfi_le(n->raw+56,4)>4||pwfi_le(n->raw+60,4)||
               (!s->count&&base)||(s->count&&(end==UINT64_MAX||base!=end+1)))return pgns_fail(r,PGNS_RANGE,1);
            previous=cursor;cursor=pwfi_le(n->raw+8,8);end=last;s->count++;
#endif
        }
        if(previous!=pwfi_le(s->head_raw[0]+8,8)||end<UINT64_C(0x85ffffff)||!pgns_checkpoint(io,p,w,g,r,s,1))return pgns_fail(r,PGNS_LINK,1);
        if(!pgcd_equal(s->head_raw[0],s->head_raw[1],16)||!pgcd_equal(s->lock_raw[0],s->lock_raw[1],24)||
           !pgcd_equal(s->template_raw[0],s->template_raw[1],80))return pgns_fail(r,PGNS_CHANGED,1);
        s->complete=1;
    }
    const struct pgns_pass *a=&r->pass[0],*b=&r->pass[1];
    if(a->count!=b->count||!pgcd_equal(a->head_raw[0],b->head_raw[0],16)||!pgcd_equal(a->lock_raw[0],b->lock_raw[0],24))return pgns_fail(r,PGNS_CHANGED,1);
    for(unsigned k=0;k<a->count;k++)if(a->node[k].address!=b->node[k].address||!pgcd_equal(a->node[k].raw,b->node[k].raw,80))return pgns_fail(r,PGNS_CHANGED,1);
    r->stable=r->returned=1;return 1;
}
static inline int pgns_first_node_stopped(const struct pgns_result *r)
{
    const struct pgns_pass *s=&r->pass[0];
    if(!EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP||r->attempted!=1||r->error!=PGNS_FIRST_NODE_STOP||pgns_unsafe(r)||
       r->returned!=1||r->stable||r->phase!=1||s->complete||s->count!=1||s->visited!=1||
       r->pass[1].attempted||s->node[0].bytes!=80||!s->node[0].pages||s->node[0].pages>2)return 0;
    for(unsigned k=0;k<2;k++)if(s->hash_count[k]!=5||s->hash_failed[k]||s->head_bytes[k]!=16||s->lock_bytes[k]!=24||s->template_bytes[k]!=80)return 0;
    return 1;
}
/* Pure lookup of a completed captured namespace, NOT a fabricated original
 * API status, a fresh namespace check or permission to load target memory.
 * The future physical caller must revalidate its same source/context/time. */
static inline int pgns_descriptor(const struct pgns_result *r,uint64_t page,struct pgcd_descriptor *out)
{
    if(!r||!out||r->attempted!=1||r->stable!=1||r->returned!=1||r->error||r->unknown||r->outstanding||
       r->pass[0].complete!=1||r->pass[1].complete!=1||!r->pass[1].count||r->pass[1].count>PGNS_NODES||(page&4095)||
       page<UINT64_C(0x85fe0000)||page>UINT64_C(0x86000000)-4096)return 0;
    for(unsigned k=0;k<r->pass[1].count;k++){
        const uint8_t *n=r->pass[1].node[k].raw;uint64_t base=pwfi_le(n+24,8),end=pwfi_le(n+32,8);
        if(base<=page&&end>=page+4095){
            if(end-base==UINT64_MAX)return 0;
            *out=(struct pgcd_descriptor){base,end-base+1,pwfi_le(n+40,8),pwfi_le(n+48,8),
                (uint32_t)pwfi_le(n+56,4),0,pwfi_le(n+64,8),pwfi_le(n+72,8)};return 1;
        }
    }return 0;
}
/* Immediate same-context validation of the exact captured head, released-lock
 * observation and target node. This only admits the immutable CmdDb RAM read;
 * no descriptor status is invented and no Device/MMIO address is accepted.
 * The caller still checks its current map and fresh target NS/WB AT, and keeps
 * the original source hashes around the complete database copies. */
static inline int pgns_target_guard(const struct pgns_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,struct pgns_result *r,uint64_t page,struct pgns_target *s,struct pgcd_descriptor *out)
{
    if(!s||s->attempted||!pgns_descriptor(r,page,out))return pgns_fail(r,PGNS_ARGUMENT,1);
    s->attempted=1;s->page=page;
    for(s->index=0;s->index<r->pass[1].count;s->index++){
        const struct pgns_node *n=&r->pass[1].node[s->index];
        if(pwfi_le(n->raw+24,8)==out->base)break;
    }
    if(s->index==r->pass[1].count||!pgns_live(g,r,&s->before))return pgns_fail(r,PGNS_CONTEXT,1);
    if(!pwrcl_owned(io->memory,p,w,r->core,PGCI_IMAGE_BYTES)||
       !pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,
        s->source_hash,&s->hash_failed,&s->hash_count))return pgns_fail(r,PGNS_SOURCE,1);
    s->node.address=r->pass[1].node[s->index].address;
    if(!pgns_copy(io,p,w,g,r,s->head,r->core+PGNS_HEAD_RVA,16,&s->head_bytes,s->AT[0],&s->pages[0],0)||
       !pgns_copy(io,p,w,g,r,s->lock,r->core+PGNS_LOCK_RVA,24,&s->lock_bytes,s->AT[1],&s->pages[1],0)||
       !pgns_copy(io,p,w,g,r,s->node.raw,s->node.address,80,&s->node.bytes,s->node.AT,&s->node.pages,1))return 0;
    if(!pgcd_equal(s->head,r->pass[1].head_raw[1],16)||!pgcd_equal(s->lock,r->pass[1].lock_raw[1],24)||
       !pgcd_equal(s->node.raw,r->pass[1].node[s->index].raw,80))return pgns_fail(r,PGNS_CHANGED,1);
    s->target_AT.page=page;r->outstanding=1;paic_actual_order(0);
    int returned=io->translate(io->context,&s->target_AT);paic_actual_order(0);
    const struct pgns_translation *t=&s->target_AT;
    if(!returned||t->page!=page||t->issued!=1||t->returned!=1||t->saved!=t->restored||
       t->par!=(UINT64_C(0xff00000000000b80)|page))return pgns_fail(r,PGNS_TRANSLATION,1);
    r->outstanding=0;
    if(!pgns_live(g,r,&s->after))return 0;s->complete=1;return 1;
}
static inline int pgns_actual_translate(void *context,struct pgns_translation *t)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    t->issued=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,par_el1\n\tat s1e1r,%3\n\tisb\n\tmrs %1,par_el1\n\tmsr par_el1,%0\n\tisb\n\tmrs %2,par_el1"
        :"=&r"(t->saved),"=&r"(t->par),"=&r"(t->restored):"r"(t->page):"memory");
    t->returned=1;paic_actual_order(0);return 1;
#else
    (void)t;return 0;
#endif
}
#endif
#endif
