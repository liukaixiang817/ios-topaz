/* NEW0144 exact ConfigurationTable RO runtime-data scope.
 * Extends only the latched UEFI ConfigurationTable span; runtime RAM never
 * becomes reclaimable, writable, executable or an MMIO/ownership capability.
 * Original0143 source/manifest and frozen phone controller stay unchanged.
 * Registered original DxeCore GCD descriptor query only.
 * This never edits old0142 policy or registers/allocates an MMIO resource.
 * GCD classification+AT is not an exclusive clock/I2C/DMA/power owner lease.
 * Internal original RestoreTPL can dispatch original firmware events; all
 * calls belong to prepare stage2, CPU0EL1/DAIF0/GROUP1 on, never SFPB critical.
 */
#ifndef POLARIS_UEFI_GCD_MMIO_READONLY_H
#define POLARIS_UEFI_GCD_MMIO_READONLY_H
#include "gcd-core-identity.h"
#ifndef EFI_XNU_GCD_MMIO_QUERY_AVAILABLE
#define EFI_XNU_GCD_MMIO_QUERY_AVAILABLE 0
#endif
#define PGCD_MAP_CAP 8192u
#define PGCD_CONFIG_MAX 128u
#define PGCD_PAGES 4u
#define PGCD_FRESH_TICKS UINT64_C(3840000)
static const uint64_t pgcd_pages[4]={0x10b000,0x117000,0x152000,0x18a000};
struct pgcd_descriptor {uint64_t base,length,capabilities,attributes;uint32_t type,pad;uint64_t image_handle,device_handle;};
_Static_assert(sizeof(struct pgcd_descriptor)==56,"original GCD descriptor ABI");
struct pgcd_arch {struct pwfc_arch cpu;uint64_t cpacr;};
struct pgcd_fp_guard {
    uint64_t cpacr_before,cpacr_after,fpcr,fpsr;uint64_t q8_q15[16] __attribute__((aligned(16)));
    uint32_t saved,restored;
};
struct pgcd_service_guard {
    struct pgcd_arch before,after;
    struct pgcd_fp_guard fp;
    uint64_t TPL_before,TPL_after,boot_before,boot_after,tables_before,tables_after,count_before,count_after;
    uint32_t entered,left,foreign_returned,unknown;
};
struct pgcd_observation {
    uint64_t page,status,before_ticks,after_ticks;
    volatile uint32_t issued,returned,unknown,reserved;
    struct pgcd_descriptor descriptor;
    struct pgcd_service_guard guard;
};
struct pgcd_map {
    uint64_t status,bytes,key,stride;uint32_t version;volatile uint32_t issued,returned;uint32_t valid;
};
struct pgcd_config {efi_guid guid;uint64_t table;};
struct pgcd_prestart {struct pgcd_arch arch;uint64_t TPL,boot,tables,count;uint32_t issued,completed,hash_count,hash_failed;uint8_t hashes[PGCI_RANGE_COUNT][32];};
struct pgcd_config_span {
    uint64_t pointer,bytes;
    struct efi_memory descriptor;
    uint64_t address[2],par[2];
    volatile uint32_t attempted,admission_class,issued,completed,error;
    uint32_t reserved;
};
_Static_assert(sizeof(struct pgcd_config_span)==112,"exact config span raw ABI");
struct pgcd_result {
    uint64_t self_base,self_bytes,self_system,core,DS,get_descriptor,config_pointer,config_count,self_owner_address;
    struct efi_loaded self_owner;
    struct pgcd_arch before,after;
    struct pgcd_map map[2];struct pgcd_service_guard map_guard[2];
    uint64_t last_identity_address,last_identity_par,original_GetMap,TPL_initial,TPL_final;
    uint32_t attempted,error,phase,uncertain,outstanding,pre_mask,post_mask,DS_matches,DS_index,self_bound;
    uint32_t hash_count[2],hash_failed[2],arch_issued,arch_returned;
    uint8_t hashes[2][PGCI_RANGE_COUNT][32],DS_raw[2][168],GCD_lock_raw[2][24];
    struct pgcd_config config[2][PGCD_CONFIG_MAX];
    struct pgcd_observation query[2][PGCD_PAGES];
    uint32_t prestart_count;struct pgcd_prestart prestart[2];
    uint8_t maps[2][PGCD_MAP_CAP] __attribute__((aligned(8)));
    uint64_t preserved0143_tail_padding; /* original30000B includes this8B */
    struct pgcd_config_span config_span[2];
};
struct pgcd_lifetime {volatile uint32_t spent;uint64_t result;};
struct pgcd_io {
    void *opaque;struct efi_system *system;
    int (*arch)(void *,struct pgcd_arch *);
    int (*map)(void *,struct efi_system *,struct pgcd_map *,void *);
    int (*identity)(void *,uint64_t,uint64_t,uint64_t *,uint64_t *);
    int (*query)(void *,uint64_t,uint64_t,struct pgcd_descriptor *,uint64_t *);
    int (*fp_save)(void *,struct pgcd_fp_guard *);
    int (*fp_restore)(void *,struct pgcd_fp_guard *);
    void (*order)(void *);
};
struct pgcd_context {struct pgcd_io io;struct pgcd_result *record;struct pgcd_lifetime *ticket;uint32_t stage,opened,finished;};
enum pgcd_error {PGCD_OK,PGCD_DISABLED,PGCD_STAGE,PGCD_SELF,PGCD_ARCH,PGCD_CLOCK,PGCD_MAP,PGCD_CORE,PGCD_HASH,PGCD_CONFIG,PGCD_TABLE,PGCD_PAGE,PGCD_QUERY,PGCD_UNKNOWN,PGCD_CHANGED,PGCD_LIFETIME};
/* Stable adapter interface. out points into this boot's resident append-only
 * raw query slot BEFORE original entry. 1 means returned EFI_SUCCESS only;
 * callers must still inspect raw descriptor/class/AT and never infer a lease.
 * First query opens lazily, after the Clock caller finishes BS allocations.
 * finish rereads four pages and the map/table/config before caller FreePool. */
static inline int pgcd_service_enter(struct pgcd_context *,struct pgcd_service_guard *);
static inline int pgcd_service_leave(struct pgcd_context *,struct pgcd_service_guard *,int);
static inline int pgcd_query_page(struct pgcd_context *,uint64_t,const struct pgcd_observation **);
static inline int pgcd_finish(struct pgcd_context *);
static inline int pgcd_uncertain(const struct pgcd_context *c){return !c||!c->record||c->record->uncertain||c->record->outstanding;}
static inline void pgcd_fail(struct pgcd_context *c,unsigned e,int unknown)
{if(c&&c->record){if(!c->record->error)c->record->error=e;if(unknown)c->record->uncertain=1;if(c->io.order)c->io.order(c->io.opaque);}}
static inline void pgcd_poison(struct pgcd_context *c)
{pgcd_fail(c,PGCD_CHANGED,1);}
static inline int pgcd_equal(const void *a,const void *b,size_t n)
{return pwfc_equal(a,b,n);}
static inline void pgcd_copy(void *a,const void *b,size_t n)
{for(size_t k=0;k<n;k++)((uint8_t*)a)[k]=((const volatile uint8_t*)b)[k];}
static inline int pgcd_live(struct pgcd_context *c,struct pgcd_arch *a,int after_call)
{
    struct pgcd_result *r=c->record;r->arch_issued++;uint64_t previous=r->after.cpu.ticks;struct pgcd_arch now={0};
    if(!c->io.arch(c->io.opaque,&now)){pgcd_fail(c,PGCD_ARCH,after_call);return 0;}r->arch_returned++;
    unsigned first=!r->before.cpu.ticks;*a=now;r->after=now;
    if(!pwfc_arch_admitted(&a->cpu)||a->cpu.mair!=UINT64_C(0xffbb4400)||((a->cpacr>>20)&3)!=3){pgcd_fail(c,PGCD_ARCH,after_call);return 0;}
    if(first){r->before=*a;return 1;}
    if(!pwfc_arch_stable(&r->before.cpu,&a->cpu)||a->cpacr!=r->before.cpacr){pgcd_fail(c,PGCD_ARCH,after_call);return 0;}
    if(a->cpu.ticks<previous){pgcd_fail(c,PGCD_CLOCK,after_call);return 0;}
    if(a->cpu.ticks-r->before.cpu.ticks>PGCD_FRESH_TICKS){pgcd_fail(c,PGCD_CLOCK,0);return 0;}
    return 1;
}
static inline int pgcd_owned(struct pgcd_context *c,unsigned slot,uint64_t at,uint64_t bytes)
{
    struct pgcd_result *r=c->record;struct pgcd_map *m=&r->map[slot];
    if(!m->valid||!bytes||at>UINT64_MAX-bytes||at+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t p=at&~UINT64_C(4095);p<at+bytes;p+=4096)
        if(!polaris_efi_range_owned(r->maps[slot],m->bytes,m->stride,p,4096,3)&&!polaris_efi_range_owned(r->maps[slot],m->bytes,m->stride,p,4096,4))return 0;
    return c->io.identity(c->io.opaque,at,bytes,&r->last_identity_address,&r->last_identity_par);
}
static inline int pgcd_map_read(struct pgcd_context *c,unsigned slot)
{
    struct pgcd_result *r=c->record;struct pgcd_map *m=&r->map[slot];struct pgcd_service_guard *g=&r->map_guard[slot];
    /* First standard GetMap authority is the incoming UEFI BS contract. No
     * core/TPL address is dereferenced before this map+AT identity establishes
     * RAM bounds. UINT64_MAX means TPL NOT_OBSERVED, never a proven TPL value. */
    g->before=r->after;g->TPL_before=g->TPL_after=UINT64_MAX;
    g->boot_before=(uintptr_t)c->io.system->boot;g->tables_before=(uintptr_t)c->io.system->tables;g->count_before=c->io.system->table_count;
    if(slot)g->TPL_before=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);
    if(!c->io.fp_save(c->io.opaque,&g->fp)){pgcd_fail(c,PGCD_ARCH,0);return 0;}
    g->entered=1;g->unknown=1;m->bytes=PGCD_MAP_CAP;m->issued=1;r->outstanding=0x20000u+slot;
    c->io.order(c->io.opaque);int returned=c->io.map(c->io.opaque,c->io.system,m,r->maps[slot]);
    m->returned=returned?1u:0u;g->foreign_returned=m->returned;
    int arch=pgcd_live(c,&g->after,1);int fp=c->io.fp_restore(c->io.opaque,&g->fp);
    g->boot_after=(uintptr_t)c->io.system->boot;g->tables_after=(uintptr_t)c->io.system->tables;g->count_after=c->io.system->table_count;
    if(slot)g->TPL_after=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);g->left=1;c->io.order(c->io.opaque);
    if(!returned||!arch||!fp||!g->fp.restored||g->TPL_before!=g->TPL_after||g->boot_before!=g->boot_after||g->tables_before!=g->tables_after||g->count_before!=g->count_after){pgcd_fail(c,PGCD_UNKNOWN,1);return 0;}
    g->unknown=0;c->io.order(c->io.opaque);r->outstanding=0;c->io.order(c->io.opaque);
    struct polaris_efi_memory checked;
    if(m->status||!m->key||m->version!=1||!polaris_efi_memory_check(r->maps[slot],m->bytes,PGCD_MAP_CAP,m->stride,&checked)){pgcd_fail(c,PGCD_MAP,0);return 0;}
    m->valid=1;return 1;
}
/* Read only the exact incoming/later-still-latched ConfigurationTable.
 * The original InstallConfigurationTable allocates its table with type6.
 * A validated map classification does not grant any other runtime access.
 * One descriptor must cover the full span, including both boundary pages;
 * the map has already rejected physical descriptor alias/overlap. */
static inline int pgcd_config_readonly(struct pgcd_context *c,unsigned pass)
{
    if(pass>1)return 0;
    struct pgcd_result *r=c->record;struct pgcd_config_span *p=&r->config_span[pass];
    const struct pgcd_map *m=&r->map[pass];struct efi_system *s=c->io.system;
    if(p->attempted)return 0;
    p->attempted=1;p->pointer=r->config_pointer;
    if(!r->config_count||r->config_count>PGCD_CONFIG_MAX||!p->pointer||!m->valid){p->error=1;return 0;}
    p->bytes=r->config_count*sizeof(struct pgcd_config);
    if(p->bytes>3072||p->pointer>UINT64_MAX-p->bytes||p->pointer+p->bytes>UINT64_MAX-4095){p->error=2;return 0;}
    uint64_t end=p->pointer+p->bytes;
    if((p->pointer<r->self_base+r->self_bytes&&r->self_base<end)||
       (p->pointer<r->core+PGCI_IMAGE_BYTES&&r->core<end)){p->error=3;return 0;}
    if((uintptr_t)s->tables!=p->pointer||s->table_count!=r->config_count){p->error=4;pgcd_fail(c,PGCD_CHANGED,1);return 0;}
    unsigned matches=0;
    for(uint64_t at=0;at<m->bytes;at+=m->stride){
        const struct efi_memory *d=(const void*)(r->maps[pass]+at);
        uint64_t stop=d->physical+d->pages*4096;
        if(d->physical<=p->pointer&&end<=stop){p->descriptor=*d;matches++;}
    }
    if(matches!=1){p->error=5;return 0;}
    if((p->descriptor.type==3||p->descriptor.type==4)&&!(p->descriptor.attributes>>63))p->admission_class=1;
    else if(p->descriptor.type==6&&p->descriptor.attributes==UINT64_C(0x800000000000000f))p->admission_class=2;
    else {p->error=6;return 0;}
    unsigned n=0;
    for(uint64_t page=p->pointer&~UINT64_C(4095);page<end;page+=4096,n++){
        if(n>=2){p->error=7;return 0;}
        p->address[n]=page;p->par[n]=UINT64_MAX;p->issued|=1u<<n;r->outstanding=0x40000u|(pass<<4)|n;c->io.order(c->io.opaque);
        uint64_t actual=UINT64_MAX;int identity=c->io.identity(c->io.opaque,page,4096,&actual,&p->par[n]);
        p->completed|=1u<<n;c->io.order(c->io.opaque);r->outstanding=0;c->io.order(c->io.opaque);
        /* Callback return is an identity verdict, not an invented delivery
         * status. Its actual AT F/raw result remains recorded on refusal. */
        if(!identity||actual!=page||(p->par[n]&1)||(p->par[n]&UINT64_C(0x0000fffffffff000))!=page){p->error=8;return 0;}
        if(p->admission_class==2&&p->par[n]!=(UINT64_C(0xff00000000000b80)|page)){p->error=9;return 0;}
    }
    if((uintptr_t)s->tables!=p->pointer||s->table_count!=r->config_count){p->error=4;pgcd_fail(c,PGCD_CHANGED,1);return 0;}
    return 1;
}
static inline int pgcd_crc(const uint8_t *p,unsigned bytes)
{
    uint32_t actual=(uint32_t)pwfi_le(p+16,4);if(!actual)return 1;uint32_t crc=UINT32_MAX;
    for(unsigned n=0;n<bytes;n++){uint8_t b=n>=16&&n<20?0:p[n];crc^=b;for(unsigned j=0;j<8;j++)crc=(crc>>1)^(UINT32_C(0xedb88320)&(0u-(crc&1)));}
    return (crc^UINT32_MAX)==actual;
}
static inline int pgcd_snapshot(struct pgcd_context *c,unsigned pass)
{
    struct pgcd_result *r=c->record;struct efi_system *s=c->io.system;
    if((uintptr_t)s->boot!=r->core+0x1b800||(uintptr_t)s->boot->get_map!=r->core+0xd3ec||
       (uintptr_t)s->tables!=r->config_pointer||s->table_count!=r->config_count){pgcd_fail(c,PGCD_CHANGED,pass);return 0;}
    if(!pgcd_owned(c,pass,r->core,PGCI_IMAGE_BYTES)||!pgcd_config_readonly(c,pass)){pgcd_fail(c,PGCD_CORE,pass);return 0;}
    pgcd_copy(r->DS_raw[pass],(const void*)(uintptr_t)r->DS,168);
    if(pwfi_le(r->DS_raw[pass],8)!=UINT64_C(0x565245535f455844)||pwfi_le(r->DS_raw[pass]+8,4)!=0x10046||pwfi_le(r->DS_raw[pass]+12,4)!=168||pwfi_le(r->DS_raw[pass]+20,4)||!pgcd_crc(r->DS_raw[pass],168)||pwfi_le(r->DS_raw[pass]+0x38,8)!=r->get_descriptor){pgcd_fail(c,PGCD_TABLE,pass);return 0;}
    if(!pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,r->hashes[pass],&r->hash_failed[pass],&r->hash_count[pass])){pgcd_fail(c,PGCD_HASH,pass);return 0;}
    pgcd_copy(r->config[pass],(const void*)(uintptr_t)r->config_pointer,r->config_count*sizeof(struct pgcd_config));
    if((uintptr_t)s->tables!=r->config_pointer||s->table_count!=r->config_count){pgcd_fail(c,PGCD_CHANGED,1);return 0;}
    static const efi_guid guid={0x05ad34ba,0x6f02,0x4214,{0x95,0x2e,0x4d,0xa0,0x39,0x8e,0x2b,0xb9}};
    unsigned matches=0,index=0;
    for(unsigned k=0;k<r->config_count;k++)if(pgcd_equal(&r->config[pass][k].guid,&guid,sizeof(guid))){matches++;index=k;if(r->config[pass][k].table!=r->DS){pgcd_fail(c,PGCD_TABLE,pass);return 0;}}
    if(matches!=1){pgcd_fail(c,PGCD_CONFIG,pass);return 0;}r->DS_matches=matches;r->DS_index=index;
    pgcd_copy(r->GCD_lock_raw[pass],(const void*)(uintptr_t)(r->core+0x1bd48),24);
    if(pwfi_le(r->GCD_lock_raw[pass],8)!=16||pwfi_le(r->GCD_lock_raw[pass]+16,4)!=1){pgcd_fail(c,PGCD_LIFETIME,pass);return 0;}
    if(pass&&(!pgcd_equal(r->DS_raw[0],r->DS_raw[1],168)||!pgcd_equal(r->config[0],r->config[1],r->config_count*sizeof(struct pgcd_config)))){pgcd_fail(c,PGCD_CHANGED,1);return 0;}
    return 1;
}
static inline int pgcd_in_self(const struct pgcd_result *r,uint64_t at,uint64_t bytes)
{return bytes&&r->self_bytes>=bytes&&at>=r->self_base&&at-r->self_base<=r->self_bytes-bytes;}
static inline int pgcd_bind(struct pgcd_result *r,const struct efi_loaded *image)
{
    if(!r||!image||r->self_bound||r->attempted)return 0;
    uint64_t b=(uintptr_t)image->base;
    if(image->revision!=0x1000||image->code_type!=3||image->data_type!=4||!b||!image->bytes||b>UINT64_MAX-image->bytes||!image->system)return 0;
    r->self_base=b;r->self_bytes=image->bytes;r->self_system=(uintptr_t)image->system;
    if(!pgcd_in_self(r,(uintptr_t)r,sizeof(*r))||(b<0x86200000&&0x86000000<b+image->bytes))return 0;
    r->self_owner_address=(uintptr_t)image;r->self_owner=*image;r->self_bound=1;return 1;
}
static inline int pgcd_open(struct pgcd_context *c)
{
    if(!c||!c->record||!c->ticket)return 0;
    struct pgcd_result *r=c->record;
    if(!r->self_bound||!pgcd_in_self(r,(uintptr_t)r,sizeof(*r))||!pgcd_in_self(r,(uintptr_t)c,sizeof(*c))||!pgcd_in_self(r,(uintptr_t)c->ticket,sizeof(*c->ticket))){pgcd_fail(c,PGCD_SELF,0);return 0;}
    if(r->attempted||c->ticket->spent)return 0;
    c->ticket->spent=1;c->ticket->result=(uintptr_t)r;r->attempted=1;
    if(c->stage!=2){pgcd_fail(c,PGCD_STAGE,0);return 0;}
    if(!r->self_bound||!c->io.system||!c->io.system->boot||!c->io.system->boot->get_map||!c->io.arch||!c->io.map||!c->io.identity||!c->io.query||!c->io.fp_save||!c->io.fp_restore||!c->io.order||r->self_system!=(uintptr_t)c->io.system){pgcd_fail(c,PGCD_SELF,0);return 0;}
    if(!pgcd_live(c,&r->before,0)||!pgcd_map_read(c,0)||!pgcd_live(c,&r->after,1))return 0;
    if(!pgcd_in_self(r,(uintptr_t)r,sizeof(*r))||!pgcd_in_self(r,(uintptr_t)c,sizeof(*c))||!pgcd_in_self(r,(uintptr_t)c->ticket,sizeof(*c->ticket))||
       !pgcd_owned(c,0,r->self_owner_address,sizeof(r->self_owner))||!pgcd_equal(&r->self_owner,(const void*)(uintptr_t)r->self_owner_address,sizeof(r->self_owner))||
       r->self_owner.system!=c->io.system||r->self_owner.base!=(void*)(uintptr_t)r->self_base||r->self_owner.bytes!=r->self_bytes||r->self_owner.revision!=0x1000||r->self_owner.code_type!=3||r->self_owner.data_type!=4||
       !pgcd_owned(c,0,(uintptr_t)r,sizeof(*r))||!pgcd_owned(c,0,(uintptr_t)c,sizeof(*c))||!pgcd_owned(c,0,(uintptr_t)c->ticket,sizeof(*c->ticket))){pgcd_fail(c,PGCD_SELF,0);return 0;}
    uint64_t bs=(uintptr_t)c->io.system->boot;if(bs<0x1b800){pgcd_fail(c,PGCD_CORE,0);return 0;}
    r->core=bs-0x1b800;r->DS=r->core+0x1bb18;r->get_descriptor=r->core+0x2c68;r->original_GetMap=(uintptr_t)c->io.system->boot->get_map;
    r->config_pointer=(uintptr_t)c->io.system->tables;r->config_count=c->io.system->table_count;
    if((r->core&4095)||r->core>UINT64_MAX-PGCI_IMAGE_BYTES||!r->config_count||r->config_count>PGCD_CONFIG_MAX||!r->config_pointer||!pgcd_snapshot(c,0)){if(!r->error)pgcd_fail(c,PGCD_CORE,0);return 0;}
    r->TPL_initial=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);
    if(r->TPL_initial>16){pgcd_fail(c,PGCD_STAGE,0);return 0;}c->opened=1;r->phase=1;return 1;
}
static inline int pgcd_cached_owner_stable(const struct pgcd_context *c)
{
    const struct pgcd_result *r=c->record;
    return pgcd_equal(&r->self_owner,(const void*)(uintptr_t)r->self_owner_address,sizeof(r->self_owner))&&
        pgcd_equal(r->config[0],(const void*)(uintptr_t)r->config_pointer,r->config_count*sizeof(struct pgcd_config));
}
static inline int pgcd_service_enter(struct pgcd_context *c,struct pgcd_service_guard *g)
{
    if(!c||!g||!c->record||!c->opened||c->finished||pgcd_uncertain(c)||g->entered)return 0;
    struct pgcd_result *r=c->record;
    if(!pgcd_in_self(r,(uintptr_t)g,sizeof(*g))||!pgcd_owned(c,0,(uintptr_t)g,sizeof(*g))){pgcd_fail(c,PGCD_SELF,0);return 0;}
    if(!pgcd_live(c,&g->before,0))return 0;
    g->TPL_before=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);g->boot_before=(uintptr_t)c->io.system->boot;g->tables_before=(uintptr_t)c->io.system->tables;g->count_before=c->io.system->table_count;
    if(g->TPL_before>16||g->boot_before!=r->core+0x1b800||g->tables_before!=r->config_pointer||g->count_before!=r->config_count||!pgcd_equal(r->DS_raw[0],(const void*)(uintptr_t)r->DS,168)||!pgcd_cached_owner_stable(c)){pgcd_fail(c,PGCD_CHANGED,1);return 0;}
    if(!c->io.fp_save(c->io.opaque,&g->fp)){pgcd_fail(c,PGCD_ARCH,0);return 0;}
    g->entered=1;g->unknown=1;r->outstanding=0x10000;c->io.order(c->io.opaque);return 1;
}
static inline int pgcd_service_leave(struct pgcd_context *c,struct pgcd_service_guard *g,int returned)
{
    if(!c||!g||!g->entered||g->left)return 0;struct pgcd_result *r=c->record;g->foreign_returned=returned?1u:0u;
    int arch=pgcd_live(c,&g->after,1);int fp=c->io.fp_restore(c->io.opaque,&g->fp);
    g->TPL_after=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);g->boot_after=(uintptr_t)c->io.system->boot;g->tables_after=(uintptr_t)c->io.system->tables;g->count_after=c->io.system->table_count;g->left=1;
    c->io.order(c->io.opaque);
    if(!returned||!arch||!fp||!g->fp.restored||g->TPL_before!=g->TPL_after||g->boot_before!=g->boot_after||g->tables_before!=g->tables_after||g->count_before!=g->count_after||!pgcd_equal(r->DS_raw[0],(const void*)(uintptr_t)r->DS,168)||!pgcd_cached_owner_stable(c)){pgcd_fail(c,PGCD_UNKNOWN,1);return 0;}
    g->unknown=0;c->io.order(c->io.opaque);r->outstanding=0;c->io.order(c->io.opaque);return 1;
}
static inline int pgcd_one(struct pgcd_context *c,unsigned pass,unsigned k)
{
    struct pgcd_result *r=c->record;struct pgcd_observation *q=&r->query[pass][k];if(q->issued)return q->returned&&!q->unknown&&!q->status;
    q->page=pgcd_pages[k];q->status=UINT64_MAX;
    if(!pgcd_service_enter(c,&q->guard))return 0;
    q->before_ticks=q->guard.before.cpu.ticks;q->issued=1;q->unknown=1;c->io.order(c->io.opaque);
    int returned=c->io.query(c->io.opaque,r->get_descriptor,q->page,&q->descriptor,&q->status);q->returned=returned?1u:0u;c->io.order(c->io.opaque);
    if(!pgcd_service_leave(c,&q->guard,returned))return 0;q->after_ticks=q->guard.after.cpu.ticks;q->unknown=0;c->io.order(c->io.opaque);
    return !q->status;
}
static inline int pgcd_query_page(struct pgcd_context *c,uint64_t page,const struct pgcd_observation **out)
{
    if(out)*out=0;if(!c||!out||!c->record||c->finished)return 0;
    if(!c->opened&&!pgcd_open(c))return 0;
    unsigned k;for(k=0;k<4&&page!=pgcd_pages[k];k++){}if(k==4){pgcd_fail(c,PGCD_PAGE,0);return 0;}
    *out=&c->record->query[0][k];if(pgcd_uncertain(c))return 0;
    c->record->pre_mask|=1u<<k;c->io.order(c->io.opaque);return pgcd_one(c,0,k);
}
static inline int pgcd_finish(struct pgcd_context *c)
{
    if(!c||!c->record||!c->opened||c->finished||pgcd_uncertain(c))return 0;struct pgcd_result *r=c->record;c->finished=1;
    if(r->pre_mask!=15){pgcd_fail(c,PGCD_LIFETIME,0);return 0;}
    /* The last four registered descriptor queries run before finish is closed
     * to further Clock calls. Temporarily keep service guard entry eligible. */
    c->finished=0;
    for(unsigned k=0;k<4;k++){r->post_mask|=1u<<k;(void)pgcd_one(c,1,k);if(pgcd_uncertain(c)){c->finished=1;return 0;}
        if(r->query[0][k].status!=r->query[1][k].status||!pgcd_equal(&r->query[0][k].descriptor,&r->query[1][k].descriptor,56)){pgcd_fail(c,PGCD_CHANGED,1);c->finished=1;return 0;}}
    c->finished=1;
    if(!pgcd_map_read(c,1)||!pgcd_snapshot(c,1)||!pgcd_live(c,&r->after,1))return 0;
    r->TPL_final=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);
    if(r->TPL_final!=r->TPL_initial||r->map[0].bytes!=r->map[1].bytes||r->map[0].key!=r->map[1].key||r->map[0].stride!=r->map[1].stride||!pgcd_equal(r->maps[0],r->maps[1],r->map[0].bytes)){pgcd_fail(c,PGCD_CHANGED,1);return 0;}
    r->phase=2;return !r->uncertain;
}
/* Restoration checkpoint, not a renewed200ms namespace/read grant. It performs
 * no original API/AT/MMIO and permits no further queries after finish. Parent
 * calls after FreePool and again BEFORE its deliberate DAIF/Group1 change. */
static inline int pgcd_prestart_check(struct pgcd_context *c)
{
    if(!c||!c->record||pgcd_uncertain(c))return 0;struct pgcd_result *r=c->record;
    if(!c->opened)return 1; /* Completed bootstrap refusal: no new original getter. */
    if(r->prestart_count>=2){pgcd_fail(c,PGCD_LIFETIME,1);return 0;}
    struct pgcd_prestart *p=&r->prestart[r->prestart_count++];p->issued=1;c->io.order(c->io.opaque);
    if(!c->io.arch(c->io.opaque,&p->arch)){pgcd_fail(c,PGCD_UNKNOWN,1);return 0;}
    struct pwfc_arch baseline=r->before.cpu;baseline.ticks=p->arch.cpu.ticks;
    p->TPL=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);p->boot=(uintptr_t)c->io.system->boot;p->tables=(uintptr_t)c->io.system->tables;p->count=c->io.system->table_count;
    if(!pwfc_arch_stable(&baseline,&p->arch.cpu)||p->arch.cpacr!=r->before.cpacr||p->arch.cpu.ticks<r->after.cpu.ticks||p->TPL!=r->TPL_initial||p->boot!=r->core+0x1b800||p->tables!=r->config_pointer||p->count!=r->config_count||
       !pgcd_cached_owner_stable(c)||!pgcd_equal(r->DS_raw[0],(const void*)(uintptr_t)r->DS,168)||
       !pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,p->hashes,&p->hash_failed,&p->hash_count)){pgcd_fail(c,PGCD_UNKNOWN,1);return 0;}
    p->completed=1;c->io.order(c->io.opaque);return 1;
}
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
static struct pgcd_result pgcd_record;
static struct pgcd_context pgcd_resident_context;
static struct pgcd_lifetime pgcd_ticket;
static inline int pgcd_actual_arch(void *opaque,struct pgcd_arch *a)
{
    if(!pwfc_actual_arch(opaque,&a->cpu))return 0;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,cpacr_el1":"=r"(a->cpacr));return 1;
#else
    return 0;
#endif
}
static inline int pgcd_actual_map(void *opaque,struct efi_system *system,struct pgcd_map *m,void *buffer)
{(void)opaque;m->status=system->boot->get_map(&m->bytes,buffer,&m->key,&m->stride,&m->version);return 1;}
static inline int pgcd_actual_query(void *opaque,uint64_t function,uint64_t page,struct pgcd_descriptor *d,uint64_t *status)
{(void)opaque;typedef efi_status(*getter)(uint64_t,struct pgcd_descriptor*);*status=((getter)(uintptr_t)function)(page,d);return 1;}
/* Explicit asm only AFTER actual FPEN3. No q/d clobber list that would make
 * the compiler spill SIMD in the function prologue before the admission. The
 * entire caller TU is -mgeneral-regs-only; these are the only FP instructions. */
static __attribute__((noinline)) int pgcd_actual_fp_save(void *opaque,struct pgcd_fp_guard *g)
{
    (void)opaque;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,cpacr_el1":"=r"(g->cpacr_before));if(((g->cpacr_before>>20)&3)!=3)return 0;
    __asm__ volatile(".arch_extension fp\n\tmrs %0,fpcr\n\tmrs %1,fpsr\n\t.arch_extension nofp":"=r"(g->fpcr),"=r"(g->fpsr));
    __asm__ volatile(".arch_extension fp\n\tstp q8,q9,[%0]\n\tstp q10,q11,[%0,#32]\n\tstp q12,q13,[%0,#64]\n\tstp q14,q15,[%0,#96]\n\t.arch_extension nofp"::"r"(g->q8_q15):"memory");
    g->saved=1;return 1;
#else
    (void)g;return 0;
#endif
}
static __attribute__((noinline)) int pgcd_actual_fp_restore(void *opaque,struct pgcd_fp_guard *g)
{
    (void)opaque;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,cpacr_el1":"=r"(g->cpacr_after));
    /* No CPACR write/fallback and no SIMD on a changed/disabled FP context. */
    if(!g->saved||g->cpacr_after!=g->cpacr_before||((g->cpacr_after>>20)&3)!=3)return 0;
    __asm__ volatile(".arch_extension fp\n\tldp q8,q9,[%0]\n\tldp q10,q11,[%0,#32]\n\tldp q12,q13,[%0,#64]\n\tldp q14,q15,[%0,#96]\n\tmsr fpcr,%1\n\tmsr fpsr,%2\n\t.arch_extension nofp"::"r"(g->q8_q15),"r"(g->fpcr),"r"(g->fpsr):"memory");
    g->restored=1;return 1;
#else
    (void)g;return 0;
#endif
}
static inline int pgcd_bind_resident(const struct efi_loaded *self)
{return pgcd_bind(&pgcd_record,self);}
static inline struct pgcd_context *pgcd_prepare(struct efi_system *system,unsigned stage)
{
    struct pgcd_context *c=&pgcd_resident_context;
    if(c->record){if(c->io.system!=system||c->stage!=stage)pgcd_fail(c,PGCD_LIFETIME,1);return c;}
    c->record=&pgcd_record;c->ticket=&pgcd_ticket;c->stage=stage;
    c->io=(struct pgcd_io){0,system,pgcd_actual_arch,pgcd_actual_map,pwfc_actual_identity,pgcd_actual_query,pgcd_actual_fp_save,pgcd_actual_fp_restore,pwfc_actual_order};return c;
}
#else
static inline int pgcd_bind_resident(const struct efi_loaded *self){(void)self;return 0;}
static inline struct pgcd_context *pgcd_prepare(struct efi_system *system,unsigned stage){(void)system;(void)stage;return 0;}
#endif
#endif
