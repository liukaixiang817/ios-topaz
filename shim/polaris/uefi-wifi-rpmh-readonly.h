/* NEW pre-CPU_ON, source-bound RPMh initialization/DRV/TCS RAM observation. It calls only two
 * LocateProtocol and two GetMemoryMap entries, each under the existing original
 * service FP/architecture/TPL guard. NO RPMh function, client, query callback,
 * MMIO, SMC, vote, allocation or physical permission change is invoked. */
#ifndef POLARIS_UEFI_WIFI_RPMH_READONLY_H
#define POLARIS_UEFI_WIFI_RPMH_READONLY_H
#ifndef EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE
#define EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "../../tools/polaris-wifi-rpmh-identity.h"
/* Exact own provider ABI only. TCS records below are firmware RAM state,
 * never hardware TCS/MMIO ownership, rail votes or permissions. */
#define PWRPH_DRVS 4u
#define PWRPH_TCS 16u
#define PWRPH_MODES 4u
#define PWRPH_PROTOCOL_BYTES 200u
struct pwrph_drv {
    uint32_t row_bytes,mode_ptr_bytes,mode_bytes[PWRPH_MODES];
    uint32_t queue_ptr_bytes,queue_state_bytes,queue_bytes[5],tcs_ptr_bytes,tcs_bytes,mode_index_bytes;
    uint8_t row[48],mode_ptr[PWRPH_MODES*8],mode[PWRPH_MODES][24];
    uint8_t queue_ptr[8],queue_state[48],queue[5][40];
    uint8_t tcs_ptr[8],tcs[PWRPH_TCS*24],mode_index[4];
};
struct pwrph_snapshot {
    uint32_t root_pointer_bytes,root_bytes,global_bytes,HAL_config_bytes,drv_count,initialized;
    uint64_t root;
    uint8_t root_pointer[8],config[40],global[0x110],HAL_config[80];
    struct pwrph_drv drv[PWRPH_DRVS];
};
enum pwrph_error {PWRPH_OK,PWRPH_STAGE,PWRPH_BASELINE,PWRPH_GUARD,PWRPH_BS,
    PWRPH_MAP,PWRPH_OWNER,PWRPH_HASH,PWRPH_CONFIG,PWRPH_LIMIT,PWRPH_CHANGED,PWRPH_NOT_READY};
struct pwrph_result {
    uint32_t attempted,error,unknown,outstanding,issued,returned,owner_matches;
    uint32_t snapshot_complete[2],hash_count[2],hash_failed[2],stable;
    uint64_t protocol[2],protocol_status[2],image,owner_address;
    struct efi_loaded owner;
    struct paic_arch before,after;
    uint64_t identity_address,identity_par;
    struct pgcd_service_guard guard[4];
    struct paic_map_sample maps[2]; uint8_t map_raw[2][4096];
    uint8_t hashes[2][PWRPI_RANGE_COUNT][32],protocol_raw[2][PWRPH_PROTOCOL_BYTES];
    struct pwrph_snapshot snapshot[2];
};
_Static_assert(sizeof(struct pwrph_result)==19264,"RPMh full raw V1 extent");
struct pwrph_work { uint8_t map[4096] __attribute__((aligned(8))); uint64_t bytes,stride; };
struct pwrph_io {
    struct paic_io memory;
    /* Return1 only after the original service returned; a non-return retains
     * its published UNKNOWN operation. No alternate/fallback service path. */
    int (*locate)(void *,struct efi_system *,const efi_guid *,void **,uint64_t *);
    int (*map)(void *,struct efi_system *,uint8_t *,struct paic_map_sample *);
};
static struct { uint32_t used,outstanding; } pwrph_ticket;
static struct pwrph_result pwrph_record;
static struct pwrph_work pwrph_work;
static inline void pwrph_fail(struct pwrph_result *r,unsigned e,int unknown)
{ if(!r->error)r->error=e; if(unknown)r->unknown=1; paic_actual_order(0); }
static inline int pwrph_owned(const struct paic_io *io,struct pwrph_result *r,
    const struct pwrph_work *w,uint64_t at,uint64_t bytes)
{
    if(!at || !bytes || at>UINT64_MAX-bytes || at+bytes>UINT64_MAX-4095) return 0;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096)
        if(!polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,3) &&
           !polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,4)) return 0;
    return io->identity(io->context,at,bytes,&r->identity_address,&r->identity_par);
}
static inline int pwrph_copy(const struct paic_io *io,struct pwrph_result *r,
    const struct pwrph_work *w,void *dst,uint64_t at,uint32_t bytes,uint32_t *done)
{
    *done=0;
    if(!pwrph_owned(io,r,w,at,bytes)) return 0;
    for(uint32_t i=0;i<bytes;i++) { ((uint8_t*)dst)[i]=((const volatile uint8_t*)(uintptr_t)at)[i]; *done=i+1; }
    return 1;
}
static inline int pwrph_fresh(const struct paic_io *io,struct pwrph_result *r)
{
    if(!io->arch(io->context,&r->after) || !paic_arch_stable(&r->before,&r->after) ||
        r->after.ticks-r->before.ticks>UINT64_C(3840000)) { pwrph_fail(r,PWRPH_BASELINE,0); return 0; }
    return 1;
}
/* Original3f18/5aa4: config pointer, count, rows+0x20, stride0x30.
 * Original575c/58a4/5a00: globald3e0 perDRV pointers, 24B perTCS.
 * Original3f90/4a7c: globald2f8 perDRV RAM queues, five40B headers.
 * Original58fc: row+0x28 is a mode-pointer array. No followed pointer is
 * dereferenced until the complete extent has BootServicesRAM+actualAT identity.
 * All partial byte counts/raw fields survive failure. */
static inline int pwrph_snapshot(const struct paic_io *io,struct pwrph_result *r,
    struct pwrph_work *w,unsigned pass)
{
    struct pwrph_snapshot *s=&r->snapshot[pass];
    if(!pwrph_copy(io,r,w,s->root_pointer,r->image+0xb100,8,&s->root_pointer_bytes)) return 0;
    s->root=pwfi_le(s->root_pointer,8);
    if(!pwrph_copy(io,r,w,s->config,s->root,sizeof(s->config),&s->root_bytes) ||
       !pwrph_copy(io,r,w,s->global,r->image+0xd2e8,sizeof(s->global),&s->global_bytes) ||
       !pwrph_copy(io,r,w,s->HAL_config,r->image+0xd208,sizeof(s->HAL_config),&s->HAL_config_bytes)) return 0;
    s->initialized=(uint32_t)pwfi_le(s->global,4);
    s->drv_count=(uint32_t)pwfi_le(s->config,4);
    if(!s->drv_count || s->drv_count>PWRPH_DRVS) {pwrph_fail(r,PWRPH_LIMIT,0);return 0;}
    uint64_t rows=pwfi_le(s->config+0x20,8);
    uint64_t queues=pwfi_le(s->global+0x10,8),tcs=pwfi_le(s->global+0xf8,8),indices=pwfi_le(s->global+0x100,8);
    if(s->initialized>1) {pwrph_fail(r,PWRPH_CONFIG,0);return 0;}
    /* flag1 is set before init completes: missing dynamic state is NOT READY,
     * never a reason to call the mutating Init entry. */
    for(unsigned j=0;j<s->drv_count;j++) {
        struct pwrph_drv *d=&s->drv[j];
        if(!pwrph_fresh(io,r) || rows>UINT64_MAX-48*j ||
           !pwrph_copy(io,r,w,d->row,rows+48*j,48,&d->row_bytes)) return 0;
        for(unsigned k=0;k<j;k++) if(pwfi_le(d->row,4)==pwfi_le(s->drv[k].row,4)) {pwrph_fail(r,PWRPH_CONFIG,0);return 0;}
        unsigned ntcs=(unsigned)pwfi_le(d->row+0x18,4),nmodes=(unsigned)pwfi_le(d->row+0x20,4);
        if(!ntcs || ntcs>PWRPH_TCS || !nmodes || nmodes>PWRPH_MODES || pwfi_le(d->row+0x1c,4)!=16) {
            pwrph_fail(r,PWRPH_LIMIT,0);return 0;
        }
        if(!pwrph_copy(io,r,w,d->mode_ptr,pwfi_le(d->row+0x28,8),nmodes*8,&d->mode_ptr_bytes)) return 0;
        for(unsigned k=0;k<nmodes;k++)
            if(!pwrph_copy(io,r,w,d->mode[k],pwfi_le(d->mode_ptr+8*k,8),24,&d->mode_bytes[k])) return 0;
        if(queues) {
            if(queues>UINT64_MAX-8*j || !pwrph_copy(io,r,w,d->queue_ptr,queues+8*j,8,&d->queue_ptr_bytes)) return 0;
            uint64_t q=pwfi_le(d->queue_ptr,8);
            if(q) {
                if(!pwrph_copy(io,r,w,d->queue_state,q,48,&d->queue_state_bytes)) return 0;
                for(unsigned k=0;k<5;k++) {
                    uint64_t h=pwfi_le(d->queue_state+8+8*k,8);
                    if(h && !pwrph_copy(io,r,w,d->queue[k],h,40,&d->queue_bytes[k])) return 0;
                }
            } else if(s->initialized) {pwrph_fail(r,PWRPH_NOT_READY,0);return 0;}
        } else if(s->initialized) {pwrph_fail(r,PWRPH_NOT_READY,0);return 0;}
        if(tcs) {
            if(tcs>UINT64_MAX-8*j || !pwrph_copy(io,r,w,d->tcs_ptr,tcs+8*j,8,&d->tcs_ptr_bytes)) return 0;
            uint64_t state=pwfi_le(d->tcs_ptr,8);
            if(state) {
                if(!pwrph_copy(io,r,w,d->tcs,state,ntcs*24,&d->tcs_bytes)) return 0;
            } else if(s->initialized) {pwrph_fail(r,PWRPH_NOT_READY,0);return 0;}
        } else if(s->initialized) {pwrph_fail(r,PWRPH_NOT_READY,0);return 0;}
        if(indices) {
            if(indices>UINT64_MAX-4*j || !pwrph_copy(io,r,w,d->mode_index,indices+4*j,4,&d->mode_index_bytes)) return 0;
        } else if(s->initialized) {pwrph_fail(r,PWRPH_NOT_READY,0);return 0;}
    }
    r->snapshot_complete[pass]=1;return 1;
}
static inline int pwrph_enter(struct pgcd_context *g,struct pwrph_result *r,unsigned operation)
{
    if(!pgcd_service_enter(g,&r->guard[operation])) { pwrph_fail(r,PWRPH_GUARD,pgcd_uncertain(g)); return 0; }
    r->outstanding=pwrph_ticket.outstanding=operation+1; r->issued++; paic_actual_order(0); return 1;
}
static inline int pwrph_leave(struct pgcd_context *g,struct pwrph_result *r,unsigned operation,int returned)
{
    if(returned)r->returned++; paic_actual_order(0);
    if(!pgcd_service_leave(g,&r->guard[operation],returned)) { pwrph_fail(r,PWRPH_GUARD,1); return 0; }
    r->outstanding=pwrph_ticket.outstanding=0; paic_actual_order(0); return 1;
}
static inline int pwrph_collect(const struct pwrph_io *ops,unsigned stage,
    const struct paic_result *enumeration,struct pgcd_context *g,
    struct pwrph_result *r,struct pwrph_work *w)
{
    if(!r || !w || r->attempted || pwrph_ticket.used) return 0;
    r->attempted=pwrph_ticket.used=1;
    if(stage!=2) { pwrph_fail(r,PWRPH_STAGE,0); return 0; }
    const struct paic_io *io=ops?&ops->memory:0;
    if(!ops || !ops->locate || !ops->map || !io || !io->arch || !io->identity || !io->order || !io->system || !io->system->boot ||
        !enumeration || enumeration->error || enumeration->owner_matches!=1 || !enumeration->cache_consistent ||
        enumeration->handle_count==0 || enumeration->handle_count>PAIC_HANDLES ||
        !io->arch(io->context,&r->before) || !paic_arch_admitted(&r->before) || !g || !pgcd_open(g)) {
        pwrph_fail(r,PWRPH_BASELINE,g&&pgcd_uncertain(g)); return 0;
    }
    static const efi_guid protocol={0xe1d0b573,0xf29f,0x495d,{0x93,0x52,0xca,0x0d,0xd4,0x2a,0x0a,0x74}};
    struct efi_boot *bs=io->system->boot;
    if(!bs->locate_protocol || !bs->get_map) { pwrph_fail(r,PWRPH_BS,0); return 0; }
    for(unsigned pass=0;pass<2;pass++) {
        void *table=0; unsigned op=pass*2;
        r->protocol_status[pass]=UINT64_MAX;
        if(!pwrph_enter(g,r,op)) return 0;
        int returned=ops->locate(io->context,io->system,&protocol,&table,&r->protocol_status[pass]); r->protocol[pass]=(uintptr_t)table;
        if(!pwrph_leave(g,r,op,returned)) return 0;
        if(r->protocol_status[pass] || !table) { pwrph_fail(r,PWRPH_BS,0); return 0; }
        r->maps[pass]=(struct paic_map_sample){UINT64_MAX,0,sizeof(w->map),0,0};
        if(!pwrph_enter(g,r,op+1)) return 0;
        returned=ops->map(io->context,io->system,w->map,&r->maps[pass]);
        pgcd_copy(r->map_raw[pass],w->map,sizeof(w->map));
        if(!pwrph_leave(g,r,op+1,returned)) return 0;
        uint64_t bytes=r->maps[pass].bytes,key=r->maps[pass].key,stride=r->maps[pass].stride;
        uint64_t status=r->maps[pass].status;uint32_t version=r->maps[pass].version;
        (void)key;
        struct polaris_efi_memory checked;
        if(status || version!=1 || !polaris_efi_memory_check(w->map,bytes,sizeof(w->map),stride,&checked)) {
            pwrph_fail(r,PWRPH_MAP,0); return 0;
        }
        w->bytes=bytes; w->stride=stride;
        if(!pwrph_owned(io,r,w,(uintptr_t)r,sizeof(*r)) || !pwrph_owned(io,r,w,(uintptr_t)w,sizeof(*w)) ||
            !pwrph_owned(io,r,w,(uintptr_t)enumeration,sizeof(*enumeration))) { pwrph_fail(r,PWRPH_OWNER,0); return 0; }
        if(!pass) {
            /* Reuse the completed same-boot enumeration, NEVER its freed handle
             * array. Every loaded-image object is validated again in this map. */
            for(unsigned n=0;n<enumeration->handle_count;n++) {
                struct efi_loaded candidate; uint32_t done;
                if(enumeration->handle_status[n] || !pwrph_copy(io,r,w,&candidate,enumeration->loaded_address[n],sizeof(candidate),&done)) {
                    pwrph_fail(r,PWRPH_OWNER,0); return 0;
                }
                uint64_t base=(uintptr_t)candidate.base;
                if(base>UINT64_MAX-0xd0d8 || base+0xd0d8!=r->protocol[0]) continue;
                r->owner_matches++; r->image=base; r->owner=candidate; r->owner_address=enumeration->loaded_address[n];
                if(candidate.revision!=0x1000 || candidate.system!=io->system || candidate.bytes!=PWRPI_IMAGE_BYTES ||
                    candidate.code_type!=3 || candidate.data_type!=4 || (base&4095)) { pwrph_fail(r,PWRPH_OWNER,0); return 0; }
            }
            if(r->owner_matches!=1 || r->image>UINT64_MAX-PWRPI_IMAGE_BYTES ||
                (r->image<g->record->self_base+g->record->self_bytes && g->record->self_base<r->image+PWRPI_IMAGE_BYTES) ||
                (r->image<g->record->core+PGCI_IMAGE_BYTES && g->record->core<r->image+PWRPI_IMAGE_BYTES)) {
                pwrph_fail(r,PWRPH_OWNER,0); return 0;
            }
        } else {
            struct efi_loaded owner; uint32_t done;
            if(r->protocol[1]!=r->protocol[0] || !pwrph_copy(io,r,w,&owner,r->owner_address,sizeof(owner),&done) ||
                !pgcd_equal(&owner,&r->owner,sizeof(owner))) { pwrph_fail(r,PWRPH_CHANGED,0); return 0; }
        }
        if(!pwrph_owned(io,r,w,r->image,PWRPI_IMAGE_BYTES)) { pwrph_fail(r,PWRPH_OWNER,0); return 0; }
        if(!pwrpi_verify((const uint8_t*)(uintptr_t)r->image,r->image,r->hashes[pass],&r->hash_count[pass],&r->hash_failed[pass])) {
            pwrph_fail(r,PWRPH_HASH,0); return 0;
        }
        uint32_t done;
        if(!pwrph_copy(io,r,w,r->protocol_raw[pass],r->protocol[pass],PWRPH_PROTOCOL_BYTES,&done) ||
            !pwrph_snapshot(io,r,w,pass)) { if(!r->error)pwrph_fail(r,PWRPH_CONFIG,0); return 0; }
        if(!pwrph_fresh(io,r)) return 0;
    }
    if(r->maps[0].key!=r->maps[1].key || r->maps[0].bytes!=r->maps[1].bytes || r->maps[0].stride!=r->maps[1].stride ||
        !pgcd_equal(r->map_raw[0],r->map_raw[1],r->maps[0].bytes) || 
        !pgcd_equal(r->protocol_raw[0],r->protocol_raw[1],PWRPH_PROTOCOL_BYTES) ||
        !pgcd_equal(&r->snapshot[0],&r->snapshot[1],sizeof(struct pwrph_snapshot))) {
        pwrph_fail(r,PWRPH_CHANGED,0); return 0;
    }
    r->stable=1; return 1; /* FirmwareRAM observation ONLY, all mutation grants false. */
}
static inline int pwrph_actual_locate(void *ctx,struct efi_system *system,const efi_guid *guid,void **table,uint64_t *status)
{ (void)ctx; *status=system->boot->locate_protocol(guid,0,table); return 1; }
static inline int pwrph_actual_map(void *ctx,struct efi_system *system,uint8_t *buffer,struct paic_map_sample *m)
{ (void)ctx; m->status=system->boot->get_map(&m->bytes,buffer,&m->key,&m->stride,&m->version); return 1; }
static inline void pwrph_collect_preboot(const struct paic_io *io,unsigned stage,
    const struct paic_result *enumeration,struct pgcd_context *g)
{ const struct pwrph_io ops={*io,pwrph_actual_locate,pwrph_actual_map};
  (void)pwrph_collect(&ops,stage,enumeration,g,&pwrph_record,&pwrph_work); }
static inline int pwrph_unknown(void)
{ return pwrph_record.unknown || pwrph_record.outstanding || pwrph_ticket.outstanding; }
static inline void pwrph_report_preboot(void (*append)(const char *))
{
    static const char hex[]="0123456789abcdef"; char chunk[127];
    append("WIFI_RPMH_RAW_V1_BEGIN\r\n");
    const uint8_t *p=(const uint8_t*)&pwrph_record;
    for(size_t at=0;at<sizeof(pwrph_record);) {
        unsigned n=(unsigned)(sizeof(pwrph_record)-at); if(n>63)n=63;
        for(unsigned j=0;j<n;j++) { chunk[2*j]=hex[p[at+j]>>4]; chunk[2*j+1]=hex[p[at+j]&15]; }
        chunk[2*n]=0; append(chunk); at+=n;
    }
    append("\r\nWIFI_RPMH_RAW_V1_END\r\nWIFI_RPMH_SOURCE_SHA256=" PWRPI_SOURCE_SHA256 "\r\n");
    append("WIFI_RPMH_SCOPE=SOURCE_BOUND_INIT_DRV_TCS_RAM NO_RPMH_API NO_MMIO NO_SMC NO_CLIENT NO_VOTE NO_MSS_START NO_WRITE_PERMISSION\r\n");
}
#else
static inline int pwrph_unknown(void) { return 0; }
#endif
#endif
