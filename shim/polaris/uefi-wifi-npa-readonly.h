/* NEW pre-CPU_ON, source-bound NPA namespace observation. It calls only two
 * LocateProtocol and two GetMemoryMap entries, each under the existing original
 * service FP/architecture/TPL guard. NO NPA function, client, query callback,
 * MMIO, SMC, vote, allocation or physical permission change is invoked. */
#ifndef POLARIS_UEFI_WIFI_NPA_READONLY_H
#define POLARIS_UEFI_WIFI_NPA_READONLY_H
#ifndef EFI_XNU_WIFI_NPA_READONLY_AVAILABLE
#define EFI_XNU_WIFI_NPA_READONLY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_NPA_READONLY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "../../tools/polaris-wifi-npa-identity.h"
#define PWNPA_NODES 128u
#define PWNPA_NAME 64u
#define PWNPA_PROTOCOL_BYTES 432u
/* All followed fields correspond to the exact original NpaDxe ABI. Captured
 * pointers are data, not callable targets or votes. A named unresolved node
 * with NULL resource/definition is retained rather than called available. */
struct pwnpa_node {
    uint64_t address,name,resource,definition,plugin;
    uint32_t link_bytes,name_bytes,resource_bytes,definition_bytes,plugin_bytes;
    uint8_t link[32],name_raw[PWNPA_NAME],resource_raw[160],definition_raw[64],plugin_raw[64];
};
enum pwnpa_error {PWNPA_OK,PWNPA_STAGE,PWNPA_BASELINE,PWNPA_GUARD,PWNPA_BS,
    PWNPA_MAP,PWNPA_OWNER,PWNPA_HASH,PWNPA_GRAPH,PWNPA_LIMIT,PWNPA_CHANGED};
struct pwnpa_result {
    uint32_t attempted,error,unknown,outstanding,issued,returned,owner_matches;
    uint32_t nodes[2],walk_complete[2],hash_count[2],hash_failed[2],stable;
    uint64_t protocol[2],protocol_status[2],image,owner_address,head[2];
    struct efi_loaded owner;
    struct paic_arch before,after;
    uint64_t identity_address,identity_par;
    struct pgcd_service_guard guard[4];
    struct paic_map_sample maps[2]; uint8_t map_raw[2][4096];
    uint8_t hashes[2][PWNPI_RANGE_COUNT][32],protocol_raw[2][PWNPA_PROTOCOL_BYTES];
    struct pwnpa_node node[2][PWNPA_NODES];
};
struct pwnpa_work { uint8_t map[4096] __attribute__((aligned(8))); uint64_t bytes,stride; };
_Static_assert(sizeof(struct pwnpa_node)==448,"original NPA node raw record ABI");
_Static_assert(sizeof(struct pwnpa_result)==126432,"NPA raw V1 complete extent");
struct pwnpa_io {
    struct paic_io memory;
    /* Return1 only after the original service returned; a non-return retains
     * its published UNKNOWN operation. No alternate/fallback service path. */
    int (*locate)(void *,struct efi_system *,const efi_guid *,void **,uint64_t *);
    int (*map)(void *,struct efi_system *,uint8_t *,struct paic_map_sample *);
};
static struct { uint32_t used,outstanding; } pwnpa_ticket;
static struct pwnpa_result pwnpa_record;
static struct pwnpa_work pwnpa_work;
static inline void pwnpa_fail(struct pwnpa_result *r,unsigned e,int unknown)
{ if(!r->error)r->error=e; if(unknown)r->unknown=1; paic_actual_order(0); }
static inline int pwnpa_owned(const struct paic_io *io,struct pwnpa_result *r,
    const struct pwnpa_work *w,uint64_t at,uint64_t bytes)
{
    if(!at || !bytes || at>UINT64_MAX-bytes || at+bytes>UINT64_MAX-4095) return 0;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096)
        if(!polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,3) &&
           !polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,4)) return 0;
    return io->identity(io->context,at,bytes,&r->identity_address,&r->identity_par);
}
static inline int pwnpa_copy(const struct paic_io *io,struct pwnpa_result *r,
    const struct pwnpa_work *w,void *dst,uint64_t at,uint32_t bytes,uint32_t *done)
{
    *done=0;
    if(!pwnpa_owned(io,r,w,at,bytes)) return 0;
    for(uint32_t i=0;i<bytes;i++) { ((uint8_t*)dst)[i]=((const volatile uint8_t*)(uintptr_t)at)[i]; *done=i+1; }
    return 1;
}
static inline int pwnpa_fresh(const struct paic_io *io,struct pwnpa_result *r)
{
    if(!io->arch(io->context,&r->after) || !paic_arch_stable(&r->before,&r->after) ||
        r->after.ticks-r->before.ticks>UINT64_C(3840000)) { pwnpa_fail(r,PWNPA_BASELINE,0); return 0; }
    return 1;
}
static inline int pwnpa_walk(const struct paic_io *io,struct pwnpa_result *r,
    struct pwnpa_work *w,unsigned pass)
{
    uint32_t done; uint8_t raw[8];
    if(!pwnpa_copy(io,r,w,raw,r->image+0x108b0,8,&done)) return 0;
    uint64_t cursor=r->head[pass]=pwfi_le(raw,8);
    while(cursor) {
        if(!pwnpa_fresh(io,r)) return 0;
        if(r->nodes[pass]==PWNPA_NODES) { pwnpa_fail(r,PWNPA_LIMIT,0); return 0; }
        for(unsigned j=0;j<r->nodes[pass];j++) if(r->node[pass][j].address==cursor) {
            pwnpa_fail(r,PWNPA_GRAPH,0); return 0;
        }
        struct pwnpa_node *n=&r->node[pass][r->nodes[pass]++]; n->address=cursor;
        if(!pwnpa_copy(io,r,w,n->link,cursor,sizeof(n->link),&n->link_bytes)) return 0;
        n->name=pwfi_le(n->link+16,8); n->resource=pwfi_le(n->link+24,8);
        for(unsigned j=0;j<PWNPA_NAME;j++) {
            uint32_t bytes;
            if(n->name>UINT64_MAX-j || !pwnpa_copy(io,r,w,n->name_raw+j,n->name+j,1,&bytes)) return 0;
            n->name_bytes=j+1;
            if(!n->name_raw[j]) break;
        }
        if(!n->name_bytes || n->name_raw[n->name_bytes-1]) { pwnpa_fail(r,PWNPA_GRAPH,0); return 0; }
        if(n->resource) {
            if(!pwnpa_copy(io,r,w,n->resource_raw,n->resource,sizeof(n->resource_raw),&n->resource_bytes)) return 0;
            n->definition=pwfi_le(n->resource_raw,8); n->plugin=pwfi_le(n->resource_raw+0x28,8);
            if(n->definition && !pwnpa_copy(io,r,w,n->definition_raw,n->definition,sizeof(n->definition_raw),&n->definition_bytes)) return 0;
            if(n->plugin && !pwnpa_copy(io,r,w,n->plugin_raw,n->plugin,sizeof(n->plugin_raw),&n->plugin_bytes)) return 0;
        }
        cursor=pwfi_le(n->link,8);
    }
    /* The actual root is read again, not inferred from a successful walk. */
    if(!pwnpa_copy(io,r,w,raw,r->image+0x108b0,8,&done) || r->head[pass]!=pwfi_le(raw,8)) {
        pwnpa_fail(r,PWNPA_CHANGED,0); return 0;
    }
    r->walk_complete[pass]=1; return 1;
}
static inline int pwnpa_enter(struct pgcd_context *g,struct pwnpa_result *r,unsigned operation)
{
    if(!pgcd_service_enter(g,&r->guard[operation])) { pwnpa_fail(r,PWNPA_GUARD,pgcd_uncertain(g)); return 0; }
    r->outstanding=pwnpa_ticket.outstanding=operation+1; r->issued++; paic_actual_order(0); return 1;
}
static inline int pwnpa_leave(struct pgcd_context *g,struct pwnpa_result *r,unsigned operation,int returned)
{
    if(returned)r->returned++; paic_actual_order(0);
    if(!pgcd_service_leave(g,&r->guard[operation],returned)) { pwnpa_fail(r,PWNPA_GUARD,1); return 0; }
    r->outstanding=pwnpa_ticket.outstanding=0; paic_actual_order(0); return 1;
}
static inline int pwnpa_collect(const struct pwnpa_io *ops,unsigned stage,
    const struct paic_result *enumeration,struct pgcd_context *g,
    struct pwnpa_result *r,struct pwnpa_work *w)
{
    if(!r || !w || r->attempted || pwnpa_ticket.used) return 0;
    r->attempted=pwnpa_ticket.used=1;
    if(stage!=2) { pwnpa_fail(r,PWNPA_STAGE,0); return 0; }
    const struct paic_io *io=ops?&ops->memory:0;
    if(!ops || !ops->locate || !ops->map || !io || !io->arch || !io->identity || !io->order || !io->system || !io->system->boot ||
        !enumeration || enumeration->error || enumeration->owner_matches!=1 || !enumeration->cache_consistent ||
        enumeration->handle_count==0 || enumeration->handle_count>PAIC_HANDLES ||
        !io->arch(io->context,&r->before) || !paic_arch_admitted(&r->before) || !g || !pgcd_open(g)) {
        pwnpa_fail(r,PWNPA_BASELINE,g&&pgcd_uncertain(g)); return 0;
    }
    static const efi_guid protocol={0x79d6c870,0x725e,0x489e,{0xa0,0xa1,0x27,0xe7,0xa5,0xd0,0xcb,0x35}};
    struct efi_boot *bs=io->system->boot;
    if(!bs->locate_protocol || !bs->get_map) { pwnpa_fail(r,PWNPA_BS,0); return 0; }
    for(unsigned pass=0;pass<2;pass++) {
        void *table=0; unsigned op=pass*2;
        r->protocol_status[pass]=UINT64_MAX;
        if(!pwnpa_enter(g,r,op)) return 0;
        int returned=ops->locate(io->context,io->system,&protocol,&table,&r->protocol_status[pass]); r->protocol[pass]=(uintptr_t)table;
        if(!pwnpa_leave(g,r,op,returned)) return 0;
        if(r->protocol_status[pass] || !table) { pwnpa_fail(r,PWNPA_BS,0); return 0; }
        r->maps[pass]=(struct paic_map_sample){UINT64_MAX,0,sizeof(w->map),0,0};
        if(!pwnpa_enter(g,r,op+1)) return 0;
        returned=ops->map(io->context,io->system,w->map,&r->maps[pass]);
        pgcd_copy(r->map_raw[pass],w->map,sizeof(w->map));
        if(!pwnpa_leave(g,r,op+1,returned)) return 0;
        uint64_t bytes=r->maps[pass].bytes,key=r->maps[pass].key,stride=r->maps[pass].stride;
        uint64_t status=r->maps[pass].status;uint32_t version=r->maps[pass].version;
        (void)key;
        struct polaris_efi_memory checked;
        if(status || version!=1 || !polaris_efi_memory_check(w->map,bytes,sizeof(w->map),stride,&checked)) {
            pwnpa_fail(r,PWNPA_MAP,0); return 0;
        }
        w->bytes=bytes; w->stride=stride;
        if(!pwnpa_owned(io,r,w,(uintptr_t)r,sizeof(*r)) || !pwnpa_owned(io,r,w,(uintptr_t)w,sizeof(*w)) ||
            !pwnpa_owned(io,r,w,(uintptr_t)enumeration,sizeof(*enumeration))) { pwnpa_fail(r,PWNPA_OWNER,0); return 0; }
        if(!pass) {
            /* Reuse the completed same-boot enumeration, NEVER its freed handle
             * array. Every loaded-image object is validated again in this map. */
            for(unsigned n=0;n<enumeration->handle_count;n++) {
                struct efi_loaded candidate; uint32_t done;
                if(enumeration->handle_status[n] || !pwnpa_copy(io,r,w,&candidate,enumeration->loaded_address[n],sizeof(candidate),&done)) {
                    pwnpa_fail(r,PWNPA_OWNER,0); return 0;
                }
                uint64_t base=(uintptr_t)candidate.base;
                if(base>UINT64_MAX-0x100b0 || base+0x100b0!=r->protocol[0]) continue;
                r->owner_matches++; r->image=base; r->owner=candidate; r->owner_address=enumeration->loaded_address[n];
                if(candidate.revision!=0x1000 || candidate.system!=io->system || candidate.bytes!=PWNPI_IMAGE_BYTES ||
                    candidate.code_type!=3 || candidate.data_type!=4 || (base&4095)) { pwnpa_fail(r,PWNPA_OWNER,0); return 0; }
            }
            if(r->owner_matches!=1 || r->image>UINT64_MAX-PWNPI_IMAGE_BYTES ||
                (r->image<g->record->self_base+g->record->self_bytes && g->record->self_base<r->image+PWNPI_IMAGE_BYTES) ||
                (r->image<g->record->core+PGCI_IMAGE_BYTES && g->record->core<r->image+PWNPI_IMAGE_BYTES)) {
                pwnpa_fail(r,PWNPA_OWNER,0); return 0;
            }
        } else {
            struct efi_loaded owner; uint32_t done;
            if(r->protocol[1]!=r->protocol[0] || !pwnpa_copy(io,r,w,&owner,r->owner_address,sizeof(owner),&done) ||
                !pgcd_equal(&owner,&r->owner,sizeof(owner))) { pwnpa_fail(r,PWNPA_CHANGED,0); return 0; }
        }
        if(!pwnpa_owned(io,r,w,r->image,PWNPI_IMAGE_BYTES)) { pwnpa_fail(r,PWNPA_OWNER,0); return 0; }
        if(!pwnpi_verify((const uint8_t*)(uintptr_t)r->image,r->image,r->hashes[pass],&r->hash_count[pass],&r->hash_failed[pass])) {
            pwnpa_fail(r,PWNPA_HASH,0); return 0;
        }
        uint32_t done;
        if(!pwnpa_copy(io,r,w,r->protocol_raw[pass],r->protocol[pass],PWNPA_PROTOCOL_BYTES,&done) ||
            !pwnpa_walk(io,r,w,pass)) { if(!r->error)pwnpa_fail(r,PWNPA_GRAPH,0); return 0; }
        if(!pwnpa_fresh(io,r)) return 0;
    }
    if(r->maps[0].key!=r->maps[1].key || r->maps[0].bytes!=r->maps[1].bytes || r->maps[0].stride!=r->maps[1].stride ||
        !pgcd_equal(r->map_raw[0],r->map_raw[1],r->maps[0].bytes) || r->nodes[0]!=r->nodes[1] || r->head[0]!=r->head[1] ||
        !pgcd_equal(r->protocol_raw[0],r->protocol_raw[1],PWNPA_PROTOCOL_BYTES) ||
        !pgcd_equal(r->node[0],r->node[1],r->nodes[0]*sizeof(struct pwnpa_node))) {
        pwnpa_fail(r,PWNPA_CHANGED,0); return 0;
    }
    r->stable=1; return 1; /* Namespace observation ONLY, all mutation grants false. */
}
static inline int pwnpa_actual_locate(void *ctx,struct efi_system *system,const efi_guid *guid,void **table,uint64_t *status)
{ (void)ctx; *status=system->boot->locate_protocol(guid,0,table); return 1; }
static inline int pwnpa_actual_map(void *ctx,struct efi_system *system,uint8_t *buffer,struct paic_map_sample *m)
{ (void)ctx; m->status=system->boot->get_map(&m->bytes,buffer,&m->key,&m->stride,&m->version); return 1; }
static inline void pwnpa_collect_preboot(const struct paic_io *io,unsigned stage,
    const struct paic_result *enumeration,struct pgcd_context *g)
{ const struct pwnpa_io ops={*io,pwnpa_actual_locate,pwnpa_actual_map};
  (void)pwnpa_collect(&ops,stage,enumeration,g,&pwnpa_record,&pwnpa_work); }
static inline int pwnpa_unknown(void)
{ return pwnpa_record.unknown || pwnpa_record.outstanding || pwnpa_ticket.outstanding; }
static inline void pwnpa_report_preboot(void (*append)(const char *))
{
    static const char hex[]="0123456789abcdef"; char chunk[127];
    append("WIFI_NPA_RAW_V1_BEGIN\r\n");
    const uint8_t *p=(const uint8_t*)&pwnpa_record;
    for(size_t at=0;at<sizeof(pwnpa_record);) {
        unsigned n=(unsigned)(sizeof(pwnpa_record)-at); if(n>63)n=63;
        for(unsigned j=0;j<n;j++) { chunk[2*j]=hex[p[at+j]>>4]; chunk[2*j+1]=hex[p[at+j]&15]; }
        chunk[2*n]=0; append(chunk); at+=n;
    }
    append("\r\nWIFI_NPA_RAW_V1_END\r\nWIFI_NPA_SOURCE_SHA256=" PWNPI_SOURCE_SHA256 "\r\n");
    append("WIFI_NPA_SCOPE=SOURCE_BOUND_RAM_NAMESPACE NO_NPA_API NO_QUERY_PLUGIN NO_CLIENT NO_VOTE NO_MSS_START NO_WRITE_PERMISSION\r\n");
}
#else
static inline int pwnpa_unknown(void) { return 0; }
#endif
#endif
