/* Read-only Core heap classification in an actually opened, independent RO
 * context. No private RPMh client is fabricated. This is a RAM-read class,
 * never a writer, DRV2, EE/EL3, VMID/MPU, rail or DMA ownership grant. */
#ifndef POLARIS_UEFI_WIFI_GCD_RO_OWNER_H
#define POLARIS_UEFI_WIFI_GCD_RO_OWNER_H
struct pgns_ro_owner {
    uint32_t attempted,error,outstanding,complete,closed,image_count;
    uint64_t context,core_record,ticket;
    uint64_t address[PAIC_HANDLES];
    uint32_t bytes[2][PAIC_HANDLES];
    struct efi_loaded image[2][PAIC_HANDLES];
};
static inline int pgns_ro_ready(const struct pgns_ro_owner *r,const struct pgcd_context *g)
{
    return r&&g&&g->record&&r->attempted==1&&r->complete==1&&!r->closed&&!r->error&&!r->outstanding&&
        r->image_count&&r->image_count<=PAIC_HANDLES&&r->context==(uintptr_t)g&&
        r->core_record==(uintptr_t)g->record&&r->ticket==(uintptr_t)g->ticket&&
        g->opened&&!g->finished&&!pgcd_uncertain(g)&&!g->record->error&&g->record->phase==1&&
        g->ticket&&g->ticket->spent==1&&g->ticket->result==(uintptr_t)g->record&&
        pgcd_in_self(g->record,(uintptr_t)r,sizeof(*r));
}
static inline int pgns_ro_owner_fail(struct pgns_ro_owner *r,unsigned e)
{if(!r->error)r->error=e;paic_actual_order(0);return 0;}
static inline int pgns_ro_owner_copy(struct pgcd_context *g,struct pgns_ro_owner *r,unsigned slot,unsigned k)
{
    struct pgcd_arch a;
    if(slot>1||k>=PAIC_HANDLES||!pgcd_live(g,&a,0)||!pgcd_cached_owner_stable(g)||
       !pgcd_owned(g,0,r->address[k],sizeof(struct efi_loaded)))return pgns_ro_owner_fail(r,2);
    r->outstanding=slot*PAIC_HANDLES+k+1;paic_actual_order(0);
    for(unsigned j=0;j<sizeof(struct efi_loaded);j++){
        ((uint8_t*)&r->image[slot][k])[j]=((const volatile uint8_t*)(uintptr_t)r->address[k])[j];r->bytes[slot][k]=j+1;
    }
    paic_actual_order(0);r->outstanding=0;
    const struct efi_loaded *p=&r->image[slot][k];uint64_t b=(uintptr_t)p->base;
    if(p->revision!=0x1000||p->system!=g->io.system||!b||!p->bytes||b>UINT64_MAX-p->bytes||
       !pgcd_live(g,&a,0))return pgns_ro_owner_fail(r,3);
    if(slot&&!pgcd_equal(&r->image[0][k],p,sizeof(*p)))return pgns_ro_owner_fail(r,4);
    return 1;
}
static inline int pgns_ro_owner_open(const struct paic_result *enumeration,struct pgcd_context *g,struct pgns_ro_owner *r)
{
    if(!r)return 0;if(r->attempted)return pgns_ro_owner_fail(r,1);r->attempted=1;
    if(!enumeration||enumeration->error||!enumeration->cache_consistent||enumeration->owner_matches!=1||
       !enumeration->handle_count||enumeration->handle_count>PAIC_HANDLES||!pwrph_context_ready(g)||
       !pgcd_in_self(g->record,(uintptr_t)r,sizeof(*r))||!pgcd_owned(g,0,(uintptr_t)r,sizeof(*r)))return pgns_ro_owner_fail(r,1);
    r->context=(uintptr_t)g;r->core_record=(uintptr_t)g->record;r->ticket=(uintptr_t)g->ticket;
    /* Only the retained LoadedImage addresses are used. Never dereference the
     * already freed handle-array from the completed enumeration. */
    for(unsigned k=0;k<enumeration->handle_count;k++){
        if(enumeration->handle_status[k])return pgns_ro_owner_fail(r,1);
        r->address[k]=enumeration->loaded_address[k];
        if(!pgns_ro_owner_copy(g,r,0,k))return 0;r->image_count=k+1;
    }
    r->complete=1;return 1;
}
static inline int pgns_ro_owner_close(struct pgcd_context *g,struct pgns_ro_owner *r)
{
    if(!pgns_ro_ready(r,g))return pgns_ro_owner_fail(r,5);
    for(unsigned k=0;k<r->image_count;k++)if(!pgns_ro_owner_copy(g,r,1,k))return 0;
    r->closed=1;paic_actual_order(0);return 1;
}
static inline int pgns_ro_owned(struct pgcd_context *g,struct pgns_ro_owner *r,uint64_t at,uint32_t n,int heap)
{
    if(!pgns_ro_ready(r,g)||!at||!n||at>UINT64_MAX-n||at+n>UINT64_MAX-4095||
       !pgcd_owned(g,0,at,n))return 0;
    if(!heap)return 1;
    if(at&7)return 0;
    for(uint64_t page=at&~UINT64_C(4095);page<at+n;page+=4096)
        if(!polaris_efi_range_owned(g->record->maps[0],g->record->map[0].bytes,g->record->map[0].stride,page,4096,4))return 0;
    if(pwrcl_overlap(at,n,g->record->self_base,g->record->self_bytes)||
       pwrcl_overlap(at,n,g->record->core,PGCI_IMAGE_BYTES))return 0;
    for(unsigned k=0;k<r->image_count;k++){
        if(r->bytes[0][k]!=sizeof(struct efi_loaded)||
           pwrcl_overlap(at,n,(uintptr_t)r->image[0][k].base,r->image[0][k].bytes))return 0;
    }
    return 1;
}
#endif
