/* Default-OFF normal-IRQ observation of the exact future access objects.
 * No private/CPU/access lifetime is created here. The caller must close the
 * SAME current namespace/source/pools/client and invoke known Delete before
 * exporting this record. Passing this observation grants no masked or radio
 * access: the existing masked checks must still run afresh in a later phase. */
#ifndef POLARIS_UEFI_WIFI_PRE_MASK_ARGUMENTS_H
#define POLARIS_UEFI_WIFI_PRE_MASK_ARGUMENTS_H
#define PWRPA_OBJECTS 10u
#define PWRPA_PAGES 512u
struct pwrpa_object {
    uint64_t address,bytes;
    uint32_t in_self,pages_first,pages,complete;
};
struct pwrpa_page {uint32_t object,valid;struct pgns_translation AT;};
struct pwrpa_result {
    _Alignas(16) uint32_t attempted;
    uint32_t error,unknown,outstanding,complete,admitted,declined,objects,pages;
    uint32_t failed_object,failed_page,native_first,native_last,native_reads;
    uint64_t provider,core,ticket,memory,work,native_address;
    struct pgcd_arch before,last;
    struct pwrpa_object object[PWRPA_OBJECTS];
    struct pwrpa_page page[PWRPA_PAGES];
};
enum pwrpa_error {PWRPA_OK,PWRPA_ARGUMENT,PWRPA_CONTEXT,PWRPA_RANGE,PWRPA_ALIAS,
    PWRPA_MAP,PWRPA_TRANSLATION,PWRPA_PARTIAL,PWRPA_LIMIT,PWRPA_PREFIX};
struct pwrpa_input {const void *object;uint64_t bytes;};
static inline int pwrpa_fail(struct pwrpa_result *r,unsigned e,unsigned unknown)
{if(!r->error)r->error=e;if(unknown)r->unknown=1;paic_actual_order(0);return 0;}
static inline int pwrpa_unsafe(const struct pwrpa_result *r)
{return r->unknown||r->outstanding||(r->attempted&&!r->complete);}
static inline int pwrpa_live(const struct paic_io *m,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,struct pwrpa_result *r)
{
    if(r->unknown||r->outstanding||!m||!p||!w||!g||!g->record||!g->ticket||!m->system||m->system!=g->io.system||g->record!=&p->core||g->ticket!=&p->core_ticket||
       r->provider!=(uintptr_t)p||r->core!=(uintptr_t)g||r->ticket!=(uintptr_t)g->ticket||
       r->memory!=(uintptr_t)m||r->work!=(uintptr_t)w||!p->client_held||p->client_returned||p->retired||
       p->error||p->unknown||p->outstanding||!pwrph_context_ready(g)||
       !pgcd_live(g,&r->last,0)||!pwrcl_fresh(m,p)||!pgcd_cached_owner_stable(g)||
       !pgcd_owned(g,0,p->core.core+0x1b098,8)||pwfi_le((const void*)(uintptr_t)(p->core.core+0x1b098),8)!=4||
       (uintptr_t)m->system->boot!=p->core.core+0x1b800||
       (uintptr_t)m->system->tables!=p->core.config_pointer||m->system->table_count!=p->core.config_count||
       !pgcd_equal(p->core.DS_raw[0],(const void*)(uintptr_t)p->core.DS,168)||
       !pgcd_in_self(&p->core,r->native_address,4)||!pwrcl_owned(m,p,w,r->native_address,4))
        return pwrpa_fail(r,PWRPA_CONTEXT,1);
    r->native_last=*(const volatile uint32_t*)(uintptr_t)r->native_address;r->native_reads++;
    if(r->native_last)return pwrpa_fail(r,PWRPA_CONTEXT,1);return 1;
}
static inline int pwrpa_close(const struct paic_io *m,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,const struct pwrpa_input input[PWRPA_OBJECTS],struct pwrpa_result *r)
{
    /* Output fields never authorize another address. Recheck the full
     * returned prefix against the caller's independent typed arguments. */
    if(!r->objects||r->objects>PWRPA_OBJECTS||r->pages>PWRPA_PAGES||r->complete||r->admitted||r->declined)
        return pwrpa_fail(r,PWRPA_PREFIX,1);
    unsigned at=0;
    for(unsigned k=0;k<r->objects;k++){
        const struct pwrpa_object *o=&r->object[k];
        if(o->address!=(uintptr_t)input[k].object||o->bytes!=input[k].bytes||o->pages_first!=at||
           o->complete>1||o->in_self>1||o->pages>r->pages-at||(!o->complete&&k+1!=r->objects)||
           (o->complete&&(o->in_self!=1||!o->bytes||o->address>UINT64_MAX-o->bytes||
               o->pages!=(o->address+o->bytes-1)/4096-o->address/4096+1)))return pwrpa_fail(r,PWRPA_PREFIX,1);
        for(unsigned j=0;j<o->pages;j++,at++){
            const struct pwrpa_page *q=&r->page[at];const struct pgns_translation *t=&q->AT;
            if(q->object!=k||t->page!=(o->address&~UINT64_C(4095))+4096u*j)return pwrpa_fail(r,PWRPA_PREFIX,1);
            if(q->valid){
                if(q->valid!=1||t->issued!=1||t->returned!=1||t->saved!=t->restored||
                   t->par!=(UINT64_C(0xff00000000000b80)|t->page))return pwrpa_fail(r,PWRPA_PREFIX,1);
            }else if(k+1!=r->objects||j+1!=o->pages||o->complete||
                (r->error!=PWRPA_MAP&&r->error!=PWRPA_TRANSLATION))return pwrpa_fail(r,PWRPA_PREFIX,1);
            else if(r->error==PWRPA_TRANSLATION&&
                (t->issued!=1||t->returned!=1||t->saved!=t->restored||t->par==(UINT64_C(0xff00000000000b80)|t->page)))
                return pwrpa_fail(r,PWRPA_PREFIX,1);
            else if(r->error==PWRPA_MAP&&(t->issued||t->returned||t->par||t->saved||t->restored))
                return pwrpa_fail(r,PWRPA_PREFIX,1);
        }
    }
    if(at!=r->pages||(!r->error&&r->objects!=PWRPA_OBJECTS))return pwrpa_fail(r,PWRPA_PREFIX,1);
    if(!pwra_zero(r->object+r->objects,(PWRPA_OBJECTS-r->objects)*sizeof(r->object[0]))||
       !pwra_zero(r->page+r->pages,(PWRPA_PAGES-r->pages)*sizeof(r->page[0])))return pwrpa_fail(r,PWRPA_PREFIX,1);
    if(r->unknown||r->outstanding||!pwrpa_live(m,p,w,g,r))return 0;
    r->admitted=!r->error;r->declined=!!r->error;r->complete=1;paic_actual_order(0);return 1;
}
static inline int pwrpa_run(const struct paic_io *m,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pgcd_context *g,uint64_t native,const struct pwrpa_input objects[PWRPA_OBJECTS],
    void *AT_context,int (*translate)(void*,struct pgns_translation*),struct pwrpa_result *r)
{
    if(!r)return 0;if(!pwra_zero(r,sizeof(*r)))return pwrpa_fail(r,PWRPA_ARGUMENT,1);
    r->attempted=1;r->provider=(uintptr_t)p;r->core=(uintptr_t)g;r->ticket=(uintptr_t)(g?g->ticket:0);
    r->memory=(uintptr_t)m;r->work=(uintptr_t)w;r->native_address=native;
    if(!objects||!translate||!pwrpa_live(m,p,w,g,r))return pwrpa_fail(r,PWRPA_ARGUMENT,1);
    r->before=r->last;r->native_first=r->native_last;
    for(unsigned k=0;k<PWRPA_OBJECTS;k++){
        const uint64_t address=(uintptr_t)objects[k].object,bytes=objects[k].bytes;
        struct pwrpa_object *o=&r->object[k];
        if(!pwra_zero(o,sizeof(*o)))return pwrpa_fail(r,PWRPA_PREFIX,1);
        o->address=address;o->bytes=bytes;o->pages_first=r->pages;
        r->objects=k+1;r->failed_object=k;r->failed_page=UINT32_MAX;
        if(!o->bytes||o->bytes>UINT32_MAX||!pgcd_in_self(&p->core,o->address,o->bytes)){
            pwrpa_fail(r,PWRPA_RANGE,0);return pwrpa_close(m,p,w,g,objects,r);
        }
        o->in_self=1;unsigned first=r->pages;
        for(unsigned j=0;j<k;j++)if(pwrcl_overlap(o->address,o->bytes,r->object[j].address,r->object[j].bytes)){
            pwrpa_fail(r,PWRPA_ALIAS,0);return pwrpa_close(m,p,w,g,objects,r);
        }
        for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
            if(o->address!=address||o->bytes!=bytes||o->in_self!=1||o->complete||o->pages_first!=first)
                return pwrpa_fail(r,PWRPA_PREFIX,1);
            if(r->pages==PWRPA_PAGES){pwrpa_fail(r,PWRPA_LIMIT,0);return pwrpa_close(m,p,w,g,objects,r);}
            if(!pwrpa_live(m,p,w,g,r))return 0;
            struct pwrpa_page *q=&r->page[r->pages];
            if(!pwra_zero(q,sizeof(*q)))return pwrpa_fail(r,PWRPA_PREFIX,1);
            r->pages++;q->object=k;q->AT.page=page;r->failed_page=r->pages-1;o->pages++;
            if(!polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,3)&&
               !polaris_efi_range_owned(w->map,w->bytes,w->stride,page,4096,4)){
                pwrpa_fail(r,PWRPA_MAP,0);return pwrpa_close(m,p,w,g,objects,r);
            }
            unsigned position=r->pages;r->outstanding=position;paic_actual_order(0);
            int returned=translate(AT_context,&q->AT);paic_actual_order(0);
            if(r->error||r->unknown||r->complete||r->admitted||r->declined||
               r->pages!=position||r->outstanding!=position||r->objects!=k+1||o->address!=address||o->bytes!=bytes||
               o->in_self!=1||o->complete||o->pages_first!=first||o->pages!=position-first||q->object!=k||q->valid||
               r->failed_object!=k||r->failed_page!=position-1||
               !returned||q->AT.issued!=1||q->AT.returned!=1||q->AT.page!=page||q->AT.saved!=q->AT.restored)
                return pwrpa_fail(r,PWRPA_PARTIAL,1);
            r->outstanding=0;
            if(!pwrpa_live(m,p,w,g,r))return 0;
            if(q->AT.par!=(UINT64_C(0xff00000000000b80)|page)){
                pwrpa_fail(r,PWRPA_TRANSLATION,0);return pwrpa_close(m,p,w,g,objects,r);
            }
            q->valid=1;
        }
        o->complete=1;
    }
    r->failed_object=r->failed_page=UINT32_MAX;return pwrpa_close(m,p,w,g,objects,r);
}
#endif
