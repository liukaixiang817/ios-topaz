/* Checked four-supply composition over the original resident Device/CPU
 * leaves. No permission boolean or reusable ticket. Every resource input is
 * bound to this client's fresh full CmdDb and sixteen returned READs. */
#ifndef POLARIS_UEFI_WIFI_VRM_ACCESS_H
#define POLARIS_UEFI_WIFI_VRM_ACCESS_H
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#if !EFI_XNU_WIFI_CURRENT_WORD_READ || !EFI_XNU_WIFI_DB_WORD_CAPTURE || !EFI_XNU_WIFI_PRE_MASK_ARGUMENTS || !EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION || EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT || EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#error Four VRM requires current word delivery, original work/CPU/argument gates and actual checked access
#endif
static inline int pwva_binding(const struct pwra_context*c)
{
    if(!c||!c->VRM||!c->record||!c->prepared||!c->provider||!c->critical)return 0;
    const struct pwv_result*q=c->VRM;const struct pwra_result*r=c->record;
    if(q->attempted!=1||q->unknown||(q->error&&!(q->known_refusal&&q->error==PWV_VALUES))||
       q->provider!=(uintptr_t)c->provider||q->core!=(uintptr_t)c->core||q->prepared!=(uintptr_t)c->prepared||
       q->access!=(uintptr_t)r||r->client!=(uintptr_t)c->provider->handle_output||r->provider!=(uintptr_t)c->provider||
       r->critical!=(uintptr_t)c->critical||r->namespace_record!=(uintptr_t)c->device||
       r->read_transaction!=(uintptr_t)&q->read||r->write_transaction!=(uintptr_t)&q->write||c->read||c->write||c->cmd||
       !pgcd_equal(q->resources[0],c->prepared->VRM[1],sizeof(q->resources[0]))||
       !pgcd_equal(q->resources[0],q->resources[1],sizeof(q->resources[0])))return 0;
    if(!r->write_bound)return q->phase==1&&c->transaction==&q->read.io&&r->transaction==(uintptr_t)&q->read.io;
    if(q->phase!=2||c->transaction!=&q->write.io||r->transaction!=(uintptr_t)&q->write.io||
       q->read.valid!=65535||q->read.response_seen!=65535||!q->read.io.finished||!q->read.io.restored||
       q->read.io.error||q->read.io.unknown||q->read.io.outstanding)return 0;
    if(q->write.io.attempted){
        if(!pwvm_inputs(q->write.rail))return 0;
        for(unsigned k=0;k<4;k++){
            const struct pwvm_rail*s=&q->write.rail[k];
            if(s->address!=q->resources[1][k].address||s->saved_mV!=q->read.response[4*k]||
               s->saved_enable!=q->read.response[4*k+1]||s->saved_mode!=q->read.response[4*k+2]||
               s->requested_mV!=pwvm_min_mV[k]||q->read.response[4*k+3]>511)return 0;
        }
        if(q->write.io.phase&&
           (q->write.io.tcs!=q->read.io.tcs||q->write.io.IRQ_enable!=q->read.io.IRQ_enable||
            q->write.io.active_mask!=q->read.io.active_mask||
            !pgcd_equal(&q->write.io.saved,&q->read.io.observed,sizeof(q->write.io.saved))))return 0;
    }
    return 1;
}
static inline int pwva_writable(const struct pwra_context*c,uint64_t at,uint32_t value)
{
    if(!pwva_binding(c))return 0;
    return c->record->write_bound?pwvm_writable(&c->VRM->write,at,value):pwvr_writable(&c->VRM->read,at,value);
}
static inline int pwva_transfer(struct pwra_context*c,uint64_t at,uint32_t*value,unsigned write,unsigned engine)
{
    struct pwra_result*r=c->record;struct pwv_result*v=c->VRM;struct pwrsc_transaction*t=c->transaction;
    if(!value||!pwva_binding(c)||r->unknown||r->error||r->outstanding||r->retired||r->events>=PWRA_EVENTS||
       !pwra_address(at)||(!write&&at==PWRSC_BASE+8)||
       (write&&(!r->acquired||!r->local_held||!engine||!pwva_writable(c,at,*value))))return pwra_fail(c,PWRA_SCOPE,1);
    unsigned reading=!r->write_bound;
    if(engine){
        if(!t->attempted||!t->outstanding||t->outstanding!=t->events||t->events>PWRSC_HISTORY||
           v->read.io.events+v->write.io.events>PWRSC_HISTORY)return pwra_fail(c,PWRA_PREFIX,1);
        const struct pwrsc_event*e=&t->history[t->outstanding-1];
        if(e->phase!=t->phase||e->address!=at||e->operation!=(write?2u:1u)||e->issued!=1||!e->unknown||
           (write&&e->value!=*value)||t->active_mask!=r->mask)return pwra_fail(c,PWRA_PREFIX,1);
        for(unsigned k=0;k<3;k++)if(t->address[k]||t->saved_vote[k]||t->raised_vote[k])return pwra_fail(c,PWRA_SAVED,1);
        /* Recheck the complete returned READ immediately before the first
         * resource-writer store, after its resident begin/clock callbacks. */
        if(write&&!reading&&v->write.io.writes==1&&!pwvr_retired(&v->read))return pwra_fail(c,PWRA_PREFIX,1);
    }else if(write||!pwrmd_readable(at))return pwra_fail(c,PWRA_SCOPE,1);
    struct pwra_event*event=&r->history[r->events++];struct pwrmd_event*q=&event->io;
    q->address=at;q->value=write?*value:UINT32_MAX;event->operation=write?2u:1u;
    event->engine_event=engine?(t->outstanding|(reading?UINT32_C(0x80000000):0)):0;
    if(!pwra_live(c,&event->native_before,&q->before))return 0;
    uint64_t page=at&~UINT64_C(4095);unsigned k;for(k=0;k<3&&pwrmd_pages[k]!=page;k++){}
    if(k==3||!pwrmd_exclude(c->work,page)||!c->device->GCD[k].issued||!c->device->GCD[k].returned||c->device->GCD[k].unknown||c->device->GCD[k].status)
        return pwra_fail(c,PWRA_SCOPE,1);
    q->translation.page=page;r->outstanding=r->events;paic_actual_order(0);
    int returned=c->io.translate(c->io.context,&q->translation);paic_actual_order(0);
    if(!returned||q->translation.page!=page||!pwrmd_translation_valid(&q->translation))return pwra_fail(c,PWRA_TRANSLATION,1);
    unsigned match=0;
    for(unsigned j=0;j<c->device->events;j++){
        const struct pwrmd_event*old=&c->device->history[j];
        if(old->translation.page==page&&old->issued&&old->returned&&!old->unknown&&pwrmd_translation_valid(&old->translation)){
            if(old->translation.read_par!=q->translation.read_par)return pwra_fail(c,PWRA_TRANSLATION,1);match=1;break;
        }
    }
    if(!match||!pwra_live(c,&event->native_before,&q->before)||!pwva_binding(c)||
       (write&&!pwva_writable(c,at,*value)))return pwra_fail(c,PWRA_SCOPE,1);
    q->issued=q->unknown=1;if(write)r->writes++;else r->reads++;paic_actual_order(0);
    returned=write?c->io.write(c->io.context,at,*value):c->io.read(c->io.context,at,&q->value);
    q->returned=returned?1:0;paic_actual_order(0);if(returned&&!write)*value=q->value;
    if(!returned)return pwra_fail(c,PWRA_IO,1);
    if(!write&&engine)for(unsigned j=0;j<3;j++)if(at==pwrsc_tcs(t)+0x3c+20*j){
        r->command_status_OR[j]|=q->value;
        unsigned final_phase=reading?33u:17u,edges=reading?16u:8u;
        if(t->phase==0){
            if(t->writes||t->triggers||t->completed||t->acknowledged||t->steps)return pwra_fail(c,PWRA_PREFIX,1);
        }else if(t->phase==final_phase){
            if(t->triggers!=edges||t->completed!=edges||t->acknowledged!=edges)return pwra_fail(c,PWRA_PREFIX,1);
        }else{
            if((reading?j!=0:j>1)||!t->phase||(t->phase&1)||t->phase>=final_phase||t->triggers!=t->phase/2||
               t->completed+1!=t->triggers||t->acknowledged!=t->completed)return pwra_fail(c,PWRA_PREFIX,1);
            if(!pwrr_pending_status_known(q->value))return pwra_fail(c,PWRA_UNKNOWN_STATUS,1);
        }
    }
    if(!pwra_live(c,&event->native_after,&q->after)||!pwva_binding(c))return pwra_fail(c,PWRA_SCOPE,1);
    q->unknown=0;r->outstanding=0;*value=q->value;paic_actual_order(0);return 1;
}
static inline int pwva_clock(void*context,uint64_t*ticks,uint64_t*frequency)
{
    struct pwra_context*c=context;struct pwv_result*v=c->VRM;uint32_t native;c->record->clock_calls++;
    if(!pwva_binding(c)||!pwra_live(c,&native,ticks)||!pwva_binding(c))return pwra_fail(c,PWRA_SCOPE,1);
    if(v->read.io.started&&(*ticks<v->read.io.started||*ticks-v->read.io.started>PWRSC_DEADLINE||
       v->read.io.steps+v->write.io.steps>256||v->read.io.events+v->write.io.events>PWRSC_HISTORY))return pwra_fail(c,PWRA_TIME,1);
    *frequency=c->critical->after.cpu.frequency;c->record->clock_returned++;return 1;
}
static inline int pwva_engine_prefixes(const struct pwra_context*c)
{
    const struct pwra_result*r=c->record;const struct pwv_result*v=c->VRM;unsigned rs=0,ws=0,reads=0,writes=0;uint32_t status[3]={0};
    if(!pwva_binding(c)||r->events>PWRA_EVENTS||r->clock_calls!=r->clock_returned)return 0;
    for(unsigned k=0;k<r->events;k++){
        const struct pwra_event*a=&r->history[k];
        if(a->io.issued!=1||a->io.returned!=1||a->io.unknown||a->native_before||a->native_after||
           !pwrmd_translation_valid(&a->io.translation)||a->io.after<a->io.before||
           a->io.before<c->critical->normal.cpu.ticks)return 0;
        if(a->operation==1)reads++;else if(a->operation==2)writes++;else return 0;
        if(!a->engine_event){if(a->operation!=1||!pwrmd_readable(a->io.address))return 0;continue;}
        unsigned reading=a->engine_event>>31,index=a->engine_event&UINT32_C(0x7fffffff);
        const struct pwrsc_transaction*t=reading?&v->read.io:&v->write.io;
        if(reading){if(ws||index!=++rs)return 0;}else if(index!=++ws||rs!=v->read.io.events)return 0;
        if(!index||index>t->events)return 0;const struct pwrsc_event*e=&t->history[index-1];
        if(a->operation!=e->operation||a->io.address!=e->address||a->io.value!=e->value||
           a->io.before<e->before||a->io.after>e->after)return 0;
        if(a->operation==1)for(unsigned j=0;j<3;j++)if(a->io.address==pwrsc_tcs(t)+0x3c+20*j)status[j]|=a->io.value;
    }
    return rs==v->read.io.events&&ws==(r->write_bound?v->write.io.events:0)&&
        reads==r->reads&&writes==r->writes&&writes==v->read.io.writes+v->write.io.writes&&
        pgcd_equal(status,r->command_status_OR,sizeof(status));
}
static inline int pwva_acquire(struct pwra_context*c,const struct pwra_io*io,struct pgcd_context*g,
    struct pwrcl_result*p,const struct pwrph_work*w,struct pwrpc_result*cpu,const struct pwcp_result*d,
    const struct pwrpb_baseline*normal,const struct pwrpb_baseline*masked,const struct pwrmd_result*device,
    struct pwv_result*v,struct pwra_result*r)
{
    if(!r||r->attempted||!v||!pwra_zero(v,sizeof(*v)))return 0;r->attempted=1;v->attempted=1;
    if(!c||!io||!io->memory||!io->translate||!io->read||!io->write||!io->RAM_translate||!g||!p||!w||!cpu||!d||!normal||!masked||!device)
        {r->error=PWRA_ARGUMENT;v->error=PWV_ARGUMENT;return 0;}
    *c=(struct pwra_context){.io=*io,.core=g,.provider=p,.work=w,.critical=cpu,.transaction=&v->read.io,
        .device=device,.record=r,.prepared=d,.VRM=v};
    r->client=(uintptr_t)p->handle_output;r->provider=(uintptr_t)p;r->critical=(uintptr_t)cpu;r->transaction=(uintptr_t)&v->read.io;
    r->normal_RAM=(uintptr_t)normal;r->masked_RAM=(uintptr_t)masked;r->namespace_record=(uintptr_t)device;
    r->read_transaction=(uintptr_t)&v->read;r->write_transaction=(uintptr_t)&v->write;
    v->provider=(uintptr_t)p;v->core=(uintptr_t)g;v->prepared=(uintptr_t)d;v->access=(uintptr_t)r;v->phase=1;
    const void*objects[]={c,p,cpu,d,normal,masked,device,v,r};
    const uint64_t sizes[]={sizeof(*c),sizeof(*p),sizeof(*cpu),sizeof(*d),sizeof(*normal),sizeof(*masked),sizeof(*device),sizeof(*v),sizeof(*r)};
    for(unsigned k=0;k<9;k++)if(!pgcd_in_self(&p->core,(uintptr_t)objects[k],sizes[k])||
       !pwrcl_owned(io->memory,p,w,(uintptr_t)objects[k],(uint32_t)sizes[k]))return pwra_fail(c,PWRA_SCOPE,1);
    for(unsigned k=0;k<9;k++)for(unsigned j=0;j<k;j++)if(pwrcl_overlap((uintptr_t)objects[k],sizes[k],(uintptr_t)objects[j],sizes[j]))return pwra_fail(c,PWRA_SCOPE,1);
    if(!p->client_held||p->client_returned||p->retired||p->unknown||p->outstanding||p->error||!p->pools_complete[1]||
       p->created.bytes!=88||!r->client||!pwrpc_local_held(cpu)||!pwrpb_equal(normal,masked)||normal->before.daif||normal->before.group1!=1||
       masked->before.daif!=0xc0||masked->before.group1||!device->complete||device->error||device->unknown||device->outstanding||
       device->queries!=3||device->reads!=70||device->image!=p->reader.image||device->core!=p->core.core||
       device->self_base!=p->core.self_base||device->self_bytes!=p->core.self_bytes||device->after.ticks>cpu->normal.cpu.ticks||
       !d->complete||!d->stable||d->error||pwcp_unsafe(d)||d->owner_matches!=1||d->provider!=(uintptr_t)p||d->core!=(uintptr_t)g||
       d->bound_after.ticks>cpu->normal.cpu.ticks||d->before.ticks<g->record->before.cpu.ticks||
       !pgcd_equal(d->resources[0],d->resources[1],sizeof(d->resources[0]))||!pgcd_equal(d->VRM[0],d->VRM[1],sizeof(d->VRM[0])))return pwra_fail(c,PWRA_SCOPE,1);
    unsigned matches=0;const struct pwrcl_list*active=&masked->pool.list[0];
    for(unsigned k=0;k<active->count;k++)if(active->node[k].address==r->client&&pgcd_equal(active->node[k].raw,p->created.raw,88))matches++;
    if(matches!=1)return pwra_fail(c,PWRA_CLIENT,1);
    for(unsigned k=0;k<4;k++)if(p->created.queue_bytes[k]!=24||pwfi_le(p->created.queue[k]+4,4))return pwra_fail(c,PWRA_CLIENT,1);
    pgcd_copy(v->resources[0],d->VRM[1],sizeof(v->resources[0]));r->mask=masked->active_mask;
    /* The source/CPU leaf uses the original context; no normal observation
     * supplies masked admission. The full fresh DB completes before MMIO. */
    if(!pwra_cmddb(c,0)||!pwra_observed_databases_valid(c,1)||
       !pwv_select_bytes(r->CmdDb[0].raw,v->resources[1])||
       !pgcd_equal(v->resources[0],v->resources[1],sizeof(v->resources[0])))return pwra_fail(c,PWRA_CHANGED,1);
    if(!pwra_snapshot(c,0)||!pwva_binding(c))return 0;r->acquired=r->local_held=1;paic_actual_order(0);return 1;
}
static inline int pwva_execute(struct pwra_context*c)
{
    struct pwv_result*v=c->VRM;struct pwra_result*r=c->record;uint32_t native;uint64_t ticks;
    if(!r->acquired||!r->local_held||!pwva_binding(c)||!pwra_observed_databases_valid(c,1))return pwra_fail(c,PWRA_PREFIX,1);
    const struct pwrsc_io io={c,pwra_read,pwra_write,pwra_clock,pwra_order};
    if(!pwvr_begin(&io,&v->read,r->mask))return pwra_fail(c,PWRA_IO,1);
    int result=0;for(unsigned k=0;k<256&&!result;k++)result=pwvr_step(&io,&v->read);
    if(result!=1||!pwvr_retired(&v->read)||!pwva_engine_prefixes(c)||!pwra_live(c,&native,&ticks)||
       v->read.io.started<c->critical->normal.cpu.ticks||v->read.io.last>ticks)return pwra_fail(c,PWRA_PREFIX,1);
    r->read_events=v->read.io.events;r->read_writes=v->read.io.writes;r->read_end=c->critical->after;r->read_retired=1;
    struct pwvm_rail rails[4];
    if(!pwv_plan(v,rails)){
        v->error=PWV_VALUES;v->known_refusal=1;return 1;
    }
    if(!pwra_zero(&v->write,sizeof(v->write))||!pwra_observed_databases_valid(c,1)||!pwvr_retired(&v->read))return pwra_fail(c,PWRA_PREFIX,1);
    c->transaction=&v->write.io;r->transaction=(uintptr_t)c->transaction;r->write_bound=1;v->phase=2;paic_actual_order(0);
    if(!pwvm_begin(&io,&v->write,r->mask,rails))return pwra_fail(c,PWRA_IO,1);
    result=0;for(unsigned k=0;k<256&&!result;k++){
        if(v->read.io.steps+v->write.io.steps>=256)break;result=pwvm_step(&io,&v->write);
    }
    if(result!=1||!pwv_engine_prefix(v)||!pwva_engine_prefixes(c))return pwra_fail(c,PWRA_PREFIX,1);return 1;
}
static inline int pwva_retire(struct pwra_context*c)
{
    struct pwra_result*r=c->record;struct pwv_result*v=c->VRM;
    if(!r->acquired||!r->local_held||r->retired||r->error||r->unknown||r->outstanding||
       !pwv_engine_prefix(v)||!pwva_engine_prefixes(c))return pwra_fail(c,PWRA_PREFIX,1);
    if(!pwra_cmddb(c,1)||!pwra_snapshot(c,1)||!pwra_observed_databases_valid(c,2)||
       !pwv_select_bytes(r->CmdDb[1].raw,v->resources[2])||
       !pgcd_equal(v->resources[0],v->resources[2],sizeof(v->resources[0]))||
       !pwv_engine_prefix(v)||!pwva_engine_prefixes(c))return pwra_fail(c,PWRA_PREFIX,1);
    r->local_held=0;r->retired=1;v->engines_retired=1;paic_actual_order(0);return 1;
}
#endif
#endif
