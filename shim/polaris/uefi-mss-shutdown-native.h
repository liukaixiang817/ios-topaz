/* Actual native normal shutdown: live SMP2P STOP/ACK, three AXI halts, reset.
 * No clock/power drop, DMA-retired claim, VMID return or freeing is implied.
 * RMTFS remains serviced until ACK, then all transport work is frozen. */
#ifndef POLARIS_UEFI_MSS_SHUTDOWN_NATIVE_H
#define POLARIS_UEFI_MSS_SHUTDOWN_NATIVE_H
#ifndef EFI_XNU_MSS_SHUTDOWN_NATIVE_AVAILABLE
#define EFI_XNU_MSS_SHUTDOWN_NATIVE_AVAILABLE 0
#endif
#include "uefi-wifi-wlfw-native.h"
#if EFI_XNU_MSS_SHUTDOWN_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_WLFW_NATIVE_AVAILABLE
#error Native shutdown requires actual native WLAN/RMTFS/MSS lifetime
#endif
#define PMND_RECORDS (PMS_EVENTS+PMH_EVENTS+PMSR_EVENTS)
struct pmnd_delivery {
    struct pmsd_command command;struct pmsl_delivery access;
    uint32_t attempted,complete,unknown,error;uint8_t digest[32];
};
struct pmnd_state {
    uint64_t wlan,service,glink,channel,smp,auth,owner,opening,records;
    struct pmsd_shutdown shutdown;struct pwea_core source[2];struct pms_sample sample;
    uint32_t attempted,ready,unknown,error,pending,deliveries,quiesced,complete;
    uint8_t records_digest[32],digest[32];
    uint64_t retirement; /* Unique later continuation; excluded from stop seal. */
};
static inline int pmnd_fail(struct pmnd_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmnd_live(struct pmnd_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error)return 0;
    struct pmsy_state*y=(void*)(uintptr_t)s->smp;struct pmsx_state*x=(void*)(uintptr_t)s->channel;
    struct pmwa_state*w=(void*)(uintptr_t)s->wlan;
    return y->stopping==(uintptr_t)s&&y->channel==s->channel&&y->owner==s->owner&&y->opening==s->opening&&
        x->auth==s->auth&&w->service==s->service&&w->owner==s->owner&&w->opening==s->opening&&
        pmwa_live(w)&&pmsx_live(x)&&pmsn_live((void*)(uintptr_t)s->auth);
}
/* Negotiation grants no arbitrary alternate state. Only this actual owner,
 * exact issued STOP word and matching original named entries may change. */
static inline int pmsy_stop_current(struct pmsy_state*y,struct pmsx_state*x)
{
    struct pmsn_state*a=(void*)(uintptr_t)x->auth;
    if(!pmsn_child(a,y->stopping,sizeof(struct pmnd_state)))return 0;
    struct pmnd_state*s=(void*)(uintptr_t)y->stopping;const struct pms_stop*p=&s->shutdown.stop.stop;
    if(!pmnd_live(s)||s->quiesced||s->smp!=(uintptr_t)y||s->channel!=(uintptr_t)x||p->unknown||p->error||
       !p->started||p->config.epoch!=s->opening||p->config.out_offset!=x->item[0].data||p->config.in_offset!=y->in_offset)return 0;
    struct pms_view in,out;if(!pms_parse(y->current_in,1,&in)||!pms_parse(y->current_out,0,&out)||
       in.index!=y->in_index||in.flags!=y->in_flags||(in.value&1)||out.index||out.value!=(p->write_returned?1u:0u)||
       ((in.value&8)&&!p->write_returned))return 0;
    for(unsigned n=0;n<340;n++)if((n<36||n>=40)&&y->current_out[n]!=y->out[n])return 0;
    if(p->events&&p->event[0].returned){
        const uint8_t*initial=p->event[0].sample.in;
        for(unsigned n=0;n<340;n++)if((n<20||(n-20)%20<16)&&y->current_in[n]!=initial[n])return 0;
    }return 1;
}
static inline int pmnd_begin(struct pmnd_state*s,struct pmnd_delivery*records,struct pmwa_state*w)
{
    if(!s||!records||!w||!pwmc_zero(s,sizeof(*s))||!pwmc_zero(records,sizeof(*records)*PMND_RECORDS)||
       !pmwa_current(w)||!w->client.ready||!w->assigned||w->pending||
       (w->client.enable_requested&&!w->client.disabled))return 0;
    struct pmrf_state*r=(void*)(uintptr_t)w->service;struct pmsg_state*g=(void*)(uintptr_t)r->glink;
    struct pmsx_state*x=(void*)(uintptr_t)g->channel;struct pmsy_state*y=(void*)(uintptr_t)x->negotiation;
    struct pmsn_state*a=(void*)(uintptr_t)x->auth;struct pmsc_owner*o=(void*)(uintptr_t)x->owner;
    if(y->stopping||!pmsy_current(y,x)||!pmsn_child(a,(uintptr_t)s,sizeof(*s))||
       !pmsn_child(a,(uintptr_t)records,sizeof(*records)*PMND_RECORDS)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)records,sizeof(*records)*PMND_RECORDS))return 0;
    struct pms_view in;if(!pms_parse(y->current_in,1,&in)||(in.value&11)!=2)return 0;
    const uint64_t addresses[]={(uintptr_t)w,(uintptr_t)r,(uintptr_t)g,(uintptr_t)x,(uintptr_t)y,(uintptr_t)a,a->records,a->copy,a->segments,r->grant,r->nv,x->smem,x->allocation};
    const uint64_t sizes[]={sizeof(*w),sizeof(*r),sizeof(*g),sizeof(*x),sizeof(*y),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,sizeof(struct pmtf_state),sizeof(struct pnnv_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state)};
    for(unsigned n=0;n<13;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),addresses[n],sizes[n])||
       !pwea_disjoint((uintptr_t)records,sizeof(*records)*PMND_RECORDS,addresses[n],sizes[n]))return 0;
    s->wlan=(uintptr_t)w;s->service=(uintptr_t)r;s->glink=(uintptr_t)g;s->channel=(uintptr_t)x;s->smp=(uintptr_t)y;
    s->auth=(uintptr_t)a;s->owner=x->owner;s->opening=x->opening;s->records=(uintptr_t)records;s->attempted=1;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(!pwea_core_check(h->input.early,&s->source[0],&h->map)||!pmwa_current(w))return pmnd_fail(s,1);
    struct pms_config cfg={s->opening,428,435,x->item[0].data,y->in_offset,340,340};
    if(pmsd_begin(&s->shutdown,&cfg,o->last,o->current.cpu.frequency)<0)return pmnd_fail(s,1);
    s->ready=1;y->stopping=(uintptr_t)s;return pmnd_live(s);
}
static inline int pmnd_access(struct pmnd_state*s,struct pmnd_delivery*r)
{
    struct pmsd_shutdown*d=&s->shutdown;const struct pmsd_command*c=&r->command;
    if(!d->pending||d->unknown||!pgcd_equal(c,&d->command,sizeof(*c))||!pmnd_live(s))return 0;
    struct pmsn_state*a=(void*)(uintptr_t)s->auth;struct pmpn_state*p=(void*)(uintptr_t)a->power;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmni_command io={0};
    unsigned typed=0;
    if(c->phase==2){const struct pmsr_command*q=&c->command.reset;io=(struct pmni_command){q->address,q->kind,q->value};typed=2;}
    else if(c->command.stop.phase==2){const struct pmh_command*q=&c->command.stop.command.halt;io=(struct pmni_command){q->address,q->write?PMNI_WRITE:PMNI_READ,q->value};typed=1;}
    else{
        const struct pms_command*q=&c->command.stop.command.stop;
        if(q->step==PMS_RING_SET||q->step==PMS_RING_CLEAR)io=(struct pmni_command){q->address,PMNI_WRITE,q->value};
        else if(q->step==PMS_PUBLISH||q->step==PMS_RING_ORDER)io.kind=PMNI_FULL_ORDER;else return 0;
    }
    unsigned memory=io.kind==PMNI_READ||io.kind==PMNI_WRITE;struct pmsl_delivery*v=&r->access;
    if((memory&&!pmpn_target(p,io.address&~UINT64_C(4095),&v->target[0]))||!pmpn_arch(p,&v->opening)||
       (io.kind==PMNI_WRITE&&!pmsc_mark_effect(o,PMSC_REMOTE)))return 0;
    int ok=typed==2?pmni_reset(d,c,&v->opening,&v->native):typed==1?pmni_halt(d,c,&v->opening,&v->native):pmni_access(&v->opening,&io,&v->native);
    return ok&&(!memory||(pmpn_target(p,io.address&~UINT64_C(4095),&v->target[1])&&v->target[0].index==v->target[1].index))&&pmnd_live(s);
}
static inline int pmnd_current(struct pmnd_state*s)
{
    if(!pmnd_live(s)||s->complete!=1||s->pending||!s->quiesced||s->shutdown.complete!=1||s->shutdown.unknown||
       s->shutdown.phase!=3||s->shutdown.stop.stop.ack_held!=1||s->shutdown.stop.halt.ports_held!=7||!s->shutdown.reset.complete)return 0;
    uint8_t hash[32];pweh_digest((const void*)(uintptr_t)s->records,s->deliveries*sizeof(struct pmnd_delivery),hash);
    if(!pgcd_equal(hash,s->records_digest,32))return 0;pweh_digest(s,offsetof(struct pmnd_state,digest),hash);
    return pgcd_equal(hash,s->digest,32)&&pmsn_current((void*)(uintptr_t)s->auth)&&pmnd_live(s);
}
/*0=sticky refusal,1=work/wait,2=ACK+AXI+reset complete (not DMA retirement).*/
static inline int pmnd_step(struct pmnd_state*s)
{
    if(!pmnd_live(s)||s->pending)return 0;if(s->complete)return pmnd_current(s)?2:0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmsd_shutdown*d=&s->shutdown;
    struct pmsx_state*x=(void*)(uintptr_t)s->channel;struct pmsy_state*y=(void*)(uintptr_t)s->smp;
    if(!s->quiesced&&d->phase==1&&d->stop.phase==1&&(d->stop.stop.step==PMS_INITIAL||
       (d->stop.stop.step==PMS_POLL&&o->last>=d->stop.stop.next_poll))){
        struct pmrf_state*r=(void*)(uintptr_t)s->service;if(polaris_rmtfs_poll(r->service))return pmnd_fail(s,2);
    }
    struct pmsd_command command;int next=pmsd_next(d,o->last,&command);if(next==PMSD_WAIT)return 1;
    if(next==PMSD_RESET_PULSED){
        const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
        if(!pwea_core_check(h->input.early,&s->source[1],&h->map)||!pmsn_current((void*)(uintptr_t)s->auth)||!pmnd_live(s))return pmnd_fail(s,3);
        pweh_digest((const void*)(uintptr_t)s->records,s->deliveries*sizeof(struct pmnd_delivery),s->records_digest);
        s->complete=1;pweh_digest(s,offsetof(struct pmnd_state,digest),s->digest);return 2;
    }
    if(next!=PMSD_IO||s->deliveries==PMND_RECORDS)return pmnd_fail(s,3);
    struct pmnd_delivery*r=(struct pmnd_delivery*)(uintptr_t)s->records+s->deliveries;
    if(!pwmc_zero(r,sizeof(*r)))return pmnd_fail(s,3);r->command=command;r->attempted=r->unknown=1;s->pending=++s->deliveries;
    uint32_t value=0;const struct pms_sample*sample=0;int ok;
    if(command.phase==1&&command.command.stop.phase==1){
        const struct pms_command*c=&command.command.stop.command.stop;
        if(c->step==PMS_INITIAL||c->step==PMS_POLL){
            sample=&s->sample;s->sample.out_bytes=s->sample.in_bytes=340;
            ok=pmsy_read(y,x->item[0].data,s->sample.out,340)&&pmsy_read(y,y->in_offset,s->sample.in,340);
        }else if(c->step==PMS_SET_STOP)ok=pmsx_write(x,0,(unsigned)(c->address-PMSQ_BASE-x->item[0].data),c->value);
        else if(c->step==PMS_READBACK){const uint8_t*p=pmsx_read(x,(unsigned)(c->address-PMSQ_BASE),4);ok=p!=0;if(ok)value=pms_u32(p);}
        else{ok=pmnd_access(s,r);value=r->access.native.value;}
    }else{ok=pmnd_access(s,r);value=r->access.native.value;}
    if(!ok||!pmnd_live(s)||!pgcd_equal(&command,&r->command,sizeof(command))||pmsd_complete(d,&command,o->last,1,value,sample)<0)return pmnd_fail(s,4);
    if(d->stop.stop.ack_held)s->quiesced=1;
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmnd_delivery,digest),r->digest);s->pending=0;return 1;
}
#endif
#endif
