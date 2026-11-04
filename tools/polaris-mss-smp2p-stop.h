/* Polaris MSS stop request over existing negotiated SMP2P items428/435.
 * Own DT: master-kernel bit0, slave-kernel bit3, APCS0x1799000c mask0x4000.
 * Pure finite protocol: no SMEM allocator, memory/MMIO/cache backend or reset.
 * A caller must own a fresh MSS generation and exclusive APPS producer, prove
 * item provenance/mappings/cache lifetime, and keep all other resetters out.
 * Unchanged headers cannot by themselves prove an external epoch or no ABA.
 * Success leaves STOP asserted; neither success nor ACK proves DMA retirement.
 */
#ifndef POLARIS_MSS_SMP2P_STOP_H
#define POLARIS_MSS_SMP2P_STOP_H
#include <stdint.h>
#include <stddef.h>
#define PMS_ITEM_BYTES 340u
#define PMS_EVENTS 136u
#define PMS_SAMPLES 128u
#define PMS_TICKS UINT64_C(19200000) /* own stop timeout1s at19.2MHz */
#define PMS_POLL_TICKS UINT64_C(153600) /*8ms, finite polling replacement for IRQ wait*/
#define PMS_SMEM_BASE UINT64_C(0x86000000)
#define PMS_DOORBELL UINT64_C(0x1799000c)
#define PMS_DOORBELL_MASK UINT32_C(0x4000)
enum pms_result {PMS_FAILED=-1,PMS_WAIT,PMS_IO,PMS_ACK_HELD};
enum pms_step {PMS_INITIAL=1,PMS_SET_STOP,PMS_PUBLISH,PMS_READBACK,
    PMS_RING_SET,PMS_RING_CLEAR,PMS_RING_ORDER,PMS_POLL,PMS_DONE};
enum pms_error {PMS_OK,PMS_ARGUMENT,PMS_REENTRY,PMS_TIME,PMS_LIMIT,PMS_ACCESS,
    PMS_ITEM,PMS_STALE,PMS_CHANGED,PMS_FATAL,PMS_READBACK_ERROR};
struct pms_config {uint64_t epoch;uint32_t out_id,in_id,out_offset,in_offset,out_bytes,in_bytes;};
struct pms_sample {uint8_t out[PMS_ITEM_BYTES],in[PMS_ITEM_BYTES];uint32_t out_bytes,in_bytes;};
struct pms_view {uint32_t index,value,flags,valid;};
struct pms_command {uint64_t address,second;uint32_t sequence,step,bytes,value;};
struct pms_event {
    struct pms_command command;uint64_t before,after;
    uint32_t issued,returned,value;int32_t return_raw;
    struct pms_sample sample;
};
struct pms_stop {
    struct pms_config config;uint64_t opening,last,next_poll;
    uint32_t started,unknown,error,pending,step,events,samples,ack_held;
    uint32_t out_index,in_index,saved_out,write_intent,write_returned,ring_intent,ring_returned,reserved;
    struct pms_event event[PMS_EVENTS];
};
static inline uint32_t pms_u32(const uint8_t*p)
{return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline int pms_equal(const void*a,const void*b,unsigned n)
{const uint8_t*x=a,*y=b;for(unsigned k=0;k<n;k++)if(x[k]!=y[k])return 0;return 1;}
static inline int pms_zero(const void*a,unsigned n)
{const uint8_t*x=a;for(unsigned k=0;k<n;k++)if(x[k])return 0;return 1;}
static inline int pms_name_equal(const uint8_t*a,const uint8_t*b)
{for(unsigned k=0;k<16;k++){if(a[k]!=b[k])return 0;if(!a[k])return 1;}return 0;}
/* This parser never follows a physical address or writes the sampled item. */
static inline int pms_parse(const uint8_t*p,unsigned inbound,struct pms_view*v)
{
    static const uint8_t names[2][16]={"master-kernel","slave-kernel"};
    if(!p||!v||inbound>1||pms_u32(p)!=0x504d5324||pms_u32(p+4)!=0x101||
       pms_u32(p+8)!=(inbound?1u:0x10000u)||(pms_u32(p+12)&0xffff)!=16||
       !(pms_u32(p+12)>>16)||(pms_u32(p+12)>>16)>16||(pms_u32(p+16)&~3u))return 0;
    unsigned used=0,found=0,index=0;
    for(unsigned k=0;k<16;k++){
        const uint8_t*name=p+20+k*20;if(!name[0])continue;used++;
        unsigned n=0;while(n<16&&name[n])n++;if(n==16)return 0;
        for(unsigned j=0;j<k;j++)if(pms_name_equal(name,p+20+j*20))return 0;
        if(pms_name_equal(name,names[inbound])){found++;index=k;}
    }
    if(used!=(pms_u32(p+12)>>16)||found!=1)return 0;
    *v=(struct pms_view){index,pms_u32(p+36+index*20),pms_u32(p+16),used};return 1;
}
static inline int pms_disjoint(uint64_t a,unsigned n,uint64_t b,unsigned m)
{return a&&b&&a<=UINT64_MAX-n&&b<=UINT64_MAX-m&&!(a<b+m&&b<a+n);}
static inline int pms_fail(struct pms_stop*s,unsigned error)
{if(s){if(!s->error)s->error=error;s->unknown=1;}return PMS_FAILED;}
static inline int pms_time(struct pms_stop*s,uint64_t now)
{
    if(!now||now<s->last||now<s->opening||now-s->opening>PMS_TICKS)return pms_fail(s,PMS_TIME);
    s->last=now;return 1;
}
static inline int pms_span(uint32_t offset,uint32_t bytes)
{return !(offset&3)&&offset>=8400&&offset<0x1ff000&&bytes>=PMS_ITEM_BYTES&&bytes<=4096&&bytes<=0x1ff000-offset;}
static inline int pms_begin(struct pms_stop*s,const struct pms_config*c,uint64_t now,uint64_t hz)
{
    if(!s||!c||!pms_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)c,sizeof(*c))||
       !now||hz!=19200000||!c->epoch||c->out_id!=428||c->in_id!=435||
       !pms_span(c->out_offset,c->out_bytes)||!pms_span(c->in_offset,c->in_bytes)||
       !pms_disjoint(c->out_offset,c->out_bytes,c->in_offset,c->in_bytes)||!pms_zero(s,sizeof(*s)))return PMS_FAILED;
    s->config=*c;s->opening=s->last=now;s->step=PMS_INITIAL;s->started=1;return PMS_WAIT;
}
static inline int pms_next(struct pms_stop*s,uint64_t now,struct pms_command*out)
{
    if(!s||!out||!s->started)return PMS_FAILED;
    if(!pms_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)out,sizeof(*out)))return pms_fail(s,PMS_ARGUMENT);
    if(s->unknown||s->error)return PMS_FAILED;
    if(s->pending)return pms_fail(s,PMS_REENTRY);
    if(s->ack_held)return s->ack_held==1&&s->step==PMS_DONE?PMS_ACK_HELD:pms_fail(s,PMS_REENTRY);
    if(s->step<PMS_INITIAL||s->step>PMS_POLL||s->out_index>=16||s->in_index>=16)return pms_fail(s,PMS_REENTRY);
    if(pms_time(s,now)<0)return PMS_FAILED;
    if(s->step==PMS_POLL&&now<s->next_poll)return PMS_WAIT;
    if(s->events>=PMS_EVENTS||s->samples>=PMS_SAMPLES)return pms_fail(s,PMS_LIMIT);
    struct pms_command c={.sequence=s->events+1,.step=s->step};
    switch(s->step){
    case PMS_INITIAL:case PMS_POLL:
        c.address=PMS_SMEM_BASE+s->config.out_offset;c.second=PMS_SMEM_BASE+s->config.in_offset;
        c.bytes=PMS_ITEM_BYTES;break;
    case PMS_SET_STOP:case PMS_READBACK:
        c.address=PMS_SMEM_BASE+s->config.out_offset+36+20*s->out_index;c.bytes=4;
        if(s->step==PMS_SET_STOP){c.value=s->saved_out|1u;s->write_intent=1;}break;
    case PMS_RING_SET:case PMS_RING_CLEAR:
        c.address=PMS_DOORBELL;c.bytes=4;c.value=s->step==PMS_RING_SET?PMS_DOORBELL_MASK:0;
        s->ring_intent|=s->step==PMS_RING_SET?1u:2u;break;
    default:break; /* PUBLISH and RING_ORDER are actual device/cache barriers. */
    }
    struct pms_event*e=&s->event[s->events++];e->command=c;e->before=now;e->issued=1;
    s->pending=c.sequence;*out=c;return PMS_IO;
}
static inline int pms_check_sample(struct pms_stop*s,const struct pms_sample*sample,unsigned first)
{
    struct pms_view out,in;
    if(sample->out_bytes!=PMS_ITEM_BYTES||sample->in_bytes!=PMS_ITEM_BYTES||
       !pms_parse(sample->out,0,&out)||!pms_parse(sample->in,1,&in))return pms_fail(s,PMS_ITEM);
    if(((out.flags>>1)&1)!=(in.flags&1)||((in.flags>>1)&1)!=(out.flags&1))return pms_fail(s,PMS_STALE);
    if(in.value&1)return pms_fail(s,PMS_FATAL);
    if(first){
        if((out.value&1)||(in.value&8)||!(in.value&2))return pms_fail(s,PMS_STALE);
        s->out_index=out.index;s->in_index=in.index;s->saved_out=out.value;return 1;
    }
    const struct pms_sample*initial=&s->event[0].sample;
    if(out.index!=s->out_index||in.index!=s->in_index||out.value!=(s->saved_out|1u)||
       !pms_equal(sample->out,initial->out,20)||!pms_equal(sample->in,initial->in,20))return pms_fail(s,PMS_CHANGED);
    for(unsigned k=20;k<PMS_ITEM_BYTES;k++){
        /* No other APPS byte can change under the exclusive producer scope.
         * Remote values can change; all entry names must retain their identity. */
        unsigned value_start=36+20*s->out_index;
        if((k<value_start||k>=value_start+4)&&sample->out[k]!=initial->out[k])return pms_fail(s,PMS_CHANGED);
        if((k-20)%20<16&&sample->in[k]!=initial->in[k])return pms_fail(s,PMS_CHANGED);
    }
    return (in.value&8)?2:1;
}
static inline int pms_complete(struct pms_stop*s,const struct pms_command*c,uint64_t now,
    int returned,uint32_t value,const struct pms_sample*sample)
{
    if(!s||!c||!s->started||s->unknown||s->error)return PMS_FAILED;
    if(sample&&!pms_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)sample,sizeof(*sample)))return pms_fail(s,PMS_ARGUMENT);
    if(!s->pending||s->events>PMS_EVENTS||s->pending!=s->events)return pms_fail(s,PMS_REENTRY);
    struct pms_event*e=&s->event[s->events-1];
    if(e->issued!=1||e->returned||e->command.sequence!=s->pending||e->command.step!=s->step||
       !pms_equal(c,&e->command,sizeof(*c)))return pms_fail(s,PMS_REENTRY);
    e->after=now;e->return_raw=returned;e->returned=returned==1?1:0;e->value=value;
    unsigned sampling=s->step==PMS_INITIAL||s->step==PMS_POLL;
    if(sampling){if(!sample)return pms_fail(s,PMS_ARGUMENT);e->sample=*sample;s->samples++;}
    else if(sample)return pms_fail(s,PMS_ARGUMENT);
    if(returned!=1)return pms_fail(s,PMS_ACCESS);
    if(pms_time(s,now)<0)return PMS_FAILED;
    if(sampling){
        int accepted=pms_check_sample(s,&e->sample,s->step==PMS_INITIAL);
        if(accepted<0)return PMS_FAILED;
        if(s->step==PMS_INITIAL)s->step=PMS_SET_STOP;
        else if(accepted==2){s->ack_held=1;s->step=PMS_DONE;}
        else{
            if(now>UINT64_MAX-PMS_POLL_TICKS)return pms_fail(s,PMS_TIME);
            s->next_poll=now+PMS_POLL_TICKS;
        }
    }else{
        if(s->step==PMS_SET_STOP)s->write_returned=1;
        if(s->step==PMS_READBACK&&value!=(s->saved_out|1u))return pms_fail(s,PMS_READBACK_ERROR);
        if(s->step==PMS_RING_SET)s->ring_returned|=1;
        if(s->step==PMS_RING_CLEAR)s->ring_returned|=2;
        s->step++;
    }
    s->pending=0;return s->ack_held?PMS_ACK_HELD:PMS_WAIT;
}
#endif
