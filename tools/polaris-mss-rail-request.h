/* One finite HLOS/DRV2 resource request, for a separately owned MSS lifetime.
 * Unlike the diagnostic roundtrip this returns with the resource vote held.
 * Only CMD0 is used and all TCS RW registers are restored after its fresh
 * completion. Resource restoration is a later, distinct request after stop.
 *
 * This engine creates NO exclusive owner. The native parent must continuously
 * exclude original RPMh writers, bind current CmdDb addresses/levels, qualify
 * every MMIO delivery and preserve its own epoch across all requests and MSS
 * operation. A new request's 50ms bound does not renew that owner's lifetime.
 * No provider call, IRQ enable/type change, automatic unwind or boot flag.
 */
#ifndef POLARIS_MSS_RAIL_REQUEST_H
#define POLARIS_MSS_RAIL_REQUEST_H
#include "polaris-wifi-rsc-read.h"
#define PMRV_RESOURCES 19u
struct pmrv_request {
    struct pwrsc_transaction io;
    uint64_t epoch;
    uint32_t resource,write,value,response,valid;
};
static inline uint32_t pmrv_address(unsigned resource)
{
    const uint32_t address[PMRV_RESOURCES]={0x30000,0x30010,0x30060,
        0x40f00,0x40f04,0x40f08,0x40f0c,0x41300,0x41304,0x41308,0x4130c,
        0x40c00,0x40c04,0x40c08,0x40c0c,0x42000,0x42004,0x42008,0x4200c};
    return resource<PMRV_RESOURCES?address[resource]:0;
}
static inline int pmrv_input(unsigned resource,unsigned write,uint32_t value)
{
    if(resource>=PMRV_RESOURCES||write>1)return 0;
    if(!write)return value==0;
    if(resource<3)return value<=15;
    unsigned field=(resource-3)%4;
    /* Mode/headroom are observation-only. No arbitrary PMIC write path. */
    return field==0?value<=8191:field==1?value<=1:0;
}
static inline int pmrv_writable(const struct pmrv_request*q,uint64_t at,uint32_t value)
{
    const struct pwrsc_transaction*r=&q->io;
    if(!q->epoch||!pmrv_input(q->resource,q->write,q->value)||r->tcs>=8||
       !(r->active_mask&(1u<<r->tcs)))return 0;
    uint64_t t=pwrsc_tcs(r);uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(at==PWRSC_BASE+8)return r->phase==2&&r->completed==1&&value==(1u<<r->tcs);
    if(at==t+0x14)return (r->phase==1&&(value==arm||value==(arm|PWRSC_TRIGGER)))||
        (r->phase==2&&r->completed==1&&!(r->saved.control&PWRSC_TRIGGER)&&value==r->saved.control);
    if(at==t+0x1c)return (r->phase==1&&value==1)||
        (r->phase==2&&r->completed==1&&value==0)||(r->phase==3&&value==r->saved.enable);
    if(at==t+0x10)return (r->phase==1&&value==(r->saved.wait|1))||(r->phase==3&&value==r->saved.wait);
    for(unsigned j=0;j<3;j++)if(at==t+0x30+4*j){
        if(j==2&&!q->write)return 0;
        if(r->phase==3)return value==r->saved.command[0][j];
        return r->phase==1&&value==(j==0?(q->write?PWRSC_MESSAGE:PWRR_MESSAGE):
            j==1?pmrv_address(q->resource):q->value);
    }
    return 0;
}
static inline int pmrv_access(const struct pwrsc_io*io,struct pmrv_request*q,
    uint64_t at,uint32_t*value,unsigned write)
{
    struct pwrsc_transaction*r=&q->io;
    if(!q->epoch||!pmrv_input(q->resource,q->write,q->value)||!r->attempted||r->finished||
       r->error||r->unknown||r->outstanding||r->events>=PWRSC_HISTORY||
       (write?!pmrv_writable(q,at,*value):!pwrr_readable(at))){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    struct pwrsc_event*e=&r->history[r->events++];
    e->address=at;e->value=*value;e->operation=write?2:1;e->phase=r->phase;
    if(!pwrsc_clock(io,r,&e->before))return 0;
    if(!q->epoch||!pmrv_input(q->resource,q->write,q->value)||
       (write&&!pmrv_writable(q,at,*value))){r->unknown=1;pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    e->issued=e->unknown=1;r->outstanding=r->events;if(write)r->writes++;io->order(io->context);
    int returned=write?io->write(io->context,at,*value):io->read(io->context,at,value);
    e->value=*value;e->returned=returned==1;io->order(io->context);
    if(returned!=1){pwrsc_fail(r,write?PWRSC_WRITE:PWRSC_READ);return 0;}
    if(!pwrsc_clock(io,r,&e->after)){r->unknown=1;return 0;}
    e->unknown=0;r->outstanding=0;return 1;
}
static inline int pmrv_read(const struct pwrsc_io*io,struct pmrv_request*q,uint64_t at,uint32_t*v)
{*v=UINT32_MAX;return pmrv_access(io,q,at,v,0);}
static inline int pmrv_store(const struct pwrsc_io*io,struct pmrv_request*q,uint64_t at,uint32_t v)
{
    uint32_t actual;
    if(!pmrv_access(io,q,at,&v,1)||!pmrv_read(io,q,at,&actual))return 0;
    if(actual!=v){pwrsc_fail(&q->io,PWRSC_CHANGED);return 0;}return 1;
}
static inline int pmrv_snapshot(const struct pwrsc_io*io,struct pmrv_request*q,struct pwrsc_registers*s)
{
    uint64_t t=pwrsc_tcs(&q->io);
    if(!pmrv_read(io,q,t+0x14,&s->control)||!pmrv_read(io,q,t+0x1c,&s->enable)||
       !pmrv_read(io,q,t+0x10,&s->wait)||!pmrv_read(io,q,t+0x18,&s->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)
        if(!pmrv_read(io,q,t+0x30+20*k+4*j,&s->command[k][j]))return 0;
    return 1;
}
static inline int pmrv_begin(const struct pwrsc_io*io,struct pmrv_request*q,uint64_t epoch,
    unsigned active,unsigned tcs,unsigned resource,unsigned write,uint32_t value)
{
    if(!q)return 0;
    const unsigned char*raw=(const void*)q;
    for(unsigned n=0;n<sizeof(*q);n++)if(raw[n])return 0;
    struct pwrsc_transaction*r=&q->io;r->attempted=1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!epoch||tcs>=8||
       (active&~255u)||!(active&(1u<<tcs))||!pmrv_input(resource,write,value)){
        pwrsc_fail(r,PWRSC_ARGUMENT);return 0;
    }
    q->epoch=epoch;q->resource=resource;q->write=write;q->value=value;r->active_mask=active;r->tcs=tcs;
    if(!io->clock(io->context,&r->started,&r->frequency)||!r->started||r->frequency!=19200000){
        pwrsc_fail(r,PWRSC_TIME);return 0;
    }
    r->last=r->started;
    if(!pmrv_read(io,q,PWRSC_BASE,&r->IRQ_enable)||!pmrv_read(io,q,PWRSC_BASE+4,&r->IRQ_status)||
       !pmrv_snapshot(io,q,&r->saved))return 0;
    if(r->IRQ_status||!(r->IRQ_enable&(1u<<tcs))||!pwrr_saved_supported(&r->saved)){
        pwrsc_fail(r,PWRSC_BUSY);return 0;
    }
    r->phase=1;return 1;
}
static inline int pmrv_stage(const struct pwrsc_io*io,struct pmrv_request*q)
{
    struct pwrsc_transaction*r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,en;
    if(r->triggers||r->completed||r->acknowledged||!pmrv_snapshot(io,q,&r->observed)||
       !pmrv_read(io,q,PWRSC_BASE,&en)||!pmrv_read(io,q,PWRSC_BASE+4,&irq))return 0;
    const uint32_t*a=(const void*)&r->saved,*b=(const void*)&r->observed;
    for(unsigned n=0;n<sizeof(r->saved)/4;n++)if(a[n]!=b[n]){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    if(irq||en!=r->IRQ_enable){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(!pmrv_store(io,q,t+0x14,arm)||!pmrv_store(io,q,t+0x30,q->write?PWRSC_MESSAGE:PWRR_MESSAGE)||
       !pmrv_store(io,q,t+0x34,pmrv_address(q->resource))||
       (q->write&&!pmrv_store(io,q,t+0x38,q->value))||
       !pmrv_store(io,q,t+0x10,r->saved.wait|1)||!pmrv_store(io,q,t+0x1c,1))return 0;
    uint32_t trigger=arm|PWRSC_TRIGGER;
    if(!pmrv_access(io,q,t+0x14,&trigger,1))return 0;
    r->triggers=1;r->phase=2;return 1;
}
static inline int pmrv_poll(const struct pwrsc_io*io,struct pmrv_request*q)
{
    struct pwrsc_transaction*r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,status,response,idle,en;
    if(!pmrv_read(io,q,PWRSC_BASE,&en)||!pmrv_read(io,q,PWRSC_BASE+4,&irq))return -1;
    r->IRQ_OR|=irq;
    if(en!=r->IRQ_enable||(irq&~(1u<<r->tcs))){pwrsc_fail(r,PWRSC_CHANGED);return -1;}
    if(!irq)return 0;
    if(!pmrv_read(io,q,t+0x3c,&status)||!pmrv_read(io,q,t+0x40,&response)||!pmrv_read(io,q,t+0x18,&idle))return -1;
    r->status_OR[0]|=status;r->response_OR[0]|=response;
    if((status&~(PWRSC_DONE|1u))||(status&PWRSC_DONE)!=PWRSC_DONE){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
    if(idle!=1){pwrsc_fail(r,PWRSC_BUSY);return -1;}
    q->response=response;r->completed=1;return 1;
}
static inline int pmrv_retire(const struct pwrsc_io*io,struct pmrv_request*q)
{
    struct pwrsc_transaction*r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,control,en,ack=1u<<r->tcs;
    if(r->triggers!=1||r->completed!=1||r->acknowledged||!pmrv_store(io,q,t+0x1c,0))return 0;
    if(r->saved.control&PWRSC_TRIGGER){
        if(!pmrv_read(io,q,t+0x14,&control))return 0;
        if(control!=r->saved.control){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    }else if(!pmrv_store(io,q,t+0x14,r->saved.control))return 0;
    if(!pmrv_read(io,q,PWRSC_BASE+4,&irq))return 0;
    if(irq!=ack){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    if(!pmrv_access(io,q,PWRSC_BASE+8,&ack,1)||!pmrv_read(io,q,PWRSC_BASE+4,&irq))return 0;
    if(irq){pwrsc_fail(r,PWRSC_CHANGED);return 0;}r->acknowledged=1;r->phase=3;
    for(unsigned j=0;j<(q->write?3u:2u);j++)if(!pmrv_store(io,q,t+0x30+4*j,r->saved.command[0][j]))return 0;
    if(!pmrv_store(io,q,t+0x10,r->saved.wait)||
       (r->saved.enable&&!pmrv_store(io,q,t+0x1c,r->saved.enable))||
       !pmrv_snapshot(io,q,&r->observed)||!pmrv_read(io,q,PWRSC_BASE,&en)||!pmrv_read(io,q,PWRSC_BASE+4,&irq))return 0;
    if(irq||en!=r->IRQ_enable||r->observed.status!=1||r->observed.control!=r->saved.control||
       r->observed.wait!=r->saved.wait||r->observed.enable!=r->saved.enable){pwrsc_fail(r,PWRSC_RESTORE);return 0;}
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)if(r->observed.command[k][j]!=r->saved.command[k][j]){
        pwrsc_fail(r,PWRSC_RESTORE);return 0;
    }
    q->valid=1;r->restored=r->finished=1;r->phase=4;return 1;
}
static inline int pmrv_step(const struct pwrsc_io*io,struct pmrv_request*q)
{
    if(!q)return -1;struct pwrsc_transaction*r=&q->io;
    if(r->error||r->unknown||r->outstanding)return -1;
    if(r->finished)return q->valid==1?1:-1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!r->attempted||++r->steps>256){pwrsc_fail(r,PWRSC_ARGUMENT);return -1;}
    uint64_t now;if(!pwrsc_clock(io,r,&now))return -1;
    if(r->phase==1)return pmrv_stage(io,q)?0:-1;
    if(r->phase==2){int ready=pmrv_poll(io,q);return ready<=0?ready:pmrv_retire(io,q)?1:-1;}
    pwrsc_fail(r,PWRSC_ARGUMENT);return -1;
}
/* Structural consumer check, not source/CPU ownership. The actual native
 * owner additionally seals the input/result around every delivery. */
static inline int pmrv_retired(const struct pmrv_request*q)
{
    if(!q||!q->epoch||!pmrv_input(q->resource,q->write,q->value)||q->valid!=1)return 0;
    const struct pwrsc_transaction*r=&q->io;
    if(r->attempted!=1||r->error||r->unknown||r->outstanding||r->finished!=1||r->restored!=1||
       r->phase!=4||r->triggers!=1||r->completed!=1||r->acknowledged!=1||r->tcs>=8||
       (r->active_mask&~255u)||!(r->active_mask&(1u<<r->tcs))||!(r->IRQ_enable&(1u<<r->tcs))||
       r->IRQ_status||r->IRQ_OR!=(1u<<r->tcs)||r->frequency!=19200000||!r->started||
       r->last<r->started||r->last-r->started>PWRSC_DEADLINE||
       !r->events||r->events>PWRSC_HISTORY||!r->steps||r->steps>256||!pwrr_saved_supported(&r->saved)||
       r->observed.control!=r->saved.control||r->observed.enable!=r->saved.enable||
       r->observed.wait!=r->saved.wait||r->observed.status!=1||
       (r->status_OR[0]&~(PWRSC_DONE|1u))||(r->status_OR[0]&PWRSC_DONE)!=PWRSC_DONE||
       r->response_OR[0]!=q->response)return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)
        if(r->observed.command[k][j]!=r->saved.command[k][j])return 0;
    uint64_t last=r->started,t=pwrsc_tcs(r);unsigned writes=0,triggers=0,acks=0;
    for(unsigned n=0;n<r->events;n++){
        const struct pwrsc_event*e=&r->history[n];
        if(e->issued!=1||e->returned!=1||e->unknown||e->phase>3||e->before<last||
           e->after<e->before||e->after>r->last)return 0;
        last=e->after;
        if(e->operation==1){
            if(e->address!=PWRSC_BASE&&e->address!=PWRSC_BASE+4&&
               (e->address<t||e->address>=t+PWRSC_STRIDE))return 0;
            if(!pwrr_readable(e->address))return 0;
        }else if(e->operation==2){
            writes++;
            if(e->address==PWRSC_BASE+8){if(e->phase!=2||e->value!=(1u<<r->tcs))return 0;acks++;}
            else if(e->address==t+0x14){
                uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
                if(e->phase==1){if(e->value!=arm&&e->value!=(arm|PWRSC_TRIGGER))return 0;if(e->value&PWRSC_TRIGGER)triggers++;}
                else if(e->phase!=2||(r->saved.control&PWRSC_TRIGGER)||e->value!=r->saved.control)return 0;
            }else if(e->address==t+0x10){
                if(!((e->phase==1&&e->value==(r->saved.wait|1))||(e->phase==3&&e->value==r->saved.wait)))return 0;
            }else if(e->address==t+0x1c){
                if(!((e->phase==1&&e->value==1)||(e->phase==2&&!e->value)||(e->phase==3&&e->value==r->saved.enable)))return 0;
            }else{
                if(e->address<t+0x30||e->address>t+0x38||(e->address&3))return 0;
                unsigned j=(unsigned)(e->address-t-0x30)/4;if(j==2&&!q->write)return 0;
                uint32_t expected=e->phase==3?r->saved.command[0][j]:j==0?(q->write?PWRSC_MESSAGE:PWRR_MESSAGE):j==1?pmrv_address(q->resource):q->value;
                if((e->phase!=1&&e->phase!=3)||e->value!=expected)return 0;
            }
        }else return 0;
    }
    return writes==r->writes&&triggers==1&&acks==1;
}
#endif
