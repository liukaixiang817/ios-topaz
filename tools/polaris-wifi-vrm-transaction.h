/* Independent finite four-supply VRM transaction. Default OFF and currently
 * not wired to a physical caller. Inputs need fresh same-session CmdDb and
 * returned HLOS/DRV2 READ evidence; this component grants no hardware scope.
 * A future physical parent MUST bind every input to returned current READs,
 * and enforce one combined READ+WRITE 50ms/256-step/1024-event interval inside
 * the original 200ms owner/source/CPU lifetime. This writer's local clock is
 * an additional bound, never a lease renewal or a replacement for that gate.
 * ICNSS load/delay are zero for the saved own DT: preserve mode/headroom,
 * program voltage before enable, and restore exact saved enable/voltage in
 * reverse rail order. No fixed HPM, blanket disable, IRQ type/enable or reset.
 */
#ifndef POLARIS_WIFI_VRM_TRANSACTION_H
#define POLARIS_WIFI_VRM_TRANSACTION_H
#ifndef EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
#define EFI_XNU_WIFI_FOUR_VRM_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
#include "polaris-wifi-rsc-read.h"
struct pwvm_rail {uint32_t address,saved_mV,saved_enable,saved_mode,requested_mV;};
struct pwvm_transaction {struct pwrsc_transaction io;struct pwvm_rail rail[4];};
static const uint32_t pwvm_addresses[4]={0x40f00,0x41300,0x40c00,0x42000};
static const uint32_t pwvm_min_mV[4]={800,1800,1304,3104};
static const uint32_t pwvm_max_mV[4]={800,1800,1304,3312};
static inline int pwvm_unused(const struct pwvm_transaction *q)
{const unsigned char *p=(const void*)q;for(unsigned k=0;k<sizeof(*q);k++)if(p[k])return 0;return 1;}
static inline int pwvm_inputs(const struct pwvm_rail rail[4])
{
    if(!rail)return 0;
    for(unsigned k=0;k<4;k++){
        const struct pwvm_rail *s=&rail[k];
        if(s->address!=pwvm_addresses[k]||s->saved_mV>8191||s->saved_enable>1||
           (s->saved_mode!=0&&s->saved_mode!=4&&s->saved_mode!=5&&s->saved_mode!=7)||
           s->requested_mV!=pwvm_min_mV[k]||
           s->saved_mV>pwvm_max_mV[k])return 0;
    }return 1;
}
/* No mode/headroom command exists. The caller must retain their READ values
 * and independently check them during its full retirement. A missing READ
 * cannot be represented by synthesizing a zero input. */
static inline void pwvm_command(const struct pwvm_transaction *q,unsigned edge,unsigned command,
    uint32_t *address,uint32_t *value)
{
    unsigned restore=edge>=4,rail=restore?7-edge:edge;
    const struct pwvm_rail *s=&q->rail[rail];
    if(restore){*address=s->address+(command?0:4);*value=command?s->saved_mV:s->saved_enable;}
    else{*address=s->address+(command?4:0);*value=command?1:
        (s->saved_mV>s->requested_mV?s->saved_mV:s->requested_mV);}
}
static inline int pwvm_writable(const struct pwvm_transaction *q,uint64_t at,uint32_t value)
{
    if(!q||!pwvm_inputs(q->rail))return 0;
    const struct pwrsc_transaction *r=&q->io;
    if(r->tcs>=8||!(r->active_mask&(1u<<r->tcs))||!r->phase||r->phase>17)return 0;
    uint64_t t=pwrsc_tcs(r);unsigned stage=r->phase<17&&(r->phase&1),complete=r->phase<17&&!(r->phase&1);
    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(at==PWRSC_BASE+8)return complete&&value==(1u<<r->tcs);
    if(at==t+0x14)return (stage&&(value==arm||value==(arm|PWRSC_TRIGGER)))||
        (complete&&!(r->saved.control&PWRSC_TRIGGER)&&value==r->saved.control);
    if(at==t+0x1c)return (stage&&value==3)||(complete&&value==0)||(r->phase==17&&value==r->saved.enable);
    if(at==t+0x10)return (stage&&value==(r->saved.wait|3u))||(r->phase==17&&value==r->saved.wait);
    for(unsigned k=0;k<2;k++)for(unsigned j=0;j<3;j++)if(at==t+0x30+20*k+4*j){
        if(r->phase==17)return value==r->saved.command[k][j];
        if(!stage||r->triggers>=8)return 0;uint32_t address,data;
        pwvm_command(q,r->triggers,k,&address,&data);
        return value==(j==0?PWRSC_MESSAGE:j==1?address:data);
    }
    return 0;
}
static inline int pwvm_access(const struct pwrsc_io *io,struct pwvm_transaction *q,uint64_t at,uint32_t *value,unsigned write)
{
    struct pwrsc_transaction *r=&q->io;
    if(!pwvm_inputs(q->rail)){r->unknown=1;pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!r->attempted||r->finished||r->error||r->unknown||r->outstanding||r->events>=PWRSC_HISTORY||
       (write?!pwvm_writable(q,at,*value):!pwrr_readable(at))){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    struct pwrsc_event *e=&r->history[r->events++];e->address=at;e->operation=write?2:1;e->phase=r->phase;e->value=*value;
    if(!pwrsc_clock(io,r,&e->before))return 0;
    if(!pwvm_inputs(q->rail)||(write&&!pwvm_writable(q,at,*value))){r->unknown=1;pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    e->issued=e->unknown=1;r->outstanding=r->events;if(write)r->writes++;io->order(io->context);
    int returned=write?io->write(io->context,at,*value):io->read(io->context,at,value);
    e->value=*value;e->returned=returned?1:0;io->order(io->context);
    if(!returned){pwrsc_fail(r,write?PWRSC_WRITE:PWRSC_READ);return 0;}
    if(!pwrsc_clock(io,r,&e->after)){r->unknown=1;return 0;}
    e->unknown=0;r->outstanding=0;io->order(io->context);return 1;
}
static inline int pwvm_read(const struct pwrsc_io *io,struct pwvm_transaction *q,uint64_t at,uint32_t *value)
{*value=UINT32_MAX;return pwvm_access(io,q,at,value,0);}
static inline int pwvm_store(const struct pwrsc_io *io,struct pwvm_transaction *q,uint64_t at,uint32_t value)
{uint32_t got;if(!pwvm_access(io,q,at,&value,1)||!pwvm_read(io,q,at,&got))return 0;if(got!=value){pwrsc_fail(&q->io,PWRSC_CHANGED);return 0;}return 1;}
static inline int pwvm_irq(const struct pwrsc_io *io,struct pwvm_transaction *q,uint32_t *irq)
{if(!pwvm_read(io,q,PWRSC_BASE+4,irq))return 0;q->io.IRQ_OR|=*irq;return 1;}
static inline int pwvm_snapshot(const struct pwrsc_io *io,struct pwvm_transaction *q,struct pwrsc_registers *s)
{
    uint64_t t=pwrsc_tcs(&q->io);
    if(!pwvm_read(io,q,t+0x14,&s->control)||!pwvm_read(io,q,t+0x1c,&s->enable)||
       !pwvm_read(io,q,t+0x10,&s->wait)||!pwvm_read(io,q,t+0x18,&s->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)if(!pwvm_read(io,q,t+0x30+20*k+4*j,&s->command[k][j]))return 0;
    return 1;
}
static inline int pwvm_begin(const struct pwrsc_io *io,struct pwvm_transaction *q,uint32_t active,const struct pwvm_rail rail[4])
{
    if(!q||q->io.attempted)return 0;struct pwrsc_transaction *r=&q->io;
    if(!pwvm_unused(q)){r->attempted=1;pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}r->attempted=1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!active||(active&~255u)||!pwvm_inputs(rail)){
        pwrsc_fail(r,PWRSC_ARGUMENT);return 0;
    }
    for(unsigned k=0;k<4;k++)q->rail[k]=rail[k];r->active_mask=active;
    if(!io->clock(io->context,&r->started,&r->frequency)||r->frequency!=19200000){pwrsc_fail(r,PWRSC_TIME);return 0;}r->last=r->started;
    if(!pwvm_read(io,q,PWRSC_BASE,&r->IRQ_enable)||!pwvm_irq(io,q,&r->IRQ_status))return 0;
    if(r->IRQ_status){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    unsigned found=0;
    for(unsigned k=0;k<8;k++)if((active&r->IRQ_enable)&(1u<<k)){
        r->tcs=k;if(!pwvm_snapshot(io,q,&r->observed))return 0;
        if(pwrr_saved_supported(&r->observed)){r->saved=r->observed;found=1;break;}
    }
    if(!found){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    if(r->last==r->started){pwrsc_fail(r,PWRSC_TIME);return 0;}r->phase=1;return 1;
}
static inline int pwvm_stage(const struct pwrsc_io *io,struct pwvm_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,control,enabled,status,irq_enabled;
    if(r->triggers>=8||r->triggers!=r->completed||r->triggers!=r->acknowledged){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwvm_irq(io,q,&irq)||!pwvm_read(io,q,t+0x14,&control)||!pwvm_read(io,q,t+0x1c,&enabled)||
       !pwvm_read(io,q,t+0x18,&status)||!pwvm_read(io,q,PWRSC_BASE,&irq_enabled))return 0;
    if(irq||control!=r->saved.control||enabled!=(r->triggers?0:r->saved.enable)||status!=1||irq_enabled!=r->IRQ_enable){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(!pwvm_store(io,q,t+0x14,arm))return 0;
    for(unsigned k=0;k<2;k++){
        uint32_t address,data;pwvm_command(q,r->triggers,k,&address,&data);
        if(!pwvm_store(io,q,t+0x30+20*k,PWRSC_MESSAGE)||!pwvm_store(io,q,t+0x34+20*k,address)||
           !pwvm_store(io,q,t+0x38+20*k,data))return 0;
    }
    if(!pwvm_store(io,q,t+0x10,r->saved.wait|3u)||!pwvm_store(io,q,t+0x1c,3))return 0;
    uint32_t trigger=arm|PWRSC_TRIGGER;if(!pwvm_access(io,q,t+0x14,&trigger,1))return 0;
    r->triggers++;r->phase++;return 1;
}
static inline int pwvm_poll(const struct pwrsc_io *io,struct pwvm_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,idle;
    if(!pwvm_irq(io,q,&irq))return -1;if(irq&~(1u<<r->tcs)){pwrsc_fail(r,PWRSC_CHANGED);return -1;}if(!irq)return 0;
    for(unsigned k=0;k<2;k++){
        uint32_t status,response;if(!pwvm_read(io,q,t+0x3c+20*k,&status))return -1;r->status_OR[k]|=status;
        if((status&~0x10101u)||(status&PWRSC_DONE)!=PWRSC_DONE){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
        if(!pwvm_read(io,q,t+0x40+20*k,&response))return -1;r->response_OR[k]|=response;
    }
    if(!pwvm_read(io,q,t+0x18,&idle))return -1;if(idle&~1u){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
    if(!idle)return 0;r->completed++;return 1;
}
static inline int pwvm_ack(const struct pwrsc_io *io,struct pwvm_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,control,value=1u<<r->tcs;
    if(r->completed!=r->triggers||r->acknowledged+1!=r->completed){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwvm_store(io,q,t+0x1c,0))return 0;
    if(r->saved.control&PWRSC_TRIGGER){if(!pwvm_read(io,q,t+0x14,&control))return 0;if(control!=r->saved.control){pwrsc_fail(r,PWRSC_CHANGED);return 0;}}
    else if(!pwvm_store(io,q,t+0x14,r->saved.control))return 0;
    if(!pwvm_irq(io,q,&irq))return 0;if(irq!=value){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    if(!pwvm_access(io,q,PWRSC_BASE+8,&value,1)||!pwvm_irq(io,q,&irq))return 0;
    if(irq){pwrsc_fail(r,PWRSC_CHANGED);return 0;}r->acknowledged++;return 1;
}
static inline int pwvm_restore(const struct pwrsc_io *io,struct pwvm_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,enabled;
    if(r->triggers!=8||r->completed!=8||r->acknowledged!=8){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    for(unsigned k=0;k<2;k++)for(unsigned j=0;j<3;j++)if(!pwvm_store(io,q,t+0x30+20*k+4*j,r->saved.command[k][j]))return 0;
    if(!pwvm_store(io,q,t+0x10,r->saved.wait)||(r->saved.enable&&!pwvm_store(io,q,t+0x1c,r->saved.enable))||
       !pwvm_snapshot(io,q,&r->observed)||!pwvm_read(io,q,PWRSC_BASE,&enabled)||!pwvm_irq(io,q,&irq))return 0;
    if(enabled!=r->IRQ_enable||irq||r->observed.control!=r->saved.control||r->observed.enable!=r->saved.enable||
       r->observed.wait!=r->saved.wait||r->observed.status!=1){pwrsc_fail(r,PWRSC_RESTORE);return 0;}
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)if(r->observed.command[k][j]!=r->saved.command[k][j]){pwrsc_fail(r,PWRSC_RESTORE);return 0;}
    r->restored=r->finished=1;r->phase=18;io->order(io->context);return 1;
}
static inline int pwvm_step(const struct pwrsc_io *io,struct pwvm_transaction *q)
{
    if(!q)return -1;struct pwrsc_transaction *r=&q->io;
    if(r->error||r->unknown||r->outstanding)return -1;if(r->finished)return 1;
    if(!pwvm_inputs(q->rail)){r->unknown=1;pwrsc_fail(r,PWRSC_ARGUMENT);return -1;}
    if(!io||!io->clock||!io->read||!io->write||!io->order||!r->attempted){pwrsc_fail(r,PWRSC_ARGUMENT);return -1;}
    if(++r->steps>256){pwrsc_fail(r,PWRSC_TIME);return -1;}uint64_t ticks;if(!pwrsc_clock(io,r,&ticks))return -1;
    if(r->phase<17&&(r->phase&1)){if(!pwvm_stage(io,q))return -1;return 0;}
    if(r->phase&&r->phase<17){int done=pwvm_poll(io,q);if(done<0)return -1;if(!done)return 0;
        if(!pwvm_ack(io,q))return -1;r->phase++;if(r->phase==17)return pwvm_restore(io,q)?1:-1;return 0;}
    pwrsc_fail(r,PWRSC_ARGUMENT);return -1;
}
/* Read-only replay of the complete delivered prefix. It never calls an I/O
 * function or interprets an address in the record as a host/firmware pointer. */
struct pwvm_replay {const struct pwvm_transaction *q;unsigned at,writes,steps;uint64_t last;uint32_t irq_OR,status_OR[2],response_OR[2];};
static inline int pwvm_r_get(struct pwvm_replay *s,unsigned phase,unsigned operation,uint64_t address,uint32_t *value)
{
    const struct pwrsc_transaction *r=&s->q->io;if(s->at>=r->events)return 0;
    const struct pwrsc_event *e=&r->history[s->at++];
    if(e->phase!=phase||e->operation!=operation||e->address!=address||e->issued!=1||e->returned!=1||e->unknown||
       e->before<s->last||e->after<e->before||e->after>r->last)return 0;
    s->last=e->after;if(operation==2)s->writes++;else if(address==PWRSC_BASE+4)s->irq_OR|=e->value;
    *value=e->value;return 1;
}
static inline int pwvm_r_word(struct pwvm_replay *s,unsigned phase,unsigned operation,uint64_t address,uint32_t expected)
{uint32_t value;return pwvm_r_get(s,phase,operation,address,&value)&&value==expected;}
static inline int pwvm_r_store(struct pwvm_replay *s,unsigned phase,uint64_t address,uint32_t value)
{return pwvm_r_word(s,phase,2,address,value)&&pwvm_r_word(s,phase,1,address,value);}
static inline int pwvm_r_snapshot(struct pwvm_replay *s,unsigned phase,unsigned slot,struct pwrsc_registers *out)
{
    uint64_t t=PWRSC_BASE+PWRSC_STRIDE*slot;
    if(!pwvm_r_get(s,phase,1,t+0x14,&out->control)||!pwvm_r_get(s,phase,1,t+0x1c,&out->enable)||
       !pwvm_r_get(s,phase,1,t+0x10,&out->wait)||!pwvm_r_get(s,phase,1,t+0x18,&out->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)if(!pwvm_r_get(s,phase,1,t+0x30+20*k+4*j,&out->command[k][j]))return 0;
    return 1;
}
static inline int pwvm_regs_equal(const struct pwrsc_registers *a,const struct pwrsc_registers *b,unsigned RW_only)
{
    if(a->control!=b->control||a->enable!=b->enable||a->wait!=b->wait||(!RW_only&&a->status!=b->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<(RW_only?3u:5u);j++)if(a->command[k][j]!=b->command[k][j])return 0;
    return 1;
}
static inline int pwvm_retired(const struct pwvm_transaction *q)
{
    if(!q||!pwvm_inputs(q->rail))return 0;const struct pwrsc_transaction *r=&q->io;
    if(r->attempted!=1||r->error||r->unknown||r->outstanding||r->phase!=18||r->finished!=1||r->restored!=1||
       r->triggers!=8||r->completed!=8||r->acknowledged!=8||r->frequency!=19200000||r->last<r->started||
       r->last-r->started>PWRSC_DEADLINE||!r->events||r->events>PWRSC_HISTORY||!r->steps||r->steps>256||
       !r->active_mask||(r->active_mask&~255u)||r->tcs>=8||!(r->active_mask&r->IRQ_enable&(1u<<r->tcs))||
       r->IRQ_status||!pwrr_saved_supported(&r->saved)||!pwvm_regs_equal(&r->saved,&r->observed,1)||r->observed.status!=1||
       r->status_OR[2]||r->response_OR[2])return 0;
    for(unsigned k=0;k<3;k++)if(r->address[k]||r->saved_vote[k]||r->raised_vote[k])return 0;
    struct pwvm_replay s={.q=q,.last=r->started};
    if(!pwvm_r_word(&s,0,1,PWRSC_BASE,r->IRQ_enable)||!pwvm_r_word(&s,0,1,PWRSC_BASE+4,0))return 0;
    unsigned found=0;
    for(unsigned k=0;k<8;k++)if((r->active_mask&r->IRQ_enable)&(1u<<k)){
        struct pwrsc_registers got;if(!pwvm_r_snapshot(&s,0,k,&got))return 0;
        if(pwrr_saved_supported(&got)){if(k!=r->tcs||!pwvm_regs_equal(&got,&r->saved,0))return 0;found=1;break;}
    }
    if(!found)return 0;uint64_t t=pwrsc_tcs(r);uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    for(unsigned edge=0;edge<8;edge++){
        unsigned stage=1+2*edge,pending=stage+1;s.steps++;
        if(!pwvm_r_word(&s,stage,1,PWRSC_BASE+4,0)||!pwvm_r_word(&s,stage,1,t+0x14,r->saved.control)||
           !pwvm_r_word(&s,stage,1,t+0x1c,edge?0:r->saved.enable)||!pwvm_r_word(&s,stage,1,t+0x18,1)||
           !pwvm_r_word(&s,stage,1,PWRSC_BASE,r->IRQ_enable)||!pwvm_r_store(&s,stage,t+0x14,arm))return 0;
        for(unsigned k=0;k<2;k++){
            uint32_t address,data;pwvm_command(q,edge,k,&address,&data);
            if(!pwvm_r_store(&s,stage,t+0x30+20*k,PWRSC_MESSAGE)||!pwvm_r_store(&s,stage,t+0x34+20*k,address)||
               !pwvm_r_store(&s,stage,t+0x38+20*k,data))return 0;
        }
        if(!pwvm_r_store(&s,stage,t+0x10,r->saved.wait|3u)||!pwvm_r_store(&s,stage,t+0x1c,3)||
           !pwvm_r_word(&s,stage,2,t+0x14,arm|PWRSC_TRIGGER))return 0;
        unsigned done=0;
        for(unsigned attempts=0;attempts<256&&!done;attempts++){
            uint32_t irq,idle;s.steps++;
            if(!pwvm_r_get(&s,pending,1,PWRSC_BASE+4,&irq))return 0;if(!irq)continue;if(irq!=(1u<<r->tcs))return 0;
            for(unsigned k=0;k<2;k++){
                uint32_t status,response;
                if(!pwvm_r_get(&s,pending,1,t+0x3c+20*k,&status)||
                   (status&~0x10101u)||(status&PWRSC_DONE)!=PWRSC_DONE||
                   !pwvm_r_get(&s,pending,1,t+0x40+20*k,&response))return 0;
                s.status_OR[k]|=status;s.response_OR[k]|=response;
            }
            if(!pwvm_r_get(&s,pending,1,t+0x18,&idle)||idle>1)return 0;done=idle;
        }
        if(!done||!pwvm_r_store(&s,pending,t+0x1c,0))return 0;
        if(r->saved.control&PWRSC_TRIGGER){if(!pwvm_r_word(&s,pending,1,t+0x14,r->saved.control))return 0;}
        else if(!pwvm_r_store(&s,pending,t+0x14,r->saved.control))return 0;
        if(!pwvm_r_word(&s,pending,1,PWRSC_BASE+4,1u<<r->tcs)||!pwvm_r_word(&s,pending,2,PWRSC_BASE+8,1u<<r->tcs)||
           !pwvm_r_word(&s,pending,1,PWRSC_BASE+4,0))return 0;
    }
    for(unsigned k=0;k<2;k++)for(unsigned j=0;j<3;j++)if(!pwvm_r_store(&s,17,t+0x30+20*k+4*j,r->saved.command[k][j]))return 0;
    if(!pwvm_r_store(&s,17,t+0x10,r->saved.wait)||(r->saved.enable&&!pwvm_r_store(&s,17,t+0x1c,r->saved.enable)))return 0;
    struct pwrsc_registers observed;
    if(!pwvm_r_snapshot(&s,17,r->tcs,&observed)||!pwvm_regs_equal(&observed,&r->observed,0)||
       !pwvm_r_word(&s,17,1,PWRSC_BASE,r->IRQ_enable)||!pwvm_r_word(&s,17,1,PWRSC_BASE+4,0))return 0;
    return s.at==r->events&&s.last==r->last&&s.steps==r->steps&&s.writes==r->writes&&s.irq_OR==r->IRQ_OR&&
        s.status_OR[0]==r->status_OR[0]&&s.status_OR[1]==r->status_OR[1]&&
        s.response_OR[0]==r->response_OR[0]&&s.response_OR[1]==r->response_OR[1];
}
#endif
#endif
