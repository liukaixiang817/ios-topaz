/* Finite single-command ARC READ engine, independent implementation.
 * Register format follows own RSC2.7 geometry and the pinned upstream READ
 * message format. A returned word is RAW, not a rail level or a grant.
 * The physical caller must establish the SAME current source/client/RAM/
 * Device/CPU interval as the write engine, and qualify ARC response semantics
 * before using a word as a saved vote. No direct MMIO or boot option here. */
#ifndef POLARIS_WIFI_RSC_READ_H
#define POLARIS_WIFI_RSC_READ_H
#include "polaris-wifi-rsc-transaction.h"
#define PWRR_MESSAGE 0x108u
struct pwrr_transaction {
    struct pwrsc_transaction io;
    uint32_t response[3],response_seen,valid,reserved;
};
/* Own HAL7704..7734 explicitly clears then raises TRIGGER; it is not an
 * automatic busy flag. A completed original ACTIVE slot may retain both
 * AMC/TRIGGER and one enabled command. Caller still needs the source-bound
 * FREE/no-request RAM state and actual idle/IRQ/CPU interval. */
static inline int pwrr_saved_supported(const struct pwrsc_registers *s)
{
    if(s->status!=1||(s->control&~(PWRSC_AMC|PWRSC_TRIGGER)))return 0;
    if(s->control&PWRSC_TRIGGER)return s->control==(PWRSC_AMC|PWRSC_TRIGGER)&&s->enable==1;
    return s->enable==0;
}
static inline int pwrr_readable(uint64_t at)
{
    if(at==PWRSC_BASE||at==PWRSC_BASE+4)return 1;
    if((at&3)||at<PWRSC_BASE||at>=PWRSC_BASE+8*PWRSC_STRIDE)return 0;
    unsigned off=(unsigned)(at-PWRSC_BASE)%PWRSC_STRIDE;
    if(off==0x10||off==0x14||off==0x18||off==0x1c)return 1;
    for(unsigned k=0;k<3;k++)if(off>=0x30+20*k&&off<=0x40+20*k)return 1;
    return 0;
}
static inline int pwrr_writable(const struct pwrr_transaction *q,uint64_t at,uint32_t v)
{
    const struct pwrsc_transaction *r=&q->io;
    if(r->tcs>=8||!(r->active_mask&(1u<<r->tcs))||r->phase<1||r->phase>7)return 0;
    uint64_t t=pwrsc_tcs(r);unsigned stage=r->phase<7&&(r->phase&1);
    unsigned complete=r->phase<7&&!(r->phase&1)&&r->completed==r->triggers;
    if(at==PWRSC_BASE+8)return complete&&v==(1u<<r->tcs);
    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(at==t+0x14)return (stage&&(v==arm||v==(arm|PWRSC_TRIGGER)))||
        (complete&&!(r->saved.control&PWRSC_TRIGGER)&&v==r->saved.control);
    if(at==t+0x1c)return (stage&&v==1)||(complete&&v==0)||(r->phase==7&&v==r->saved.enable);
    if(at==t+0x10)return (stage&&v==(r->saved.wait|1u))||(r->phase==7&&v==r->saved.wait);
    static const uint32_t addresses[3]={0x30000,0x30010,0x30060};
    if(at==t+0x30)return (stage&&v==PWRR_MESSAGE)||(r->phase==7&&v==r->saved.command[0][0]);
    if(at==t+0x34)return (stage&&r->triggers<3&&v==addresses[r->triggers])||(r->phase==7&&v==r->saved.command[0][1]);
    /* READ never programs CMD_DATA, another command, IRQ enable or type. */
    return 0;
}
static inline int pwrr_access(const struct pwrsc_io *io,struct pwrr_transaction *q,uint64_t at,uint32_t *v,unsigned write)
{
    struct pwrsc_transaction *r=&q->io;
    if(!r->attempted||r->finished||r->error||r->unknown||r->outstanding||r->events>=PWRSC_HISTORY||
       (write?!pwrr_writable(q,at,*v):!pwrr_readable(at))){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    struct pwrsc_event *e=&r->history[r->events++];e->address=at;e->operation=write?2:1;e->phase=r->phase;e->value=*v;
    if(!pwrsc_clock(io,r,&e->before))return 0;
    e->issued=e->unknown=1;r->outstanding=r->events;if(write)r->writes++;io->order(io->context);
    int returned=write?io->write(io->context,at,*v):io->read(io->context,at,v);
    e->value=*v;e->returned=returned?1:0;io->order(io->context);
    if(!returned){pwrsc_fail(r,write?PWRSC_WRITE:PWRSC_READ);return 0;}
    if(!pwrsc_clock(io,r,&e->after)){r->unknown=1;return 0;}
    e->unknown=0;r->outstanding=0;io->order(io->context);return 1;
}
static inline int pwrr_read(const struct pwrsc_io *io,struct pwrr_transaction *q,uint64_t at,uint32_t *v)
{*v=UINT32_MAX;return pwrr_access(io,q,at,v,0);}
static inline int pwrr_store(const struct pwrsc_io *io,struct pwrr_transaction *q,uint64_t at,uint32_t v)
{
    uint32_t actual;if(!pwrr_access(io,q,at,&v,1)||!pwrr_read(io,q,at,&actual))return 0;
    if(actual!=v){pwrsc_fail(&q->io,PWRSC_CHANGED);return 0;}return 1;
}
static inline int pwrr_irq(const struct pwrsc_io *io,struct pwrr_transaction *q,uint32_t *irq)
{if(!pwrr_read(io,q,PWRSC_BASE+4,irq))return 0;q->io.IRQ_OR|=*irq;return 1;}
static inline int pwrr_snapshot(const struct pwrsc_io *io,struct pwrr_transaction *q,struct pwrsc_registers *s)
{
    uint64_t t=pwrsc_tcs(&q->io);
    if(!pwrr_read(io,q,t+0x14,&s->control)||!pwrr_read(io,q,t+0x1c,&s->enable)||
       !pwrr_read(io,q,t+0x10,&s->wait)||!pwrr_read(io,q,t+0x18,&s->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)if(!pwrr_read(io,q,t+0x30+20*k+4*j,&s->command[k][j]))return 0;
    return 1;
}
static inline int pwrr_begin(const struct pwrsc_io *io,struct pwrr_transaction *q,uint32_t active)
{
    if(!q||q->io.attempted)return 0;struct pwrsc_transaction *r=&q->io;r->attempted=1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!active||(active&~255u)){
        pwrsc_fail(r,PWRSC_ARGUMENT);return 0;
    }
    r->active_mask=active;
    if(!io->clock(io->context,&r->started,&r->frequency)||r->frequency!=19200000){pwrsc_fail(r,PWRSC_TIME);return 0;}
    r->last=r->started;
    if(!pwrr_read(io,q,PWRSC_BASE,&r->IRQ_enable)||!pwrr_irq(io,q,&r->IRQ_status))return 0;
    if(r->IRQ_status){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    unsigned found=0;
    for(unsigned k=0;k<8;k++)if((active&r->IRQ_enable)&(1u<<k)){
        r->tcs=k;if(!pwrr_snapshot(io,q,&r->observed))return 0;
        if(pwrr_saved_supported(&r->observed)){
            r->saved=r->observed;found=1;break;
        }
    }
    if(!found){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    if(r->last==r->started){pwrsc_fail(r,PWRSC_TIME);return 0;}
    r->phase=1;return 1;
}
static inline int pwrr_stage(const struct pwrsc_io *io,struct pwrr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,control,enabled,status,irq_enabled,wait,msg,addr,data;
    if(r->triggers>=3||r->triggers!=r->completed||r->triggers!=r->acknowledged){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwrr_irq(io,q,&irq)||!pwrr_read(io,q,t+0x14,&control)||!pwrr_read(io,q,t+0x1c,&enabled)||
       !pwrr_read(io,q,t+0x18,&status)||!pwrr_read(io,q,PWRSC_BASE,&irq_enabled)||
       !pwrr_read(io,q,t+0x10,&wait)||!pwrr_read(io,q,t+0x30,&msg)||
       !pwrr_read(io,q,t+0x34,&addr)||!pwrr_read(io,q,t+0x38,&data))return 0;
    static const uint32_t addresses[3]={0x30000,0x30010,0x30060};
    if(irq||control!=r->saved.control||enabled!=(r->triggers?0:r->saved.enable)||!(status&1)||irq_enabled!=r->IRQ_enable||
       wait!=(r->triggers?(r->saved.wait|1u):r->saved.wait)||data!=r->saved.command[0][2]||
       msg!=(r->triggers?PWRR_MESSAGE:r->saved.command[0][0])||
       addr!=(r->triggers?addresses[r->triggers-1]:r->saved.command[0][1])){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    /* Deassert before changing any command. The only subsequent rising edge
     * is the explicitly counted NEW READ launch; no restore writes a1. */
    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(!pwrr_store(io,q,t+0x14,arm)||!pwrr_store(io,q,t+0x30,PWRR_MESSAGE)||!pwrr_store(io,q,t+0x34,addresses[r->triggers])||
       !pwrr_store(io,q,t+0x10,r->saved.wait|1u)||!pwrr_store(io,q,t+0x1c,1))return 0;
    uint32_t trigger=arm|PWRSC_TRIGGER;
    if(!pwrr_access(io,q,t+0x14,&trigger,1))return 0;
    r->triggers++;r->phase++;return 1;
}
static inline int pwrr_poll(const struct pwrsc_io *io,struct pwrr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,status,response,idle;
    if(!pwrr_irq(io,q,&irq))return -1;
    if(irq&~(1u<<r->tcs)){pwrsc_fail(r,PWRSC_CHANGED);return -1;}if(!irq)return 0;
    if(!pwrr_read(io,q,t+0x3c,&status))return -1;
    unsigned k=r->triggers-1;r->status_OR[k]|=status;
    if(status!=PWRSC_DONE){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
    if(!pwrr_read(io,q,t+0x40,&response)||!pwrr_read(io,q,t+0x18,&idle))return -1;
    r->response_OR[k]|=response;
    if((q->response_seen&(1u<<k))&&q->response[k]!=response){pwrsc_fail(r,PWRSC_CHANGED);return -1;}
    q->response[k]=response;q->response_seen|=1u<<k;
    if(idle&~1u){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
    if(!idle)return 0;r->completed++;return 1;
}
static inline int pwrr_ack(const struct pwrsc_io *io,struct pwrr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,control,value=1u<<r->tcs;
    if(r->completed!=r->triggers||r->acknowledged+1!=r->completed){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwrr_store(io,q,t+0x1c,0))return 0;
    if(r->saved.control&PWRSC_TRIGGER){
        /* Leave the completed NEW launch latch high. Writing the saved high
         * trigger is forbidden outside a NEW launch; no fourth rising edge. */
        if(!pwrr_read(io,q,t+0x14,&control))return 0;
        if(control!=r->saved.control){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    }else if(!pwrr_store(io,q,t+0x14,r->saved.control))return 0;
    if(!pwrr_irq(io,q,&irq))return 0;
    if(irq!=value){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    if(!pwrr_access(io,q,PWRSC_BASE+8,&value,1)||!pwrr_irq(io,q,&irq))return 0;
    if(irq){pwrsc_fail(r,PWRSC_CHANGED);return 0;}r->acknowledged++;return 1;
}
static inline int pwrr_restore(const struct pwrsc_io *io,struct pwrr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,enabled;
    if(r->triggers!=3||r->completed!=3||r->acknowledged!=3){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwrr_store(io,q,t+0x30,r->saved.command[0][0])||!pwrr_store(io,q,t+0x34,r->saved.command[0][1])||
       !pwrr_store(io,q,t+0x10,r->saved.wait)||
       (r->saved.enable&&!pwrr_store(io,q,t+0x1c,r->saved.enable))||!pwrr_snapshot(io,q,&r->observed)||
       !pwrr_read(io,q,PWRSC_BASE,&enabled)||!pwrr_irq(io,q,&irq))return 0;
    if(enabled!=r->IRQ_enable||irq||r->observed.control!=r->saved.control||r->observed.enable!=r->saved.enable||
       r->observed.wait!=r->saved.wait||!(r->observed.status&1)){pwrsc_fail(r,PWRSC_RESTORE);return 0;}
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)if(r->observed.command[k][j]!=r->saved.command[k][j]){
        pwrsc_fail(r,PWRSC_RESTORE);return 0;
    }
    q->valid=7;r->restored=r->finished=1;r->phase=8;io->order(io->context);return 1;
}
static inline int pwrr_step(const struct pwrsc_io *io,struct pwrr_transaction *q)
{
    if(!q)return -1;struct pwrsc_transaction *r=&q->io;
    if(r->error||r->unknown||r->outstanding)return -1;if(r->finished)return 1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!r->attempted){pwrsc_fail(r,PWRSC_ARGUMENT);return -1;}
    if(++r->steps>256){pwrsc_fail(r,PWRSC_TIME);return -1;}uint64_t ticks;if(!pwrsc_clock(io,r,&ticks))return -1;
    if(r->phase==1||r->phase==3||r->phase==5){if(!pwrr_stage(io,q))return -1;return 0;}
    if(r->phase==2||r->phase==4||r->phase==6){
        int done=pwrr_poll(io,q);if(done<0)return -1;if(!done)return 0;
        if(!pwrr_ack(io,q))return -1;r->phase++;if(r->phase==7)return pwrr_restore(io,q)?1:-1;return 0;
    }
    pwrsc_fail(r,PWRSC_ARGUMENT);return -1;
}
/* Independent full-prefix retirement. Summary counters or a callback return
 * cannot publish responses or authorize restoring the CPU interrupt state. */
static inline int pwrr_retired(const struct pwrr_transaction *q)
{
    if(!q)return 0;const struct pwrsc_transaction *r=&q->io;
    if(r->attempted!=1||r->error||r->unknown||r->outstanding||r->finished!=1||r->restored!=1||r->phase!=8||
       r->tcs>=8||!(r->active_mask&(1u<<r->tcs))||(r->active_mask&~255u)||r->frequency!=19200000||
       r->last<r->started||r->last-r->started>PWRSC_DEADLINE||!r->events||r->events>PWRSC_HISTORY||
       !r->steps||r->steps>256||r->triggers!=3||r->completed!=3||r->acknowledged!=3||
       q->valid!=7||q->response_seen!=7||q->reserved||!pwrr_saved_supported(&r->saved)||
       !(r->IRQ_enable&(1u<<r->tcs)))return 0;
    for(unsigned k=0;k<3;k++)if(r->address[k]||r->saved_vote[k]||r->raised_vote[k]||
       r->status_OR[k]!=PWRSC_DONE||r->response_OR[k]!=q->response[k])return 0;
    uint64_t t=pwrsc_tcs(r),last=r->started;
    uint32_t phase=0,writes=0,triggers=0,acks=0,pending=0,irq_seen=0,done=0,response=0,idle=0,arm_written=0,armed=0;
    uint32_t enable=UINT32_MAX,control=UINT32_MAX,wait=UINT32_MAX,last_irq=UINT32_MAX,irq_enable=UINT32_MAX;
    uint32_t values[3][3]={{0}},initial=0,final=0,seen=0,final_global=0,IRQ_OR=0;
    static const uint32_t addresses[3]={0x30000,0x30010,0x30060};
    for(unsigned n=0;n<r->events;n++){
        const struct pwrsc_event *e=&r->history[n];
        if(final_global==3)return 0;
        if(e->issued!=1||e->returned!=1||e->unknown||(e->operation!=1&&e->operation!=2)||
           e->before<last||e->after<e->before||e->after>r->last||e->phase<phase||e->phase>7)return 0;
        if(!phase&&e->phase&&initial!=524287u)return 0;
        phase=e->phase;last=e->after;
        unsigned stage=phase<7&&(phase&1),complete=phase<7&&!(phase&1)&&phase;
        if(e->operation==2){
            writes++;if(!phase)return 0;
            if(e->address==PWRSC_BASE+8){
                if(!complete||e->value!=(1u<<r->tcs)||!pending||!irq_seen||!done||!response||!idle||
                   enable||control!=r->saved.control||(seen&3)!=3||last_irq!=(1u<<r->tcs))return 0;
                acks++;pending=irq_seen=done=response=idle=arm_written=armed=0;if(acks!=triggers||acks>3)return 0;continue;
            }
            if(e->address==t+0x14){
                seen&=~1u;
                if(stage){
                    if(phase!=1+2*acks||pending||acks!=triggers)return 0;
                    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
                    if(e->value!=arm&&e->value!=(arm|PWRSC_TRIGGER))return 0;
                    if(e->value&PWRSC_TRIGGER){
                        if(!armed||arm_written!=1||last_irq||enable!=1||control!=arm||wait!=(r->saved.wait|1u)||(seen&14)!=14||
                           values[0][0]!=PWRR_MESSAGE||values[0][1]!=addresses[acks]||
                           (seen&(3u<<4))!=(3u<<4))return 0;
                        triggers++;pending=1;armed=0;
                    }else{if(arm_written||armed)return 0;arm_written=1;}
                }else if(!complete||(r->saved.control&PWRSC_TRIGGER)||!pending||!irq_seen||!done||!response||!idle||enable||
                         e->value!=r->saved.control)return 0;
                continue;
            }
            if(e->address==t+0x1c){
                seen&=~2u;if(stage){if(!armed||e->value!=1||pending||phase!=1+2*acks)return 0;}
                else if(phase==7){if(pending||acks!=3||e->value!=r->saved.enable)return 0;}
                else if(!complete||e->value||!pending||!irq_seen||!done||!response||!idle)return 0;continue;
            }
            if(e->address==t+0x10){
                seen&=~4u;
                if((stage&&armed&&e->value==(r->saved.wait|1u))||(phase==7&&acks==3&&e->value==r->saved.wait))continue;
                return 0;
            }
            if(e->address==t+0x30||e->address==t+0x34){
                unsigned k=e->address==t+0x30?0:1;seen&=~(1u<<(4+k));
                if((!stage&&phase!=7)||(stage&&!armed)||pending||acks>2+(phase==7))return 0;
                uint32_t want=phase==7?r->saved.command[0][k]:(k?addresses[acks]:PWRR_MESSAGE);
                if(e->value!=want)return 0;continue;
            }
            return 0; /* Includes every CMD_DATA and IRQ-enable/type write. */
        }
        if(!pwrr_readable(e->address))return 0;
        if(e->address==PWRSC_BASE){
            if(e->value!=r->IRQ_enable)return 0;irq_enable=e->value;
            if(phase==7){if(final!=524287u)return 0;final_global|=1;}continue;
        }
        if(e->address==PWRSC_BASE+4){
            IRQ_OR|=e->value;
            last_irq=e->value;if(e->value&~(1u<<r->tcs))return 0;
            if(phase==7){if(final_global!=1||e->value)return 0;final_global|=2;}
            if(e->value){if(!pending||!complete)return 0;irq_seen=1;}continue;
        }
        if(!phase&&e->address<t)continue;
        if(e->address<t||e->address>=t+PWRSC_STRIDE)return 0;
        unsigned bit=UINT32_MAX;
        if(e->address==t+0x14){
            control=e->value;seen|=1;bit=0;
            if(stage&&!pending&&arm_written&&control==((r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC))armed=1;
        }
        if(e->address==t+0x1c){enable=e->value;seen|=2;bit=1;}
        if(e->address==t+0x10){wait=e->value;seen|=4;bit=2;}
        if(e->address==t+0x18){
            if(e->value&~1u)return 0;
            if(e->value&1)seen|=8;else seen&=~8u;
            bit=3;if(pending&&complete&&irq_seen&&done&&response)idle=(e->value&1)!=0;
        }
        for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)if(e->address==t+0x30+20*k+4*j){
            if(j<3){values[k][j]=e->value;if(k==0)seen|=1u<<(4+j);}bit=4+5*k+j;
        }
        if(e->address==t+0x3c&&pending&&complete&&irq_seen){if(e->value!=PWRSC_DONE)return 0;done=1;}
        if(e->address==t+0x40&&pending&&complete&&irq_seen&&done){
            if(acks>=3||e->value!=q->response[acks])return 0;response=1;
        }
        if(bit!=UINT32_MAX){
            if(!phase){
                uint32_t want=bit==0?r->saved.control:(bit==1?r->saved.enable:(bit==2?r->saved.wait:
                    (bit==3?r->saved.status:r->saved.command[(bit-4)/5][(bit-4)%5])));
                if(e->value!=want)return 0;initial|=1u<<bit;
            }
            if(phase==7){
                uint32_t want=bit==0?r->saved.control:(bit==1?r->saved.enable:(bit==2?r->saved.wait:
                    (bit==3?e->value:((bit-4)%5<3?r->saved.command[(bit-4)/5][(bit-4)%5]:e->value))));
                uint32_t actual=bit==0?r->observed.control:(bit==1?r->observed.enable:(bit==2?r->observed.wait:
                    (bit==3?r->observed.status:r->observed.command[(bit-4)/5][(bit-4)%5])));
                if(e->value!=want||e->value!=actual||(bit==3&&!(e->value&1)))return 0;final|=1u<<bit;
            }
        }
    }
    return phase==7&&initial==524287u&&final==524287u&&final_global==3&&last==r->last&&writes==r->writes&&triggers==3&&acks==3&&
        !pending&&!last_irq&&!r->IRQ_status&&IRQ_OR==r->IRQ_OR&&irq_enable==r->IRQ_enable&&
        enable==r->saved.enable&&control==r->saved.control&&wait==r->saved.wait;
}
#endif
