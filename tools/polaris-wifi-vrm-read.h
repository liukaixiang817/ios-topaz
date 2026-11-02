/* Finite sixteen-field own VRM READ engine, default OFF.
 * Register format follows own RSC2.7 geometry and the pinned upstream READ
 * message format. A returned word is RAW, not a supply setting or a grant.
 * The physical caller must establish the SAME current source/client/RAM/
 * Device/CPU interval as the write engine, and qualify VRM response semantics
 * before using a word as a saved vote. No direct MMIO or boot option here. */
#ifndef POLARIS_WIFI_VRM_READ_H
#define POLARIS_WIFI_VRM_READ_H
#ifndef EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
#define EFI_XNU_WIFI_FOUR_VRM_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
#include "polaris-wifi-rsc-read.h"
static const uint32_t pwvr_addresses[16]={0x40f00,0x40f04,0x40f08,0x40f0c,
    0x41300,0x41304,0x41308,0x4130c,0x40c00,0x40c04,0x40c08,0x40c0c,0x42000,0x42004,0x42008,0x4200c};
#define PWVR_MESSAGE 0x108u
#if EFI_XNU_WIFI_CURRENT_WORD_READ
/* Own Polaris mailbox source tests ISSUED/COMPL independently. Qualcomm's
 * CMD_STATUS description additionally names bit0 TRIGGERED. Preserve the
 * entire delivered word: bit0 may accompany completion, every other bit
 * outside ISSUED/COMPL remains unknown. This changes no write engine. */
#define PWVR_STATUS_TRIGGERED UINT32_C(1)
static inline int pwvr_pending_status_known(uint32_t value)
{return !(value&~(PWRSC_DONE|PWVR_STATUS_TRIGGERED));}
static inline int pwvr_pending_status_done(uint32_t value)
{return pwvr_pending_status_known(value)&&(value&PWRSC_DONE)==PWRSC_DONE;}
#endif
struct pwvr_transaction {
    struct pwrsc_transaction io;
    uint32_t response[16],response_seen,valid,reserved;
    uint32_t status_OR[16],response_OR[16];
};
/* Own HAL7704..7734 explicitly clears then raises TRIGGER; it is not an
 * automatic busy flag. A completed original ACTIVE slot may retain both
 * AMC/TRIGGER and one enabled command. Caller still needs the source-bound
 * FREE/no-request RAM state and actual idle/IRQ/CPU interval. */
static inline int pwvr_saved_supported(const struct pwrsc_registers *s)
{
    if(s->status!=1||(s->control&~(PWRSC_AMC|PWRSC_TRIGGER)))return 0;
    if(s->control&PWRSC_TRIGGER)return s->control==(PWRSC_AMC|PWRSC_TRIGGER)&&s->enable==1;
    return s->enable==0;
}
static inline int pwvr_readable(uint64_t at)
{
    if(at==PWRSC_BASE||at==PWRSC_BASE+4)return 1;
    if((at&3)||at<PWRSC_BASE||at>=PWRSC_BASE+8*PWRSC_STRIDE)return 0;
    unsigned off=(unsigned)(at-PWRSC_BASE)%PWRSC_STRIDE;
    if(off==0x10||off==0x14||off==0x18||off==0x1c)return 1;
    for(unsigned k=0;k<3;k++)if(off>=0x30+20*k&&off<=0x40+20*k)return 1;
    return 0;
}
static inline int pwvr_writable(const struct pwvr_transaction *q,uint64_t at,uint32_t v)
{
    const struct pwrsc_transaction *r=&q->io;
    if(r->tcs>=8||!(r->active_mask&(1u<<r->tcs))||r->phase<1||r->phase>33)return 0;
    uint64_t t=pwrsc_tcs(r);unsigned stage=r->phase<33&&(r->phase&1);
    unsigned complete=r->phase<33&&!(r->phase&1)&&r->completed==r->triggers;
    if(at==PWRSC_BASE+8)return complete&&v==(1u<<r->tcs);
    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(at==t+0x14)return (stage&&(v==arm||v==(arm|PWRSC_TRIGGER)))||
        (complete&&!(r->saved.control&PWRSC_TRIGGER)&&v==r->saved.control);
    if(at==t+0x1c)return (stage&&v==1)||(complete&&v==0)||(r->phase==33&&v==r->saved.enable);
    if(at==t+0x10)return (stage&&v==(r->saved.wait|1u))||(r->phase==33&&v==r->saved.wait);
    const uint32_t *addresses=pwvr_addresses;
    if(at==t+0x30)return (stage&&v==PWVR_MESSAGE)||(r->phase==33&&v==r->saved.command[0][0]);
    if(at==t+0x34)return (stage&&r->triggers<16&&v==addresses[r->triggers])||(r->phase==33&&v==r->saved.command[0][1]);
    /* READ never programs CMD_DATA, another command, IRQ enable or type. */
    return 0;
}
static inline int pwvr_access(const struct pwrsc_io *io,struct pwvr_transaction *q,uint64_t at,uint32_t *v,unsigned write)
{
    struct pwrsc_transaction *r=&q->io;
    if(!r->attempted||r->finished||r->error||r->unknown||r->outstanding||r->events>=PWRSC_HISTORY||
       (write?!pwvr_writable(q,at,*v):!pwvr_readable(at))){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    struct pwrsc_event *e=&r->history[r->events++];e->address=at;e->operation=write?2:1;e->phase=r->phase;e->value=*v;
    if(!pwrsc_clock(io,r,&e->before))return 0;
    e->issued=e->unknown=1;r->outstanding=r->events;if(write)r->writes++;io->order(io->context);
    int returned=write?io->write(io->context,at,*v):io->read(io->context,at,v);
    e->value=*v;e->returned=returned?1:0;io->order(io->context);
    if(!returned){pwrsc_fail(r,write?PWRSC_WRITE:PWRSC_READ);return 0;}
    if(!pwrsc_clock(io,r,&e->after)){r->unknown=1;return 0;}
    e->unknown=0;r->outstanding=0;io->order(io->context);return 1;
}
static inline int pwvr_read(const struct pwrsc_io *io,struct pwvr_transaction *q,uint64_t at,uint32_t *v)
{*v=UINT32_MAX;return pwvr_access(io,q,at,v,0);}
static inline int pwvr_store(const struct pwrsc_io *io,struct pwvr_transaction *q,uint64_t at,uint32_t v)
{
    uint32_t actual;if(!pwvr_access(io,q,at,&v,1)||!pwvr_read(io,q,at,&actual))return 0;
    if(actual!=v){pwrsc_fail(&q->io,PWRSC_CHANGED);return 0;}return 1;
}
static inline int pwvr_irq(const struct pwrsc_io *io,struct pwvr_transaction *q,uint32_t *irq)
{if(!pwvr_read(io,q,PWRSC_BASE+4,irq))return 0;q->io.IRQ_OR|=*irq;return 1;}
static inline int pwvr_snapshot(const struct pwrsc_io *io,struct pwvr_transaction *q,struct pwrsc_registers *s)
{
    uint64_t t=pwrsc_tcs(&q->io);
    if(!pwvr_read(io,q,t+0x14,&s->control)||!pwvr_read(io,q,t+0x1c,&s->enable)||
       !pwvr_read(io,q,t+0x10,&s->wait)||!pwvr_read(io,q,t+0x18,&s->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)if(!pwvr_read(io,q,t+0x30+20*k+4*j,&s->command[k][j]))return 0;
    return 1;
}
static inline int pwvr_begin(const struct pwrsc_io *io,struct pwvr_transaction *q,uint32_t active)
{
    if(!q||q->io.attempted)return 0;struct pwrsc_transaction *r=&q->io;
    const unsigned char *unused=(const void*)q;for(unsigned j=0;j<sizeof(*q);j++)if(unused[j]){r->attempted=1;pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}r->attempted=1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!active||(active&~255u)){
        pwrsc_fail(r,PWRSC_ARGUMENT);return 0;
    }
    r->active_mask=active;
    if(!io->clock(io->context,&r->started,&r->frequency)||r->frequency!=19200000){pwrsc_fail(r,PWRSC_TIME);return 0;}
    r->last=r->started;
    if(!pwvr_read(io,q,PWRSC_BASE,&r->IRQ_enable)||!pwvr_irq(io,q,&r->IRQ_status))return 0;
    if(r->IRQ_status){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    unsigned found=0;
    for(unsigned k=0;k<8;k++)if((active&r->IRQ_enable)&(1u<<k)){
        r->tcs=k;if(!pwvr_snapshot(io,q,&r->observed))return 0;
        if(pwvr_saved_supported(&r->observed)){
            r->saved=r->observed;found=1;break;
        }
    }
    if(!found){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    if(r->last==r->started){pwrsc_fail(r,PWRSC_TIME);return 0;}
    r->phase=1;return 1;
}
static inline int pwvr_stage(const struct pwrsc_io *io,struct pwvr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,control,enabled,status,irq_enabled,wait,msg,addr,data;
    if(r->triggers>=16||r->triggers!=r->completed||r->triggers!=r->acknowledged){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwvr_irq(io,q,&irq)||!pwvr_read(io,q,t+0x14,&control)||!pwvr_read(io,q,t+0x1c,&enabled)||
       !pwvr_read(io,q,t+0x18,&status)||!pwvr_read(io,q,PWRSC_BASE,&irq_enabled)||
       !pwvr_read(io,q,t+0x10,&wait)||!pwvr_read(io,q,t+0x30,&msg)||
       !pwvr_read(io,q,t+0x34,&addr)||!pwvr_read(io,q,t+0x38,&data))return 0;
    const uint32_t *addresses=pwvr_addresses;
    if(irq||control!=r->saved.control||enabled!=(r->triggers?0:r->saved.enable)||!(status&1)||irq_enabled!=r->IRQ_enable||
       wait!=(r->triggers?(r->saved.wait|1u):r->saved.wait)||data!=r->saved.command[0][2]||
       msg!=(r->triggers?PWVR_MESSAGE:r->saved.command[0][0])||
       addr!=(r->triggers?addresses[r->triggers-1]:r->saved.command[0][1])){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    /* Deassert before changing any command. The only subsequent rising edge
     * is the explicitly counted NEW READ launch; no restore writes a1. */
    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    if(!pwvr_store(io,q,t+0x14,arm)||!pwvr_store(io,q,t+0x30,PWVR_MESSAGE)||!pwvr_store(io,q,t+0x34,addresses[r->triggers])||
       !pwvr_store(io,q,t+0x10,r->saved.wait|1u)||!pwvr_store(io,q,t+0x1c,1))return 0;
    uint32_t trigger=arm|PWRSC_TRIGGER;
    if(!pwvr_access(io,q,t+0x14,&trigger,1))return 0;
    r->triggers++;r->phase++;return 1;
}
static inline int pwvr_poll(const struct pwrsc_io *io,struct pwvr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,status,response,idle;
    if(!pwvr_irq(io,q,&irq))return -1;
    if(irq&~(1u<<r->tcs)){pwrsc_fail(r,PWRSC_CHANGED);return -1;}if(!irq)return 0;
    if(!pwvr_read(io,q,t+0x3c,&status))return -1;
    unsigned k=r->triggers-1;q->status_OR[k]|=status;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    if(!pwvr_pending_status_done(status)){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
#else
    if(status!=PWRSC_DONE){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
#endif
    if(!pwvr_read(io,q,t+0x40,&response)||!pwvr_read(io,q,t+0x18,&idle))return -1;
    q->response_OR[k]|=response;
    if((q->response_seen&(1u<<k))&&q->response[k]!=response){pwrsc_fail(r,PWRSC_CHANGED);return -1;}
    q->response[k]=response;q->response_seen|=1u<<k;
    if(idle&~1u){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
    if(!idle)return 0;r->completed++;return 1;
}
static inline int pwvr_ack(const struct pwrsc_io *io,struct pwvr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,control,value=1u<<r->tcs;
    if(r->completed!=r->triggers||r->acknowledged+1!=r->completed){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwvr_store(io,q,t+0x1c,0))return 0;
    if(r->saved.control&PWRSC_TRIGGER){
        /* Leave the completed NEW launch latch high. Writing the saved high
         * trigger is forbidden outside a NEW launch; no seventeenth rising edge. */
        if(!pwvr_read(io,q,t+0x14,&control))return 0;
        if(control!=r->saved.control){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    }else if(!pwvr_store(io,q,t+0x14,r->saved.control))return 0;
    if(!pwvr_irq(io,q,&irq))return 0;
    if(irq!=value){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    if(!pwvr_access(io,q,PWRSC_BASE+8,&value,1)||!pwvr_irq(io,q,&irq))return 0;
    if(irq){pwrsc_fail(r,PWRSC_CHANGED);return 0;}r->acknowledged++;return 1;
}
static inline int pwvr_restore(const struct pwrsc_io *io,struct pwvr_transaction *q)
{
    struct pwrsc_transaction *r=&q->io;uint64_t t=pwrsc_tcs(r);uint32_t irq,enabled;
    if(r->triggers!=16||r->completed!=16||r->acknowledged!=16){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!pwvr_store(io,q,t+0x30,r->saved.command[0][0])||!pwvr_store(io,q,t+0x34,r->saved.command[0][1])||
       !pwvr_store(io,q,t+0x10,r->saved.wait)||
       (r->saved.enable&&!pwvr_store(io,q,t+0x1c,r->saved.enable))||!pwvr_snapshot(io,q,&r->observed)||
       !pwvr_read(io,q,PWRSC_BASE,&enabled)||!pwvr_irq(io,q,&irq))return 0;
    if(enabled!=r->IRQ_enable||irq||r->observed.control!=r->saved.control||r->observed.enable!=r->saved.enable||
       r->observed.wait!=r->saved.wait||!(r->observed.status&1)){pwrsc_fail(r,PWRSC_RESTORE);return 0;}
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)if(r->observed.command[k][j]!=r->saved.command[k][j]){
        pwrsc_fail(r,PWRSC_RESTORE);return 0;
    }
    q->valid=65535;r->restored=r->finished=1;r->phase=34;io->order(io->context);return 1;
}
static inline int pwvr_step(const struct pwrsc_io *io,struct pwvr_transaction *q)
{
    if(!q)return -1;struct pwrsc_transaction *r=&q->io;
    if(r->error||r->unknown||r->outstanding)return -1;if(r->finished)return 1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!r->attempted){pwrsc_fail(r,PWRSC_ARGUMENT);return -1;}
    if(++r->steps>256){pwrsc_fail(r,PWRSC_TIME);return -1;}uint64_t ticks;if(!pwrsc_clock(io,r,&ticks))return -1;
    if(r->phase<33&&(r->phase&1)){if(!pwvr_stage(io,q))return -1;return 0;}
    if(r->phase&&r->phase<33&&!(r->phase&1)){
        int done=pwvr_poll(io,q);if(done<0)return -1;if(!done)return 0;
        if(!pwvr_ack(io,q))return -1;r->phase++;if(r->phase==33)return pwvr_restore(io,q)?1:-1;return 0;
    }
    pwrsc_fail(r,PWRSC_ARGUMENT);return -1;
}
/* Independent full-prefix retirement. Summary counters or a callback return
 * cannot publish responses or authorize restoring the CPU interrupt state. */
static inline int pwvr_semantic_retired(const struct pwvr_transaction *q)
{
    if(!q)return 0;const struct pwrsc_transaction *r=&q->io;
    if(r->attempted!=1||r->error||r->unknown||r->outstanding||r->finished!=1||r->restored!=1||r->phase!=34||
       r->tcs>=8||!(r->active_mask&(1u<<r->tcs))||(r->active_mask&~255u)||r->frequency!=19200000||
       r->last<r->started||r->last-r->started>PWRSC_DEADLINE||!r->events||r->events>PWRSC_HISTORY||
       !r->steps||r->steps>256||r->triggers!=16||r->completed!=16||r->acknowledged!=16||
       q->valid!=65535||q->response_seen!=65535||q->reserved||!pwvr_saved_supported(&r->saved)||
       !(r->IRQ_enable&(1u<<r->tcs)))return 0;
    for(unsigned k=0;k<3;k++)if(r->address[k]||r->saved_vote[k]||r->raised_vote[k]||r->status_OR[k]||r->response_OR[k])return 0;
    for(unsigned k=0;k<16;k++)if(
#if EFI_XNU_WIFI_CURRENT_WORD_READ
       !pwvr_pending_status_done(q->status_OR[k])||
#else
       q->status_OR[k]!=PWRSC_DONE||
#endif
       q->response_OR[k]!=q->response[k])return 0;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    uint32_t pending_status_OR[16]={0};
#endif
    uint64_t t=pwrsc_tcs(r),last=r->started;
    uint32_t phase=0,writes=0,triggers=0,acks=0,pending=0,irq_seen=0,done=0,response=0,idle=0,arm_written=0,armed=0;
    uint32_t enable=UINT32_MAX,control=UINT32_MAX,wait=UINT32_MAX,last_irq=UINT32_MAX,irq_enable=UINT32_MAX;
    uint32_t values[3][3]={{0}},initial=0,final=0,seen=0,final_global=0,IRQ_OR=0;
    const uint32_t *addresses=pwvr_addresses;
    for(unsigned n=0;n<r->events;n++){
        const struct pwrsc_event *e=&r->history[n];
        if(final_global==3)return 0;
        if(e->issued!=1||e->returned!=1||e->unknown||(e->operation!=1&&e->operation!=2)||
           e->before<last||e->after<e->before||e->after>r->last||e->phase<phase||e->phase>33)return 0;
        if(!phase&&e->phase&&initial!=524287u)return 0;
        phase=e->phase;last=e->after;
        unsigned stage=phase<33&&(phase&1),complete=phase<33&&!(phase&1)&&phase;
        if(e->operation==2){
            writes++;if(!phase)return 0;
            if(e->address==PWRSC_BASE+8){
                if(!complete||e->value!=(1u<<r->tcs)||!pending||!irq_seen||!done||!response||!idle||
                   enable||control!=r->saved.control||(seen&3)!=3||last_irq!=(1u<<r->tcs))return 0;
                acks++;pending=irq_seen=done=response=idle=arm_written=armed=0;if(acks!=triggers||acks>16)return 0;continue;
            }
            if(e->address==t+0x14){
                seen&=~1u;
                if(stage){
                    if(phase!=1+2*acks||pending||acks!=triggers)return 0;
                    uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
                    if(e->value!=arm&&e->value!=(arm|PWRSC_TRIGGER))return 0;
                    if(e->value&PWRSC_TRIGGER){
                        if(!armed||arm_written!=1||last_irq||enable!=1||control!=arm||wait!=(r->saved.wait|1u)||(seen&14)!=14||
                           values[0][0]!=PWVR_MESSAGE||values[0][1]!=addresses[acks]||
                           (seen&(3u<<4))!=(3u<<4))return 0;
                        triggers++;pending=1;armed=0;
                    }else{if(arm_written||armed)return 0;arm_written=1;}
                }else if(!complete||(r->saved.control&PWRSC_TRIGGER)||!pending||!irq_seen||!done||!response||!idle||enable||
                         e->value!=r->saved.control)return 0;
                continue;
            }
            if(e->address==t+0x1c){
                seen&=~2u;if(stage){if(!armed||e->value!=1||pending||phase!=1+2*acks)return 0;}
                else if(phase==33){if(pending||acks!=16||e->value!=r->saved.enable)return 0;}
                else if(!complete||e->value||!pending||!irq_seen||!done||!response||!idle)return 0;continue;
            }
            if(e->address==t+0x10){
                seen&=~4u;
                if((stage&&armed&&e->value==(r->saved.wait|1u))||(phase==33&&acks==16&&e->value==r->saved.wait))continue;
                return 0;
            }
            if(e->address==t+0x30||e->address==t+0x34){
                unsigned k=e->address==t+0x30?0:1;seen&=~(1u<<(4+k));
                if((!stage&&phase!=33)||(stage&&!armed)||pending||acks>15+(phase==33))return 0;
                uint32_t want=phase==33?r->saved.command[0][k]:(k?addresses[acks]:PWVR_MESSAGE);
                if(e->value!=want)return 0;continue;
            }
            return 0; /* Includes every CMD_DATA and IRQ-enable/type write. */
        }
        if(!pwvr_readable(e->address))return 0;
        if(e->address==PWRSC_BASE){
            if(e->value!=r->IRQ_enable)return 0;irq_enable=e->value;
            if(phase==33){if(final!=524287u)return 0;final_global|=1;}continue;
        }
        if(e->address==PWRSC_BASE+4){
            IRQ_OR|=e->value;
            last_irq=e->value;if(e->value&~(1u<<r->tcs))return 0;
            if(phase==33){if(final_global!=1||e->value)return 0;final_global|=2;}
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
        if(e->address==t+0x3c&&pending&&complete&&irq_seen){
#if EFI_XNU_WIFI_CURRENT_WORD_READ
            if(acks>=16||!pwvr_pending_status_done(e->value))return 0;
            pending_status_OR[acks]|=e->value;
#else
            if(e->value!=PWRSC_DONE)return 0;
#endif
            done=1;
        }
        if(e->address==t+0x40&&pending&&complete&&irq_seen&&done){
            if(acks>=16||e->value!=q->response[acks])return 0;response=1;
        }
        if(bit!=UINT32_MAX){
            if(!phase){
                uint32_t want=bit==0?r->saved.control:(bit==1?r->saved.enable:(bit==2?r->saved.wait:
                    (bit==3?r->saved.status:r->saved.command[(bit-4)/5][(bit-4)%5])));
                if(e->value!=want)return 0;initial|=1u<<bit;
            }
            if(phase==33){
                uint32_t want=bit==0?r->saved.control:(bit==1?r->saved.enable:(bit==2?r->saved.wait:
                    (bit==3?e->value:((bit-4)%5<3?r->saved.command[(bit-4)/5][(bit-4)%5]:e->value))));
                uint32_t actual=bit==0?r->observed.control:(bit==1?r->observed.enable:(bit==2?r->observed.wait:
                    (bit==3?r->observed.status:r->observed.command[(bit-4)/5][(bit-4)%5])));
                if(e->value!=want||e->value!=actual||(bit==3&&!(e->value&1)))return 0;final|=1u<<bit;
            }
        }
    }
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    for(unsigned k=0;k<16;k++)if(pending_status_OR[k]!=q->status_OR[k])return 0;
#endif
    return phase==33&&initial==524287u&&final==524287u&&final_global==3&&last==r->last&&writes==r->writes&&triggers==16&&acks==16&&
        !pending&&!last_irq&&!r->IRQ_status&&IRQ_OR==r->IRQ_OR&&irq_enable==r->IRQ_enable&&
        enable==r->saved.enable&&control==r->saved.control&&wait==r->saved.wait;
}
struct pwvr_replay {const struct pwrsc_transaction *record;unsigned at,writes,steps;uint64_t last;uint32_t irq_OR;};
static inline int pwvr_r_get(struct pwvr_replay *s,unsigned phase,unsigned operation,uint64_t address,uint32_t *value)
{
    const struct pwrsc_transaction *r=s->record;if(s->at>=r->events)return 0;
    const struct pwrsc_event *e=&r->history[s->at++];
    if(e->phase!=phase||e->operation!=operation||e->address!=address||e->issued!=1||e->returned!=1||e->unknown||
       e->before<s->last||e->after<e->before||e->after>r->last)return 0;
    s->last=e->after;if(operation==2)s->writes++;else if(address==PWRSC_BASE+4)s->irq_OR|=e->value;
    *value=e->value;return 1;
}
static inline int pwvr_r_word(struct pwvr_replay *s,unsigned phase,unsigned operation,uint64_t address,uint32_t expected)
{uint32_t value;return pwvr_r_get(s,phase,operation,address,&value)&&value==expected;}
static inline int pwvr_r_store(struct pwvr_replay *s,unsigned phase,uint64_t address,uint32_t value)
{return pwvr_r_word(s,phase,2,address,value)&&pwvr_r_word(s,phase,1,address,value);}
static inline int pwvr_r_snapshot(struct pwvr_replay *s,unsigned phase,unsigned slot,struct pwrsc_registers *out)
{
    uint64_t t=PWRSC_BASE+PWRSC_STRIDE*slot;
    if(!pwvr_r_get(s,phase,1,t+0x14,&out->control)||!pwvr_r_get(s,phase,1,t+0x1c,&out->enable)||
       !pwvr_r_get(s,phase,1,t+0x10,&out->wait)||!pwvr_r_get(s,phase,1,t+0x18,&out->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)if(!pwvr_r_get(s,phase,1,t+0x30+20*k+4*j,&out->command[k][j]))return 0;
    return 1;
}
static inline int pwvr_regs_equal(const struct pwrsc_registers *a,const struct pwrsc_registers *b,unsigned RW_only)
{
    if(a->control!=b->control||a->enable!=b->enable||a->wait!=b->wait||(!RW_only&&a->status!=b->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<(RW_only?3u:5u);j++)if(a->command[k][j]!=b->command[k][j])return 0;
    return 1;
}

static inline int pwvr_retired(const struct pwvr_transaction *q)
{
    if(!pwvr_semantic_retired(q))return 0;const struct pwrsc_transaction*r=&q->io;
    struct pwvr_replay s={.record=r,.last=r->started};
    if(!pwvr_r_word(&s,0,1,PWRSC_BASE,r->IRQ_enable)||!pwvr_r_word(&s,0,1,PWRSC_BASE+4,0))return 0;
    unsigned found=0;
    for(unsigned k=0;k<8;k++)if(r->active_mask&r->IRQ_enable&(1u<<k)){
        struct pwrsc_registers got;if(!pwvr_r_snapshot(&s,0,k,&got))return 0;
        if(pwvr_saved_supported(&got)){if(k!=r->tcs||!pwvr_regs_equal(&got,&r->saved,0))return 0;found=1;break;}
    }
    if(!found)return 0;uint64_t t=pwrsc_tcs(r);uint32_t arm=(r->saved.control&~PWRSC_TRIGGER)|PWRSC_AMC;
    for(unsigned edge=0;edge<16;edge++){
        unsigned stage=1+2*edge,pending=stage+1;s.steps++;
        if(!pwvr_r_word(&s,stage,1,PWRSC_BASE+4,0)||!pwvr_r_word(&s,stage,1,t+0x14,r->saved.control)||
           !pwvr_r_word(&s,stage,1,t+0x1c,edge?0:r->saved.enable)||!pwvr_r_word(&s,stage,1,t+0x18,1)||
           !pwvr_r_word(&s,stage,1,PWRSC_BASE,r->IRQ_enable)||!pwvr_r_word(&s,stage,1,t+0x10,edge?r->saved.wait|1u:r->saved.wait)||
           !pwvr_r_word(&s,stage,1,t+0x30,edge?PWVR_MESSAGE:r->saved.command[0][0])||
           !pwvr_r_word(&s,stage,1,t+0x34,edge?pwvr_addresses[edge-1]:r->saved.command[0][1])||
           !pwvr_r_word(&s,stage,1,t+0x38,r->saved.command[0][2])||!pwvr_r_store(&s,stage,t+0x14,arm)||
           !pwvr_r_store(&s,stage,t+0x30,PWVR_MESSAGE)||!pwvr_r_store(&s,stage,t+0x34,pwvr_addresses[edge])||
           !pwvr_r_store(&s,stage,t+0x10,r->saved.wait|1u)||!pwvr_r_store(&s,stage,t+0x1c,1)||
           !pwvr_r_word(&s,stage,2,t+0x14,arm|PWRSC_TRIGGER))return 0;
        unsigned done=0;uint32_t status_OR=0,response_OR=0;
        for(unsigned attempts=0;attempts<256&&!done;attempts++){
            uint32_t irq,status,response,idle;s.steps++;
            if(!pwvr_r_get(&s,pending,1,PWRSC_BASE+4,&irq))return 0;if(!irq)continue;
            if(irq!=(1u<<r->tcs)||!pwvr_r_get(&s,pending,1,t+0x3c,&status)||!pwvr_pending_status_done(status)||
               !pwvr_r_get(&s,pending,1,t+0x40,&response)||response!=q->response[edge]||
               !pwvr_r_get(&s,pending,1,t+0x18,&idle)||idle>1)return 0;
            status_OR|=status;response_OR|=response;done=idle;
        }
        if(!done||status_OR!=q->status_OR[edge]||response_OR!=q->response_OR[edge]||!pwvr_r_store(&s,pending,t+0x1c,0))return 0;
        if(r->saved.control&PWRSC_TRIGGER){if(!pwvr_r_word(&s,pending,1,t+0x14,r->saved.control))return 0;}
        else if(!pwvr_r_store(&s,pending,t+0x14,r->saved.control))return 0;
        if(!pwvr_r_word(&s,pending,1,PWRSC_BASE+4,1u<<r->tcs)||!pwvr_r_word(&s,pending,2,PWRSC_BASE+8,1u<<r->tcs)||
           !pwvr_r_word(&s,pending,1,PWRSC_BASE+4,0))return 0;
    }
    if(!pwvr_r_store(&s,33,t+0x30,r->saved.command[0][0])||!pwvr_r_store(&s,33,t+0x34,r->saved.command[0][1])||
       !pwvr_r_store(&s,33,t+0x10,r->saved.wait)||(r->saved.enable&&!pwvr_r_store(&s,33,t+0x1c,r->saved.enable)))return 0;
    struct pwrsc_registers got;
    if(!pwvr_r_snapshot(&s,33,r->tcs,&got)||!pwvr_regs_equal(&got,&r->observed,0)||
       !pwvr_r_word(&s,33,1,PWRSC_BASE,r->IRQ_enable)||!pwvr_r_word(&s,33,1,PWRSC_BASE+4,0))return 0;
    return s.at==r->events&&s.last==r->last&&s.steps==r->steps&&s.writes==r->writes&&s.irq_OR==r->IRQ_OR;
}
#endif
#endif
