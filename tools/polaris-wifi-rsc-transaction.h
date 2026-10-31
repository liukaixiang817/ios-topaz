/* Polaris ARC transaction core. Register facts checked against own DT,
 * pinned vendor-qcom-rpmh-mailbox.c and original RpmhDxe; independent code.
 *
 * This implements staging -> fresh completion -> acknowledgement -> saved
 * votes -> fresh completion -> RW-register restoration. No firmware churn,
 * IRQ enable/type change, reset, retry or timeout cleanup. It does NOT grant
 * a hardware lease: its caller must first establish source-bound provider
 * quiescence, current CmdDb/cache baselines and exclusive CPU0/DRV2 access.
 * There is no physical caller/boot flag or direct MMIO adapter in this file.
 * Software read/write callbacks test delivery; they cannot certify ownership.
 */
#ifndef POLARIS_WIFI_RSC_TRANSACTION_H
#define POLARIS_WIFI_RSC_TRANSACTION_H
#include <stdint.h>
#define PWRSC_BASE UINT64_C(0x179e0d00)
#define PWRSC_STRIDE 672u
#define PWRSC_CMDS 3u
#define PWRSC_HISTORY 1024u
#define PWRSC_DEADLINE UINT64_C(960000) /* 50ms at the admitted 19.2MHz */
#define PWRSC_TRIGGER (1u<<24)
#define PWRSC_AMC (1u<<16)
#define PWRSC_MESSAGE 0x10108u
#define PWRSC_DONE 0x10100u
enum pwrsc_error {PWRSC_OK,PWRSC_ARGUMENT,PWRSC_TIME,PWRSC_READ,PWRSC_WRITE,
    PWRSC_HISTORY_FULL,PWRSC_BUSY,PWRSC_CHANGED,PWRSC_COMPLETION,PWRSC_RESTORE};
struct pwrsc_io {
    void *context;
    int (*read)(void *,uint64_t,uint32_t *);
    int (*write)(void *,uint64_t,uint32_t);
    int (*clock)(void *,uint64_t *,uint64_t *);
    void (*order)(void *);
};
struct pwrsc_event {
    uint64_t address,before,after;
    uint32_t value,operation,phase,issued,returned,unknown;
};
struct pwrsc_registers {uint32_t control,enable,wait,status,command[3][5];};
struct pwrsc_transaction {
    uint32_t attempted,error,unknown,outstanding,phase,finished,restored;
    uint32_t tcs,active_mask,events,writes,triggers,completed,acknowledged,steps;
    uint32_t IRQ_enable,IRQ_status,IRQ_OR,status_OR[3],response_OR[3];
    uint32_t saved_vote[3],raised_vote[3],address[3];
    uint64_t started,last,frequency;
    struct pwrsc_registers saved,observed;
    struct pwrsc_event history[PWRSC_HISTORY];
};
_Static_assert(sizeof(struct pwrsc_event)==48,"RSC append-only event extent");
_Static_assert(sizeof(struct pwrsc_transaction)==49464,"RSC complete transaction raw extent");
static inline void pwrsc_fail(struct pwrsc_transaction *r,unsigned error)
{if(!r->error)r->error=error;if(r->writes||r->outstanding)r->unknown=1;}
static inline int pwrsc_clock(const struct pwrsc_io *io,struct pwrsc_transaction *r,uint64_t *ticks)
{
    uint64_t frequency=0,time=0;
    if(!io->clock(io->context,&time,&frequency)||frequency!=r->frequency||time<r->last||
       time-r->started>PWRSC_DEADLINE){pwrsc_fail(r,PWRSC_TIME);return 0;}
    r->last=time;*ticks=time;return 1;
}
/* Only the chosen TCS' three command RW registers, its control/wait/enable,
 * and its own IRQ W1C acknowledgement can be written. No arbitrary address. */
static inline int pwrsc_writable(const struct pwrsc_transaction *r,uint64_t at,uint32_t value)
{
    if(r->tcs>=8||!(r->active_mask&(1u<<r->tcs)))return 0;
    if(at==PWRSC_BASE+8)return value==(1u<<r->tcs);
    uint64_t t=PWRSC_BASE+(uint64_t)PWRSC_STRIDE*r->tcs;
    if(at==t+0x10)return value==r->saved.wait||value==(r->saved.wait|7u);
    if(at==t+0x14)return value==r->saved.control||value==(r->saved.control|PWRSC_AMC)||value==(r->saved.control|PWRSC_AMC|PWRSC_TRIGGER);
    if(at==t+0x1c)return value==0||value==7;
    unsigned restoring=r->completed==2&&r->acknowledged==2;
    static const uint32_t address[3]={0x30000,0x30010,0x30060};
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)if(at==t+0x30+20*k+4*j){
        if(restoring)return value==r->saved.command[k][j];
        unsigned resource=r->phase==3?2-k:k;
        if(j==0)return value==PWRSC_MESSAGE;
        if(j==1)return value==address[resource];
        return value==(r->phase==3?r->saved_vote[resource]:r->raised_vote[resource]);
    }
    return 0;
}
static inline int pwrsc_access(const struct pwrsc_io *io,struct pwrsc_transaction *r,
    uint64_t at,uint32_t *value,int write)
{
    if(!r->attempted||r->finished||(write&&(r->phase<1||r->phase>4))){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(r->error||r->outstanding||r->events>=PWRSC_HISTORY){pwrsc_fail(r,PWRSC_HISTORY_FULL);return 0;}
    if((at&3)||at<PWRSC_BASE||at>=PWRSC_BASE+0x3000||
       (write&&!pwrsc_writable(r,at,*value))){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    struct pwrsc_event *e=&r->history[r->events++];e->address=at;e->operation=write?2:1;e->phase=r->phase;e->value=*value;
    if(!pwrsc_clock(io,r,&e->before))return 0;
    e->issued=e->unknown=1;r->outstanding=r->events;
    if(write)r->writes++;io->order(io->context);
    int returned=write?io->write(io->context,at,*value):io->read(io->context,at,value);
    e->value=*value;e->returned=returned?1:0;io->order(io->context);
    if(!returned){pwrsc_fail(r,write?PWRSC_WRITE:PWRSC_READ);return 0;}
    if(!pwrsc_clock(io,r,&e->after)){r->unknown=1;return 0;}
    e->unknown=0;r->outstanding=0;io->order(io->context);return 1;
}
static inline int pwrsc_read(const struct pwrsc_io *io,struct pwrsc_transaction *r,uint64_t at,uint32_t *v)
{*v=UINT32_MAX;return pwrsc_access(io,r,at,v,0);}
static inline int pwrsc_store(const struct pwrsc_io *io,struct pwrsc_transaction *r,uint64_t at,uint32_t value)
{
    uint32_t readback;
    if(!pwrsc_access(io,r,at,&value,1)||!pwrsc_read(io,r,at,&readback))return 0;
    if(readback!=value){pwrsc_fail(r,PWRSC_CHANGED);return 0;}return 1;
}
static inline uint64_t pwrsc_tcs(const struct pwrsc_transaction *r)
{return PWRSC_BASE+(uint64_t)PWRSC_STRIDE*r->tcs;}
static inline int pwrsc_irq(const struct pwrsc_io *io,struct pwrsc_transaction *r,uint32_t *irq)
{
    if(!pwrsc_read(io,r,PWRSC_BASE+4,irq))return 0;
    r->IRQ_OR|=*irq;return 1;
}
static inline int pwrsc_snapshot(const struct pwrsc_io *io,struct pwrsc_transaction *r,struct pwrsc_registers *s)
{
    uint64_t t=pwrsc_tcs(r);
    if(!pwrsc_read(io,r,t+0x14,&s->control)||!pwrsc_read(io,r,t+0x1c,&s->enable)||
       !pwrsc_read(io,r,t+0x10,&s->wait)||!pwrsc_read(io,r,t+0x18,&s->status))return 0;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<5;j++)
        if(!pwrsc_read(io,r,t+0x30+20*k+4*j,&s->command[k][j]))return 0;
    return 1;
}
/* Begin is finite and read-only. The active mask comes from the actual
 * original provider mode/DRV2 snapshot, never an assumed Mi8 TCS1. The mask,
 * vote arrays and this successful function are NOT physical lease evidence. */
static inline int pwrsc_begin(const struct pwrsc_io *io,struct pwrsc_transaction *r,
    uint32_t active_mask,const uint32_t saved[3],const uint32_t desired[3])
{
    if(!r||r->attempted)return 0;r->attempted=1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!saved||!desired||
       !active_mask||(active_mask&~0xffu)){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    if(!io->clock(io->context,&r->started,&r->frequency)||r->frequency!=19200000){pwrsc_fail(r,PWRSC_TIME);return 0;}
    r->last=r->started;r->active_mask=active_mask;
    static const uint32_t addresses[3]={0x30000,0x30010,0x30060};
    for(unsigned k=0;k<3;k++){
        if(saved[k]>15||desired[k]>15){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
        r->saved_vote[k]=saved[k];r->raised_vote[k]=saved[k]>desired[k]?saved[k]:desired[k];r->address[k]=addresses[k];
    }
    if(!pwrsc_read(io,r,PWRSC_BASE,&r->IRQ_enable)||!pwrsc_irq(io,r,&r->IRQ_status))return 0;
    if(r->IRQ_status){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    unsigned found=0;
    for(unsigned k=0;k<8;k++)if((active_mask&r->IRQ_enable)&(1u<<k)){
        r->tcs=k;
        if(!pwrsc_snapshot(io,r,&r->observed))return 0;
        if((r->observed.status&1)&&!r->observed.enable&&!(r->observed.control&PWRSC_TRIGGER)){
            r->saved=r->observed;found=1;break;
        }
    }
    if(!found){pwrsc_fail(r,PWRSC_BUSY);return 0;}
    if(r->last==r->started){pwrsc_fail(r,PWRSC_TIME);return 0;}
    r->phase=1;return 1;
}
static inline int pwrsc_stage(const struct pwrsc_io *io,struct pwrsc_transaction *r,unsigned restore)
{
    if((restore&&(r->triggers!=1||r->completed!=1||r->acknowledged!=1))||
       (!restore&&(r->triggers||r->completed||r->acknowledged))){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    uint64_t t=pwrsc_tcs(r);uint32_t irq,control,enable,status,irq_enabled;
    if(!pwrsc_irq(io,r,&irq)||!pwrsc_read(io,r,t+0x14,&control)||!pwrsc_read(io,r,t+0x1c,&enable)||
       !pwrsc_read(io,r,t+0x18,&status)||!pwrsc_read(io,r,PWRSC_BASE,&irq_enabled))return 0;
    if(irq||control!=r->saved.control||enable||!(status&1)||irq_enabled!=r->IRQ_enable){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    for(unsigned k=0;k<3;k++){
        /* Raise CX -> MX -> MSS; restore MSS -> MX -> CX. Never lower the
         * dependency rails ahead of restoring MSS' saved vote. */
        unsigned resource=restore?2-k:k;
        if(!pwrsc_store(io,r,t+0x30+20*k,PWRSC_MESSAGE)||!pwrsc_store(io,r,t+0x34+20*k,r->address[resource])||
           !pwrsc_store(io,r,t+0x38+20*k,restore?r->saved_vote[resource]:r->raised_vote[resource]))return 0;
    }
    if(!pwrsc_store(io,r,t+0x10,r->saved.wait|7u)||!pwrsc_store(io,r,t+0x1c,7u)||
       !pwrsc_store(io,r,t+0x14,r->saved.control|PWRSC_AMC))return 0;
    uint32_t value=r->saved.control|PWRSC_AMC|PWRSC_TRIGGER;
    /* A trigger may complete before its readback and is self-changing. Its
     * delivery is recorded; completion comes only from NEW IRQ + all3 DONE. */
    if(!pwrsc_access(io,r,t+0x14,&value,1))return 0;
    r->triggers++;r->phase=restore?4:2;return 1;
}
/* Return1 means complete, 0 means pending, -1 means sticky failure. Exactly
 * one finite poll is performed per step; no hidden churn/recursion loop. */
static inline int pwrsc_poll(const struct pwrsc_io *io,struct pwrsc_transaction *r)
{
    uint32_t irq,status;uint64_t t=pwrsc_tcs(r);
    if(!pwrsc_irq(io,r,&irq))return -1;
    if(irq&~(1u<<r->tcs)){pwrsc_fail(r,PWRSC_CHANGED);return -1;}
    if(!irq)return 0;
    for(unsigned k=0;k<3;k++){
        uint32_t command,response;
        if(!pwrsc_read(io,r,t+0x3c+20*k,&command)||!pwrsc_read(io,r,t+0x40+20*k,&response))return -1;
        r->status_OR[k]|=command;r->response_OR[k]|=response;
        if((command&PWRSC_DONE)!=PWRSC_DONE){pwrsc_fail(r,PWRSC_COMPLETION);return -1;}
    }
    if(!pwrsc_read(io,r,t+0x18,&status))return -1;
    if(!(status&1))return 0;
    r->completed++;return 1;
}
static inline int pwrsc_ack(const struct pwrsc_io *io,struct pwrsc_transaction *r)
{
    if(r->completed!=r->triggers||r->acknowledged+1!=r->completed){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    uint64_t t=pwrsc_tcs(r);uint32_t irq,value=1u<<r->tcs;
    if(!pwrsc_store(io,r,t+0x1c,0)||!pwrsc_store(io,r,t+0x14,r->saved.control))return 0;
    /* Never clear pending/unknown work. This is reached only after the fresh
     * selected IRQ and every command's issued+completed bits were observed. */
    if(!pwrsc_irq(io,r,&irq))return 0;
    if(irq!=value){pwrsc_fail(r,PWRSC_CHANGED);return 0;}
    if(!pwrsc_access(io,r,PWRSC_BASE+8,&value,1)||!pwrsc_irq(io,r,&irq))return 0;
    if(irq){pwrsc_fail(r,PWRSC_CHANGED);return 0;}r->acknowledged++;return 1;
}
static inline int pwrsc_restore_registers(const struct pwrsc_io *io,struct pwrsc_transaction *r)
{
    if(r->triggers!=2||r->completed!=2||r->acknowledged!=2){pwrsc_fail(r,PWRSC_ARGUMENT);return 0;}
    uint64_t t=pwrsc_tcs(r);uint32_t irq,enabled;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)
        if(!pwrsc_store(io,r,t+0x30+20*k+4*j,r->saved.command[k][j]))return 0;
    if(!pwrsc_store(io,r,t+0x10,r->saved.wait)||!pwrsc_snapshot(io,r,&r->observed)||
       !pwrsc_read(io,r,PWRSC_BASE,&enabled)||!pwrsc_irq(io,r,&irq))return 0;
    if(enabled!=r->IRQ_enable||irq||r->observed.control!=r->saved.control||r->observed.enable||
       r->observed.wait!=r->saved.wait||!(r->observed.status&1)){pwrsc_fail(r,PWRSC_RESTORE);return 0;}
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)if(r->observed.command[k][j]!=r->saved.command[k][j]){
        pwrsc_fail(r,PWRSC_RESTORE);return 0;}
    /* Status/response are RO results and deliberately retained, not called
     * bitwise hardware restoration. No original provider RAM was modified. */
    r->restored=r->finished=1;r->phase=5;io->order(io->context);return 1;
}
static inline int pwrsc_step(const struct pwrsc_io *io,struct pwrsc_transaction *r)
{
    if(!r||r->error||r->unknown||r->outstanding)return -1;
    if(r->finished)return 1;
    if(!io||!io->clock||!io->read||!io->write||!io->order||!r->attempted){pwrsc_fail(r,PWRSC_ARGUMENT);return -1;}
    /* A frozen counter cannot make polling infinite. This is independent of
     * the elapsed-time and append-only history bounds. */
    if(++r->steps>256){pwrsc_fail(r,PWRSC_TIME);return -1;}
    uint64_t ticks;if(!pwrsc_clock(io,r,&ticks))return -1;
    if(r->phase==1){if(!pwrsc_stage(io,r,0))return -1;return 0;}
    if(r->phase==3){if(!pwrsc_stage(io,r,1))return -1;return 0;}
    if(r->phase==2||r->phase==4){
        int done=pwrsc_poll(io,r);if(done<0)return -1;if(!done)return 0;
        if(!pwrsc_ack(io,r))return -1;
        if(r->phase==2){r->phase=3;return 0;}
        return pwrsc_restore_registers(io,r)?1:-1;
    }
    pwrsc_fail(r,PWRSC_ARGUMENT);return -1;
}
#endif
