/* Own Polaris qdsp6v65-1-0/self-auth MBA startup protocol. No PAS15 shortcut.
 * Consumes the typed clock-held and HLOS->MSS RW assignment results; the
 * native owner must retain the real allocation, image/cache provenance,
 * proxy power and exclusive hardware generation. These software records are
 * necessary sequencing inputs, not an ownership grant. No MBA RAM is read.
 * Failure retains everything; no guessed reset/clock/permission cleanup. */
#ifndef POLARIS_MSS_MBA_BOOT_H
#define POLARIS_MSS_MBA_BOOT_H
#include "polaris-mss-clocks.h"
#include "polaris-wifi-mem-transaction.h"
#define PMBA_EVENTS 1632u
#define PMBA_TOTAL UINT64_C(134400000) /*7s entire returned-call protocol*/
#define PMBA_ROM_TIMEOUT UINT64_C(57600000) /*own minidump-id present:3s*/
#define PMBA_ROM_POLL UINT64_C(288000) /*15ms finite polling, >=vendor50us*/
enum pmba_result {PMBA_FAILED=-1,PMBA_WAIT,PMBA_IO,PMBA_READY};
enum pmba_step {PMBA_DEBUG_READ,PMBA_DEBUG_RESTORE,PMBA_IMAGE,PMBA_IMAGE_ORDER,
    PMBA_DP_START,PMBA_DP_LENGTH,PMBA_DP_ORDER,PMBA_SLEEP_READ,PMBA_SLEEP_ON,
    PMBA_SLEEP_POLL,PMBA_CORE_START,PMBA_CORE_ORDER,PMBA_BOOT_COMMAND,
    PMBA_BOOT_POLL,PMBA_PBL_POLL,PMBA_MBA_POLL,PMBA_DONE};
enum pmba_error {PMBA_OK,PMBA_ARGUMENT,PMBA_REENTRY,PMBA_TIME,PMBA_ACCESS,PMBA_RESET,PMBA_LIMIT,PMBA_STATUS};
struct pmba_command {
    uint32_t phase,sequence,step,kind;uint64_t address;uint32_t value,reserved;
    struct pmsr_command reset;
};
struct pmba_event {
    struct pmba_command command;uint64_t before,after;
    int32_t return_raw;uint32_t issued,returned,value;
};
struct pmba_boot {
    uint64_t epoch,mba,mba_bytes,image_bytes,clock_held_at,assignment_at,opening,last,window,next_poll;
    uint32_t phase,unknown,error,pending,step,events,polls,ready,debug,sleep,image_issued,boot_issued;
    struct pmba_command command;struct pmsr_reset reset;struct pmba_event event[PMBA_EVENTS];
};
static inline int pmba_fail(struct pmba_boot*b,unsigned error)
{if(b){b->unknown=1;if(!b->error)b->error=error;}return PMBA_FAILED;}
static inline int pmba_begin(struct pmba_boot*b,const struct pmck_lifecycle*c,
    const struct pwmt_transaction*a,uint64_t image_bytes,uint64_t now)
{
    if(!b||!c||!a||!pmsr_disjoint(b,sizeof(*b),c,sizeof(*c))||!pmsr_disjoint(b,sizeof(*b),a,sizeof(*a))||
       !pms_zero(b,sizeof(*b))||!now||now>UINT64_MAX-PMBA_TOTAL)return PMBA_FAILED;
    const struct pwma_spec*s=&a->spec;
    if(c->phase!=2||c->unknown||c->error||c->pending||c->held!=63||!c->epoch||!c->held_at||now<c->last||
       a->complete!=1||a->unknown||a->error||a->pending||a->step!=PWMT_DONE||!a->last||now<a->last||
       s->region_bytes!=0x100000||(s->region_pa&4095)||s->region_pa<0x80000000||s->region_pa>UINT64_C(0xfff00000)||
       s->sources!=1||s->source[0]!=PWMA_HLOS||s->destinations!=1||
       s->destination[0].vmid!=PWMA_MSS_MSA||s->destination[0].permissions!=PWMA_RW||
       !image_bytes||image_bytes>0x100000)return pmba_fail(b,PMBA_ARGUMENT);
    b->epoch=c->epoch;b->mba=s->region_pa;b->mba_bytes=s->region_bytes;b->image_bytes=image_bytes;
    b->clock_held_at=c->held_at;b->assignment_at=a->last;b->opening=b->last=b->window=b->next_poll=now;b->phase=1;
    return PMBA_WAIT;
}
static inline int pmba_time(struct pmba_boot*b,uint64_t now)
{
    if(!now||now<b->last||now<b->opening||now-b->opening>PMBA_TOTAL)return pmba_fail(b,PMBA_TIME);
    b->last=now;
    uint64_t limit=b->step==PMBA_SLEEP_POLL?3840:b->step==PMBA_BOOT_POLL?192000:
        (b->step==PMBA_PBL_POLL||b->step==PMBA_MBA_POLL)?PMBA_ROM_TIMEOUT:PMBA_TOTAL;
    if(now<b->window||now-b->window>limit)return pmba_fail(b,PMBA_TIME);return 1;
}
static inline int pmba_next(struct pmba_boot*b,uint64_t now,struct pmba_command*out)
{
    if(!b||!out||b->unknown||b->error)return PMBA_FAILED;
    if(!pmsr_disjoint(b,sizeof(*b),out,sizeof(*out)))return pmba_fail(b,PMBA_ARGUMENT);
    if(b->pending)return pmba_fail(b,PMBA_REENTRY);
    if(b->phase==4)return b->ready==1&&b->step==PMBA_DONE?PMBA_READY:pmba_fail(b,PMBA_ARGUMENT);
    if(!b->phase||pmba_time(b,now)<0)return pmba_fail(b,PMBA_TIME);
    struct pmba_command c={.phase=b->phase,.step=b->step};
    if(b->phase==2){
        int result=pmsr_next(&b->reset,now,&c.reset);
        if(result<0)return pmba_fail(b,PMBA_RESET);
        if(result==PMSR_WAIT)return PMBA_WAIT;
        if(result==PMSR_PULSED){b->phase=3;b->step=PMBA_DEBUG_RESTORE;b->window=now;return PMBA_WAIT;}
        if(result!=PMSR_IO)return pmba_fail(b,PMBA_RESET);
        c.sequence=c.reset.sequence;
    }else{
        if((b->phase!=1&&b->phase!=3)||b->events>=PMBA_EVENTS||b->step>=PMBA_DONE)return pmba_fail(b,PMBA_LIMIT);
        if(now<b->next_poll)return PMBA_WAIT;
        unsigned limit=b->step==PMBA_SLEEP_POLL?200:b->step==PMBA_BOOT_POLL?1001:201;
        if(b->polls>=limit)return pmba_fail(b,PMBA_LIMIT);
        c.sequence=b->events+1;c.kind=PMSR_WRITE;
        switch(b->step){
        case PMBA_DEBUG_READ:c.address=0x4080018;c.kind=PMSR_READ;break;
        case PMBA_DEBUG_RESTORE:c.address=0x4080018;c.value=b->debug;break;
        case PMBA_IMAGE:c.address=0x4180000;c.value=(uint32_t)b->mba;b->image_issued=1;break;
        case PMBA_DP_START:c.address=0x4180014;break;
        case PMBA_DP_LENGTH:c.address=0x4180018;break;
        case PMBA_SLEEP_READ:case PMBA_SLEEP_POLL:c.address=0x408003c;c.kind=PMSR_READ;break;
        case PMBA_SLEEP_ON:c.address=0x408003c;c.value=b->sleep|1;break;
        case PMBA_CORE_START:c.address=0x4080400;c.value=1;break;
        case PMBA_BOOT_COMMAND:c.address=0x4080404;c.value=1;b->boot_issued=1;break;
        case PMBA_BOOT_POLL:c.address=0x4180040;c.kind=PMSR_READ;break;
        case PMBA_PBL_POLL:c.address=0x4180004;c.kind=PMSR_READ;break;
        case PMBA_MBA_POLL:c.address=0x418000c;c.kind=PMSR_READ;break;
        default:c.kind=PMSR_FULL_ORDER;break;
        }
        if(b->step==PMBA_SLEEP_POLL||b->step==PMBA_BOOT_POLL||b->step==PMBA_PBL_POLL||b->step==PMBA_MBA_POLL)b->polls++;
        struct pmba_event*e=&b->event[b->events++];e->command=c;e->before=now;e->issued=1;
    }
    b->command=c;b->pending=1;*out=c;return PMBA_IO;
}
static inline int pmba_complete(struct pmba_boot*b,const struct pmba_command*c,uint64_t now,int returned,uint32_t value)
{
    if(!b||!c||b->unknown||b->error)return PMBA_FAILED;
    if(!pmsr_disjoint(b,sizeof(*b),c,sizeof(*c))||b->pending!=1||!pmsr_equal(c,&b->command,sizeof(*c)))return pmba_fail(b,PMBA_REENTRY);
    if(b->phase==2){
        if(pmsr_complete(&b->reset,&c->reset,now,returned,value)<0)return pmba_fail(b,PMBA_RESET);
        if(pmba_time(b,now)<0)return PMBA_FAILED;b->pending=0;return PMBA_WAIT;
    }
    if(!b->events||b->events>PMBA_EVENTS||c->sequence!=b->events||c->step!=b->step||c->phase!=b->phase)return pmba_fail(b,PMBA_REENTRY);
    struct pmba_event*e=&b->event[b->events-1];
    if(!e->issued||e->returned||!pmsr_equal(c,&e->command,sizeof(*c)))return pmba_fail(b,PMBA_REENTRY);
    e->after=now;e->return_raw=returned;e->returned=returned==1;e->value=value;
    if(returned!=1)return pmba_fail(b,PMBA_ACCESS);
    if(pmba_time(b,now)<0)return PMBA_FAILED;
    unsigned advance=1;
    switch(b->step){
    case PMBA_DEBUG_READ:
        b->debug=value;if(pmsr_begin(&b->reset,now,19200000)<0)return pmba_fail(b,PMBA_RESET);
        b->phase=2;advance=0;break;
    case PMBA_SLEEP_READ:b->sleep=value;break;
    case PMBA_SLEEP_POLL:
        if(!(value&1))return pmba_fail(b,PMBA_STATUS);
        if(value&UINT32_C(0x80000000)){advance=0;b->next_poll=now+20;}break;
    case PMBA_BOOT_POLL:
        if(!(value&1)){advance=0;b->next_poll=now+192;}break;
    case PMBA_PBL_POLL:
        if(!value){advance=0;b->next_poll=now+PMBA_ROM_POLL;}
        else if(value!=1)return pmba_fail(b,PMBA_STATUS);break;
    case PMBA_MBA_POLL:
        if(!value){advance=0;b->next_poll=now+PMBA_ROM_POLL;}
        else if(value!=1&&value!=2)return pmba_fail(b,PMBA_STATUS);break;
    default:break;
    }
    if(advance){b->step++;b->window=b->next_poll=now;b->polls=0;}
    b->pending=0;
    if(b->step==PMBA_DONE){b->phase=4;b->ready=1;return PMBA_READY;}return PMBA_WAIT;
}
#endif
