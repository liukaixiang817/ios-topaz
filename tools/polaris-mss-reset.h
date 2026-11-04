/* Polaris own pil-msa.c shutdown reset pulse, after fresh stop ACK and three
 * AXI halts. Protocol addresses are data; the parent retains the same MSS
 * generation, clocks, power, mappings and exclusive reset owner throughout.
 * No ALT/RESTART read is invented: own source only writes these registers.
 * Completion does NOT drop clocks, retire every DMA master or return memory.
 * Every partial failure is sticky; there is no cleanup/replay/reset-clear API. */
#ifndef POLARIS_MSS_RESET_H
#define POLARIS_MSS_RESET_H
#include <stdint.h>
#define PMSR_PDC UINT64_C(0xb2e0100)
#define PMSR_ALT UINT64_C(0x4180044)
#define PMSR_RESTART UINT64_C(0xc2b0000)
#define PMSR_MASK UINT32_C(0x200)
#define PMSR_EVENTS 14u
#define PMSR_TWO_US UINT64_C(39) /* ceil(19.2MHz * 2us), never 38 ticks */
#define PMSR_200_US UINT64_C(3840)
#define PMSR_LIMIT UINT64_C(192000) /* finite10ms returned-operation scope */
enum pmsr_result {PMSR_FAILED=-1,PMSR_WAIT,PMSR_IO,PMSR_PULSED};
enum pmsr_kind {PMSR_READ=1,PMSR_WRITE,PMSR_STORE_ORDER,PMSR_FULL_ORDER};
enum pmsr_step {
    PMSR_PDC_READ_ON,PMSR_PDC_ON,PMSR_PDC_ON_ORDER,
    PMSR_ALT_ON,PMSR_ALT_ON_ORDER,PMSR_RESTART_ON,PMSR_RESTART_ON_ORDER,
    PMSR_RESTART_OFF,PMSR_RESTART_OFF_ORDER,PMSR_ALT_OFF,PMSR_ALT_OFF_ORDER,
    PMSR_PDC_READ_OFF,PMSR_PDC_OFF,PMSR_PDC_OFF_ORDER
};
enum pmsr_error {PMSR_OK,PMSR_ARGUMENT,PMSR_REENTRY,PMSR_TIME,PMSR_ACCESS,PMSR_FOREIGN};
struct pmsr_command {uint64_t address;uint32_t sequence,step,kind,value;};
struct pmsr_event {
    struct pmsr_command command;uint64_t before,after;
    int32_t return_raw;uint32_t issued,returned,value;
};
struct pmsr_reset {
    uint64_t opening,last,not_before;
    uint32_t started,unknown,error,pending,step,events,complete,pdc;
    uint32_t write_intent,write_returned,reserved[2];
    struct pmsr_event event[PMSR_EVENTS];
};
static inline int pmsr_equal(const void*a,const void*b,unsigned bytes)
{const uint8_t*x=a,*y=b;for(unsigned k=0;k<bytes;k++)if(x[k]!=y[k])return 0;return 1;}
static inline int pmsr_disjoint(const void*a,uint64_t an,const void*b,uint64_t bn)
{
    uint64_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=UINT64_MAX-an&&y<=UINT64_MAX-bn&&(x+an<=y||y+bn<=x);
}
static inline int pmsr_fail(struct pmsr_reset*r,unsigned error)
{if(r){r->unknown=1;if(!r->error)r->error=error;}return PMSR_FAILED;}
static inline int pmsr_time(struct pmsr_reset*r,uint64_t now)
{
    if(!now||now<r->last||now<r->opening||now-r->opening>PMSR_LIMIT)
        return pmsr_fail(r,PMSR_TIME);
    r->last=now;return 1;
}
static inline int pmsr_begin(struct pmsr_reset*r,uint64_t now,uint64_t frequency)
{
    if(!r||!now||frequency!=19200000||now>UINT64_MAX-PMSR_LIMIT)return PMSR_FAILED;
    const uint8_t*p=(const void*)r;for(unsigned k=0;k<sizeof(*r);k++)if(p[k])return PMSR_FAILED;
    r->started=1;r->opening=r->last=r->not_before=now;return PMSR_WAIT;
}
static inline int pmsr_next(struct pmsr_reset*r,uint64_t now,struct pmsr_command*out)
{
    if(!r||!out||!r->started||r->unknown||r->error)return PMSR_FAILED;
    if(!pmsr_disjoint(r,sizeof(*r),out,sizeof(*out)))return pmsr_fail(r,PMSR_ARGUMENT);
    if(r->pending)return pmsr_fail(r,PMSR_REENTRY);
    if(pmsr_time(r,now)<0)return PMSR_FAILED;
    if(now<r->not_before)return PMSR_WAIT;
    if(r->step==PMSR_EVENTS){
        if(r->events!=PMSR_EVENTS||r->write_intent!=0x3f||r->write_returned!=0x3f)
            return pmsr_fail(r,PMSR_ARGUMENT);
        r->complete=1;return PMSR_PULSED;
    }
    if(r->step>=PMSR_EVENTS||r->events!=r->step||r->complete)return pmsr_fail(r,PMSR_ARGUMENT);
    struct pmsr_command c={.sequence=r->events+1,.step=r->step};unsigned bit=0;
    switch(r->step){
    case PMSR_PDC_READ_ON:case PMSR_PDC_READ_OFF:c.kind=PMSR_READ;c.address=PMSR_PDC;break;
    case PMSR_PDC_ON:c.kind=PMSR_WRITE;c.address=PMSR_PDC;c.value=r->pdc|PMSR_MASK;bit=1;break;
    case PMSR_ALT_ON:c.kind=PMSR_WRITE;c.address=PMSR_ALT;c.value=1;bit=2;break;
    case PMSR_RESTART_ON:c.kind=PMSR_WRITE;c.address=PMSR_RESTART;c.value=1;bit=4;break;
    case PMSR_RESTART_OFF:c.kind=PMSR_WRITE;c.address=PMSR_RESTART;bit=8;break;
    case PMSR_ALT_OFF:c.kind=PMSR_WRITE;c.address=PMSR_ALT;bit=16;break;
    case PMSR_PDC_OFF:c.kind=PMSR_WRITE;c.address=PMSR_PDC;c.value=r->pdc&~PMSR_MASK;bit=32;break;
    case PMSR_RESTART_ON_ORDER:case PMSR_RESTART_OFF_ORDER:c.kind=PMSR_FULL_ORDER;break;
    default:c.kind=PMSR_STORE_ORDER;break;
    }
    struct pmsr_event*e=&r->event[r->events++];e->command=c;e->before=now;e->issued=1;
    r->write_intent|=bit;r->pending=c.sequence;*out=c;return PMSR_IO;
}
static inline int pmsr_complete(struct pmsr_reset*r,const struct pmsr_command*c,
    uint64_t now,int returned,uint32_t value)
{
    if(!r||!c||!r->started||r->unknown||r->error)return PMSR_FAILED;
    if(!pmsr_disjoint(r,sizeof(*r),c,sizeof(*c)))return pmsr_fail(r,PMSR_ARGUMENT);
    if(!r->pending||r->pending!=r->events||r->events>PMSR_EVENTS||r->step+1!=r->events)
        return pmsr_fail(r,PMSR_REENTRY);
    struct pmsr_event*e=&r->event[r->events-1];
    if(!e->issued||e->returned||!pmsr_equal(c,&e->command,sizeof(*c)))return pmsr_fail(r,PMSR_REENTRY);
    e->after=now;e->return_raw=returned;e->returned=returned==1;e->value=value;
    if(returned!=1)return pmsr_fail(r,PMSR_ACCESS);
    if(pmsr_time(r,now)<0)return PMSR_FAILED;
    uint64_t delay=0;unsigned bit=0;
    switch(r->step){
    case PMSR_PDC_READ_ON:
        if(value&PMSR_MASK)return pmsr_fail(r,PMSR_FOREIGN);r->pdc=value;break;
    case PMSR_PDC_READ_OFF:
        if(!(value&PMSR_MASK))return pmsr_fail(r,PMSR_FOREIGN);r->pdc=value;break;
    case PMSR_PDC_ON:bit=1;break;case PMSR_ALT_ON:bit=2;break;
    case PMSR_RESTART_ON:bit=4;break;case PMSR_RESTART_OFF:bit=8;break;
    case PMSR_ALT_OFF:bit=16;break;case PMSR_PDC_OFF:bit=32;break;
    case PMSR_RESTART_ON_ORDER:case PMSR_RESTART_OFF_ORDER:delay=PMSR_TWO_US+PMSR_200_US;break;
    default:delay=PMSR_TWO_US;break;
    }
    if(now>UINT64_MAX-delay)return pmsr_fail(r,PMSR_TIME);
    r->write_returned|=bit;r->not_before=now+delay;r->step++;r->pending=0;
    /* Even the last store-order must observe its2us minimum before success. */
    return PMSR_WAIT;
}
#endif
