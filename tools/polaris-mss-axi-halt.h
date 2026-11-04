/* Finite Polaris MSS AXI halt protocol, from own DT and c7cb50c1
 * pil-q6v5.c ABI facts. No MMIO backend, reset, permission or DMA-retired flag.
 * The owner must retain clocks/mappings and exclude competing MSS operations.
 * Success leaves all three requests asserted; failure never clears a request.
 * Own DT declares8B windows while the vendor also reads IDLE at+8. That extra
 * register needs explicit parent mapping/access admission, not silent expansion. */
#ifndef POLARIS_MSS_AXI_HALT_H
#define POLARIS_MSS_AXI_HALT_H
#include <stdint.h>
#define PMH_PORTS 3u
#define PMH_EVENTS 256u
#define PMH_PORT_TICKS UINT64_C(1920000) /* own100ms at19.2MHz */
#define PMH_TOTAL_TICKS (PMH_PORTS*PMH_PORT_TICKS)
#define PMH_POLL_TICKS UINT64_C(960) /* own50us ACK polling interval */
#define PMH_MAX_ACK_READS 64u
enum pmh_result {PMH_FAILED=-1,PMH_WAIT,PMH_IO,PMH_HELD};
enum pmh_step {PMH_INITIAL_REQ,PMH_SET_REQ,PMH_SET_READBACK,PMH_ACK,PMH_IDLE,PMH_FINAL_REQ};
enum pmh_error {PMH_OK,PMH_ARGUMENT,PMH_REENTRY,PMH_TIME,PMH_LIMIT,PMH_ACCESS,PMH_FOREIGN_REQ,PMH_READBACK,PMH_NOT_IDLE};
struct pmh_command {uint64_t address;uint32_t sequence,port,step,write,value,reserved;};
struct pmh_event {
    struct pmh_command command;uint64_t before,after;
    uint32_t issued,returned,value,reserved;
};
struct pmh_halt {
    uint64_t opening,last,port_opening,next_poll;
    uint32_t started,unknown,error,pending,port,step,events,ack_reads;
    uint32_t write_intent,write_returned,ports_held,reserved;
    struct pmh_event event[PMH_EVENTS];
};
static inline uint64_t pmh_base(unsigned port)
{
    const uint64_t base[PMH_PORTS]={UINT64_C(0x1f63000),UINT64_C(0x1f65000),UINT64_C(0x1f64000)};
    return port<PMH_PORTS?base[port]:0;
}
static inline int pmh_fail(struct pmh_halt*h,unsigned error)
{if(h){if(!h->error)h->error=error;h->unknown=1;}return PMH_FAILED;}
static inline int pmh_time(struct pmh_halt*h,uint64_t now)
{
    if(!now||now<h->last||now<h->opening||now-h->opening>PMH_TOTAL_TICKS||
       now<h->port_opening||now-h->port_opening>PMH_PORT_TICKS)return pmh_fail(h,PMH_TIME);
    h->last=now;return 1;
}
static inline int pmh_begin(struct pmh_halt*h,uint64_t now,uint64_t frequency)
{
    if(!h||!now||frequency!=19200000)return PMH_FAILED;
    const uint8_t*p=(const void*)h;for(unsigned n=0;n<sizeof(*h);n++)if(p[n])return PMH_FAILED;
    h->started=1;h->opening=h->last=h->port_opening=now;return 1;
}
/* An IO result must complete exactly once before another request is issued.
 * WAIT emits nothing. All integer addresses below are protocol DATA only. */
static inline int pmh_next(struct pmh_halt*h,uint64_t now,struct pmh_command*out)
{
    if(!h||!out||!h->started)return PMH_FAILED;
    uint64_t hb=(uintptr_t)h,ob=(uintptr_t)out;
    if(hb>UINT64_MAX-sizeof(*h)||ob>UINT64_MAX-sizeof(*out)||
       (hb<ob+sizeof(*out)&&ob<hb+sizeof(*h)))return pmh_fail(h,PMH_ARGUMENT);
    if(h->unknown||h->error)return PMH_FAILED;
    if(h->pending)return pmh_fail(h,PMH_REENTRY);
    if(h->ports_held==7&&h->port==PMH_PORTS)return PMH_HELD;
    if(h->port>=PMH_PORTS||h->step>PMH_FINAL_REQ)return pmh_fail(h,PMH_ARGUMENT);
    if(pmh_time(h,now)<0)return PMH_FAILED;
    if(h->step==PMH_ACK&&now<h->next_poll)return PMH_WAIT;
    if(h->events>=PMH_EVENTS||(h->step==PMH_ACK&&h->ack_reads>=PMH_MAX_ACK_READS))return pmh_fail(h,PMH_LIMIT);
    struct pmh_command c={.address=pmh_base(h->port),.sequence=h->events+1,.port=h->port,.step=h->step};
    if(h->step==PMH_ACK){c.address+=4;h->ack_reads++;}
    if(h->step==PMH_IDLE)c.address+=8;
    if(h->step==PMH_SET_REQ){c.write=1;c.value=1;h->write_intent|=1u<<h->port;}
    struct pmh_event*e=&h->event[h->events++];e->command=c;e->before=now;e->issued=1;
    h->pending=c.sequence;*out=c;return PMH_IO;
}
static inline int pmh_complete(struct pmh_halt*h,const struct pmh_command*command,
    uint64_t now,int returned,uint32_t value)
{
    if(!h||!command||!h->started||h->unknown||h->error)return PMH_FAILED;
    if(!h->pending||h->pending!=h->events||h->events>PMH_EVENTS)return pmh_fail(h,PMH_REENTRY);
    struct pmh_event*e=&h->event[h->events-1];
    if(e->command.sequence!=h->pending||e->command.port!=h->port||e->command.step!=h->step)
        return pmh_fail(h,PMH_REENTRY);
    const uint8_t*a=(const void*)command,*b=(const void*)&e->command;
    for(unsigned n=0;n<sizeof(*command);n++)if(a[n]!=b[n])return pmh_fail(h,PMH_REENTRY);
    if(e->returned||!e->issued)return pmh_fail(h,PMH_REENTRY);
    e->after=now;e->returned=returned==1?1u:0u;e->value=value;
    if(returned!=1)return pmh_fail(h,PMH_ACCESS);
    if(pmh_time(h,now)<0)return PMH_FAILED;
    switch(h->step){
    case PMH_INITIAL_REQ:
        if(value)return pmh_fail(h,PMH_FOREIGN_REQ);h->step=PMH_SET_REQ;break;
    case PMH_SET_REQ:
        h->write_returned|=1u<<h->port;h->step=PMH_SET_READBACK;break;
    case PMH_SET_READBACK:
        if(value!=1)return pmh_fail(h,PMH_READBACK);h->step=PMH_ACK;h->next_poll=now;break;
    case PMH_ACK:
        if(value)h->step=PMH_IDLE;
        else{
            if(now>UINT64_MAX-PMH_POLL_TICKS)return pmh_fail(h,PMH_TIME);
            h->next_poll=now+PMH_POLL_TICKS;
        }break;
    case PMH_IDLE:
        if(!value)return pmh_fail(h,PMH_NOT_IDLE);h->step=PMH_FINAL_REQ;break;
    case PMH_FINAL_REQ:
        if(value!=1)return pmh_fail(h,PMH_READBACK);
        h->ports_held|=1u<<h->port;h->port++;h->step=PMH_INITIAL_REQ;
        h->port_opening=now;h->ack_reads=0;h->next_poll=0;break;
    default:return pmh_fail(h,PMH_ARGUMENT);
    }
    h->pending=0;return h->ports_held==7?PMH_HELD:PMH_WAIT;
}
#endif
