/* Own PIL incremental modem authentication, after metadata return and shared
 * modem assignment. This is an RMB protocol, not a copy/ownership receipt.
 * The actual parent must finish each segment's filesz copy, memsz zero tail,
 * readback/cache and source checks before calling pmim_publish. Nothing here
 * reads modem RAM or releases MBA, clocks, power, allocations or the owner. */
#ifndef POLARIS_MSS_MODEM_AUTH_H
#define POLARIS_MSS_MODEM_AUTH_H
#include "polaris-mss-metadata.h"
#include "../shim/polaris/uefi-mss-firmware-types.h"
#define PMIM_SEGMENTS 28u
#define PMIM_EVENTS 680u
#define PMIM_TOTAL UINT64_C(2304000000) /*120s whole returned-step envelope*/
#define PMIM_TIMEOUT UINT64_C(192000000) /*own final auth timeout10s*/
#define PMIM_POLL UINT64_C(384000) /*20ms bounded poll interval*/
enum pmim_result {PMIM_FAILED=-1,PMIM_WAIT,PMIM_IO,PMIM_NEED_SEGMENT,PMIM_NEED_EXCLUSIVE,PMIM_AUTHENTICATED};
enum pmim_step {PMIM_LENGTH_READ,PMIM_START,PMIM_COMMAND,PMIM_LENGTH_WRITE,PMIM_ORDER,PMIM_STATUS,PMIM_FINAL};
struct pmim_command {uint64_t address;uint32_t sequence,segment,step,kind,value,reserved;};
struct pmim_event {struct pmim_command command;uint64_t before,after;int32_t return_raw;uint32_t issued,returned,value;};
struct pmim_auth {
    uint64_t epoch,base,bytes,metadata_returned,shared_at,shared_page,opening,last,exclusive_at,exclusive_page,poll_opening,next_poll,authenticated_at;
    uint32_t phase,unknown,error,pending,segment,step,events,length,polls,submitted;
    struct pmsf_segment segments[PMIM_SEGMENTS];
    uint64_t publication[PMIM_SEGMENTS];struct pmim_event event[PMIM_EVENTS];
};
static inline int pmim_fail(struct pmim_auth*m,unsigned error)
{if(m){m->unknown=1;if(!m->error)m->error=error;}return PMIM_FAILED;}
static inline int pmim_assignment(const struct pwmt_transaction*t,unsigned exclusive,uint64_t base,uint64_t minimum)
{
    const struct pwma_spec*s=&t->spec;
    if(t->complete!=1||t->unknown||t->error||t->pending||t->step!=PWMT_DONE||t->opening<minimum||
       t->last<t->opening||s->region_pa!=base||s->region_bytes!=0x7800000||
       s->source[0]!=PWMA_HLOS||s->source[2]||s->destination[2].vmid||s->destination[2].permissions)return 0;
    if(exclusive)return s->sources==2&&s->source[1]==PWMA_MSS_MSA&&s->destinations==1&&
        s->destination[0].vmid==PWMA_MSS_MSA&&s->destination[0].permissions==PWMA_RW&&
        !s->destination[1].vmid&&!s->destination[1].permissions;
    return s->sources==1&&!s->source[1]&&s->destinations==2&&s->destination[0].vmid==PWMA_HLOS&&
        s->destination[0].permissions==PWMA_RW&&s->destination[1].vmid==PWMA_MSS_MSA&&s->destination[1].permissions==PWMA_RW;
}
static inline int pmim_time(struct pmim_auth*m,uint64_t now)
{
    if(!now||now<m->last||now<m->opening||now-m->opening>PMIM_TOTAL||
       (m->poll_opening&&(now<m->poll_opening||now-m->poll_opening>PMIM_TIMEOUT)))return pmim_fail(m,2);
    m->last=now;return 1;
}
static inline int pmim_begin(struct pmim_auth*m,const struct pmmd_metadata*d,const struct pmck_lifecycle*c,
    const struct pwmt_transaction*t,const struct pmsf_segment segments[PMIM_SEGMENTS],uint64_t now)
{
    if(!m||!d||!c||!t||!segments||!pms_zero(m,sizeof(*m))||!now||now>UINT64_MAX-PMIM_TOTAL||
       !pmsr_disjoint(m,sizeof(*m),d,sizeof(*d))||!pmsr_disjoint(m,sizeof(*m),c,sizeof(*c))||
       !pmsr_disjoint(m,sizeof(*m),t,sizeof(*t))||!pmsr_disjoint(m,sizeof(*m),segments,PMIM_SEGMENTS*sizeof(*segments)))return PMIM_FAILED;
    uint64_t base=t->spec.region_pa;
    if(d->phase!=3||d->unknown||d->error||d->pending||!d->authenticated_at||!d->returned_at||
       d->returned_at<d->authenticated_at||!d->epoch||d->epoch!=c->epoch||c->phase!=2||
       c->unknown||c->error||c->pending||c->held!=63||!c->held_at||
       now<c->last||now<d->returned_at||now<t->last||base<0x80000000||base>0xf8800000||(base&0xfffff)||
       !pmim_assignment(t,0,base,d->returned_at))return pmim_fail(m,1);
    uint64_t end=0,total=0;
    for(unsigned k=0;k<PMIM_SEGMENTS;k++){
        const struct pmsf_segment*s=&segments[k];
        if(s->index!=k+2||!s->memsz||s->filesz>s->memsz||(s->target_offset&4095)||
           s->target_offset<end||s->target_offset>=0x7800000||s->memsz>0x7800000-s->target_offset||
           s->alignment!=(k?4096u:0x100000u)||s->flags<0x8000004||s->flags>0x8000007||
           (s->filesz&&(s->asset<2||s->asset>26))||
           (!k&&s->target_offset)||((s->asset==(uint32_t)-1)!=(s->filesz==0)))return pmim_fail(m,3);
        end=(uint64_t)s->target_offset+s->memsz;total+=s->memsz;m->segments[k]=*s;
    }
    if(end!=0x7800000||total>0x7800000)return pmim_fail(m,3);
    m->epoch=d->epoch;m->base=base;m->bytes=0x7800000;m->metadata_returned=d->returned_at;
    m->shared_at=t->last;m->shared_page=t->page;m->opening=m->last=now;m->phase=1;return PMIM_NEED_SEGMENT;
}
/* Explicit caller boundary after the REAL copy/cache operation. It records
 * publication timing only; it does not certify that operation or synthesize
 * a segment-loaded record. The native parent must bind its own evidence. */
static inline int pmim_publish(struct pmim_auth*m,unsigned segment,uint64_t now)
{
    if(!m||m->unknown||m->error)return PMIM_FAILED;
    if(m->phase!=1||m->pending||segment!=m->segment||segment>=PMIM_SEGMENTS||m->publication[segment]||
       pmim_time(m,now)<0)return pmim_fail(m,4);
    m->publication[segment]=now;m->submitted++;m->phase=2;m->step=PMIM_LENGTH_READ;return PMIM_WAIT;
}
static inline int pmim_exclusive(struct pmim_auth*m,const struct pwmt_transaction*t,uint64_t now)
{
    if(!m||!t||m->unknown||m->error)return PMIM_FAILED;
    if(!pmsr_disjoint(m,sizeof(*m),t,sizeof(*t))||m->phase!=3||m->pending||m->segment!=PMIM_SEGMENTS||
       m->submitted!=PMIM_SEGMENTS||t->page==m->shared_page||!pmim_assignment(t,1,m->base,m->last)||now<t->last||pmim_time(m,now)<0)
        return pmim_fail(m,5);
    m->exclusive_at=t->last;m->exclusive_page=t->page;m->poll_opening=m->next_poll=now;m->phase=4;m->step=PMIM_FINAL;return PMIM_WAIT;
}
static inline int pmim_next(struct pmim_auth*m,uint64_t now,struct pmim_command*out)
{
    if(!m||!out||m->unknown||m->error)return PMIM_FAILED;
    if(!pmsr_disjoint(m,sizeof(*m),out,sizeof(*out))||m->pending||pmim_time(m,now)<0)return pmim_fail(m,4);
    if(m->phase==1)return PMIM_NEED_SEGMENT;
    if(m->phase==3)return PMIM_NEED_EXCLUSIVE;
    if(m->phase==5)return m->authenticated_at?PMIM_AUTHENTICATED:pmim_fail(m,1);
    if((m->phase!=2&&m->phase!=4)||m->events>=PMIM_EVENTS||m->step>PMIM_FINAL)return pmim_fail(m,4);
    if((m->phase==2&&(m->segment>=PMIM_SEGMENTS||m->step==PMIM_FINAL))||
       (m->phase==4&&(m->segment!=PMIM_SEGMENTS||m->step!=PMIM_FINAL)))return pmim_fail(m,4);
    if(m->phase==4){if(now<m->next_poll)return PMIM_WAIT;if(m->polls>=501)return pmim_fail(m,6);m->polls++;}
    struct pmim_command c={.sequence=m->events+1,.segment=m->segment,.step=m->step,.kind=PMSR_WRITE};
    switch(m->step){
    case PMIM_LENGTH_READ:c.address=0x4180018;c.kind=PMSR_READ;break;
    case PMIM_START:c.address=0x4180014;c.value=(uint32_t)m->base;break;
    case PMIM_COMMAND:c.address=0x4180008;c.value=2;break;
    case PMIM_LENGTH_WRITE:
        if(m->segment>=PMIM_SEGMENTS)return pmim_fail(m,4);
        c.address=0x4180018;c.value=m->length+m->segments[m->segment].memsz;break;
    case PMIM_ORDER:c.kind=PMSR_FULL_ORDER;break;
    case PMIM_STATUS:case PMIM_FINAL:c.address=0x418000c;c.kind=PMSR_READ;break;
    }
    struct pmim_event*e=&m->event[m->events++];e->command=c;e->before=now;e->issued=1;m->pending=c.sequence;*out=c;return PMIM_IO;
}
static inline int pmim_complete(struct pmim_auth*m,const struct pmim_command*c,uint64_t now,int returned,uint32_t value)
{
    if(!m||!c||m->unknown||m->error)return PMIM_FAILED;
    if(!pmsr_disjoint(m,sizeof(*m),c,sizeof(*c))||!m->pending||m->pending!=m->events||m->events>PMIM_EVENTS||
       c->sequence!=m->events||c->segment!=m->segment||c->step!=m->step||
       (m->phase!=2&&m->phase!=4)||(m->phase==2&&(m->segment>=PMIM_SEGMENTS||m->step==PMIM_FINAL))||
       (m->phase==4&&(m->segment!=PMIM_SEGMENTS||m->step!=PMIM_FINAL)))return pmim_fail(m,4);
    struct pmim_event*e=&m->event[m->events-1];
    if(e->issued!=1||e->returned||!pmsr_equal(c,&e->command,sizeof(*c)))return pmim_fail(m,4);
    e->after=now;e->return_raw=returned;e->returned=returned==1;e->value=value;
    if(returned!=1||pmim_time(m,now)<0)return pmim_fail(m,7);
    switch(m->step){
    case PMIM_LENGTH_READ:
        if(value!=m->length)return pmim_fail(m,8);
        m->step=m->segment?PMIM_LENGTH_WRITE:PMIM_START;break;
    case PMIM_START:m->step=PMIM_COMMAND;break;
    case PMIM_COMMAND:m->step=PMIM_LENGTH_WRITE;break;
    case PMIM_LENGTH_WRITE:m->length=c->value;m->step=PMIM_ORDER;break;
    case PMIM_ORDER:m->step=PMIM_STATUS;break;
    case PMIM_STATUS:
        if(value>4)return pmim_fail(m,9);
        m->segment++;m->phase=m->segment==PMIM_SEGMENTS?3:1;break;
    case PMIM_FINAL:
        if(value>4)return pmim_fail(m,9);
        if(value==4){m->phase=5;m->authenticated_at=now;}else m->next_poll=now+PMIM_POLL;break;
    default:return pmim_fail(m,4);
    }
    m->pending=0;return m->phase==5?PMIM_AUTHENTICATED:PMIM_WAIT;
}
#endif
