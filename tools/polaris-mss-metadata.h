/* Own self-auth metadata phase after MBA-ready, before modem region sharing.
 * Input records sequence actual producers; they do not replace the native
 * owner's allocation/cache/source/lifetime qualification. Status3 permits a
 * separate secure return transaction. Neither status3 nor return-zero frees
 * the allocation or authorizes unchecked CPU access. No metadata RAM reads. */
#ifndef POLARIS_MSS_METADATA_H
#define POLARIS_MSS_METADATA_H
#include "polaris-mss-mba-boot.h"
#define PMMD_EVENTS 512u
#define PMMD_TIMEOUT UINT64_C(192000000) /*own10s metadata auth timeout*/
#define PMMD_POLL UINT64_C(384000) /*20ms, >=own50us polling interval*/
enum pmmd_result {PMMD_FAILED=-1,PMMD_WAIT,PMMD_IO,PMMD_AUTHENTICATED,PMMD_RETURNED_ZERO};
enum pmmd_step {PMMD_LENGTH,PMMD_ADDRESS,PMMD_COMMAND,PMMD_ORDER,PMMD_STATUS};
struct pmmd_command {uint64_t address;uint32_t sequence,step,kind,value;};
struct pmmd_event {
    struct pmmd_command command;uint64_t before,after;
    int32_t return_raw;uint32_t issued,returned,value;
};
struct pmmd_metadata {
    uint64_t epoch,metadata,bytes,allocation_bytes,assignment_page,assignment_at,mba_ready_at,
        opening,last,poll_opening,next_poll,authenticated_at,returned_at;
    uint32_t phase,unknown,error,pending,step,events,polls,published;
    struct pmmd_event event[PMMD_EVENTS];
};
static inline int pmmd_fail(struct pmmd_metadata*m,unsigned error)
{if(m){m->unknown=1;if(!m->error)m->error=error;}return PMMD_FAILED;}
static inline int pmmd_begin(struct pmmd_metadata*m,const struct pmba_boot*b,
    const struct pmck_lifecycle*c,const struct pwmt_transaction*a,uint64_t bytes,uint64_t now)
{
    if(!m||!b||!c||!a||!pmsr_disjoint(m,sizeof(*m),b,sizeof(*b))||
       !pmsr_disjoint(m,sizeof(*m),c,sizeof(*c))||!pmsr_disjoint(m,sizeof(*m),a,sizeof(*a))||
       !pms_zero(m,sizeof(*m))||!now||now>UINT64_MAX-PMMD_TIMEOUT-19200000)return PMMD_FAILED;
    const struct pwma_spec*s=&a->spec;uint64_t rounded=(bytes+4095)&~UINT64_C(4095);
    if(!bytes||bytes>65536||b->phase!=4||b->ready!=1||b->step!=PMBA_DONE||b->unknown||b->error||b->pending||
       c->phase!=2||c->unknown||c->error||c->pending||c->held!=63||!c->epoch||c->epoch!=b->epoch||now<c->last||
       a->complete!=1||a->unknown||a->error||a->pending||a->step!=PWMT_DONE||a->opening<b->last||
       !a->last||now<a->last||s->region_bytes!=rounded||(s->region_pa&4095)||s->region_pa<0x80000000||
       s->region_pa>UINT64_C(0x100000000)-rounded||s->sources!=1||s->source[0]!=PWMA_HLOS||
       s->destinations!=1||s->destination[0].vmid!=PWMA_MSS_MSA||s->destination[0].permissions!=PWMA_RW||
       !pmsr_disjoint((void*)(uintptr_t)s->region_pa,rounded,(void*)(uintptr_t)b->mba,b->mba_bytes))return pmmd_fail(m,1);
    m->epoch=b->epoch;m->metadata=s->region_pa;m->bytes=bytes;m->allocation_bytes=rounded;
    m->assignment_page=a->page;m->assignment_at=a->last;m->mba_ready_at=b->last;
    m->opening=m->last=m->next_poll=now;m->phase=1;return PMMD_WAIT;
}
static inline int pmmd_time(struct pmmd_metadata*m,uint64_t now)
{
    if(!now||now<m->last||now<m->opening||now-m->opening>PMMD_TIMEOUT+19200000||
       (m->poll_opening&&(now<m->poll_opening||now-m->poll_opening>PMMD_TIMEOUT)))return pmmd_fail(m,2);
    m->last=now;return 1;
}
static inline int pmmd_next(struct pmmd_metadata*m,uint64_t now,struct pmmd_command*out)
{
    if(!m||!out||m->unknown||m->error)return PMMD_FAILED;
    if(!pmsr_disjoint(m,sizeof(*m),out,sizeof(*out))||m->pending)return pmmd_fail(m,3);
    if(m->phase==2)return m->authenticated_at?PMMD_AUTHENTICATED:pmmd_fail(m,1);
    if(m->phase==3)return m->returned_at?PMMD_RETURNED_ZERO:pmmd_fail(m,1);
    if(m->phase!=1||m->step>PMMD_STATUS||m->events>=PMMD_EVENTS||pmmd_time(m,now)<0)return pmmd_fail(m,2);
    if(now<m->next_poll)return PMMD_WAIT;
    if(m->step==PMMD_STATUS&&m->polls>=501)return pmmd_fail(m,4);
    struct pmmd_command c={.sequence=m->events+1,.step=m->step,.kind=PMSR_WRITE};
    switch(m->step){
    case PMMD_LENGTH:c.address=0x4180018;break;
    case PMMD_ADDRESS:c.address=0x4180010;c.value=(uint32_t)m->metadata;m->published=1;break;
    case PMMD_COMMAND:c.address=0x4180008;c.value=1;break;
    case PMMD_ORDER:c.kind=PMSR_FULL_ORDER;break;
    case PMMD_STATUS:c.address=0x418000c;c.kind=PMSR_READ;m->polls++;break;
    }
    struct pmmd_event*e=&m->event[m->events++];e->command=c;e->before=now;e->issued=1;m->pending=c.sequence;*out=c;return PMMD_IO;
}
static inline int pmmd_complete(struct pmmd_metadata*m,const struct pmmd_command*c,uint64_t now,int returned,uint32_t value)
{
    if(!m||!c||m->unknown||m->error)return PMMD_FAILED;
    if(!pmsr_disjoint(m,sizeof(*m),c,sizeof(*c))||m->phase!=1||!m->pending||m->pending!=m->events||
       m->events>PMMD_EVENTS||c->sequence!=m->events||c->step!=m->step)return pmmd_fail(m,3);
    struct pmmd_event*e=&m->event[m->events-1];
    if(!e->issued||e->returned||!pmsr_equal(c,&e->command,sizeof(*c)))return pmmd_fail(m,3);
    e->after=now;e->return_raw=returned;e->returned=returned==1;e->value=value;
    if(returned!=1)return pmmd_fail(m,5);
    if(pmmd_time(m,now)<0)return PMMD_FAILED;
    if(m->step==PMMD_STATUS){
        if(value==3){m->phase=2;m->authenticated_at=now;}
        else if(value<=2)m->next_poll=now+PMMD_POLL;
        else return pmmd_fail(m,6); /* negative auth error or unexpected later phase */
    }else{
        if(m->step==PMMD_ORDER)m->poll_opening=now;m->step++;
    }
    m->pending=0;return m->phase==2?PMMD_AUTHENTICATED:PMMD_WAIT;
}
static inline int pmmd_return(struct pmmd_metadata*m,const struct pwmt_transaction*t)
{
    if(!m||!t||m->unknown||m->error)return PMMD_FAILED;
    const struct pwma_spec*s=&t->spec;
    if(!pmsr_disjoint(m,sizeof(*m),t,sizeof(*t))||m->phase!=2||m->pending||!m->authenticated_at||
       t->complete!=1||t->unknown||t->error||t->pending||t->step!=PWMT_DONE||t->opening<m->authenticated_at||
       t->last<t->opening||t->page==m->assignment_page||s->region_pa!=m->metadata||s->region_bytes!=m->allocation_bytes||
       s->sources!=1||s->source[0]!=PWMA_MSS_MSA||s->destinations!=1||
       s->destination[0].vmid!=PWMA_HLOS||s->destination[0].permissions!=PWMA_RWX)return pmmd_fail(m,7);
    m->returned_at=t->last;m->phase=3;return PMMD_RETURNED_ZERO;
}
#endif
