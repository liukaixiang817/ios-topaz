/* Finite MP_ASSIGN descriptor/continuation protocol. This emits operations;
 * it never executes firmware, caches, allocation or memory-owner changes.
 * ZERO means the complete observed protocol returned zero and its read-only
 * descriptors survived. It is not a hardware owner or DMA-retirement grant.
 * A failed/pending transaction retains all buffers. There is no release API. */
#ifndef POLARIS_WIFI_MEM_TRANSACTION_H
#define POLARIS_WIFI_MEM_TRANSACTION_H
#include "polaris-wifi-mem-cache.h"
#define PWMT_ROUNDS 4u
#define PWMT_EVENTS (PWMT_ROUNDS+2u)
#define PWMT_TICKS UINT64_C(1920000) /*100ms returned-step budget,19.2MHz*/
enum pwmt_result {PWMT_FAILED=-1,PWMT_WAIT,PWMT_IO,PWMT_ZERO};
enum pwmt_operation {PWMT_CLEAN=1,PWMT_SMC,PWMT_INVALIDATE,PWMT_DONE};
enum pwmt_error {PWMT_OK,PWMT_ARGUMENT,PWMT_REENTRY,PWMT_TIME,PWMT_CACHE,
    PWMT_CHANGED_PAGE,PWMT_TRANSPORT,PWMT_LIMIT,PWMT_RETURN};
struct pwmt_command {
    uint64_t page;uint32_t sequence,operation;
    struct pwma_registers registers;
};
struct pwmt_event {
    struct pwmt_command command;uint64_t before,after;
    uint32_t issued,returned;int32_t return_raw;uint32_t reserved;
    struct pwma_registers response;struct pwmk_record cache;
};
struct pwmt_transaction {
    uint64_t page,opening,last;
    uint32_t started,unknown,error,pending,step,events,rounds,complete;
    struct pwma_spec spec;struct pwma_registers initial,next;
    uint8_t expected[4096];struct pwmt_event event[PWMT_EVENTS];
};
static inline int pwmt_equal(const void*a,const void*b,unsigned bytes)
{const uint8_t*x=a,*y=b;for(unsigned k=0;k<bytes;k++)if(x[k]!=y[k])return 0;return 1;}
static inline int pwmt_zero(const void*a,unsigned bytes)
{const uint8_t*x=a;for(unsigned k=0;k<bytes;k++)if(x[k])return 0;return 1;}
static inline int pwmt_fail(struct pwmt_transaction*t,unsigned error)
{if(t){if(!t->error)t->error=error;t->unknown=1;}return PWMT_FAILED;}
static inline int pwmt_disjoint(uint64_t a,unsigned n,uint64_t b,unsigned m)
{return pwma_span(a,n)&&pwma_span(b,m)&&!pwma_overlap(a,n,b,m);}
static inline int pwmt_time(struct pwmt_transaction*t,uint64_t now)
{
    if(!now||now<t->last||now<t->opening||now-t->opening>PWMT_TICKS)return pwmt_fail(t,PWMT_TIME);
    t->last=now;return 1;
}
static inline int pwmt_begin_profile(struct pwmt_transaction*t,struct pwma_page*page,
    const struct pwma_spec*spec,uint64_t now,uint64_t frequency,unsigned modem)
{
    if(!t||!page||!spec||!now||frequency!=19200000||
       !pwmt_disjoint((uintptr_t)t,sizeof(*t),(uintptr_t)page,sizeof(*page))||
       !pwmt_disjoint((uintptr_t)t,sizeof(*t),(uintptr_t)spec,sizeof(*spec))||
       !pwmt_zero(t,sizeof(*t)))return PWMT_FAILED;
    if(!pwma_encode_profile(page,&t->initial,spec,modem))return PWMT_FAILED;
    t->page=(uintptr_t)page;t->spec=*spec;t->next=t->initial;
    for(unsigned k=0;k<4096;k++)t->expected[k]=page->data[k];
    t->started=1;t->opening=t->last=now;t->step=PWMT_CLEAN;return PWMT_WAIT;
}
static inline int pwmt_begin(struct pwmt_transaction*t,struct pwma_page*page,
    const struct pwma_spec*spec,uint64_t now,uint64_t frequency)
{return pwmt_begin_profile(t,page,spec,now,frequency,0);}
static inline int pwmt_begin_modem(struct pwmt_transaction*t,struct pwma_page*page,
    const struct pwma_spec*spec,uint64_t now,uint64_t frequency)
{return pwmt_begin_profile(t,page,spec,now,frequency,1);}
static inline int pwmt_page_equal(const struct pwmt_transaction*t)
{return pwmt_equal(t->expected,(const void*)(uintptr_t)t->page,4096);}
/* Reading descriptor bytes before CLEAN or the FIRST SMC does not dirty them.
 * No descriptor read occurs after issuing SMC until post-return invalidation.
 * In particular an interrupted continuation never re-cleans or re-encodes it. */
static inline int pwmt_next(struct pwmt_transaction*t,uint64_t now,struct pwmt_command*out)
{
    if(!t||!out||!t->started)return PWMT_FAILED;
    if(!pwmt_disjoint((uintptr_t)t,sizeof(*t),(uintptr_t)out,sizeof(*out))||
       !pwmt_disjoint(t->page,4096,(uintptr_t)out,sizeof(*out)))return pwmt_fail(t,PWMT_ARGUMENT);
    if(t->unknown||t->error)return PWMT_FAILED;
    if(t->pending)return pwmt_fail(t,PWMT_REENTRY);
    if(t->complete)return t->complete==1&&t->step==PWMT_DONE?PWMT_ZERO:pwmt_fail(t,PWMT_REENTRY);
    if(t->step<PWMT_CLEAN||t->step>PWMT_INVALIDATE||t->events>=PWMT_EVENTS||t->rounds>PWMT_ROUNDS)
        return pwmt_fail(t,PWMT_REENTRY);
    if(pwmt_time(t,now)<0)return PWMT_FAILED;
    if((t->step==PWMT_CLEAN||(t->step==PWMT_SMC&&!t->rounds))&&!pwmt_page_equal(t))
        return pwmt_fail(t,PWMT_CHANGED_PAGE);
    if(t->step==PWMT_SMC&&t->rounds==PWMT_ROUNDS)return pwmt_fail(t,PWMT_LIMIT);
    struct pwmt_command command={.page=t->page,.sequence=t->events+1,.operation=t->step};
    if(t->step==PWMT_SMC)command.registers=t->next;
    struct pwmt_event*e=&t->event[t->events++];e->command=command;e->before=now;e->issued=1;
    t->pending=command.sequence;*out=command;return PWMT_IO;
}
/* Completion receives exactly one typed cache/SMC result. Control matching is
 * checked before storing raw outputs. Caller execution and source envelopes
 * remain a separate obligation, not a callback bool supplied to this engine. */
static inline int pwmt_complete(struct pwmt_transaction*t,const struct pwmt_command*command,
    uint64_t now,int returned,const struct pwma_registers*response,const struct pwmk_record*cache)
{
    if(!t||!command||!t->started||t->unknown||t->error)return PWMT_FAILED;
    if((response&&(!pwmt_disjoint((uintptr_t)t,sizeof(*t),(uintptr_t)response,sizeof(*response))||
          !pwmt_disjoint(t->page,4096,(uintptr_t)response,sizeof(*response))))||
       (cache&&(!pwmt_disjoint((uintptr_t)t,sizeof(*t),(uintptr_t)cache,sizeof(*cache))||
          !pwmt_disjoint(t->page,4096,(uintptr_t)cache,sizeof(*cache)))))return pwmt_fail(t,PWMT_ARGUMENT);
    if(!t->pending||t->pending!=t->events||t->events>PWMT_EVENTS)return pwmt_fail(t,PWMT_REENTRY);
    struct pwmt_event*e=&t->event[t->events-1];
    if(e->returned||e->issued!=1||e->command.page!=t->page||e->command.operation!=t->step||
       e->command.sequence!=t->pending||!pwmt_equal(command,&e->command,sizeof(*command)))
        return pwmt_fail(t,PWMT_REENTRY);
    e->after=now;e->return_raw=returned;e->returned=returned==1?1u:0u;
    if(t->step==PWMT_SMC){
        if(!response||cache)return pwmt_fail(t,PWMT_ARGUMENT);
        e->response=*response;if(returned==1)t->rounds++;
    }else{
        if(!cache||response)return pwmt_fail(t,PWMT_ARGUMENT);e->cache=*cache;
    }
    if(returned!=1)return pwmt_fail(t,PWMT_RETURN);
    if(pwmt_time(t,now)<0)return PWMT_FAILED;
    if(t->step==PWMT_SMC){
        enum pwma_return result=pwma_classify(&e->response);
        if(result==PWMA_RETURN_UNKNOWN)return pwmt_fail(t,PWMT_TRANSPORT);
        if(result==PWMA_RETURN_INTERRUPTED){
            if(t->rounds==PWMT_ROUNDS)return pwmt_fail(t,PWMT_LIMIT);
            t->next=e->response;
        }else t->step=PWMT_INVALIDATE;
    }else{
        unsigned operation=t->step==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE;
        if(!pwmk_record_valid(&e->cache,t->page,operation))return pwmt_fail(t,PWMT_CACHE);
        if(!pwmt_page_equal(t))return pwmt_fail(t,PWMT_CHANGED_PAGE);
        if(t->step==PWMT_CLEAN)t->step=PWMT_SMC;
        else{t->step=PWMT_DONE;t->complete=1;}
    }
    t->pending=0;return t->complete?PWMT_ZERO:PWMT_WAIT;
}
#endif
