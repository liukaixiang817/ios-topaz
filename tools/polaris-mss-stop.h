/* Ordered local protocol composition: fresh SMP2P ACK then three-port AXI
 * halt. No native backend or reset/cache/MPU handback. BOTH requests stay held.
 * The external owner retains the same live MSS generation and all resources
 * throughout. This result is a prerequisite, never a full DMA-stop grant. */
#ifndef POLARIS_MSS_STOP_H
#define POLARIS_MSS_STOP_H
#include "polaris-mss-smp2p-stop.h"
#include "polaris-mss-axi-halt.h"
enum pmss_result {PMSS_FAILED=-1,PMSS_WAIT,PMSS_IO,PMSS_HELD};
struct pmss_command {uint32_t phase,reserved;union {struct pms_command stop;struct pmh_command halt;} command;};
struct pmss_stop {
    uint32_t phase,unknown,pending,complete;
    struct pmss_command command;
    struct pms_stop stop;struct pmh_halt halt;
};
static inline int pmss_fail(struct pmss_stop*s)
{if(s)s->unknown=1;return PMSS_FAILED;}
static inline int pmss_begin(struct pmss_stop*s,const struct pms_config*c,uint64_t now,uint64_t hz)
{
    if(!s||!c||!pms_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)c,sizeof(*c))||!pms_zero(s,sizeof(*s)))return PMSS_FAILED;
    if(pms_begin(&s->stop,c,now,hz)<0)return pmss_fail(s);
    s->phase=1;return PMSS_WAIT;
}
static inline int pmss_next(struct pmss_stop*s,uint64_t now,struct pmss_command*out)
{
    if(!s||!out||s->unknown)return PMSS_FAILED;
    if(!pms_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)out,sizeof(*out))||s->pending)return pmss_fail(s);
    if(s->complete)return s->complete==1&&s->phase==3?PMSS_HELD:pmss_fail(s);
    struct pmss_command command={.phase=s->phase};int result;
    if(s->phase==1)result=pms_next(&s->stop,now,&command.command.stop);
    else if(s->phase==2)result=pmh_next(&s->halt,now,&command.command.halt);
    else return pmss_fail(s);
    if(result<0)return pmss_fail(s);
    if(!result)return PMSS_WAIT;
    if(result!=1)return pmss_fail(s); /* Completion alone advances phases. */
    s->command=command;s->pending=1;*out=command;return PMSS_IO;
}
static inline int pmss_complete(struct pmss_stop*s,const struct pmss_command*c,
    uint64_t now,int returned,uint32_t value,const struct pms_sample*sample)
{
    if(!s||!c||s->unknown)return PMSS_FAILED;
    if(sample&&!pms_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)sample,sizeof(*sample)))return pmss_fail(s);
    if(!s->pending||c->phase!=s->phase||!pms_equal(c,&s->command,sizeof(*c)))return pmss_fail(s);
    int result;
    if(s->phase==1){
        result=pms_complete(&s->stop,&c->command.stop,now,returned,value,sample);
        if(result==PMS_ACK_HELD){
            /* AXI's own timeout starts only after the stop ACK was observed. */
            if(pmh_begin(&s->halt,now,19200000)<0)return pmss_fail(s);s->phase=2;
        }
    }else if(s->phase==2){
        if(sample)return pmss_fail(s);
        result=pmh_complete(&s->halt,&c->command.halt,now,returned,value);
        if(result==PMH_HELD){s->phase=3;s->complete=1;}
    }else return pmss_fail(s);
    if(result<0)return pmss_fail(s);s->pending=0;
    return s->complete?PMSS_HELD:PMSS_WAIT;
}
#endif
