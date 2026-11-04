/* Ordered own-MSS protocol: fresh SMP2P stop ACK -> three AXI halts -> reset
 * pulse. This still requires the live native owner, clock/power retirement and
 * secure permission return. RESET_PULSED never authorizes freeing memory. */
#ifndef POLARIS_MSS_SHUTDOWN_H
#define POLARIS_MSS_SHUTDOWN_H
#include "polaris-mss-stop.h"
#include "polaris-mss-reset.h"
enum pmsd_result {PMSD_FAILED=-1,PMSD_WAIT,PMSD_IO,PMSD_RESET_PULSED};
struct pmsd_command {uint32_t phase,reserved;union {struct pmss_command stop;struct pmsr_command reset;} command;};
struct pmsd_shutdown {
    uint32_t phase,unknown,pending,complete;
    struct pmsd_command command;struct pmss_stop stop;struct pmsr_reset reset;
};
static inline int pmsd_fail(struct pmsd_shutdown*s)
{if(s)s->unknown=1;return PMSD_FAILED;}
static inline int pmsd_begin(struct pmsd_shutdown*s,const struct pms_config*c,uint64_t now,uint64_t hz)
{
    if(!s||!c||!pmsr_disjoint(s,sizeof(*s),c,sizeof(*c))||!pms_zero(s,sizeof(*s)))return PMSD_FAILED;
    if(pmss_begin(&s->stop,c,now,hz)<0)return pmsd_fail(s);
    s->phase=1;return PMSD_WAIT;
}
static inline int pmsd_next(struct pmsd_shutdown*s,uint64_t now,struct pmsd_command*out)
{
    if(!s||!out||s->unknown)return PMSD_FAILED;
    if(!pmsr_disjoint(s,sizeof(*s),out,sizeof(*out))||s->pending)return pmsd_fail(s);
    if(s->complete)return s->complete==1&&s->phase==3?PMSD_RESET_PULSED:pmsd_fail(s);
    struct pmsd_command c={.phase=s->phase};int result;
    if(s->phase==1)result=pmss_next(&s->stop,now,&c.command.stop);
    else if(s->phase==2)result=pmsr_next(&s->reset,now,&c.command.reset);
    else return pmsd_fail(s);
    if(result<0)return pmsd_fail(s);
    if(!result)return PMSD_WAIT;
    if(s->phase==2&&result==PMSR_PULSED){s->phase=3;s->complete=1;return PMSD_RESET_PULSED;}
    if(result!=1)return pmsd_fail(s);
    s->command=c;s->pending=1;*out=c;return PMSD_IO;
}
static inline int pmsd_complete(struct pmsd_shutdown*s,const struct pmsd_command*c,
    uint64_t now,int returned,uint32_t value,const struct pms_sample*sample)
{
    if(!s||!c||s->unknown)return PMSD_FAILED;
    if(!pmsr_disjoint(s,sizeof(*s),c,sizeof(*c))||
       (sample&&!pmsr_disjoint(s,sizeof(*s),sample,sizeof(*sample)))||
       !s->pending||c->phase!=s->phase||!pmsr_equal(c,&s->command,sizeof(*c)))return pmsd_fail(s);
    int result;
    if(s->phase==1){
        result=pmss_complete(&s->stop,&c->command.stop,now,returned,value,sample);
        if(result==PMSS_HELD){
            if(pmsr_begin(&s->reset,now,19200000)<0)return pmsd_fail(s);s->phase=2;
        }
    }else if(s->phase==2){
        if(sample)return pmsd_fail(s);
        result=pmsr_complete(&s->reset,&c->command.reset,now,returned,value);
    }else return pmsd_fail(s);
    if(result<0)return pmsd_fail(s);s->pending=0;return PMSD_WAIT;
}
#endif
