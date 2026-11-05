/* WCN3990 CE register initialization, derived from primary ath10k ce.c/hw.c.
 * Own DT supplies ICNSS18800000. Caller provides current power/SMMU/CPU and
 * freshly zeroed independent backing. This protocol alone grants no DMA. */
#ifndef POLARIS_WIFI_CE_INIT_H
#define POLARIS_WIFI_CE_INIT_H
#include "polaris-wifi-ce-memory.h"
#define PWCE_BASE UINT64_C(0x18a40000)
#define PWCE_WRAPPER UINT64_C(0x18a4c000)
#define PWCE_EVENTS 512u
enum pwce_operation {PWCE_READ=1,PWCE_WRITE=2,PWCE_ORDER=3};
struct pwce_command {uint64_t address;uint32_t operation,value,sequence,stage,pipe,index;};
struct pwce_pipe_state {uint32_t ctrl,host_ie,misc_ie,source_read,source_write,dest_read,dest_write;};
struct pwce_init {
    uint64_t epoch,opening,last;struct pwdm_layout layout;
    struct pwce_pipe_state pipe[12];struct pwce_command command;
    uint32_t started,unknown,error,pending,events,stage,current,index,verify,complete;
};
static inline int pwce_register(uint64_t address,unsigned write)
{
    if(address==PWCE_WRAPPER+4||address==PWCE_WRAPPER+8)return 1;
    if(address<PWCE_BASE||address>=PWCE_WRAPPER||(address&3))return 0;
    unsigned pipe=(unsigned)((address-PWCE_BASE)/4096),at=(unsigned)(address&4095);
    const struct pwcn_host_pipe*p=&polaris_wcn3990_host[pipe];
    if(at==0x18||at==0x2c||at==0x34)return 1;
    if(!write&&at==0x38)return 1;
    if(p->source_entries&&(at==0||at==4||at==8||at==0x4c||(!write&&(at==0x44||at==0x3c))))return 1;
    return p->destination_entries&&(at==0xc||at==0x10||at==0x14||at==0x50||(!write&&(at==0x48||at==0x40)));
}
static inline int pwce_equal(const void*a,const void*b,size_t n)
{const uint8_t*x=a,*y=b;for(size_t j=0;j<n;j++)if(x[j]!=y[j])return 0;return 1;}
static inline int pwce_zero(const void*p,size_t n)
{const uint8_t*b=p;for(size_t j=0;j<n;j++)if(b[j])return 0;return 1;}
static inline int pwce_fail(struct pwce_init*s,unsigned e)
{s->unknown=1;if(!s->error)s->error=e;return -1;}
static inline int pwce_begin(struct pwce_init*s,const struct pwdm_layout*l,uint64_t epoch,uint64_t now)
{
    struct pwdm_layout expected={0};
    if(!s||!l||!epoch||!now||!pwce_zero(s,sizeof(*s))||!pwdm_plan(&expected,l->allocation)||!pwce_equal(l,&expected,sizeof(*l)))return -1;
    s->layout=*l;s->epoch=epoch;s->opening=s->last=now;s->started=1;return 1;
}
/* The entire host-owned side is observed before the first store. Opposite
 * firmware-owned rings are not read, adopted or overwritten. */
static inline unsigned pwce_read_offset(const struct pwdm_pipe*p,unsigned i)
{
    const unsigned common[]={0x18,0x2c,0x34,0x38};
    const unsigned source[]={0,4,8,0x44,0x3c},destination[]={0x0c,0x10,0x14,0x48,0x40};
    if(i<4)return common[i];i-=4;
    if(p->sources){if(i<5)return source[i];i-=5;}
    return destination[i];
}
static inline unsigned pwce_writes(const struct pwdm_pipe*p)
{return 3u+(p->sources?4u:0u)+(p->destinations?4u:0u);}
static inline void pwce_store(const struct pwce_init*s,unsigned pipe,unsigned i,unsigned*offset,uint32_t*value)
{
    const struct pwdm_pipe*p=&s->layout.pipe[pipe];const struct pwce_pipe_state*q=&s->pipe[pipe];
    if(i==0){*offset=0x2c;*value=q->host_ie&~0x1fu;return;}
    if(i==1){*offset=0x34;*value=q->misc_ie&~0x3e0u;return;}
    if(i==2){
        *offset=0x18;*value=q->ctrl|0x80000;
        if(p->sources)*value=(*value&~0x2ffffu)|p->buffer_bytes;
        if(p->destinations)*value&=~0x40000u;return;
    }i-=3;
    if(p->sources){
        if(i<4){uint64_t at=s->layout.allocation+p->source;const unsigned offsets[]={0,4,8,0x4c};
            *offset=offsets[i];*value=i==0?(uint32_t)at:i==1?(uint32_t)(at>>32):p->sources;return;}i-=4;
    }
    uint64_t at=s->layout.allocation+p->destination;const unsigned offsets[]={0xc,0x10,0x14,0x50};
    *offset=offsets[i];*value=i==0?(uint32_t)at:i==1?(uint32_t)(at>>32):p->destinations;
}
static inline int pwce_next(struct pwce_init*s,uint64_t now,struct pwce_command*out)
{
    if(!s||!out||!s->started||s->unknown||s->error)return -1;
    if(s->pending||now<s->last||now-s->opening>19200000||s->events>=PWCE_EVENTS)return pwce_fail(s,1);
    s->last=now;if(s->complete)return 2;
    if(s->stage>2||s->current>=12||s->verify>2)return pwce_fail(s,1);
    const struct pwdm_pipe*p=&s->layout.pipe[s->current];
    unsigned count=s->stage==0?4u+(p->sources?5u:0u)+(p->destinations?5u:0u):s->stage==1?2u:pwce_writes(p);
    if(s->index>=count)return pwce_fail(s,1);
    struct pwce_command c={.sequence=s->events+1,.stage=s->stage,.pipe=s->current,.index=s->index};
    if(!s->stage){c.address=PWCE_BASE+4096*s->current+pwce_read_offset(&s->layout.pipe[s->current],s->index);c.operation=PWCE_READ;}
    else{
        if(s->stage==1){uint64_t at=s->layout.allocation+s->layout.rri;
            c.address=PWCE_WRAPPER+4+4*s->index;c.value=s->index?(uint32_t)(at>>32):(uint32_t)at;
        }else{unsigned offset;pwce_store(s,s->current,s->index,&offset,&c.value);c.address=PWCE_BASE+4096*s->current+offset;}
        c.operation=s->verify==2?PWCE_READ:s->verify==1?PWCE_ORDER:PWCE_WRITE;
        if(c.operation==PWCE_ORDER)c.address=c.value=0;
    }
    s->command=c;s->pending=1;*out=c;return 1;
}
static inline int pwce_complete(struct pwce_init*s,const struct pwce_command*c,uint64_t now,int returned,uint32_t value)
{
    if(!s||!c||!s->started||s->unknown||s->error)return -1;
    if(!s->pending||!pwce_equal(c,&s->command,sizeof(*c))||now<s->last||now-s->opening>19200000||returned!=1)return pwce_fail(s,2);
    s->last=now;s->pending=0;s->events++;
    const struct pwdm_pipe*p=&s->layout.pipe[s->current];struct pwce_pipe_state*q=&s->pipe[s->current];
    if(!s->stage){
        if(!s->index)q->ctrl=value;else if(s->index==1)q->host_ie=value;else if(s->index==2)q->misc_ie=value;
        else if(s->index==3){if(value&0x3e0)return pwce_fail(s,3);}
        else{
            unsigned i=s->index-4,destination=0;if(!p->sources||i>=5){if(p->sources)i-=5;destination=1;}
            if(i<3){if(value)return pwce_fail(s,4);}
            else{
                unsigned entries=destination?p->destinations:p->sources;
                if(value&0xffff0000u)return pwce_fail(s,4);value&=entries-1;
                if(destination){if(i==3)q->dest_read=value;else q->dest_write=value;}
                else{if(i==3)q->source_read=value;else q->source_write=value;}
            }
        }
        if(++s->index==4u+(p->sources?5u:0u)+(p->destinations?5u:0u)){
            if(q->source_read!=q->source_write||q->dest_read!=q->dest_write)return pwce_fail(s,5);
            s->index=0;if(++s->current==12){s->stage=1;s->current=0;}
        }
    }else{
        if(!s->verify){s->verify=1;return 1;}
        if(s->verify==1){s->verify=2;return 1;}
        if(value!=c->value)return pwce_fail(s,6);s->verify=0;s->index++;
        if(s->stage==1){if(s->index==2){s->stage=2;s->index=0;}}
        else if(s->index==pwce_writes(p)){s->index=0;if(++s->current==12){s->complete=1;return 2;}}
    }return 1;
}
#endif
