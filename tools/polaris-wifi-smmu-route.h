/* Own c7cb50c1 arm-smmu.c + current Polaris DT APPS SMMU route observation.
 * Read commands only. No stream/CB allocation, write, translation claim from
 * DT alone, or authority for DMA. Native caller supplies current ownership. */
#ifndef POLARIS_WIFI_SMMU_ROUTE_H
#define POLARIS_WIFI_SMMU_ROUTE_H
#include <stdint.h>
#include <stddef.h>
#define PWSU_BASE UINT64_C(0x15000000)
#define PWSU_GROUPS 255u
#define PWSU_READS (2u*(6u+2u*PWSU_GROUPS+10u))
struct pwsu_command {uint64_t address;uint32_t sequence,pass,stage,index;};
struct pwsu_pass {
    uint32_t header[6],smr[PWSU_GROUPS],s2cr[PWSU_GROUPS],context[2][5];
    uint32_t selected[2],type[2],bank[2],groups,banks,s2banks,complete;
};
struct pwsu_route {
    uint64_t epoch,opening,last;uint32_t started,unknown,error,pass,stage,index,pending,reads,complete;
    struct pwsu_command command;struct pwsu_pass sample[2];
};
enum pwsu_result {PWSU_FAILED=-1,PWSU_IO=1,PWSU_OBSERVED=2};
static inline int pwsu_readable(uint64_t address)
{
    if(address<PWSU_BASE||address>=PWSU_BASE+0x80000||(address&3))return 0;
    unsigned at=(unsigned)(address-PWSU_BASE);
    if(at==0||at==0x20||at==0x24||at==0x28||at==0x48||at==0x74)return 1;
    if((at>=0x800&&at<0x800+4*PWSU_GROUPS)||(at>=0xc00&&at<0xc00+4*PWSU_GROUPS))return 1;
    if((at>=0x1000&&at<0x1100)||(at>=0x1800&&at<0x1900))return 1;
    return at>=0x40000&&((at&4095)==0||(at&4095)==0x58||(at&4095)==0x7f4);
}
static inline int pwsu_zero(const void*p,size_t n)
{const uint8_t*b=p;for(size_t j=0;j<n;j++)if(b[j])return 0;return 1;}
static inline int pwsu_equal(const void*a,const void*b,size_t n)
{const uint8_t*x=a,*y=b;for(size_t j=0;j<n;j++)if(x[j]!=y[j])return 0;return 1;}
static inline int pwsu_fail(struct pwsu_route*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return PWSU_FAILED;}
static inline int pwsu_disjoint(const void*a,size_t n,const void*b,size_t m)
{uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x&&y&&n&&m&&x<=UINTPTR_MAX-n&&y<=UINTPTR_MAX-m&&(x+n<=y||y+m<=x);}
static inline int pwsu_begin(struct pwsu_route*s,uint64_t epoch,uint64_t now,uint64_t hz)
{
    if(!s||!epoch||!now||hz!=19200000||!pwsu_zero(s,sizeof(*s)))return PWSU_FAILED;
    s->epoch=epoch;s->opening=s->last=now;s->started=1;return PWSU_IO;
}
/* Fixed4KiB register geometry is derived from ID1 and checked against own
 *512KiB DT aperture before any context-bank address is generated. */
static inline int pwsu_geometry(struct pwsu_pass*p)
{
    uint32_t id0=p->header[0],id1=p->header[1],id2=p->header[2];
    p->groups=id0&255;p->banks=id1&255;p->s2banks=(id1>>16)&255;
    unsigned oas=(id2>>4)&15;
    return (id0&(1u<<27))&&(id0&(1u<<30))&&p->groups&&p->groups<=PWSU_GROUPS&&
        !(id1&0x80000000u)&&((id1>>28)&7)==5&&p->banks&&p->banks<=64&&p->s2banks<=p->banks&&
        oas>=1&&oas<=5&&!(p->header[3]&1)&&!p->header[4]&&!(p->header[5]&1);
}
static inline int pwsu_select(struct pwsu_pass*p)
{
    for(unsigned sid=0;sid<2;sid++){
        unsigned found=0;
        for(unsigned n=0;n<p->groups;n++){
            uint32_t smr=p->smr[n],id=smr&0x7fff,mask=(smr>>16)&0x7fff;
            if(!(smr&0x80000000u)||(((0x40u+sid)^id)&~mask))continue;
            if(++found!=1)return 0;p->selected[sid]=n;p->type[sid]=(p->s2cr[n]>>16)&3;p->bank[sid]=p->s2cr[n]&255;
            if(p->type[sid]>1||(p->type[sid]==0&&(p->bank[sid]>=p->banks||p->bank[sid]<p->s2banks)))return 0;
        }if(found!=1)return 0;
    }return 1;
}
static inline int pwsu_context(struct pwsu_pass*p,unsigned sid)
{
    if(p->type[sid]==1)return pwsu_zero(p->context[sid],sizeof(p->context[sid]));
    const uint32_t*q=p->context[sid];
    /* CBAR=S1 translation/S2 bypass, SCTLR.M=0: vendor's S1-bypass route.
     * FSR and pending TLB sync must be clear. No fault clearing is performed. */
    return ((q[0]>>16)&3)==1&&!(q[2]&1)&&!q[3]&&!(q[4]&1);
}
static inline int pwsu_next(struct pwsu_route*s,uint64_t now,struct pwsu_command*out)
{
    if(!s||!out||!s->started)return PWSU_FAILED;
    if(s->unknown||s->error)return PWSU_FAILED;
    if(!pwsu_disjoint(s,sizeof(*s),out,sizeof(*out))||s->pending||now<s->last||now-s->opening>19200000)return pwsu_fail(s,1);
    s->last=now;if(s->complete)return PWSU_OBSERVED;
    if(s->pass>1||s->stage>2||s->reads==PWSU_READS)return pwsu_fail(s,1);
    struct pwsu_pass*p=&s->sample[s->pass];uint64_t at;
    if(!s->stage){const unsigned offsets[]={0x20,0x24,0x28,0,0x48,0x74};if(s->index>=6)return pwsu_fail(s,1);at=PWSU_BASE+offsets[s->index];}
    else if(s->stage==1){if(s->index>=2*p->groups)return pwsu_fail(s,1);at=PWSU_BASE+(s->index&1?0xc00:0x800)+4*(s->index/2);}
    else{
        unsigned sid=s->index/5,reg=s->index%5;if(sid>=2||p->type[sid]!=0)return pwsu_fail(s,1);
        unsigned bank=p->bank[sid];
        at=reg<2?PWSU_BASE+0x1000+(reg?0x800:0)+4*bank:
            PWSU_BASE+0x40000+4096*bank+(reg==2?0:reg==3?0x58:0x7f4);
    }
    s->command=(struct pwsu_command){at,s->reads+1,s->pass,s->stage,s->index};s->pending=1;*out=s->command;return PWSU_IO;
}
static inline int pwsu_complete(struct pwsu_route*s,const struct pwsu_command*c,uint64_t now,int returned,uint32_t value)
{
    if(!s||!c||!s->started||s->unknown||s->error)return PWSU_FAILED;
    if(!s->pending||!pwsu_disjoint(s,sizeof(*s),c,sizeof(*c))||!pwsu_equal(c,&s->command,sizeof(*c))||
       now<s->last||now-s->opening>19200000||returned!=1)return pwsu_fail(s,2);
    struct pwsu_pass*p=&s->sample[s->pass];s->last=now;s->reads++;s->pending=0;
    if(!s->stage){p->header[s->index++]=value;
        if(s->index==6){if(!pwsu_geometry(p))return pwsu_fail(s,3);s->stage=1;s->index=0;}
    }else if(s->stage==1){
        if(s->index&1)p->s2cr[s->index/2]=value;else p->smr[s->index/2]=value;s->index++;
        if(s->index==2*p->groups){if(!pwsu_select(p))return pwsu_fail(s,4);s->stage=2;s->index=0;}
    }else p->context[s->index/5][s->index%5]=value,s->index++;
    if(s->stage==2){
        if(s->index==0&&p->type[0]==1)s->index=5;
        if(s->index==5&&p->type[1]==1)s->index=10;
        if(s->index==10){
            if(!pwsu_context(p,0)||!pwsu_context(p,1))return pwsu_fail(s,5);p->complete=1;
            if(!p->type[0]&&!p->type[1]&&p->bank[0]==p->bank[1]&&!pwsu_equal(p->context[0],p->context[1],sizeof(p->context[0])))return pwsu_fail(s,5);
            if(s->pass==1){if(!pwsu_equal(&s->sample[0],p,sizeof(*p)))return pwsu_fail(s,6);s->complete=1;return PWSU_OBSERVED;}
            s->pass=1;s->stage=s->index=0;
        }
    }return PWSU_IO;
}
#endif
