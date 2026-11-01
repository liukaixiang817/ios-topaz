/* Software register peer, never original firmware or physical MMIO. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-rsc-read.h"
static struct pwrr_transaction q,good;
static uint32_t reg[0x3000/4],saved[0x3000/4];
static uint32_t answers[3]={0,4,7};
static unsigned fault,reads,writes,triggers,acks,pending,polls,selected;
static uint64_t now;
static const uint32_t addresses[3]={0x30000,0x30010,0x30060};
static unsigned off(uint64_t at){assert(at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(reg)&&!(at&3));return (unsigned)(at-PWRSC_BASE);}
static int clock_peer(void *ctx,uint64_t *t,uint64_t *f)
{
    (void)ctx;if(fault!=21&&!(fault==15&&triggers))now+=100;
    if(pending&&(fault==6||fault==10||fault==22))now+=15000;
    if(fault==12&&triggers)now+=1000000;
    *t=(fault==14&&triggers)?1:now;*f=(fault==13&&triggers)?1:19200000;return 1;
}
static void complete(void)
{
    unsigned t=PWRSC_STRIDE*selected,k=triggers-1;
    reg[4/4]|=1u<<selected;reg[(t+0x14)/4]&=~PWRSC_TRIGGER;
    reg[(t+0x18)/4]=(fault==10||fault==11)?0:1;
    reg[(t+0x3c)/4]=PWRSC_DONE;
    reg[(t+0x40)/4]=fault==23?UINT32_MAX:answers[k];
    if(fault==7)reg[(t+0x3c)/4]&=~(1u<<16);
    if(fault==8)reg[4/4]|=1u<<7;
    if(fault==9)reg[(t+0x3c)/4]|=4;
    pending=0;
}
static int read_peer(void *ctx,uint64_t at,uint32_t *v)
{
    (void)ctx;unsigned o=off(at);reads++;
    if(o==4&&pending){
        polls++;
        if(fault!=6&&fault!=15&&!(fault==22&&triggers==2)&&polls>=2)complete();
    }
    if(fault==11&&triggers&&o==PWRSC_STRIDE*selected+0x40&&q.response_seen)reg[o/4]^=1;
    if(fault==18&&acks==1&&o==0)reg[0]^=1;
    if(fault==19&&acks==1&&o==PWRSC_STRIDE*selected+0x38)reg[o/4]^=1;
    *v=reg[o/4];
    if(fault==17&&q.io.phase==7&&o==PWRSC_STRIDE*selected+0x34)*v^=1;
    return !(fault==5&&writes&&o==4);
}
static int write_peer(void *ctx,uint64_t at,uint32_t v)
{
    (void)ctx;unsigned o=off(at);writes++;
    assert(q.io.outstanding&&q.io.history[q.io.events-1].issued&&q.io.history[q.io.events-1].unknown);
    assert(o!=0&&o!=0xc); /* No IRQ enable or type write. */
    if(o==8){
        assert(v==(1u<<selected)&&reg[4/4]==v&&reg[(PWRSC_STRIDE*selected+0x3c)/4]==PWRSC_DONE);
        if(fault!=20)reg[4/4]&=~v;acks++;return fault!=16;
    }
    assert(o/PWRSC_STRIDE==selected);
    unsigned within=o%PWRSC_STRIDE;
    assert(within==0x10||within==0x14||within==0x1c||within==0x30||within==0x34);
    reg[o/4]=v;
    if(within==0x14&&(v&PWRSC_TRIGGER)){
        assert(!pending&&triggers==acks&&triggers<3);
        unsigned t=PWRSC_STRIDE*selected;
        assert(reg[(t+0x30)/4]==PWRR_MESSAGE&&reg[(t+0x34)/4]==addresses[triggers]);
        assert(reg[(t+0x38)/4]==saved[(t+0x38)/4]&&reg[(t+0x1c)/4]==1);
        triggers++;pending=1;polls=0;reg[(t+0x18)/4]=0;
        if(fault==24)complete();
    }
    return !(fault==4&&writes==5);
}
static void order_peer(void *ctx){(void)ctx;}
static struct pwrsc_io io={0,read_peer,write_peer,clock_peer,order_peer};
static void setup(unsigned f)
{
    memset(&q,0,sizeof(q));memset(reg,0,sizeof(reg));fault=f;reads=writes=triggers=acks=pending=polls=0;now=100;
    reg[0]=(1u<<1)|(1u<<3);selected=3;
    reg[(PWRSC_STRIDE+0x18)/4]=1;reg[(PWRSC_STRIDE+0x1c)/4]=1; /* Busy first candidate. */
    unsigned t=PWRSC_STRIDE*selected;reg[(t+0x18)/4]=1;reg[(t+0x10)/4]=0x18;
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)reg[(t+0x30+20*k+4*j)/4]=0xabc000+8*k+j;
    if(f==1)reg[4/4]=1u<<3;
    if(f==2)reg[0]=0;
    if(f==3)reg[(t+0x1c)/4]=1;
    memcpy(saved,reg,sizeof(reg));
}
static int run(unsigned f)
{
    setup(f);if(!pwrr_begin(&io,&q,(1u<<1)|(1u<<3)))return 0;
    int result=0;for(unsigned k=0;k<260&&!result;k++)result=pwrr_step(&io,&q);
    return result==1;
}
static void RW_restored(void)
{
    unsigned t=PWRSC_STRIDE*selected;
    assert(reg[0]==saved[0]&&!reg[4/4]);
    for(unsigned j=0;j<3;j++)assert(reg[(t+(uint32_t[]){0x10,0x14,0x1c}[j])/4]==saved[(t+(uint32_t[]){0x10,0x14,0x1c}[j])/4]);
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)assert(reg[(t+0x30+20*k+4*j)/4]==saved[(t+0x30+20*k+4*j)/4]);
}
int main(void)
{
    unsigned checks=0;assert(run(0)&&pwrr_retired(&q));RW_restored();assert(triggers==3&&acks==3&&q.io.tcs==3);
    assert(q.valid==7&&q.response[0]==0&&q.response[1]==4&&q.response[2]==7);good=q;checks++;
    assert(run(24)&&pwrr_retired(&q));RW_restored();checks++;
    assert(run(23)&&pwrr_retired(&q)&&q.response[0]==UINT32_MAX); /* RAW is not a qualified ARC level. */checks++;
    for(unsigned f=1;f<=22;f++){
        int ok=run(f);
        if(ok||!q.io.error||pwrr_retired(&q))fprintf(stderr,"fault%u ok%d err%u unknown%u phase%u writes%u triggers%u ack%u steps%u\n",f,ok,q.io.error,q.io.unknown,q.io.phase,writes,triggers,acks,q.io.steps);
        assert(!ok&&q.io.error&&!pwrr_retired(&q));
        if(writes)assert(q.io.unknown);else assert(!q.io.unknown);
        unsigned before=writes;assert(pwrr_step(&io,&q)==-1&&writes==before);checks++;
    }
    setup(0);assert(pwrr_begin(&io,&q,8));unsigned before=reads+writes;
    assert(!pwrr_begin(&io,&q,8)&&reads+writes==before);checks++;
    const uint64_t denied[]={PWRSC_BASE,PWRSC_BASE+0xc,PWRSC_BASE+PWRSC_STRIDE*3+0x38,
        PWRSC_BASE+PWRSC_STRIDE*3+0x44,PWRSC_BASE+PWRSC_STRIDE*2+0x30};
    for(unsigned n=0;n<sizeof(denied)/sizeof(denied[0]);n++){
        setup(0);assert(pwrr_begin(&io,&q,8));uint32_t v=0;assert(!pwrr_access(&io,&q,denied[n],&v,1)&&!writes);checks++;
    }
    for(unsigned n=0;n<good.io.events;n++){
        q=good;q.io.history[n].returned=0;assert(!pwrr_retired(&q));checks++;
        q=good;q.io.history[n].unknown=1;assert(!pwrr_retired(&q));checks++;
        q=good;q.io.history[n].after=q.io.history[n].before-1;assert(!pwrr_retired(&q));checks++;
    }
    for(unsigned n=0;n<good.io.events;n++)if(good.io.history[n].operation==2){
        q=good;q.io.history[n].value^=0x80000000;assert(!pwrr_retired(&q));checks++;
    }
    q=good;q.response[0]=1;assert(!pwrr_retired(&q));checks++;
    q=good;q.io.saved.command[0][2]^=1;assert(!pwrr_retired(&q));checks++;
    q=good;q.io.saved_vote[0]=0xf;assert(!pwrr_retired(&q));checks++;
    q=good;q.io.events--;assert(!pwrr_retired(&q));checks++;
    q=good;q.valid=0;assert(!pwrr_retired(&q));checks++;
    printf("{\"passed\":true,\"checks\":%u,\"raw_bytes\":%zu,\"full_prefix_events\":%u,\"single_outstanding_reads\":3,\"resource_vote_writes\":0,\"CMD_DATA_writes\":0,\"actual_MMIO\":false,\"ARC_response_semantics_qualified\":false,\"physical_caller_registered\":false}\n",checks,sizeof(q),good.io.events);
    return 0;
}
