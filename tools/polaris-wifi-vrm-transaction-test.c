/* SOFTWARE TCS/VRM peer. No firmware, native CPU, MMIO, radio or device. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define EFI_XNU_WIFI_FOUR_VRM_AVAILABLE 1
#define EFI_XNU_WIFI_CURRENT_WORD_READ 1
#include "polaris-wifi-vrm-transaction.h"
static struct pwvm_transaction q,good;
static uint32_t reg[0x3000/4],initial[0x3000/4],votes[4][4],original[4][4],high_values[4];
static unsigned fault,reads,writes,edges,acks,polls,pending,slot,clocks;
static uint32_t status_pattern=0xffff;
static uint64_t ticks;
static const uint32_t base[4]={0x40f00,0x41300,0x40c00,0x42000};
static const struct pwvm_rail rail[4]={{0x40f00,0,0,5,800},{0x41300,1800,1,7,1800},
    {0x40c00,0,0,5,1304},{0x42000,3200,1,7,3104}};
static unsigned off(uint64_t at){assert(at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(reg)&&!(at&3));return (unsigned)(at-PWRSC_BASE);}
static int clock_peer(void *c,uint64_t *time,uint64_t *frequency)
{
    (void)c;clocks++;ticks+=100;if(fault==12&&edges)ticks+=960000;
    if(fault==15&&!writes&&q.io.events&&q.io.history[q.io.events-1].operation==2)q.rail[0].address+=8;
    *time=ticks;*frequency=fault==11&&edges?1:19200000;return 1;
}
static void complete(void)
{
    unsigned t=slot*PWRSC_STRIDE,restore=edges>4,k=restore?8-edges:edges-1;
    assert(reg[(t+0x1c)/4]==3);
    for(unsigned j=0;j<2;j++){
        uint32_t address=reg[(t+0x34+20*j)/4],value=reg[(t+0x38+20*j)/4];
        assert(reg[(t+0x30+20*j)/4]==0x10108);
        /* Independently assert external logical rail/field order and values. */
        assert(address==base[k]+(restore?(j?0:4):(j?4:0)));
        unsigned field=(address-base[k])/4;
        uint32_t expected=restore?original[k][field]:field==1?1:
            (original[k][0]>pwvm_min_mV[k]?original[k][0]:pwvm_min_mV[k]);
        assert(value==expected);votes[k][field]=value;
        reg[(t+0x3c+20*j)/4]=fault==7&&j==1?0x10000:fault==8&&j==1?0x10105:
            0x10100u|((status_pattern>>(2*(edges-1)+j))&1u);
        reg[(t+0x40+20*j)/4]=0x4000+edges*2+j;
    }
    if(!restore)high_values[k]=votes[k][0];
    reg[1]|=1u<<slot;if(fault==6)reg[1]|=0x80;
    reg[(t+0x18)/4]=1;pending=0;
}
static int read_peer(void *c,uint64_t at,uint32_t *value)
{
    (void)c;unsigned o=off(at);reads++;
    if(o==4&&pending){polls++;if(polls==2)complete();}
    *value=reg[o/4];
    if(fault==5&&writes==1&&o==slot*PWRSC_STRIDE+0x14)*value^=1;
    if(fault==10&&q.io.phase==17&&o==slot*PWRSC_STRIDE+0x38+40)*value^=1;
    return !(fault==13&&edges&&o==4);
}
static int write_peer(void *c,uint64_t at,uint32_t value)
{
    (void)c;unsigned o=off(at);writes++;
    assert(q.io.outstanding==q.io.events&&q.io.history[q.io.events-1].issued&&q.io.history[q.io.events-1].unknown);
    assert(o!=0&&o!=12);
    if(fault==4&&writes==1)return 0;
    if(o==8){assert(value==(1u<<slot)&&q.io.completed==edges);acks++;
        if(fault!=9)reg[1]&=~value;
        if(fault==14&&acks==3)reg[0]^=0x40;
        return 1;
    }
    uint32_t old=reg[o/4];reg[o/4]=value;
    if(o==slot*PWRSC_STRIDE+0x14&&(value&PWRSC_TRIGGER)){
        assert(!(old&PWRSC_TRIGGER)&&edges==acks);edges++;assert(edges<=8);pending=1;polls=0;
        reg[(slot*PWRSC_STRIDE+0x18)/4]=0;
        for(unsigned j=0;j<2;j++)reg[(slot*PWRSC_STRIDE+0x3c+20*j)/4]=0;
    }return 1;
}
static void order_peer(void *c){(void)c;}
static const struct pwrsc_io io={0,read_peer,write_peer,clock_peer,order_peer};
static void reset(unsigned f,unsigned chosen,unsigned high,unsigned earlier_busy)
{
    memset(&q,0,sizeof(q));memset(reg,0,sizeof(reg));fault=f;reads=writes=edges=acks=polls=pending=clocks=0;ticks=1000;slot=chosen;
    reg[0]=1u<<slot;if(earlier_busy)reg[0]|=1;
    for(unsigned k=0;k<8;k++){
        unsigned t=k*PWRSC_STRIDE;reg[(t+0x18)/4]=1;reg[(t+0x10)/4]=0x80;
        if(k==slot){reg[(t+0x14)/4]=high?0x1010000:0x10000;reg[(t+0x1c)/4]=high?1:0;}
        else reg[(t+0x1c)/4]=2;
        for(unsigned j=0;j<3;j++){reg[(t+0x30+20*j)/4]=0x210+j;reg[(t+0x34+20*j)/4]=0x50000+j*4;
            reg[(t+0x38+20*j)/4]=0x430+j;reg[(t+0x3c+20*j)/4]=0x10101;reg[(t+0x40+20*j)/4]=0x40+j;}
    }
    for(unsigned k=0;k<4;k++){votes[k][0]=rail[k].saved_mV;votes[k][1]=rail[k].saved_enable;votes[k][2]=rail[k].saved_mode;votes[k][3]=13+k;high_values[k]=0;}
    if(f==1)reg[0]=0;if(f==2)reg[1]=0x80;if(f==3)reg[(slot*PWRSC_STRIDE+0x18)/4]=0;
    memcpy(initial,reg,sizeof(reg));memcpy(original,votes,sizeof(votes));
}
static int run(unsigned f,unsigned slot,unsigned high,unsigned earlier_busy)
{
    reset(f,slot,high,earlier_busy);if(!pwvm_begin(&io,&q,15,rail))return -1;
    int result=0;for(unsigned n=0;n<256&&!result;n++)result=pwvm_step(&io,&q);return result;
}
static void check_success(void)
{
    assert(pwvm_retired(&q)&&q.io.triggers==8&&q.io.completed==8&&q.io.acknowledged==8&&edges==8&&acks==8);
    assert(!memcmp(votes,original,sizeof(votes))&&high_values[0]==800&&high_values[1]==1800&&high_values[2]==1304&&high_values[3]==3200);
    unsigned t=slot*PWRSC_STRIDE;assert(reg[0]==initial[0]&&!reg[1]&&reg[(t+0x14)/4]==initial[(t+0x14)/4]&&reg[(t+0x1c)/4]==initial[(t+0x1c)/4]&&reg[(t+0x10)/4]==initial[(t+0x10)/4]);
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)assert(reg[(t+0x30+20*k+4*j)/4]==initial[(t+0x30+20*k+4*j)/4]);
    for(unsigned k=0;k<8;k++)if(k!=slot)for(unsigned j=0;j<PWRSC_STRIDE/4;j++){
        unsigned o=k*PWRSC_STRIDE/4+j;if(o>2)assert(reg[o]==initial[o]);
    }
}
int main(void)
{
    unsigned checks=0;
    for(unsigned high=0;high<2;high++)for(unsigned chosen=0;chosen<4;chosen++){
        assert(run(0,chosen,high,chosen>0)==1);check_success();checks++;
    }
    for(unsigned bit=0;bit<16;bit++){
        status_pattern=0xffffu^(1u<<bit);assert(run(0,0,1,0)==1);check_success();checks++;
    }
    status_pattern=0;assert(run(0,0,1,0)==1);check_success();checks++;status_pattern=0xffff;
    assert(run(0,0,1,0)==1);check_success();good=q;
    for(unsigned n=0;n<good.io.events;n++){
        q=good;q.io.history[n].issued=0;assert(!pwvm_retired(&q));checks++;
        q=good;q.io.history[n].returned=0;assert(!pwvm_retired(&q));checks++;
        q=good;q.io.history[n].unknown=1;assert(!pwvm_retired(&q));checks++;
        q=good;q.io.history[n].phase^=1;assert(!pwvm_retired(&q));checks++;
        q=good;q.io.history[n].address^=4;assert(!pwvm_retired(&q));checks++;
    }
    for(unsigned n=0;n<good.io.events;n++)if(good.io.history[n].operation==2){
        q=good;q.io.history[n].value^=1;assert(!pwvm_retired(&q));checks++;
    }
    for(unsigned f=1;f<=15;f++){
        assert(run(f,0,1,0)==-1&&!pwvm_retired(&q));
        unsigned old_reads=reads,old_writes=writes;assert(pwvm_step(&io,&q)==-1&&reads==old_reads&&writes==old_writes);
        if(writes)assert(q.io.unknown);checks++;
        if(f==15)assert(!writes&&q.io.unknown);
    }
    for(unsigned n=0;n<4;n++)for(unsigned field=0;field<5;field++){
        reset(0,0,1,0);struct pwvm_rail bad[4];memcpy(bad,rail,sizeof(bad));
        if(field==0)bad[n].address+=4;if(field==1)bad[n].saved_mV=8192;if(field==2)bad[n].saved_enable=2;
        if(field==3)bad[n].saved_mode=2;if(field==4)bad[n].requested_mV=pwvm_max_mV[n]+1;
        assert(!pwvm_begin(&io,&q,15,bad)&&!reads&&!writes&&!clocks&&!q.io.unknown);checks++;
    }
    for(unsigned n=0;n<4;n++){
        reset(0,0,1,0);
        if(n==0)q.io.events=1;if(n==1)q.io.last=1;if(n==2)q.rail[0].address=1;if(n==3)q.io.history[12].issued=1;
        assert(!pwvm_begin(&io,&q,15,rail)&&!reads&&!writes&&!clocks);checks++;
    }
    for(unsigned k=0;k<4;k++)for(unsigned n=0;n<3;n++){
        reset(0,0,1,0);assert(pwvm_begin(&io,&q,15,rail));
        if(n==0)q.rail[k].address+=8;if(n==1)q.rail[k].requested_mV++;if(n==2)q.rail[k].saved_enable=2;
        unsigned before_reads=reads,before_writes=writes;
        assert(pwvm_step(&io,&q)==-1&&reads==before_reads&&writes==before_writes&&!writes&&q.io.unknown);checks++;
    }
    assert(run(0,0,1,0)==1);good=q;unsigned prior_reads=reads,prior_writes=writes,prior_clocks=clocks;
    assert(!pwvm_begin(&io,&q,15,rail)&&!memcmp(&q,&good,sizeof(q))&&reads==prior_reads&&writes==prior_writes&&clocks==prior_clocks);checks++;
    assert(run(0,0,1,0)==1);check_success();q.io.history[q.io.events-1].after--;assert(!pwvm_retired(&q));checks++;
    printf("{\"passed\":true,\"SOFTWARE_only\":true,\"checks\":%u,\"complete_four_supply_raise_reverse_saved_restore\":true,\"no_mode_headroom_or_IRQ_enable_type_store\":true,\"original_50ms_256steps_1024events\":true,\"physical_caller_wired\":false,\"native_or_WiFi_success\":false}\n",checks);
    return 0;
}
