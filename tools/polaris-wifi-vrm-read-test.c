/* SOFTWARE peer for sixteen explicit VRM fields; never a resource WRITE. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define EFI_XNU_WIFI_FOUR_VRM_AVAILABLE 1
#define EFI_XNU_WIFI_CURRENT_WORD_READ 1
#include "polaris-wifi-vrm-read.h"
static struct pwvr_transaction q,good;
static uint32_t reg[0x3000/4],initial[0x3000/4];
static const uint32_t base[4]={0x40f00,0x41300,0x40c00,0x42000};
static const uint32_t values[4][4]={{0,0,5,13},{1800,1,7,14},{0,0,5,15},{3200,1,7,16}};
static unsigned fault,reads,writes,edges,acks,pending,polls,slot;
static uint64_t ticks;
static int clock_peer(void*c,uint64_t*t,uint64_t*f)
{(void)c;ticks+=100;if(fault==7&&edges)ticks+=960000;*t=ticks;*f=fault==6&&edges?1:19200000;return 1;}
static unsigned offset(uint64_t at){assert(at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(reg)&&!(at&3));return (unsigned)(at-PWRSC_BASE);}
static int read_peer(void*c,uint64_t at,uint32_t*value)
{
    (void)c;unsigned o=offset(at);reads++;
    if(o==4&&pending&&++polls==2){
        unsigned t=slot*PWRSC_STRIDE,k=(edges-1)/4,field=(edges-1)%4;
        assert(reg[(t+0x30)/4]==0x108&&reg[(t+0x34)/4]==base[k]+4*field&&reg[(t+0x38)/4]==initial[(t+0x38)/4]);
        reg[(t+0x3c)/4]=fault==4?0x10000:fault==5?0x10105:0x10101;
        reg[(t+0x40)/4]=values[k][field];reg[(t+0x18)/4]=1;reg[1]|=1u<<slot;
        if(fault==3)reg[1]|=0x80;pending=0;
    }
    *value=reg[o/4];
    if(fault==9&&q.io.phase==33&&o==slot*PWRSC_STRIDE+0x30)*value^=1;
    return !(fault==8&&edges&&o==4);
}
static int write_peer(void*c,uint64_t at,uint32_t value)
{
    (void)c;unsigned o=offset(at);writes++;
    assert(q.io.outstanding&&q.io.history[q.io.events-1].issued&&q.io.history[q.io.events-1].unknown);
    assert(o!=0&&o!=12);
    if(fault==2&&writes==1)return 0;
    if(o==8){assert(q.io.completed==edges&&value==(1u<<slot));acks++;reg[1]&=~value;return 1;}
    unsigned local=o-slot*PWRSC_STRIDE;
    assert(local==0x10||local==0x14||local==0x1c||local==0x30||local==0x34);
    uint32_t old=reg[o/4];reg[o/4]=value;
    if(local==0x14&&(value&PWRSC_TRIGGER)){
        assert(!(old&PWRSC_TRIGGER)&&edges==acks);edges++;assert(edges<=16);pending=1;polls=0;
        reg[(slot*PWRSC_STRIDE+0x18)/4]=0;reg[(slot*PWRSC_STRIDE+0x3c)/4]=0;
    }return 1;
}
static void order_peer(void*c){(void)c;}
static const struct pwrsc_io io={0,read_peer,write_peer,clock_peer,order_peer};
static int run(unsigned f,unsigned chosen,unsigned high)
{
    fault=f;slot=chosen;reads=writes=edges=acks=pending=polls=0;ticks=1000;memset(&q,0,sizeof(q));memset(reg,0,sizeof(reg));reg[0]=1u<<slot;
    if(chosen)reg[0]|=1;
    for(unsigned k=0;k<8;k++){
        unsigned t=k*PWRSC_STRIDE;reg[(t+0x18)/4]=1;reg[(t+0x10)/4]=0x80;reg[(t+0x1c)/4]=k==slot?high:2;
        reg[(t+0x14)/4]=k==slot&&high?0x1010000:0x10000;
        for(unsigned j=0;j<3;j++){reg[(t+0x30+20*j)/4]=0x90+j;reg[(t+0x34+20*j)/4]=0x50000+j*4;reg[(t+0x38+20*j)/4]=0x345+j;reg[(t+0x3c+20*j)/4]=0x10101;reg[(t+0x40+20*j)/4]=0x789+j;}
    }
    if(f==1)reg[1]=0x80;memcpy(initial,reg,sizeof(reg));
    if(!pwvr_begin(&io,&q,15))return -1;int result=0;for(unsigned k=0;k<256&&!result;k++)result=pwvr_step(&io,&q);return result;
}
static void success(void)
{
    assert(pwvr_retired(&q)&&edges==16&&acks==16&&q.response_seen==65535&&q.valid==65535);
    for(unsigned k=0;k<4;k++)for(unsigned j=0;j<4;j++)assert(q.response[k*4+j]==values[k][j]);
    unsigned t=slot*PWRSC_STRIDE;assert(reg[0]==initial[0]&&!reg[1]&&reg[(t+0x14)/4]==initial[(t+0x14)/4]&&reg[(t+0x1c)/4]==initial[(t+0x1c)/4]&&reg[(t+0x10)/4]==initial[(t+0x10)/4]);
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)assert(reg[(t+0x30+20*k+4*j)/4]==initial[(t+0x30+20*k+4*j)/4]);
}
int main(void)
{
    unsigned checks=0;
    for(unsigned high=0;high<2;high++)for(unsigned chosen=0;chosen<4;chosen++){assert(run(0,chosen,high)==1);success();checks++;}
    assert(run(0,0,1)==1);success();good=q;
    for(unsigned n=0;n<good.io.events;n++){
        q=good;q.io.history[n].issued=0;assert(!pwvr_retired(&q));checks++;
        q=good;q.io.history[n].returned=0;assert(!pwvr_retired(&q));checks++;
        q=good;q.io.history[n].unknown=1;assert(!pwvr_retired(&q));checks++;
        q=good;q.io.history[n].address^=4;assert(!pwvr_retired(&q));checks++;
    }
    for(unsigned k=0;k<16;k++)for(unsigned bit=0;bit<32;bit++){
        q=good;q.status_OR[k]^=1u<<bit;assert(!pwvr_retired(&q));checks++;
        q=good;q.response[k]^=1u<<bit;assert(!pwvr_retired(&q));checks++;
        q=good;q.response_OR[k]^=1u<<bit;assert(!pwvr_retired(&q));checks++;
    }
    for(unsigned f=1;f<=9;f++){
        assert(run(f,0,1)==-1&&!pwvr_retired(&q));unsigned old_reads=reads,old_writes=writes;
        assert(pwvr_step(&io,&q)==-1&&reads==old_reads&&writes==old_writes);if(writes)assert(q.io.unknown);checks++;
    }
    printf("{\"passed\":true,\"SOFTWARE_only\":true,\"checks\":%u,\"actual_sixteen_field_READs\":true,\"no_CMD_DATA_or_resource_WRITE\":true,\"full_RW_prefix_retirement\":true,\"physical_caller_wired\":false}\n",checks);return 0;
}
