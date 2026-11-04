/* Executable independent RSC peer; no physical MMIO or firmware calls. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-mss-rail-request.h"
static struct pmrv_request q;
static uint32_t reg[0x3000/4],initial[0x3000/4],votes[19],before_votes[19];
static unsigned slot,actions,fail_at,mode,edges,acks,pending,checks,cases;
static uint64_t tick;
#define CHECK(x) do{checks++;assert(x);}while(0)
static unsigned offset(uint64_t at)
{CHECK(at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(reg)&&!(at&3));return (unsigned)(at-PWRSC_BASE);}
static void complete(void)
{
    unsigned t=slot*PWRSC_STRIDE;uint32_t address=reg[(t+0x34)/4],msg=reg[(t+0x30)/4];
    /* Explicit independent address table: no engine helper supplies effects. */
    static const uint32_t address_table[19]={0x30000,0x30010,0x30060,
        0x40f00,0x40f04,0x40f08,0x40f0c,0x41300,0x41304,0x41308,0x4130c,
        0x40c00,0x40c04,0x40c08,0x40c0c,0x42000,0x42004,0x42008,0x4200c};
    unsigned n=0;while(n<19&&address_table[n]!=address)n++;CHECK(n<19);
    CHECK(reg[(t+0x1c)/4]==1);CHECK(msg==0x108||msg==0x10108);
    if(msg==0x10108)votes[n]=reg[(t+0x38)/4];
    reg[(t+0x40)/4]=votes[n];reg[(t+0x3c)/4]=mode==2?0x10000:mode==3?0x10105:0x10101;
    reg[(t+0x18)/4]=mode==4?0:1;reg[1]|=1u<<slot;
    if(mode==5)reg[1]|=1u<<((slot+1)%8);
    pending=0;
}
static int read_peer(void*unused,uint64_t at,uint32_t*v)
{
    (void)unused;unsigned o=offset(at);actions++;
    if(actions==fail_at)return 0;
    if(o==4&&pending&&mode!=1)complete();
    *v=reg[o/4];
    if(mode==6&&q.io.phase==3&&o==slot*PWRSC_STRIDE+0x60)*v^=1;
    return 1;
}
static int write_peer(void*unused,uint64_t at,uint32_t v)
{
    (void)unused;unsigned o=offset(at);actions++;
    CHECK(o!=0&&o!=12);CHECK(q.io.outstanding==q.io.events);
    CHECK(q.io.history[q.io.events-1].issued&&q.io.history[q.io.events-1].unknown);
    if(actions==fail_at)return 0;
    unsigned t=slot*PWRSC_STRIDE;
    if(o==8){CHECK(v==(1u<<slot)&&q.io.completed==1);acks++;if(mode!=7)reg[1]&=~v;return 1;}
    CHECK(o==t+0x10||o==t+0x14||o==t+0x1c||o==t+0x30||o==t+0x34||o==t+0x38);
    if(o==t+0x38)CHECK(q.write==1);
    uint32_t old=reg[o/4];reg[o/4]=v;
    if(o==t+0x14&&(v&0x1000000)){
        CHECK(!(old&0x1000000));CHECK(!edges&&!acks);edges++;pending=1;
        reg[(t+0x3c)/4]=0;reg[(t+0x18)/4]=0;
    }
    if(mode==8&&o==t+0x14&&!edges)reg[o/4]^=1;
    return 1;
}
static int clock_peer(void*unused,uint64_t*time,uint64_t*hz)
{
    (void)unused;tick+=10;if(mode==9&&edges)tick+=960001;
    *time=tick;*hz=mode==10&&edges?1:19200000;return 1;
}
static void order_peer(void*unused){(void)unused;}
static const struct pwrsc_io io={0,read_peer,write_peer,clock_peer,order_peer};
static void reset(unsigned s,unsigned high,unsigned f,unsigned m)
{
    memset(&q,0,sizeof(q));memset(reg,0,sizeof(reg));slot=s;actions=edges=acks=pending=0;
    fail_at=f;mode=m;tick=1000;reg[0]=1u<<s;
    for(unsigned k=0;k<8;k++){
        unsigned t=k*PWRSC_STRIDE;reg[(t+0x14)/4]=high==2?0:high?0x1010000:0x10000;
        reg[(t+0x18)/4]=1;reg[(t+0x1c)/4]=high==1?1:0;reg[(t+0x10)/4]=0x80;
        for(unsigned n=0;n<3;n++)for(unsigned j=0;j<5;j++)reg[(t+0x30+20*n+4*j)/4]=0x100+k*20+n*5+j;
    }
    for(unsigned k=0;k<19;k++)votes[k]=before_votes[k]=k<3?2:k%4==0?1:37;
    memcpy(initial,reg,sizeof(reg));cases++;
}
static int run(unsigned resource,unsigned write,uint32_t value)
{
    if(!pmrv_begin(&io,&q,91,1u<<slot,slot,resource,write,value))return -1;
    int result=0;for(unsigned n=0;n<300&&!result;n++)result=pmrv_step(&io,&q);return result;
}
static void good(unsigned resource,unsigned write,uint32_t value)
{
    CHECK(run(resource,write,value)==1);CHECK(q.epoch==91&&q.valid==1);CHECK(pmrv_retired(&q));
    CHECK(q.io.finished&&q.io.restored&&!q.io.error&&!q.io.unknown&&!q.io.outstanding);
    CHECK(edges==1&&acks==1&&q.io.triggers==1&&q.io.completed==1&&q.io.acknowledged==1);
    CHECK(q.response==votes[resource]);
    for(unsigned n=0;n<19;n++)CHECK(votes[n]==(n==resource&&write?value:before_votes[n]));
    unsigned t=slot*PWRSC_STRIDE;
    for(unsigned n=0;n<sizeof(reg)/4;n++){
        unsigned at=n*4;if(at==8||at==t+0x3c||at==t+0x40)continue;
        CHECK(reg[n]==initial[n]);
    }
    unsigned a=actions;CHECK(pmrv_step(&io,&q)==1);CHECK(actions==a);
    CHECK(!pmrv_begin(&io,&q,91,1u<<slot,slot,resource,write,value));CHECK(actions==a);
}
int main(void)
{
    for(unsigned slot_=0;slot_<8;slot_++)for(unsigned high=0;high<3;high++){
        for(unsigned n=0;n<19;n++){reset(slot_,high,0,0);good(n,0,0);}
        for(unsigned n=0;n<19;n++)if(n<3||(n-3)%4<2){
            reset(slot_,high,0,0);good(n,1,n<3?7:(n-3)%4==0?800:1);
        }
    }
    /* Fail every actual returned read/write location, including before first
     * write and after completion during ACK/register retirement. */
    for(unsigned write=0;write<2;write++){
        reset(3,1,0,0);good(3,write,write?800:0);unsigned total=actions;
        for(unsigned f=1;f<=total;f++){
            reset(3,1,f,0);CHECK(run(3,write,write?800:0)==-1);CHECK(!q.valid);
            CHECK(q.io.error);unsigned a=actions;CHECK(pmrv_step(&io,&q)==-1);CHECK(actions==a);
            if(q.io.writes||q.io.outstanding)CHECK(q.io.unknown);
        }
    }
    for(unsigned m=1;m<=10;m++){
        reset(2,1,0,m);CHECK(run(0,1,7)==-1);CHECK(!q.valid&&q.io.unknown);
        unsigned a=actions;CHECK(pmrv_step(&io,&q)==-1);CHECK(actions==a);
    }
    reset(0,0,0,0);reg[1]=1;CHECK(run(0,0,0)==-1);CHECK(!q.io.writes&&!edges);
    reset(0,0,0,0);reg[0]=0;CHECK(run(0,0,0)==-1);CHECK(!q.io.writes&&!edges);
    for(unsigned n=0;n<19;n++)if(n>=3&&(n-3)%4>=2){
        reset(0,0,0,0);CHECK(run(n,1,0)==-1);CHECK(!actions);
    }
    reset(0,0,0,0);CHECK(run(19,0,0)==-1);CHECK(!actions);
    reset(0,0,0,0);CHECK(run(0,1,16)==-1);CHECK(!actions);
    reset(0,0,0,0);CHECK(run(3,1,8192)==-1);CHECK(!actions);
    reset(0,0,0,0);CHECK(run(4,1,2)==-1);CHECK(!actions);
    reset(0,0,0,0);CHECK(run(0,0,1)==-1);CHECK(!actions);
    printf("MSS finite retained-vote request: %u scenarios / %u checks PASS; no hardware\n",cases,checks);return 0;
}
