#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-wpa.h"
static unsigned checks,length[9];static uint64_t ticks;
static uint8_t messages[9][640],pmk[32],nonce[32],ptk[48],gtk[16],packet[640];
static struct pwpa_state wpa;static struct psta_state station;
#define CHECK(x) do{assert(x);checks++;}while(0)
static unsigned number(FILE*f)
{uint8_t p[4];CHECK(fread(p,1,4,f)==4);return p[0]|((unsigned)p[1]<<8)|((unsigned)p[2]<<16)|((unsigned)p[3]<<24);}
static void setup(void)
{
    memset(&station,0,sizeof(station));memset(&wpa,0,sizeof(wpa));ticks=100;
    station.opened=station.associated=1;station.phase=4;station.security=2;station.epoch=9;station.last=ticks;
    station.own[0]=2;station.own[5]=7;station.target.bssid[0]=2;station.target.bssid[5]=9;
    const uint8_t rsn[]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
    memcpy(station.rsn,rsn,22);memcpy(station.ap_rsn,rsn,22);station.rsn_bytes=22;
    CHECK(pwpa_open(&wpa,&station,pmk,nonce,++ticks));
}
static void message1(void)
{
    CHECK(pwpa_receive(&wpa,messages[0],length[0],++ticks)==1&&wpa.pending==2&&wpa.derived&&!wpa.authorized);
    CHECK(wpa.reply_bytes==length[1]&&!memcmp(wpa.reply,messages[1],length[1]));
    CHECK(!memcmp(wpa.kck,ptk,16)&&!memcmp(wpa.kek,ptk+16,16)&&!memcmp(wpa.tk,ptk+32,16));
    CHECK(pwpa_step(&wpa,++ticks)==2&&!pwpa_install(&wpa,++ticks));
    CHECK(pwpa_sent(&wpa,++ticks,1)==1&&wpa.phase==1);
}
static int message3(unsigned index)
{
    CHECK(pwpa_receive(&wpa,messages[index],length[index],++ticks)==1&&wpa.phase==2);
    int result=1;unsigned n=0;for(;n<64&&wpa.phase==2;n++){result=pwpa_step(&wpa,++ticks);CHECK(result==1||result==2);}
    CHECK(n==36);return result;
}
int main(int argc,char**argv)
{
    CHECK(argc==2);FILE*f=fopen(argv[1],"rb");CHECK(f);uint8_t magic[8];CHECK(fread(magic,1,8,f)==8&&!memcmp(magic,"PWPA001",8));
    CHECK(fread(pmk,1,32,f)==32&&fread(nonce,1,32,f)==32&&fread(ptk,1,48,f)==48&&fread(gtk,1,16,f)==16);
    for(unsigned n=0;n<9;n++){length[n]=number(f);CHECK(length[n]>=99&&length[n]<=640&&fread(messages[n],1,length[n],f)==length[n]);}
    CHECK(fgetc(f)==EOF&&!fclose(f));setup();message1();
    CHECK(message3(2)==2&&wpa.pending==4&&wpa.have_m3&&wpa.keys_ready&&!wpa.authorized&&wpa.gtk_id==1);
    CHECK(wpa.reply_bytes==length[3]&&!memcmp(wpa.reply,messages[3],length[3])&&!memcmp(wpa.gtk,gtk,16)&&wpa.rsc[0]==1);
    CHECK(!pwpa_nonzero(wpa.pmk,32)&&!pwpa_nonzero((const uint8_t*)&wpa.unwrap,sizeof(wpa.unwrap)));
    CHECK(!pwpa_install(&wpa,++ticks)&&pwpa_sent(&wpa,++ticks,1)==1);
    CHECK(pwpa_step(&wpa,++ticks)==3&&pwpa_install(&wpa,++ticks)&&!pwpa_install(&wpa,++ticks)&&!wpa.authorized);
    CHECK(pwpa_installed(&wpa,++ticks,1)==1&&pwpa_step(&wpa,++ticks)==4&&!wpa.keys_ready);
    /* Exact M3 retry responds but leaves key install state and RSC untouched. */
    CHECK(pwpa_receive(&wpa,messages[2],length[2],++ticks)==1&&wpa.pending==4&&wpa.retries==1&&wpa.installed&&wpa.authorized);
    CHECK(!memcmp(wpa.reply,messages[3],length[3])&&!pwpa_install(&wpa,++ticks)&&pwpa_sent(&wpa,++ticks,1)==1&&wpa.rsc[0]==1);
    /* A higher authenticated retry is re-verified, never reinstalled. Its
     * higher group RSC cannot reset or rewrite the existing packet counter. */
    CHECK(message3(4)==2&&wpa.retries==2&&wpa.installed&&!wpa.keys_ready&&wpa.rsc[0]==1);
    CHECK(!memcmp(wpa.reply,messages[5],length[5])&&!pwpa_install(&wpa,++ticks));
    CHECK(pwpa_sent(&wpa,++ticks,1)==1&&pwpa_step(&wpa,++ticks)==4);
    CHECK(pwpa_receive(&wpa,messages[2],length[2],++ticks)==1&&wpa.bad==1&&!wpa.pending&&wpa.authorized);
    CHECK(pwpa_receive(&wpa,messages[0],length[0],++ticks)==1&&wpa.ignored==1&&wpa.installed&&!memcmp(wpa.tk,ptk+32,16));
    for(unsigned bad=6;bad<9;bad++){
        setup();message1();CHECK(message3(bad)==1&&wpa.bad==1&&!wpa.have_m3&&!wpa.keys_ready&&!wpa.authorized&&wpa.phase==1);
        CHECK(!pwpa_nonzero((const uint8_t*)&wpa.unwrap,sizeof(wpa.unwrap)));
        CHECK(message3(2)==2&&wpa.keys_ready); /* valid retry still possible */
    }
    /* Truncations, flags, replay, ANonce and MIC are checked before unwrap. */
    setup();message1();
    for(unsigned n=0;n<length[2];n++){
        CHECK(pwpa_receive(&wpa,messages[2],n,++ticks)>=0&&wpa.phase==1&&!wpa.have_m3&&!wpa.authorized);
    }
    for(unsigned fault=0;fault<8;fault++){
        memcpy(packet,messages[2],length[2]);
        if(fault==0)packet[81]^=1;if(fault==1)packet[17]^=1;if(fault==2)packet[8]=32;
        if(fault==3)packet[16]=1;if(fault==4)packet[71]=1;if(fault==5)packet[4]=1;
        if(fault==6)packet[98]--;if(fault==7)packet[0]=0;
        CHECK(pwpa_receive(&wpa,packet,length[2],++ticks)==1&&wpa.phase==1&&!wpa.have_m3);
    }
    memcpy(packet,messages[0],length[0]);packet[16]=0;
    CHECK(pwpa_receive(&wpa,packet,length[0],++ticks)==1&&!wpa.pending);
    CHECK(pwpa_receive(&wpa,messages[0],length[0],++ticks)==1&&wpa.pending==2&&wpa.retries==1);
    CHECK(pwpa_sent(&wpa,++ticks,1)==1&&!wpa.authorized);
    CHECK(!pwpa_step(&wpa,wpa.deadline+1)&&wpa.phase==5&&!wpa.authorized);
    setup();message1();CHECK(message3(2)==2&&pwpa_sent(&wpa,++ticks,1)==1&&pwpa_install(&wpa,++ticks));
    CHECK(pwpa_installed(&wpa,++ticks,0)==-1&&wpa.unknown&&!wpa.authorized);
    setup();CHECK(pwpa_receive(&wpa,messages[0],length[0],++ticks)==1&&pwpa_sent(&wpa,++ticks,0)==-1&&wpa.unknown);
    printf("PASS %u WPA2 four-way/retry/replay/key-install checks; SOFTWARE only\n",checks);return 0;
}
