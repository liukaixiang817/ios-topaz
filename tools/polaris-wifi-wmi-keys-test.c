#define main wpa_protocol_main
#include "polaris-wifi-wpa-test.c"
#undef main
#include "polaris-wifi-wmi-keys.h"
static struct pwki_state keys;
static void ready(void)
{
    setup();message1();CHECK(message3(2)==2&&pwpa_sent(&wpa,++ticks,1)==1&&pwpa_install(&wpa,++ticks));
    memset(&keys,0,sizeof(keys));CHECK(pwki_open(&keys,&wpa,17,++ticks));
}
static unsigned security(unsigned peer,unsigned unicast,unsigned cipher)
{memset(packet,0,sizeof(packet));packet[0]=11;packet[1]=(uint8_t)((unicast?128:0)|cipher);psta_put16(packet+2,peer);return 28;}
int main(int argc,char**argv)
{
    CHECK(!wpa_protocol_main(argc,argv));ready();
    for(unsigned group=0;group<2;group++){
        CHECK(pwki_next(&keys,++ticks)==1&&keys.pending&&pwmi_get(keys.tx)==0x5009&&pwmi_get(keys.tx+4)==0x0060005c);
        CHECK(!memcmp(keys.tx+12,wpa.peer,6)&&pwmi_get(keys.tx+20)==(group?1u:0u)&&pwmi_get(keys.tx+24)==group&&pwmi_get(keys.tx+28)==4&&pwmi_get(keys.tx+88)==16);
        CHECK(pwmi_get(keys.tx+100)==0x00110010&&!memcmp(keys.tx+104,group?gtk:ptk+32,16));
        CHECK(!pwpa_nonzero(keys.tx+32,56)); /* primary command leaves all counters zero */
        CHECK(pwki_sent(&keys,++ticks,1)==1&&!pwki_next(&keys,++ticks)&&!pwpa_nonzero(keys.tx,120));
        unsigned bytes=security(18,!group,6);CHECK(!pwki_htt(&keys,packet,bytes,++ticks)&&keys.phase==1+2*group);
        bytes=security(17,!group,6);CHECK(pwki_htt(&keys,packet,bytes,++ticks)==1&&keys.phase==2+2*group);
        CHECK(pwki_htt(&keys,packet,bytes,++ticks)==1&&keys.phase==2+2*group); /* duplicate */
    }
    CHECK(keys.confirmed==3&&keys.group_floor[0]==1&&!pwpa_nonzero(keys.tk,16)&&!pwpa_nonzero(keys.gtk,16));
    CHECK(pwpa_installed(&wpa,++ticks,1)==1&&wpa.authorized);
    for(unsigned fault=0;fault<7;fault++){
        ready();CHECK(pwki_next(&keys,++ticks)==1);
        if(fault==0){CHECK(pwki_sent(&keys,++ticks,0)==-1&&keys.unknown);continue;}
        if(fault==1){unsigned bytes=security(17,1,6);CHECK(pwki_htt(&keys,packet,bytes,++ticks)==-1&&keys.unknown);continue;}
        CHECK(pwki_sent(&keys,++ticks,1)==1);
        unsigned bytes=security(17,1,6);
        if(fault==2)packet[1]=4;if(fault==3)packet[1]=6;if(fault==4)bytes=27;
        if(fault==5){CHECK(pwki_next(&keys,keys.deadline+1)==-1&&keys.unknown);continue;}
        if(fault==6){CHECK(pwki_htt(&keys,packet,bytes,keys.last-1)==-1&&keys.unknown);continue;}
        CHECK(pwki_htt(&keys,packet,bytes,++ticks)==-1&&keys.unknown&&!wpa.authorized);
    }
    printf("PASS %u WMI/HTT key installation checks; SOFTWARE only\n",checks);return 0;
}
