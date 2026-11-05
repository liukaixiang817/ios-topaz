#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-regulatory.h"
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
int main(void)
{
    struct pwmi_state w={0};struct pwrg_profile p;struct pwst_channel c;
    w.phase=4;
    for(unsigned rd=0;rd<65536;rd++){
        unsigned d=rd&~0x4000u,expected=(d>=0x60&&d<=0x6c&&d!=0x6b)||!d||d==0x3a||d==0x3b||d==0x23||d==0x52||
            d==(0x8000|36)||d==(0x8000|5000)||d==(0x8000|156)||d==(0x8000|840)||d==(0x8000|841)||d==(0x8000|843);
        memset(&p,0,sizeof(p));pwmi_put(w.regulatory,rd);CHECK(pwrg_make(&p,&w,36)==(int)expected);
        if(!expected)continue;
        CHECK(pwmi_get(p.command)==0x4001&&pwmi_get(p.command+4)==0x510014);
        CHECK(pwmi_get(p.command+8)==p.domain&&pwmi_get(p.command+12)==p.domain&&pwmi_get(p.command+16)==p.domain);
        unsigned ctl=p.domain>=0x60?255:p.domain==0x3a?16:48;
        CHECK(pwmi_get(p.command+20)==ctl&&pwmi_get(p.command+24)==(p.domain>=0x60?255u:16u));
        for(unsigned frequency=2400;frequency<=2485;frequency++){
            int allowed=frequency>=2412&&frequency<=2462&&(frequency-2412)%5==0;
            CHECK(pwrg_channel(&p,&w,frequency,&c)==allowed);
            if(allowed)CHECK(c.frequency==frequency&&!c.min_power&&c.max_power==40&&c.reg_power==40&&!c.antenna&&!c.reg_class&&!c.reserved);
        }
        for(unsigned n=0;n<36;n++){w.regulatory[n]^=1;CHECK(!pwrg_channel(&p,&w,2437,&c));w.regulatory[n]^=1;}
    }
    memset(&p,0,sizeof(p));memset(w.regulatory,0,36);pwmi_put(w.regulatory,0x8000);CHECK(!pwrg_make(&p,&w,36));
    pwmi_put(w.regulatory,0x10060);CHECK(!pwrg_make(&p,&w,36));
    pwmi_put(w.regulatory,0x60);CHECK(!pwrg_make(&p,&w,0));CHECK(!pwrg_make(&p,&w,156));
    pwmi_put(w.regulatory+20,2432);CHECK(!pwrg_make(&p,&w,36));pwmi_put(w.regulatory+24,2442);
    CHECK(pwrg_make(&p,&w,36));CHECK(!pwrg_channel(&p,&w,2412,&c));CHECK(pwrg_channel(&p,&w,2437,&c));CHECK(!pwrg_channel(&p,&w,2462,&c));
    printf("PASS %u restricted AU regulatory checks; no native publication\n",checks);return 0;
}
