/* Restricted Australia profile, from ath/regd.c and ath10k/wmi-tlv.c at
 * Linux458c6079fc1d41d564c37679c8ace02cd83ee817. Preserve the actual EEPROM
 * domain; never select a country from a beacon or host locale. User-selected
 * AU is intersected with supported EEPROM pairs: channels1..11,20MHz,20dBm,
 * antenna gain0. AU db.txt40095bd16e53d5c5682fd6e7e3dbbbfaf0fe5410 permits
 * 2400..2483.5MHz/40MHz/4000mW; this narrower profile never raises that limit.
 * Unknown EEPROM domains require a separate mapping, not a guessed CTL.
 * This encoder does not establish native publication or radio readiness. */
#ifndef POLARIS_WIFI_REGULATORY_H
#define POLARIS_WIFI_REGULATORY_H
#include "polaris-wifi-mailbox.h"
#include "polaris-wifi-wmi-station.h"
struct pwrg_profile {uint8_t regulatory[36],command[28];uint32_t domain,low,high,valid,country;};
static inline int pwrg_make(struct pwrg_profile*s,const struct pwmi_state*w,unsigned country)
{
    if(!s||!w||country!=36||!pwmb_zero(s,sizeof(*s))||w->phase!=4||w->unknown||w->error)return 0;
    unsigned rd=pwmi_get(w->regulatory),domain=rd&~0x4000u;
    /* regd.c's explicit world-domain switch omits0x6b. Do not adopt its
     * warning/default fallback or sanitize malformed0x8000 EEPROM values. */
    if(rd>65535)return 0;
    if(domain&0x8000){
        unsigned code=domain&0x7fff;
        if(code==36)domain=0x3b;else if(code==5000)domain=0x23;else if(code==156)domain=0x52;
        else if(code==840||code==841||code==843)domain=0x3a;else return 0;
    }else if(!domain)domain=0x3a; /* Exact ath EEPROM-default -> US/FCC3_FCCA convention, not host country. */
    unsigned ctl2,ctl5;
    if(domain>=0x60&&domain<=0x6c&&domain!=0x6b)ctl2=ctl5=0xff;
    else if(domain==0x3b||domain==0x23||domain==0x52){ctl2=0x30;ctl5=0x10;}
    else if(domain==0x3a){ctl2=ctl5=0x10;}else return 0;
    unsigned low=pwmi_get(w->regulatory+20),high=pwmi_get(w->regulatory+24);
    if((low&&!high)||(!low&&high)||(low&&low>high)||(low&&high<2412)||(low&&low>2462))return 0;
    s->domain=domain;s->low=low;s->high=high;s->country=country;pwmi_copy(s->regulatory,w->regulatory,36);
    pwmi_put(s->command,0x4001);pwmi_header(s->command+4,81,20);
    for(unsigned n=0;n<3;n++)pwmi_put(s->command+8+4*n,domain);
    pwmi_put(s->command+20,ctl2);pwmi_put(s->command+24,ctl5);s->valid=1;return 1;
}
static inline int pwrg_channel(const struct pwrg_profile*s,const struct pwmi_state*w,
    unsigned frequency,struct pwst_channel*out)
{
    if(!s||!w||!out||!s->valid||s->country!=36||w->phase!=4||w->unknown||w->error||
       !psta_equal(s->regulatory,w->regulatory,36)||frequency<2412||frequency>2462||(frequency-2412)%5||
       (s->low&&(frequency<s->low||frequency>s->high)))return 0;
    *out=(struct pwst_channel){(uint16_t)frequency,0,40,40,0,0,0};return 1;
}
#endif
