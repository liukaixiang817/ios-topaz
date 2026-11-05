/* Operation-specific, address-free mailbox reply bodies. RSSI is not guessed
 * from the WMI SNR observation. All lengths refer to the actual private copy. */
#ifndef POLARIS_WIFI_CONTROL_WIRE_H
#define POLARIS_WIFI_CONTROL_WIRE_H
#include "polaris-wifi-mailbox.h"
#define PWCB_STATE_BYTES 56u
#define PWCB_BSS_HEADER 64u
#define PWCB_IES 768u
static inline unsigned pwcb_u16(const uint8_t*p){return p[0]|((unsigned)p[1]<<8);}
static inline void pwcb_put16(uint8_t*p,unsigned n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static inline int pwcb_frequency(unsigned n){return n>=2412&&n<=2462&&(n-2412)%5==0;}
/* STATE56: flags(ready1,link2,fault4,scanning8,joining16,closed32), errno,
 * scan count, frequency; BSSID6, SSID length, zero; SSID32. */
static inline int pwcb_state_valid(const uint8_t*p,unsigned bytes)
{
    if(!p||bytes!=PWCB_STATE_BYTES)return 0;
    unsigned flags=pwmb_u32(p),frequency=pwmb_u32(p+12);
    return !(flags&~63u)&&(!(flags&2)||((flags&1)&&!(flags&60)))&&pwmb_u32(p+4)<=4095&&
        pwmb_u32(p+8)<=32&&(!frequency||pwcb_frequency(frequency))&&p[22]<=32&&!p[23]&&
        !(p[16]&1)&&(!(flags&2)||(frequency&&!pwmb_zero(p+16,6)&&p[22]))&&
        pwmb_zero(p+24+p[22],32-p[22]);
}
/* BSS64+IEs: index, frequency, signed SNR, observation count; capability16,
 * beacon interval16, IE length16, zero16; SSID length8, BSSID6, zero8;
 * SSID32; exact received information elements (<=768). */
static inline int pwcb_bss_valid(const uint8_t*p,unsigned bytes)
{
    if(!p||bytes<PWCB_BSS_HEADER||bytes>PWCB_BSS_HEADER+PWCB_IES||pwmb_u32(p)>=32||
       !pwcb_frequency(pwmb_u32(p+4))||!pwmb_u32(p+12)||pwcb_u16(p+20)!=bytes-PWCB_BSS_HEADER||
       pwcb_u16(p+22)||p[24]>32||(p[25]&1)||pwmb_zero(p+25,6)||p[31]||!pwmb_zero(p+32+p[24],32-p[24]))return 0;
    unsigned at=PWCB_BSS_HEADER;
    while(at<bytes){if(bytes-at<2||p[at+1]>bytes-at-2)return 0;at+=2+p[at+1];}
    return 1;
}
static inline int pwcb_reply_valid(const uint8_t*p,unsigned bytes)
{
    if(!pwmb_payload(PWMB_REPLY,PWMB_RESPONSE,p,bytes))return 0;
    unsigned op=pwmb_u32(p+8);
    if(pwmb_u32(p+12))return bytes==16;
    if(op==PWMB_STATE)return pwcb_state_valid(p+16,bytes-16);
    if(op==PWMB_SCAN_ENTRY)return pwcb_bss_valid(p+16,bytes-16);
    return bytes==16;
}
#endif
