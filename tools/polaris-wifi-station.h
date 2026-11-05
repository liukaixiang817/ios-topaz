/* Bounded single-station 11b/g authentication/association. This is the MAC
 * protocol, not a radio permission or a WPA success indication. Callers must
 * start the selected channel and create the BSS peer before publishing frames.
 * WCN3990 WMI/HTT and the locally indexed HackiOS station were cross-checked;
 * no foreign driver callbacks or memory are used here. */
#ifndef POLARIS_WIFI_STATION_H
#define POLARIS_WIFI_STATION_H
#include "polaris-wifi-wmi-scan.h"
#define PSTA_WAIT UINT64_C(19200000) /* one second at the own 19.2MHz counter */
#define PSTA_TOTAL (10*PSTA_WAIT)
struct psta_state {
    uint64_t epoch,last,deadline,opening;
    uint32_t opened,error,unknown,phase,pending,attempts,security,tx_bytes;
    uint32_t associated,rejected,reason,aid,dropped,ignored,sequence,dtim,rate_count,rsn_bytes,assoc_caps;
    uint8_t own[6],rates[12],rsn[22],ap_rsn[257],tx[256];
    struct pwsc_bss target;
};
static inline unsigned psta_u16(const uint8_t*p){return p[0]|((unsigned)p[1]<<8);}
static inline void psta_put16(uint8_t*p,unsigned v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static inline int psta_equal(const uint8_t*a,const uint8_t*b,unsigned n)
{unsigned d=0;for(unsigned i=0;i<n;i++)d|=a[i]^b[i];return !d;}
static inline int psta_mac(const uint8_t*p)
{unsigned v=0;for(unsigned n=0;n<6;n++)v|=p[n];return v&&!(p[0]&1);}
static inline int psta_suite(const uint8_t*p,unsigned type)
{return p[0]==0&&p[1]==15&&p[2]==172&&p[3]==type;}
/* Select only RSN PSK with CCMP pairwise AND group cipher, no required PMF.
 * Lists and optional fields are bounded before inspection. Unsupported suites
 * never silently fall back to an open connection. */
static inline int psta_rsn(const uint8_t*p,unsigned bytes)
{
    if(bytes<18||psta_u16(p)!=1||!psta_suite(p+2,4))return 0;
    unsigned at=6,count=psta_u16(p+at),match=0;at+=2;
    if(!count||count>(bytes-at)/4)return 0;
    for(unsigned n=0;n<count;n++)if(psta_suite(p+at+4*n,4))match=1;
    if(!match)return 0;at+=4*count;if(bytes-at<2)return 0;
    count=psta_u16(p+at);at+=2;match=0;if(!count||count>(bytes-at)/4)return 0;
    for(unsigned n=0;n<count;n++)if(psta_suite(p+at+4*n,2))match=1;
    if(!match)return 0;at+=4*count;if(at==bytes)return 1;
    if(bytes-at<2||(psta_u16(p+at)&0x40))return 0;at+=2;if(at==bytes)return 1;
    if(bytes-at<2)return 0;count=psta_u16(p+at);at+=2;
    if(count>(bytes-at)/16)return 0;at+=16*count;
    return at==bytes||(bytes-at==4&&psta_suite(p+at,6));
}
static inline int psta_rate(unsigned rate)
{
    const uint8_t supported[12]={2,4,11,22,12,18,24,36,48,72,96,108};
    for(unsigned n=0;n<12;n++)if((rate&127)==supported[n])return 1;return 0;
}
/* rates[] is scratch owned by the state. Unknown optional rates are skipped;
 * every advertised basic rate must be supported, including membership values.
 * No HT/VHT/QoS capability is claimed by this initial 20MHz legacy profile. */
static inline int psta_rates(struct psta_state*s,const uint8_t*p,unsigned bytes)
{
    unsigned at=0,seen=0,extended=0;s->rate_count=0;
    while(at<bytes){
        if(bytes-at<2||p[at+1]>bytes-at-2)return 0;
        unsigned id=p[at],length=p[at+1];at+=2;
        if(id==1||id==50){
            if(!length||(id==1&&(seen++||length>8))||(id==50&&extended++))return 0;
            for(unsigned n=0;n<length;n++){
                unsigned rate=p[at+n];if(!psta_rate(rate)){if(rate&128)return 0;continue;}
                unsigned j=0;for(;j<s->rate_count;j++)if((s->rates[j]&127)==(rate&127)){s->rates[j]|=(uint8_t)(rate&128);break;}
                if(j==s->rate_count){if(j>=12)return 0;s->rates[s->rate_count++]=(uint8_t)rate;}
            }
        }at+=length;
    }return seen==1&&s->rate_count>0;
}
/* security=0 explicitly open,2 explicitly WPA2-PSK/CCMP. A caller-selected
 * scan index is required; choosing a similarly named network is not implicit. */
static inline int psta_open(struct psta_state*s,const struct pwsc_state*scan,unsigned index,unsigned security,uint64_t now)
{
    if(!s||!scan||!scan->opened||scan->unknown||scan->error||!scan->completed||scan->phase!=5||index>=scan->count||
       (security!=0&&security!=2)||now<scan->last||now>UINT64_MAX-PSTA_TOTAL||!psta_mac(scan->mac))return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    const struct pwsc_bss*b=&scan->bss[index];
    if(!b->observations||!psta_mac(b->bssid)||!b->ssid_bytes||b->ssid_bytes>32||!b->interval||b->ie_bytes>PWSC_IES||
       b->frequency<2412||b->frequency>2462||(b->frequency-2412)%5||!(b->capability&1)||(b->capability&2)||
       (!!(b->capability&16)!=(security==2))||!psta_rates(s,b->ies,b->ie_bytes))return 0;
    unsigned at=0,rsn=0,ssid=0,tim=0,ds=0;s->dtim=1;
    while(at<b->ie_bytes){
        unsigned id=b->ies[at],length=b->ies[at+1];const uint8_t*p=b->ies+at+2;
        if(id==0){if(ssid++||length>32||(length&&(length!=b->ssid_bytes||!psta_equal(p,b->ssid,length))))return 0;}
        if(id==3){if(ds++||length!=1||2407+5*p[0]!=b->frequency)return 0;}
        if(id==5){if(tim++||length<4||!p[1])return 0;s->dtim=p[1];}
        if(id==48){
            if(rsn++||security!=2||!psta_rsn(p,length))return 0;
            s->rsn_bytes=length+2;pwmi_copy(s->ap_rsn,b->ies+at,length+2);
        }
        /* A WPA vendor IE without an RSN IE is never accepted as WPA2. */
        if(id==221&&length>=4&&!p[0]&&p[1]==80&&p[2]==242&&p[3]==1&&security==0)return 0;
        at+=2+length;
    }
    if(!ssid||(security==2&&!rsn))return 0;
    const uint8_t own_rsn[22]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
    pwmi_copy(s->rsn,own_rsn,22);pwmi_copy(s->own,scan->mac,6);s->target=*b;
    s->epoch=scan->epoch;s->last=s->opening=now;s->deadline=now+PSTA_WAIT;s->security=security;s->opened=1;return 1;
}
static inline int psta_fail(struct psta_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int psta_time(struct psta_state*s,uint64_t now)
{
    if(!s||!s->opened||s->unknown||s->error)return 0;
    if(now<s->last||now>UINT64_MAX-PSTA_TOTAL)return psta_fail(s,1),0;s->last=now;
    if(s->phase<4&&now-s->opening>PSTA_TOTAL){s->rejected=1;s->reason=UINT32_MAX;s->phase=5;s->pending=0;}
    return 1;
}
/* 1=frame prepared;0=wait/associated/rejected;-1=invalid worker state.
 * Retry the SAME sequence and contents with Retry set, at most three tries.
 * The bounded timer applies only to published frames, not arbitrary RX. */
static inline int psta_next(struct psta_state*s,uint64_t now)
{
    if(!psta_time(s,now)||s->pending)return -1;if(s->phase>=4)return 0;
    if(s->phase&1){
        if(now<=s->deadline)return 0;
        if(s->attempts>=3){s->rejected=1;s->reason=UINT32_MAX;s->phase=5;return 0;}
        s->tx[1]|=8;s->pending=1;return 1;
    }
    for(unsigned n=0;n<sizeof(s->tx);n++)s->tx[n]=0;
    uint8_t*p=s->tx;p[0]=s->phase?0:0xb0;
    pwmi_copy(p+4,s->target.bssid,6);pwmi_copy(p+10,s->own,6);pwmi_copy(p+16,s->target.bssid,6);
    psta_put16(p+22,(s->sequence++&4095)<<4);s->attempts=0;
    if(!s->phase){psta_put16(p+26,1);s->tx_bytes=30;}
    else{
        psta_put16(p+24,s->target.capability&0x431);psta_put16(p+26,10); /* listen interval, no PS */
        p[28]=0;p[29]=(uint8_t)s->target.ssid_bytes;pwmi_copy(p+30,s->target.ssid,s->target.ssid_bytes);
        unsigned at=30+s->target.ssid_bytes,count=s->rate_count<8?s->rate_count:8;
        p[at++]=1;p[at++]=(uint8_t)count;pwmi_copy(p+at,s->rates,count);at+=count;
        if(s->rate_count>8){p[at++]=50;p[at++]=(uint8_t)(s->rate_count-8);pwmi_copy(p+at,s->rates+8,s->rate_count-8);at+=s->rate_count-8;}
        if(s->security==2){pwmi_copy(p+at,s->rsn,22);at+=22;}s->tx_bytes=at;
    }s->pending=1;return 1;
}
static inline int psta_sent(struct psta_state*s,uint64_t now,int published)
{
    if(!psta_time(s,now)||!s->pending||s->phase>=4)return -1;
    if(published!=1)return psta_fail(s,2);s->pending=0;s->phase|=1;s->attempts++;s->deadline=now+PSTA_WAIT;return 1;
}
/* Over-air malformed/foreign frames are ignored, never a transport failure.
 * associated only means the AP accepted association; it grants no data port,
 * key installation, IP interface, or successful WPA handshake. */
static inline int psta_frame(struct psta_state*s,const uint8_t*p,unsigned bytes,unsigned frequency,uint64_t now)
{
    if(!psta_time(s,now))return -1;if(!p||bytes<24||bytes>2048)return s->dropped++,1;
    if(p[0]!=0xb0&&p[0]!=0x10&&p[0]!=0xa0&&p[0]!=0xc0)return 0;
    if(frequency!=s->target.frequency||!psta_equal(p+4,s->own,6)||!psta_equal(p+10,s->target.bssid,6)||!psta_equal(p+16,s->target.bssid,6))return s->ignored++,1;
    if((p[1]&0xc7)||(p[22]&15)||bytes<26)return s->dropped++,1; /* DS, fragment, protected, order */
    if(p[0]==0xa0||p[0]==0xc0){
        if(s->phase==5)return 1;s->associated=0;s->rejected=1;s->reason=psta_u16(p+24);s->phase=5;s->pending=0;return 1;
    }
    if(bytes<30)return s->dropped++,1;
    if(p[0]==0xb0){
        if(s->phase!=1||s->pending)return s->ignored++,1;
        if(psta_u16(p+24)||psta_u16(p+26)!=2)return s->dropped++,1;
        unsigned status=psta_u16(p+28);if(status){s->rejected=1;s->reason=status;s->phase=5;return 1;}
        s->phase=2;s->attempts=0;return 1;
    }
    if(s->phase!=3||s->pending)return s->ignored++,1;
    unsigned status=psta_u16(p+26);if(status){s->rejected=1;s->reason=status;s->phase=5;return 1;}
    unsigned aid=psta_u16(p+28),caps=psta_u16(p+24);
    if((aid&0xc000)!=0xc000||!(aid&0x3fff)||(aid&0x3fff)>2007||!(caps&1)||(caps&2)||
       (!!(caps&16)!=(s->security==2))||!psta_rates(s,p+30,bytes-30))return s->dropped++,1;
    s->aid=aid&0x3fff;s->assoc_caps=caps;s->phase=4;s->associated=1;return 1;
}
static inline int psta_wmi(struct psta_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!psta_time(s,now))return -1;if(!p||bytes<4||bytes>PWMI_FRAME)return psta_fail(s,3);
    if((pwmi_get(p)&0xffffff)!=0x7001)return 0;
    unsigned at=0,tag=0,length=0,header_bytes=0,frame_bytes=0;const uint8_t*body=0,*header=0,*frame=0;int next;
    while((next=pwmi_tlv(p+4,bytes-4,&at,&tag,&length,&body))==1){
        if(tag==44){if(header)return psta_fail(s,3);header=body;header_bytes=length;}
        else if(tag==17){if(frame)return psta_fail(s,3);frame=body;frame_bytes=length;}
    }
    if(next<0||!header||header_bytes<40||!frame||pwmi_get(header+16)>frame_bytes)return psta_fail(s,3);
    if(pwmi_get(header+20)&0x39)return s->dropped++,1;
    unsigned channel=pwmi_get(header);if(channel<1||channel>11)return s->ignored++,1;
    return psta_frame(s,frame,pwmi_get(header+16),2407+5*channel,now);
}
#endif
