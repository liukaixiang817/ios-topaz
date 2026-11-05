/* Passive WMI TLV scan and bounded BSS collection. Primary ath10k
 * wmi-tlv.c/wmi.c/mac.c supplies command/event layouts. This is a bootstrap
 * receive-only 2.4 GHz profile; joining requires its own regulatory/TX setup. */
#ifndef POLARIS_WIFI_WMI_SCAN_H
#define POLARIS_WIFI_WMI_SCAN_H
#include "polaris-wifi-wmi-init.h"
#define PWSC_BSS 32u
#define PWSC_IES 768u
#define PWSC_WAIT UINT64_C(422400000) /* 22 seconds, original owner unchanged */
struct pwsc_bss {
    uint8_t bssid[6],ssid[32];uint16_t frequency,capability,interval,ie_bytes;
    uint32_t ssid_bytes,observations;int32_t snr;uint8_t ies[PWSC_IES];
};
struct pwsc_state {
    uint64_t epoch,last,deadline;uint32_t opened,error,unknown,phase,pending,tx_bytes;
    uint32_t scan_id,request_id,vdev,started,completed,events,foreign,ignored,dropped,count;
    uint8_t mac[6],tx[512];struct pwsc_bss bss[PWSC_BSS];
};
static inline int pwsc_fail(struct pwsc_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwsc_time(struct pwsc_state*s,uint64_t now)
{
    if(!s||!s->opened||s->unknown||s->error)return 0;
    if(now<s->last||now>UINT64_MAX-PWSC_WAIT||(s->phase<5&&now>s->deadline))return pwsc_fail(s,1),0;
    s->last=now;return 1;
}
static inline int pwsc_open(struct pwsc_state*s,const struct pwmi_state*w,unsigned scan,uint64_t now)
{
    if(!s||!w||w->phase!=4||w->unknown||w->error||!scan||scan>4095||now<w->last||now>UINT64_MAX-PWSC_WAIT)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    s->epoch=w->epoch;s->last=now;s->deadline=now+PWSC_WAIT;s->scan_id=0xa000|scan;s->request_id=0xa001;
    pwmi_copy(s->mac,w->mac,6);s->opened=1;return 1;
}
/* Commands are serialized: own-MAC station vdev0, passive channel list,
 * passive scan. Acceptance of VDEV_CREATE is established by later scan events,
 * not invented from a command's publication (there is no create reply here). */
static inline int pwsc_next(struct pwsc_state*s,uint64_t now)
{
    if(!pwsc_time(s,now)||s->pending)return -1;if(s->phase>=3)return 0;
    for(unsigned n=0;n<sizeof(s->tx);n++)s->tx[n]=0;
    uint8_t*p=s->tx;
    if(!s->phase){
        pwmi_put(p,0x5001);pwmi_header(p+4,86,20);pwmi_put(p+8,s->vdev);pwmi_put(p+12,2);pwmi_copy(p+20,s->mac,6);s->tx_bytes=28;
    }else if(s->phase==1){
        pwmi_put(p,0x3003);pwmi_header(p+4,79,4);pwmi_put(p+8,11);pwmi_header(p+12,18,11*28);
        for(unsigned n=0;n<11;n++){
            uint8_t*q=p+16+28*n;pwmi_header(q,80,24);pwmi_put(q+4,2412+5*n);pwmi_put(q+8,2412+5*n);
            pwmi_put(q+16,0x81); /* MODE_11G, passive; no TX power grant */
        }s->tx_bytes=324;
    }else{
        pwmi_put(p,0x3001);pwmi_header(p+4,77,100);
        const uint32_t common[15]={s->scan_id,s->request_id,s->vdev,1,0x15f,50,150,50,500,0,0,0,20000,5,0x31};
        for(unsigned n=0;n<15;n++)pwmi_put(p+8+4*n,common[n]);
        pwmi_put(p+72,11);pwmi_put(p+76,1);pwmi_put(p+88,3);
        pwmi_header(p+108,16,44);for(unsigned n=0;n<11;n++)pwmi_put(p+112+4*n,2412+5*n);
        pwmi_header(p+156,19,0);pwmi_header(p+160,19,8);for(unsigned n=0;n<6;n++)p[164+n]=255;
        pwmi_header(p+172,17,0);s->tx_bytes=176;
    }s->pending=1;return 1;
}
static inline int pwsc_sent(struct pwsc_state*s,uint64_t now,int published)
{
    if(!pwsc_time(s,now)||!s->pending||s->phase>=3)return -1;
    if(published!=1)return pwsc_fail(s,2);s->pending=0;s->phase++;if(s->phase==3)s->deadline=now+PWSC_WAIT;return 1;
}
static inline int pwsc_beacon(struct pwsc_state*s,const uint8_t*p,unsigned bytes,unsigned channel,int32_t snr)
{
    if(bytes<36||bytes-36>PWSC_IES||channel<1||channel>11||(p[0]!=0x80&&p[0]!=0x50)||(p[1]&0x43)||(p[16]&1)){s->dropped++;return 1;}
    unsigned nonzero=0;for(unsigned n=0;n<6;n++)nonzero|=p[16+n];if(!nonzero){s->dropped++;return 1;}
    unsigned at=36,ssid=0,ssid_bytes=0,seen=0;
    while(at<bytes){
        if(bytes-at<2){s->dropped++;return 1;}unsigned id=p[at],length=p[at+1];at+=2;
        if(length>bytes-at){s->dropped++;return 1;}
        if(!id){if(seen++||length>32){s->dropped++;return 1;}ssid=at;ssid_bytes=length;}
        if(id==3&&(length!=1||p[at]!=channel)){s->dropped++;return 1;}at+=length;
    }
    if(!seen){s->dropped++;return 1;}unsigned index=s->count;
    for(unsigned n=0;n<s->count;n++){
        unsigned equal=1;for(unsigned j=0;j<6;j++)if(s->bss[n].bssid[j]!=p[16+j])equal=0;
        if(equal&&s->bss[n].frequency==2407+channel*5){index=n;break;}
    }
    if(index==PWSC_BSS){s->dropped++;return 1;}struct pwsc_bss*b=&s->bss[index];
    if(index==s->count)s->count++;
    pwmi_copy(b->bssid,p+16,6);b->frequency=(uint16_t)(2407+5*channel);b->snr=snr;
    b->interval=(uint16_t)(p[32]|((unsigned)p[33]<<8));b->capability=(uint16_t)(p[34]|((unsigned)p[35]<<8));
    /* Hidden beacons must not erase a previously learned probe-response SSID. */
    if(ssid_bytes||!b->observations){b->ssid_bytes=ssid_bytes;for(unsigned n=0;n<32;n++)b->ssid[n]=n<ssid_bytes?p[ssid+n]:0;}
    b->ie_bytes=(uint16_t)(bytes-36);pwmi_copy(b->ies,p+36,bytes-36);b->observations++;return 1;
}
/* 1=consumed,0=retain for another consumer,-1=malformed matching WMI event.
 * Malformed over-the-air frames are dropped without poisoning the worker. */
static inline int pwsc_receive(struct pwsc_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!pwsc_time(s,now))return -1;if(!p||bytes<4||bytes>PWMI_FRAME)return pwsc_fail(s,3);
    unsigned event=pwmi_get(p)&0xffffff;if(event!=0x3001&&event!=0x7001)return 0;
    if(s->phase<3||s->phase>4)return 0;p+=4;bytes-=4;
    unsigned at=0,tag=0,length=0,header_bytes=0,frame_bytes=0;const uint8_t*body=0,*header=0,*frame=0;int next;
    while((next=pwmi_tlv(p,bytes,&at,&tag,&length,&body))==1){
        if(tag==(event==0x3001?36u:44u)){if(header)return pwsc_fail(s,3);header=body;header_bytes=length;}
        else if(event==0x7001&&tag==17){if(frame)return pwsc_fail(s,3);frame=body;frame_bytes=length;}
    }if(next<0||!header)return pwsc_fail(s,3);
    if(event==0x3001){
        if(header_bytes<24)return pwsc_fail(s,3);
        if(pwmi_get(header+12)!=s->request_id||pwmi_get(header+16)!=s->scan_id||pwmi_get(header+20)!=s->vdev){s->ignored++;return 1;}
        unsigned type=pwmi_get(header),reason=pwmi_get(header+4);s->events++;
        if(type==1){if(s->started||reason)return pwsc_fail(s,4);s->started=1;s->phase=4;}
        else if(type==2){if(!s->started||reason)return pwsc_fail(s,4);s->completed=1;s->phase=5;}
        else if(type==64||type==16||type==32)return pwsc_fail(s,4);
        else if(type==8){unsigned freq=pwmi_get(header+8);if(freq<2412||freq>2462||(freq-2412)%5)return pwsc_fail(s,4);s->foreign++;}
        else if(type!=4&&type!=256)return pwsc_fail(s,4);return 1;
    }
    if(header_bytes<40||!frame||pwmi_get(header+16)>frame_bytes)return pwsc_fail(s,3);
    if(pwmi_get(header+20)&0x39){s->dropped++;return 1;}
    unsigned actual=pwmi_get(header+16);
    if(actual>=2&&frame[0]!=0x80&&frame[0]!=0x50)return 0;
    return pwsc_beacon(s,frame,actual,pwmi_get(header),(int32_t)pwmi_get(header+4));
}
#endif
