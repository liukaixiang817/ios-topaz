/* WCN3990 TLV station command ordering. Pure wire/state logic. Channel power
 * values are inputs from the radio's regulatory configuration, NOT a grant
 * created by observing an AP. The native owner must qualify that configuration
 * before this protocol can publish anything to hardware. */
#ifndef POLARIS_WIFI_WMI_STATION_H
#define POLARIS_WIFI_WMI_STATION_H
#include "polaris-wifi-station.h"
#define PWST_WAIT UINT64_C(96000000)
struct pwst_channel {uint16_t frequency;uint8_t min_power,max_power,reg_power,antenna,reg_class,reserved;};
struct pwst_state {
    struct psta_state station;struct pwst_channel channel;
    uint64_t last,deadline;uint32_t opened,error,unknown,phase,pending,kind,tx_bytes;
    uint32_t peer_id,peer_valid,start_received,up_published,ignored;
    uint8_t tx[256];
};
static inline int pwst_fail(struct pwst_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwst_live(struct pwst_state*s,uint64_t now)
{
    if(!s||!s->opened||s->unknown||s->error||s->station.unknown||s->station.error)return 0;
    if(now<s->last||now>UINT64_MAX-PWST_WAIT||
       ((s->phase==2||s->phase==4)&&now>s->deadline))return pwst_fail(s,1),0;
    s->last=now;return 1;
}
static inline int pwst_open(struct pwst_state*s,const struct pwsc_state*scan,unsigned index,unsigned security,
    const struct pwst_channel*c,uint64_t now)
{
    if(!s||!c||!scan||index>=scan->count||now>UINT64_MAX-PWST_WAIT||c->reserved||c->frequency!=scan->bss[index].frequency||
       c->min_power>c->max_power||c->max_power>c->reg_power)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    if(!psta_open(&s->station,scan,index,security,now))return 0;
    s->channel=*c;s->last=now;s->deadline=now+PWST_WAIT;s->opened=1;return 1;
}
static inline void pwst_channel_bytes(const struct pwst_channel*c,uint8_t*p)
{
    pwmi_header(p,80,24);pwmi_put(p+4,c->frequency);pwmi_put(p+8,c->frequency);pwmi_put(p+16,1); /* MODE_11G */
    p[20]=c->min_power;p[21]=c->max_power;p[22]=c->reg_power;p[23]=c->reg_class;p[24]=c->antenna;p[25]=c->max_power;
}
/* 1=prepared action,0=wait/finished,-1=error. kind1 WMI,kind2 management frame
 * for the selected supported MGMT_TX transport. All publication ACKs must
 * refer to the actual CE commit, not merely accepting a software queue. */
static inline int pwst_next(struct pwst_state*s,uint64_t now)
{
    if(!pwst_live(s,now)||s->pending)return -1;
    if(s->station.rejected){s->phase=9;s->up_published=0;return 0;}
    if(s->phase==2||s->phase==4||s->phase>=8)return 0;
    struct psta_state*a=&s->station;
    if(s->phase==5){
        if(a->associated)s->phase=6;
        else{
            int result=psta_next(a,now);if(result<0)return pwst_fail(s,2);if(!result)return 0;
            pwmi_copy(s->tx,a->tx,a->tx_bytes);s->tx_bytes=a->tx_bytes;s->kind=2;s->pending=1;return 1;
        }
    }
    for(unsigned n=0;n<sizeof(s->tx);n++)s->tx[n]=0;uint8_t*p=s->tx;s->kind=1;
    if(s->phase==0){
        /* Replace receive-only scan list with this separately qualified
         * active channel. No arbitrary widening of the scan's channel set. */
        pwmi_put(p,0x3003);pwmi_header(p+4,79,4);pwmi_put(p+8,1);pwmi_header(p+12,18,28);
        pwst_channel_bytes(&s->channel,p+16);s->tx_bytes=44;
    }else if(s->phase==1){
        pwmi_put(p,0x5003);pwmi_header(p+4,88,72);pwmi_put(p+12,1);pwmi_put(p+16,a->target.interval);
        pwmi_put(p+20,a->dtim);pwmi_put(p+28,a->target.ssid_bytes);pwmi_copy(p+32,a->target.ssid,a->target.ssid_bytes);
        pwst_channel_bytes(&s->channel,p+80);pwmi_header(p+108,18,0);s->tx_bytes=112;
    }else if(s->phase==3){
        pwmi_put(p,0x6001);pwmi_header(p+4,97,16);pwmi_copy(p+12,a->target.bssid,6);pwmi_put(p+20,1);s->tx_bytes=24;
    }else if(s->phase==6){
        pwmi_put(p,0x6005);pwmi_header(p+4,101,76);pwmi_copy(p+8,a->target.bssid,6);
        pwmi_put(p+20,1);pwmi_put(p+24,a->aid);pwmi_put(p+28,1|(a->security?4:0)); /* AUTH, NEED_PTK */
        pwmi_put(p+32,a->assoc_caps);pwmi_put(p+36,10);pwmi_put(p+56,1);pwmi_put(p+64,1);
        pwmi_put(p+76,a->rate_count);unsigned padded=(a->rate_count+3)&~3u;
        pwmi_header(p+84,17,padded);for(unsigned n=0;n<a->rate_count;n++)p[88+n]=a->rates[n]&127;
        pwmi_header(p+88+padded,17,0);pwmi_header(p+92+padded,102,16);s->tx_bytes=112+padded;
    }else if(s->phase==7){
        pwmi_put(p,0x5005);pwmi_header(p+4,92,16);pwmi_put(p+12,a->aid);pwmi_copy(p+16,a->target.bssid,6);s->tx_bytes=24;
    }else return pwst_fail(s,2);
    s->pending=1;return 1;
}
static inline int pwst_sent(struct pwst_state*s,uint64_t now,int published)
{
    if(!pwst_live(s,now)||!s->pending)return -1;if(published!=1)return pwst_fail(s,3);
    if(s->kind==2){if(s->phase!=5||psta_sent(&s->station,now,1)!=1)return pwst_fail(s,3);}
    else if(s->phase==0||s->phase==1||s->phase==3||s->phase==6||s->phase==7){
        s->phase++;s->deadline=now+PWST_WAIT;if(s->phase==8)s->up_published=1;
    }else return pwst_fail(s,3);s->pending=0;return 1;
}
/* Call only for the HTT parser's actual retained PEER_MAP/UNMAP event. Exact
 * BSSID/vdev matching is required. A command publication is not a peer map. */
static inline int pwst_peer(struct pwst_state*s,unsigned id,unsigned vdev,const uint8_t*mac,int present,uint64_t now)
{
    if(!pwst_live(s,now)||!mac||id>=2048||vdev>=4||(present!=0&&present!=1))return -1;
    if(vdev||!psta_equal(mac,s->station.target.bssid,6)){s->ignored++;return 0;}
    if(!present){
        if(!s->peer_valid||id!=s->peer_id)return pwst_fail(s,4);
        s->peer_valid=0;s->up_published=0;s->station.associated=0;s->station.rejected=1;s->phase=9;return 1;
    }
    if(s->phase!=4||s->pending||s->peer_valid)return pwst_fail(s,4);
    s->peer_id=id;s->peer_valid=1;s->phase=5;return 1;
}
static inline int pwst_wmi(struct pwst_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!pwst_live(s,now))return -1;if(!p||bytes<4||bytes>PWMI_FRAME)return pwst_fail(s,5);
    unsigned event=pwmi_get(p)&0xffffff;
    if(event==0x7001){
        /* Retain management before the selected channel/peer is established. */
        if(s->phase<5)return 0;int result=psta_wmi(&s->station,p,bytes,now);
        if(result<0)return pwst_fail(s,5);
        if(s->station.rejected){s->phase=9;s->pending=0;s->up_published=0;}return result;
    }
    if(event!=0x5001)return 0;
    unsigned at=0,tag=0,length=0,header_bytes=0;const uint8_t*body=0,*header=0;int next;
    while((next=pwmi_tlv(p+4,bytes-4,&at,&tag,&length,&body))==1){
        if(tag==40){if(header)return pwst_fail(s,5);header=body;header_bytes=length;}
    }
    if(next<0||!header||header_bytes<16)return pwst_fail(s,5);
    if(pwmi_get(header)||pwmi_get(header+4)!=1){s->ignored++;return 1;}
    if(s->phase!=2||s->pending||pwmi_get(header+8)||pwmi_get(header+12))return pwst_fail(s,6);
    s->start_received=1;s->phase=3;return 1;
}
#endif
