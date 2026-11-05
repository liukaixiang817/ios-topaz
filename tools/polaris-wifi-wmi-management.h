/* Service76 management DMA publication. A dedicated page is independent of
 * the HTT MSDU rings; only the matching WMI completion releases its contents. */
#ifndef POLARIS_WIFI_WMI_MANAGEMENT_H
#define POLARIS_WIFI_WMI_MANAGEMENT_H
#include "polaris-wifi-htt-init.h"
#define PWMG_WAIT UINT64_C(57600000)
struct pwmg_state {
    uint64_t epoch,buffer,last,deadline;
    uint32_t opened,unknown,error,phase,sequence,id,frame_bytes,tx_bytes,status,completed;
    uint8_t tx[104];
};
static inline int pwmg_fail(struct pwmg_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwmg_live(struct pwmg_state*s,uint64_t now)
{
    if(!s||!s->opened||s->unknown||s->error)return 0;
    if(now<s->last||now>UINT64_MAX-PWMG_WAIT||(s->phase==2&&now>s->deadline))return pwmg_fail(s,1),0;
    s->last=now;return 1;
}
static inline int pwmg_open(struct pwmg_state*s,const struct phtm_layout*l,uint64_t epoch,uint64_t now)
{
    if(!s||!l||!epoch||!now||now>UINT64_MAX-PWMG_WAIT)return 0;
    struct phtm_layout expected={0};if(!phtm_plan(&expected,l->allocation))return 0;
    for(unsigned n=0;n<sizeof(*l);n++)if(((const uint8_t*)l)[n]!=((const uint8_t*)&expected)[n])return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    s->epoch=epoch;s->last=now;s->buffer=l->allocation+l->management;s->opened=1;return 1;
}
static inline int pwmg_prepare(struct pwmg_state*s,const uint8_t*frame,unsigned bytes,uint64_t now)
{
    if(!pwmg_live(s,now)||s->phase||!frame||bytes<24||bytes>256||(frame[0]&0xf)!=0||s->sequence==UINT32_MAX)return -1;
    for(unsigned n=0;n<sizeof(s->tx);n++)s->tx[n]=0;
    unsigned copy=bytes<64?bytes:64,padded=(copy+3)&~3u;uint8_t*p=s->tx;
    s->id=++s->sequence;pwmi_put(p,0x7008);pwmi_header(p+4,422,28);pwmi_put(p+12,s->id);
    phtt_put64(p+20,s->buffer);pwmi_put(p+28,bytes);pwmi_put(p+32,padded);pwmi_header(p+36,17,padded);
    pwmi_copy(p+40,frame,copy);s->frame_bytes=bytes;s->tx_bytes=40+padded;s->phase=1;return 1;
}
static inline int pwmg_sent(struct pwmg_state*s,uint64_t now,int published)
{
    if(!pwmg_live(s,now)||s->phase!=1)return -1;if(published!=1)return pwmg_fail(s,2);
    s->phase=2;s->deadline=now+PWMG_WAIT;return 1;
}
/* Single in-flight command. Bundle support checks all array lengths before
 * accepting its single report. Unrelated IDs cannot release our DMA page. */
static inline int pwmg_event(struct pwmg_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!pwmg_live(s,now))return -1;if(!p||bytes<4)return 0;
    unsigned event=pwmi_get(p)&0xffffff;if(event!=0x7006&&event!=0x7007)return 0;
    unsigned at=4,header=0,arrays=0,id=0,status=0,count=0;
    while(at<bytes){
        if(bytes-at<4)return pwmg_fail(s,3);unsigned n=pwmi_get(p+at)&65535,tag=pwmi_get(p+at)>>16;at+=4;
        if(n>bytes-at||(n&3))return pwmg_fail(s,3);
        if(event==0x7006&&tag==423){if(header++||(n!=16&&n!=20))return pwmg_fail(s,3);id=pwmi_get(p+at);status=pwmi_get(p+at+4);}
        else if(event==0x7007&&tag==552){if(header++||n!=4)return pwmg_fail(s,3);count=pwmi_get(p+at);}
        else if(event==0x7007&&tag==16){
            if(n!=4||arrays==4)return pwmg_fail(s,3);
            if(arrays==0)id=pwmi_get(p+at);if(arrays==1)status=pwmi_get(p+at);arrays++;
        }
        at+=n;
    }
    if(header!=1||(event==0x7007&&(count!=1||arrays<2)))return pwmg_fail(s,3);
    if(s->phase!=2||id!=s->id)return 0;s->status=status;s->phase=3;s->completed++;return 1;
}
static inline int pwmg_ack(struct pwmg_state*s,uint64_t now)
{
    if(!pwmg_live(s,now)||s->phase!=3)return 0;s->phase=0;s->frame_bytes=s->tx_bytes=0;
    for(unsigned n=0;n<sizeof(s->tx);n++)s->tx[n]=0;return 1;
}
#endif
