/* WCN3990 HTC control/framing, compared with primary ath10k htc.c/core.c.
 * Pure protocol; caller owns current native CE transport and its lifetime. */
#ifndef POLARIS_WIFI_HTC_H
#define POLARIS_WIFI_HTC_H
#include <stdint.h>
#include <stddef.h>
#define PHTC_ENDPOINTS 9u
#define PHTC_FRAME 2048u
#define PHTC_WAIT UINT64_C(19200000)
struct phtc_endpoint {uint16_t service,maximum,credits;uint8_t tx_pipe,rx_pipe,sequence,flow;};
struct phtc_state {
    uint64_t epoch,opening,last,deadline;
    struct phtc_endpoint endpoint[PHTC_ENDPOINTS];
    uint8_t tx[PHTC_FRAME],rx[PHTC_FRAME-8];
    uint32_t started,unknown,error,phase,pending,tx_bytes,tx_eid,tx_credit,frame_ready,rx_bytes,rx_eid;
    uint32_t target_credits,credit_size,max_endpoints,version,bundle_max,alt_credit_size;
    uint32_t htt,wmi,pktlog,received,sent;
};
static inline uint16_t phtc_u16(const uint8_t*p){return (uint16_t)(p[0]|((unsigned)p[1]<<8));}
static inline void phtc_put(uint8_t*p,unsigned v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static inline int phtc_fail(struct phtc_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int phtc_time(struct phtc_state*s,uint64_t now)
{
    if(!s||!s->started||s->unknown||s->error)return 0;
    if(now<s->last||now>UINT64_MAX-PHTC_WAIT||((s->phase==0||s->phase==2||s->phase==4||s->phase==7)&&now>s->deadline))return phtc_fail(s,1),0;
    s->last=now;return 1;
}
static inline int phtc_open(struct phtc_state*s,uint64_t epoch,uint64_t now)
{
    if(!s||!epoch||!now||now>UINT64_MAX-2*PHTC_WAIT)return -1;
    const uint8_t*b=(const uint8_t*)s;for(unsigned n=0;n<sizeof(*s);n++)if(b[n])return -1;
    s->epoch=epoch;s->opening=s->last=now;s->deadline=now+2*PHTC_WAIT;s->started=1;
    s->endpoint[0]=(struct phtc_endpoint){.service=1,.maximum=256,.tx_pipe=0,.rx_pipe=2};return 1;
}
static inline int phtc_header(struct phtc_state*s,unsigned eid,unsigned bytes)
{
    if(eid>=PHTC_ENDPOINTS||!s->endpoint[eid].service||s->pending||bytes>PHTC_FRAME-8||bytes>s->endpoint[eid].maximum)return -1;
    struct phtc_endpoint*e=&s->endpoint[eid];unsigned credit=0;
    if(e->flow){if(!s->credit_size)return phtc_fail(s,2);credit=(bytes+8+s->credit_size-1)/s->credit_size;if(credit>e->credits)return 0;}
    for(unsigned n=0;n<8;n++)s->tx[n]=0;s->tx[0]=(uint8_t)eid;s->tx[1]=e->flow?1:0;
    phtc_put(s->tx+2,bytes);s->tx[5]=e->sequence;s->tx_eid=eid;s->tx_bytes=bytes+8;s->tx_credit=credit;s->pending=1;return 1;
}
/*0=no outgoing control frame,1=tx[] ready,-1=sticky protocol failure. */
static inline int phtc_next(struct phtc_state*s,uint64_t now)
{
    if(!phtc_time(s,now)||s->pending)return -1;
    if(s->phase!=1&&s->phase!=3&&s->phase!=5&&s->phase!=6)return 0;
    unsigned bytes=s->phase==5?12:8;for(unsigned n=0;n<bytes;n++)s->tx[8+n]=0;
    if(s->phase==5)phtc_put(s->tx+8,5);
    else{
        unsigned service=s->phase==1?0x300:s->phase==3?0x100:0x600;
        phtc_put(s->tx+8,2);phtc_put(s->tx+10,service);
        /* WCN3990 uses one initial WMI credit, not the reported total, per
         * use_fw_tx_credits=false. All other services disable credit flow. */
        phtc_put(s->tx+12,service==0x100?0x100:8);
    }return phtc_header(s,0,bytes);
}
static inline int phtc_sent(struct phtc_state*s,uint64_t now,int published)
{
    if(!phtc_time(s,now)||!s->pending)return -1;
    if(published!=1||s->tx_eid>=PHTC_ENDPOINTS)return phtc_fail(s,3);
    struct phtc_endpoint*e=&s->endpoint[s->tx_eid];if(e->credits<s->tx_credit)return phtc_fail(s,3);
    e->credits=(uint16_t)(e->credits-s->tx_credit);e->sequence++;s->pending=0;s->sent++;
    if(s->phase==1||s->phase==3||s->phase==6){s->phase++;s->deadline=now+PHTC_WAIT;}
    else if(s->phase==5)s->phase=6;return 1;
}
static inline int phtc_data(struct phtc_state*s,unsigned eid,const uint8_t*data,unsigned bytes,uint64_t now)
{
    if(!phtc_time(s,now)||s->phase!=8||!data||!bytes||!eid||eid>=PHTC_ENDPOINTS||s->endpoint[eid].tx_pipe==255)return -1;
    unsigned maximum=s->endpoint[eid].tx_pipe==4?248:2040;if(bytes>maximum)return -1;
    int result=phtc_header(s,eid,bytes);if(result!=1)return result;
    for(unsigned n=0;n<bytes;n++)s->tx[8+n]=data[n];return 1;
}
static inline int phtc_trailer(struct phtc_state*s,const uint8_t*p,unsigned bytes)
{
    unsigned at=0;uint32_t credits[PHTC_ENDPOINTS]={0};
    while(at<bytes){
        if(bytes-at<4)return 0;unsigned id=p[at],length=p[at+1];at+=4;if(length>bytes-at)return 0;
        if(id==1){
            if(!length||(length&3))return 0;
            for(unsigned n=0;n<length;n+=4){unsigned eid=p[at+n];if(eid>=PHTC_ENDPOINTS||!s->endpoint[eid].service)return 0;credits[eid]+=p[at+n+1];}
        }at+=length;
    }
    for(unsigned n=0;n<PHTC_ENDPOINTS;n++)if(credits[n]>65535u-s->endpoint[n].credits)return 0;
    for(unsigned n=0;n<PHTC_ENDPOINTS;n++)s->endpoint[n].credits=(uint16_t)(s->endpoint[n].credits+credits[n]);return 1;
}
static inline int phtc_receive(struct phtc_state*s,unsigned pipe,const uint8_t*frame,unsigned bytes,uint64_t now)
{
    if(!phtc_time(s,now))return -1;
    if(!frame||bytes<8||bytes>PHTC_FRAME)return phtc_fail(s,4);
    unsigned eid=frame[0],flags=frame[1],length=phtc_u16(frame+2),trailer=flags&2?frame[4]:0;
    if(eid>=PHTC_ENDPOINTS||!s->endpoint[eid].service||
       (pipe!=s->endpoint[eid].rx_pipe&&!(s->endpoint[eid].service==0x300&&(pipe==9||pipe==10)))||
       (flags&~3u)||length>bytes-8||bytes-8-length>3||trailer>length||(trailer&&trailer<4)||((flags&2)&&!trailer))return phtc_fail(s,4);
    if(trailer&&!phtc_trailer(s,frame+8+length-trailer,trailer))return phtc_fail(s,5);
    length-=trailer;s->received++;if(!length)return 0;
    const uint8_t*p=frame+8;
    if(eid){
        if(s->frame_ready)return phtc_fail(s,6);for(unsigned n=0;n<length;n++)s->rx[n]=p[n];
        s->rx_eid=eid;s->rx_bytes=length;s->frame_ready=1;return 2;
    }
    if(length<2)return phtc_fail(s,6);unsigned message=phtc_u16(p);
    if(message==1){
        if(s->phase||length<8||length>256||!phtc_u16(p+4)||p[6]<3)return phtc_fail(s,7);
        s->target_credits=phtc_u16(p+2);s->credit_size=phtc_u16(p+4);s->max_endpoints=p[6];
        if(length>=12){s->version=p[8];s->bundle_max=p[9];s->alt_credit_size=phtc_u16(p+10)&0xfff;}
        s->phase=1;return 1;
    }
    if(message==3){
        if((s->phase!=2&&s->phase!=4&&s->phase!=7)||length<8||length>256)return phtc_fail(s,8);
        unsigned service=s->phase==2?0x300:s->phase==4?0x100:0x600,id=p[5],maximum=phtc_u16(p+6);
        if(phtc_u16(p+2)!=service||p[4]||!id||id>=PHTC_ENDPOINTS||id>=s->max_endpoints||s->endpoint[id].service||!maximum)return phtc_fail(s,8);
        s->endpoint[id]=(struct phtc_endpoint){.service=(uint16_t)service,.maximum=(uint16_t)maximum,
            .credits=service==0x100?1:0,.tx_pipe=service==0x300?4:service==0x100?3:255,
            .rx_pipe=service==0x300?1:service==0x100?2:11,.flow=service==0x100};
        if(service==0x300)s->htt=id;else if(service==0x100)s->wmi=id;else s->pktlog=id;
        s->phase++;return 1;
    }
    /* Suspend complete is not consumed by this active bootstrap profile. */
    return phtc_fail(s,9);
}
static inline int phtc_ack(struct phtc_state*s)
{if(!s||s->unknown||s->error||s->frame_ready!=1)return 0;s->frame_ready=0;s->rx_bytes=0;return 1;}
#endif
