/* WCN3990 64-bit HTT setup, compared with primary ath10k htt.c/htt_tx.c.
 * RX v2 offsets were independently compiled from the pinned rx_desc.h.
 * This pure plan grants no memory/DMA rights; native publication is separate. */
#ifndef POLARIS_WIFI_HTT_INIT_H
#define POLARIS_WIFI_HTT_INIT_H
#include "polaris-wifi-wmi-init.h"
#define PHTM_BYTES 0x802000u
#define PHTM_RX 2048u
#define PHTM_TX 1056u
#define PHTM_BUFFER 2048u
#define PHTM_FRAGMENT 72u
#define PHTT_WAIT UINT64_C(57600000)
struct phtm_layout {
    uint64_t allocation;uint32_t bytes,used,index,ring,fragments,receive,transmit,reserved;
};
static inline int phtm_region(struct phtm_layout*l,unsigned bytes,uint32_t*out)
{
    uint32_t at=(l->used+4095u)&~4095u;
    if(at<l->used||at>PHTM_BYTES-4096||bytes>PHTM_BYTES-4096-at)return 0;
    *out=at;l->used=at+bytes;return 1;
}
static inline int phtm_plan(struct phtm_layout*l,uint64_t allocation)
{
    if(!l||!allocation||(allocation&4095)||allocation>(UINT64_C(1)<<35)-PHTM_BYTES)return 0;
    for(unsigned n=0;n<sizeof(*l);n++)if(((const uint8_t*)l)[n])return 0;
    l->allocation=allocation;l->bytes=PHTM_BYTES;l->used=4096;
    return phtm_region(l,4096,&l->index)&&phtm_region(l,8*PHTM_RX,&l->ring)&&
        phtm_region(l,PHTM_FRAGMENT*PHTM_TX,&l->fragments)&&
        phtm_region(l,PHTM_BUFFER*PHTM_RX,&l->receive)&&phtm_region(l,PHTM_BUFFER*PHTM_TX,&l->transmit);
}
static inline void phtt_put16(uint8_t*p,unsigned value)
{p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);}
static inline void phtt_put64(uint8_t*p,uint64_t value)
{pwmi_put(p,(uint32_t)value);pwmi_put(p+4,(uint32_t)(value>>32));}
struct phtt_state {
    uint64_t epoch,last,deadline;struct phtm_layout memory;
    uint32_t opened,error,unknown,phase,pending,tx_bytes,major,minor,published;
    uint8_t tx[64];
};
static inline int phtt_fail(struct phtt_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int phtt_time(struct phtt_state*s,uint64_t now)
{
    if(!s||!s->opened||s->unknown||s->error)return 0;
    if(now<s->last||now>UINT64_MAX-PHTT_WAIT||(s->phase<5&&now>s->deadline))return phtt_fail(s,1),0;
    s->last=now;return 1;
}
static inline int phtt_open(struct phtt_state*s,const struct phtm_layout*l,uint64_t epoch,uint64_t now)
{
    if(!s||!l||!epoch||!now||now>UINT64_MAX-PHTT_WAIT)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    struct phtm_layout expected={0};if(!phtm_plan(&expected,l->allocation))return 0;
    for(unsigned n=0;n<sizeof(*l);n++)if(((const uint8_t*)l)[n]!=((const uint8_t*)&expected)[n])return 0;
    s->memory=*l;s->epoch=epoch;s->last=now;s->deadline=now+PHTT_WAIT;s->opened=1;return 1;
}
static inline int phtt_next(struct phtt_state*s,uint64_t now)
{
    if(!phtt_time(s,now)||s->pending)return -1;if(s->phase==1||s->phase==5)return 0;
    for(unsigned n=0;n<sizeof(s->tx);n++)s->tx[n]=0;
    uint8_t*p=s->tx;const struct phtm_layout*m=&s->memory;
    if(!s->phase)s->tx_bytes=4;
    else if(s->phase==2){
        p[0]=6;p[2]=1;p[3]=PHTM_FRAGMENT;phtt_put64(p+4,m->allocation+m->fragments);
        phtt_put16(p+38,PHTM_TX-1);p[60]=1; /* no peer-flow-control q-state grant */
        s->tx_bytes=64;
    }else if(s->phase==3){
        p[0]=2;p[1]=1;phtt_put64(p+4,m->allocation+m->index);phtt_put64(p+12,m->allocation+m->ring);
        phtt_put16(p+20,PHTM_RX);phtt_put16(p+22,PHTM_BUFFER);phtt_put16(p+24,0xffff);phtt_put16(p+26,PHTM_RX-1);
        /* Byte offsets from independently compiled WCN3990 RX v2 descriptor:
         * hdr296,payload360,PPDU108/148,MPDU16/104,MSDU28/48,attention4,frag8. */
        const uint16_t offsets[10]={74,90,27,37,4,26,7,12,1,2};
        for(unsigned n=0;n<10;n++)phtt_put16(p+28+2*n,offsets[n]);s->tx_bytes=48;
    }else if(s->phase==4){p[0]=5;p[1]=64;p[2]=3;s->tx_bytes=4;}
    else return phtt_fail(s,2);
    s->pending=1;return 1;
}
static inline int phtt_sent(struct phtt_state*s,uint64_t now,int published)
{
    if(!phtt_time(s,now)||!s->pending||s->phase==1||s->phase>=5)return -1;
    if(published!=1)return phtt_fail(s,3);s->pending=0;s->phase++;s->published++;
    if(s->phase==1)s->deadline=now+PHTT_WAIT;return 1;
}
/* VERSION_CONF is the only setup reply; all other HTT messages stay retained
 * for actual peer/TX/RX processing. No response is invented for ring config. */
static inline int phtt_receive(struct phtt_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!phtt_time(s,now))return -1;if(!p||!bytes||bytes>2040)return phtt_fail(s,4);
    if(p[0])return 0;
    if(s->phase!=1||bytes<4||(p[2]!=2&&p[2]!=3))return phtt_fail(s,4);
    s->minor=p[1];s->major=p[2];s->phase=2;return 1;
}
#endif
