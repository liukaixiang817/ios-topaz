/* HTT buffer ownership and TLV-family messages. CE completion only releases
 * the command buffer; a TX MSDU stays owned until its explicit HTT completion.
 * Pure protocol: callers perform DMA cache/copy/publication separately. */
#ifndef POLARIS_WIFI_HTT_RING_H
#define POLARIS_WIFI_HTT_RING_H
#include "polaris-wifi-htt-init.h"
#define PHTR_RX_BATCH 169u
struct phtr_peer {uint16_t id;uint8_t valid,vdev,mac[6];};
struct phtr_rx {uint16_t slot,bytes;uint8_t fw,reserved[3];};
struct phtr_state {
    struct phtm_layout memory;uint64_t epoch;
    uint32_t opened,error,unknown,busy,major,tx_cursor,tx_id,tx_length,tx_bytes,tx_mode;
    uint32_t rx_index,rx_posted,rx_count,rx_at,rx_info,rx_peer,rx_vdev,repost_slot,repost_next;
    uint64_t sent,completed,received,reposted;
    uint8_t tx_owner[PHTM_TX],tx_status[PHTM_TX],rx_owner[PHTM_RX];
    uint8_t command[72],fragment[72],ring_entry[8];
    struct phtr_rx rx[PHTR_RX_BATCH];struct phtr_peer peer[66];
};
static inline unsigned phtr_u16(const uint8_t*p){return p[0]|((unsigned)p[1]<<8);}
static inline uint64_t phtr_u64(const uint8_t*p){return pwmi_get(p)|((uint64_t)pwmi_get(p+4)<<32);}
static inline int phtr_fail(struct phtr_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int phtr_live(const struct phtr_state*s)
{return s&&s->opened&&!s->unknown&&!s->error;}
static inline int phtr_open(struct phtr_state*s,const struct phtt_state*h)
{
    if(!s||!h||!h->opened||h->unknown||h->error||h->phase!=5||h->published!=4)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    s->memory=h->memory;s->epoch=h->epoch;s->major=h->major;s->rx_index=PHTM_RX-1;s->rx_posted=PHTM_RX-1;
    for(unsigned n=0;n<PHTM_RX-1;n++)s->rx_owner[n]=1;s->opened=1;return 1;
}
/* 1=retained pending frame,0=no free TX slot,-1=invalid input. Data is a
 * complete native-WiFi, Ethernet or (HTT3) management frame; encryption flags
 * come from the station/key state, not inferred from frame contents. */
static inline int phtr_tx(struct phtr_state*s,const uint8_t*data,unsigned bytes,unsigned mode,unsigned vdev,unsigned tid,unsigned no_encrypt)
{
    if(!phtr_live(s)||s->busy||!data||bytes<14||bytes>PHTM_BUFFER||mode<1||mode>3||(mode!=2&&bytes<24)||vdev>=4||tid>17||no_encrypt>1||(mode==3&&s->major<3))return -1;
    unsigned id=s->tx_cursor,n=0;for(;n<PHTM_TX;n++,id=(id+1)%PHTM_TX)if(!s->tx_owner[id])break;if(n==PHTM_TX)return 0;
    for(n=0;n<72;n++)s->command[n]=s->fragment[n]=0;
    uint64_t address=s->memory.allocation+s->memory.transmit+(uint64_t)PHTM_BUFFER*id;
    unsigned prefetch=(bytes<50?bytes:50);prefetch=(prefetch+3)&~3u;
    s->command[0]=1;s->command[1]=(uint8_t)((mode<<5)|(mode==2?0:1)|(no_encrypt?4:0));
    phtt_put16(s->command+2,vdev|(tid<<6)|0x800);phtt_put16(s->command+4,bytes);phtt_put16(s->command+6,id);
    phtt_put64(s->command+8,mode==3?address:s->memory.allocation+s->memory.fragments+(uint64_t)PHTM_FRAGMENT*id);
    pwmi_put(s->command+16,65535);
    for(n=0;n<prefetch;n++)s->command[20+n]=n<bytes?data[n]:0;
    pwmi_put(s->fragment+24,(uint32_t)address);phtt_put16(s->fragment+28,(unsigned)(address>>32));phtt_put16(s->fragment+30,bytes);
    s->tx_id=id;s->tx_length=bytes;s->tx_bytes=20+prefetch;s->tx_mode=mode;s->busy=1;s->tx_owner[id]=1;return 1;
}
static inline int phtr_tx_published(struct phtr_state*s,int published)
{
    if(!phtr_live(s)||s->busy!=1||s->tx_owner[s->tx_id]!=1)return -1;
    if(published!=1)return phtr_fail(s,1);s->tx_owner[s->tx_id]=2;s->tx_cursor=(s->tx_id+1)%PHTM_TX;s->sent++;s->busy=0;return 1;
}
/* Completion is validated in full before any slot changes ownership. Optional
 * RSSI/stats suffix bytes are retained by the caller; only bounded IDs release
 * buffers. Double completion and mixed valid/invalid lists are errors. */
static inline int phtr_completion(struct phtr_state*s,const uint8_t*p,unsigned bytes)
{
    if(bytes<4)return phtr_fail(s,2);unsigned count=p[2],status=p[1]&7;
    if(!count||status>3||bytes<4+2*count)return phtr_fail(s,2);
    for(unsigned n=0;n<count;n++){
        unsigned id=phtr_u16(p+4+2*n);if(id>=PHTM_TX||s->tx_owner[id]!=2)return phtr_fail(s,2);
        for(unsigned j=0;j<n;j++)if(phtr_u16(p+4+2*j)==id)return phtr_fail(s,2);
    }
    for(unsigned n=0;n<count;n++){unsigned id=phtr_u16(p+4+2*n);s->tx_owner[id]=3;s->tx_status[id]=(uint8_t)status;s->completed++;}return 1;
}
static inline int phtr_tx_ack(struct phtr_state*s,unsigned id,unsigned*status)
{
    if(!phtr_live(s)||!status||id>=PHTM_TX||s->tx_owner[id]!=3)return 0;
    *status=s->tx_status[id];s->tx_owner[id]=0;return 1;
}
static inline int phtr_peer(struct phtr_state*s,const uint8_t*p,unsigned bytes)
{
    if(bytes<4)return phtr_fail(s,3);unsigned id=phtr_u16(p+2);if(id>=2048)return phtr_fail(s,3);
    unsigned slot=66,free_slot=66;
    for(unsigned n=0;n<66;n++){if(s->peer[n].valid&&s->peer[n].id==id)slot=n;else if(!s->peer[n].valid&&free_slot==66)free_slot=n;}
    if(p[0]==4){if(slot==66)return phtr_fail(s,3);s->peer[slot].valid=0;return 1;}
    if(bytes<12||p[1]>=4||(p[4]&1)||slot!=66||free_slot==66)return phtr_fail(s,3);
    unsigned nonzero=0;for(unsigned n=0;n<6;n++)nonzero|=p[4+n];if(!nonzero)return phtr_fail(s,3);
    struct phtr_peer*q=&s->peer[free_slot];q->valid=1;q->id=(uint16_t)id;q->vdev=p[1];pwmi_copy(q->mac,p+4,6);return 1;
}
static inline int phtr_indication(struct phtr_state*s,const uint8_t*p,unsigned bytes)
{
    if(bytes<8||s->rx_count||s->busy)return phtr_fail(s,4);unsigned count=phtr_u16(p+6);
    if(!count||count>PHTR_RX_BATCH||count>s->rx_posted||bytes<8+12*count||(p[1]&0x80)||p[4]>=4)return phtr_fail(s,4);
    uint64_t first=s->memory.allocation+s->memory.receive;
    for(unsigned n=0;n<count;n++){
        const uint8_t*q=p+8+12*n;uint64_t address=phtr_u64(q);unsigned length=phtr_u16(q+8);
        if(address<first||address-first>=(uint64_t)PHTM_RX*PHTM_BUFFER||(address-first)%PHTM_BUFFER||
           !length||length>(p[1]&0x20?PHTM_BUFFER:PHTM_BUFFER-360))return phtr_fail(s,4);
        unsigned slot=(unsigned)((address-first)/PHTM_BUFFER);if(s->rx_owner[slot]!=1)return phtr_fail(s,4);
        for(unsigned j=0;j<n;j++)if(phtr_u64(p+8+12*j)==address)return phtr_fail(s,4);
    }
    for(unsigned n=0;n<count;n++){
        const uint8_t*q=p+8+12*n;unsigned slot=(unsigned)((phtr_u64(q)-first)/PHTM_BUFFER);
        s->rx[n]=(struct phtr_rx){(uint16_t)slot,(uint16_t)phtr_u16(q+8),q[10],{0,0,0}};s->rx_owner[slot]=2;
    }
    s->rx_count=count;s->rx_at=0;s->rx_info=p[1];s->rx_peer=phtr_u16(p+2);s->rx_vdev=p[4];s->rx_posted-=count;return 1;
}
static inline int phtr_event(struct phtr_state*s,const uint8_t*p,unsigned bytes)
{
    if(!phtr_live(s)||!p||!bytes||bytes>2040)return -1;
    if(p[0]==7)return phtr_completion(s,p,bytes);
    if(p[0]==3||p[0]==4)return phtr_peer(s,p,bytes);
    if(p[0]==0x12)return phtr_indication(s,p,bytes);
    return 0;
}
/* After native cache invalidate and copying the indicated RX bytes to retained
 * private memory. No target-owned buffer can be cleared or reused earlier. */
static inline int phtr_rx_copied(struct phtr_state*s,unsigned slot,int copied)
{
    if(!phtr_live(s)||s->rx_at>=s->rx_count||s->rx[s->rx_at].slot!=slot||s->rx_owner[slot]!=2)return -1;
    if(copied!=1)return phtr_fail(s,5);s->rx_owner[slot]=0;s->rx_at++;s->received++;
    if(s->rx_at==s->rx_count)s->rx_count=s->rx_at=0;return 1;
}
static inline int phtr_repost(struct phtr_state*s,unsigned slot)
{
    if(!phtr_live(s)||s->busy||slot>=PHTM_RX||s->rx_owner[slot]||s->rx_posted>=PHTM_RX-1)return -1;
    s->repost_slot=slot;s->repost_next=(s->rx_index+1)&(PHTM_RX-1);s->busy=2;
    phtt_put64(s->ring_entry,s->memory.allocation+s->memory.receive+(uint64_t)PHTM_BUFFER*slot);return 1;
}
/* Caller zeroes/cleans buffer, stores/cleans ring entry, then stores/cleans
 * alloc-index with ordering. Failure retains pending ownership permanently. */
static inline int phtr_reposted(struct phtr_state*s,int published)
{
    if(!phtr_live(s)||s->busy!=2)return -1;if(published!=1)return phtr_fail(s,6);
    s->rx_owner[s->repost_slot]=1;s->rx_index=s->repost_next;s->rx_posted++;s->reposted++;s->busy=0;return 1;
}
#endif
