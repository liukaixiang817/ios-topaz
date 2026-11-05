/* Single-MSDU legacy station decapsulation and controlled port. WCN3990 v2
 * offsets come from the compiled primary rx_desc definitions. This initial
 * non-QoS/no-HT profile rejects A-MSDU, fragments and offloaded RX metadata;
 * those paths cannot inherit security evidence they do not carry. */
#ifndef POLARIS_WIFI_ETHERNET_H
#define POLARIS_WIFI_ETHERNET_H
#include "polaris-wifi-wmi-keys.h"
#define PWEN_FRAME 1514u
struct pwen_state {
    uint64_t epoch,pn[2],group_floor;
    uint32_t opened,closed,peer,security,keys_seen,authorized,gtk_id,rx_ready,rx_bytes,rx_kind,tx_bytes,tx_plain;
    uint64_t dropped,replayed,received,sent;uint32_t group_generation,group_blocked;
    uint8_t own[6],ap[6],receive[PWEN_FRAME],transmit[PWEN_FRAME];
};
static inline uint64_t pwen_pn(const uint8_t*p)
{uint64_t n=0;for(unsigned i=0;i<6;i++)n|=(uint64_t)p[i]<<(8*i);return n;}
static inline int pwen_open(struct pwen_state*s,const struct psta_state*a,unsigned peer)
{
    if(!s||!a||peer>=2048||!a->opened||a->unknown||a->error||!a->associated||a->rejected||a->phase!=4||(a->security!=0&&a->security!=2))return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    s->epoch=a->epoch;s->peer=peer;s->security=a->security;pwch_copy(s->own,a->own,6);pwch_copy(s->ap,a->target.bssid,6);s->opened=1;
    s->authorized=a->security==0;return 1;
}
/* Called from the native key owner after each actual security indication.
 * Repeated snapshots cannot reset any PN; GTK floor is installed only once.
 */
static inline int pwen_keys(struct pwen_state*s,const struct pwki_state*k,const struct pwpa_state*w)
{
    if(!s||!s->opened||s->closed||s->security!=2||!k||!w||!k->opened||k->unknown||k->error||k->epoch!=s->epoch||k->peer!=s->peer||
       !psta_equal(k->mac,s->ap,6)||!w->opened||w->unknown||w->error||w->epoch!=s->epoch||!w->install_issued||!w->have_m3||
       !psta_equal(w->peer,s->ap,6)||!psta_equal(w->own,s->own,6)||(k->confirmed&~3u)||k->confirmed==2||(s->keys_seen&~k->confirmed)||
       (w->authorized&&(!w->installed||k->phase!=5||k->confirmed!=3)))return 0;
    if(k->confirmed&1)s->keys_seen|=1;
    if(k->confirmed&2){
        uint64_t floor=pwen_pn(k->group_floor);if(k->group_floor[6]||k->group_floor[7]||k->gtk_id>3)return 0;
        if(s->keys_seen&2){if(s->gtk_id!=k->gtk_id||s->group_floor!=floor)return 0;}
        else{s->gtk_id=k->gtk_id;s->group_floor=s->pn[1]=floor;s->keys_seen|=2;}
    }
    s->authorized=w->authorized&&w->installed&&s->keys_seen==3;return 1;
}
/* A new confirmed GTK resets only its own receive floor. Duplicate EAPOL
 * messages never call this boundary; the native installer supplies generation. */
static inline int pwen_group(struct pwen_state*s,const struct pwki_state*k,const struct pwpa_state*w)
{
    if(!s||!s->opened||s->closed||!s->authorized||s->keys_seen!=3||!k||!w||k->unknown||k->error||k->phase!=5||k->confirmed!=3||
       k->epoch!=s->epoch||k->peer!=s->peer||!psta_equal(k->mac,s->ap,6)||!w->authorized||!w->installed||w->unknown||w->error||
       w->epoch!=s->epoch||!w->group_generation||w->group_generation!=s->group_generation+1||k->gtk_id!=w->gtk_id||k->gtk_id>3||
       !psta_equal(k->group_floor,w->rsc,8)||w->rsc[6]||w->rsc[7])return 0;
    s->gtk_id=k->gtk_id;s->group_floor=s->pn[1]=pwen_pn(k->group_floor);s->group_generation=w->group_generation;s->group_blocked=0;return 1;
}
/* Raw is the private2048-byte copy made by the native HTT transport. bytes is
 * the in-order indication's payload length, not an untrusted Ethernet length.
 *1=Ethernet data,2=EAPOL,0=dropped,-1=invalid caller/backpressure.
 */
static inline int pwen_receive(struct pwen_state*s,const uint8_t*raw,unsigned raw_bytes,unsigned bytes,unsigned peer,unsigned vdev,unsigned htt_info)
{
    if(!s||!s->opened||s->closed||s->rx_ready||!raw)return -1;
    if(raw_bytes!=2048||bytes<32||bytes>1688||peer!=s->peer||vdev||(htt_info&0x60))return s->dropped++,0;
    uint32_t attention=pwmi_get(raw+4),mpdu=pwmi_get(raw+16),msdu_end=pwmi_get(raw+64);
    const uint32_t bad=(1u<<3)|(1u<<4)|(1u<<7)|(1u<<8)|(1u<<9)|(1u<<13)|(3u<<16)|(31u<<26);
    if(!(attention&(1u<<31))||(attention&bad)||(msdu_end&0xc000)!=0xc000||(msdu_end&(1u<<18))||
       ((pwmi_get(raw+36)>>8)&3)!=1||pwpa_nonzero(raw+8,8))return s->dropped++,0;
    const uint8_t*original=raw+296,*frame=raw+360;
    if(original[0]!=8||frame[0]!=8||(original[1]&0x87)!=2||(frame[1]&0x87)!=2||(original[22]&15)||(frame[22]&15)||
       !psta_equal(original+4,frame+4,18)||!psta_equal(original+10,s->ap,6)||(original[16]&1)||
       !pwpa_nonzero(original+16,6)||(!(original[4]&1)&&!psta_equal(original+4,s->own,6)))return s->dropped++,0;
    const uint8_t snap[6]={170,170,3,0,0,0};if(!psta_equal(frame+24,snap,6))return s->dropped++,0;
    unsigned type=pwpa_be16(frame+30),payload=bytes-32,group=original[4]&1;
    if(type<1536||!payload||payload>1500)return s->dropped++,0;
    unsigned eapol=type==0x888e,encrypted=(mpdu>>13)&1;
    if(encrypted!=((original[1]>>6)&1)||((mpdu>>11)&3)!=1)return s->dropped++,0;
    if(eapol){if(group||!psta_equal(original+16,s->ap,6))return s->dropped++,0;}
    else if(!s->authorized||(group&&s->group_blocked)||(attention&(1u<<24)))return s->dropped++,0;
    uint64_t pn=0;
    if(encrypted){
        unsigned which=group?1:0;if(s->security!=2||!(s->keys_seen&(1u<<which))||(mpdu>>28)!=6)return s->dropped++,0;
        const uint8_t*iv=original+24;unsigned keyid=iv[3]>>6;
        if(iv[2]||(iv[3]&63)!=32||raw[52]!=iv[3]||keyid!=(group?s->gtk_id:0))return s->dropped++,0;
        uint8_t wire_pn[6]={iv[0],iv[1],iv[4],iv[5],iv[6],iv[7]};pn=pwen_pn(raw+20);
        if(pn!=pwen_pn(wire_pn)||pn<=s->pn[which])return s->replayed++,0;
    }else if(s->security==2&&!eapol)return s->dropped++,0;
    pwch_copy(s->receive,frame+4,6);pwch_copy(s->receive+6,frame+16,6);pwch_copy(s->receive+12,frame+30,2);
    pwch_copy(s->receive+14,frame+32,payload);s->rx_bytes=payload+14;s->rx_kind=eapol?2:1;s->rx_ready=1;s->received++;
    if(encrypted)s->pn[group?1:0]=pn;return (int)s->rx_kind;
}
static inline int pwen_ack(struct pwen_state*s)
{
    if(!s||!s->opened||s->closed||!s->rx_ready)return 0;
    pwch_wipe(s->receive,s->rx_bytes);s->rx_ready=s->rx_bytes=s->rx_kind=0;return 1;
}
/* Only the EAPOL worker can use this entry before the controlled port opens.
 * Native sender selects Ethernet HTT mode2/TID16 and NO_ENCRYPT for this frame.
 */
static inline int pwen_eapol(struct pwen_state*s,const uint8_t*p,unsigned bytes)
{
    if(!s||!s->opened||s->closed||s->tx_bytes||!p||bytes<4||bytes>PWPA_MESSAGE||4+pwpa_be16(p+2)!=bytes)return 0;
    pwch_copy(s->transmit,s->ap,6);pwch_copy(s->transmit+6,s->own,6);s->transmit[12]=0x88;s->transmit[13]=0x8e;
    pwch_copy(s->transmit+14,p,bytes);s->tx_bytes=bytes+14;s->tx_plain=1;return 1;
}
static inline int pwen_data(struct pwen_state*s,const uint8_t*p,unsigned bytes)
{
    if(!s||!s->opened||s->closed||!s->authorized||s->tx_bytes||!p||bytes<15||bytes>PWEN_FRAME||
       !psta_equal(p+6,s->own,6)||!pwpa_nonzero(p,6)||pwpa_be16(p+12)<1536||pwpa_be16(p+12)==0x888e)return 0;
    pwch_copy(s->transmit,p,bytes);s->tx_bytes=bytes;s->tx_plain=s->security==0;return 1;
}
static inline int pwen_sent(struct pwen_state*s)
{
    if(!s||!s->opened||s->closed||!s->tx_bytes)return 0;
    pwch_wipe(s->transmit,s->tx_bytes);s->tx_bytes=s->tx_plain=0;s->sent++;return 1;
}
static inline void pwen_stop(struct pwen_state*s)
{
    if(!s)return;s->closed=1;s->authorized=s->rx_ready=s->rx_bytes=s->rx_kind=s->tx_bytes=s->tx_plain=0;
    pwch_wipe(s->receive,sizeof(s->receive));pwch_wipe(s->transmit,sizeof(s->transmit));
}
#endif
