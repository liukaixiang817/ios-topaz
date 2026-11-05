/* Persistent CPU0 mailbox/radio worker. A successful request reply means
 * accepted, not scan/join/IP completion; actual radio events drive NOTIFY.
 * No original firmware services, allocation, secret logging or DMA release.
 * Disconnect/reconnect retirement is not implemented by this worker yet. */
#ifndef POLARIS_UEFI_WIFI_WORKER_NATIVE_H
#define POLARIS_UEFI_WIFI_WORKER_NATIVE_H
#ifndef EFI_XNU_WIFI_WORKER_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_WORKER_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_WORKER_NATIVE_AVAILABLE
#include "uefi-wifi-mailbox-native.h"
#include "../../tools/polaris-wifi-control-wire.h"
#include "../../tools/polaris-wifi-regulatory.h"
#if !EFI_XNU_WIFI_MAILBOX_NATIVE_AVAILABLE
#error Native worker requires qualified native mailbox and network
#endif
enum pwwn_phase {PWWN_IDLE,PWWN_SCAN,PWWN_SCANNED,PWWN_PMK,PWWN_REGULATORY,PWWN_JOIN,PWWN_LINK,PWWN_CLOSED};
struct pwwn_state {
    struct pwmn_state mailbox;struct pmwsn_state scan;struct pmst_state station;struct pmwn_state network;
    struct pwrg_profile regulatory;struct pwch_pmk derivation;struct pwst_channel channel;
    struct pwmb_message request,packet;
    uint8_t reply[16+PWCB_BSS_HEADER+PWCB_IES],pmk[32],event[16];
    uint64_t turns,ignored,tx_dropped,rx_dropped,close_deadline,retirement;
    uint32_t ready,unknown,error,phase,scan_id,index,reply_bytes,event_pending,tx_pending,reg_submitted,reg_published,country,closing;
};
static inline struct pwns_parent*pwwn_parent(struct pwwn_state*s)
{return (void*)(uintptr_t)s->mailbox.parent;}
static inline void pwwn_secrets(struct pwwn_state*s)
{pwch_wipe(s->pmk,32);pwch_wipe(&s->derivation,sizeof(s->derivation));pwch_wipe(&s->request,sizeof(s->request));}
static inline int pwwn_fail(struct pwwn_state*s,unsigned error)
{
    s->unknown=1;if(!s->error)s->error=error;pwwn_secrets(s);
    if(s->network.ready)pmwn_close(&s->network);return -1;
}
static inline int pwwn_live(struct pwwn_state*s)
{return s&&s->ready&&!s->unknown&&!s->error&&!s->retirement&&pwmn_current(&s->mailbox);}
static inline void pwwn_event(struct pwwn_state*s,unsigned event,unsigned error,uint64_t detail)
{
    /* One pending event is bounded. Link-down/fault supersedes an unread scan
     * or link-up; STATE always reports current state independently. */
    pwmb_put32(s->event,event);pwmb_put32(s->event+4,error);pwmb_put64(s->event+8,detail);s->event_pending=1;
}
static inline int pwwn_begin(struct pwwn_state*s,struct pwns_parent*p,unsigned country)
{
    if(!s||!p||country!=36||!pwmb_zero(s,sizeof(*s))||pwkr_poll(p)!=2)return 0;
    struct pmsc_owner*o=&p->owner;const struct pweh_result*h=(void*)(uintptr_t)o->retained;
    if(!pmwi_child(&p->htc,(uintptr_t)s,sizeof(*s))||
       !pmsi_image_range(h->input.early,&h->map,(uintptr_t)s,sizeof(*s))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)p,sizeof(*p)))return 0;
    const uint64_t at[]={o->runtime.copy,o->runtime.context,o->runtime.stack,o->retained,o->memory,o->mba,(uintptr_t)h->input.early};
    const uint64_t bytes[]={sizeof(struct pwks_image),sizeof(struct polaris_efi_ap),o->runtime.stack_bytes,sizeof(*h),sizeof(struct pmmn_native),sizeof(struct pmsb_result),sizeof(struct pwea_native)};
    for(unsigned n=0;n<7;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    if(p->wmi.consumer||p->data.consumer||!pmhd_live(&p->data)||!pmnp_live(&p->nonce)||!pwmn_begin(&s->mailbox,p))return 0;
    s->country=country;s->ready=1;pwwn_event(s,1,0,0);return pwwn_live(s);
}
/* Normal host quiescence for the later radio OFF continuation. Stop new BSD
 * TX first, but keep servicing submitted HTT/WMI and handshake completions.
 * This API neither sends OFF nor deletes peers nor retires remote DMA. */
static inline int pwwn_quiesce_begin(struct pwwn_state*s)
{
    if(!pwwn_live(s)||s->closing||s->phase!=PWWN_LINK)return 0;
    uint64_t now=pwwn_parent(s)->owner.last;if(now>UINT64_MAX-192000000)return 0;
    s->close_deadline=now+192000000;s->closing=1;return 1;
}
static inline int pwwn_quiesce_poll(struct pwwn_state*s)
{
    if(!s->closing)return 1;if(s->closing==2)return 2;
    struct pwns_parent*p=pwwn_parent(s);
    if(p->owner.last>s->close_deadline)return pwwn_fail(s,15);
    if(s->network.closed)return pwwn_fail(s,15); /* Unexpected loss is not normal drain. */
    if(s->network.submitted||s->network.tx_wait||s->network.ethernet.tx_bytes||
       s->network.wpa.pending||s->network.wpa.group_ready||s->network.wpa.group_issued||
       s->station.submitted||s->station.mgmt_wait||p->htc.client.pending||p->htc.frame_kind||
       p->data.submitted||p->data.frame_ready||p->data.rings.busy||p->transport.busy||p->transport.rings.busy)return 1;
    for(unsigned n=0;n<PHTM_TX;n++)if(p->data.rings.tx_owner[n])return 1;
    for(unsigned n=0;n<12;n++)if(p->transport.rings.source[n].posted)return 1;
    pmwn_close(&s->network);s->phase=PWWN_CLOSED;s->closing=2;pwwn_event(s,4,0,0);return 2;
}
static inline void pwwn_state_body(struct pwwn_state*s,uint8_t*out)
{
    pwmb_clear(out,PWCB_STATE_BYTES);unsigned flags=1;
    if(s->phase==PWWN_LINK)flags|=2;if(s->unknown)flags=(flags&~2u)|4;
    if(s->phase==PWWN_SCAN)flags|=8;
    if(s->phase>=PWWN_PMK&&s->phase<=PWWN_JOIN)flags|=16;
    if(s->phase==PWWN_CLOSED)flags|=32;
    pwmb_put32(out,flags);pwmb_put32(out+4,s->error?5:0);pwmb_put32(out+8,s->scan.client.count);
    if(s->station.ready){const struct pwsc_bss*b=&s->station.client.station.target;
        pwmb_put32(out+12,b->frequency);pwmi_copy(out+16,b->bssid,6);out[22]=(uint8_t)b->ssid_bytes;pwmi_copy(out+24,b->ssid,b->ssid_bytes);}
}
static inline unsigned pwwn_bss(struct pwwn_state*s,unsigned index,uint8_t*out)
{
    if(index>=s->scan.client.count)return 0;const struct pwsc_bss*b=&s->scan.client.bss[index];
    if(b->ie_bytes>PWCB_IES||b->ssid_bytes>32)return 0;
    unsigned bytes=PWCB_BSS_HEADER+b->ie_bytes;pwmb_clear(out,bytes);
    pwmb_put32(out,index);pwmb_put32(out+4,b->frequency);pwmb_put32(out+8,(uint32_t)b->snr);pwmb_put32(out+12,b->observations);
    pwcb_put16(out+16,b->capability);pwcb_put16(out+18,b->interval);pwcb_put16(out+20,b->ie_bytes);
    out[24]=(uint8_t)b->ssid_bytes;pwmi_copy(out+25,b->bssid,6);pwmi_copy(out+32,b->ssid,b->ssid_bytes);
    pwmi_copy(out+64,b->ies,b->ie_bytes);return pwcb_bss_valid(out,bytes)?bytes:0;
}
/* Process an already validated private CONTROL copy. Errnos use Darwin's
 * numeric ABI, not the build host's errno.h. No returned body holds secrets. */
static inline int pwwn_control(struct pwwn_state*s)
{
    struct pwns_parent*p=pwwn_parent(s);struct pwmb_message*q=&s->request;
    unsigned error=0,bytes=16;pwmb_clear(s->reply,sizeof(s->reply));
    pwmb_put64(s->reply,q->sequence);pwmb_put32(s->reply+8,q->operation);
    if(s->closing&&q->operation!=PWMB_STATE&&q->operation!=PWMB_SCAN_ENTRY)error=16;
    else if(q->operation==PWMB_STATE){pwwn_state_body(s,s->reply+16);bytes+=PWCB_STATE_BYTES;}
    else if(q->operation==PWMB_SCAN_ENTRY){
        unsigned n=pwwn_bss(s,pwmb_u32(q->data),s->reply+16);if(!n)error=2;else bytes+=n;
    }else if(q->operation==PWMB_SCAN){
        if(s->phase!=PWWN_IDLE&&s->phase!=PWWN_SCANNED)error=16;
        else if(s->scan_id==4095)error=75;
        else if(!(s->scan.ready?pmwsn_restart(&s->scan,s->scan_id+1):pmwsn_begin(&s->scan,&p->wmi,s->scan_id+1)))error=16;
        else{s->scan_id++;s->phase=PWWN_SCAN;}
    }else if(q->operation==PWMB_JOIN){
        if(s->phase!=PWWN_SCANNED)error=16;
        else{
            unsigned chosen=PWSC_BSS;int32_t strength=INT32_MIN;
            for(unsigned n=0;n<s->scan.client.count;n++){const struct pwsc_bss*b=&s->scan.client.bss[n];
                if(b->ssid_bytes==q->data[4]&&psta_equal(b->ssid,q->data+16,b->ssid_bytes)&&
                   (pwmb_zero(q->data+8,6)||psta_equal(b->bssid,q->data+8,6))&&(chosen==PWSC_BSS||b->snr>strength)){chosen=n;strength=b->snr;}}
            if(chosen==PWSC_BSS)error=2;
            else{
                pwmb_clear(&s->regulatory,sizeof(s->regulatory));
                if(!pwrg_make(&s->regulatory,&p->wmi.client,s->country)||!pwrg_channel(&s->regulatory,&p->wmi.client,s->scan.client.bss[chosen].frequency,&s->channel))error=45;
                else if(q->data[6]==1&&!pwch_pmk_open(&s->derivation,q->data+48,q->data[5],q->data+16,q->data[4]))error=22;
                else{s->index=chosen;if(q->data[6]==2){pwch_copy(s->pmk,q->data+48,32);s->phase=PWWN_REGULATORY;}else s->phase=PWWN_PMK;}
            }
        }
    }else if(q->operation==PWMB_DISCONNECT)error=45; /* No false retirement/reconnect claim. */
    else error=22;
    pwmb_put32(s->reply+12,error);s->reply_bytes=bytes;
    pwch_wipe(q,sizeof(*q));return pwcb_reply_valid(s->reply,bytes)?1:pwwn_fail(s,1);
}
/* Retained events have passed HTC/HTT framing and relevant typed consumers.
 * Unknown WMI events must still have valid TLVs before being discarded. No
 * discarded event advances a scan, association, key or regulatory state. */
static inline int pwwn_other(struct pwwn_state*s)
{
    struct pmhc_state*h=&pwwn_parent(s)->htc;
    if(h->frame_kind==1&&h->client.rx_eid==h->client.wmi){
        if(h->client.rx_bytes<4)return 0;unsigned at=0,tag=0,bytes=0;const uint8_t*body=0;int next;
        while((next=pwmi_tlv(h->client.rx+4,h->client.rx_bytes-4,&at,&tag,&bytes,&body))==1){}
        if(next<0)return 0;
    }
    if(s->ignored==UINT64_MAX||!pmhc_ack(h))return 0;s->ignored++;return 1;
}
static inline int pwwn_radio(struct pwwn_state*s)
{
    struct pwns_parent*p=pwwn_parent(s);struct pmhc_state*h=&p->htc;int result;
    if(s->phase==PWWN_JOIN||s->phase==PWWN_LINK){
        result=pmwn_step(&s->network);if(result<0)return pwwn_fail(s,2);
        if(result==2&&!pwwn_other(s))return pwwn_fail(s,3);
        if(result==4){s->phase=PWWN_CLOSED;pwwn_event(s,4,0,0);return 1;}
        if(s->network.ethernet.authorized&&s->phase!=PWWN_LINK){s->phase=PWWN_LINK;pwwn_event(s,3,0,0);}
        if(result==3){
            int sent;
            if(s->closing){if(s->rx_dropped==UINT64_MAX)return pwwn_fail(s,4);s->rx_dropped++;sent=1;}
            else sent=pwmn_send(&s->mailbox,PWMB_RX,PWMB_ETHERNET_RX,s->network.ethernet.receive,s->network.ethernet.rx_bytes);
            if(sent<0)return pwwn_fail(s,4);if(sent&&!pmwn_ack(&s->network))return pwwn_fail(s,4);}
        return 1;
    }
    if(s->phase==PWWN_SCAN){
        result=pmwsn_step(&s->scan);if(result<0)return pwwn_fail(s,5);
        if(result==3){s->phase=PWWN_SCANNED;pwwn_event(s,2,0,s->scan.client.count);}
        if(result!=2)return 1;
    }
    result=pmhd_poll(&p->data);if(result<0)return pwwn_fail(s,6);
    if(result==2&&!pwwn_other(s))return pwwn_fail(s,3);
    if(result==3){if(s->rx_dropped==UINT64_MAX||!pmhd_ack(&p->data))return pwwn_fail(s,6);s->rx_dropped++;}
    if(s->phase==PWWN_PMK){
        int crypto=pwch_pmk_step(&s->derivation,32);if(!crypto)return pwwn_fail(s,7);
        if(crypto==2){pwch_copy(s->pmk,s->derivation.pmk,32);pwch_wipe(&s->derivation,sizeof(s->derivation));s->phase=PWWN_REGULATORY;}
    }
    if(s->phase==PWWN_REGULATORY){
        if(!pwrg_channel(&s->regulatory,&p->wmi.client,s->channel.frequency,&s->channel))return pwwn_fail(s,8);
        if(!s->reg_submitted&&!h->client.pending&&!h->frame_kind){
            int sent=pmhc_send(h,h->client.wmi,s->regulatory.command,28);if(sent<0)return pwwn_fail(s,8);if(sent)s->reg_submitted=1;
        }
        /* Queue acceptance is insufficient: HTC pending clears only after
         * CE publication. SET_REGDOMAIN has no dedicated WMI response. */
        if(s->reg_submitted&&!h->client.pending&&!h->frame_kind&&!p->data.frame_ready){
            s->reg_published=1;
            if(!pmst_begin(&s->station,&s->scan,&p->data,s->index,2,&s->channel)||
               !pmwn_begin_pool(&s->network,&s->station,s->pmk,&p->nonce))return pwwn_fail(s,9);
            pwch_wipe(s->pmk,32);s->phase=PWWN_JOIN;
        }
    }return 1;
}
/* One bounded service turn; no wait loop for a peer, PBKDF2 or firmware event.
 *1=continue,2=normal host quiescence: caller must immediately advance radio
 * retirement. It must not resume this worker to refill/post another CE ring. */
static inline int pwwn_step(struct pwwn_state*s)
{
    if(!pwwn_live(s))return s?pwwn_fail(s,10):-1;
    if(s->closing==2)return 2;
    if(s->turns==UINT64_MAX)return pwwn_fail(s,10);s->turns++;
    if(pwwn_radio(s)<0)return -1;
    if(s->event_pending){int result=pwmn_send(&s->mailbox,PWMB_EVENT,PWMB_NOTIFY,s->event,16);
        if(result<0)return pwwn_fail(s,11);if(result)s->event_pending=0;}
    if(s->reply_bytes){int result=pwmn_send(&s->mailbox,PWMB_REPLY,PWMB_RESPONSE,s->reply,s->reply_bytes);
        if(result<0)return pwwn_fail(s,12);if(result){pwmb_clear(s->reply,sizeof(s->reply));s->reply_bytes=0;}}
    if(!s->reply_bytes){int result=pwmn_receive(&s->mailbox,PWMB_CONTROL,&s->request);
        if(result<0)return pwwn_fail(s,13);
        if(result&&(pwwn_control(s)<0||pwmn_complete(&s->mailbox,PWMB_CONTROL)!=1))return pwwn_fail(s,13);}
    if(!s->tx_pending){int result=pwmn_receive(&s->mailbox,PWMB_TX,&s->packet);
        if(result<0)return pwwn_fail(s,14);if(result)s->tx_pending=1;}
    if(s->tx_pending){
        unsigned done=0;
        const uint8_t*frame=s->packet.data;unsigned bytes=s->packet.bytes;
        unsigned valid=bytes>=15&&bytes<=1514&&psta_equal(frame+6,pwwn_parent(s)->wmi.client.mac,6)&&
            pwpa_nonzero(frame,6)&&pwpa_be16(frame+12)>=1536&&pwpa_be16(frame+12)!=0x888e;
        if(s->phase==PWWN_LINK&&!s->closing&&valid)done=pmwn_send(&s->network,frame,bytes);
        else{if(s->tx_dropped==UINT64_MAX)return pwwn_fail(s,14);s->tx_dropped++;done=1;}
        if(done){pwch_wipe(&s->packet,sizeof(s->packet));s->tx_pending=0;if(pwmn_complete(&s->mailbox,PWMB_TX)!=1)return pwwn_fail(s,14);}
    }return pwwn_quiesce_poll(s);
}
#endif
#endif
