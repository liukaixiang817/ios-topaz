/* Serialized WMI CCMP installation confirmed by actual HTT SEC_IND. Primary
 * ath10k mac.c waits for HTT, while WMI INSTALL_KEY_COMPLETE merely logs.
 * Command layout and zero sequence fields follow its TLV generator. The AP's
 * GTK RSC is retained separately as a mandatory receive replay floor. */
#ifndef POLARIS_WIFI_WMI_KEYS_H
#define POLARIS_WIFI_WMI_KEYS_H
#include "polaris-wifi-wpa.h"
#define PWKI_WAIT UINT64_C(57600000) /*3s per actual publication*/
struct pwki_state {
    uint64_t epoch,last,deadline;uint32_t opened,unknown,error,phase,pending,peer,gtk_id,confirmed,ignored,tx_bytes;
    uint8_t mac[6],tk[16],gtk[16],group_floor[8],tx[120];
};
static inline int pwki_fail(struct pwki_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwki_live(struct pwki_state*s,uint64_t now)
{
    if(!s||!s->opened||s->unknown||s->error)return 0;
    if(now<s->last||now>UINT64_MAX-PWKI_WAIT||((s->phase==1||s->phase==3)&&now>s->deadline))return pwki_fail(s,1),0;
    s->last=now;return 1;
}
static inline int pwki_open(struct pwki_state*s,const struct pwpa_state*w,unsigned peer,uint64_t now)
{
    if(!s||!w||peer>=2048||!w->opened||w->unknown||w->error||w->phase!=3||!w->keys_ready||!w->have_m3||
       !w->install_issued||w->installed||w->pending||w->gtk_id>3||now<w->last||now>UINT64_MAX-PWKI_WAIT)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    s->epoch=w->epoch;s->last=now;s->deadline=now+PWKI_WAIT;s->peer=peer;s->gtk_id=w->gtk_id;
    pwch_copy(s->mac,w->peer,6);pwch_copy(s->tk,w->tk,16);pwch_copy(s->gtk,w->gtk,16);pwch_copy(s->group_floor,w->rsc,8);s->opened=1;return 1;
}
static inline int pwki_group_open(struct pwki_state*s,const struct pwpa_state*w,unsigned peer,uint64_t now)
{
    if(!s||!w||peer>=2048||!w->opened||w->unknown||w->error||w->phase!=6||!w->authorized||!w->installed||
       !w->group_ready||!w->group_issued||w->pending||w->group_id>3||now<w->last||now>UINT64_MAX-PWKI_WAIT)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    s->epoch=w->epoch;s->last=now;s->deadline=now+PWKI_WAIT;s->peer=peer;s->gtk_id=w->group_id;
    s->phase=2;s->confirmed=1; /* existing PTK remains installed; do not send it again */
    pwch_copy(s->mac,w->peer,6);pwch_copy(s->gtk,w->group_key,16);pwch_copy(s->group_floor,w->group_rsc,8);s->opened=1;return 1;
}
static inline int pwki_next(struct pwki_state*s,uint64_t now)
{
    if(!pwki_live(s,now)||s->pending)return -1;if(s->phase!=0&&s->phase!=2&&s->phase!=4)return 0;
    pwch_wipe(s->tx,sizeof(s->tx));uint8_t*p=s->tx;unsigned group=s->phase==2;
    if(s->phase==4){
        /* mac.c authorizes the peer after pairwise key installation. Delay
         * until both keys are confirmed; still before opening our data port. */
        pwmi_put(p,0x6004);pwmi_header(p+4,100,20);pwch_copy(p+12,s->mac,6);pwmi_put(p+20,3);pwmi_put(p+24,1);
        s->tx_bytes=28;s->pending=1;return 1;
    }
    pwmi_put(p,0x5009);pwmi_header(p+4,96,92);pwch_copy(p+12,s->mac,6);
    pwmi_put(p+20,group?s->gtk_id:0);pwmi_put(p+24,group?1:0);pwmi_put(p+28,4);pwmi_put(p+88,16);
    pwmi_header(p+100,17,16);pwch_copy(p+104,group?s->gtk:s->tk,16);s->tx_bytes=120;s->pending=1;return 1;
}
static inline int pwki_sent(struct pwki_state*s,uint64_t now,int published)
{
    if(!pwki_live(s,now)||!s->pending||(s->phase!=0&&s->phase!=2&&s->phase!=4))return -1;
    if(published!=1)return pwki_fail(s,2);s->pending=0;s->phase++;s->deadline=now+PWKI_WAIT;pwch_wipe(s->tx,sizeof(s->tx));s->tx_bytes=0;return 1;
}
/*1=consumed,0=other peer/event,-1=inconsistent own security state. A duplicate
 * already-confirmed indication cannot acknowledge the other key or reset PN.
 * The indication contains no key index, so exactly one install may be pending.
 */
static inline int pwki_htt(struct pwki_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!pwki_live(s,now))return -1;if(!p||!bytes)return pwki_fail(s,3);if(p[0]!=11)return 0;
    if(bytes<28)return pwki_fail(s,3);if(psta_u16(p+2)!=s->peer){s->ignored++;return 0;}
    if((p[1]&127)!=6)return pwki_fail(s,4);
    unsigned bit=p[1]&128?1:2;
    if(s->confirmed&bit){s->ignored++;return 1;}
    if(s->pending||(bit==1?s->phase!=1:s->phase!=3))return pwki_fail(s,4);
    s->confirmed|=bit;s->phase++;
    if(s->phase==4){pwch_wipe(s->tk,16);pwch_wipe(s->gtk,16);}return 1;
}
#endif
