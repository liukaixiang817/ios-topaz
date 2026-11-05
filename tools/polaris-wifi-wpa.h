/* WPA2-PSK/CCMP four-way handshake. Protocol only: fresh SNonce and PMK are
 * supplied by separately qualified producers. AP RSN IE is bound to the actual
 * selected association. Keys are installable once; authenticated retries get
 * another message4 without reinstalling keys or resetting packet counters. */
#ifndef POLARIS_WIFI_WPA_H
#define POLARIS_WIFI_WPA_H
#include "polaris-wifi-station.h"
#include "polaris-wifi-wpa-crypto.h"
#define PWPA_MESSAGE 640u
#define PWPA_WAIT UINT64_C(384000000) /*20s, does not renew the native owner*/
struct pwpa_state {
    uint64_t epoch,last,deadline;
    uint32_t opened,error,unknown,phase,pending,reply_bytes,rx_bytes,bad,ignored,retries;
    uint32_t derived,have_m3,keys_ready,install_issued,installed,authorized,gtk_id;
    uint8_t own[6],peer[6],pmk[32],snonce[32],anonce[32],kck[16],kek[16],tk[16],gtk[16],rsc[8];
    uint8_t replay1[8],replay3[8],m3_digest[20],own_rsn[22],ap_rsn[257];uint32_t ap_rsn_bytes;
    uint8_t rx[PWPA_MESSAGE],reply[128];struct pwch_unwrap unwrap;
};
static inline unsigned pwpa_be16(const uint8_t*p){return ((unsigned)p[0]<<8)|p[1];}
static inline void pwpa_put16(uint8_t*p,unsigned n){p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n;}
static inline int pwpa_compare(const uint8_t*a,const uint8_t*b,unsigned n)
{for(unsigned i=0;i<n;i++){if(a[i]<b[i])return -1;if(a[i]>b[i])return 1;}return 0;}
static inline int pwpa_nonzero(const uint8_t*p,unsigned n)
{unsigned v=0;for(unsigned i=0;i<n;i++)v|=p[i];return v!=0;}
static inline int pwpa_fail(struct pwpa_state*s,unsigned error)
{s->unknown=1;s->authorized=0;if(!s->error)s->error=error;return -1;}
static inline int pwpa_time(struct pwpa_state*s,uint64_t now)
{
    if(!s||!s->opened||s->unknown||s->error)return 0;
    if(now<s->last)return pwpa_fail(s,1),0;s->last=now;
    if(!s->authorized&&now>s->deadline){s->phase=5;s->pending=0;s->keys_ready=0;return 0;}
    return s->phase!=5;
}
static inline int pwpa_open(struct pwpa_state*s,const struct psta_state*a,const uint8_t pmk[32],const uint8_t nonce[32],uint64_t now)
{
    if(!s||!a||!pmk||!nonce||!a->opened||a->unknown||a->error||!a->associated||a->rejected||a->security!=2||a->phase!=4||
       a->rsn_bytes<20||a->rsn_bytes>257||!pwpa_nonzero(nonce,32)||now<a->last||now>UINT64_MAX-PWPA_WAIT)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    pwch_copy(s->own,a->own,6);pwch_copy(s->peer,a->target.bssid,6);pwch_copy(s->pmk,pmk,32);pwch_copy(s->snonce,nonce,32);
    pwch_copy(s->own_rsn,a->rsn,22);pwch_copy(s->ap_rsn,a->ap_rsn,a->rsn_bytes);s->ap_rsn_bytes=a->rsn_bytes;
    s->epoch=a->epoch;s->last=now;s->deadline=now+PWPA_WAIT;s->opened=1;return 1;
}
static inline void pwpa_derive(struct pwpa_state*s)
{
    uint8_t data[76],digest[20],keys[48],counter;struct pwch_hmac h;
    int first=pwpa_compare(s->own,s->peer,6)<0;
    pwch_copy(data,first?s->own:s->peer,6);pwch_copy(data+6,first?s->peer:s->own,6);
    first=pwpa_compare(s->snonce,s->anonce,32)<0;
    pwch_copy(data+12,first?s->snonce:s->anonce,32);pwch_copy(data+44,first?s->anonce:s->snonce,32);
    const uint8_t label[]="Pairwise key expansion";const uint8_t*parts[]={label,data,&counter};const unsigned lengths[]={sizeof(label),76,1};
    pwch_hmac_init(&h,s->pmk,32);
    for(unsigned n=0;n<3;n++){counter=(uint8_t)n;(void)pwch_hmac_parts(&h,parts,lengths,3,digest);pwch_copy(keys+20*n,digest,n==2?8:20);}
    pwch_copy(s->kck,keys,16);pwch_copy(s->kek,keys+16,16);pwch_copy(s->tk,keys+32,16);s->derived=1;
    pwch_wipe(&h,sizeof(h));pwch_wipe(data,sizeof(data));pwch_wipe(digest,sizeof(digest));pwch_wipe(keys,sizeof(keys));
}
static inline void pwpa_mic(const struct pwpa_state*s,const uint8_t*p,unsigned bytes,uint8_t mic[16])
{
    const uint8_t zeros[16]={0};const uint8_t*parts[]={p,zeros,p+97};const unsigned lengths[]={81,16,bytes-97};
    uint8_t digest[20];struct pwch_hmac h;pwch_hmac_init(&h,s->kck,16);
    (void)pwch_hmac_parts(&h,parts,lengths,3,digest);pwch_copy(mic,digest,16);pwch_wipe(digest,20);pwch_wipe(&h,sizeof(h));
}
static inline void pwpa_reply(struct pwpa_state*s,const uint8_t*p,unsigned kind)
{
    pwch_wipe(s->reply,sizeof(s->reply));uint8_t*q=s->reply;unsigned data=kind==2?22:0;
    q[0]=p[0];q[1]=3;pwpa_put16(q+2,95+data);q[4]=2;pwpa_put16(q+5,kind==2?0x10a:0x30a);
    pwch_copy(q+9,p+9,8);if(kind==2){pwch_copy(q+17,s->snonce,32);pwch_copy(q+99,s->own_rsn,22);}
    pwpa_put16(q+97,data);s->reply_bytes=99+data;pwpa_mic(s,q,s->reply_bytes,q+81);s->pending=kind;
}
/*1=consumed,0=unrelated/backpressure,-1=invalid worker. Invalid network input
 * is dropped without poisoning native DMA/service ownership. Ethernet source/
 * destination and controlled-port checks belong to the native frame consumer.
 */
static inline int pwpa_receive(struct pwpa_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!pwpa_time(s,now))return s&&s->phase==5?0:-1;
    if(s->pending||s->phase==2)return 0;
    if(!p||bytes<4||p[1]!=3)return 0;
    unsigned length=4+pwpa_be16(p+2);
    if((p[0]!=1&&p[0]!=2)||length<99||length>PWPA_MESSAGE||length>bytes||p[4]!=2||pwpa_be16(p+97)!=length-99)return s->bad++,1;
    unsigned info=pwpa_be16(p+5),data=length-99;
    if(info==0x8a){
        if(s->have_m3||s->install_issued||s->phase>1)return s->ignored++,1;
        if(pwpa_be16(p+7)!=16||!pwpa_nonzero(p+17,32)||pwpa_nonzero(p+81,16))return s->bad++,1;
        if(s->derived){
            if(pwpa_compare(p+9,s->replay1,8)<0||!psta_equal(p+17,s->anonce,32))return s->bad++,1;
            s->retries++;
        }else{pwch_copy(s->anonce,p+17,32);pwpa_derive(s);}
        pwch_copy(s->replay1,p+9,8);pwpa_reply(s,p,2);return 1;
    }
    if(info!=0x13ca)return s->ignored++,1; /* group rekey has its own future state */
    if(!s->derived||pwpa_be16(p+7)!=16||!psta_equal(p+17,s->anonce,32)||data<24||data>520||(data&7)||
       pwpa_compare(p+9,s->replay1,8)<=0||p[71]||p[72])return s->bad++,1;
    uint8_t mic[16];pwpa_mic(s,p,length,mic);int valid=psta_equal(mic,p+81,16);pwch_wipe(mic,16);
    if(!valid)return s->bad++,1;
    if(s->have_m3){
        int order=pwpa_compare(p+9,s->replay3,8);if(order<0)return s->bad++,1;
        /* Exact retry can reuse its validated result. A larger authenticated
         * counter must unwrap and verify the same GTK, without reinstalling. */
        struct pwch_sha1 sha;uint8_t digest[20];pwch_sha_init(&sha);pwch_sha_add(&sha,p,length);pwch_sha_final(&sha,digest);
        valid=psta_equal(digest,s->m3_digest,20);pwch_wipe(digest,20);
        if(!order){if(!valid)return s->bad++,1;s->retries++;pwpa_reply(s,p,4);return 1;}
    }
    pwch_copy(s->rx,p,length);s->rx_bytes=length;pwch_wipe(&s->unwrap,sizeof(s->unwrap));
    if(!pwch_unwrap_open(&s->unwrap,s->kek,p+99,data))return pwpa_fail(s,2);s->phase=2;return 1;
}
/* Verify the AP's RSN binding and exact16-byte GTK KDE before exposing keys.
 * Padding is a single0xdd followed by zeros. Unknown bounded KDEs are skipped. */
static inline int pwpa_keys(struct pwpa_state*s)
{
    const uint8_t*p=s->unwrap.plain;unsigned bytes=s->unwrap.bytes,at=0,rsn=0,gtk=0,key_at=0,key_id=0;
    while(at<bytes){
        unsigned left=bytes-at;
        if(p[at]==221&&(left==1||!p[at+1])){
            for(unsigned n=at+1;n<bytes;n++)if(p[n])return 0;at=bytes;break;
        }
        if(left<2||p[at+1]>left-2)return 0;unsigned length=p[at+1];
        if(p[at]==48){if(rsn++||length+2!=s->ap_rsn_bytes||!psta_equal(p+at,s->ap_rsn,length+2))return 0;}
        if(p[at]==221&&length>=4&&psta_suite(p+at+2,1)){
            if(gtk++||length!=22||(p[at+6]&~7u)||p[at+7])return 0;key_at=at+8;key_id=p[at+6]&3;
        }at+=2+length;
    }
    if(!rsn||!gtk)return 0;
    if(s->have_m3)return s->gtk_id==key_id&&psta_equal(s->gtk,p+key_at,16);
    pwch_copy(s->gtk,p+key_at,16);s->gtk_id=key_id;pwch_copy(s->rsc,s->rx+65,8);return 1;
}
/*1=progress/wait,2=reply pending,3=keys ready for one native installation,
 *4=authorized by explicit native completion,0=timeout/rejected,-1=unknown. */
static inline int pwpa_step(struct pwpa_state*s,uint64_t now)
{
    if(!pwpa_time(s,now))return s&&s->phase==5?0:-1;
    if(s->phase==2){
        int result=pwch_unwrap_step(&s->unwrap,1);
        if(result==-1||(result==2&&!pwpa_keys(s))){
            pwch_wipe(&s->unwrap,sizeof(s->unwrap));s->phase=s->have_m3?(s->installed?4:3):1;s->bad++;return 1;
        }
        if(result==0)return pwpa_fail(s,2);
        if(result==1)return 1;
        if(result==2){
            struct pwch_sha1 sha;pwch_sha_init(&sha);pwch_sha_add(&sha,s->rx,s->rx_bytes);pwch_sha_final(&sha,s->m3_digest);
            pwch_copy(s->replay3,s->rx+9,8);
            if(s->have_m3)s->retries++;else s->have_m3=s->keys_ready=1;
            s->phase=s->installed?4:3;pwpa_reply(s,s->rx,4);
            pwch_wipe(&s->unwrap,sizeof(s->unwrap));pwch_wipe(s->rx,sizeof(s->rx));pwch_wipe(s->pmk,32);
        }
    }
    return s->pending?2:s->authorized?4:s->keys_ready?3:1;
}
static inline int pwpa_sent(struct pwpa_state*s,uint64_t now,int published)
{
    if(!pwpa_time(s,now)||!s->pending)return -1;if(published!=1)return pwpa_fail(s,3);
    if(s->pending==2)s->phase=1;s->pending=0;pwch_wipe(s->reply,sizeof(s->reply));s->reply_bytes=0;return 1;
}
/* The native key installer must issue exactly one pairwise and one group
 * installation, bind the returned completion events, then call complete1.
 * Publication alone or an EAPOL message alone cannot authorize the port. */
static inline int pwpa_install(struct pwpa_state*s,uint64_t now)
{
    if(!pwpa_time(s,now)||!s->keys_ready||s->pending||s->install_issued||s->installed||s->phase!=3)return 0;
    s->install_issued=1;return 1;
}
static inline int pwpa_installed(struct pwpa_state*s,uint64_t now,int complete)
{
    if(!pwpa_time(s,now)||!s->install_issued||s->installed||!s->have_m3||(s->phase!=3&&s->phase!=2))return -1;
    if(complete!=1)return pwpa_fail(s,4);s->installed=s->authorized=1;s->keys_ready=0;if(s->phase!=2)s->phase=4;return 1;
}
static inline void pwpa_stop(struct pwpa_state*s)
{
    if(!s)return;s->authorized=s->keys_ready=s->pending=s->reply_bytes=0;s->phase=5;
    pwch_wipe(s->pmk,32);pwch_wipe(s->snonce,32);pwch_wipe(s->anonce,32);pwch_wipe(s->kck,16);pwch_wipe(s->kek,16);
    pwch_wipe(s->tk,16);pwch_wipe(s->gtk,16);pwch_wipe(s->rx,sizeof(s->rx));pwch_wipe(s->reply,sizeof(s->reply));pwch_wipe(&s->unwrap,sizeof(s->unwrap));
}
#endif
