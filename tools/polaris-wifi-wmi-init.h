/* WCN3990 WMI TLV bootstrap. Wire definitions/resource choices compared with
 * primary ath10k wmi-tlv.c/h, wmi.c and the SNOC entry in core.c. Pure protocol;
 * native caller must own, zero and publish the planned independent memory. */
#ifndef POLARIS_WIFI_WMI_INIT_H
#define POLARIS_WIFI_WMI_INIT_H
#include <stdint.h>
#include <stddef.h>
#define PWMI_REQUESTS 16u
#define PWMI_FRAME 2040u
#define PWMI_WAIT UINT64_C(96000000)
struct pwmi_request {uint32_t id,unit,flags,units;};
struct pwmi_chunk {uint64_t address;uint32_t id,bytes;};
struct pwmi_state {
    uint64_t epoch,last,deadline,bank,bank_bytes,used;
    uint32_t started,phase,error,unknown,requests,service_bytes,ext_seen,ext_length;
    uint32_t pending,tx_bytes,events,skipped,prepared;
    uint8_t service_ready[104],regulatory[36],services[128],extended[16],mac[6];
    struct pwmi_request request[PWMI_REQUESTS];struct pwmi_chunk chunk[PWMI_REQUESTS];
    uint8_t tx[PWMI_FRAME];
};
static inline uint32_t pwmi_get(const uint8_t*p)
{return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline void pwmi_put(uint8_t*p,uint32_t x)
{for(unsigned n=0;n<4;n++)p[n]=(uint8_t)(x>>(8*n));}
static inline void pwmi_copy(uint8_t*d,const uint8_t*s,unsigned bytes)
{for(unsigned n=0;n<bytes;n++)d[n]=s[n];}
static inline int pwmi_fail(struct pwmi_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwmi_time(struct pwmi_state*s,uint64_t now)
{
    if(!s||!s->started||s->unknown||s->error)return 0;
    if(now<s->last||now>UINT64_MAX-PWMI_WAIT||(s->phase<4&&now>s->deadline))return pwmi_fail(s,1),0;
    s->last=now;return 1;
}
static inline int pwmi_open(struct pwmi_state*s,uint64_t epoch,uint64_t now)
{
    if(!s||!epoch||!now||now>UINT64_MAX-PWMI_WAIT)return 0;
    for(unsigned n=0;n<sizeof(*s);n++)if(((const uint8_t*)s)[n])return 0;
    s->epoch=epoch;s->last=now;s->deadline=now+PWMI_WAIT;s->started=1;return 1;
}
static inline int pwmi_abi(const uint8_t*p)
{return pwmi_get(p)==0x01000000&&pwmi_get(p+8)==0x5f414351&&pwmi_get(p+12)==0x4c4d&&!pwmi_get(p+16)&&!pwmi_get(p+20);}
/* Base service bitmap has four service bits per 32-bit word. Extended
 * services are a separate SERVICE_AVAILABLE bitmap, starting at ID128. */
static inline int pwmi_service(const struct pwmi_state*s,unsigned id)
{
    if(id<128){unsigned word=id/4;return id<s->service_bytes&&4*word+4<=s->service_bytes&&((pwmi_get(s->services+4*word)>>(id%4))&1);}
    return id<256&&s->ext_seen&&((pwmi_get(s->extended+4*((id-128)/32))>>((id-128)%32))&1);
}
/* Validated TLV cursor; unknown fields remain bounded by the received frame. */
static inline int pwmi_tlv(const uint8_t*p,unsigned bytes,unsigned*at,unsigned*tag,unsigned*length,const uint8_t**body)
{
    if(*at==bytes)return 0;if(*at>bytes||bytes-*at<4)return -1;
    uint32_t h=pwmi_get(p+*at);*length=h&65535;*tag=h>>16;*at+=4;
    if(*length>bytes-*at)return -1;*body=p+*at;*at+=*length;return 1;
}
/* 1=bootstrap event accepted, 0=unconsumed event, -1=sticky failure.
 * Caller retains unconsumed packets for their typed WMI/data consumer. */
static inline int pwmi_receive(struct pwmi_state*s,const uint8_t*p,unsigned bytes,uint64_t now)
{
    if(!pwmi_time(s,now))return -1;
    if(!p||bytes<4||bytes>PWMI_FRAME)return pwmi_fail(s,2);
    unsigned event=pwmi_get(p)&0xffffff;if(event>3||!event){s->skipped++;return 0;}
    p+=4;bytes-=4;unsigned at=0,tag=0,length=0,seen=0,count=0,arrays=0;const uint8_t*b=0;int next;
    if((event==1&&s->phase)||(event==2&&s->phase!=3)||(event==3&&(s->ext_seen||s->phase>=2)))return pwmi_fail(s,3);
    while((next=pwmi_tlv(p,bytes,&at,&tag,&length,&b))==1){
        if(event==1){
            if(tag==32){if((seen&1)||length<104||!pwmi_abi(b+4))return pwmi_fail(s,4);pwmi_copy(s->service_ready,b,104);seen|=1;}
            else if(tag==33){if((seen&2)||length<36)return pwmi_fail(s,4);pwmi_copy(s->regulatory,b,36);seen|=2;}
            else if(tag==16){
                if(length&3)return pwmi_fail(s,4);
                if(!arrays++){if(!length||length>128)return pwmi_fail(s,4);s->service_bytes=length;pwmi_copy(s->services,b,length);seen|=4;}
            }else if(tag==18){
                if(seen&8)return pwmi_fail(s,4);seen|=8;unsigned inner=0,it=0,il=0;const uint8_t*q=0;int result;
                while((result=pwmi_tlv(b,length,&inner,&it,&il,&q))==1){
                    if(it!=34||il<16||count==PWMI_REQUESTS)return pwmi_fail(s,5);
                    struct pwmi_request*r=&s->request[count];*r=(struct pwmi_request){pwmi_get(q),pwmi_get(q+4),pwmi_get(q+8),pwmi_get(q+12)};
                    if(!r->unit||r->unit>UINT32_MAX-3||(r->flags&~7u))return pwmi_fail(s,5);
                    for(unsigned n=0;n<count;n++)if(s->request[n].id==r->id)return pwmi_fail(s,5);count++;
                }if(result<0)return pwmi_fail(s,5);
            }
        }else if(event==2&&tag==35){
            if(seen||length<36||!pwmi_abi(b)||pwmi_get(b+32))return pwmi_fail(s,6);
            unsigned nonzero=0;for(unsigned n=0;n<6;n++)nonzero|=b[24+n];
            if(!nonzero||(b[24]&1))return pwmi_fail(s,6);pwmi_copy(s->mac,b+24,6);seen=1;
        }else if(event==3&&tag==559){
            if(seen||length<20)return pwmi_fail(s,7);s->ext_length=pwmi_get(b);pwmi_copy(s->extended,b+4,16);seen=1;
        }
    }
    if(next<0)return pwmi_fail(s,2);
    if(event==1){if(seen!=15||pwmi_get(s->service_ready+72)!=count)return pwmi_fail(s,5);s->requests=count;s->phase=1;}
    else {if(!seen)return pwmi_fail(s,2);if(event==2)s->phase=4;else s->ext_seen=1;}
    s->events++;return 1;
}
/* Only offsets in a caller-owned, disjoint, page-aligned region. Each chunk
 * gets whole pages; actual byte counts come exclusively from SERVICE_READY. */
static inline int pwmi_plan(struct pwmi_state*s,uint64_t bank,uint64_t bytes,uint64_t now)
{
    if(!pwmi_time(s,now)||s->phase!=1||s->bank||!bank||(bank&4095)||(bytes&4095)||!bytes||bank>UINT64_MAX-bytes)return -1;
    uint64_t limit=pwmi_service(s,179)?(UINT64_C(1)<<35):(UINT64_C(1)<<32),used=0;
    if(bank>=limit||bytes>limit-bank)return pwmi_fail(s,8);
    for(unsigned n=0;n<s->requests;n++){
        const struct pwmi_request*r=&s->request[n];uint64_t units=r->flags&6?34:r->flags&1?5:r->units;
        uint64_t size=units*((r->unit+3u)&~3u),rounded=(size+4095)&~UINT64_C(4095);
        if(!size||size>UINT32_MAX||rounded>bytes-used)return pwmi_fail(s,8);
        s->chunk[n]=(struct pwmi_chunk){bank+used,r->id,(uint32_t)size};used+=rounded;
    }s->bank=bank;s->bank_bytes=bytes;s->used=used;return 1;
}
static inline void pwmi_header(uint8_t*p,unsigned tag,unsigned bytes)
{pwmi_put(p,(tag<<16)|bytes);}
/* Native caller calls only after zero/readback/cache publication of every
 * planned page, under the same live owner; this function grants no DMA rights. */
static inline int pwmi_init(struct pwmi_state*s,uint64_t now)
{
    if(!pwmi_time(s,now)||s->phase!=1||!s->bank||s->pending)return -1;
    unsigned bytes=220+20*s->requests;for(unsigned n=0;n<bytes;n++)s->tx[n]=0;
    pwmi_put(s->tx,1);pwmi_header(s->tx+4,74,28);
    const uint32_t abi[]={0x01000000,53,0x5f414351,0x4c4d,0,0};for(unsigned n=0;n<6;n++)pwmi_put(s->tx+8+4*n,abi[n]);
    pwmi_put(s->tx+32,s->requests);pwmi_header(s->tx+36,75,176);
    const uint32_t config[44]={4,33,0,0,2,66,16,7,7,100,100,100,40,1,4,4,4,8,0,0,0,1024,2,0,0,0,0,2,1056,2,1,32,2,5,22,6,0,1,1,0,0,0,0,512};
    for(unsigned n=0;n<44;n++)pwmi_put(s->tx+40+4*n,config[n]);
    if(pwmi_service(s,65)){pwmi_put(s->tx+48,4);pwmi_put(s->tx+52,4);}
    if(pwmi_service(s,174))pwmi_put(s->tx+212,512|(1u<<18));
    pwmi_header(s->tx+216,18,20*s->requests);
    for(unsigned n=0;n<s->requests;n++){
        uint8_t*p=s->tx+220+20*n;const struct pwmi_chunk*c=&s->chunk[n];pwmi_header(p,76,16);
        pwmi_put(p+4,c->id);pwmi_put(p+8,(uint32_t)c->address);pwmi_put(p+12,c->bytes);pwmi_put(p+16,(uint32_t)(c->address>>32));
    }s->tx_bytes=bytes;s->pending=1;s->prepared=1;s->phase=2;return 1;
}
static inline int pwmi_sent(struct pwmi_state*s,uint64_t now,int published)
{
    if(!pwmi_time(s,now)||s->phase!=2||!s->pending)return -1;
    if(published!=1)return pwmi_fail(s,9);s->pending=0;s->phase=3;s->deadline=now+PWMI_WAIT;return 1;
}
#endif
