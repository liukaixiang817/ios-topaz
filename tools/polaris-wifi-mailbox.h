/* Fixed CPU0/XNU message boundary. These are private-copy wire/state helpers;
 * they do not map memory, publish cache lines, start a CPU or extend the MSS
 * startup owner. The native runtime and kernel adapters must supply those
 * operations. No message contains a caller-selected address or DMA pointer. */
#ifndef POLARIS_WIFI_MAILBOX_H
#define POLARIS_WIFI_MAILBOX_H
#include <stdint.h>
#include <stddef.h>
#define PWMB_VERSION 1u
#define PWMB_LINE 128u
#define PWMB_DATA 1536u
#define PWMB_RECORD (PWMB_LINE+PWMB_DATA)
#define PWMB_ACK_OFFSET PWMB_RECORD
#define PWMB_SLOT 2048u
#define PWMB_BYTES 16384u
#define PWMB_LANES 5u
#define PWMB_BOOTSTRAP_OFFSET (5u*PWMB_SLOT)
enum pwmb_lane {PWMB_CONTROL=0,PWMB_REPLY=1,PWMB_TX=2,PWMB_RX=3,PWMB_EVENT=4};
enum pwmb_operation {PWMB_STATE=1,PWMB_SCAN=2,PWMB_SCAN_ENTRY=3,PWMB_JOIN=4,
    PWMB_DISCONNECT=5,PWMB_ETHERNET_TX=6,PWMB_ETHERNET_RX=7,PWMB_NOTIFY=8,PWMB_RESPONSE=9,
    PWMB_POWER_OFF=10}; /* Explicit whole-system terminal request, not disconnect. */
enum pwmb_role {PWMB_PRODUCER=1,PWMB_CONSUMER=2};
struct pwmb_identity {uint64_t epoch;uint8_t mac[6];};
struct pwmb_state {uint64_t epoch,next;uint32_t lane,role,opened,stage,unknown,error;};
struct pwmb_message {uint64_t sequence;uint32_t operation,bytes;uint8_t data[PWMB_DATA];};
_Static_assert(PWMB_RECORD%PWMB_LINE==0&&PWMB_ACK_OFFSET+PWMB_LINE<=PWMB_SLOT,"separate producer and ACK cache lines");
_Static_assert(PWMB_SLOT*8==PWMB_BYTES,"one reserved XNU16KiB page");
static inline uint32_t pwmb_u32(const uint8_t*p)
{return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline uint64_t pwmb_u64(const uint8_t*p)
{return pwmb_u32(p)|((uint64_t)pwmb_u32(p+4)<<32);}
static inline void pwmb_put32(uint8_t*p,uint32_t n)
{for(unsigned k=0;k<4;k++)p[k]=(uint8_t)(n>>(8*k));}
static inline void pwmb_put64(uint8_t*p,uint64_t n)
{for(unsigned k=0;k<8;k++)p[k]=(uint8_t)(n>>(8*k));}
static inline int pwmb_zero(const void*p,unsigned n)
{const uint8_t*b=p;for(unsigned k=0;k<n;k++)if(b[k])return 0;return 1;}
static inline void pwmb_clear(void*p,unsigned n)
{volatile uint8_t*b=p;for(unsigned k=0;k<n;k++)b[k]=0;}
/* Immutable bootstrap input, prepared BEFORE the kernel is started. Parsing
 * this header is wire validation only, not proof of native runtime readiness. */
static inline int pwmb_identity_valid(const struct pwmb_identity*i)
{
    return i&&i->epoch&&!(i->mac[0]&1)&&!pwmb_zero(i->mac,6);
}
static inline int pwmb_bootstrap_make(const struct pwmb_identity*i,uint8_t*out)
{
    if(!pwmb_identity_valid(i)||!out)return 0;pwmb_clear(out,PWMB_LINE);
    pwmb_put64(out,UINT64_C(0x3130304946495750));pwmb_put32(out+8,PWMB_VERSION);
    pwmb_put32(out+12,PWMB_BYTES);pwmb_put64(out+16,i->epoch);pwmb_put32(out+24,PWMB_LANES);
    for(unsigned n=0;n<6;n++)out[32+n]=i->mac[n];return 1;
}
static inline int pwmb_bootstrap_parse(const uint8_t*p,struct pwmb_identity*out)
{
    if(!p||!out||pwmb_u64(p)!=UINT64_C(0x3130304946495750)||pwmb_u32(p+8)!=PWMB_VERSION||
       pwmb_u32(p+12)!=PWMB_BYTES||pwmb_u32(p+24)!=PWMB_LANES||pwmb_u32(p+28)||!pwmb_zero(p+38,90))return 0;
    struct pwmb_identity i={0};i.epoch=pwmb_u64(p+16);for(unsigned n=0;n<6;n++)i.mac[n]=p[32+n];
    if(!pwmb_identity_valid(&i))return 0;*out=i;return 1;
}
static inline int pwmb_fail(struct pwmb_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwmb_live(const struct pwmb_state*s,unsigned role)
{return s&&s->opened==1&&!s->unknown&&!s->error&&s->epoch&&s->next&&s->next<UINT64_MAX&&s->lane<PWMB_LANES&&s->role==role;}
static inline int pwmb_open(struct pwmb_state*s,unsigned lane,unsigned role,uint64_t epoch)
{
    if(!s||!pwmb_zero(s,sizeof(*s))||lane>=PWMB_LANES||(role!=PWMB_PRODUCER&&role!=PWMB_CONSUMER)||!epoch)return 0;
    s->epoch=epoch;s->next=1;s->lane=lane;s->role=role;s->opened=1;return 1;
}
/* JOIN112B: security u32=2, SSID length, secret length, secret kind(1 ASCII
 * passphrase/2 PMK), zero; BSSID6 or zero, zero2; SSID32; secret64. Never log
 * this payload. Both native and kernel adapters wipe their private copy after
 * consumption; only the producer may wipe/reuse its shared payload after ACK. */
static inline int pwmb_payload(unsigned lane,unsigned operation,const uint8_t*p,unsigned n)
{
    if(n>PWMB_DATA||(n&&!p))return 0;
    if(lane==PWMB_CONTROL){
        if(operation==PWMB_STATE||operation==PWMB_SCAN||operation==PWMB_DISCONNECT||operation==PWMB_POWER_OFF)return !n;
        if(operation==PWMB_SCAN_ENTRY)return n==4&&pwmb_u32(p)<32;
        if(operation!=PWMB_JOIN||n!=112||pwmb_u32(p)!=2||!p[4]||p[4]>32||p[7]||p[14]||p[15]||
           (p[8]&1)||!pwmb_zero(p+16+p[4],32-p[4]))return 0;
        if(p[6]==1){if(p[5]<8||p[5]>63)return 0;for(unsigned k=0;k<p[5];k++)if(p[48+k]<32||p[48+k]>126)return 0;}
        else if(p[6]==2){if(p[5]!=32)return 0;}else return 0;
        return pwmb_zero(p+48+p[5],64-p[5]);
    }
    /* RESPONSE: request sequence u64, request operation u32, errno u32,
     * operation-specific body. The upper adapter validates that body's ABI. */
    if(lane==PWMB_REPLY)return operation==PWMB_RESPONSE&&n>=16&&pwmb_u64(p)&&pwmb_u64(p)<UINT64_MAX&&
        ((pwmb_u32(p+8)>=PWMB_STATE&&pwmb_u32(p+8)<=PWMB_DISCONNECT)||pwmb_u32(p+8)==PWMB_POWER_OFF)&&pwmb_u32(p+12)<=4095;
    if(lane==PWMB_TX||lane==PWMB_RX)return operation==(lane==PWMB_TX?PWMB_ETHERNET_TX:PWMB_ETHERNET_RX)&&n>=14&&n<=1514;
    /* NOTIFY: event1..5 (ready/scan/link/disconnect/fault), errno, detail u64. */
    if(lane==PWMB_EVENT)return operation==PWMB_NOTIFY&&n==16&&pwmb_u32(p)>=1&&pwmb_u32(p)<=5&&pwmb_u32(p+4)<=4095;
    return 0;
}
/* Encode into PRIVATE memory. Publish shared payload/header first, clean/order,
 * then sequence at offset24 LAST, clean/order, then call tx_published. */
static inline int pwmb_prepare(struct pwmb_state*s,unsigned operation,const uint8_t*p,unsigned n,uint8_t*out)
{
    if(!pwmb_live(s,PWMB_PRODUCER)||s->stage||!out||!pwmb_payload(s->lane,operation,p,n))return 0;
    pwmb_clear(out,PWMB_RECORD);pwmb_put32(out,UINT32_C(0x31425750));pwmb_put32(out+4,PWMB_VERSION);
    pwmb_put32(out+8,s->lane);pwmb_put32(out+12,operation);pwmb_put64(out+16,s->epoch);pwmb_put64(out+24,s->next);pwmb_put32(out+32,n);
    for(unsigned k=0;k<n;k++)out[128+k]=p[k];s->stage=1;return 1;
}
static inline int pwmb_tx_published(struct pwmb_state*s,uint64_t sequence,int complete)
{
    if(!pwmb_live(s,PWMB_PRODUCER)||s->stage!=1||sequence!=s->next)return -1;
    if(complete!=1)return pwmb_fail(s,1);s->stage=2;return 1;
}
/* before/after are independently observed publication sequence values around
 * the copied record, with native invalidate/order at each boundary. An old
 * slot remains visible after ACK; it is idle, not another delivery. */
static inline int pwmb_receive(struct pwmb_state*s,const uint8_t*p,uint64_t before,uint64_t after,struct pwmb_message*out)
{
    if(!pwmb_live(s,PWMB_CONSUMER)||!p||!out)return -1;
    if(s->stage||before!=after||before==s->next-1)return 0;
    if(before!=s->next||pwmb_u64(p+24)!=before||pwmb_u64(p+16)!=s->epoch||
       pwmb_u32(p)!=UINT32_C(0x31425750)||pwmb_u32(p+4)!=PWMB_VERSION||pwmb_u32(p+8)!=s->lane||!pwmb_zero(p+36,92))return pwmb_fail(s,2);
    unsigned n=pwmb_u32(p+32),op=pwmb_u32(p+12);
    if(!pwmb_payload(s->lane,op,p+128,n)||!pwmb_zero(p+128+n,PWMB_DATA-n))return pwmb_fail(s,3);
    pwmb_clear(out,sizeof(*out));out->sequence=before;out->operation=op;out->bytes=n;
    for(unsigned k=0;k<n;k++)out->data[k]=p[128+k];s->stage=2;return 1;
}
static inline int pwmb_ack_prepare(struct pwmb_state*s,uint8_t*out)
{
    if(!pwmb_live(s,PWMB_CONSUMER)||s->stage!=2||!out)return 0;
    pwmb_clear(out,PWMB_LINE);pwmb_put32(out,UINT32_C(0x41425750));pwmb_put32(out+4,PWMB_VERSION);
    pwmb_put32(out+8,s->lane);pwmb_put64(out+16,s->epoch);pwmb_put64(out+24,s->next);return 1;
}
/* ACK has the same sequence-last publication rule, on consumer-owned lines. */
static inline int pwmb_rx_ack_published(struct pwmb_state*s,uint64_t sequence,int complete)
{
    if(!pwmb_live(s,PWMB_CONSUMER)||s->stage!=2||sequence!=s->next)return -1;
    if(complete!=1)return pwmb_fail(s,4);s->stage=0;s->next++;return 1;
}
static inline int pwmb_ack(struct pwmb_state*s,const uint8_t*p,uint64_t before,uint64_t after)
{
    if(!pwmb_live(s,PWMB_PRODUCER)||s->stage!=2||!p)return -1;
    if(before!=after||before==s->next-1)return 0;
    if(before!=s->next||pwmb_u64(p+24)!=before||pwmb_u64(p+16)!=s->epoch||pwmb_u32(p)!=UINT32_C(0x41425750)||
       pwmb_u32(p+4)!=PWMB_VERSION||pwmb_u32(p+8)!=s->lane||pwmb_u32(p+12)||!pwmb_zero(p+32,96))return pwmb_fail(s,5);
    s->stage=0;s->next++;return 1;
}
#endif
