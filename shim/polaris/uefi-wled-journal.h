/* Bounded wire journal and the final two actual reset-gate observations.
 * No writer, bus access, retry, allocation or caller-selected register. The
 * full packet retains absolute raw times even on failures. A successful reset
 * receipt appends exactly two new records to the previously captured packet;
 * the checksum covers the ENTIRE record history, never only the latest pair.
 */
#ifndef POLARIS_EFI_WLED_JOURNAL_H
#define POLARIS_EFI_WLED_JOURNAL_H
#include "uefi-wled-power.h"
#define PWJ_HEADER 64u
#define PWJ_RECORD 20u
#define PWJ_LIMIT (PWJ_HEADER+PWS_RECORDS*PWJ_RECORD+4u)
#define PWJ_RECEIPT 56u
struct polaris_wled_journal {
    uint64_t cookie;
    uint32_t sequence,published_count;
};
static inline void pwj_put(uint8_t *p,uint64_t v,unsigned n)
{for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(8*i));}
static inline uint32_t pwj_crc_step(uint32_t crc,const uint8_t *p,unsigned n)
{
    for(unsigned i=0;i<n;i++) {
        crc^=p[i];for(unsigned b=0;b<8;b++)crc=(crc>>1)^(0xedb88320u&-(crc&1u));
    }return crc;
}
static inline void pwj_record(uint8_t out[PWJ_RECORD],const struct polaris_wled_status_record *r)
{
    pwj_put(out,r->began_us,8);pwj_put(out+8,r->ended_us,8);
    out[16]=r->fault;out[17]=r->rt;out[18]=r->valid;out[19]=r->expected;
}
static inline uint32_t pwj_history_crc(const struct polaris_wled_status_witness *w)
{
    uint32_t crc=~0u;uint8_t raw[PWJ_RECORD];
    for(unsigned n=0;n<w->count;n++){pwj_record(raw,&w->record[n]);crc=pwj_crc_step(crc,raw,sizeof(raw));}
    return ~crc;
}
static inline uint8_t pwj_flags(const struct polaris_wled_power *p)
{return (p->actual_on?1u:0u)|(p->desired_on?2u:0u)|(p->uncertain?4u:0u);}
static inline bool pwj_dormant_zero(const struct polaris_wled_power *p)
{
    return p->status_policy==PWP_STRICT_SNAPSHOT&&!p->issued&&!p->completed&&!p->uncertain&&
        !p->witness.count&&!p->witness.error&&!p->request&&!p->acknowledged&&
        ((p->phase==PWP_UNINITIALIZED&&!p->error&&!p->actual_on&&!p->desired_on&&!p->module&&!p->irq)||
         (p->phase==PWP_FAILED&&p->error));
}
static inline bool pwj_packet(struct polaris_wled_journal *j,
    const struct polaris_wled_power *p,uint8_t *out,unsigned capacity,unsigned *bytes)
{
    if(!j||!p||!out||!bytes||!j->cookie||j->sequence==UINT32_MAX||
       (p->status_policy!=PWP_OEM_STATUS_WITNESS&&!pwj_dormant_zero(p))||p->witness.count>PWS_RECORDS||
       p->error>UINT16_MAX||p->witness.error>UINT16_MAX||p->issued>255||p->completed>255)
        return false;
    unsigned count=p->witness.count,length=PWJ_HEADER+count*PWJ_RECORD+4;
    if(capacity<length)return false;
    for(unsigned n=0;n<PWJ_HEADER;n++)out[n]=0;
    const char magic[8]={'W','L','E','D','J','2',0,0};
    for(unsigned n=0;n<8;n++)out[n]=(uint8_t)magic[n];
    pwj_put(out+8,j->cookie,8);pwj_put(out+16,count?p->witness.record[0].began_us:0,8);
    pwj_put(out+24,j->sequence+1,4);pwj_put(out+28,count,2);
    pwj_put(out+30,p->witness.error,2);pwj_put(out+32,pwj_history_crc(&p->witness),4);
    pwj_put(out+36,p->error,2);out[38]=(uint8_t)p->phase;out[39]=pwj_flags(p);
    out[40]=(uint8_t)p->issued;out[41]=(uint8_t)p->completed;
    out[42]=p->module;out[43]=p->irq;
    pwj_put(out+44,p->request,8);pwj_put(out+52,p->acknowledged,8);
    out[60]=p->witness.fault_or;out[61]=p->witness.rt_or;
    for(unsigned n=0;n<count;n++)pwj_record(out+PWJ_HEADER+n*PWJ_RECORD,&p->witness.record[n]);
    pwj_put(out+length-4,~pwj_crc_step(~0u,out,length-4),4);
    j->sequence++;j->published_count=count;*bytes=length;return true;
}
static inline bool pwj_receipt(const struct polaris_wled_journal *j,
    const struct polaris_wled_power *p,unsigned mode,uint64_t now,uint8_t out[PWJ_RECEIPT])
{
    if(!j||!p||!out||!j->cookie||!j->sequence||mode<1||mode>2||
       p->status_policy!=PWP_OEM_STATUS_WITNESS||p->error||p->witness.error||
       p->phase!=PWP_ON||pwj_flags(p)!=3||p->module!=0x80||p->irq!=2||
       p->request!=2||p->acknowledged!=2||p->issued!=4||p->completed!=4||
       p->witness.count>PWS_RECORDS||j->published_count>PWS_RECORDS-2||
       p->witness.count!=j->published_count+2||!j->published_count)
        return false;
    uint64_t origin=p->witness.record[0].began_us;
    for(unsigned k=0;k<2;k++) {
        const struct polaris_wled_status_record *r=&p->witness.record[j->published_count+k];
        if(r->valid!=3||r->expected!=0x82||((r->fault|r->rt)&~1u)||
           r->began_us<origin||r->ended_us<=r->began_us||
           r->ended_us-origin>UINT32_MAX||now<r->ended_us||
           now-r->ended_us>PWS_MAX_CHECK_US)return false;
    }
    for(unsigned n=0;n<PWJ_RECEIPT;n++)out[n]=0;
    out[0]='W';out[1]='L';out[2]='R';out[3]='2';pwj_put(out+4,j->cookie,8);
    pwj_put(out+12,j->published_count,2);pwj_put(out+14,p->witness.count,2);
    pwj_put(out+16,pwj_history_crc(&p->witness),4);
    out[22]=(uint8_t)p->issued;out[23]=(uint8_t)p->completed;
    out[24]=p->witness.fault_or;out[25]=p->witness.rt_or;
    out[26]=(uint8_t)mode;out[27]=(uint8_t)p->phase;out[28]=pwj_flags(p);
    for(unsigned k=0;k<2;k++) {
        const struct polaris_wled_status_record *r=&p->witness.record[j->published_count+k];
        uint8_t *to=out+32+12*k;
        pwj_put(to,r->began_us-origin,4);pwj_put(to+4,r->ended_us-origin,4);
        to[8]=r->fault;to[9]=r->rt;to[10]=r->valid;to[11]=r->expected;
    }return true;
}
#endif
