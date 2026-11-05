/* WCN3990 software ring ownership. Caller performs typed native memory/cache/
 * MMIO operations before committing a transaction. No callback or address is
 * itself DMA authority. RX descriptors are recycled in complete64-byte lines:
 * never clean a line while the device owns another descriptor in that line. */
#ifndef POLARIS_WIFI_CE_RING_H
#define POLARIS_WIFI_CE_RING_H
#include "polaris-wifi-ce-init.h"
#define PWCR_SHADOW UINT64_C(0x18832000)
static inline int pwcr_register(uint64_t address,unsigned write,uint32_t value)
{
    if(!write)return 0;
    if(address>=PWCR_SHADOW&&address<PWCR_SHADOW+48&&!(address&3)){
        unsigned pipe=(unsigned)((address-PWCR_SHADOW)/4);
        return polaris_wcn3990_host[pipe].source_entries&&value<polaris_wcn3990_host[pipe].source_entries;
    }
    if(address>=PWCE_BASE&&address<PWCE_WRAPPER&&(address&4095)==0x40){
        unsigned pipe=(unsigned)((address-PWCE_BASE)/4096);
        return polaris_wcn3990_host[pipe].destination_entries>=8&&value<polaris_wcn3990_host[pipe].destination_entries;
    }return 0;
}
struct pwcr_ring {uint32_t read,write,posted,entries;uint64_t completed,published;};
struct pwcr_transfer {
    uint64_t descriptor,buffer;uint32_t bytes,pipe,index,next,receive;
    uint8_t wire[64];
};
struct pwcr_state {
    uint64_t epoch;struct pwdm_layout layout;struct pwcr_ring source[12],destination[12];
    struct pwcr_transfer pending;uint32_t started,busy,unknown,error;
};
static inline void pwcr_put(uint8_t*p,uint64_t value,unsigned bytes)
{for(unsigned n=0;n<bytes;n++)p[n]=(uint8_t)(value>>(8*n));}
static inline uint64_t pwcr_get(const uint8_t*p,unsigned bytes)
{uint64_t value=0;for(unsigned n=0;n<bytes;n++)value|=(uint64_t)p[n]<<(8*n);return value;}
static inline int pwcr_fail(struct pwcr_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwcr_begin(struct pwcr_state*s,const struct pwce_init*i,unsigned cache_line)
{
    if(!s||!i||!pwce_zero(s,sizeof(*s))||!i->complete||i->unknown||i->error||i->pending||cache_line!=64)return -1;
    struct pwdm_layout expected={0};if(!pwdm_plan(&expected,i->layout.allocation)||!pwce_equal(&expected,&i->layout,sizeof(expected)))return -1;
    for(unsigned n=0;n<12;n++){
        const struct pwdm_pipe*p=&i->layout.pipe[n];const struct pwce_pipe_state*q=&i->pipe[n];
        if((p->sources&&(q->source_read>=p->sources||q->source_read!=q->source_write))||
           (p->destinations&&(q->dest_read>=p->destinations||q->dest_read!=q->dest_write)))return -1;
        /* CE7 is the optional2-entry diagnostic pipe, kept empty. All WLAN
         * RX pipes must start at a cache-line boundary for grouped recycling. */
        if(p->destinations>=8&&(q->dest_write&3))return -1;
    }
    s->epoch=i->epoch;s->layout=i->layout;s->started=1;
    for(unsigned n=0;n<12;n++){
        const struct pwdm_pipe*p=&i->layout.pipe[n];const struct pwce_pipe_state*q=&i->pipe[n];
        s->source[n]=(struct pwcr_ring){.read=q->source_read,.write=q->source_write,.entries=p->sources};
        s->destination[n]=(struct pwcr_ring){.read=q->dest_read,.write=q->dest_write,.entries=p->destinations};
    }return 1;
}
/* Returns0 when no whole cache line can be posted yet. Four exact descriptor
 * slots and their private buffers are CPU-owned throughout this transaction. */
static inline int pwcr_post_rx(struct pwcr_state*s,unsigned pipe,struct pwcr_transfer*out)
{
    if(!s||!out||!s->started||s->unknown||s->error||s->busy||pipe>=12)return -1;
    struct pwcr_ring*r=&s->destination[pipe];const struct pwdm_pipe*p=&s->layout.pipe[pipe];
    if(r->entries<8)return 0;
    if(r->write>=r->entries||(r->write&3)||r->posted>r->entries-4)return pwcr_fail(s,1);
    if(r->entries-4-r->posted<4)return 0;
    struct pwcr_transfer t={.descriptor=s->layout.allocation+p->destination+16u*r->write,
        .buffer=s->layout.allocation+p->destination_buffers+(uint64_t)p->buffer_bytes*r->write,
        .bytes=4u*p->buffer_bytes,.pipe=pipe,.index=r->write,.next=(r->write+4)&(r->entries-1),.receive=1};
    for(unsigned n=0;n<4;n++)pwcr_put(t.wire+16*n,t.buffer+(uint64_t)n*p->buffer_bytes,8);
    s->pending=*out=t;s->busy=1;return 1;
}
static inline int pwcr_send(struct pwcr_state*s,unsigned pipe,unsigned bytes,unsigned id,struct pwcr_transfer*out)
{
    if(!s||!out||!s->started||s->unknown||s->error||s->busy||pipe>=12||!bytes||id>4095)return -1;
    struct pwcr_ring*r=&s->source[pipe];const struct pwdm_pipe*p=&s->layout.pipe[pipe];
    if(r->entries<2||bytes>p->buffer_bytes)return -1;
    if(r->write>=r->entries||r->posted>=r->entries)return pwcr_fail(s,1);
    if(r->posted==r->entries-1)return 0;
    struct pwcr_transfer t={.descriptor=s->layout.allocation+p->source+16u*r->write,
        .buffer=s->layout.allocation+p->source_buffers+(uint64_t)p->buffer_bytes*r->write,
        .bytes=bytes,.pipe=pipe,.index=r->write,.next=(r->write+1)&(r->entries-1)};
    pwcr_put(t.wire,t.buffer,8);pwcr_put(t.wire+8,bytes,2);pwcr_put(t.wire+10,id<<4,2);
    s->pending=*out=t;s->busy=1;return 1;
}
/* Only commit after buffer/descriptor cache maintenance, write-index store
 * and ordering completed. Any partial publication is sticky, never retried. */
static inline int pwcr_publish(struct pwcr_state*s,const struct pwcr_transfer*t,int completed)
{
    if(!s||!t||!s->started||s->unknown||s->error)return -1;
    if(!s->busy||t->receive>1||!pwce_equal(&s->pending,t,sizeof(*t))||completed!=1)return pwcr_fail(s,2);
    struct pwcr_ring*r=t->receive?&s->destination[t->pipe]:&s->source[t->pipe];
    unsigned count=t->receive?4:1;r->write=t->next;r->posted+=count;r->published+=count;s->busy=0;
    for(unsigned n=0;n<sizeof(s->pending);n++)((uint8_t*)&s->pending)[n]=0;return 1;
}
/* Hardware never writes source descriptors. It returns ownership through the
 * source read index. RX ownership instead requires nonzero returned nbytes. */
static inline int pwcr_complete_tx(struct pwcr_state*s,unsigned pipe,uint32_t index)
{
    if(!s||!s->started||s->unknown||s->error||s->busy||pipe>=12)return -1;
    struct pwcr_ring*r=&s->source[pipe];if(!r->entries||index>=r->entries)return pwcr_fail(s,3);
    unsigned count=(index-r->read)&(r->entries-1);if(count>r->posted)return pwcr_fail(s,3);
    r->read=index;r->posted-=count;r->completed+=count;return (int)count;
}
/* Descriptor bytes must come from native invalidate+read, payload copied out
 * before consume_rx. This function never clears or cleans a device-owned line. */
static inline int pwcr_receive(struct pwcr_state*s,unsigned pipe,const uint8_t wire[16],struct pwcr_transfer*out)
{
    if(!s||!wire||!out||!s->started||s->unknown||s->error||s->busy||pipe>=12)return -1;
    struct pwcr_ring*r=&s->destination[pipe];const struct pwdm_pipe*p=&s->layout.pipe[pipe];
    if(!r->entries||!r->posted)return 0;
    uint32_t bytes=(uint32_t)pwcr_get(wire+8,2);if(!bytes)return 0;
    uint64_t buffer=s->layout.allocation+p->destination_buffers+(uint64_t)p->buffer_bytes*r->read;
    if(bytes>p->buffer_bytes||pwcr_get(wire,8)!=buffer)return pwcr_fail(s,4);
    struct pwcr_transfer t={.descriptor=s->layout.allocation+p->destination+16u*r->read,
        .buffer=buffer,.bytes=bytes,.pipe=pipe,.index=r->read,.next=(r->read+1)&(r->entries-1),.receive=2};
    for(unsigned n=0;n<16;n++)t.wire[n]=wire[n];s->pending=*out=t;s->busy=1;return 1;
}
static inline int pwcr_consume_rx(struct pwcr_state*s,const struct pwcr_transfer*t,int copied)
{
    if(!s||!t||!s->started||s->unknown||s->error)return -1;
    if(!s->busy||t->receive!=2||!pwce_equal(&s->pending,t,sizeof(*t))||copied!=1)return pwcr_fail(s,5);
    struct pwcr_ring*r=&s->destination[t->pipe];if(!r->posted)return pwcr_fail(s,5);
    r->read=t->next;r->posted--;r->completed++;s->busy=0;
    for(unsigned n=0;n<sizeof(s->pending);n++)((uint8_t*)&s->pending)[n]=0;return 1;
}
#endif
