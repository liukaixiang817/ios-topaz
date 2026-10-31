/* Fixed clock-only OEM bridge. The caller must bind this context to the
 * exact admitted NEW image's kernel-owned _polaris_uefi_clock, and call it
 * only in kernel-entered phase, never on the old/frozen runtime controller.
 * Callbacks are local counter/cache operations, not supplied over USB.
 * The per-image context starts zero and can be prepared only once. */
#ifndef POLARIS_CLOCK_UEFI_H
#define POLARIS_CLOCK_UEFI_H
#include "polaris-clock-sync.h"
#include <stddef.h>
/* Freestanding EFI: no host libc or implicit memcpy/memset import. */
static inline void pc_fw_copy(void *dst,const void *src,size_t bytes)
{ for(size_t i=0;i<bytes;i++)((uint8_t *)dst)[i]=((const uint8_t *)src)[i]; }
static inline void pc_fw_zero(void *dst,size_t bytes)
{ for(size_t i=0;i<bytes;i++)((uint8_t *)dst)[i]=0; }
static inline bool pc_fw_equal(const void *a,const void *b,size_t bytes)
{ for(size_t i=0;i<bytes;i++)if(((const uint8_t *)a)[i]!=((const uint8_t *)b)[i])return false;return true; }
struct pc_fw_io {
    uint64_t (*counter)(void *),(*frequency)(void *);
    void (*clean)(void *,uintptr_t,size_t),(*invalidate)(void *,uintptr_t,size_t);
    void *context;
};
struct pc_fw {
    struct polaris_clock_slot *slot;
    struct pc_fw_io io;
    uint64_t cookie,issued,probe_sequence,rx,tx;
    bool probe_pending;
};
static inline bool pc_fw_prepare(struct pc_fw *f,struct polaris_clock_slot *slot,
    uint64_t cookie,const struct pc_fw_io *io,bool kernel_owned_before_cpu_start)
{
    if(!f || !slot || ((uintptr_t)slot&127) || !cookie || !io || !io->counter ||
       !io->frequency || !io->clean || !io->invalidate || !kernel_owned_before_cpu_start ||
       f->slot || f->cookie || f->issued || f->probe_sequence || f->rx || f->tx || f->probe_pending ||
       io->frequency(io->context)!=PC_FREQUENCY || !io->counter(io->context))return false;
    pc_fw_zero(f,sizeof(*f));f->slot=slot;f->cookie=cookie;f->io=*io;
    /* Only before CPU_ON: after this, firmware never writes the native line. */
    pc_fw_zero(slot,sizeof(*slot));slot->firmware.magic=PC_MAGIC;
    slot->firmware.cookie=cookie;slot->firmware.frequency_hz=PC_FREQUENCY;
    slot->firmware.source=PC_SOURCE_HOST_UTC;
    io->clean(io->context,(uintptr_t)slot,sizeof(*slot));return true;
}
static inline bool pc_fw_status(struct pc_fw *f,struct polaris_clock_status *out)
{
    if(!f || !f->slot || f->io.frequency(f->io.context)!=PC_FREQUENCY)return false;
    struct polaris_clock_status *s=&f->slot->kernel;
    f->io.invalidate(f->io.context,(uintptr_t)s,sizeof(*s));
    uint64_t revision=__atomic_load_n(&s->revision,__ATOMIC_ACQUIRE);
    if(!revision || (revision&1))return false;
    pc_fw_copy(out,s,sizeof(*out));
    f->io.invalidate(f->io.context,(uintptr_t)s,sizeof(*s));
    if(revision!=__atomic_load_n(&s->revision,__ATOMIC_ACQUIRE) || out->revision!=revision ||
       out->magic!=PC_MAGIC || out->cookie!=f->cookie || out->sequence>UINT32_MAX ||
       out->sequence>f->issued || out->frequency_hz!=PC_FREQUENCY ||
       out->status<PC_READY || out->status>PC_SEALED || out->error>PC_READBACK)return false;
    for(unsigned i=0;i<5;i++)if(out->reserved[i])return false;
    return true;
}
static inline bool pc_fw_probe(struct pc_fw *f,uint32_t seq,uint8_t out[60])
{
    struct polaris_clock_status s;
    uint64_t rx=f&&f->slot?f->io.counter(f->io.context):0;
    if(!rx || !seq || !pc_fw_status(f,&s) || s.status==PC_SEALED ||
       s.sequence!=f->issued || f->issued>=UINT32_MAX || seq!=f->issued+1)return false;
    /* A new probe may replace an unused probe; it cannot replay a SET or
     * replace an outstanding native request. Cookie is per admitted boot. */
    f->rx=rx;f->probe_sequence=seq;f->probe_pending=true;
    pc_fw_copy(out,"PCLPRO01",8);pc_put64(out+8,f->cookie);pc_put32(out+16,seq);
    pc_put32(out+20,(uint32_t)PC_FREQUENCY);pc_put64(out+24,rx);
    pc_put32(out+40,(uint32_t)s.sequence);pc_put32(out+44,(uint32_t)s.status);
    pc_put32(out+48,(uint32_t)s.error);pc_put64(out+52,0);
    uint64_t tx=f->io.counter(f->io.context);
    if(tx<rx || tx-rx>PC_FREQUENCY/4 || f->io.frequency(f->io.context)!=PC_FREQUENCY) {
        f->probe_pending=false;return false;
    }
    f->tx=tx;pc_put64(out+32,tx);return true;
}
static inline bool pc_fw_set(struct pc_fw *f,uint32_t seq,uint64_t utc,
    uint64_t anchor,uint32_t uncertainty)
{
    if(!f || !f->probe_pending || seq!=f->probe_sequence)return false;
    /* Consume the probe on every SET attempt; an unknown ACK is status-only. */
    f->probe_pending=false;
    struct polaris_clock_status s;
    uint64_t now=f->io.counter(f->io.context);
    if(!pc_fw_status(f,&s) || s.status==PC_SEALED || s.sequence!=f->issued ||
       anchor!=f->rx+(f->tx-f->rx)/2)return false;
    struct polaris_clock_request r={.magic=PC_MAGIC,.cookie=f->cookie,.sequence=seq,
        .utc_us=utc,.anchor_ticks=anchor,.uncertainty_us=uncertainty,
        .frequency_hz=PC_FREQUENCY,.source=PC_SOURCE_HOST_UTC};
    uint64_t checked=0;
    if(pc_validate(&r,f->cookie,f->issued,now,f->io.frequency(f->io.context),&checked))return false;
    /* Publish sequence last; do not write any native-owned bytes. */
    uint64_t old=f->slot->firmware.sequence;r.sequence=old;
    pc_fw_copy(&f->slot->firmware,&r,sizeof(r));
    f->io.clean(f->io.context,(uintptr_t)&f->slot->firmware,sizeof(r));
    __atomic_store_n(&f->slot->firmware.sequence,seq,__ATOMIC_RELEASE);
    f->io.clean(f->io.context,(uintptr_t)&f->slot->firmware,sizeof(r));
    f->issued=seq;return true;
}
static inline bool pc_fw_status_wire(struct pc_fw *f,uint8_t out[60])
{
    struct polaris_clock_status s;if(!pc_fw_status(f,&s))return false;
    pc_fw_copy(out,"PCLSTA01",8);pc_put64(out+8,s.cookie);pc_put32(out+16,(uint32_t)s.sequence);
    pc_put32(out+20,(uint32_t)s.status);pc_put32(out+24,(uint32_t)s.error);
    pc_put32(out+28,(uint32_t)s.frequency_hz);pc_put64(out+32,s.actual_utc_us);
    pc_put64(out+40,s.actual_ticks);pc_put64(out+48,s.uncertainty_us);
    pc_put32(out+56,(uint32_t)s.applied_count);return true;
}
static inline bool pc_hex(const char *p,unsigned count,uint64_t *out)
{
    uint64_t v=0;
    for(unsigned i=0;i<count;i++) {
        unsigned c=(unsigned char)p[i],n;
        if(c>='0'&&c<='9')n=c-'0';else if(c>='a'&&c<='f')n=c-'a'+10;else return false;
        v=(v<<4)|n;
    }
    *out=v;return true;
}
/* Command input is length-delimited. Replies contain exactly60B metadata or
 * zero bytes for accepted SET; caller prepends OKAY or sends a fixed FAIL.
 * No arbitrary address/field/sysctl/counter/frequency/reset operation exists. */
static inline bool pc_fw_command(struct pc_fw *f,const char *cmd,size_t bytes,
    uint8_t out[60],size_t *out_bytes)
{
    *out_bytes=0;
    if(bytes==14 && pc_fw_equal(cmd,"oem utc-status",14)) {
        if(!pc_fw_status_wire(f,out))return false;*out_bytes=60;return true;
    }
    if(bytes==22 && pc_fw_equal(cmd,"oem utc-probe:",14)) {
        uint64_t seq=0;if(!pc_hex(cmd+14,8,&seq) || !pc_fw_probe(f,(uint32_t)seq,out))return false;
        *out_bytes=60;return true;
    }
    if(bytes==63 && pc_fw_equal(cmd,"oem utc-set:",12) && cmd[20]==':' && cmd[37]==':' && cmd[54]==':') {
        uint64_t seq=0,utc=0,anchor=0,uncertainty=0;
        if(!pc_hex(cmd+12,8,&seq) || !pc_hex(cmd+21,16,&utc) ||
           !pc_hex(cmd+38,16,&anchor) || !pc_hex(cmd+55,8,&uncertainty))return false;
        return pc_fw_set(f,(uint32_t)seq,utc,anchor,(uint32_t)uncertainty);
    }
    return false;
}
#endif
