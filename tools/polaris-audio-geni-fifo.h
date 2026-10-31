/* Future Polaris SE5 identity transaction executor, defaultOFF.
 * This is NOT a physical MMIO/clock/owner provider. None currently exists.
 * A reviewed provider must first establish an exclusive live SE5 lease, exact
 * clock/pin/FIFO/8-bit packing and firmware WRITE_READ/abort capabilities,
 * actual inherited TAS book0/page0, and actual stop/restore ownership. DT/PAR,
 * the original I2CDxe RAM cache, or a nonzero cached pointer cannot grant it.
 * No original Open/Read/Close/DAL call, clock/pin/packing change, DMA, reset,
 * selector write, calibration, address scan or audio playback occurs here.
 */
#ifndef POLARIS_AUDIO_GENI_FIFO_H
#define POLARIS_AUDIO_GENI_FIFO_H
#include <stdint.h>
#include <stddef.h>
#include "../shim/polaris/uefi-audio-i2c-cache.h"
#ifndef EFI_XNU_AUDIO_GENI_FIFO_AVAILABLE
#define EFI_XNU_AUDIO_GENI_FIFO_AVAILABLE 0
#endif
#ifndef EFI_XNU_AUDIO_GENI_FIFO_PHYSICAL_PROVIDER_AVAILABLE
#define EFI_XNU_AUDIO_GENI_FIFO_PHYSICAL_PROVIDER_AVAILABLE 0
#endif
#if EFI_XNU_AUDIO_GENI_FIFO_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU) && \
    (EFI_XNU_AUDIO_GENI_FIFO_PHYSICAL_PROVIDER_AVAILABLE || defined(PAIG_SOFTWARE_PEER_ONLY))
#define PAIG_EXECUTOR_BODY 1
#else
#define PAIG_EXECUTOR_BODY 0
#endif
#define PAIG_EVENTS 1024u
#define PAIG_DONE 1u
#define PAIG_ABORT (1u<<5)
#define PAIG_TXWM (1u<<30)
#define PAIG_RX ((1u<<26)|(1u<<27))
#define PAIG_ERROR (0x0eu|(1u<<9)|(1u<<10)|(1u<<12)|(1u<<13)|(3u<<24)|(3u<<28))
#define PAIG_KNOWN (PAIG_DONE|PAIG_ABORT|PAIG_TXWM|PAIG_RX|PAIG_ERROR)
enum paig_error {PAIG_OK,PAIG_DISABLED,PAIG_ARGUMENT,PAIG_CACHE,PAIG_NO_LEASE,
    PAIG_OWNER_LOST,PAIG_INITIAL,PAIG_IO,PAIG_UNCERTAIN,PAIG_TIMEOUT,PAIG_IRQ,
    PAIG_FIFO,PAIG_COMPLETION,PAIG_ABORT_FAILED,PAIG_RESTORE,PAIG_EVENT_LIMIT};
enum paig_delivery {PAIG_NOT_ISSUED,PAIG_ACCESS_COMPLETED,PAIG_ACCESS_UNKNOWN};
struct paig_lease {
    uint64_t cookie,cache_cookie,image,protocol,base,bytes,frequency,begin_ticks,end_ticks;
    /* Opaque binding to the provider's actual raw owner/clock/pin/firmware and
     * selector observations. Nonzero values are necessary, not sufficient;
     * current() must independently revalidate that authority at EACH access. */
    uint64_t source_evidence,exclusive_owner,clock_owner,pin_owner,selector_witness;
};
struct paig_event {uint64_t ticks;uint32_t offset,value;uint16_t write,delivery;};
struct paig_result {
    uint32_t attempted,error,sticky,uncertain,lease_acquired,lease_released;
    uint32_t acquire_delivery,release_delivery,outstanding,access_issued,access_completed;
    uint32_t command_issued,command_store_completed,command_not_issued,command_completed;
    uint32_t abort_issued,abort_store_completed,abort_not_issued,abort_completed,stop_confirmed;
    uint32_t saved[3],dirty,restored,sent,received,valid_identity,value,irq_or;
    uint64_t last_ticks;
    struct paig_lease lease;
    uint32_t events,event_overflow;
    struct paig_event raw[PAIG_EVENTS];
};
struct paig_io {
    void *context;
    /* A zero acquire result is a definitive refusal with no acquired lease
     * or ownership transition. A provider must never translate uncertain
     * acquisition into zero; its unknown prefix remains outstanding=2. */
    int (*acquire)(void *,const struct paic_result *,uint32_t,struct paig_lease *);
    int (*current)(void *,const struct paig_lease *,uint64_t *);
    enum paig_delivery (*read32)(void *,const struct paig_lease *,uint32_t,uint32_t *);
    enum paig_delivery (*write32)(void *,const struct paig_lease *,uint32_t,uint32_t);
    void (*delay_us)(void *,unsigned);
    void (*order)(void *);
    int (*release)(void *,const struct paig_lease *);
};
/* One boot/controller ticket, shared even when result/selected are changed.
 * Only the explicitly synthetic host peer may reset it. No physical reset API. */
static struct {uint32_t used,outstanding,sticky;uintptr_t result;} paig_boot_ticket;
#if defined(PAIG_SOFTWARE_PEER_ONLY)
static inline void paig_software_reset_ticket(void)
{paig_boot_ticket.used=paig_boot_ticket.outstanding=paig_boot_ticket.sticky=0;paig_boot_ticket.result=0;}
#endif
static inline void paig_actual_order(void *context)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("dsb sy":::"memory");
#else
    __asm__ volatile("":::"memory"); /* SOFTWARE host only; physical target is AArch64. */
#endif
}
static inline void paig_fail(struct paig_result *r,unsigned error,int unknown)
{if(!r->error)r->error=error;r->sticky=1;paig_boot_ticket.sticky=1;if(unknown)r->uncertain=1;paig_actual_order(0);}
static inline int paig_cache_admitted(const struct paic_result *c,uint32_t stage)
{
    if(!c||stage!=2||c->error||c->attempted!=1||c->owner_matches!=1||c->hash_count!=4||c->hash_failed||
       !c->cache_consistent||c->snapshot_bytes[0]!=120||c->snapshot_bytes[1]!=120||
       c->release_status||!c->release_attempted||!c->map_keys_before_release_only||
       !c->image||(c->image&4095)||c->image>UINT64_MAX-0x8000||c->protocol_status||c->enumerate_status||
       c->protocol!=c->image+0x6098||c->protocol_after_status||c->protocol_after!=c->protocol||
       c->owner.revision!=0x1000||(uintptr_t)c->owner.base!=c->image||
       c->owner.bytes!=PAII_IMAGE_BYTES||c->owner.code_type!=3||c->owner.data_type!=4||
       !paic_arch_stable(&c->before,&c->after)||!paic_equal(c->snapshot[0],c->snapshot[1],120))return 0;
    for(unsigned n=0;n<4;n++)if(!paic_equal(c->hashes[n],paii_ranges[n].sha256,32))return 0;
    return c->cookie&&c->map_version[0]==1&&c->map_version[1]==1&&c->map_key[0]==c->map_key[1];
}
static inline int paig_current(const struct paig_io *io,struct paig_result *r)
{
    uint64_t now=0;
    if(r->uncertain||!io->current(io->context,&r->lease,&now)||now<r->last_ticks||
       now<r->lease.begin_ticks||now>r->lease.end_ticks){paig_fail(r,PAIG_OWNER_LOST,1);return 0;}
    r->last_ticks=now;return 1;
}
static inline int paig_access(const struct paig_io *io,struct paig_result *r,unsigned write,uint32_t offset,uint32_t *value)
{
    if(r->events==PAIG_EVENTS){r->event_overflow=1;paig_fail(r,PAIG_EVENT_LIMIT,1);return 0;}
    if(!paig_current(io,r))return 0;
    struct paig_event *e=&r->raw[r->events++];e->ticks=r->last_ticks;e->offset=offset;e->write=(uint16_t)write;
    e->value=*value;e->delivery=PAIG_ACCESS_UNKNOWN;r->outstanding=1;r->access_issued++;
    paig_boot_ticket.outstanding=1;
    if(write&&offset==0x600)r->command_issued=1;
    if(write&&offset==0x604)r->abort_issued=1;
    io->order(io->context); /* UNKNOWN/issued/outstanding BEFORE the callback can fault. */
    e->delivery=(uint16_t)(write?io->write32(io->context,&r->lease,offset,*value):io->read32(io->context,&r->lease,offset,value));
    if(!write)e->value=*value;
    if(e->delivery==PAIG_ACCESS_COMPLETED)r->access_completed++;
    if(write&&offset==0x600){r->command_store_completed=e->delivery==PAIG_ACCESS_COMPLETED;r->command_not_issued=e->delivery==PAIG_NOT_ISSUED;}
    if(write&&offset==0x604){r->abort_store_completed=e->delivery==PAIG_ACCESS_COMPLETED;r->abort_not_issued=e->delivery==PAIG_NOT_ISSUED;}
    if(e->delivery!=PAIG_ACCESS_COMPLETED)paig_fail(r,e->delivery==PAIG_NOT_ISSUED?PAIG_IO:PAIG_UNCERTAIN,e->delivery!=PAIG_NOT_ISSUED);
    if(r->sticky)paig_boot_ticket.sticky=1;
    io->order(io->context); /* Publish completion/partial/error BEFORE clearing outstanding. */
    if(e->delivery==PAIG_ACCESS_COMPLETED||e->delivery==PAIG_NOT_ISSUED){
        r->outstanding=0;paig_boot_ticket.outstanding=0;io->order(io->context);
    } /* UNKNOWN retains outstanding/lease/ticket: completion is not known. */
    return e->delivery==PAIG_ACCESS_COMPLETED;
}
static inline int paig_read(const struct paig_io *io,struct paig_result *r,uint32_t offset,uint32_t *value)
{*value=0;return paig_access(io,r,0,offset,value);}
static inline int paig_write(const struct paig_io *io,struct paig_result *r,uint32_t offset,uint32_t value)
{return paig_access(io,r,1,offset,&value);}
static inline int paig_set(const struct paig_io *io,struct paig_result *r,unsigned slot,uint32_t value)
{
    static const uint32_t offsets[3]={0x26c,0x270,0x80c};uint32_t actual=0;
    uint32_t prior_dirty=r->dirty,prior_events=r->events,bit=1u<<slot;
    r->dirty|=bit;io->order(io->context); /* Possible change BEFORE the store can fault. */
    if(!paig_write(io,r,offsets[slot],value)){
        if(r->events>prior_events&&r->raw[r->events-1].delivery==PAIG_NOT_ISSUED&&!(prior_dirty&bit)){
            r->dirty&=~bit;io->order(io->context); /* Revoke only this newly added bit. */
        }
        return 0;
    }
    if(!paig_read(io,r,offsets[slot],&actual)||actual!=value){paig_fail(r,PAIG_RESTORE,0);return 0;}return 1;
}
static inline int paig_idle(const struct paig_io *io,struct paig_result *r,int *idle)
{
    uint32_t status=0,tx=0,rx=0,ios=0;
    if(!paig_read(io,r,0x40,&status)||!paig_read(io,r,0x800,&tx)||
       !paig_read(io,r,0x804,&rx)||!paig_read(io,r,0x908,&ios))return 0;
    *idle=!(status&0x1001u)&&!(tx&0x0fffffffu)&&!(rx&0x01ffffffu)&&(ios&3u)==3u;return 1;
}
static inline int paig_ack(const struct paig_io *io,struct paig_result *r,uint32_t irq)
{
    uint32_t after=0;
    if(irq&~PAIG_KNOWN){paig_fail(r,PAIG_IRQ,1);return 0;}
    if(irq&&!paig_write(io,r,0x618,irq))return 0;
    if(!paig_read(io,r,0x610,&after))return 0;r->irq_or|=after;
    if(after){paig_fail(r,PAIG_IRQ,1);return 0;}return 1;
}
static inline int paig_stop_owned(const struct paig_io *io,struct paig_result *r)
{
    if(!r->command_issued||r->command_not_issued||r->uncertain)return 0;
    uint32_t pending=0,status=0;int stopped=0;
    if(!paig_read(io,r,0x610,&pending)||!paig_read(io,r,0x40,&status)||!paig_idle(io,r,&stopped))return 0;
    r->irq_or|=pending;
    if(pending&~PAIG_KNOWN){paig_fail(r,PAIG_IRQ,1);return 0;}
    if((pending&PAIG_DONE)&&stopped){if(!paig_ack(io,r,pending))return 0;r->stop_confirmed=1;return 1;}
    if(!(status&1)){paig_fail(r,PAIG_ABORT_FAILED,1);return 0;}
    /* Owned command only; no inherited sequencer cancellation or STOP_ON_BUS,
     * SW_RESET, FIFO flush, all-ones IRQ clear or error retry. */
    if(!paig_write(io,r,0x604,2))return 0;
    for(unsigned n=0;n<64;n++){
        uint32_t irq=0,rx=0,word=0;int idle=0;
        if(!paig_read(io,r,0x610,&irq)||!paig_read(io,r,0x804,&rx))return 0;r->irq_or|=irq;
        if((irq&~PAIG_KNOWN)||(rx&0x01ffffffu)>1){paig_fail(r,PAIG_ABORT_FAILED,1);return 0;}
        if(rx&0x01ffffffu){if(!paig_read(io,r,0x780,&word))return 0;}
        if(!paig_idle(io,r,&idle))return 0;
        if((irq&PAIG_ABORT)&&idle){if(!paig_ack(io,r,irq))return 0;r->abort_completed=1;r->stop_confirmed=1;return 1;}
        io->delay_us(io->context,25);
    }
    paig_fail(r,PAIG_ABORT_FAILED,1);return 0;
}
static inline int paig_restore(const struct paig_io *io,struct paig_result *r)
{
    static const uint32_t offsets[3]={0x26c,0x270,0x80c};int idle=0;
    if(!paig_idle(io,r,&idle)||!idle){paig_fail(r,PAIG_RESTORE,1);return 0;}
    for(unsigned n=3;n;n--){unsigned slot=n-1;uint32_t actual=0;
        if(!(r->dirty&(1u<<slot)))continue;
        if(!paig_write(io,r,offsets[slot],r->saved[slot])||!paig_read(io,r,offsets[slot],&actual)||actual!=r->saved[slot]){
            paig_fail(r,PAIG_RESTORE,1);return 0;
        }
        r->dirty&=~(1u<<slot);
    }
    r->restored=1;return 1;
}
/* selected0=TAS2559 book0/page0/PGID3; selected1=TAS2560 book0/page0/ID125.
 * The provider must prove selectors, reset/power state and exact firmware
 * WRITE_READ capability. Nothing here writes page/book or invents an ID. */
static inline int paig_identity_once(const struct paig_io *io,const struct paic_result *cache,
    uint32_t stage,unsigned selected,struct paig_result *r)
{
    if(!r||r->attempted||paig_boot_ticket.used)return 0;
    paig_boot_ticket.used=1;paig_boot_ticket.result=(uintptr_t)r;r->attempted=1;
#if !PAIG_EXECUTOR_BODY
    (void)io;(void)cache;(void)stage;(void)selected;r->error=PAIG_DISABLED;return 0;
#else
    uint32_t addr=selected?0x4d:0x4c,reg=selected?125:3,word=0,irq=0,rx=0;int idle=0;
    if(selected>1||!io||!io->acquire||!io->current||!io->read32||!io->write32||!io->delay_us||!io->order||!io->release){paig_fail(r,PAIG_NO_LEASE,0);return 0;}
#if !defined(PAIG_SOFTWARE_PEER_ONLY)
    if(io->order!=paig_actual_order){paig_fail(r,PAIG_NO_LEASE,0);return 0;}
#endif
    if(!paig_cache_admitted(cache,stage)){paig_fail(r,PAIG_CACHE,0);return 0;}
    r->acquire_delivery=PAIG_ACCESS_UNKNOWN;r->outstanding=2;paig_boot_ticket.outstanding=2;io->order(io->context);
    int acquired=io->acquire(io->context,cache,stage,&r->lease);
    r->acquire_delivery=acquired?PAIG_ACCESS_COMPLETED:PAIG_NOT_ISSUED;r->lease_acquired=acquired?1u:0u;
    if(!acquired)paig_fail(r,PAIG_NO_LEASE,0);
    io->order(io->context);r->outstanding=0;paig_boot_ticket.outstanding=0;io->order(io->context);
    if(!acquired)return 0;
    if(!r->lease.cookie||r->lease.cache_cookie!=cache->cookie||r->lease.image!=cache->image||r->lease.protocol!=cache->protocol||
       r->lease.base!=0x894000||r->lease.bytes!=0x4000||r->lease.frequency!=19200000||
       r->lease.begin_ticks<cache->after.ticks||r->lease.begin_ticks-cache->after.ticks>3840000||
       r->lease.end_ticks<r->lease.begin_ticks||r->lease.end_ticks-r->lease.begin_ticks>3840000||
       !r->lease.source_evidence||!r->lease.exclusive_owner||!r->lease.clock_owner||!r->lease.pin_owner||!r->lease.selector_witness){
        paig_fail(r,PAIG_NO_LEASE,1);goto finish;
    }
    r->last_ticks=r->lease.begin_ticks;
    if(!paig_idle(io,r,&idle)||!idle){paig_fail(r,PAIG_INITIAL,0);goto finish;}
    /* Observe only after the INDEPENDENT live lease. Never probe cold MMIO to
     * discover whether that very access was allowed. No init/packing write. */
    static const uint32_t ro[7]={0x64,0x68,0x258,0x260,0x264,0x284,0x288};
    for(unsigned n=0;n<7;n++){
        if(!paig_read(io,r,ro[n],&word))goto finish;
        int ok=n==0?!(word&1):n==1?((word>>8)&255)==3:n==2?!(word&1):word==((n&1)?0x7f8feu:0xffefeu);
        if(!ok){paig_fail(r,PAIG_INITIAL,0);goto finish;}
    }
    if(!paig_read(io,r,0x610,&irq)||irq){paig_fail(r,PAIG_INITIAL,0);goto finish;}
    for(unsigned n=0;n<3;n++){static const uint32_t offsets[3]={0x26c,0x270,0x80c};if(!paig_read(io,r,offsets[n],&r->saved[n]))goto finish;}
    if(!paig_set(io,r,0,1)||!paig_set(io,r,1,1)||!paig_set(io,r,2,1))goto finish;
    /* One combined WRITE_READ command has no inherited/partially held bus
     * phase between two independent commands. Hardware capability is a lease
     * prerequisite; the own Linux opcode constant alone does not prove it. */
    if(!paig_write(io,r,0x600,(3u<<27)|(addr<<9)))goto finish;
    for(unsigned n=0;n<96;n++){
        if(!paig_read(io,r,0x610,&irq)||!paig_read(io,r,0x804,&rx))goto finish;r->irq_or|=irq;
        if(irq&~PAIG_KNOWN){paig_fail(r,PAIG_IRQ,1);goto finish;}
        if(irq&(PAIG_ERROR|PAIG_ABORT)){paig_fail(r,PAIG_IRQ,0);goto finish;}
        if((rx&0x01ffffffu)>1){paig_fail(r,PAIG_FIFO,1);goto finish;}
        if((irq&PAIG_DONE)&&!r->sent){paig_fail(r,PAIG_COMPLETION,0);goto finish;}
        if((irq&PAIG_TXWM)&&!r->sent){if(!paig_write(io,r,0x700,reg)||!paig_set(io,r,2,0))goto finish;r->sent=1;}
        if(rx&0x01ffffffu){
            if(r->received||!(rx>>31)||((rx>>28)&7)!=1){paig_fail(r,PAIG_FIFO,1);goto finish;}
            if(!paig_read(io,r,0x780,&word))goto finish;r->value=word&255;r->received=1;
        }
        if(irq&PAIG_DONE){
            if(!paig_idle(io,r,&idle)||!idle||r->sent!=1||r->received!=1){paig_fail(r,PAIG_COMPLETION,0);goto finish;}
            if(!paig_read(io,r,0x610,&irq))goto finish;r->irq_or|=irq;
            if(irq&~PAIG_KNOWN){paig_fail(r,PAIG_IRQ,1);goto finish;}
            if(!(irq&PAIG_DONE)||(irq&(PAIG_ERROR|PAIG_ABORT))||!paig_ack(io,r,irq)){paig_fail(r,PAIG_COMPLETION,0);goto finish;}
            r->command_completed=1;r->stop_confirmed=1;break;
        }
        if(irq&(PAIG_TXWM|PAIG_RX))if(!paig_write(io,r,0x618,irq&(PAIG_TXWM|PAIG_RX)))goto finish;
        io->delay_us(io->context,25);
    }
    if(!r->command_completed)paig_fail(r,PAIG_TIMEOUT,0);
finish:
    if(!r->uncertain&&r->command_issued&&!r->command_not_issued&&!r->command_completed)if(!paig_stop_owned(io,r))paig_fail(r,PAIG_ABORT_FAILED,1);
    if(!r->uncertain&&r->dirty)(void)paig_restore(io,r);
    if(!r->uncertain&&!r->dirty){
        r->release_delivery=PAIG_ACCESS_UNKNOWN;r->outstanding=3;paig_boot_ticket.outstanding=3;io->order(io->context);
        r->lease_released=io->release(io->context,&r->lease)?1u:0u;
        r->release_delivery=r->lease_released?PAIG_ACCESS_COMPLETED:PAIG_ACCESS_UNKNOWN;
        if(!r->lease_released)paig_fail(r,PAIG_OWNER_LOST,1);
        io->order(io->context);
        if(r->lease_released){r->outstanding=0;paig_boot_ticket.outstanding=0;}
        io->order(io->context);
    }
    if(r->sticky)paig_boot_ticket.sticky=1;
    r->valid_identity=!r->error&&r->command_completed&&r->restored&&r->lease_released;
    io->order(io->context);
    return r->valid_identity!=0;
#endif
}
#endif
