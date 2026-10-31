/* Independent NEXT-CANDIDATE DRAFT; never included in the frozen0142 image.
 * One real-owner lease, one whole-boot SE5 ticket, at most three complete
 * WRITE_READ commands: read PAGE0, read BOOK127 only on page0, then own ID.
 * No selector DATA write, reset, amp status/CRC read, clock/pin init or PCM.
 * The physical ownership/clock/pin/FIFO capability provider is still absent.
 */
#ifndef POLARIS_AUDIO_GENI_SELECTOR_SESSION_DRAFT_H
#define POLARIS_AUDIO_GENI_SELECTOR_SESSION_DRAFT_H
#include "polaris-audio-geni-fifo.h"
#ifndef EFI_XNU_AUDIO_GENI_SELECTOR_SESSION_AVAILABLE
#define EFI_XNU_AUDIO_GENI_SELECTOR_SESSION_AVAILABLE 0
#endif
#if EFI_XNU_AUDIO_GENI_SELECTOR_SESSION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU) && \
    (EFI_XNU_AUDIO_GENI_FIFO_PHYSICAL_PROVIDER_AVAILABLE || defined(PAIG_SOFTWARE_PEER_ONLY))
#define PAGS_EXECUTOR_BODY 1
#else
#define PAGS_EXECUTOR_BODY 0
#endif
enum pags_refusal {PAGS_PAGE_NOT_ZERO=0x100,PAGS_BOOK_NOT_ZERO};
struct pags_step {
    uint32_t reg,first_event,end_event,sealed,value;
    uint32_t command_issued,command_store_completed,command_not_issued,command_completed;
    uint32_t abort_issued,abort_store_completed,abort_not_issued,abort_completed,stop_confirmed;
    uint32_t sent,received,irq_or,error;
};
struct pags_result {
    struct paig_result io; /* Complete append-only raw events for ALL3 commands. */
    uint32_t selected,steps_started,steps_completed,active_step;
    uint32_t page_read,book_read,page,book,selector_qualified,id_read_completed,id_value;
    uint32_t selector_data_writes,fault_lease_retained,stop_restore_complete;
    struct pags_step step[3];
};
/* Caller supplies a resident zero-initialized result; every later attempt
 * shares paig_boot_ticket with the original one-command executor. */
static inline void pags_seal(struct pags_result *s)
{
    struct paig_result *r=&s->io;struct pags_step *q=&s->step[s->active_step];
    q->end_event=r->events;q->value=r->value;q->command_issued=r->command_issued;
    q->command_store_completed=r->command_store_completed;q->command_not_issued=r->command_not_issued;
    q->command_completed=r->command_completed;q->abort_issued=r->abort_issued;
    q->abort_store_completed=r->abort_store_completed;q->abort_not_issued=r->abort_not_issued;
    q->abort_completed=r->abort_completed;q->stop_confirmed=r->stop_confirmed;
    q->sent=r->sent;q->received=r->received;q->irq_or=r->irq_or;q->error=r->error;q->sealed=1;
}
static inline void pags_begin_command(struct pags_result *s,unsigned index,uint32_t reg)
{
    struct paig_result *r=&s->io;
    s->active_step=index;s->steps_started=index+1;s->step[index].reg=reg;s->step[index].first_event=r->events;
    /* Prior command already sealed and positively stopped, so its flags may
     * become this command's live prefix. Previous flags/raw are never lost. */
    r->command_issued=r->command_store_completed=r->command_not_issued=r->command_completed=0;
    r->abort_issued=r->abort_store_completed=r->abort_not_issued=r->abort_completed=0;
    r->stop_confirmed=r->sent=r->received=r->value=r->irq_or=0;
}
static inline int pags_command(const struct paig_io *io,struct pags_result *s,unsigned index,uint32_t reg,uint32_t addr)
{
    struct paig_result *r=&s->io;uint32_t irq=0,rx=0,word=0;int idle=0;
    /* Reserve512 raw slots for this command's worst bounded owned abort and
     * restore. Never issue another command after exhausting its raw budget. */
    if(r->events>PAIG_EVENTS-512){paig_fail(r,PAIG_EVENT_LIMIT,0);return 0;}
    pags_begin_command(s,index,reg);
    if(!paig_idle(io,r,&idle))return 0;
    if(!idle){paig_fail(r,PAIG_INITIAL,1);return 0;} /* Unexpected new owner/bus state. */
    if(!paig_read(io,r,0x610,&irq))return 0;
    if(irq){r->irq_or|=irq;paig_fail(r,PAIG_IRQ,1);return 0;} /* Never clear an inherited/new IRQ. */
    if(!paig_set(io,r,0,1)||!paig_set(io,r,1,1)||!paig_set(io,r,2,1))return 0;
    if(!paig_write(io,r,0x600,(3u<<27)|(addr<<9)))return 0;
    for(unsigned n=0;n<96;n++){
        if(!paig_read(io,r,0x610,&irq)||!paig_read(io,r,0x804,&rx))return 0;r->irq_or|=irq;
        if(irq&~PAIG_KNOWN){paig_fail(r,PAIG_IRQ,1);return 0;}
        if(irq&(PAIG_ERROR|PAIG_ABORT)){paig_fail(r,PAIG_IRQ,0);return 0;}
        if((rx&0x01ffffffu)>1){paig_fail(r,PAIG_FIFO,1);return 0;}
        if((irq&PAIG_DONE)&&!r->sent){paig_fail(r,PAIG_COMPLETION,0);return 0;}
        if((irq&PAIG_TXWM)&&!r->sent){if(!paig_write(io,r,0x700,reg)||!paig_set(io,r,2,0))return 0;r->sent=1;}
        if(rx&0x01ffffffu){
            if(r->received||!(rx>>31)||((rx>>28)&7)!=1){paig_fail(r,PAIG_FIFO,1);return 0;}
            if(!paig_read(io,r,0x780,&word))return 0;r->value=word&255;r->received=1;
        }
        if(irq&PAIG_DONE){
            if(!paig_idle(io,r,&idle)||!idle||r->sent!=1||r->received!=1){paig_fail(r,PAIG_COMPLETION,0);return 0;}
            if(!paig_read(io,r,0x610,&irq))return 0;r->irq_or|=irq;
            if((irq&~PAIG_KNOWN)||!(irq&PAIG_DONE)||(irq&(PAIG_ERROR|PAIG_ABORT))||!paig_ack(io,r,irq)){
                paig_fail(r,PAIG_COMPLETION,0);return 0;}
            r->command_completed=1;r->stop_confirmed=1;s->steps_completed++;pags_seal(s);return 1;
        }
        if(irq&(PAIG_TXWM|PAIG_RX))if(!paig_write(io,r,0x618,irq&(PAIG_TXWM|PAIG_RX)))return 0;
        io->delay_us(io->context,25);
    }
    paig_fail(r,PAIG_TIMEOUT,0);return 0;
}
static inline int pags_identity_session_once(const struct paig_io *io,const struct paic_result *cache,
    uint32_t stage,unsigned selected,struct pags_result *s)
{
    if(!s||s->io.attempted||paig_boot_ticket.used)return 0;
    struct paig_result *r=&s->io;r->attempted=1;s->selected=selected;
    paig_boot_ticket.used=1;paig_boot_ticket.result=(uintptr_t)s;
#if !PAGS_EXECUTOR_BODY
    (void)io;(void)cache;(void)stage;r->error=PAIG_DISABLED;return 0;
#else
    uint32_t word=0,irq=0;int idle=0;
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
       !r->lease.source_evidence||!r->lease.exclusive_owner||!r->lease.clock_owner||!r->lease.pin_owner){paig_fail(r,PAIG_NO_LEASE,1);goto finish;}
    /* selector_witness from the provider is deliberately NOT accepted as a
     * substitute for the two real on-bus selector reads below. */
    r->last_ticks=r->lease.begin_ticks;
    if(!paig_idle(io,r,&idle)||!idle){paig_fail(r,PAIG_INITIAL,0);goto finish;}
    static const uint32_t ro[7]={0x64,0x68,0x258,0x260,0x264,0x284,0x288};
    for(unsigned n=0;n<7;n++){
        if(!paig_read(io,r,ro[n],&word))goto finish;
        int ok=n==0?!(word&1):n==1?((word>>8)&255)==3:n==2?!(word&1):word==((n&1)?0x7f8feu:0xffefeu);
        if(!ok){paig_fail(r,PAIG_INITIAL,0);goto finish;}
    }
    if(!paig_read(io,r,0x610,&irq)||irq){paig_fail(r,PAIG_INITIAL,0);goto finish;}
    for(unsigned n=0;n<3;n++){static const uint32_t offsets[3]={0x26c,0x270,0x80c};if(!paig_read(io,r,offsets[n],&r->saved[n]))goto finish;}
    uint32_t addr=selected?0x4d:0x4c;
    if(!pags_command(io,s,0,0,addr))goto finish;s->page_read=1;s->page=r->value;
    if(s->page){paig_fail(r,PAGS_PAGE_NOT_ZERO,0);goto finish;}
    if(!pags_command(io,s,1,127,addr))goto finish;s->book_read=1;s->book=r->value;
    if(s->book){paig_fail(r,PAGS_BOOK_NOT_ZERO,0);goto finish;}
    s->selector_qualified=1;
    if(!pags_command(io,s,2,selected?125:3,addr))goto finish;
    s->id_read_completed=1;s->id_value=r->value;
finish:
    if(!r->uncertain&&r->command_issued&&!r->command_not_issued&&!r->command_completed)
        if(!paig_stop_owned(io,r))paig_fail(r,PAIG_ABORT_FAILED,1);
    if(!r->uncertain&&r->dirty)(void)paig_restore(io,r);
    if(s->steps_started&&!s->step[s->active_step].sealed)pags_seal(s);
    s->stop_restore_complete=!r->uncertain&&!r->dirty&&r->restored;
    int ordinary_refusal=r->error==PAGS_PAGE_NOT_ZERO||r->error==PAGS_BOOK_NOT_ZERO||(!s->steps_started&&r->error==PAIG_INITIAL);
    if(!r->uncertain&&!r->dirty&&(!r->error||ordinary_refusal)){
        s->fault_lease_retained=1;r->release_delivery=PAIG_ACCESS_UNKNOWN;r->outstanding=3;paig_boot_ticket.outstanding=3;io->order(io->context);
        r->lease_released=io->release(io->context,&r->lease)?1u:0u;
        r->release_delivery=r->lease_released?PAIG_ACCESS_COMPLETED:PAIG_ACCESS_UNKNOWN;
        if(!r->lease_released)paig_fail(r,PAIG_OWNER_LOST,1);
        io->order(io->context);if(r->lease_released){s->fault_lease_retained=0;r->outstanding=0;paig_boot_ticket.outstanding=0;io->order(io->context);}
    }else if(r->lease_acquired){
        /* Even known hardware errors retain the lease after any proved
         * stop/restore. UNKNOWN preserves its more specific outstanding. */
        s->fault_lease_retained=1;if(!r->outstanding){r->outstanding=4;paig_boot_ticket.outstanding=4;}io->order(io->context);
    }
    r->valid_identity=!r->error&&s->selector_qualified&&s->steps_completed==3&&s->id_read_completed&&s->stop_restore_complete&&r->lease_released;
    io->order(io->context);return r->valid_identity!=0;
#endif
}
#endif
