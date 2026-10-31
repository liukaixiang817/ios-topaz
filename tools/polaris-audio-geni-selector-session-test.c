/* Software SE5 FIFO peer only. Uses the REAL0141 RAM witness as passive input;
 * its phone addresses are never dereferenced. The lease and every IO below
 * are synthetic and cannot qualify physical MMIO, firmware or TAS identity. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
static void text(const char *s){(void)s;}
static void report(const char *s,uint64_t n){(void)s;(void)n;}
#include "polaris-audio-geni-selector-session.h"
enum {F_NONE,F_NO_LEASE,F_BUSY,F_OLD_IRQ,F_PACKING,F_TIMEOUT,F_NACK,F_UNKNOWN_IRQ,
      F_OWNER_LOST,F_CMD_NOT_SENT,F_CMD_UNKNOWN,F_PARTIAL_CONFIG,F_RESTORE,F_EXPIRED,F_READ_UNKNOWN,
      F_CONFIG_UNKNOWN,F_WM_NOT_SENT,F_SYNC_FAULT,F_CONFIG_SYNC_FAULT,
      F_RELEASE_UNKNOWN,F_RELEASE_SYNC_FAULT};
struct model {
    uint32_t registers[0x4000/4],fault,acquires,releases,reads,writes,commands,aborts,clear_or,active,irq,rx,selected;
    uint64_t ticks;
    uint32_t fail_step,page,book,inject_irq_before_step,inject_busy_before_step;
    uint32_t orders,last_callback_order,callback_returned,completion_orders;
};
static struct model m;
static struct paic_result cache;
static struct pags_result session;
#define result session.io
static jmp_buf synchronous_fault;
static void before_callback(struct model *p,uint32_t offset,int write)
{
    const struct paig_event *e=&result.raw[result.events-1];
    assert(result.outstanding==1&&paig_boot_ticket.outstanding==1&&e->delivery==PAIG_ACCESS_UNKNOWN&&
        e->offset==offset&&e->write==write&&p->orders>p->last_callback_order);
    if(write&&offset==0x600)assert(result.command_issued==1&&!result.command_store_completed);
    if(write&&offset==0x604)assert(result.abort_issued==1&&!result.abort_store_completed);
    if(write&&(offset==0x26c||offset==0x270||offset==0x80c))assert(result.dirty&(offset==0x26c?1u:offset==0x270?2u:4u));
    p->last_callback_order=p->orders;
}
static enum paig_delivery returned(struct model *p,enum paig_delivery delivery)
{p->callback_returned=1;return delivery;}
static int acquire(void *context,const struct paic_result *c,uint32_t stage,struct paig_lease *l)
{
    struct model *p=context;p->acquires++;assert(stage==2&&c==&cache);
    assert(result.acquire_delivery==PAIG_ACCESS_UNKNOWN&&result.outstanding==2&&paig_boot_ticket.outstanding==2&&p->orders);
    if(p->fault==F_NO_LEASE)return 0;
    *l=(struct paig_lease){.cookie=0x4d4f44454c,.cache_cookie=c->cookie,.image=c->image,.protocol=c->protocol,
        .base=0x894000,.bytes=0x4000,.frequency=19200000,.begin_ticks=p->ticks,.end_ticks=p->ticks+384000,
        .source_evidence=1,.exclusive_owner=1,.clock_owner=1,.pin_owner=1,.selector_witness=0};
    if(p->fault==F_EXPIRED)l->end_ticks=l->begin_ticks-1;
    return 1;
}
static int current(void *context,const struct paig_lease *l,uint64_t *ticks)
{struct model *p=context;assert(l->cookie==0x4d4f44454c);p->ticks+=32;*ticks=p->ticks;return !(p->fault==F_OWNER_LOST&&p->commands==p->fail_step);}
static enum paig_delivery read32(void *context,const struct paig_lease *l,uint32_t offset,uint32_t *value)
{
    struct model *p=context;(void)l;assert(!(offset&3)&&offset<0x4000);p->reads++;before_callback(p,offset,0);
    if(offset==0x40&&!result.command_issued&&session.active_step+1==p->inject_irq_before_step)p->irq|=1u<<7;
    if(offset==0x40&&!result.command_issued&&session.active_step+1==p->inject_busy_before_step)p->active=1;
    if(p->fault==F_READ_UNKNOWN&&p->commands==p->fail_step)return returned(p,PAIG_ACCESS_UNKNOWN);
    if(offset==0x40)*value=p->active;
    else if(offset==0x610)*value=p->irq;
    else if(offset==0x800)*value=0;
    else if(offset==0x804)*value=p->rx?0x90000001u:0;
    else if(offset==0x780){assert(p->rx);p->rx=0;*value=p->commands==1?p->page:p->commands==2?p->book:0x5a;}
    else *value=p->registers[offset/4];
    if(p->fault==F_RESTORE&&p->commands&&offset==0x26c&&*value==0x55)*value=0x54;
    return returned(p,PAIG_ACCESS_COMPLETED);
}
static enum paig_delivery write32(void *context,const struct paig_lease *l,uint32_t offset,uint32_t value)
{
    struct model *p=context;(void)l;p->writes++;before_callback(p,offset,1);
    assert(offset==0x26c||offset==0x270||offset==0x80c||offset==0x600||offset==0x604||offset==0x700||offset==0x618);
    if(offset==0x600){
        assert(p->commands<3&&!p->active&&!p->irq&&value==((3u<<27)|((p->selected?0x4du:0x4cu)<<9)));
        if(p->fault==F_CMD_NOT_SENT&&p->commands+1==p->fail_step)return returned(p,PAIG_NOT_ISSUED);
        p->commands++;p->active=1;p->irq=PAIG_TXWM;
        if(p->fault==F_SYNC_FAULT&&p->commands==p->fail_step)longjmp(synchronous_fault,1);
        return returned(p,p->fault==F_CMD_UNKNOWN&&p->commands==p->fail_step?PAIG_ACCESS_UNKNOWN:PAIG_ACCESS_COMPLETED);
    }
    if(offset==0x604){assert(value==2&&p->commands>=1&&p->active&&!p->aborts);p->aborts++;p->active=0;p->irq=PAIG_ABORT;return returned(p,PAIG_ACCESS_COMPLETED);}
    if(offset==0x700){
        assert(value==(p->commands==1?0u:p->commands==2?127u:(p->selected?125u:3u))&&p->commands>=1&&p->active);
        if(p->fault==F_TIMEOUT&&p->commands==p->fail_step){p->irq=0;return returned(p,PAIG_ACCESS_COMPLETED);}
        if(p->fault==F_UNKNOWN_IRQ){p->irq=1u<<7;return returned(p,PAIG_ACCESS_COMPLETED);}
        p->active=0;p->irq=PAIG_DONE|(p->fault==F_NACK&&p->commands==p->fail_step?(1u<<10):(1u<<27));p->rx=p->fault==F_NACK&&p->commands==p->fail_step?0:1;
        return returned(p,PAIG_ACCESS_COMPLETED);
    }
    if(offset==0x618){assert(value&&value!=UINT32_MAX&&!(value&~PAIG_KNOWN));p->clear_or|=value;p->irq&=~value;return returned(p,PAIG_ACCESS_COMPLETED);}
    if(p->fault==F_PARTIAL_CONFIG&&p->commands+1==p->fail_step&&offset==0x270&&value==1)return returned(p,PAIG_NOT_ISSUED);
    if(p->fault==F_WM_NOT_SENT&&offset==0x80c&&value==0)return returned(p,PAIG_NOT_ISSUED);
    if(offset==0x26c&&value==1&&p->commands+1==p->fail_step&&(p->fault==F_CONFIG_UNKNOWN||p->fault==F_CONFIG_SYNC_FAULT)){
        p->registers[offset/4]=value;
        if(p->fault==F_CONFIG_SYNC_FAULT)longjmp(synchronous_fault,1);
        return returned(p,PAIG_ACCESS_UNKNOWN);
    }
    p->registers[offset/4]=value;return returned(p,PAIG_ACCESS_COMPLETED);
}
static void delay(void *context,unsigned us){struct model *p=context;assert(us==25);p->ticks+=us*19;}
static void order(void *context)
{
    struct model *p=context;paig_actual_order(context);p->orders++;
    if(p->callback_returned){assert(result.outstanding==1&&paig_boot_ticket.outstanding==1);p->callback_returned=0;p->completion_orders++;}
}
static int release(void *context,const struct paig_lease *l)
{
    struct model *p=context;(void)l;
    assert(result.outstanding==3&&result.release_delivery==PAIG_ACCESS_UNKNOWN&&paig_boot_ticket.outstanding==3);
    p->releases++;
    if(p->fault==F_RELEASE_SYNC_FAULT)longjmp(synchronous_fault,1);
    return p->fault!=F_RELEASE_UNKNOWN;
}
static void reset(unsigned fault,unsigned selected)
{
    memset(&m,0,sizeof(m));memset(&session,0,sizeof(session));paig_software_reset_ticket();m.fault=fault;m.selected=selected;m.ticks=cache.after.ticks+100;
    m.registers[0x68/4]=3u<<8;m.registers[0x908/4]=3;
    m.registers[0x260/4]=m.registers[0x284/4]=0x7f8fe;
    m.registers[0x264/4]=m.registers[0x288/4]=0xffefe;
    m.registers[0x26c/4]=0x55;m.registers[0x270/4]=0x66;m.registers[0x80c/4]=7;
    if(fault==F_BUSY)m.active=1;
    if(fault==F_OLD_IRQ)m.irq=1u<<10;
    if(fault==F_PACKING)m.registers[0x260/4]=0;
}
static int run(unsigned selected)
{const struct paig_io io={&m,acquire,current,read32,write32,delay,order,release};return pags_identity_session_once(&io,&cache,2,selected,&session);}
static void saved_restored(void)
{assert(m.registers[0x26c/4]==0x55&&m.registers[0x270/4]==0x66&&m.registers[0x80c/4]==7&&result.dirty==0);}
int main(int argc,char **argv)
{
    assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f&&fread(&cache,1,sizeof(cache),f)==sizeof(cache)&&!fclose(f));
    unsigned checks=0,max_events=0;
    for(unsigned selected=0;selected<2;selected++){
        reset(F_NONE,selected);assert(run(selected)&&m.commands==3&&m.acquires==1&&m.releases==1&&!m.aborts);
        assert(session.steps_completed==3&&session.page_read&&session.book_read&&session.selector_qualified&&session.id_read_completed&&session.id_value==0x5a&&!session.selector_data_writes&&session.stop_restore_complete);
        saved_restored();for(unsigned n=0;n<3;n++){assert(session.step[n].sealed&&session.step[n].command_completed&&session.step[n].stop_confirmed&&session.step[n].reg==(n==0?0u:n==1?127u:selected?125u:3u));
            if(n)assert(session.step[n].first_event>=session.step[n-1].end_event);}
        unsigned calls=m.reads+m.writes;struct pags_result other={0};const struct paig_io io={&m,acquire,current,read32,write32,delay,order,release};
        assert(!pags_identity_session_once(&io,&cache,2,1-selected,&other)&&!other.io.attempted&&m.reads+m.writes==calls);
        struct paig_result old={0};assert(!paig_identity_once(&io,&cache,2,selected,&old)&&!old.attempted&&m.reads+m.writes==calls);checks++;
    }
    reset(F_NONE,0);m.page=2;assert(!run(0)&&result.error==PAGS_PAGE_NOT_ZERO&&m.commands==1&&session.steps_completed==1&&!session.book_read&&!session.id_read_completed&&m.releases==1&&!session.selector_data_writes);saved_restored();checks++;
    reset(F_NONE,0);m.book=100;assert(!run(0)&&result.error==PAGS_BOOK_NOT_ZERO&&m.commands==2&&session.steps_completed==2&&!session.id_read_completed&&m.releases==1&&!session.selector_data_writes);saved_restored();checks++;
    for(unsigned step=1;step<=3;step++){
        reset(F_NACK,0);m.fail_step=step;assert(!run(0)&&m.commands==step&&session.steps_completed==step-1&&result.error==PAIG_IRQ&&result.stop_confirmed&&result.restored&&!result.uncertain&&!m.releases&&session.fault_lease_retained&&result.outstanding==4);saved_restored();checks++;
        reset(F_TIMEOUT,0);m.fail_step=step;assert(!run(0)&&m.commands==step&&session.steps_completed==step-1&&result.error==PAIG_TIMEOUT&&m.aborts==1&&result.stop_confirmed&&result.restored&&!m.releases&&session.fault_lease_retained);saved_restored();if(result.events>max_events)max_events=result.events;checks++;
        reset(F_CMD_UNKNOWN,0);m.fail_step=step;assert(!run(0)&&m.commands==step&&session.steps_completed==step-1&&result.uncertain&&result.outstanding==1&&paig_boot_ticket.outstanding==1&&!m.releases&&!m.aborts&&session.fault_lease_retained);checks++;
        reset(F_READ_UNKNOWN,0);m.fail_step=step;assert(!run(0)&&m.commands==step&&session.steps_completed==step-1&&result.uncertain&&result.outstanding==1&&!m.releases&&!m.aborts);checks++;
        reset(F_SYNC_FAULT,0);m.fail_step=step;
        if(!setjmp(synchronous_fault)){(void)run(0);assert(!"synthetic synchronous command must not return");}
        assert(m.commands==step&&session.steps_completed==step-1&&result.outstanding==1&&paig_boot_ticket.outstanding==1&&result.raw[result.events-1].delivery==PAIG_ACCESS_UNKNOWN&&!m.releases&&!m.aborts);checks++;
    }
    reset(F_CONFIG_UNKNOWN,0);m.fail_step=2;assert(!run(0)&&m.commands==1&&session.steps_completed==1&&result.dirty&&result.uncertain&&result.outstanding==1&&!m.releases);checks++;
    reset(F_RELEASE_UNKNOWN,0);assert(!run(0)&&m.commands==3&&session.id_read_completed&&result.restored&&result.release_delivery==PAIG_ACCESS_UNKNOWN&&result.outstanding==3&&paig_boot_ticket.outstanding==3&&!result.lease_released);saved_restored();checks++;
    reset(F_RELEASE_SYNC_FAULT,0);if(!setjmp(synchronous_fault)){(void)run(0);assert(!"synthetic release must not return");}
    assert(m.commands==3&&session.id_read_completed&&result.outstanding==3&&paig_boot_ticket.outstanding==3&&result.release_delivery==PAIG_ACCESS_UNKNOWN);checks++;
    reset(F_NO_LEASE,0);assert(!run(0)&&!m.commands&&!m.reads&&!m.writes);checks++;
    reset(F_OLD_IRQ,0);assert(!run(0)&&!m.commands&&!m.writes&&!m.clear_or&&m.releases==1);checks++;
    for(unsigned step=2;step<=3;step++){
        reset(F_NONE,0);m.inject_irq_before_step=step;assert(!run(0)&&m.commands==step-1&&session.steps_completed==step-1&&result.uncertain&&result.dirty&&m.irq==(1u<<7)&&!(m.clear_or&(1u<<7))&&!m.releases&&!m.aborts);checks++;
        reset(F_NONE,0);m.inject_busy_before_step=step;assert(!run(0)&&m.commands==step-1&&session.steps_completed==step-1&&result.uncertain&&result.dirty&&m.active&&!m.releases&&!m.aborts);checks++;
    }
    printf("{\"checks\":%u,\"maximum_raw_events\":%u,\"one_lease\":true,\"maximum_commands\":3,\"amp_selector_data_writes\":0,\"physical_provider_implemented\":false,\"actual_MMIO\":0}\n",checks,max_events);
    return 0;
}
