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
#include "polaris-audio-geni-fifo.h"
enum {F_NONE,F_NO_LEASE,F_BUSY,F_OLD_IRQ,F_PACKING,F_TIMEOUT,F_NACK,F_UNKNOWN_IRQ,
      F_OWNER_LOST,F_CMD_NOT_SENT,F_CMD_UNKNOWN,F_PARTIAL_CONFIG,F_RESTORE,F_EXPIRED,F_READ_UNKNOWN,
      F_CONFIG_UNKNOWN,F_WM_NOT_SENT,F_SYNC_FAULT,F_CONFIG_SYNC_FAULT,
      F_RELEASE_UNKNOWN,F_RELEASE_SYNC_FAULT};
struct model {
    uint32_t registers[0x4000/4],fault,acquires,releases,reads,writes,commands,aborts,clear_or,active,irq,rx,selected;
    uint64_t ticks;
    uint32_t orders,last_callback_order,callback_returned,completion_orders;
};
static struct model m;
static struct paic_result cache;
static struct paig_result result;
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
        .source_evidence=1,.exclusive_owner=1,.clock_owner=1,.pin_owner=1,.selector_witness=1};
    if(p->fault==F_EXPIRED)l->end_ticks=l->begin_ticks-1;
    return 1;
}
static int current(void *context,const struct paig_lease *l,uint64_t *ticks)
{struct model *p=context;assert(l->cookie==0x4d4f44454c);p->ticks+=32;*ticks=p->ticks;return !(p->fault==F_OWNER_LOST&&p->commands);}
static enum paig_delivery read32(void *context,const struct paig_lease *l,uint32_t offset,uint32_t *value)
{
    struct model *p=context;(void)l;assert(!(offset&3)&&offset<0x4000);p->reads++;before_callback(p,offset,0);
    if(p->fault==F_READ_UNKNOWN&&p->commands)return returned(p,PAIG_ACCESS_UNKNOWN);
    if(offset==0x40)*value=p->active;
    else if(offset==0x610)*value=p->irq;
    else if(offset==0x800)*value=0;
    else if(offset==0x804)*value=p->rx?0x90000001u:0;
    else if(offset==0x780){assert(p->rx);p->rx=0;*value=0x5a;}
    else *value=p->registers[offset/4];
    if(p->fault==F_RESTORE&&p->commands&&offset==0x26c&&*value==0x55)*value=0x54;
    return returned(p,PAIG_ACCESS_COMPLETED);
}
static enum paig_delivery write32(void *context,const struct paig_lease *l,uint32_t offset,uint32_t value)
{
    struct model *p=context;(void)l;p->writes++;before_callback(p,offset,1);
    assert(offset==0x26c||offset==0x270||offset==0x80c||offset==0x600||offset==0x604||offset==0x700||offset==0x618);
    if(offset==0x600){
        assert(!p->commands&&!p->active&&value==((3u<<27)|((p->selected?0x4du:0x4cu)<<9)));
        if(p->fault==F_CMD_NOT_SENT)return returned(p,PAIG_NOT_ISSUED);
        p->commands++;p->active=1;p->irq=PAIG_TXWM;
        if(p->fault==F_SYNC_FAULT)longjmp(synchronous_fault,1);
        return returned(p,p->fault==F_CMD_UNKNOWN?PAIG_ACCESS_UNKNOWN:PAIG_ACCESS_COMPLETED);
    }
    if(offset==0x604){assert(value==2&&p->commands==1&&p->active&&!p->aborts);p->aborts++;p->active=0;p->irq=PAIG_ABORT;return returned(p,PAIG_ACCESS_COMPLETED);}
    if(offset==0x700){
        assert(value==(p->selected?125u:3u)&&p->commands==1&&p->active);
        if(p->fault==F_TIMEOUT){p->irq=0;return returned(p,PAIG_ACCESS_COMPLETED);}
        if(p->fault==F_UNKNOWN_IRQ){p->irq=1u<<7;return returned(p,PAIG_ACCESS_COMPLETED);}
        p->active=0;p->irq=PAIG_DONE|(p->fault==F_NACK?(1u<<10):(1u<<27));p->rx=p->fault==F_NACK?0:1;
        return returned(p,PAIG_ACCESS_COMPLETED);
    }
    if(offset==0x618){assert(value&&value!=UINT32_MAX&&!(value&~PAIG_KNOWN));p->clear_or|=value;p->irq&=~value;return returned(p,PAIG_ACCESS_COMPLETED);}
    if(p->fault==F_PARTIAL_CONFIG&&offset==0x270&&value==1)return returned(p,PAIG_NOT_ISSUED);
    if(p->fault==F_WM_NOT_SENT&&offset==0x80c&&value==0)return returned(p,PAIG_NOT_ISSUED);
    if(offset==0x26c&&value==1&&(p->fault==F_CONFIG_UNKNOWN||p->fault==F_CONFIG_SYNC_FAULT)){
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
    memset(&m,0,sizeof(m));memset(&result,0,sizeof(result));paig_software_reset_ticket();m.fault=fault;m.selected=selected;m.ticks=cache.after.ticks+100;
    m.registers[0x68/4]=3u<<8;m.registers[0x908/4]=3;
    m.registers[0x260/4]=m.registers[0x284/4]=0x7f8fe;
    m.registers[0x264/4]=m.registers[0x288/4]=0xffefe;
    m.registers[0x26c/4]=0x55;m.registers[0x270/4]=0x66;m.registers[0x80c/4]=7;
    if(fault==F_BUSY)m.active=1;
    if(fault==F_OLD_IRQ)m.irq=1u<<10;
    if(fault==F_PACKING)m.registers[0x260/4]=0;
}
static int run(unsigned selected)
{const struct paig_io io={&m,acquire,current,read32,write32,delay,order,release};return paig_identity_once(&io,&cache,2,selected,&result);}
static void saved_restored(void)
{assert(m.registers[0x26c/4]==0x55&&m.registers[0x270/4]==0x66&&m.registers[0x80c/4]==7&&result.dirty==0);}
int main(int argc,char **argv)
{
    assert(argc==2&&sizeof(cache)==5096);FILE *f=fopen(argv[1],"rb");assert(f&&fread(&cache,1,sizeof(cache),f)==sizeof(cache)&&!fclose(f));
    assert(paig_cache_admitted(&cache,2)&&!cache.raw_context_head&&!cache.raw_clock_handle&&!cache.raw_TLMM_handle);
    unsigned checks=0,max_events=0;
    const struct paig_io missing={0};reset(F_NONE,0);assert(!paig_identity_once(&missing,&cache,2,0,&result)&&!m.reads&&!m.writes);checks++;
    for(unsigned selected=0;selected<2;selected++){
        reset(F_NONE,selected);assert(run(selected)&&result.command_issued==1&&result.command_completed==1&&!result.uncertain&&
            result.stop_confirmed&&result.restored&&result.value==0x5a&&result.received==1&&result.sent==1&&m.releases==1&&!m.aborts);
        saved_restored();unsigned calls=m.reads+m.writes;assert(!run(selected)&&m.reads+m.writes==calls);
        struct paig_result other={0};const struct paig_io io={&m,acquire,current,read32,write32,delay,order,release};
        assert(!paig_identity_once(&io,&cache,2,1-selected,&other)&&!other.attempted&&m.reads+m.writes==calls);
        assert(!result.outstanding&&!paig_boot_ticket.outstanding&&result.access_issued==m.completion_orders&&result.access_completed==result.access_issued);checks++;
    }
    for(unsigned fault=F_NO_LEASE;fault<=F_WM_NOT_SENT;fault++){
        reset(fault,0);assert(!run(0)&&result.sticky&&!result.valid_identity&&result.events<=PAIG_EVENTS);
        if(fault==F_NO_LEASE||fault==F_EXPIRED)assert(!m.reads&&!m.writes);
        if(fault==F_BUSY||fault==F_OLD_IRQ||fault==F_PACKING)assert(!m.writes&&!m.commands&&m.releases==1);
        if(fault==F_OLD_IRQ)assert(m.irq==(1u<<10)&&!m.clear_or);
        if(fault==F_TIMEOUT)assert(result.error==PAIG_TIMEOUT&&result.abort_issued==1&&result.abort_completed==1&&
            result.stop_confirmed&&result.restored&&!result.uncertain&&m.commands==1&&m.aborts==1&&m.releases==1);
        if(fault==F_NACK)assert(result.error==PAIG_IRQ&&result.stop_confirmed&&!m.aborts&&result.restored&&m.releases==1);
        if(fault==F_UNKNOWN_IRQ||fault==F_OWNER_LOST||fault==F_CMD_UNKNOWN||fault==F_RESTORE||fault==F_READ_UNKNOWN)
            assert(result.uncertain&&!m.releases&&!result.valid_identity);
        if(fault==F_CMD_NOT_SENT)assert(result.command_issued&&result.command_not_issued&&!result.command_store_completed&&!m.aborts&&result.restored&&m.releases==1);
        if(fault==F_PARTIAL_CONFIG)assert(!result.command_issued&&result.restored&&m.releases==1);
        if(fault==F_CONFIG_UNKNOWN)assert(result.uncertain&&result.outstanding==1&&paig_boot_ticket.outstanding==1&&
            result.dirty==1&&!result.command_issued&&!m.releases&&!m.aborts&&m.registers[0x26c/4]==1);
        if(fault==F_CMD_UNKNOWN||fault==F_READ_UNKNOWN)assert(result.outstanding==1&&paig_boot_ticket.outstanding==1);
        if(fault==F_WM_NOT_SENT)assert(result.dirty&4u); /* Already-dirty WM must survive a later exact NOT_ISSUED. */
        if(result.restored)saved_restored();
        if(result.events>max_events)max_events=result.events;
        checks++;
    }
    reset(F_NONE,0);cache.hashes[1][0]^=1;assert(!run(0)&&result.error==PAIG_CACHE&&!m.acquires&&!m.reads&&!m.writes);cache.hashes[1][0]^=1;checks++;
    reset(F_NONE,0);assert(!run(2)&&!m.acquires&&!m.reads&&!m.writes);checks++;
    reset(F_SYNC_FAULT,0);
    if(!setjmp(synchronous_fault)){(void)run(0);assert(!"synthetic synchronous command fault must not return");}
    assert(result.outstanding==1&&paig_boot_ticket.outstanding==1&&result.command_issued==1&&!result.command_store_completed&&
        result.raw[result.events-1].delivery==PAIG_ACCESS_UNKNOWN&&!m.releases&&!m.aborts);
    struct paig_result other={0};const struct paig_io io={&m,acquire,current,read32,write32,delay,order,release};
    unsigned calls=m.reads+m.writes;assert(!paig_identity_once(&io,&cache,2,1,&other)&&!other.attempted&&m.reads+m.writes==calls);checks++;
    reset(F_CONFIG_SYNC_FAULT,0);
    if(!setjmp(synchronous_fault)){(void)run(0);assert(!"synthetic early config fault must not return");}
    assert(result.dirty==1&&result.outstanding==1&&paig_boot_ticket.outstanding==1&&!result.command_issued&&
        result.raw[result.events-1].delivery==PAIG_ACCESS_UNKNOWN&&!m.releases&&!m.aborts);checks++;
    reset(F_RELEASE_UNKNOWN,0);assert(!run(0));
    assert(result.command_completed&&result.restored&&result.uncertain&&result.sticky&&
        result.release_delivery==PAIG_ACCESS_UNKNOWN&&!result.lease_released&&
        result.outstanding==3&&paig_boot_ticket.outstanding==3&&m.releases==1);
    saved_restored();checks++;
    reset(F_RELEASE_SYNC_FAULT,0);
    if(!setjmp(synchronous_fault)){(void)run(0);assert(!"synthetic release fault must not return");}
    assert(result.command_completed&&result.restored&&result.release_delivery==PAIG_ACCESS_UNKNOWN&&
        !result.lease_released&&result.outstanding==3&&paig_boot_ticket.outstanding==3&&m.releases==1);
    struct paig_result after_release={0};calls=m.reads+m.writes;
    assert(!paig_identity_once(&io,&cache,2,1,&after_release)&&!after_release.attempted&&m.reads+m.writes==calls);checks++;
    printf("{\"checks\":%u,\"maximum_raw_events\":%u,\"physical_provider_implemented\":false,\"actual_I2C_MMIO_actions\":0,\"real_TAS_ID_observed\":false,\"PCM\":false}\n",checks,max_events);return 0;
}
