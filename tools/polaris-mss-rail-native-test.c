/* Real native adapter control flow against guarded CPU/AT and RSC peers. */
#define main legacy_request_test
#include "polaris-mss-rail-request-test.c"
#undef main
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define EFI_XNU_MSS_RAIL_IO_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-mss-mmio-native.h"
static struct pmni_result native_record[PWRSC_HISTORY];
static struct pmni_arch opening;
static unsigned native_fault,native_at,native_raw,native_arch,native_target;
static int pmni_arch_read(struct pmni_arch*a)
{
    *a=opening;a->ticks=++tick;native_arch++;
    if(native_target==q.io.events){
        if(native_fault==1)a->daif=0;
        if(native_fault==2)a->group1=1;
        if(native_fault==3)a->mpidr|=1;
        if(native_fault==4)a->mair^=1;
    }
    return 1;
}
static int pmni_translate(struct pmni_translation*t)
{
    native_at++;t->saved=t->restored=0x12345;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(native_target==q.io.events){
        if(native_fault==5)t->write_par^=4096;
        if(native_fault==6)t->restored++;
        if(native_fault==7)t->read_par=t->write_par|=1;
    }
    return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*v)
{
    native_raw++;
    if(native_target==q.io.events&&native_fault==8)return 0;
    return c->kind==PMNI_WRITE?write_peer(0,c->address,c->value):read_peer(0,c->address,v);
}
static int native_access(uint64_t at,uint32_t*v,unsigned write)
{
    CHECK(q.io.events&&q.io.events<=PWRSC_HISTORY);
    struct pwrsc_event e=q.io.history[q.io.events-1];struct pmni_result*r=&native_record[q.io.events-1];
    opening=(struct pmni_arch){.el=4,.mpidr=0x81000000,.ttbr0=0x10004000,.tcr=0x80803520,
        .sctlr=5,.mair=0xffbb4400,.daif=0xc0,.sre=7,.cpacr=0x300000,.frequency=19200000,.ticks=tick};
    CHECK(e.address==at&&e.operation==(write?2u:1u));
    if(native_target==q.io.events){
        if(native_fault==9)e.address^=4;
        if(native_fault==10)e.phase++;
        if(native_fault==11)e.value++;
        if(native_fault==12)e.issued=0;
    }
    int result=pmni_rail(&q,&e,&opening,r);if(!result)return 0;
    CHECK(r->complete&&r->issued&&r->returned&&!r->unknown&&!r->error);
    if(!write)*v=r->value;
    CHECK(r->AT.page==(at&~UINT64_C(4095))&&r->AT.read_par==r->AT.write_par&&r->AT.saved==r->AT.restored);
    return 1;
}
static int native_read(void*unused,uint64_t at,uint32_t*v){(void)unused;return native_access(at,v,0);}
static int native_write(void*unused,uint64_t at,uint32_t v){(void)unused;return native_access(at,&v,1);}
static const struct pwrsc_io native_io={0,native_read,native_write,clock_peer,order_peer};
static void native_reset(unsigned s,unsigned high,unsigned fault,unsigned target)
{
    reset(s,high,0,0);memset(native_record,0,sizeof(native_record));
    native_fault=fault;native_target=target;native_at=native_raw=native_arch=0;
}
static int native_run(unsigned resource,unsigned write,uint32_t value)
{
    if(!pmrv_begin(&native_io,&q,91,1u<<slot,slot,resource,write,value))return -1;
    int result=0;while(!result)result=pmrv_step(&native_io,&q);return result;
}
int main(void)
{
    unsigned event_count[2];
    for(unsigned s=0;s<8;s++)for(unsigned high=0;high<3;high++)for(unsigned write=0;write<2;write++){
        native_reset(s,high,0,0);CHECK(native_run(3,write,write?800:0)==1);CHECK(pmrv_retired(&q));
        CHECK(native_at==q.io.events&&native_raw==q.io.events&&native_arch==3*q.io.events);
        CHECK(votes[3]==(write?800:before_votes[3]));CHECK(edges==1&&acks==1);event_count[write]=q.io.events;
    }
    for(unsigned write=0;write<2;write++)for(unsigned event=1;event<=event_count[write];event++)for(unsigned fault=1;fault<=12;fault++){
        native_reset(2,0,fault,event);CHECK(native_run(3,write,write?800:0)==-1);CHECK(!q.valid);
        unsigned count=native_raw;CHECK(pmrv_step(&native_io,&q)==-1);CHECK(native_raw==count);
    }
    /* Leaf whitelist cannot program IRQ enable/type, another command, or a
     * broad peripheral address, even with the new flag enabled. */
    const uint64_t denied[]={PWRSC_BASE,PWRSC_BASE+4,PWRSC_BASE+12,PWRSC_BASE+0x18,
        PWRSC_BASE+0x3c,PWRSC_BASE+0x40,PWRSC_BASE+0x44,PWRSC_BASE+0x48,0x12340000};
    for(unsigned n=0;n<sizeof(denied)/sizeof(denied[0]);n++){
        struct pmni_command c={denied[n],PMNI_WRITE,1};CHECK(!pmni_allowed(&c));
    }
    printf("MSS native retained-request adapter: %u scenarios / %u checks PASS; software leaves only\n",cases,checks);return 0;
}
