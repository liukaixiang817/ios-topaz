/* Actual current producers and actual native resource caller. Device/SMC
 * leaves remain software; original firmware/DB are inert fixture DATA. */
#ifndef PMMN_TEST_ARENA_BYTES
#define PMMN_TEST_ARENA_BYTES 0x4000000
#endif
#ifndef PMMN_TEST_IMAGE_BYTES
#define PMMN_TEST_IMAGE_BYTES 0x3fc0000
#endif
#define PMDC_TEST_ENTRY unused_cmddb_suite
#include "polaris-mss-cmddb-test.c"
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define EFI_XNU_MSS_RAIL_IO_AVAILABLE 1
#define EFI_XNU_MSS_RSC_STATE_AVAILABLE 1
#define EFI_XNU_MSS_POWER_NATIVE_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "uefi-mss-power-native.h"
uint64_t pmpn_test_retire(struct pmck_lifecycle*,uint64_t,uint64_t,unsigned*);
static struct pmrs_state*device;
static struct pmpn_state*power;
static struct pmpn_request*requests;
static struct pmsp_lifecycle*supplies;
static struct pmpx_lifecycle*proxy;
static struct pmck_lifecycle*stopped_clocks;
static uint32_t hardware[0x3000/4],original_hardware[0x3000/4],votes[20],original_votes[20],prng;
static unsigned native_reads,native_writes,native_ats,edges,acks,pending,peer_fault,peer_trigger,peer_request,retirement_checks;
static int pmni_arch_read(struct pmni_arch*a)
{
    struct pgcd_arch q;if(!owner_arch(0,&q))return 0;const struct pwfc_arch*c=&q.cpu;
    *a=(struct pmni_arch){c->el,c->mpidr,c->ttbr0,c->ttbr1,c->tcr,c->sctlr,c->mair,c->daif,c->sre,c->group1,q.cpacr,c->frequency,c->ticks};
    if(peer_fault==5&&power&&power->pending==peer_request&&requests[power->pending-1].request.io.events==peer_trigger)a->ttbr0^=4096;
#ifdef PMPN_TEST_ARCH_HOOK
    PMPN_TEST_ARCH_HOOK(a);
#endif
    return 1;
}
static int selected_fault(void)
{return power&&power->pending==peer_request&&power->pending&&requests[power->pending-1].request.io.events==peer_trigger;}
static int pmni_translate(struct pmni_translation*t)
{
    native_ats++;t->saved=t->restored=0x12345;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(selected_fault()){
        if(peer_fault==2)return 0;
        if(peer_fault==3)t->write_par^=4096;
        if(peer_fault==4)t->restored++;
    }
#ifdef PMPN_TEST_AT_HOOK
    return PMPN_TEST_AT_HOOK(t);
#else
    return 1;
#endif
}
static void resource_complete(void)
{
    static const uint32_t addresses[]={0x30000,0x30010,0x30060,0x40f00,0x40f04,0x40f08,0x40f0c,
        0x41300,0x41304,0x41308,0x4130c,0x40c00,0x40c04,0x40c08,0x40c0c,0x42000,0x42004,0x42008,0x4200c,0x30080};
    unsigned n=0;while(n<20&&addresses[n]!=hardware[0x34/4])n++;CHECK(n<20);
    CHECK(hardware[0x1c/4]==1&&(hardware[0x30/4]==0x108||hardware[0x30/4]==0x10108));
    if(hardware[0x30/4]==0x10108)votes[n]=hardware[0x38/4];
    hardware[0x40/4]=votes[n];hardware[0x3c/4]=0x10101;hardware[0x18/4]=1;hardware[1]|=1;pending=0;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*v)
{
#ifdef PMPN_TEST_RAW_HOOK
    if(c->address<UINT64_C(0x179e0000)||c->address>=PWRSC_BASE+sizeof(hardware))return PMPN_TEST_RAW_HOOK(c,v);
#endif
    if(c->kind==PMNI_READ)native_reads++;else native_writes++;
    if(selected_fault()){
        if(peer_fault==1)return 0;
        if(peer_fault==6)owner_delay+=PMSC_TOTAL+1;
        if(peer_fault==7)put(image_heap+0x4030,0,8);
    }
    if(c->address==0x179e000c){CHECK(c->kind==PMNI_READ);*v=(8u<<12)|(16u<<27);return 1;}
    CHECK(c->address>=PWRSC_BASE&&c->address<PWRSC_BASE+sizeof(hardware)&&!(c->address&3));
    unsigned off=(unsigned)(c->address-PWRSC_BASE);
    if(c->kind==PMNI_READ){if(off==4&&pending)resource_complete();*v=hardware[off/4];return 1;}
    CHECK(c->kind==PMNI_WRITE&&power&&power->pending&&owner->effects&PMSC_POWER);
    const struct pmrv_request*q=&requests[power->pending-1].request;
    CHECK(q->io.outstanding==q->io.events&&q->io.history[q->io.events-1].unknown);
    if(off==8){CHECK(c->value==1&&q->io.completed==1&&hardware[1]==1);acks++;hardware[1]=0;return 1;}
    CHECK(off==0x10||off==0x14||off==0x1c||off==0x30||off==0x34||off==0x38);
    if(off==0x38)CHECK(q->write==1);
    uint32_t old=hardware[off/4];hardware[off/4]=c->value;
    if(off==0x14&&(c->value&0x1000000)){
        CHECK(!(old&0x1000000)&&!pending);edges++;pending=1;hardware[0x3c/4]=0;hardware[0x18/4]=0;
    }return 1;
}
static uint64_t power_now(void){CHECK(pmsc_live(owner));return owner->last;}
static void advance_to(uint64_t now)
{uint64_t old=power_now();if(now>old)owner_delay+=now-old;CHECK(power_now()>=now);}
static void power_setup(void)
{
    power=0;peer_fault=peer_trigger=peer_request=0;native_reads=native_writes=native_ats=edges=acks=pending=0;prng=0;
    memset(hardware,0,sizeof(hardware));hardware[0]=15;
    for(unsigned n=0;n<8;n++){
        unsigned off=n*PWRSC_STRIDE;hardware[(off+0x10)/4]=0x80;
        hardware[(off+0x14)/4]=n?0x10000:0x1010000;hardware[(off+0x18)/4]=1;hardware[(off+0x1c)/4]=!n;
        for(unsigned j=0;j<3;j++)for(unsigned k=0;k<5;k++)hardware[(off+0x30+20*j+4*k)/4]=0x100+n*20+j*5+k;
    }
    memcpy(original_hardware,hardware,sizeof(hardware));votes[0]=2;votes[1]=6;votes[2]=0;votes[19]=1;
    const uint32_t mv[]={0,1800,0,3200};
    for(unsigned n=0;n<4;n++){unsigned k=3+4*n;votes[k]=mv[n];votes[k+1]=n&1;votes[k+2]=5;votes[k+3]=17+n;}
    memcpy(original_votes,votes,sizeof(votes));cmddb_setup();CHECK(cmddb_run()&&rpmh_run());
    device=(void*)(arena+0x600000);memset(device,0,sizeof(*device));CHECK(0x600000+sizeof(*device)<0x700000);
    CHECK(pmrs_capture(device,state,resource_map));
    supplies=(void*)(arena+0x700000);proxy=(void*)(arena+0x710000);stopped_clocks=(void*)(arena+0x720000);
    CHECK(0x700000+sizeof(*supplies)<0x710000&&0x710000+sizeof(*proxy)<0x720000);
    memset(supplies,0,sizeof(*supplies));memset(proxy,0,sizeof(*proxy));memset(stopped_clocks,0,sizeof(*stopped_clocks));
    power=(void*)(arena+0x800000);requests=(void*)(arena+0x1000000);
    CHECK(0x800000+sizeof(*power)<0x1000000&&0x1000000+sizeof(*requests)*PMPN_REQUESTS<PMMN_TEST_IMAGE_BYTES);
    memset(power,0,sizeof(*power));memset(requests,0,sizeof(*requests)*PMPN_REQUESTS);
    CHECK(pmpn_begin(power,requests,device,database_state,state,resource_map));
#ifndef PMPN_TEST_DEFER_SUPPLY
    uint32_t minimum[3];for(unsigned n=0;n<3;n++)minimum[n]=database_state->pass[1].resource[n].minimum;
    CHECK(pmsp_begin(supplies,owner->opening,minimum,power_now(),19200000)==PMSP_WAIT);
#endif
}
static int supply_drive(unsigned limit)
{
    for(unsigned n=0;n<limit;n++){
        struct pmsp_command c;int result=pmsp_next(supplies,power_now(),&c);
        if(result!=PMSP_REQUEST)return result;
        if(!pmpn_supply(power,supplies,&c))return -1;
    }return 0;
}
static int proxy_drive(void)
{
    for(unsigned n=0;n<40;n++){
        struct pmpx_command c;int result=pmpx_next(proxy,power_now(),&c);
        if(result==PMPX_HELD||result==PMPX_RESTORED)return result;
        if(result==PMPX_WAIT){advance_to(proxy->not_before);continue;}
        CHECK(result==PMPX_IO);
        if(c.kind==PMPX_RAIL){if(!pmpn_proxy(power,proxy,&c))return -1;continue;}
        /* PRNG is an explicit software producer here; its native owned-IO
         * parent is a separate integration, not claimed by this test. */
        uint32_t value=0;
        if(c.kind==PMPX_READ)value=c.address==0x134004?2:prng;
        else if(c.kind==PMPX_WRITE){CHECK(c.address==0x152004);prng=c.value;}
        else CHECK(c.kind==PMPX_ORDER);
        CHECK(pmpx_complete(proxy,&c,power_now(),1,value,0)>=0);
    }CHECK(0);return -1;
}
/* Reconstruct ALL fields of successful full native/namespace records from
 * their compact variable data and checked constants; compare original hash. */
static void verify_delivery(const struct pmpn_request*r,unsigned n)
{
    const struct pmpn_delivery*d=&r->delivery[n];const struct pwrsc_event*e=&r->request.io.history[n];
    const struct pmli_read*node=&resource_map->pass[1].node[d->namespace_index];
    struct pmni_arch opening=power->architecture;opening.ticks=d->native_ticks[0];struct pmni_result native={0};
    native.command=(struct pmni_command){e->address,e->operation==2?PMNI_WRITE:PMNI_READ,e->operation==2?e->value:0};
    native.before=native.translated=native.after=power->architecture;
    native.before.ticks=d->native_ticks[1];native.translated.ticks=d->native_ticks[2];native.after.ticks=d->native_ticks[3];
    native.AT.page=e->address&~UINT64_C(4095);native.AT.saved=native.AT.restored=d->native_saved;
    native.AT.read_par=native.AT.write_par=d->native_par;
    native.AT.read_issued=native.AT.read_returned=native.AT.write_issued=native.AT.write_returned=native.AT.restore_issued=native.AT.restore_returned=1;
    native.attempted=native.issued=native.returned=native.complete=1;native.value=d->native_value;
    struct pmrg_target target[2]={0};
    for(unsigned side=0;side<2;side++){
        struct pmrg_target*t=&target[side];t->page=native.AT.page;t->before=d->namespace_ticks[side][0];t->after=d->namespace_ticks[side][1];
        uint64_t base=pwfi_le(node->raw+24,8),end=pwfi_le(node->raw+32,8);
        t->descriptor=(struct pgcd_descriptor){base,end-base+1,pwfi_le(node->raw+40,8),pwfi_le(node->raw+48,8),3,0,pwfi_le(node->raw+64,8),pwfi_le(node->raw+72,8)};
        t->index=d->namespace_index;t->attempted=t->complete=1;
        t->node.address=node->address;t->node.bytes=80;t->node.issued=t->node.returned=1;memcpy(t->node.raw,node->raw,80);
        for(uint64_t page=node->address&~UINT64_C(4095);page<node->address+80;page+=4096){
            unsigned j=t->node.pages++;struct pwmc_translation*a=&t->node.AT[j];a->page=page;a->saved=a->restored=d->namespace_saved[side][j];
            a->read_par=a->write_par=UINT64_C(0xff00000000000b80)|page;a->read_issued=a->read_returned=a->write_issued=a->write_returned=1;
        }
    }
    struct pwfi_sha256 hash;pwfi_init(&hash);const void*parts[]={&opening,&native,target};const size_t sizes[]={sizeof(opening),sizeof(native),sizeof(target)};
    for(unsigned part=0;part<3;part++)for(size_t j=0;j<sizes[part];j++)pwfi_byte(&hash,((const uint8_t*)parts[part])[j]);
    uint8_t digest[32];pwfi_final(&hash,digest);CHECK(d->complete&&pgcd_equal(digest,d->leaf_digest,32));
}
#ifndef PMPN_TEST_ENTRY
#define PMPN_TEST_ENTRY main
#endif
int PMPN_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==5);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));
    original=malloc(PGCI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cd_original=malloc(PWCDI_IMAGE_BYTES);
    database=malloc(PMDC_BYTES);db_original=malloc(PMDC_BYTES);CHECK(original&&rp_original&&cd_original&&database&&db_original);
    uint8_t*dst[]={original,rp_original,cd_original,db_original};const size_t bytes[]={PGCI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES,PMDC_BYTES};
    for(unsigned n=0;n<4;n++){FILE*f=fopen(argv[n+1],"rb");CHECK(f&&fread(dst[n],1,bytes[n],f)==bytes[n]&&!fclose(f));}
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));db_map_attr=8;
    power_setup();uint64_t epoch=owner->opening;CHECK(supply_drive(110)==PMSP_HELD&&power->supply_calls==41);
    CHECK(pmpn_proxy_begin(power,proxy)&&proxy_drive()==PMPX_HELD&&power->proxy_calls==3);
    CHECK(votes[19]==3&&(prng&0x2000)&&!pmsc_close_unused(owner));advance_to(power_now()+3*19200000);
    uint64_t now=pmpn_test_retire(stopped_clocks,epoch,power_now(),&retirement_checks);advance_to(now);
    CHECK(pmpn_proxy_release(power,proxy,stopped_clocks)&&proxy_drive()==PMPX_RESTORED&&!prng);
    CHECK(pmsp_release(supplies,stopped_clocks,power_now())==PMSP_WAIT&&supply_drive(110)==PMSP_RESTORED);
    CHECK(pmpn_finish(power)&&power->restored&&power->requests==107&&edges==107&&acks==107&&owner->opening==epoch&&owner->held);
    CHECK(!memcmp(votes,original_votes,sizeof(votes))&&!pmsc_close_unused(owner));
    for(unsigned n=0;n<107;n++)for(unsigned j=0;j<requests[n].deliveries;j++)verify_delivery(&requests[n],j);
    unsigned deliveries=requests[0].deliveries;CHECK(deliveries>50&&deliveries<PWRSC_HISTORY);
    fprintf(stderr,"complete107-request cycle and full observation reconstruction PASS; checking failures\n");
    for(unsigned at=1;at<=deliveries;at++){
        power_setup();peer_fault=1;peer_request=1;peer_trigger=at;
        CHECK(supply_drive(1)==-1&&power->unknown&&!power->restored&&power->pending==1&&requests[0].unknown&&!requests[0].complete);
        unsigned before=native_reads+native_writes;CHECK(supply_drive(1)==-1&&native_reads+native_writes==before);
    }
    for(unsigned fault=2;fault<=7;fault++)for(unsigned edge=0;edge<3;edge++){
        power_setup();peer_fault=fault;peer_request=1;peer_trigger=edge==0?1:edge==1?deliveries/2:deliveries;
        CHECK(supply_drive(1)==-1&&power->unknown&&!power->restored&&requests[0].unknown);
    }
    power_setup();database[PMDC_BYTES-1]^=1;CHECK(supply_drive(1)==-1&&power->unknown&&!native_writes);
    power_setup();rp_image[0x1000]^=1;CHECK(supply_drive(1)==-1&&power->unknown&&!native_writes);
    power_setup();supplies->minimum[0]^=1;CHECK(supply_drive(1)==-1&&!native_writes);
    CHECK(!munmap(heap_mapping,0x100000+2*host_page));CHECK(!munmap(shadow_mapping,0x104000+2*host_page));
    free(original);free(rp_original);free(cd_original);free(database);free(db_original);free(arena);
    printf("PASS %u native persistent power checks, %u scenarios, %u software retirement checks; no hardware/firmware/USB\n",checks,scenarios,retirement_checks);return 0;
}
