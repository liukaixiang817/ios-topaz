/* Real full startup and native transport, SOFTWARE cache/device views. Device
 * updates never become visible to CPU memory without the actual cache leaf. */
struct pmni_command;
static int transport_raw(const struct pmni_command*,unsigned*);
#define EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE 1
#define POLARIS_WIFI_CE_TRANSPORT_SOFTWARE_PEER 1
#define PMCE_TEST_RAW_HOOK transport_raw
#define PMCE_TEST_ENTRY unused_ce_suite
#include "polaris-wifi-ce-native-test.c"
#include "uefi-wifi-ce-transport.h"
static struct pmct_state*transport;
static uint8_t*device_memory;
static uint8_t owned[12][512];
static unsigned transport_fault,transport_scenarios,transport_reads,transport_writes,transport_caches,transport_copies,transport_orders;
static uint8_t*device_at(uint64_t at,unsigned bytes)
{CHECK(at>=CE_ALLOCATION&&bytes<=PWDM_BYTES-(at-CE_ALLOCATION));return device_memory+at-CE_ALLOCATION;}
static int pccl_actual(uint64_t at,unsigned bytes,unsigned operation,struct pccl_record*r)
{
    CHECK(transport&&transport->busy&&local_mask&&owner->held&&!(at&63)&&bytes&&!(bytes&63)&&bytes<=8192);
    transport_caches++;uint8_t*d=device_at(at,bytes),*cpu=ce_shadow+at-CE_ALLOCATION;
    if(operation==PWMK_CLEAN_INVALIDATE){
        for(unsigned pipe=0;pipe<12;pipe++){
            const struct pwdm_pipe*p=&transport->rings.layout.pipe[pipe];if(!p->destinations)continue;
            uint64_t first=CE_ALLOCATION+p->destination,last=first+16u*p->destinations;
            if(at>=last||at+bytes<=first)continue;
            CHECK(at>=first&&at+bytes<=last&&bytes==64);
            unsigned slot=(unsigned)((at-first)/16);for(unsigned n=0;n<4;n++)CHECK(!owned[pipe][slot+n]);
        }
        if(transport_fault==1)return 0;memcpy(d,cpu,bytes);
    }else{CHECK(operation==PWMK_INVALIDATE);memcpy(cpu,d,bytes);}
    *r=(struct pccl_record){.cache={.address=at,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,.operation=operation,
        .line_bytes=64,.lines_issued=bytes/64,.lines_returned=bytes/64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1},.bytes=bytes};return 1;
}
static int pmct_copy(uint64_t at,void*private,unsigned bytes,unsigned write,struct pmct_memory*r)
{
    CHECK(transport&&transport->busy&&local_mask&&owner->held&&r->address==at&&r->bytes==bytes&&r->write==write);transport_copies++;
    uint8_t*shared=ce_shadow+at-CE_ALLOCATION,*p=private;CHECK(at>=CE_ALLOCATION&&bytes<=PWDM_BYTES-(at-CE_ALLOCATION));
    for(unsigned n=0;n<bytes;n++){
        r->issued++;if(write)shared[n]=p[n];else p[n]=shared[n];r->returned++;
        if(transport_fault==2&&private==transport->receive&&n==7)return 0;
    }
#if defined(PMCT_TEST_COPY_DONE_HOOK)
    PMCT_TEST_COPY_DONE_HOOK(at,private,bytes,write);
#endif
    return 1;
}
static int transport_raw(const struct pmni_command*c,unsigned*out)
{
    if(!transport||!transport->busy||transport->io.kind!=3)return -1;
    CHECK(local_mask&&owner->held&&ce->complete&&ce->transport==(uintptr_t)transport);
    if(c->kind==PMNI_FULL_ORDER){transport_orders++;return transport_fault!=3;}
    if(c->kind==PMNI_READ){
        CHECK(c->address>=PWCE_BASE&&c->address<PWCE_WRAPPER);transport_reads++;
        *out=ce_regs[(c->address-PWCE_BASE)/4096][(c->address&4095)/4];return 1;
    }
    CHECK(c->kind==PMNI_WRITE&&pwcr_register(c->address,1,c->value));transport_writes++;
    if(c->address>=PWCR_SHADOW&&c->address<PWCR_SHADOW+48){
        unsigned pipe=(unsigned)((c->address-PWCR_SHADOW)/4);const struct pwdm_pipe*p=&transport->rings.layout.pipe[pipe];
        unsigned old=ce_regs[pipe][0x3c/4];CHECK(c->value==((old+1)&(p->sources-1)));
        uint8_t*desc=device_at(CE_ALLOCATION+p->source+16*old,16);unsigned bytes=(unsigned)pwcr_get(desc+8,2);
        uint64_t buffer=CE_ALLOCATION+p->source_buffers+(uint64_t)p->buffer_bytes*old;
        CHECK(pwcr_get(desc,8)==buffer);
#if defined(PMCT_TEST_TX_HOOK)
        PMCT_TEST_TX_HOOK(pipe,old,desc);
#else
        CHECK(bytes==31&&pwcr_get(desc+10,2)==0x120);
#endif
        CHECK(!memcmp(device_at(buffer,bytes),transport->send,bytes));
        ce_regs[pipe][0x3c/4]=c->value;put(device_at(CE_ALLOCATION+transport->rings.layout.rri+4*pipe,4),c->value,4);
    }else{
        unsigned pipe=(unsigned)((c->address-PWCE_BASE)/4096);const struct pwdm_pipe*p=&transport->rings.layout.pipe[pipe];
        unsigned old=ce_regs[pipe][0x40/4];CHECK(!(old&3)&&c->value==((old+4)&(p->destinations-1)));
        for(unsigned n=0;n<4;n++){
            unsigned slot=old+n;uint8_t*desc=device_at(CE_ALLOCATION+p->destination+16*slot,16);
            CHECK(!owned[pipe][slot]&&!pwcr_get(desc+8,2));
            CHECK(pwcr_get(desc,8)==CE_ALLOCATION+p->destination_buffers+(uint64_t)p->buffer_bytes*slot);owned[pipe][slot]=1;
        }
        ce_regs[pipe][0x40/4]=c->value;
#if defined(PMCT_TEST_POST_HOOK)
        PMCT_TEST_POST_HOOK(pipe);
#endif
    }return 1;
}
static void device_receive(unsigned pipe,unsigned sequence)
{
    const struct pwdm_pipe*p=&transport->rings.layout.pipe[pipe];unsigned slot=transport->rings.destination[pipe].read;
    CHECK(owned[pipe][slot]==1);uint8_t*desc=device_at(CE_ALLOCATION+p->destination+16*slot,16);
    uint8_t*payload=device_at(pwcr_get(desc,8),37);for(unsigned n=0;n<37;n++)payload[n]=(uint8_t)(sequence+n);
    put(desc+8,transport_fault==4?2049:37,2);owned[pipe][slot]=2;
}
static void transport_setup(unsigned kind)
{
    transport=0;ce_setup(0);int done=1;
    for(unsigned n=0;n<4000&&done==1;n++){done=pmce_step(ce);if(done==1&&ce->phase==2)advance_to(owner->last+192000);}CHECK(done==2&&pmce_current(ce));
    transport=(void*)(arena+0x7300000);CHECK(sizeof(*ce)<0x300000&&sizeof(*transport)<0x100000);memset(transport,0,sizeof(*transport));
    memcpy(device_memory,ce_shadow,PWDM_BYTES);memset(owned,0,sizeof(owned));
    transport_fault=0;transport_reads=transport_writes=transport_caches=transport_copies=transport_orders=0;transport_scenarios++;
    CHECK(pmct_begin(transport,ce)&&pmct_live(transport));transport_fault=kind;
    for(unsigned n=0;n<31;n++)transport->send[n]=(uint8_t)(0x80+n);
}
#ifndef PMCT_TEST_ENTRY
#define PMCT_TEST_ENTRY main
#endif
int PMCT_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);ce_shadow=aligned_alloc(4096,PWDM_BYTES);device_memory=aligned_alloc(4096,PWDM_BYTES);
    CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory&&ce_shadow&&device_memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned kind=0;kind<=5;kind++){
        transport_setup(kind);
        if(!kind){
            for(unsigned n=0;n<20;n++)CHECK(pmct_send(transport,0,31,0x12)==1&&pmct_reap(transport,0)==1&&!transport->rings.source[0].posted);
            unsigned groups=0;int result;while((result=pmct_refill(transport,2))==1)groups++;CHECK(!result&&groups==15);
            for(unsigned n=0;n<80;n++){
                unsigned slot=transport->rings.destination[2].read;device_receive(2,n);
                CHECK(pmct_receive(transport,2)==1&&transport->frame_ready&&transport->rx_bytes==37&&transport->rx_pipe==2);
                for(unsigned j=0;j<37;j++)CHECK(transport->receive[j]==(uint8_t)(n+j));owned[2][slot]=0;
                CHECK(pmct_receive(transport,2)==-1&&pmct_ack(transport));
                CHECK(pmct_refill(transport,2)==(n%4==3?1:0));CHECK(pmct_poll(transport)>=0);
            }
            CHECK(transport->sends==20&&transport->receives==80&&transport->posts==140&&pmct_live(transport));
            fprintf(stderr,"native CE transport: shadow TX/RRI completions, separate CPU/device views, RX80 wrap/recycle and RMTFS PASS\n");
        }else if(kind==1||kind==3){
            CHECK(pmct_send(transport,0,31,0x12)==-1&&transport->unknown&&transport->busy&&transport->rings.busy);
            CHECK(transport_writes==(kind==3?1u:0u));
        }else if(kind==2||kind==4){
            CHECK(pmct_refill(transport,2)==1);device_receive(2,0);
            CHECK(pmct_receive(transport,2)==-1&&transport->unknown&&!transport->frame_ready&&transport->rings.destination[2].posted==4);
        }else{
            owner_delay+=PMSC_TOTAL+1;unsigned before=transport_writes;
            CHECK(pmct_send(transport,0,31,0x12)==-1&&transport_writes==before&&owner->held&&!pmct_live(transport));
        }
        if(kind){unsigned before=transport_writes+transport_caches+transport_copies;CHECK(pmct_refill(transport,2)==-1&&before==transport_writes+transport_caches+transport_copies);}
    }
    wlan_unprotect();free(msa_shadow);free(device_memory);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native CE transport checks, %u scenarios; SOFTWARE cache/DMA/device/UEFI, no real radio\n",checks+nv_checks,transport_scenarios);return 0;
}
