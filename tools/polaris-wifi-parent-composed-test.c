/* Actual pwns_begin/step and all native child producers. Only firmware,
 * hardware, CPU, cache and UEFI leaves use the existing software peers.
 * A passing model is not physical admission or DMA retirement evidence. */
#include <sys/mman.h>
#include <stdint.h>
#include <assert.h>
/* macOS protects16KiB host pages; embedded native descriptors are4KiB.
 * Track descriptor ownership here rather than protecting neighbouring native
 * records. Firmware backing still has real mprotect; the dedicated producer
 * suites test descriptor protection using separately aligned allocations. */
static uintptr_t descriptor_begin,descriptor_end,descriptor_address[16];
static unsigned descriptor_protections,descriptor_restores;
static int parent_mprotect(void *p,size_t n,int protection)
{
    uintptr_t at=(uintptr_t)p;
    if(at>=descriptor_begin&&at<descriptor_end){
        assert(!(at&4095)&&n>=4096&&n<=16384&&at+4096<=descriptor_end);
        unsigned i=0;while(i<16&&descriptor_address[i]&&descriptor_address[i]!=at)i++;
        assert(i<16);
        if(protection==PROT_NONE){assert(!descriptor_address[i]);descriptor_address[i]=at;descriptor_protections++;}
        else{assert(protection==(PROT_READ|PROT_WRITE)&&descriptor_address[i]==at);descriptor_address[i]=0;descriptor_restores++;}
        return 0;
    }
    return mprotect(p,n,protection);
}
#define mprotect parent_mprotect
static unsigned parent_hold_hello;
#define PMSG_TEST_HOLD_HELLO parent_hold_hello
#define PWNS_TEST_PREPARE_ONLY 1
#define EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE 1
#define POLARIS_WIFI_NETWORK_NONCE_TEST 1
#define PMWN_TEST_ENTRY unused_network_suite
#include "polaris-wifi-network-native-test.c"
#include "uefi-wifi-startup-parent.h"
static struct pwns_parent *parent;
static uint8_t *parent_nonces,*parent_nonce_hash;
static void parent_prepare(void)
{
    /* Incoming allocation/staging/MBA producers are real; stop before opening
     * the CPU owner so pwns_begin opens its own embedded owner exactly once. */
    resource_setup();
    parent=(void*)(arena+0x2000000);
    CHECK(0x2000000+sizeof(*parent)<0x7000000);
    memset(parent,0,sizeof(*parent));descriptor_begin=(uintptr_t)parent;descriptor_end=descriptor_begin+sizeof(*parent);
    owner=&parent->owner;ledger=&parent->images;resource_map=&parent->map;
    state=&parent->rpmh;database_state=&parent->cmddb;device=&parent->rsc;
    power=&parent->power;requests=parent->power_records;supplies=&parent->supply;proxy=&parent->proxy;
    clock_owner=&parent->clocks;clock_records=parent->clock_records;active_clocks=&parent->active_clocks;
    aop_owner=&parent->aop;aop_records=parent->aop_records;
    boot_owner=&parent->boot;boot_records=parent->boot_records;
    auth_owner=&parent->auth;auth_records=parent->auth_records;auth_copy=&parent->copy;
    auth_segments=(void*)(arena+0x1e00000);memcpy(auth_segments,pmsf_segments,sizeof(pmsf_segments));
    rmtfs=&parent->rmtfs;sm=&parent->smem;channel_lock=&parent->lock;channel_allocation=&parent->allocation;
    channel=&parent->channel;negotiation=&parent->smp;glink=&parent->glink;service=&parent->service;wlan=&parent->wlan;
    smmu_owner=&parent->smmu;smmu_records=parent->smmu_records;ce=&parent->ce;transport=&parent->transport;
    htc=&parent->htc;wmi=&parent->wmi;htt=&parent->htt;data=&parent->data;
    parent_nonces=arena+0x1e10000;parent_nonce_hash=arena+0x1e11000;
    memcpy(database,db_original,PMDC_BYTES);
    memset(hardware,0,sizeof(hardware));hardware[0]=15;
    for(unsigned n=0;n<8;n++){
        unsigned off=n*PWRSC_STRIDE;hardware[(off+0x10)/4]=0x80;
        hardware[(off+0x14)/4]=n?0x10000:0x1010000;hardware[(off+0x18)/4]=1;hardware[(off+0x1c)/4]=!n;
        for(unsigned j=0;j<3;j++)for(unsigned k=0;k<5;k++)hardware[(off+0x30+20*j+4*k)/4]=0x100+n*20+j*5+k;
    }
    memcpy(original_hardware,hardware,sizeof(hardware));votes[0]=2;votes[1]=6;votes[2]=0;votes[19]=1;
    const uint32_t mv[]={0,1800,0,3200};
    for(unsigned n=0;n<4;n++){unsigned k=3+4*n;votes[k]=mv[n];votes[k+1]=n&1;votes[k+2]=5;votes[k+3]=17+n;}
    memcpy(original_votes,votes,sizeof(votes));
    memset(clock_regs,0,sizeof(clock_regs));clock_regs[2]=0x10000000;memcpy(clock_original,clock_regs,sizeof(clock_regs));
    memset(aop_memory,0,0x100000);

    const unsigned state[]={3,4,5,6,9,10,11,12};put(aop_memory,0x4d41494c,4);put(aop_memory+4,1,4);
    for(unsigned n=0;n<8;n++)put(aop_memory+4*state[n],0xffff,4);
    put(aop_memory+28,0x100,4);put(aop_memory+32,0x1000,4);put(aop_memory+52,0x100,4);put(aop_memory+56,0x2000,4);
    for(unsigned n=0;n<96;n++)aop_memory[0x2004+n]=(uint8_t)(n*7+19);
    memcpy(aop_original,aop_memory,0x100000);
    boot_status=2;

    boot_debug=0xabcd1234;boot_sleep=0x80000020;boot_pdc=0xa5000001;boot_alt=boot_restart=boot_image=boot_core=boot_command=0;
    sleep_reads=fsm_reads=pbl_reads=mba_reads=0;
    metadata_owner=modem_owner=3;
    memset(rmtfs_shadow,0xa5,0x202000);memset(msa_shadow,0xa5,0x200000);
    memset(ce_shadow,0xa5,PWDM_BYTES);memset(device_memory,0xa5,PWDM_BYTES);
    memset(htt_cpu,0xa5,PHTM_BYTES);memset(htt_device,0xa5,PHTM_BYTES);
    for(unsigned n=0;n<12;n++)ce_regs[n][0x18/4]=0x40e0000,ce_regs[n][0x2c/4]=0x8000001f,ce_regs[n][0x34/4]=0x800003e0;
    memset(sm_shadow,0,PMSQ_BYTES);put(sm_shadow+92,0xc0000,4);put(sm_shadow+192,1,4);
    uint8_t*t=sm_shadow+PMSQ_BYTES-4096;put(t,0x434f5424,4);put(t+4,1,4);put(t+8,2,4);
    channel_partition(0,0x1000,0x88000,0xfffefffe);channel_partition(1,0xb9000,0x7c000,0x10000);
    /* The remote owns its RX FIFO item before host GLINK startup. */
    unsigned header=0xb9000+pms_u32(sm_shadow+0xb900c);rx_offset=header+16;
    put(sm_shadow+0xb900c,rx_offset+16384-0xb9000,4);
    put(sm_shadow+header,0xa5a5|(480u<<16),4);put(sm_shadow+header+4,16384,4);
}
static void parent_wait(void)
{
    uint64_t at=owner->last;
    switch(parent->phase){
    case PWNS_AOP:if(aop_owner->phase)at=aop_owner->notify[aop_owner->phase-1].not_before;break;
    case PWNS_PROXY:at=proxy->not_before;break;
    case PWNS_CLOCK:at=active_clocks->not_before;break;
    case PWNS_BOOT:at=boot_owner->mba.phase==2?boot_owner->mba.reset.not_before:boot_owner->mba.next_poll;break;
    case PWNS_AUTH:if(auth_owner->phase==PMSN_MD_IO)at=auth_owner->metadata.next_poll;else if(auth_owner->phase==PMSN_AUTH)at=auth_owner->modem.next_poll;break;
    case PWNS_SMP:at=negotiation->next_poll;break;
    case PWNS_QRTR:at=glink->next_poll;break;
    case PWNS_WLAN:if(wlan->pages==512)at=wlan->next_poll;break;
    case PWNS_CE:if(ce->phase==2)at+=192000;break;
    case PWNS_WMI:case PWNS_HTT:at+=19200;break;
    default:break;
    }
    if(at>owner->last)advance_to(at);
}
int main(int argc,char**argv)
{
    CHECK(argc==9||argc==10);unsigned mode=argc==10?(unsigned)strtoul(argv[9],0,10):0;CHECK(mode<=2);
    parent_hold_hello=mode!=0;station_test_open(8,argv);parent_prepare();
    FILE*f=fopen(argv[8],"rb");CHECK(f&&fread(parent_nonces,1,PWNP_BYTES,f)==PWNP_BYTES&&fread(parent_nonce_hash,1,32,f)==32&&fgetc(f)==EOF&&!fclose(f));
    fprintf(stderr,"parent bytes=%zu auth page=%lx rmtfs page=%lx wlan page=%lx host_page=%zu\n",sizeof(*parent),(unsigned long)(uintptr_t)&auth_owner->assignment[0].page,(unsigned long)(uintptr_t)&rmtfs->assignment.page,(unsigned long)(uintptr_t)&wlan->assignment[0].page,host_page);
    uint8_t *memory_hash=arena+0x1e12000;memcpy(memory_hash,allocation_digest,32);
    int opened=pwns_begin(parent,held,mss,memory_hash,share,native_nv,ce_memory,htt_memory,auth_segments,parent_nonces,parent_nonce_hash);
    fprintf(stderr,"begin=%d parent_error=%u owner_error=%u attempted=%u\n",opened,parent->error,owner->error,owner->attempted);
    if(!opened)return 1;
    unsigned old=0;int status=1;unsigned serviced=0,qrtr_turns=0;
    for(unsigned turn=0;turn<100000&&status==1;turn++){
        if(parent->phase!=old){fprintf(stderr,"phase %u ticks %llu\n",parent->phase,(unsigned long long)(owner->last-owner->opening));old=parent->phase;}
        /* Hardware cache publication at CE initialization is represented by
         * its software device view. No producer completion is injected. */
        if(parent->phase==PWNS_TRANSPORT)memcpy(device_memory,ce_shadow,PWDM_BYTES);
        if(parent->phase==PWNS_WMI&&htc->client.phase==8&&!serviced){wmi_service();serviced=1;}
        if(parent->phase==PWNS_QRTR&&++qrtr_turns==5&&mode){
            if(mode==1){uint8_t hello[20]={2};rx_qrtr(2,0xfffffffe,hello,20);}
            else advance_to(glink->started+PMSY_TOTAL+1);
        }
        status=pwns_step(parent);if(status==1)parent_wait();
    }
    fprintf(stderr,"result=%d phase=%u error=%u owner=%u power=%u boot=%u auth=%u ce=%u wmi=%u htt=%u\n",status,parent->phase,parent->error,owner->error,power->error,boot_owner->error,auth_owner->error,ce->error,wmi->error,htt->error);
    fprintf(stderr,"wlan error=%u client_error=%u phase=%u pages=%u assigned=%u requests=%u service_error=%u glink_error=%u channel_error=%u ticks=%llu\n",wlan->error,wlan->client.error,wlan->client.phase,wlan->pages,wlan->assigned,wlan_requests,service->error,glink->error,channel->error,(unsigned long long)(owner->last-owner->opening));
    if(mode==2){
        CHECK(status==-1&&parent->phase==PWNS_QRTR&&parent->unknown&&glink->error==9&&owner->held&&!service->ready&&!wlan->ready&&!ce->attempted);
        uint64_t turns=parent->turns;CHECK(pwns_step(parent)==-1&&parent->turns==turns);
        printf("PASS %u complete-parent QRTR timeout checks; no service/radio admission\n",checks+nv_checks);return 0;
    }
    if(status!=2)return 1;
    CHECK(parent->phase==PWNS_READY&&pmhd_live(data)&&pmnp_live(&parent->nonce));
    CHECK(descriptor_protections==descriptor_restores&&descriptor_protections==8);
    printf("PASS %u full native startup parent checks; SOFTWARE hardware/firmware leaves, no physical claim\n",checks+nv_checks);return 0;
}
