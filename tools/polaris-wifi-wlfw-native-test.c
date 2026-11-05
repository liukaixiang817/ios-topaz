/* Actual NV/RMTFS/MSS and native WLFW/MSA producer composition.
 * Only UEFI/hardware leaves/modem are SOFTWARE. No phone or real VMID change. */
static int wlan_peer(const unsigned char*,unsigned);
#define PMRF_TEST_QRTR_HOOK wlan_peer
#define PMRF_TEST_ENTRY unused_rmtfs_service_suite
#include "polaris-mss-rmtfs-service-test.c"
#define EFI_XNU_WIFI_WLFW_NATIVE_AVAILABLE 1
#define POLARIS_WIFI_WLFW_SOFTWARE_PEER 1
#include "uefi-wifi-wlfw-native.h"
static struct pmwa_state*wlan;
static uint8_t*msa_shadow;
static unsigned wlan_fault,wlan_zeroes,wlan_requests,wlan_ready_requests,wlan_rounds[2],wlan_descriptor_mask,wlan_memory_mask,wlan_scenarios;
static int wlan_peer(const uint8_t*p,unsigned size)
{
#if defined(PMWA_TEST_QRTR_HOOK)
    if(PMWA_TEST_QRTR_HOOK(p,size))return 1;
#endif
    if(pms_u32(p+4)!=1||pms_u32(p+28)!=77||p[32]!=0)return 0;
    CHECK(wlan&&size>=39);const uint8_t*q=p+32;unsigned bytes=pms_u32(p+20),msg=psm_u16(q+3);wlan_requests++;
    const unsigned expected[]={0x20,0x2d,0x2e,0x24};CHECK(wlan_requests<=4&&msg==expected[wlan_requests-1]&&psm_u16(q+1)==wlan_requests);
    uint8_t reply[64]={2,q[1],q[2],q[3],q[4],7,0,2,4,0,0,0,0,0};unsigned n=14;
    if(msg==0x20)CHECK(bytes==26&&q[7]==0x10&&q[11]==0x13&&q[15]==0x14&&q[19]==0x15&&pms_u32(q+22)==0x4b4e454c);
    else if(msg==0x2d){
        CHECK(bytes==25&&pwfi_le(q+10,8)==wlan->base&&pms_u32(q+21)==0x100000&&wlan->prepared&&wlan_zeroes==512);
        reply[n++]=3;reply[n++]=27;reply[n++]=0;reply[n++]=2;
        for(unsigned j=0;j<2;j++){put(reply+n,wlan->base+j*0x80000,8);n+=8;put(reply+n,0x80000,4);n+=4;reply[n++]=(uint8_t)!j;}
        if(wlan_fault==3)put(reply+18,wlan->base-4096,8);
        /* RMTFS traffic arrives during WLFW startup on the same transport. */
        uint8_t nv_request[128];unsigned nv_bytes=qopen(nv_request,31,0);put(nv_request+5,nv_bytes-7,2);rx_qrtr(1,service_port,nv_request,nv_bytes);
    }else if(msg==0x2e){
        CHECK(bytes==7&&wlan->assigned&&wlan->assignments==2&&wlan_memory_mask==3&&!wlan_descriptor_mask);wlan_ready_requests++;
        uint8_t indication[7]={4,0,0,0x21,0,0,0};rx_qrtr(1,pms_u32(p+12),indication,7);
    }else{
        static const uint8_t cap[]={0x10,8,0,0x34,0x12,0,0,2,0,0,0,0x13,6,0,1,0,0,0,1,'T'};
        CHECK(bytes==7);memcpy(reply+n,cap,sizeof(cap));n+=sizeof(cap);
    }
    put(reply+5,n-7,2);rx_qrtr(1,pms_u32(p+12),reply,n);return 1;
}
static int pmwa_zero(uint64_t at,struct pmtf_zero*r)
{
    CHECK(wlan&&at==wlan->base+4096*wlan_zeroes&&!wlan_memory_mask&&!wlan_requests);wlan_zeroes++;
    uint64_t*p=(void*)(msa_shadow+at-wlan->base);for(unsigned n=0;n<512;n++){r->issued++;p[n]=0;CHECK(!p[n]);r->returned++;}return 1;
}
static int pmwa_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{
    CHECK(local_mask&&owner->held);
    if(at>=wlan->base&&at<wlan->base+0x200000){CHECK(op==PWMK_CLEAN_INVALIDATE&&at==wlan->base+4096*(wlan_zeroes-1)&&!wlan_memory_mask);}
    else{
        CHECK(wlan->pending&&wlan->pending<=2);unsigned index=wlan->pending-1;
        CHECK(at==(uintptr_t)&wlan->assignment[index].page);
        if(op==PWMK_CLEAN_INVALIDATE)CHECK(!(wlan_descriptor_mask&(1u<<index))&&!wlan_rounds[index]);
        else{
            CHECK(op==PWMK_INVALIDATE&&(wlan_descriptor_mask&(1u<<index)));
            if(wlan_fault==2)return 0;
            CHECK(!mprotect((void*)(uintptr_t)at,host_page,PROT_READ|PROT_WRITE));wlan_descriptor_mask&=~(1u<<index);
        }
    }
    *r=(struct pwmk_record){.address=at,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,.operation=op,
        .line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};return 1;
}
static int pmwa_affinity(uint64_t target,int64_t*raw)
{CHECK(local_mask&&target>=0x100&&target<=0x700&&!(target&255));*raw=1;return 1;}
static int pmwa_round(struct pwma_registers*r)
{
    CHECK(wlan->pending&&wlan->pending<=2&&wlan_requests==2&&!wlan_ready_requests);
    unsigned index=wlan->pending-1,round=++wlan_rounds[index];struct pmsn_assignment*a=&wlan->assignment[index];
    if(round==1){
        CHECK(r->x[0]==PWMA_FN&&r->x[1]==PWMA_ARGS&&r->x[2]==(uintptr_t)&a->page+64);
        const uint8_t*p=a->page.data;CHECK(pwfi_le(p+64,8)==wlan->base+index*0x80000&&pwfi_le(p+72,8)==0x80000);
        CHECK(pwfi_le(p,4)==3&&pwfi_le(p+128,4)==15&&pwfi_le(p+132,4)==6&&pwfi_le(p+152,4)==24&&pwfi_le(p+156,4)==6);
        CHECK(pwfi_le(p+176,4)==(index?25:0)&&pwfi_le(p+180,4)==(index?6:0));
        CHECK(pwmc_zero(msa_shadow+index*0x80000,0x80000));
        CHECK(!mprotect(&a->page,host_page,PROT_NONE));wlan_descriptor_mask|=1u<<index;
        CHECK(!mprotect(msa_shadow+index*0x80000,0x80000,PROT_NONE));wlan_memory_mask|=1u<<index;
    }else{
        CHECK(r->x[0]==1&&(wlan_descriptor_mask&(1u<<index)));
        for(unsigned j=1;j<7;j++)CHECK(r->x[j]==0x234000+10*(round-1)+j);
    }
    r->x[0]=round<4?1:0;for(unsigned j=1;j<7;j++)r->x[j]=r->x[0]?0x234000+10*round+j:0;
    if(wlan_fault==1&&index==1)r->x[0]=UINT64_MAX;
    if(wlan_fault==4)owner_delay=PMSC_TOTAL+1;return 1;
}
static void wlan_unprotect(void)
{
    if(wlan)for(unsigned j=0;j<2;j++)if(wlan_descriptor_mask&(1u<<j))CHECK(!mprotect(&wlan->assignment[j].page,host_page,PROT_READ|PROT_WRITE));
    if(wlan_memory_mask)CHECK(!mprotect(msa_shadow,0x200000,PROT_READ|PROT_WRITE));wlan_descriptor_mask=wlan_memory_mask=0;
}
static void wlan_setup(unsigned fault)
{
    wlan_unprotect();wlan=0;service_setup();CHECK(pmrf_begin(service,glink,rmtfs,native_nv));
    for(unsigned j=0;j<12&&!service_port;j++)CHECK(!polaris_rmtfs_poll(service->service));CHECK(service_port);
    wlan=(void*)(arena+0x7e10000);CHECK(sizeof(*wlan)<0x1a0000);memset(wlan,0,sizeof(*wlan));memset(msa_shadow,0xa5,0x200000);
    wlan_fault=fault;wlan_zeroes=wlan_requests=wlan_ready_requests=wlan_rounds[0]=wlan_rounds[1]=0;wlan_scenarios++;
    CHECK(pmwa_begin(wlan,service));
}
#ifndef PMWA_TEST_ENTRY
#define PMWA_TEST_ENTRY main
#endif
int PMWA_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned fault=0;fault<=4;fault++){
        wlan_setup(fault);int done=1;for(unsigned j=0;j<550&&done==1;j++){done=pmwa_step(wlan);if(done==1&&wlan->pages==512)advance_to(wlan->next_poll);}
        if(!fault){
            if(done!=2)fprintf(stderr,"WLFW step=%d native=%u phase=%u client=%u requests=%u assignments=%u pending=%u\\n",done,wlan->error,wlan->client.phase,wlan->client.error,wlan_requests,wlan->assignments,wlan->pending);
            if(done!=2)fprintf(stderr,"source reads=%llu error=%u channel=%u glink=%u owner=%u checks=%u elapsed=%llu\n",(unsigned long long)sm->reads,sm->error,channel->error,glink->error,owner->error,owner->live_checks,(unsigned long long)(owner->last-owner->opening));
            CHECK(done==2&&pmwa_current(wlan)&&wlan->client.ready&&wlan_requests==4&&wlan_ready_requests==1&&wlan_rounds[0]==4&&wlan_rounds[1]==4);
            CHECK(response_bytes==21&&responses==1&&pms_u32(response+17)&&wlan_memory_mask==3&&!wlan_descriptor_mask);
            CHECK(pwmc_zero(msa_shadow+0x100000,0x100000)); /* Unpublished allocation envelope remains host-owned. */
            fprintf(stderr,"native WLFW: current MSA, exact two regions/VMIDs, protected4+4 secure rounds, FW_READY/CAP and concurrent RMTFS PASS\\n");
        }else{
            CHECK(!done&&wlan->unknown&&wlan->error&&!wlan->client.ready&&!wlan_ready_requests&&owner->held&&service->wlan==(uintptr_t)wlan);
            if(fault==1)CHECK(wlan->assignments==1&&wlan->pending==2&&wlan_memory_mask==3);
            if(fault==2)CHECK(!wlan->assignments&&wlan->pending==1&&wlan_descriptor_mask==1);
            if(fault==3)CHECK(!wlan->assignments&&!wlan->pending&&!wlan_memory_mask);
            if(fault==4)CHECK(wlan->pending==1&&wlan_descriptor_mask==1);
            unsigned issued=wlan_rounds[0]+wlan_rounds[1],requests=wlan_requests;
            CHECK(!pmwa_step(wlan)&&issued==wlan_rounds[0]+wlan_rounds[1]&&requests==wlan_requests);
        }
    }
    wlan_unprotect();free(msa_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native WLFW checks, %u scenarios; software privileged/UEFI leaves and modem only\n",checks+nv_checks,wlan_scenarios);return 0;
}
