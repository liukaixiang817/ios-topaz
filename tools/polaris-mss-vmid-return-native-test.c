/* Complete native startup/stop/resources plus exact secure permission return.
 * All hardware/UEFI/remote peers are SOFTWARE. Descriptor pages become real
 * host PROT_NONE across every secure continuation. Targets stay inaccessible. */
#define PMNR_TEST_ENTRY unused_resource_retirement_suite
#include "polaris-mss-retirement-native-test.c"
#define EFI_XNU_MSS_VMID_RETURN_NATIVE_AVAILABLE 1
#define POLARIS_MSS_VMID_RETURN_SOFTWARE_PEER 1
#include "uefi-mss-vmid-return-native.h"
static struct pmvb_state*vmid_return;
static unsigned back_fault,back_rounds[4],back_protected,back_transferred,back_scenarios,back_peer_calls;
static int pmvb_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{
    CHECK(local_mask&&owner->held&&vmid_return->pending&&vmid_return->pending<=4);
    unsigned n=vmid_return->pending-1;CHECK(at==(uintptr_t)&vmid_return->assignment[n].page);
    if(op==PWMK_CLEAN_INVALIDATE)CHECK(!(back_protected&(1u<<n))&&!back_rounds[n]);
    else{
        CHECK(op==PWMK_INVALIDATE&&(back_protected&(1u<<n))&&(back_transferred&(1u<<n)));
        if(back_fault==2)return 0;
        CHECK(!mprotect((void*)(uintptr_t)at,host_page,PROT_READ|PROT_WRITE));back_protected&=~(1u<<n);
    }
    *r=(struct pwmk_record){.address=at,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,.operation=op,
        .line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};return 1;
}
static int pmvb_affinity(uint64_t target,int64_t*raw)
{
    CHECK(local_mask&&owner->held&&target>=0x100&&target<=0x700&&!(target&255));back_peer_calls++;
    *raw=back_fault==3&&back_rounds[0]?0:1;return 1;
}
static int pmvb_round(struct pwma_registers*r)
{
    CHECK(vmid_return->pending&&vmid_return->pending<=4&&power->restored&&clock_owner->restored&&aop_owner->restored&&owner->held);
    unsigned n=vmid_return->pending-1,round=++back_rounds[n];struct pmsn_assignment*q=&vmid_return->assignment[n];
    if(round==1){
        CHECK(r->x[0]==PWMA_FN&&r->x[1]==PWMA_ARGS&&r->x[2]==(uintptr_t)&q->page+64);
        const uint8_t*p=q->page.data;uint64_t base=n<2?wlan->base+n*0x80000:n==2?rmtfs->base:mss->memory.claim[0].requested;
        uint64_t size=n<2?0x80000:n==2?0x200000:0x7800000;
        CHECK(pwfi_le(p+64,8)==base&&pwfi_le(p+72,8)==size&&pwfi_le(p+128,4)==3&&pwfi_le(p+132,4)==7);
        CHECK(pwfi_le(p,4)==(n==2?3:15)&&pwfi_le(p+4,4)==(n<2?24:n==2?15:0)&&pwfi_le(p+8,4)==(n==1?25:0));
        CHECK(pwfi_le(p+256,8)==(n==1?12:n==3?4:8)&&pwfi_le(p+272,8)==24);
        CHECK(!mprotect(&q->page,host_page,PROT_NONE));back_protected|=1u<<n;
    }else{
        CHECK(r->x[0]==1&&(back_protected&(1u<<n)));for(unsigned j=1;j<7;j++)CHECK(r->x[j]==0x456000+10*(round-1)+j);
    }
    r->x[0]=round<4?1:0;for(unsigned j=1;j<7;j++)r->x[j]=r->x[0]?0x456000+10*round+j:0;
    if(back_fault==1&&n==1)r->x[0]=UINT64_MAX;
    if(!r->x[0])back_transferred|=1u<<n;
    if(back_fault==4)owner_delay+=PMSC_TOTAL+1;
    return 1;
}
static void back_unprotect(void)
{
    if(vmid_return)for(unsigned n=0;n<4;n++)if(back_protected&(1u<<n))CHECK(!mprotect(&vmid_return->assignment[n].page,host_page,PROT_READ|PROT_WRITE));
    back_protected=0;
}
static void back_setup(unsigned fault)
{
    back_unprotect();vmid_return=0;retire_setup(0);CHECK(retire_drive()==2&&pmnr_current(resource_retirement));
    vmid_return=(void*)(arena+0x7000000);CHECK(sizeof(*vmid_return)<0x100000&&0x4300000+sizeof(*auth_copy)<0x7000000);
    memset(vmid_return,0,sizeof(*vmid_return));memset(back_rounds,0,sizeof(back_rounds));back_fault=fault;back_transferred=back_peer_calls=0;back_scenarios++;
    CHECK(pmvb_begin(vmid_return,resource_retirement));
    if(fault==5)wlan->client.region[1].address+=4096;
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned fault=0;fault<=5;fault++){
        back_setup(fault);int done=1;for(unsigned n=0;n<6&&done==1;n++)done=pmvb_step(vmid_return);
        if(!fault){
            if(done!=2)fprintf(stderr,"VMID return result=%d error=%u returned=%u pending=%u owner=%u\n",done,vmid_return->error,vmid_return->returned,vmid_return->pending,owner->error);
            CHECK(done==2&&pmvb_current(vmid_return)&&vmid_return->returned==4&&back_transferred==15&&!back_protected);
            for(unsigned n=0;n<4;n++)CHECK(back_rounds[n]==4);
            CHECK(owner->held&&!pmsc_close_unused(owner)&&wlan_memory_mask==3&&modem_owner==2);
            fprintf(stderr,"native VMID return: actual full startup/stop/resources, exact MSA/RMTFS/120MiB inverse grants, protected4x4 continuations PASS; targets untouched/CPU held\n");
        }else{
            CHECK(!done&&vmid_return->unknown&&vmid_return->error&&!vmid_return->complete&&owner->held);
            if(fault==1)CHECK(vmid_return->returned==1&&back_transferred==1&&back_protected==2);
            if(fault==2)CHECK(!vmid_return->returned&&back_transferred==1&&back_protected==1);
            if(fault==3)CHECK(!vmid_return->returned&&back_rounds[0]==1&&back_protected==1);
            if(fault==5)CHECK(!back_peer_calls&&!back_transferred&&!back_protected);
            unsigned calls=back_peer_calls;CHECK(!pmvb_step(vmid_return)&&back_peer_calls==calls);
        }
    }
    back_unprotect();wlan_unprotect();free(msa_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native VMID return checks, %u scenarios; SOFTWARE leaves only\n",checks+nv_checks,back_scenarios);return 0;
}
