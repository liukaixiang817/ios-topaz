/* Actual pre-native NV -> native MSS/SMP/GLINK -> grant -> RMTFS.
 * Hardware leaves, modem and NV contents are SOFTWARE. Own images/GPT inert. */
struct pwea_map;
static void service_before_early(void),service_after_early(void),service_map(struct pwea_map*);
static int service_qrtr(const unsigned char*,unsigned);
#define PMMN_TEST_BEFORE_EARLY service_before_early
#define PMMN_TEST_AFTER_EARLY service_after_early
#define PMMN_TEST_MAP_EXTRA service_map
#define PMSX_TEST_MAP_EXTRA service_map
#define PMSG_TEST_QRTR_HOOK service_qrtr
#define PMSG_TEST_ENTRY unused_glink_suite
#include "polaris-mss-glink-native-test.c"
#define PMTF_TEST_EXISTING_AUTH 1
#define PMTF_TEST_ENTRY unused_rmtfs_grant_suite
#include "polaris-mss-rmtfs-native-test.c"
#define PNV_TEST_ENTRY unused_nv_collector_suite
#define device nv_device
#include "polaris-wifi-nv-inputs-test.c"
#undef device
#undef pgcd_actual_arch
#undef pgcd_actual_fp_save
#undef pgcd_actual_fp_restore
#define pgcd_actual_arch early_arch
#define pgcd_actual_fp_save early_save
#define pgcd_actual_fp_restore early_restore
#define EFI_XNU_WIFI_NV_NATIVE_AVAILABLE 1
#define POLARIS_WIFI_NV_SOFTWARE_PEER 1
#include "uefi-wifi-nv-native.h"
#undef pgcd_actual_arch
#define pgcd_actual_arch owner_arch
#define EFI_XNU_MSS_RMTFS_SERVICE_AVAILABLE 1
#define POLARIS_MSS_RMTFS_SERVICE_SOFTWARE_PEER 1
#include "uefi-mss-rmtfs-service.h"
static struct pnnv_state*native_nv;
static struct pnv_plan*native_plan;
static struct pmrf_state*service;
static unsigned nv_maps,nv_allocations,service_port,response_bytes,responses,service_fault,service_copies,service_scenarios;
static uint8_t response[25];
static efi_status pnnv_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&nv_maps<3&&m==&native_nv->map[nv_maps]);nv_maps++;
    unsigned count=0;emit_descriptor(m->data+40*count++,3,(uintptr_t)arena,PMMN_TEST_ARENA_BYTES);
    emit_descriptor(m->data+40*count++,2,0x180000000,0x10000000);
    for(unsigned n=0;n<2;n++)emit_descriptor(m->data+40*count++,2,early->memory.claim[n].requested,early->memory.claim[n].bytes);
    emit_descriptor(m->data+40*count++,nv_allocations?2:7,(uintptr_t)memory,PNV_BYTES);
    m->map.bytes=40*count;m->map.stride=40;m->map.version=1;m->map.key=50+nv_maps;return 0;
}
static efi_status pnnv_allocate(struct efi_system*system,uint64_t*at)
{CHECK(system==s&&!nv_allocations&&at==&native_nv->allocation.address);nv_allocations++;*at=(uintptr_t)memory;return 0;}
static void service_before_early(void)
{
    native_nv=(void*)(arena+0x7d00000);native_plan=(void*)(arena+0x7df0000);
    CHECK(sizeof(*native_nv)<0xf0000);memset(native_nv,0,sizeof(*native_nv));*native_plan=polaris_nv_plan;
    result=&native_nv->inputs;nv_setup(0);nv_maps=nv_allocations=0;
    s->boot->locate_buffer=boot.locate_buffer;s->boot->handle_protocol=boot.handle_protocol;s->boot->free_pool=boot.free_pool;
}
static void service_after_early(void)
{CHECK(pnnv_run(native_nv,early,native_plan)&&native_nv->complete&&nv_maps==3&&nv_allocations==1);}
static void service_map(struct pwea_map*m)
{CHECK(native_nv->complete&&m->map.bytes+40<=sizeof(m->data));emit_descriptor(m->data+m->map.bytes,2,(uintptr_t)memory,PNV_BYTES);m->map.bytes+=m->map.stride;}
static int service_qrtr(const uint8_t*q,unsigned bytes)
{
    CHECK(bytes>=32&&pms_u32(q+20)<=bytes-32);
    if(pms_u32(q+4)==4){
        CHECK(pms_u32(q+20)==20&&pms_u32(q+32)==4&&pms_u32(q+36)==14&&pms_u32(q+40)==0x101&&pms_u32(q+44)==1);
        service_port=pms_u32(q+48);CHECK(service_port&&service_port<0xfffffffe);return 1;
    }
    if(pms_u32(q+4)==1&&pms_u32(q+28)==77){
        response_bytes=pms_u32(q+20);CHECK(response_bytes>=14&&response_bytes<=25&&q[32]==2&&pms_u32(q+24)==3);
        memcpy(response,q+32,response_bytes);responses++;return 1;
    }return 0;
}
static int pmrf_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{
    CHECK(local_mask&&owner->held&&at>=rmtfs->base&&at+4096<=rmtfs->base+0x200000);
    CHECK(op==PWMK_INVALIDATE||op==PWMK_CLEAN_INVALIDATE);
    *r=(struct pwmk_record){.address=at,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,.operation=op,
        .line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
    return service_fault!=2;
}
static int pmrf_copy(uint64_t shared,uint64_t private,unsigned bytes,unsigned write,struct pmrf_access*r)
{
    CHECK(shared>=rmtfs->base&&bytes<=rmtfs->base+0x200000-shared&&pmrf_private(service,private,bytes));service_copies++;
    uint8_t*a=rmtfs_shadow+4096+shared-rmtfs->base,*b=(void*)(uintptr_t)private;
    for(unsigned n=0;n<bytes;n++){r->issued++;if(write)a[n]=b[n];else b[n]=a[n];r->returned++;if(service_fault==1&&n==31)return 0;}
    return 1;
}
static void service_setup(void)
{
    pmrf_runtime=0;service=0;glink_setup(0);CHECK(pmsg_step(glink)==2);
    for(unsigned n=0;n<12;n++)CHECK(!polaris_wifi_glink_poll_once(glink->transport));
    uint32_t node=0;CHECK(!polaris_wifi_glink_qrtr_peer(glink->transport,&node)&&node==3&&!server_seen&&!cap_replies);
    rmtfs=(void*)(arena+0x7600000);memset(rmtfs,0,sizeof(*rmtfs));memset(rmtfs_shadow,0xa5,0x202000);
    rmtfs_rounds=rmtfs_zeroes=rmtfs_caches=rmtfs_continuations=rmtfs_fault=rmtfs_protected=0;
    CHECK(pmtf_begin(rmtfs,auth_owner)&&rmtfs_drive()==2&&pmtf_current(rmtfs));
    service=(void*)(arena+0x7e00000);CHECK(sizeof(*service)<0x10000);memset(service,0,sizeof(*service));
    service_port=response_bytes=responses=service_fault=service_copies=0;service_scenarios++;
}
static unsigned qheader(uint8_t*q,unsigned txn,unsigned msg)
{memset(q,0,128);put(q+1,txn,2);put(q+3,msg,2);return 7;}
static void qfield(uint8_t*q,unsigned*n,unsigned tag,uint64_t value,unsigned width)
{q[*n]=(uint8_t)tag;put(q+*n+1,width,2);put(q+*n+3,value,width);*n+=3+width;}
static void qsend(uint8_t*q,unsigned bytes,unsigned success)
{
    put(q+5,bytes-7,2);response_bytes=0;rx_qrtr(1,service_port,q,bytes);
    for(unsigned n=0;n<16&&!response_bytes;n++){int error=polaris_rmtfs_poll(service->service);if(error){CHECK(!success);break;}}
    if(success){CHECK(response_bytes>=14&&!memcmp(response+1,q+1,4)&&!psm_u16(response+10)&&!psm_u16(response+12));}
    else CHECK(!response_bytes);
}
static unsigned qopen(uint8_t*q,unsigned txn,unsigned part)
{
    const char*paths[]={"/boot/modem_fs1","/boot/modem_fs2","/boot/modem_fsg","/boot/modem_fsc"};
    unsigned n=qheader(q,txn,1),len=(unsigned)strlen(paths[part]);q[n]=1;put(q+n+1,len,2);memcpy(q+n+3,paths[part],len);return n+3+len;
}
static unsigned qrw(uint8_t*q,unsigned txn,unsigned handle,unsigned dir,unsigned sectors)
{
    unsigned n=qheader(q,txn,3);qfield(q,&n,1,handle,4);qfield(q,&n,2,dir,1);
    q[n]=3;put(q+n+1,13,2);q[n+3]=1;put(q+n+4,0,4);put(q+n+8,rmtfs->base,4);put(q+n+12,sectors,4);return n+16;
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    service_setup();
    native_nv->digest[0]^=1;CHECK(!pmrf_begin(service,glink,rmtfs,native_nv)&&!pmrf_runtime&&!rmtfs->service&&!native_nv->consumer);native_nv->digest[0]^=1;
    native_nv->consumer=8;CHECK(!pmrf_begin(service,glink,rmtfs,native_nv)&&!pmrf_runtime&&!rmtfs->service);native_nv->consumer=0;
    int ok=pmrf_begin(service,glink,rmtfs,native_nv);
    if(!ok)fprintf(stderr,"service begin error=%u ready=%u allocations=%u grant=%u glink=%u\n",service->error,service->ready,service->allocations,rmtfs->error,glink->error);
    CHECK(ok);for(unsigned j=0;j<12&&!service_port;j++)CHECK(!polaris_rmtfs_poll(service->service));
    CHECK(service_port&&!server_seen&&!cap_replies&&pmrf_live(service)&&pmtf_current(rmtfs));
    uint8_t q[128];unsigned n=qopen(q,1,0);qsend(q,n,1);CHECK(response_bytes==21);unsigned handle=pms_u32(response+17);
    n=qheader(q,2,4);qfield(q,&n,1,1,4);qfield(q,&n,2,0x200000,4);qsend(q,n,1);CHECK(response_bytes==25&&pwfi_le(response+17,8)==rmtfs->base);
    n=qrw(q,3,handle,1,16);qsend(q,n,1);CHECK(!memcmp(rmtfs_shadow+4096,memory,8192));
    memset(rmtfs_shadow+4096,0x76,8192);n=qrw(q,4,handle,0,16);qsend(q,n,1);
    unsigned copied=service_copies;memset(rmtfs_shadow+4096,0xa5,8192);qsend(q,n,1);CHECK(service_copies==copied);
    n=qrw(q,5,handle,1,16);qsend(q,n,1);for(unsigned j=0;j<8192;j++)CHECK(rmtfs_shadow[4096+j]==0x76&&memory[j]==nv_byte(0,j));
    n=qheader(q,6,6);qfield(q,&n,1,handle,4);qsend(q,n,1);
    struct polaris_rmtfs_status status;CHECK(!polaris_rmtfs_status(service->service,&status)&&status.dirty&&!status.durable_nv&&status.replayed==1&&status.bytes_to_shadow==8192&&status.bytes_to_remote==16384);
    n=qheader(q,7,2);qfield(q,&n,1,handle,4);qsend(q,n,1);unsigned frees=service->frees;
    CHECK(polaris_rmtfs_stop(service->service)&&polaris_rmtfs_destroy(service->service)&&service->frees==frees);
    fprintf(stderr,"native RMTFS before WLFW: current NV, publish14, open/allocate, cross-page read/write, replay, volatile sync PASS\n");
    for(unsigned fault=1;fault<=3;fault++){
        service_setup();CHECK(pmrf_begin(service,glink,rmtfs,native_nv));
        for(unsigned j=0;j<12&&!service_port;j++)CHECK(!polaris_rmtfs_poll(service->service));CHECK(service_port);
        n=qopen(q,1,0);qsend(q,n,1);handle=pms_u32(response+17);
        unsigned before=service_copies;frees=service->frees;
        if(fault==3)owner_delay=PMSC_TOTAL+1;else service_fault=fault;
        n=qrw(q,2,handle,0,16);qsend(q,n,0);
        CHECK(!pmrf_live(service)&&owner->held&&native_nv->consumer==(uintptr_t)service&&rmtfs->service==(uintptr_t)service);
        if(fault<3)CHECK(service->unknown&&service->error==3&&service_copies==before+(fault==1));
        else CHECK(service_copies==before);
        copied=service_copies;CHECK(polaris_rmtfs_poll(service->service)&&polaris_rmtfs_destroy(service->service));
        CHECK(service_copies==copied&&service->frees==frees);
        for(unsigned j=0;j<4096;j++)CHECK(rmtfs_shadow[j]==0xa5&&rmtfs_shadow[0x201000+j]==0xa5);
    }
    fprintf(stderr,"native RMTFS partial-copy/cache/owner-time failures refuse success, retry and release PASS\n");
    free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native RMTFS service checks, %u scenarios; software UEFI/privileged leaves/modem only\n",checks+nv_checks,service_scenarios);return 0;
}
