/* Actual mapping producer with software original-service/AT/FP leaves only.
 * Original own Core PE is inert source data; modem physical pages are NEVER
 * mapped in this host process. Unexpected target dereferences therefore fault. */
#define PMMN_TEST_ENTRY unused_mss_memory_suite
#define PMMN_TEST_IMAGE_BYTES 0xc0000
#define POLARIS_WIFI_SCALAR_SHA256_FAST 1
#include "polaris-mss-memory-test.c"
#define EFI_XNU_MSS_MODEM_NORMAL_NC 1
#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD 1
#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1
#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT 10
#define POLARIS_MSS_MODEM_MAPPING_SOFTWARE_PEER 1
static int nc_translate(struct pwmc_translation*);
static int nc_arch(void*,struct pgcd_arch*);
static int nc_save(void*,struct pgcd_fp_guard*);
static int nc_restore(void*,struct pgcd_fp_guard*);
#undef pwmc_actual_translate
#undef pgcd_actual_arch
#undef pgcd_actual_fp_save
#undef pgcd_actual_fp_restore
#define pwmc_actual_translate nc_translate
#define pgcd_actual_arch nc_arch
#define pgcd_actual_fp_save nc_save
#define pgcd_actual_fp_restore nc_restore
#include "uefi-mss-modem-mapping.h"
static struct pmnc_result*nc;
static uint8_t*nc_digest;
static unsigned nc_calls,nc_maps,nc_set,nc_mapped,nc_fault,nc_trigger,nc_at,nc_at_trigger,nc_par_inner;
static unsigned nc_after_arch;
_Static_assert(sizeof(struct pmnc_result)<0x20000,"fixture exact own mapping extent");
static int nc_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);
    if(nc_fault==20&&nc_calls==nc_trigger)a->cpu.ttbr0^=4096;
    if(nc_fault==21&&nc_calls==nc_trigger)a->cpu.ticks+=PGCD_FRESH_TICKS+1;
    if(nc_fault==22&&nc_calls==nc_trigger)a->cpacr=0;
    if(nc_fault==31&&nc_after_arch)a->cpu.ticks+=19200001;
    return ok;
}
static int nc_save(void*p,struct pgcd_fp_guard*g)
{return nc_fault==23&&nc_calls==nc_trigger?0:early_save(p,g);}
static int nc_restore(void*p,struct pgcd_fp_guard*g)
{return nc_fault==24&&nc_calls==nc_trigger?0:early_restore(p,g);}
static int nc_translate(struct pwmc_translation*t)
{
    CHECK(t->page>=nc->base&&t->page-nc->base<PMNC_BYTES);nc_at++;
    int ok=early_translate(t);
    if(nc_mapped)t->read_par=t->write_par=(nc_par_inner?UINT64_C(0x4400000000000b80):UINT64_C(0x4400000000000b00))|t->page;
    if(nc_at==nc_at_trigger){
        if(nc_fault==10)t->read_par^=1;
        if(nc_fault==11)t->write_par^=4096;
        if(nc_fault==12)t->restored++;
        if(nc_fault==13)t->read_returned=0;
        if(nc_fault==14)t->page+=4096;
        if(nc_fault==15)return 0;
        if(nc_fault==16)t->read_par=t->write_par=UINT64_C(0xff00000000000b80)|t->page;
        if(nc_fault==17)t->read_par=t->write_par=UINT64_C(0x4400000000000b00)|t->page;
        if(nc_fault==31)nc_after_arch=1;
    }
    return ok;
}
static efi_status pmnc_service(struct pmnc_result*r,unsigned index)
{
    CHECK(r==nc&&index==nc_calls&&r->pending==index+1&&r->call[index].issued&&r->call[index].unknown);nc_calls++;
    if(index==0||index==4){
        struct pwea_map*m=&r->map[index/4];CHECK(nc_maps++==index/4);
        memcpy(m->data,mss->memory.map[3].data,mss->memory.map[3].map.bytes);
        for(unsigned at=0;at<mss->memory.map[3].map.bytes;at+=mss_stride){
            struct efi_memory*d=(void*)(m->data+at);if(d->physical==r->base)d->attributes=index==4?2:8;
        }
        m->map.bytes=mss->memory.map[3].map.bytes;m->map.stride=mss_stride;m->map.key=100+index;m->map.version=1;
    }else if(index==2){CHECK(!nc_set++&&!nc_mapped&&r->translated[0]==30720);nc_mapped=1;}
    else{
        struct pgcd_descriptor*d=&r->descriptor[index/3];
        *d=(struct pgcd_descriptor){.base=r->base,.length=PMNC_BYTES,.capabilities=15,.attributes=index==3?2:8,.type=2};
    }
    if(nc_calls==nc_trigger){
        if(nc_fault==1)return EFI_ERROR|9;
        if(nc_fault==2)r->base+=0x100000;
        if(nc_fault==3)r->call[index].fp.q8_q15[0]^=1;
        if(nc_fault==4)r->early=8;
        if(nc_fault==5)early->memory.claim[0].bytes--;
        if(nc_fault==6)s->boot=(void*)8;
        if(nc_fault==7&&index==1)r->descriptor[0].capabilities=8;
        if(nc_fault==8&&index==3)r->descriptor[1].attributes=8;
        if(nc_fault==9&&index==4)((struct efi_memory*)r->map[1].data)->attributes^=1;
        if(nc_fault==25&&index==4)r->map[1].map.bytes=8193;
        if(nc_fault==26&&index==4)r->map[1].map.key=0;
        if(nc_fault==27&&index==3)r->descriptor[1].image_handle=1;
    }
    return 0;
}
static void nc_setup(unsigned fault_kind,unsigned trigger_call,unsigned stride)
{
    mss_setup(0,0,stride);CHECK(mss_run());nc=(void*)(arena+0xa0000);nc_digest=arena+0x9e000;
    memset(nc,0,sizeof(*nc));memset((uint8_t*)nc-16,0xa5,16);memset((uint8_t*)(nc+1),0x5a,16);
    pweh_digest(mss,sizeof(*mss),nc_digest);nc_fault=fault_kind;nc_trigger=trigger_call;
    nc_calls=nc_maps=nc_set=nc_mapped=nc_at=nc_at_trigger=nc_after_arch=0;
    put(core+0x1bd48,16,8);put(core+0x1bd50,0,8);put(core+0x1bd58,1,8);
    /* The fixture relocates Core's DS entries, so recompute its ordinary EFI
     * table CRC exactly rather than using it as executable original code. */
    uint8_t*ds=core+0x1bb18;put(ds+16,0,4);uint32_t crc=UINT32_MAX;
    for(unsigned n=0;n<168;n++){crc^=ds[n];for(unsigned j=0;j<8;j++)crc=(crc>>1)^(UINT32_C(0xedb88320)&(0u-(crc&1)));}
    put(ds+16,crc^UINT32_MAX,4);
}
static void nc_canaries(void)
{for(unsigned n=0;n<16;n++){CHECK(*((uint8_t*)nc-16+n)==0xa5);CHECK(*((uint8_t*)(nc+1)+n)==0x5a);}}
static int nc_run(void){return pmnc_run(nc,early,mss,nc_digest);}
int main(int argc,char**argv)
{
    CHECK(argc==2&&!posix_memalign((void**)&arena,4096,0x100000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned stride=40;stride<=48;stride+=8)for(nc_par_inner=0;nc_par_inner<=1;nc_par_inner++){
        nc_setup(0,0,stride);CHECK(nc_run()&&nc->complete&&!nc->unknown&&nc_calls==5&&nc_set==1&&nc_maps==2);
        CHECK(nc_at==61440&&nc->translated[0]==30720&&nc->translated[1]==30720&&nc->par==(nc_par_inner?UINT64_C(0x4400000000000b80):UINT64_C(0x4400000000000b00)));
        uint8_t hash[32];pweh_digest(nc,offsetof(struct pmnc_result,digest),hash);CHECK(pgcd_equal(hash,nc->digest,32));
        CHECK(!nc_run()&&nc_calls==5&&nc_at==61440);nc_canaries();
    }
    for(unsigned call=1;call<=5;call++)for(unsigned fault_kind=1;fault_kind<=6;fault_kind++){
        nc_setup(fault_kind,call,48);CHECK(!nc_run()&&nc->unknown&&!nc->complete&&nc_calls==call);
        unsigned before=nc_calls,at=nc_at;CHECK(!nc_run()&&nc_calls==before&&nc_at==at);nc_canaries();
    }
    unsigned special[][2]={{7,2},{8,4},{9,5},{25,5},{26,5},{27,4}};
    for(unsigned k=0;k<sizeof(special)/sizeof(special[0]);k++){
        nc_setup(special[k][0],special[k][1],48);CHECK(!nc_run()&&nc->unknown&&!nc->complete);nc_canaries();
    }
    unsigned pages[]={1,222,875,30720};
    for(unsigned after=0;after<2;after++)for(unsigned k=0;k<4;k++)for(unsigned fault_kind=10;fault_kind<=17;fault_kind++){
        if(fault_kind==16&&!after)continue;
        if(fault_kind==17&&(!after||!nc_par_inner||k==0))continue;
        nc_setup(fault_kind,0,40);nc_at_trigger=after*30720+pages[k];
        CHECK(!nc_run()&&nc->unknown&&!nc->complete&&nc_at==nc_at_trigger);nc_canaries();
    }
    for(unsigned kind=20;kind<=24;kind++){
        nc_setup(kind,kind==23?0:1,40);CHECK(!nc_run()&&nc->unknown&&!nc->complete);nc_canaries();
    }
    nc_setup(31,0,40);nc_at_trigger=30720;CHECK(!nc_run()&&nc->unknown&&!nc->complete&&!nc_set);nc_canaries();
    nc_setup(0,0,40);nc_digest[0]^=1;CHECK(!nc_run()&&nc->unknown&&!nc_calls);nc_canaries();
    free(original);free(arena);printf("PASS %u actual guarded modem-mapping checks; software leaves only\n",checks);return 0;
}
