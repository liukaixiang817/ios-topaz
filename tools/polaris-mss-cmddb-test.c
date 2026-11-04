/* Actual current CPU/image/GCD producers; own CmdDb firmware and historical
 * DB bytes are inert fixture DATA. No old ticket, provider or hardware call. */
struct pwea_map;
static void cmddb_extra_map(struct pwea_map*);
static void cmddb_prepare(void);
#define PMRG_TEST_MAP_EXTRA cmddb_extra_map
#define PMRD_TEST_PREPARE cmddb_prepare
#define PMRD_TEST_ENTRY unused_rpmh_suite
#include "polaris-mss-rpmh-state-test.c"
#define EFI_XNU_MSS_CMDDB_AVAILABLE 1
#define POLARIS_MSS_CMDDB_SOFTWARE_PEER 1
#include "uefi-mss-cmddb.h"
static uint8_t*cd_original,*cd_image,*database,*db_original;
static struct pmdc_state*database_state;
static unsigned db_map_type,db_map_attr,db_map_virtual,db_words,db_fault,db_trigger;
static void cmddb_extra_map(struct pwea_map*m)
{
    struct efi_memory*d=(void*)(m->data+m->map.bytes);
    emit_descriptor((void*)d,db_map_type,PMDC_BASE,PMDC_BYTES);d->attributes=db_map_attr;
    d->virtual_address=db_map_virtual?PMDC_BASE:0;m->map.bytes+=40;
}
static void cmddb_prepare(void)
{
    cd_image=image_heap+0x90000;memcpy(cd_image,cd_original,PWCDI_IMAGE_BYTES);
    for(unsigned n=0;n<PWCDI_RELOC_COUNT;n++)put(cd_image+pwcdi_relocs[n],pwfi_le(cd_image+pwcdi_relocs[n],8)+(uintptr_t)cd_image,8);
    put(cd_image+PWCDI_IMAGEBASE_RVA,(uintptr_t)cd_image,8);put(cd_image+0x5158,PMDC_BASE,8);put(cd_image+0x5198,PMDC_BASE,8);
    uint8_t*entry=image_heap+0x7000,*i=image_heap+0x7200,*h=image_heap+0x7300;
    static const efi_guid guid={0x1c34f691,0xd33d,0x4e14,{0xb8,0xf8,0x32,0xc6,0xc0,0x29,0xe9,0x5b}};
    put(entry,0x65747270,8);put(entry+8,(uintptr_t)core+PMLI_HEAD,8);put(entry+16,(uintptr_t)image_heap+0x208,8);memcpy(entry+24,&guid,16);
    put(image_heap+0x208,(uintptr_t)entry+8,8);put(core+PMLI_HEAD+8,(uintptr_t)entry+8,8);
    put(entry+40,(uintptr_t)i+32,8);put(entry+48,(uintptr_t)i+32,8);
    put(i,0x63666970,8);put(i+24,(uintptr_t)h,8);put(i+32,(uintptr_t)entry+40,8);put(i+40,(uintptr_t)entry+40,8);
    put(i+48,(uintptr_t)entry,8);put(i+56,(uintptr_t)cd_image+0x5088,8);put(h,0x6c646e68,8);
    uint8_t*li=image_heap+0x7400,*lh=image_heap+0x7500,*meta=image_heap+0x7580;
    put(image_heap+0x1420,(uintptr_t)li+32,8);put(image_heap+0x230,(uintptr_t)li+32,8);
    put(li,0x63666970,8);put(li+8,(uintptr_t)lh+24,8);put(li+16,(uintptr_t)lh+24,8);put(li+24,(uintptr_t)lh,8);
    put(li+32,(uintptr_t)image_heap+0x228,8);put(li+40,(uintptr_t)image_heap+0x1420,8);
    put(li+48,(uintptr_t)image_heap+0x200,8);put(li+56,(uintptr_t)meta,8);
    put(lh,0x6c646e68,8);put(lh+24,(uintptr_t)li+8,8);put(lh+32,(uintptr_t)li+8,8);
    struct efi_loaded loaded={.revision=0x1000,.system=s,.base=cd_image,.bytes=PWCDI_IMAGE_BYTES,.code_type=3,.data_type=4};
    memcpy(meta,&loaded,sizeof(loaded));
    /* Split the complete GCD list around the singleton Normal-WB DB range. */
    put(image_heap+0x5008,(uintptr_t)image_heap+0x8008,8);put(image_heap+0x5020,PMDC_BASE-1,8);
    put(core+PMRG_HEAD+8,(uintptr_t)image_heap+0x9008,8);
    for(unsigned n=0;n<2;n++){
        uint8_t*q=image_heap+0x8000+4096*n;put(q,0x6d646367,8);
        put(q+8,n?(uintptr_t)core+PMRG_HEAD:(uintptr_t)image_heap+0x9008,8);
        put(q+16,(uintptr_t)image_heap+(n?0x8008:0x5008),8);
        put(q+24,n?PMDC_BASE+PMDC_BYTES:PMDC_BASE,8);put(q+32,n?UINT64_MAX:PMDC_BASE+PMDC_BYTES-1,8);
        put(q+40,n?1:8,8);put(q+48,n?1:8,8);put(q+56,n?3:2,4);
    }
}
static int pmdc_word(uint64_t at,uint64_t*out)
{
    CHECK(at>=PMDC_BASE&&at<PMDC_BASE+PMDC_BYTES&&!(at&7));db_words++;
    if(db_words==db_trigger){
        if(db_fault==1)return 0;
        if(db_fault==2)database[PMDC_BYTES-1]^=1;
        if(db_fault==3)put(image_heap+0x8030,0,8);
        if(db_fault==4)cd_image[0x1000]^=1;
        if(db_fault==5)put(cd_image+0x5198,PMDC_BASE+4096,8);
        if(db_fault==6)owner_delay=PMSC_TOTAL+1;
    }
    *out=pwfi_le(database+(at-PMDC_BASE),8);return 1;
}
static void cmddb_setup(void)
{
    db_words=db_fault=db_trigger=0;memcpy(database,db_original,PMDC_BYTES);rpmh_setup();
    database_state=(void*)(arena+0x500000);CHECK(0x500000+sizeof(*database_state)<PMMN_TEST_IMAGE_BYTES);memset(database_state,0,sizeof(*database_state));
}
static int cmddb_run(void){return pmdc_capture(database_state,resource_map);}
#ifndef PMDC_TEST_ENTRY
#define PMDC_TEST_ENTRY main
#endif
int PMDC_TEST_ENTRY(int argc,char**argv)
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
    cmddb_setup();unsigned start=image_ats;int ok=cmddb_run();
    if(!ok)fprintf(stderr,"CmdDb error%u reads%u/%u pages%u/%u AT%u words%u CPU%u\n",database_state->error,database_state->pass[0].reads,database_state->pass[1].reads,database_state->pass[0].pages,database_state->pass[1].pages,rp_ats,db_words,owner->error);
    CHECK(ok&&pmdc_current(database_state,resource_map));unsigned ats=rp_ats,nodes=image_ats-start;
    CHECK(db_words==32768&&database_state->pass[1].pages==32&&nodes==128);
    for(unsigned n=0;n<3;n++)CHECK(database_state->pass[1].resource[n].minimum>0&&database_state->pass[1].resource[n].minimum<=15);
    CHECK(database_state->pass[1].resource[7].minimum==3&&database_state->pass[1].resource[7].address==0x30080);
    CHECK(!cmddb_run());CHECK(pmsc_close_unused(owner)&&!pmdc_current(database_state,resource_map));
    fprintf(stderr,"normal current CmdDb PASS: %u AT, %u GCD reads; starting failure checks\n",ats,nodes);
    for(unsigned at=1;at<=ats;at++){
        cmddb_setup();rp_fault=2;rp_trigger=at;CHECK(!cmddb_run()&&database_state->unknown&&!database_state->complete&&rp_ats==at);
    }
    for(unsigned fault=1;fault<=6;fault++)if(fault!=2)for(unsigned edge=0;edge<4;edge++){
        cmddb_setup();rp_fault=fault;rp_trigger=edge==0?1:edge==1?ats/2:edge==2?ats/2+1:ats;
        CHECK(!cmddb_run()&&database_state->unknown&&!database_state->complete&&rp_ats==rp_trigger);
    }
    fprintf(stderr,"CmdDb AT failure positions PASS\n");
    for(unsigned at=1;at<=nodes;at++){
        cmddb_setup();image_fault=1;image_trigger=image_ats+at;
        CHECK(!cmddb_run()&&database_state->unknown&&!database_state->complete&&image_ats==image_trigger);
    }
    for(unsigned fault=1;fault<=6;fault++){
        cmddb_setup();db_fault=fault;db_trigger=fault==2?16385:512;
        CHECK(!cmddb_run()&&database_state->unknown&&!database_state->complete);
    }
    for(unsigned fault=0;fault<10;fault++){
        db_map_type=fault==0?4:fault==1?7:0;db_map_attr=fault==2?1:8;db_map_virtual=fault==3;
        cmddb_setup();
        if(fault==4)put(image_heap+0x8038,3,4);
        if(fault==5)put(image_heap+0x8030,1,8);
        if(fault==6)cd_image[0x1000]^=1;
        if(fault==7)put(cd_image+0x5158,PMDC_BASE+4096,8);
        if(fault==8)put(image_heap+0x7200+56,(uintptr_t)cd_image+0x5090,8);
        if(fault==9)owner->effects=1;
        ok=cmddb_run();CHECK(fault==0?ok:!ok&&!database_state->complete);
    }
    db_map_type=db_map_virtual=0;db_map_attr=8;cmddb_setup();CHECK(cmddb_run());
    /* Mutate the actual observed table shape, never synthesize a power grant. */
    struct pmdc_resource resources[8];memset(resources,0,sizeof(resources));CHECK(pmdc_select(db_original,resources));
    for(unsigned fault=0;fault<16;fault++){
        memcpy(database,db_original,PMDC_BYTES);
        unsigned arc=resources[0].entry,xo=resources[7].entry,vrm=resources[3].entry,aux=resources[7].aux_offset;
        switch(fault){
        case 0:database[0]^=1;break;case 1:database[4]^=1;break;
        case 2:put(database+arc+16,0x30020,4);break;case 3:put(database+arc+20,30,2);break;
        case 4:put(database+arc+22,0xffff,2);break;
        case 5:memcpy(database+resources[1].entry,database+arc,8);break;
        case 6:put(database+resources[0].aux_offset,1,2);break;
        case 7:put(database+resources[0].aux_offset+2,0xffff,2);break;
        case 8:put(database+xo+16,0x30090,4);break;case 9:put(database+xo+20,8,2);break;
        case 10:put(database+aux+6,129,2);break;case 11:put(database+aux+8,1,2);break;
        case 12:put(database+vrm+20,2,2);break;case 13:put(database+vrm+16,0x40f04,4);break;
        case 14:memcpy(database+resources[4].entry,database+vrm,8);break;
        case 15:put(database+14,513,2);break;
        }
        struct pmdc_resource out[8]={0};CHECK(!pmdc_select(database,out));
    }
    database_state->pass[1].raw[0]^=1;CHECK(!pmdc_current(database_state,resource_map));
    CHECK(!munmap(heap_mapping,0x100000+2*host_page));CHECK(!munmap(shadow_mapping,0x104000+2*host_page));
    free(original);free(rp_original);free(cd_original);free(database);free(db_original);free(arena);
    printf("PASS %u current CmdDb checks, %u native capture scenarios; no hardware/provider calls\n",checks,scenarios);return 0;
}
