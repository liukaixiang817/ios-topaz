/* Actual MSS producer with the own Core's descriptor-page side effect.
 * Firmware PE remains inert identity data; no real firmware/device calls. */
struct pwea_map;
static void heap_map(struct pwea_map*);
#define PMMN_TEST_MAP_EXTRA heap_map
#define PMMN_TEST_ENTRY unused_mss_memory_suite
#include "polaris-mss-memory-test.c"
#include "uefi-mss-memory-diagnostic.h"
static unsigned heap_fault,heap_alloc,scenarios;
static void heap_map(struct pwea_map*m)
{
    unsigned count=(unsigned)(m->map.bytes/mss_stride),changed=mss_allocs>=heap_alloc;
    uint64_t base=heap_fault==9?UINT64_C(0xb1000000):UINT64_C(0x17017b000);
    unsigned pages=heap_fault==1?2:1;
    unsigned first=count;
    mss_emit(m,&count,4,base-4096,4096);
    mss_emit(m,&count,heap_fault==3?2:heap_fault==4?4:7,base,pages*4096);
    mss_emit(m,&count,4,base+pages*4096,0x2c84*4096);
    if(changed){
        count=first;
        unsigned type=heap_fault==2?3:heap_fault==4?7:4;
        if(type==4)mss_emit(m,&count,4,base-4096,(0x2c85+pages)*4096);
        else{
            mss_emit(m,&count,4,base-4096,4096);
            mss_emit(m,&count,type,base,pages*4096);
            mss_emit(m,&count,4,base+pages*4096,0x2c84*4096);
        }
        uint8_t*d=m->data+first*mss_stride;
        if(heap_fault==5)d[32]^=1;
        if(heap_fault==6)d[16]=1;
        if(heap_fault==7)d[4]=1;
        if(heap_fault==8)d[40]^=1;
    }
    if(heap_fault==10||heap_fault==13)
        mss_emit(m,&count,heap_fault==10?(changed?4:7):(changed?7:4),base+0x4000000,4096);
    for(unsigned n=first;n<count;n++){
        struct efi_memory*d=(void*)(m->data+n*mss_stride);
        if(heap_fault==11)d->attributes=4;
        if(heap_fault==12)d->virtual_address=4096;
    }
    m->map.bytes=count*mss_stride;
}
static void write_fixture(const char*dir,unsigned stride)
{
    char name[1024];snprintf(name,sizeof(name),"%s/maps-%u.bin",dir,stride);
    FILE*f=fopen(name,"wb");CHECK(f&&fwrite(&mss->memory,1,sizeof(mss->memory),f)==sizeof(mss->memory)&&!fclose(f));
    snprintf(name,sizeof(name),"%s/native-%u.bin",dir,stride);f=fopen(name,"wb");CHECK(f&&fwrite(mss,1,sizeof(*mss),f)==sizeof(*mss)&&!fclose(f));
    snprintf(name,sizeof(name),"%s/early-%u.bin",dir,stride);f=fopen(name,"wb");CHECK(f&&fwrite(early,1,sizeof(*early),f)==sizeof(*early)&&!fclose(f));
}
int main(int argc,char**argv)
{
    CHECK(argc==3);CHECK(!posix_memalign((void**)&arena,4096,0x100000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned stride=40;stride<=48;stride+=8)for(heap_alloc=1;heap_alloc<=3;heap_alloc++){
        for(heap_fault=0;heap_fault<=13;heap_fault++){
            if(heap_fault==8&&stride==40)continue;
            mss_setup(0,0,stride);unsigned ok=mss_run();scenarios++;
            CHECK(ok==(heap_fault==0));CHECK(at_calls==1026);
            if(ok){
                CHECK(mss_calls==7&&mss->complete&&!mss->unknown);
                CHECK(pmme_delta(&mss->memory,heap_alloc-1,&mss->memory.map[heap_alloc-1],&mss->memory.map[heap_alloc]));
                CHECK(!pwmc_delta_direction(mss->memory.map[heap_alloc-1].data,mss->memory.map[heap_alloc-1].map.bytes,
                    mss->memory.map[heap_alloc].data,mss->memory.map[heap_alloc].map.bytes,stride,
                    mss->memory.claim[heap_alloc-1].requested,mss->memory.claim[heap_alloc-1].bytes,7,2));
                if(heap_alloc==3){
                    write_fixture(argv[2],stride);
                    mss->memory.error=PWEA_DELTA;struct pmmd_difference d={0};pmmd_capture(&mss->memory,&d);CHECK(d.reason==9);
                    uint64_t saved=mss->memory.input.owner.image;mss->memory.input.owner.image=UINT64_C(0x17017b000);
                    CHECK(!pmme_delta(&mss->memory,2,&mss->memory.map[2],&mss->memory.map[3]));
                    mss->memory.input.owner.image=saved;
                    saved=mss->memory.input.owner.bank;mss->memory.input.owner.bank=UINT64_C(0x17017b000);
                    CHECK(!pmme_delta(&mss->memory,2,&mss->memory.map[2],&mss->memory.map[3]));mss->memory.input.owner.bank=saved;
                }
            }else{
                CHECK(mss->unknown&&!mss->complete&&mss_calls==2*heap_alloc+1);
                CHECK(!mss_run()&&mss_calls==2*heap_alloc+1); /* no retry */
            }
        }
    }
    free(original);free(arena);printf("PASS %u MSS descriptor-page checks / %u scenarios; SOFTWARE only\n",checks,scenarios);return 0;
}
