/* Actual incoming UEFI caller with software services/architecture only.
 * Original Core PE is inert identity/hash data. No target RAM is touched. */
#define PWEA_TEST_ENTRY unused_early_suite
#include "polaris-wifi-early-native-test.c"
#undef PWEA_TEST_ENTRY
static int mss_arch(void*,struct pgcd_arch*);
static int mss_save(void*,struct pgcd_fp_guard*);
static int mss_restore(void*,struct pgcd_fp_guard*);
#undef pgcd_actual_arch
#undef pgcd_actual_fp_save
#undef pgcd_actual_fp_restore
#define pgcd_actual_arch mss_arch
#define pgcd_actual_fp_save mss_save
#define pgcd_actual_fp_restore mss_restore
#define EFI_XNU_MSS_MEMORY_AVAILABLE 1
#define POLARIS_MSS_MEMORY_SOFTWARE_PEER 1
#include "uefi-mss-memory.h"
static struct pmmn_native*mss;
static struct pweh_result*held;
static struct pweh_input held_input;
#ifndef PMMN_TEST_ARENA_BYTES
#define PMMN_TEST_ARENA_BYTES 0x100000
#endif
#ifndef PMMN_TEST_IMAGE_BYTES
#define PMMN_TEST_IMAGE_BYTES 0x80000
#endif
#ifndef PMMN_TEST_PAYLOAD_BASE
#define PMMN_TEST_PAYLOAD_BASE UINT64_C(0xd0000000)
#endif
#ifndef PMMN_TEST_PAYLOAD_BYTES
#define PMMN_TEST_PAYLOAD_BYTES 5000
#endif
static uint8_t*mss_digest;
static unsigned mss_fault,mss_trigger,mss_calls,mss_maps,mss_allocs,mss_stride;
_Static_assert(sizeof(struct pmmn_native)<0x1e000,"fixture bounds before digest/native flag");
static int mss_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);
    if(mss_calls==mss_trigger){
        if(mss_fault==30)a->cpu.ttbr0^=4096;
        if(mss_fault==31)a->cpu.ticks+=PGCD_FRESH_TICKS+1;
    }
    if(mss_fault==35&&mss->memory.complete)a->cpacr=0;
    return ok;
}
static int mss_save(void*p,struct pgcd_fp_guard*g)
{int ok=early_save(p,g);return mss_fault==32&&mss_calls==mss_trigger?0:ok;}
static int mss_restore(void*p,struct pgcd_fp_guard*g)
{int ok=early_restore(p,g);return mss_fault==33&&mss_calls==mss_trigger?0:ok;}
static void mss_mutate(void)
{
    if(mss_calls!=mss_trigger)return;
    switch(mss_fault){
    case 1:mss->memory.input.owner.image_bytes--;break;
    case 2:mss->memory.command.pages++;break;
    case 3:mss->memory.map[mss_calls==1?3:0].data[8191]^=1;break;
    case 4:mss->call[mss_calls-1].fp.q8_q15[0]^=1;break;
    case 5:mss->call[mss_calls-1].before.cpu.ttbr0^=4096;break;
    case 6:mss->early=8;break;case 7:mss->digest=8;break;
    case 8:*native_flag=1;break;case 9:early->memory.claim[0].bytes--;break;
    case 10:s->boot=(void*)8;break;case 11:self->bytes--;break;
    case 12:core[0x1010]^=1;break;case 13:put(core+0x1b098,8,8);break;
    case 14:put(core+0x1cb78,8,8);break;
    case 34:efault=35;trigger=core_at_calls+1;break;
    }
}
static void mss_emit(struct pwea_map*m,unsigned*count,unsigned type,uint64_t base,uint64_t bytes)
{
    if(!bytes)return;CHECK(!(bytes&4095)&&*count<30);
    uint8_t*p=m->data+(*count)++*mss_stride;emit_descriptor(p,type,base,bytes);
    if(mss_stride==48)memset(p+40,0x5a,8);
}
static efi_status pmmn_test_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&m==&mss->memory.map[mss_maps]);mss_calls++;mss_maps++;
    unsigned count=0;mss_emit(m,&count,3,(uintptr_t)arena,PMMN_TEST_ARENA_BYTES);
    mss_emit(m,&count,2,UINT64_C(0x180000000),0x10000000);
    struct pwmc_range range[5];unsigned ranges=2+mss_allocs;
    for(unsigned k=0;k<2;k++)range[k]=(struct pwmc_range){early->memory.claim[k].requested,early->memory.claim[k].bytes};
    for(unsigned k=0;k<mss_allocs;k++)range[k+2]=(struct pwmc_range){mss->memory.claim[k].requested,mss->memory.claim[k].bytes};
    for(unsigned k=0;k<ranges;k++)for(unsigned j=k+1;j<ranges;j++)if(range[j].base<range[k].base){struct pwmc_range t=range[k];range[k]=range[j];range[j]=t;}
    uint64_t cursor=0xc0000000;
    for(unsigned k=0;k<ranges;k++){
        CHECK(range[k].base>=cursor);
        mss_emit(m,&count,7,cursor,range[k].base-cursor);
        mss_emit(m,&count,2,range[k].base,range[k].bytes);cursor=range[k].base+range[k].bytes;
    }
    mss_emit(m,&count,7,cursor,UINT64_C(0x100000000)-cursor);
    m->map.bytes=count*mss_stride;m->map.key=20+mss_maps;m->map.stride=mss_stride;m->map.version=1;
#if defined(PMMN_TEST_MAP_EXTRA)
    PMMN_TEST_MAP_EXTRA(m);
#endif
    if(mss_calls==mss_trigger){
        if(mss_fault==20)m->map.bytes=8193;
        if(mss_fault==21)m->map.key=0;
        if(mss_fault==22)m->map.stride=mss_stride+8;
        if(mss_fault==23)((struct efi_memory*)m->data)->attributes^=1;
        if(mss_fault==24&&mss_allocs)for(unsigned k=0;k<count;k++){
            struct efi_memory*d=(void*)(m->data+k*mss_stride);
            if(d->physical==mss->memory.claim[mss_allocs-1].requested)d->type=7;
        }
        if(mss_fault==25&&mss_stride==48)m->data[40]^=1;
        if(mss_fault==29&&mss_maps==1)((struct efi_memory*)(m->data+2*mss_stride))->pages=0x4000;
    }
    mss_mutate();return mss_fault==26&&mss_calls==mss_trigger?EFI_ERROR|9:0;
}
static efi_status pmmn_test_allocate(struct efi_system*system,uint64_t pages,uint64_t*address)
{
    CHECK(system==s&&mss_allocs<3&&pages==(mss_allocs==0?30720:mss_allocs==1?256:3));
    CHECK(*address==mss->memory.command.address);mss_calls++;mss_allocs++;
    if(mss_fault==27&&mss_calls==mss_trigger)*address+=4096;
    mss_mutate();return mss_fault==28&&mss_calls==mss_trigger?EFI_ERROR|9:0;
}
static efi_status pweh_test_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&m==&held->map);
    emit_descriptor(m->data,3,(uintptr_t)arena,PMMN_TEST_ARENA_BYTES);
    emit_descriptor(m->data+40,2,UINT64_C(0x180000000),0x10000000);
    for(unsigned k=0;k<2;k++)emit_descriptor(m->data+80+40*k,2,early->memory.claim[k].requested,early->memory.claim[k].bytes);
    for(unsigned k=0;k<3;k++)emit_descriptor(m->data+160+40*k,2,mss->memory.claim[k].requested,mss->memory.claim[k].bytes);
    emit_descriptor(m->data+280,2,held->payload,held->payload_bytes);
    emit_descriptor(m->data+320,2,held->log,held_input.log_bytes);
    m->map.bytes=360;m->map.stride=40;m->map.key=100;m->map.version=1;
#if defined(PMMN_TEST_RETAINED_MAP_EXTRA)
    PMMN_TEST_RETAINED_MAP_EXTRA(m);
#endif
    put(core+0x1cdb0,m->map.key,8);return 0;
}
static void mss_setup(unsigned f,unsigned at,unsigned stride)
{
    setup(0,0);self->bytes=PMMN_TEST_IMAGE_BYTES;
#if defined(PMMN_TEST_BEFORE_EARLY)
    PMMN_TEST_BEFORE_EARLY();
#endif
    CHECK(run());
#if defined(PMMN_TEST_AFTER_EARLY)
    PMMN_TEST_AFTER_EARLY();
#endif
    mss=(void*)(arena+0x60000);mss_digest=arena+0x7e000;
    pweh_digest(early,sizeof(*early),mss_digest);
    mss_fault=f;mss_trigger=at;mss_calls=mss_maps=mss_allocs=0;mss_stride=stride;
}
static int mss_run(void){return pmmn_run(mss,early,mss_digest,8412);}
static void retained_setup(void)
{
    mss_setup(0,0,40);CHECK(mss_run());held=(void*)(arena+0xa0000);
    held_input=(struct pweh_input){.early=early,.digest=mss_digest,.payload_slot=(void*)(arena+0x7f008),.log_slot=(void*)(arena+0x7f010),
        .state=(void*)(arena+0x7f018),.received=(void*)(arena+0x7f020),.count=(void*)(arena+0x7f028),.logical_bytes=PMMN_TEST_PAYLOAD_BYTES,.log_bytes=16384};
    *(uint8_t**)(uintptr_t)held_input.payload_slot=(void*)PMMN_TEST_PAYLOAD_BASE;
    *(uint8_t**)(uintptr_t)held_input.log_slot=(void*)UINT64_C(0xd1000000);
    *(uint32_t*)(uintptr_t)held_input.state=2;
    *(uint64_t*)(uintptr_t)held_input.received=*(uint64_t*)(uintptr_t)held_input.count=held_input.logical_bytes;
    CHECK(pweh_run(held,&held_input));
}
#ifndef PMMN_TEST_ENTRY
#define PMMN_TEST_ENTRY main
#endif
int PMMN_TEST_ENTRY(int argc,char**argv)
{
    assert(argc==2||argc==3);CHECK(!posix_memalign((void**)&arena,4096,0x100000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned stride=40;stride<=48;stride+=8){
        mss_setup(0,0,stride);CHECK(mss_run());
        CHECK(mss->complete&&!mss->unknown&&mss_calls==7&&mss_maps==4&&mss_allocs==3);
        CHECK(mss->memory.claim[0].requested==0xf8300000&&mss->memory.claim[0].bytes==0x7800000);
        CHECK(mss->memory.claim[1].requested==0xf8200000&&mss->memory.claim[1].bytes==0x100000);
        CHECK(mss->memory.claim[2].requested==0xffbfb000&&mss->memory.claim[2].bytes==0x3000&&mss->memory.claim[2].exposed_bytes==8412);
        CHECK(at_calls==1026); /* Only old producer ATs; MSS target pages NOT touched. */
        CHECK(!mss_run()&&mss_calls==7);
    }
    for(unsigned call=1;call<=7;call++)for(unsigned kind=1;kind<=14;kind++){
        mss_setup(kind,call,40);CHECK(!mss_run()&&mss->unknown&&!mss->complete&&mss_calls==call);
        CHECK(!mss_run()&&mss_calls==call&&at_calls==1026);
    }
    for(unsigned call=1;call<=7;call+=2)for(unsigned kind=20;kind<=26;kind++){
        if((kind==23||kind==24||kind==25)&&call==1)continue;
        mss_setup(kind,call,48);CHECK(!mss_run()&&mss->unknown&&mss_calls==call&&!mss->complete);
    }
    for(unsigned call=2;call<=6;call+=2)for(unsigned kind=27;kind<=28;kind++){
        mss_setup(kind,call,40);CHECK(!mss_run()&&mss->unknown&&mss_calls==call);
    }
    mss_setup(29,1,40);CHECK(!mss_run()&&mss->unknown&&mss_calls==1&&!mss_allocs);
    for(unsigned kind=30;kind<=34;kind++)for(unsigned call=kind==32?0:1;call<=(kind==32?6:7);call++){
        mss_setup(kind,call,40);CHECK(!mss_run()&&mss->unknown&&mss_calls==call);
    }
    mss_setup(35,0,40);CHECK(!mss_run()&&mss->unknown&&mss_calls==7&&!mss->complete);
    mss_setup(0,0,40);mss_digest[0]^=1;CHECK(!mss_run()&&mss->unknown&&!mss_calls);
    retained_setup();uint8_t digest[32];pweh_digest(mss,sizeof(*mss),digest);
    CHECK(pmmn_retained(mss,digest,held)&&at_calls==2052);
    if(argc==3){
        FILE*out=fopen(argv[2],"wb");CHECK(out&&fwrite(mss,1,sizeof(*mss),out)==sizeof(*mss)&&!fclose(out));
        char name[4096];CHECK(snprintf(name,sizeof(name),"%s.early",argv[2])<(int)sizeof(name));
        out=fopen(name,"wb");CHECK(out&&fwrite(early,1,sizeof(*early),out)==sizeof(*early)&&!fclose(out));
        CHECK(snprintf(name,sizeof(name),"%s.retained",argv[2])<(int)sizeof(name));
        out=fopen(name,"wb");CHECK(out&&fwrite(held,1,sizeof(*held),out)==sizeof(*held)&&!fclose(out));
    }
    for(unsigned n=0;n<14;n++){
        retained_setup();pweh_digest(mss,sizeof(*mss),digest);
        if(n<3)((struct efi_memory*)(held->map.data+160+40*n))->type=7;
        else if(n<6)((struct efi_memory*)(held->map.data+160+40*(n-3)))->pages--;
        else if(n==6)mss->memory.claim[0].requested+=0x100000;
        else if(n==7)digest[0]^=1;
        else if(n==8)held->unknown=1;
        else if(n==9)held->input.early=(void*)8;
        else if(n==10)held->input.digest=(void*)8;
        else if(n==11)held->payload=mss->memory.claim[1].requested;
        else if(n==12)held->log=mss->memory.claim[2].requested;
        else held->before.cpu.ticks=mss->final.cpu.ticks-1;
        CHECK(!pmmn_retained(mss,digest,held));
    }
    free(original);free(arena);printf("PASS %u actual MSS allocation checks (software services only)\n",checks);return 0;
}
