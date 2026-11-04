/* Real early caller with explicit SOFTWARE leaves. Original Core PE is inert
 * relocation/hash DATA; no original instruction, privileged AT/FP or USB runs. */
#define main unused_original_gcd_fixture
#include "polaris-uefi-gcd-test.c"
#undef main
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#include "../shim/polaris/uefi-wifi-remote-memory.h"
static int early_arch(void*,struct pgcd_arch*);
static int early_save(void*,struct pgcd_fp_guard*);
static int early_restore(void*,struct pgcd_fp_guard*);
static int early_translate(struct pwmc_translation*);
static void early_order(void*);
#define pgcd_actual_arch early_arch
#define pgcd_actual_fp_save early_save
#define pgcd_actual_fp_restore early_restore
#define pwmc_actual_translate early_translate
#define pwfc_actual_order early_order
#define EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE 1
#define POLARIS_WIFI_EARLY_SOFTWARE_PEER 1
#include "uefi-wifi-early-native.h"
static struct pwea_native*early;
static unsigned checks,efault,trigger,api_calls,alloc_calls,map_calls,at_calls,core_at_calls;
static volatile uint32_t*native_flag;
#define CHECK(x) do{assert(x);checks++;}while(0)
_Static_assert(sizeof(struct pwea_native)<0x30000,"fixture resident bounds");
static int early_arch(void*p,struct pgcd_arch*a)
{
    int ok=arch(p,a);
    if(efault==30&&api_calls==trigger)a->cpu.daif=0x80;
    if(efault==31&&api_calls==trigger)a->cpu.ticks+=PGCD_FRESH_TICKS+1;
    if(efault==32&&at_calls==1026)a->cpu.ttbr0^=4096;
    return ok;
}
static int early_save(void*p,struct pgcd_fp_guard*g)
{if(efault==33&&api_calls==trigger)return 0;return fp_save(p,g);}
static int early_restore(void*p,struct pgcd_fp_guard*g)
{if(efault==34&&api_calls==trigger)return 0;return fp_restore(p,g);}
static void early_order(void*p){(void)p;}
static int pwea_test_core_at(struct pwmc_irq_AT*a)
{
    core_at_calls++;a->issued=1;
    if(efault==35&&core_at_calls==trigger)return 0;
    a->raw=UINT64_C(0xff00000000000b80)|a->page;a->returned=1;
    if(efault==36&&core_at_calls==trigger)a->raw^=0x1000;
    return 1;
}
static int early_translate(struct pwmc_translation*a)
{
    at_calls++;a->saved=a->restored=0x1234;a->read_issued=a->read_returned=a->write_issued=a->write_returned=1;
    a->read_par=a->write_par=UINT64_C(0xff00000000000b80)|a->page;
    if(efault==37&&at_calls==trigger)a->write_par|=1;
    if(efault==38&&at_calls==trigger){a->write_returned=0;return 0;}
    return 1;
}
static void mutate(void)
{
    if(api_calls!=trigger)return;
    switch(efault){
    case 1:early->memory.input.image_bytes--;break;
    case 2:early->memory.command.pages++;break;
    case 3:early->memory.map[2].data[8191]^=1;break;
    case 4:early->call[api_calls-1].fp.q8_q15[0]^=1;break;
    case 5:early->call[api_calls-1].before.cpu.ttbr0^=4096;break;
    case 6:early->image_address=8;break;
    case 7:s->boot=(void*)8;break;
    case 8:*native_flag=1;break;
    case 9:self->bytes--;break;
    case 10:put(core+0x1b838,(uintptr_t)core+0xd3f0,8);break;
    case 11:core[0x1010]^=1;break;
    case 12:put(core+0x1b098,8,8);break;
    case 13:put(core+0x1cb78,8,8);break;
    default:break;
    }
}
static void emit_descriptor(uint8_t*out,unsigned type,uint64_t base,uint64_t bytes)
{struct efi_memory m={.type=type,.physical=base,.pages=bytes/4096,.attributes=8};memcpy(out,&m,sizeof(m));}
static efi_status pwea_test_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&m==&early->memory.map[map_calls]);api_calls++;
    unsigned slot=map_calls++;uint64_t split=slot?early->memory.claim[slot-1].requested:UINT64_C(0x100000000);
    emit_descriptor(m->data,3,(uintptr_t)arena,0x100000);
    emit_descriptor(m->data+40,2,UINT64_C(0x180000000),0x10000000);
    emit_descriptor(m->data+80,7,0xc0000000,split-0xc0000000);
    if(slot)emit_descriptor(m->data+120,2,split,UINT64_C(0x100000000)-split);
    m->map.bytes=(slot?4:3)*40;m->map.key=10+slot;m->map.stride=40;m->map.version=1;
    if(efault==20&&api_calls==trigger)m->map.bytes=8193;
    if(efault==21&&api_calls==trigger&&slot)((struct efi_memory*)(m->data+120))->type=7;
    if(efault==22&&api_calls==trigger)m->map.key=0;
    mutate();return efault==23&&api_calls==trigger?EFI_ERROR|9:0;
}
static efi_status pwea_test_allocate(struct efi_system*system,uint64_t pages,uint64_t*address)
{
    CHECK(system==s&&alloc_calls<2&&pages==(alloc_calls?514:512));api_calls++;alloc_calls++;
    CHECK(*address==early->memory.command.address);
    if(efault==24&&api_calls==trigger)*address+=4096;
    mutate();return efault==25&&api_calls==trigger?EFI_ERROR|9:0;
}
static void setup(unsigned f,unsigned t)
{
    memset(arena,0,0x100000);core=arena;memcpy(core,original,PGCI_IMAGE_BYTES);
    for(unsigned n=0;n<PGCI_RELOC_COUNT;n++)put(core+pgci_relocations[n],pwfi_le(core+pgci_relocations[n],8)+(uintptr_t)core,8);
    early=(void*)(arena+0x40000);native_flag=(void*)(arena+0x7f000);
    s=(void*)(arena+0x90000);self=(void*)(arena+0x91000);s->boot=(void*)(core+0x1b800);
    *self=(struct efi_loaded){.revision=0x1000,.system=s,.base=arena+0x40000,.bytes=0x40000,.code_type=3,.data_type=4};
    put(core+0x1b098,4,8);put(core+0x1cb78,0,8);
    efault=f;trigger=t;fault=queries=arches=saves=restores=0;api_calls=alloc_calls=map_calls=at_calls=core_at_calls=0;
}
static int run(void)
{return pwea_native_run(early,s,self,native_flag,UINT64_C(0x180000000),0x10000000);}
#ifndef PWEA_TEST_ENTRY
#define PWEA_TEST_ENTRY main
#endif
int PWEA_TEST_ENTRY(int argc,char**argv)
{
    assert(argc==2||argc==3);CHECK(!posix_memalign((void**)&arena,4096,0x100000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    setup(0,0);CHECK(run());CHECK(early->complete&&!early->unknown&&api_calls==5&&map_calls==3&&alloc_calls==2);
    CHECK(saves==5&&restores==5&&at_calls==1026&&early->translated[0]==512&&early->translated[1]==514);
    CHECK(core_at_calls==9*PWEA_CORE_PAGES&&early->final.cpu.ticks>early->call[4].after.cpu.ticks);
    if(argc==3){FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(early,1,sizeof(*early),out)==sizeof(*early)&&!fclose(out));}
    CHECK(!run()&&api_calls==5); /* No replay of a completed producer. */
    for(unsigned n=1;n<=5;n++)for(unsigned kind=1;kind<=13;kind++){
        if(kind==3&&n==5)continue; /* current map capacity is allowed output */
        setup(kind,n);CHECK(!run());CHECK(early->unknown&&!early->complete&&api_calls==n);
        CHECK(!at_calls);
    }
    for(unsigned n=1;n<=5;n+=2)for(unsigned kind=20;kind<=23;kind++){
        if(kind==21&&n==1)continue;
        setup(kind,n);CHECK(!run()&&early->unknown&&api_calls==n&&!at_calls);
    }
    for(unsigned n=2;n<=4;n+=2)for(unsigned kind=24;kind<=25;kind++){
        setup(kind,n);CHECK(!run()&&early->unknown&&api_calls==n&&!at_calls);
    }
    for(unsigned kind=30;kind<=31;kind++)for(unsigned n=1;n<=5;n++){
        setup(kind,n);CHECK(!run()&&early->unknown&&api_calls==n);
    }
    setup(32,0);CHECK(!run()&&early->unknown&&at_calls==1026&&!early->complete);
    for(unsigned n=0;n<5;n++){setup(33,n);CHECK(!run()&&early->unknown&&api_calls==n);}
    for(unsigned n=1;n<=5;n++){setup(34,n);CHECK(!run()&&early->unknown&&api_calls==n);}
    for(unsigned kind=35;kind<=36;kind++){
        setup(kind,1);CHECK(!run()&&early->unknown&&api_calls==1&&core_at_calls==1);
    }
    for(unsigned kind=37;kind<=38;kind++)for(unsigned position=0;position<3;position++){
        unsigned at=position==0?1:position==1?513:1026;
        setup(kind,at);CHECK(!run()&&early->unknown&&api_calls==5&&at_calls==at&&!early->complete);
    }
    free(original);free(arena);printf("PASS %u actual early caller checks (software leaves only)\n",checks);return 0;
}
