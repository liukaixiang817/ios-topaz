/* Actual C reader with explicit SOFTWARE map/AT/FP/clock/container peers.
 * No original PE instruction, FreePool or whole parent constructor executes. */
#define main inert_GCD_base_fixture_main
#include "polaris-uefi-gcd-test.c"
#undef main
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#include "uefi-wifi-cache-allocation.h"
static struct pwmc_parent_map*call;
static struct pbgi_result*seed;
static struct ppli_result*images;
static struct pbha_result*allocation;
static struct pbha_input input;
static volatile uint32_t*native;
static uint8_t*pool,*block,*payload_page,*log_page,*output;
static unsigned mode,ATs,clocks,FWmaps,bad,at_fault,clock_fault,attack,attack_byte,triggered;
static void inject(void)
{
    if(!attack||triggered)return;triggered=1;
    if(attack==1)((uint8_t*)&allocation->input)[attack_byte]^=1;
    else if(attack==2)allocation->container=8;
    else if(attack==3)input.seed=(void*)8;
    else if(attack==4)seed->call.input.system=(void*)8;
    else if(attack==5)images->handles=8;
    else if(attack==6)block[40]^=1;
    else if(attack==7)pool[0x10000+24+48]^=1;
    else if(attack==8)allocation->raw[attack_byte]^=1;
    else if(attack==9)seed->clock[0].raw.cpu.ticks++;
    else if(attack==10)images->maps[1][65535]^=1;
    else if(attack==11)seed->node[1][255].raw[0]=1;
    else assert(0);
}
static int clock_peer(void*o,struct pgcd_arch*a)
{
    int ok=arch(o,a);if(!mode)return ok;clocks++;
    if(bad>=10&&clock_fault==clocks){
        if(bad==10)a->cpu.ticks=1000+PGCD_FRESH_TICKS+1;
        else if(bad==11)return 0;else if(bad==12)*native=1;
        else if(bad==13)a->cpu.ticks=1000;else assert(0);
    }
    if(!at_fault&&(!clock_fault||clock_fault==clocks))inject();return ok;
}
static int page_peer(struct ppli_at*a)
{
    a->saved=a->restored=0x123400;a->par=UINT64_C(0xff00000000000b80)|a->page;a->issued=a->returned=1;
    if(!mode)return 1;ATs++;
    if(ATs==at_fault){
        if(bad==1)return 0;if(bad==2)a->returned=0;if(bad==3)*native=1;
        if(bad==4)a->restored++;if(bad==5)seed->node[0][0].address=8;
        if(bad==6)put(core+0x1cdb0,1235,8);inject();
    }return 1;
}
static int map_peer(void*o,struct efi_system*sys,struct pgcd_map*m,void*out)
{
    (void)o;assert(sys==s);FWmaps++;
    struct efi_memory row[6]={{3,0,(uintptr_t)arena,0,0x80,8},{4,0,(uintptr_t)pool,0,0x40,8},
        {3,0,(uintptr_t)self->base,0,0x600,8},{2,0,0xc0000000,0,512,8},
        {2,0,(uintptr_t)payload_page,0,1,8},{2,0,(uintptr_t)log_page,0,1,8}};
    for(unsigned k=0;k<6;k++){memcpy((uint8_t*)out+k*48,&row[k],40);memset((uint8_t*)out+k*48+40,0x5a,8);}
    m->status=0;m->bytes=288;m->key=1234;m->stride=48;m->version=1;return 1;
}
/* Test-only peer selection lets the release test use the same initial
 * producer/metadata/target construction. Defaults keep every old case. */
static int(*allocation_fixture_arch)(void*,struct pgcd_arch*)=clock_peer;
static int(*allocation_fixture_page)(struct ppli_at*)=page_peer;
static int(*allocation_fixture_fp_save)(void*,struct pgcd_fp_guard*)=fp_save;
static int(*allocation_fixture_fp_restore)(void*,struct pgcd_fp_guard*)=fp_restore;
static void(*allocation_fixture_order)(void*)=order;
static unsigned allocation_fixture_target_offset,allocation_fixture_GCD_offset=0x10000,allocation_fixture_empty_bins;
static void setup(unsigned count,unsigned bytes,unsigned cross)
{
    reset(0);memset(arena+0x80000,0,0x780000);pool=arena+0x80000;mode=0;
    self->base=arena+0x100000;self->bytes=0x600000;
    call=(void*)(arena+0x180000);seed=(void*)(arena+0x200000);images=(void*)(arena+0x280000);
    allocation=(void*)(arena+0x2d0000);native=(void*)(arena+0x170000);output=arena+0x100000;
    block=pool+0x8000+allocation_fixture_target_offset+(cross?0xf80:0);memset(block,0xa7,bytes);
    put(block,0x30646870,4);put(block+8,4,4);put(block+16,bytes,8);
    put(block+bytes-16,0x6c617470,4);put(block+bytes-8,bytes,8);
    uint64_t*handles=(void*)(block+24);
    for(unsigned k=0;k<count;k++)handles[k]=0x123+k;
    uint64_t head=(uintptr_t)core+0x1b358;
    uint64_t low[6]={(uintptr_t)arena,(uintptr_t)pool,(uintptr_t)self->base,0xc0000000,(uintptr_t)payload_page,(uintptr_t)log_page};
    uint64_t length[6]={0x80000,0x40000,0x600000,0x200000,4096,4096};unsigned type[6]={3,4,3,2,2,2};
    for(unsigned k=0;k<6;k++){
        uint8_t*b=pool+k*4096;put(b,0x70616d6d,8);put(b+8,k==5?head:(uintptr_t)(b+4096)+8,8);
        put(b+16,k?(uintptr_t)(b-4096)+8:head,8);b[24]=1;put(b+28,type[k],4);put(b+32,low[k],8);put(b+40,low[k]+length[k]-1,8);put(b+56,8,8);
    }
    put(core+0x1b358,(uintptr_t)pool+8,8);put(core+0x1b360,(uintptr_t)pool+5*4096+8,8);
    uint8_t*h=pool+allocation_fixture_GCD_offset,*g=h+24;head=(uintptr_t)core+0x1bd60;
    put(h,0x30646870,4);put(h+8,4,4);put(h+16,120,8);put(g,0x6d646367,8);put(g+8,head,8);put(g+16,head,8);
    put(g+24,0,8);put(g+32,0xfffff,8);put(g+40,8,8);put(g+48,8,8);put(g+56,2,4);
    put(h+104,0x6c617470,4);put(h+112,120,8);put(core+0x1bd60,(uintptr_t)g+8,8);put(core+0x1bd68,(uintptr_t)g+8,8);
    for(unsigned k=0;k<3;k++){unsigned at=k==0?0x1b340:k==1?0x1bd48:0x1c1f8;put(core+at,16,8);put(core+at+8,4,8);put(core+at+16,1,4);}
    put(core+0x1cdb0,1234,8);put(core+0x1cc08,0,8);put(core+0x1dc10,0,8);put(core+0x1cb78,0,8);
    put(core+0x1d1a8,120+bytes,8);put(core+0x1d1b0,4,4);
    if(allocation_fixture_empty_bins)for(unsigned k=0;k<12;k++){
        uint64_t at=(uintptr_t)core+0x1d1a0+24+16*k;put((void*)(uintptr_t)at,at,8);put((void*)(uintptr_t)(at+8),at,8);
    }
    struct pgcd_io io={.system=s,.arch=allocation_fixture_arch,.map=map_peer,.fp_save=allocation_fixture_fp_save,.fp_restore=allocation_fixture_fp_restore,.order=allocation_fixture_order};
    struct pwmc_parent_input ci={.system=s,.image=self,.native_flag=native,.output=output,.capacity=65536,.image_handle=0x123,
        .phase=4,.bank=0xc0000000,.bank_bytes=0x200000,.payload=(uintptr_t)payload_page,.payload_bytes=4096,.log_snapshot=(uintptr_t)log_page,.log_snapshot_bytes=4096};
    FWmaps=0;assert(pwmc_parent_map_call_window(call,&ci,&io,1000)&&FWmaps==1);
    assert(ppli_bind(images,native,0x123)&&ppli_start(images,(uintptr_t)s,(uintptr_t)handles,count,call->data,288,48,1234,1000,page_peer));
    for(unsigned pass=0;pass<2;pass++){
        if(pass)assert(ppli_second(images,call->data,288,48,1234,page_peer));
        for(unsigned k=0;k<count;k++){
            struct efi_loaded*im=k?(void*)(arena+0x4b100+128*k):self;
            if(k)*im=(struct efi_loaded){.revision=0x1000,.system=s,.base=arena,.bytes=0x80000,.code_type=3,.data_type=4};
            assert(ppli_capture(images,pass,k,handles[k],(uintptr_t)im,page_peer));
        }
    }
    struct pbgi_input si={.call=call,.native=native,.opening=1000,.io=io};assert(pbgi_capture(seed,&si,page_peer));
    input=(struct pbha_input){seed,images,(uintptr_t)handles,count,allocation_fixture_page};
    ATs=clocks=bad=at_fault=clock_fault=attack=attack_byte=triggered=0;mode=1;
}
static int run(void){return pbha_capture(allocation,&input);}
static void bundle(const char*name)
{
    FILE*out=fopen(name,"wb");assert(out&&fwrite(allocation,1,sizeof(*allocation),out)==sizeof(*allocation)&&
        fwrite(seed,1,sizeof(*seed),out)==sizeof(*seed)&&fwrite(images,1,sizeof(*images),out)==sizeof(*images)&&!fclose(out));
}
#ifndef POLARIS_CACHE_ALLOCATION_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert((argc==3||argc==4)&&!posix_memalign((void**)&arena,4096,0x801000));
    assert(!posix_memalign((void**)&payload_page,4096,4096)&&!posix_memalign((void**)&log_page,4096,4096));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;
    for(unsigned n=1;n<=256;n=n==1?3:n==3?256:257)for(unsigned cross=0;cross<2;cross++){
        setup(n,40+8*n,cross);int ok=run();if(!ok)fprintf(stderr,"positive n%u err%u AT%u arch%u/%u\n",n,allocation->error,ATs,allocation->arch_issued,allocation->arch_returned);
        assert(ok&&allocation->complete&&!allocation->unknown&&allocation->bytes==40+8*n&&FWmaps==1&&ppli_live(images));checks++;
    }
    setup(256,2088,1);assert(run());if(argc==4)bundle(argv[3]);
    setup(3,2088,1);assert(run()&&allocation->capacity==2048&&allocation->input.count==3);unsigned total=ATs,clock_total=clocks;
    bundle(argv[2]);checks++;
    unsigned stopped=ATs;assert(!run()&&ATs==stopped);checks++;
    for(unsigned kind=1;kind<=6;kind++)for(unsigned point=1;point<=total;point++){
        setup(3,2088,1);bad=kind;at_fault=point;
        assert(!run()&&allocation->unknown&&!allocation->complete&&ATs==point&&FWmaps==1);checks++;
    }
    for(unsigned kind=10;kind<=13;kind++)for(unsigned point=1;point<=3;point++){
        setup(3,2088,1);bad=kind;clock_fault=point;assert(!run()&&allocation->unknown&&clocks==point&&FWmaps==1);checks++;
    }
    for(unsigned k=0;k<sizeof(input);k++){
        setup(3,2088,1);attack=1;attack_byte=k;assert(!run()&&triggered&&!ATs&&clocks==1&&allocation->unknown);checks++;
    }
    for(unsigned kind=2;kind<=5;kind++){
        setup(3,2088,1);attack=kind;at_fault=60;assert(!run()&&triggered&&ATs==60&&allocation->unknown);checks++;
    }
    for(unsigned kind=6;kind<=7;kind++){
        setup(3,2088,1);attack=kind;clock_fault=clock_total;assert(!run()&&triggered&&ATs==total&&allocation->unknown);checks++;
    }
    for(unsigned kind=9;kind<=11;kind++){
        setup(3,2088,1);attack=kind;clock_fault=2;assert(!run()&&triggered&&ATs==total&&allocation->unknown);checks++;
    }
    for(unsigned k=0;k<24;k++){
        setup(3,2088,1);attack=8;attack_byte=k;clock_fault=clock_total;assert(!run()&&triggered&&allocation->unknown);checks++;
    }
    for(unsigned kind=0;kind<15;kind++){
        setup(3,2088,1);
        switch(kind){case 0:put(block,0,4);break;case 1:put(block+8,3,4);break;case 2:put(block+16,40,8);break;
        case 3:put(block+16,56,8);break;case 4:put(block+16,2089,8);break;case 5:put(block+16,2096,8);break;
        case 6:put(block+2088-16,0,4);break;case 7:put(block+2088-8,2080,8);break;
        case 8:input.handles+=8;break;case 9:input.count=257;break;case 10:input.page=0;break;
        case 11:images->complete=1;break;case 12:put(core+0x1d1a8,0,8);break;
        case 13:seed->count[1]=0;break;case 14:((uint64_t*)(block+24))[1]++;break;default:assert(0);}
        assert(!run()&&allocation->unknown&&!allocation->complete&&FWmaps==1);checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"record_bytes\":%zu,\"input_bytes\":%zu,\"raw_offset\":%zu,\"clock_offset\":%zu,\"digest_offset\":%zu,\"normal_ATs\":%u,\"normal_clocks\":%u,\"SOFTWARE_only\":true,\"FreePool_executed\":false,\"later_consumer_admission\":false}\n",checks,sizeof(*allocation),sizeof(input),offsetof(struct pbha_result,raw),offsetof(struct pbha_result,clock),offsetof(struct pbha_result,digest),total,clock_total);
    free(original);free(arena);free(payload_page);free(log_page);return 0;
}
#endif
