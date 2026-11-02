/* SOFTWARE producer at one actual-ABI map call. Original PE is DATA only;
 * all BS, AT/PAR, clocks, FP and runtime-initialized fields are explicit peers.
 * This is not first-private-call or whole-parent temporal/ownership admission. */
#define main inert_original_GCD_fixture_main
#include "polaris-uefi-gcd-test.c"
#undef main
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#include "uefi-wifi-gcd-bootstrap.h"
static struct pbgi_result*seed;static struct pwmc_parent_map*producer;static struct pbgi_input seed_input;
static volatile uint32_t*nflag;static uint8_t*outmap,*pbytes,*lbytes,*pool;
static unsigned ATs,FWmaps,scenario,at_fault,clock_fault,clock_calls,mutbyte,mutation,triggered,mut_clock;
static int producer_map(void*o,struct efi_system*sys,struct pgcd_map*m,void*out)
{
    (void)o;assert(sys==s);FWmaps++;
    struct efi_memory rows[6]={{3,0,(uintptr_t)arena,0,0x80,8},{4,0,(uintptr_t)pool,0,0x40,8},
        {3,0,(uintptr_t)self->base,0,self->bytes/4096,8},{2,0,0xc0000000,0,512,8},
        {2,0,(uintptr_t)pbytes,0,1,8},{2,0,(uintptr_t)lbytes,0,1,8}};
    for(unsigned n=0;n<6;n++){memcpy((uint8_t*)out+48*n,&rows[n],40);memset((uint8_t*)out+48*n+40,0x5a,8);}
    m->status=0;m->bytes=sizeof(rows)/sizeof(rows[0])*48;m->key=1234;m->stride=48;m->version=1;return 1;
}
static void inject(void)
{
    if(triggered||!mutation)return;triggered=1;
    switch(mutation){case 1:((uint8_t*)&seed->input)[mutbyte]^=1;break;case 2:seed_input.call=(void*)8;break;
    case 3:seed->node[0][0].address=8;break;case 4:seed->node[1][200].raw[0]=1;break;
    case 5:seed->call.data[65535]=producer->data[65535]=1;break;
    case 6:s->boot=(void*)8;producer->boot_address=8;break;
    case 7:pool[0x10000+24+48]^=1;break;case 8:core[0x1000]^=1;break;
    case 9:seed->node[1][0].raw[mutbyte]^=1;break;case 10:seed->node[0][0].raw[mutbyte]^=1;break;
    case 11:seed->type_policy[mutbyte]^=1;break;default:assert(0);}
}
static int seed_arch(void*o,struct pgcd_arch*a)
{
    clock_calls++;int ok=arch(o,a);
    if(clock_fault==clock_calls){if(scenario==10)a->cpu.ticks=1000+PGCD_FRESH_TICKS+1;
        else if(scenario==11)return 0;else if(scenario==12)a->cpu.daif=0x80;else if(scenario==13)*nflag=1;else assert(0);}
    if(mutation&&at_fault==0&&(!mut_clock||clock_calls==mut_clock))inject();return ok;
}
static int seed_page(struct ppli_at*a)
{
    ATs++;a->saved=a->restored=0x123400;a->par=UINT64_C(0xff00000000000b80)|a->page;a->issued=a->returned=1;
    if(ATs==at_fault){
        switch(scenario){case 0:break;case 1:*nflag=1;break;case 2:a->returned=0;break;
        case 3:a->restored++;break;case 4:put(core+0x1cdb0,1235,8);break;case 5:core[0x1000]^=1;break;
        case 6:a->par^=0x200;break;case 7:put(core+0x1bd48+16,2,4);break;default:assert(0);}
        inject();
    }return 1;
}
static void fixture(unsigned gcd_nodes,unsigned cross_page)
{
    reset(0);memset(arena+0x80000,0,0x780000);pool=arena+0x80000;
    self->base=arena+0x100000;self->bytes=0x600000;
    producer=(void*)(arena+0x180000);seed=(void*)(arena+0x200000);nflag=(void*)(arena+0x170000);outmap=arena+0x100000;
    assert((uint8_t*)seed+sizeof(*seed)<arena+0x600000);
    uint64_t heads[2]={(uintptr_t)core+0x1b358,(uintptr_t)core+0x1bd60};
    uint64_t lows[6]={(uintptr_t)arena,(uintptr_t)pool,(uintptr_t)self->base,0xc0000000,(uintptr_t)pbytes,(uintptr_t)lbytes};
    uint64_t lengths[6]={0x80000,0x40000,self->bytes,0x200000,4096,4096};unsigned types[6]={3,4,3,2,2,2};
    uint64_t nodes[6];for(unsigned k=0;k<6;k++)nodes[k]=(uintptr_t)pool+(cross_page?0xff0:0)+k*4096;
    for(unsigned k=0;k<6;k++){
        uint8_t*b=(void*)(uintptr_t)nodes[k];put(b,0x70616d6d,8);put(b+8,k==5?heads[0]:nodes[k+1]+8,8);
        put(b+16,k?nodes[k-1]+8:heads[0],8);b[24]=1;put(b+28,types[k],4);
        put(b+32,lows[k],8);put(b+40,lows[k]+lengths[k]-1,8);put(b+56,8,8);
    }put(core+0x1b358,nodes[0]+8,8);put(core+0x1b360,nodes[5]+8,8);
    for(unsigned k=0;k<gcd_nodes;k++){
        uint8_t*h=pool+0x10000+128*k,*b=h+24;
        put(h,0x30646870,4);put(h+8,4,4);put(h+16,120,8);
        put(b,0x6d646367,8);put(b+8,k+1==gcd_nodes?heads[1]:(uintptr_t)(h+128)+32,8);
        put(b+16,k?(uintptr_t)(h-128)+32:heads[1],8);put(b+24,k*UINT64_C(0x100000),8);
        put(b+32,(k+1)*UINT64_C(0x100000)-1,8);put(b+40,8,8);put(b+48,8,8);put(b+56,2,4);
        put(h+104,0x6c617470,4);put(h+112,120,8);
    }
    put(core+0x1bd60,gcd_nodes?(uintptr_t)(pool+0x10000)+32:heads[1],8);
    put(core+0x1bd68,gcd_nodes?(uintptr_t)(pool+0x10000+128*(gcd_nodes-1))+32:heads[1],8);
    for(unsigned k=0;k<3;k++){unsigned off=k==0?0x1b340:k==1?0x1bd48:0x1c1f8;put(core+off,16,8);put(core+off+8,4,8);put(core+off+16,1,4);}
    put(core+0x1cdb0,1234,8);put(core+0x1cc08,0,8);put(core+0x1dc10,0,8);put(core+0x1cb78,0,8);
    put(core+0x1d1a0+8,UINT64_C(120)*gcd_nodes,8);put(core+0x1d1a0+16,4,4);
    struct pgcd_io io={.system=s,.arch=seed_arch,.map=producer_map,.fp_save=fp_save,.fp_restore=fp_restore,.order=order};
    struct pwmc_parent_input in={.system=s,.image=self,.native_flag=nflag,.output=outmap,.capacity=65536,.image_handle=0x123,
        .phase=4,.bank=0xc0000000,.bank_bytes=0x200000,.payload=(uintptr_t)pbytes,.payload_bytes=4096,.log_snapshot=(uintptr_t)lbytes,.log_snapshot_bytes=4096};
    ATs=FWmaps=clock_calls=scenario=at_fault=clock_fault=mutation=triggered=mut_clock=0;
    assert(pwmc_parent_map_call_window(producer,&in,&io,1000)&&FWmaps==1);
    seed_input=(struct pbgi_input){.call=producer,.native=nflag,.opening=1000,.io=io};clock_calls=0;
}
static int run_seed(void){return pbgi_capture(seed,&seed_input,seed_page);}
int main(int argc,char**argv)
{
    assert((argc==3||argc==4)&&!posix_memalign((void**)&arena,4096,0x801000));
    assert(!posix_memalign((void**)&pbytes,4096,4096)&&!posix_memalign((void**)&lbytes,4096,4096));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");
    assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned checks=0;
    const unsigned counts[3]={1,3,256};
    for(unsigned cno=0;cno<3;cno++)for(unsigned cross=0;cross<2;cross++){
        fixture(counts[cno],cross);int ok=run_seed();
        if(!ok)fprintf(stderr,"positive count%u cross%u error%u AT%u Core%u map%u GCD%u arch%u/%u\n",counts[cno],cross,seed->error,ATs,seed->core_pages,seed->count[0],seed->count[1],seed->arch_issued,seed->arch_returned);
        assert(ok&&seed->complete&&!seed->unknown&&seed->count[0]==6&&seed->count[1]==counts[cno]&&FWmaps==1);checks++;
    }
    if(argc==4){FILE*max=fopen(argv[3],"wb");assert(max&&fwrite(seed,1,sizeof(*seed),max)==sizeof(*seed)&&!fclose(max));}
    fixture(3,1);assert(run_seed());unsigned total=ATs;
    FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(seed,1,sizeof(*seed),out)==sizeof(*seed)&&!fclose(out));checks++;
    for(unsigned bad=1;bad<=7;bad++)for(unsigned prefix=1;prefix<=total;prefix++){
        fixture(3,1);scenario=bad;at_fault=prefix;assert(!run_seed()&&seed->unknown&&!seed->complete&&FWmaps==1);
        if(bad==5)assert(ATs==(prefix<=PBGI_CORE_PAGES+1?PBGI_CORE_PAGES+1:total)&&seed->error==(prefix<=PBGI_CORE_PAGES+1?3u:5u));
        else if(bad==7&&prefix<=PBGI_CORE_PAGES+1)assert(ATs==PBGI_CORE_PAGES+1&&seed->error==3);
        else assert(ATs==prefix);
        checks++;
    }
    for(unsigned bad=10;bad<=13;bad++)for(unsigned prefix=1;prefix<=3;prefix++){
        fixture(3,1);scenario=bad;clock_fault=prefix;assert(!run_seed()&&seed->unknown&&clock_calls==prefix&&FWmaps==1);checks++;
    }
    for(unsigned byte=0;byte<sizeof(seed_input);byte++){
        fixture(3,1);mutation=1;mutbyte=byte;assert(!run_seed()&&triggered&&seed->unknown&&!ATs);checks++;
    }
    for(unsigned bad=2;bad<=6;bad++){
        fixture(3,1);mutation=bad;at_fault=65;assert(!run_seed()&&triggered&&seed->unknown&&FWmaps==1);checks++;
    }
    for(unsigned bad=7;bad<=8;bad++){
        fixture(3,1);mutation=bad;mut_clock=total+3;
        assert(!run_seed()&&triggered&&seed->unknown&&seed->error==5&&FWmaps==1);checks++;
    }
    for(unsigned byte=0;byte<120;byte++){
        fixture(3,1);mutation=9;mutbyte=byte;at_fault=72;
        assert(!run_seed()&&triggered&&ATs==72&&seed->unknown&&FWmaps==1);checks++;
    }
    for(unsigned byte=0;byte<64;byte++){
        fixture(3,1);mutation=10;mutbyte=byte;at_fault=61;
        assert(!run_seed()&&triggered&&ATs==61&&seed->unknown&&FWmaps==1);checks++;
    }
    for(unsigned byte=0;byte<720;byte++){
        fixture(3,1);mutation=11;mutbyte=byte;at_fault=59;
        assert(!run_seed()&&triggered&&ATs==59&&seed->unknown&&FWmaps==1);checks++;
    }
    for(unsigned bad=0;bad<20;bad++){
        fixture(bad==0?0:bad==1?257:3,1);
        uint8_t*h=pool+0x10000,*b=h+24;
        switch(bad){case 0:case 1:break;case 2:put(core+0x1bd60,8,8);break;
        case 3:put(b+8,(uintptr_t)b+8,8);break;case 4:put(b+16,8,8);break;
        case 5:put(h,0x30726670,4);break;case 6:put(h+8,3,4);break;case 7:put(h+16,128,8);break;
        case 8:put(h+104,0,4);break;case 9:put(h+112,128,8);break;case 10:put(b+32,UINT64_MAX,8);break;
        case 11:put(pool+0xff0+32,(uintptr_t)arena+1,8);break;
        case 12:seed_input.opening=producer->after.cpu.ticks+1;break;
        case 13:seed_input.opening=0;break;case 14:seed_input.io.arch=(void*)8;break;
        case 15:put(core+0x1d1a0+16,0,4);break;case 16:put(core+0x1cc08,1,8);break;case 17:put(core+0x1cb78,1,8);break;case 18:put(b+60,1,4);break;
        case 19:put(core+0x1d1a0+8,0,8);break;
        default:assert(0);}
        assert(!run_seed()&&seed->unknown&&!seed->complete&&FWmaps==1);checks++;
    }
    for(unsigned bad=0;bad<7;bad++){
        fixture(3,1);struct pwmc_parent_map*extra=(void*)(arena+0x1a0000);
        struct pwmc_parent_input in=producer->input;struct pgcd_io io=producer->io;
        unsigned old_saves=saves,old_restores=restores;uint64_t opening=1000;
        if(bad==0)opening=5000000;
        if(bad==1){opening=1;arches=PGCD_FRESH_TICKS/100+10;}
        if(bad==2)in.capacity=8192;
        if(bad==4)in.phase=3;
        if(bad==5){scenario=10;clock_fault=2;clock_calls=0;}
        if(bad==6){assert(pwmc_parent_map_call_window(extra,&in,&io,opening)&&FWmaps==2&&extra->complete);checks++;continue;}
        int ok=bad==3?pwmc_parent_map_read(extra,&in,&io):pwmc_parent_map_call_window(extra,&in,&io,opening);
        assert(!ok&&extra->unknown&&FWmaps==(bad==5?2u:1u)&&restores==old_restores);
        assert(saves==old_saves+(bad==5));
        if(bad==5)assert(extra->arch_returned==2&&!extra->fp_restore_issued&&extra->fp.saved==1&&!extra->fp.restored);
        checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"seed_bytes\":%zu,\"input_bytes\":%zu,\"node_bytes\":%zu,\"clock_bytes\":%zu,\"normal_ATs\":%u,\"Core_pages\":%u,\"SOFTWARE_only\":true,\"existing_map_calls\":1,\"first_private_admission\":false}\n",checks,sizeof(*seed),sizeof(seed_input),sizeof(struct pbgi_node),sizeof(struct pbgi_clock),total,PBGI_CORE_PAGES);
    free(original);free(arena);free(pbytes);free(lbytes);return 0;
}
