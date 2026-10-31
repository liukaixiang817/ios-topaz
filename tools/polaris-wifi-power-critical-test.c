/* Source-bound CPU-local critical interval -> actual RSC core -> source RAM
 * comparison -> prefix-gated restoration. All privileged I/O is SOFTWARE. */
#define POLARIS_RSC_BASELINE_FIXTURE_ONLY 1
#include "polaris-wifi-rsc-baseline-test.c"
#include "uefi-wifi-power-critical.h"
static struct pwrpc_result *critical;
static struct pwrsc_transaction *tx;
static struct pwrpb_baseline *during,*post;
static volatile uint32_t *native_issued;
static unsigned scenario,affinity_calls,mask_calls,restore_calls,hw_requests;
static uint64_t sim_daif,sim_group;
static uint32_t hw[0x3000/4];
static int critical_arch(void *ctx,struct pgcd_arch *a)
{
    int ok=arch(ctx,a);a->cpu.daif=sim_daif;a->cpu.group1=sim_group;
    if((scenario==5&&mask_calls)||(scenario==19&&affinity_calls>=8))a->cpacr=0;return ok;
}
static int critical_memory_arch(void *ctx,struct paic_arch *a)
{
    struct pgcd_arch g;if(!critical_arch(ctx,&g))return 0;
    *a=(struct paic_arch){g.cpu.el,g.cpu.mpidr,g.cpu.ttbr0,g.cpu.ttbr1,g.cpu.tcr,g.cpu.sctlr,g.cpu.mair,g.cpu.daif,g.cpu.sre,g.cpu.group1,g.cpu.frequency,g.cpu.ticks};return 1;
}
static int affinity_peer(void *ctx,uint64_t target,int64_t *raw)
{
    (void)ctx;
    if(affinity_calls<7)assert(!sim_daif&&sim_group==1&&r->outstanding);
    else assert(sim_daif==0xc0&&!sim_group&&!r->outstanding&&critical->outstanding&&!critical->local_quiescent);
    assert(target==0x100+0x100*(affinity_calls%7));affinity_calls++;
    *raw=scenario==1?0:1;
    if(scenario==4)*native_issued=1;
    if(affinity_calls>=8){
        if(scenario==17)*raw=0;
        if(scenario==20)put(core+0x1b098,8,8);
        if(scenario==21)*native_issued=1;
        if(scenario==22&&affinity_calls==14)rimage[0x1000]^=1;
    }
    return scenario!=2&&!(scenario==18&&affinity_calls>=8);
}
static int mask_peer(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;assert(affinity_calls==7&&critical->outstanding==8);
    mask_calls++;t->daif_before=sim_daif;t->group_before=sim_group;
    sim_daif=0xc0;t->daif_written=t->daif_observed=1;t->daif_read=sim_daif;
    if(scenario==3)return 0;
    sim_group=0;t->group_written=t->group_observed=1;t->group_read=sim_group;
    if(scenario==15)put(core+0x1b098,8,8);return 1;
}
static int restore_peer(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;assert(sim_daif==0xc0&&!sim_group&&critical->outstanding==9);
    restore_calls++;t->daif_before=sim_daif;t->group_before=sim_group;
    sim_group=1;t->group_written=t->group_observed=1;t->group_read=sim_group;
    if(scenario==7)return 0;
    sim_daif=0;t->daif_written=t->daif_observed=1;t->daif_read=sim_daif;return 1;
}
static int power_clock(void *ctx,uint64_t *ticks,uint64_t *frequency)
{
    (void)ctx;struct pgcd_arch g;if(!pwrpc_live(c,critical,1,&g))return 0;
    *ticks=g.cpu.ticks;*frequency=g.cpu.frequency;return 1;
}
static int power_read(void *ctx,uint64_t at,uint32_t *v)
{
    (void)ctx;assert(critical->local_mask_held&&sim_daif==0xc0&&!sim_group&&at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(hw));
    *v=hw[(at-PWRSC_BASE)/4];return 1;
}
static int power_write(void *ctx,uint64_t at,uint32_t value)
{
    (void)ctx;assert(critical->local_mask_held&&sim_daif==0xc0&&!sim_group&&at>=PWRSC_BASE&&at<PWRSC_BASE+sizeof(hw));
    unsigned off=(unsigned)(at-PWRSC_BASE);assert(off);
    if(off==8){hw[1]&=~value;return 1;}
    hw[off/4]=value;
    if(off%PWRSC_STRIDE==0x14&&(value&PWRSC_TRIGGER)){
        unsigned t=off-0x14,tcs=t/PWRSC_STRIDE;hw_requests++;
        hw[1]|=1u<<tcs;hw[off/4]&=~PWRSC_TRIGGER;
        for(unsigned k=0;k<3;k++)hw[(t+0x3c+20*k)/4]=PWRSC_DONE;
    }return 1;
}
static struct paic_io critical_setup(unsigned which)
{
    struct paic_io memory=setup(0);scenario=which;affinity_calls=mask_calls=restore_calls=hw_requests=0;sim_daif=0;sim_group=1;
    critical=(void*)(arena+0x90000);native_issued=(void*)(arena+0x94000);tx=(void*)(arena+0xe0000);
    during=(void*)(arena+0x120000);post=(void*)(arena+0x140000);
    memset(critical,0,sizeof(*critical));memset(tx,0,sizeof(*tx));memset(during,0,sizeof(*during));memset(post,0,sizeof(*post));*native_issued=0;
    c->io.arch=critical_arch;memory.arch=critical_memory_arch;
    assert(critical_memory_arch(0,&reference));
    assert(pwrpb_capture(&memory,provider,rw,&provider->pools[0][1],&reference,before));
    assert(pwrpb_capture(&memory,provider,rw,&provider->pools[0][1],&reference,after)&&pwrpb_equal(before,after));
    memset(hw,0,sizeof(hw));hw[0]=0xff;for(unsigned k=0;k<8;k++)hw[(PWRSC_STRIDE*k+0x18)/4]=1;
    return memory;
}
static const struct pwrpc_io cpu_io={0,affinity_peer,mask_peer,restore_peer};
static int run_critical(unsigned which)
{
    struct paic_io memory=critical_setup(which);
    if(which==14)rimage[0x1000]^=1;
    int ok=pwrpc_begin(&cpu_io,&memory,provider,rw,c,(uintptr_t)native_issued,critical);
    if(!ok)return 0;
    struct paic_arch masked;assert(critical_memory_arch(0,&masked));
    assert(pwrpb_capture(&memory,provider,rw,&provider->pools[0][1],&masked,during)&&pwrpb_equal(before,during));
    if(which==8)return pwrpc_end(&cpu_io,&memory,provider,rw,c,tx,0,0,critical);
    if(which==9){tx->triggers=1;return pwrpc_end(&cpu_io,&memory,provider,rw,c,tx,0,0,critical);}
    const uint32_t saved[3]={8,2,1},desired[3]={7,4,7};
    const struct pwrsc_io power={0,power_read,power_write,power_clock,order};
    assert(pwrsc_begin(&power,tx,during->active_mask,saved,desired));
    int done=0;for(unsigned k=0;k<12&&!done;k++)done=pwrsc_step(&power,tx);
    assert(done==1&&pwrsc_retired(tx)&&hw_requests==2);
    if(which==6)links[0x4004+0x3f]^=1;
    assert(pwrpb_capture(&memory,provider,rw,&provider->pools[0][1],&masked,post));
    if(which==10)arches=50000;
    if(which==11)tx->history[tx->events-1].returned=0;
    if(which==12)core[0x1000]^=1;
    if(which==13)rimage[0xd0d8+0x20]^=1;
    if(which==16)s->table_count++;
    if(which==23)critical->masked_psci[0].raw=0;
    if(which==24)critical->masked_psci[0].complete=0;
    return pwrpc_end(&cpu_io,&memory,provider,rw,c,tx,during,post,critical);
}
int main(int argc,char **argv)
{
    assert(argc==4&&!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);assert(original&&npa_original&&rp_original);
    const size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES};uint8_t *dst[]={original,npa_original,rp_original};
    for(unsigned k=0;k<3;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;int ok=run_critical(0);
    if(!ok)fprintf(stderr,"baseline critical%u unknown%u outstanding%u mask%u TX%u source%u\n",critical->error,critical->unknown,critical->outstanding,critical->local_mask_held,tx->error,r->error);
    assert(ok&&critical->retired&&critical->local_restored&&!pwrpc_unsafe(critical)&&critical->affinity_returned==0x7f&&critical->masked_returned==0x7f&&affinity_calls==14&&critical->flag_reads==10&&restore_calls==1&&!sim_daif&&sim_group==1&&critical->source[0].complete&&critical->source[1].complete&&critical->masked_source.complete);checks++;
    unsigned old_calls=affinity_calls;
    assert(!pwrpc_begin(&cpu_io,0,provider,rw,c,(uintptr_t)native_issued,critical)&&affinity_calls==old_calls);checks++;
    for(unsigned k=1;k<=24;k++){
        ok=run_critical(k);
        if(k==8){assert(ok&&critical->retired&&critical->local_restored&&!pwrpc_unsafe(critical)&&!tx->writes&&!hw_requests);}
        else{
            if(ok)fprintf(stderr,"unexpected critical success%u\n",k);
            assert(!ok&&critical->error);
            if(k==1||k==14)assert(critical->retired&&!pwrpc_unsafe(critical)&&!mask_calls&&!restore_calls);
            else assert(pwrpc_unsafe(critical)&&critical->unknown);
            if(k>=3&&k!=4&&k!=14)assert(critical->local_mask_held&&sim_daif==0xc0);
            if(k>=6&&k!=7)assert(!restore_calls);
            if(k==2)assert(critical->affinity_unknown==1&&critical->outstanding==1&&!mask_calls);
            if(k==7)assert(critical->restore.group_written&&!critical->restore.daif_written&&critical->outstanding==9);
            if(k>=17&&k<=22)assert(!tx->writes&&!hw_requests&&!restore_calls);
        }checks++;
    }
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"transition_bytes\":%zu,\"SOFTWARE_CPU_IRQ_and_PSCI\":true,\"full_transaction_and_prefix_restore\":true,\"physical_IRQ_or_MMIO_executed\":false,\"DRV2_EL3_TCS_lease_granted\":false}\n",checks,sizeof(*critical),sizeof(struct pwrpc_transition));
    free(original);free(npa_original);free(rp_original);free(arena);return 0;
}
