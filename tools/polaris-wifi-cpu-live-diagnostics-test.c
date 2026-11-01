/* Actual pwrpc_live with SOFTWARE peers; original PE inputs are DATA only. */
#define EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS 1
#define PWRPC_CRITICAL_TEST_MAIN legacy_critical_main
#include "polaris-wifi-power-critical-test.c"
static struct pgcd_arch diagnostic_sample;
static unsigned diagnostic_arch_calls,diagnostic_callback_fail;
static int diagnostic_arch(void *ctx,struct pgcd_arch *a)
{(void)ctx;diagnostic_arch_calls++;*a=diagnostic_sample;return !diagnostic_callback_fail;}
static void diagnostic_setup(void)
{
    struct paic_io memory=critical_setup(0);
    assert(pwrpc_begin(&cpu_io,&memory,provider,rw,c,(uintptr_t)native_issued,critical));
    assert(critical->local_quiescent&&critical->local_mask_held&&!critical->error);
    diagnostic_sample=critical->after;c->io.arch=diagnostic_arch;
    diagnostic_arch_calls=diagnostic_callback_fail=0;
}
static void diagnostic_fault(unsigned reason)
{
    struct pwfc_arch *a=&diagnostic_sample.cpu,*n=&critical->normal.cpu;
    switch(reason){
    case PWRPC_LIVE_ARCH_CALLBACK:diagnostic_callback_fail=1;break;
    case PWRPC_LIVE_EL:a->el=0;break;
    case PWRPC_LIVE_MPIDR_LOCAL:a->mpidr|=1;break;
    case PWRPC_LIVE_FREQUENCY:a->frequency++;break;
    case PWRPC_LIVE_EL_CHANGED:n->el=0;break;
    case PWRPC_LIVE_MPIDR_CHANGED:a->mpidr^=UINT64_C(1)<<32;break;
    case PWRPC_LIVE_TTBR0:a->ttbr0^=4096;break;
    case PWRPC_LIVE_TTBR1:a->ttbr1^=4096;break;
    case PWRPC_LIVE_TCR:a->tcr^=1;break;
    case PWRPC_LIVE_SCTLR:a->sctlr^=1;break;
    case PWRPC_LIVE_MAIR:a->mair^=1;break;
    case PWRPC_LIVE_SRE:a->sre^=1;break;
    case PWRPC_LIVE_DAIF:a->daif^=0x40;break;
    case PWRPC_LIVE_GROUP1:a->group1=1;break;
    case PWRPC_LIVE_CPACR:diagnostic_sample.cpacr^=1;break;
    case PWRPC_LIVE_BEFORE_NORMAL:a->ticks=n->ticks-1;break;
    case PWRPC_LIVE_NORMAL_AGE:a->ticks=n->ticks+PGCD_FRESH_TICKS+1;break;
    case PWRPC_LIVE_BEFORE_OPENING:r->before.cpu.ticks=a->ticks+1;break;
    case PWRPC_LIVE_OPENING_AGE:a->ticks=r->before.cpu.ticks+PGCD_FRESH_TICKS+1;break;
    case PWRPC_LIVE_TPL:put(core+0x1b098,8,8);break;
    case PWRPC_LIVE_BOOT:s->boot=(void*)((uintptr_t)s->boot+8);break;
    case PWRPC_LIVE_TABLES:s->tables=(void*)((uintptr_t)s->tables+8);break;
    case PWRPC_LIVE_TABLE_COUNT:s->table_count++;break;
    case PWRPC_LIVE_DS:((uint8_t*)(uintptr_t)r->DS)[0]^=1;break;
    case PWRPC_LIVE_OWNER:self->bytes^=4096;break;
    default:assert(0);
    }
}
int main(int argc,char **argv)
{
    assert(legacy_critical_main(argc,argv)==0);
    assert(!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);
    uint8_t *data[]={original,npa_original,rp_original};size_t bytes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES};
    for(unsigned k=0;k<3;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,bytes[k],f)==bytes[k]&&!fclose(f));}
    unsigned checks=26;struct pgcd_arch out;
    diagnostic_setup();assert(pwrpc_live(c,critical,1,&out));
    assert(diagnostic_arch_calls==1&&!critical->live_failure.attempted);checks++;
    for(unsigned reason=1;reason<=25;reason++){
        diagnostic_setup();diagnostic_fault(reason);
        uint64_t opening=r->before.cpu.ticks,normal=critical->normal.cpu.ticks,failed=diagnostic_sample.cpu.ticks;
        unsigned call=critical->live_calls+1;
        assert(!pwrpc_live(c,critical,1,&out));
        struct pwrpc_live_diagnostic d=critical->live_failure;
        if(d.reason!=reason)fprintf(stderr,"reason expected%u actual%u CPUerror%u\n",reason,d.reason,critical->error);
        assert(d.attempted==1&&d.reason==reason&&d.call==call&&d.masked==1);
        assert(d.opening_ticks==opening&&d.normal_ticks==normal&&d.failed_ticks==(reason==1?0:failed));
        assert(d.arch_callback_ok==(reason!=1)&&!d.reserved&&diagnostic_arch_calls==1);
        assert(critical->error==PWRPC_ARCH&&critical->unknown&&critical->local_mask_held&&!critical->local_restored);
        assert(!restore_calls&&!hw_requests&&!tx->writes);checks++;
        diagnostic_sample.cpu.ticks+=999999;assert(!pwrpc_live(c,critical,1,&out));
        assert(diagnostic_arch_calls==1&&!memcmp(&d,&critical->live_failure,sizeof(d)));checks++;
    }
    /* Original <=200ms boundary, followed by the first tick outside it. */
    diagnostic_setup();diagnostic_sample.cpu.ticks=r->before.cpu.ticks+PGCD_FRESH_TICKS;
    assert(pwrpc_live(c,critical,1,&out)&&!critical->live_failure.attempted);checks++;
    diagnostic_sample.cpu.ticks++;assert(!pwrpc_live(c,critical,1,&out));
    assert(critical->live_failure.reason==PWRPC_LIVE_OPENING_AGE);checks++;
    /* Later memory predicates must remain unevaluated after the first fail. */
    diagnostic_setup();diagnostic_sample.cpu.el=0;diagnostic_sample.cpu.frequency=0;
    r->DS=1;r->self_owner_address=1;
    assert(!pwrpc_live(c,critical,1,&out)&&critical->live_failure.reason==PWRPC_LIVE_EL);checks++;
    printf("{\"passed\":true,\"checks\":%u,\"reasons\":25,\"actual_original_live_gate\":true,\"first_failure_and_sample_preserved\":true,\"extra_arch_reads\":0,\"original_200ms_boundary\":true,\"SOFTWARE_only\":true,\"CPU_bytes\":%zu}\n",checks,sizeof(*critical));
    free(original);free(npa_original);free(rp_original);free(arena);return 0;
}
