/* Executable source-bound RO CPU peer. Original PE is DATA, no SMC/MMIO. */
#define main original_gcd_test_main
#include "polaris-uefi-gcd-test.c"
#undef main
#define EFI_XNU_WIFI_CPU_RO_ADMISSION 1
#include "uefi-wifi-cpu-readonly.h"
static struct pwcq_result *cpu;
static uint32_t *native_on;
static unsigned cf,affinity_calls;
static int64_t response[7];
static int cpu_arch(void *v,struct pgcd_arch *a)
{
    int ok=arch(v,a);
    if(affinity_calls){
        if(cf==1)a->cpu.ticks+=3840001;
        if(cf==2)a->cpu.daif=0xc0;
        if(cf==3)a->cpacr=0;
        if(cf==4)a->cpu.frequency=24000000;
        if(cf==5)a->cpu.mpidr+=0x100;
    }
    return ok;
}
static int cpu_map(void *v,struct efi_system *sys,struct pgcd_map *m,void *out)
{
    int ok=map(v,sys,m,out);
    if(maps==2){if(cf==6)m->key++;if(cf==7)((uint8_t*)out)[36]^=1;if(cf==8)core[0x1000]^=1;if(cf==9)return 0;}
    return ok;
}
static int cpu_restore(void *v,struct pgcd_fp_guard *g)
{int ok=fp_restore(v,g);if(cf==10&&affinity_calls){g->restored=0;return 0;}return ok;}
static int cpu_affinity(void *v,uint64_t target,int64_t *raw)
{
    (void)v;unsigned k=affinity_calls++;assert(k<7&&target==0x100u+0x100u*k);
    assert(cpu->call[k].issued&&cpu->call[k].unknown&&cpu->outstanding==k+1);
    assert(cpu->call[k].guard.entered&&!cpu->call[k].guard.left);
    *raw=response[k];
    if(cf==11)cfg[0].table++;
    if(cf==12)put(core+0x1b098,8,8);
    if(cf==13)self->bytes--;
    if(cf==14)core[0x1000]^=1;
    if(cf==15)*native_on=1;
    if(cf==16)return 0;
    if(cf==17){cpu->call[k].guard.fp.saved=0;cpu->call[k].guard.fp.restored=0;}
    return 1;
}
static struct pgcd_context *prepare(unsigned f)
{
    reset(0);put(core+0x1b098,4,8);cf=f;affinity_calls=0;for(unsigned k=0;k<7;k++)response[k]=1;
    struct pgcd_config entry=*cfg;cfg=(void*)(arena+0xf0000);*cfg=entry;s->tables=cfg;
    self->bytes=0xef000;memset(r,0,sizeof(*r));assert(pgcd_bind(r,self));
    cpu=(void*)(arena+0x60000);native_on=(void*)(arena+0xe0000);memset(cpu,0,sizeof(*cpu));*native_on=0;
    struct pgcd_context *final=c;final->io.arch=cpu_arch;final->io.map=cpu_map;final->io.fp_restore=cpu_restore;
    r=&cpu->core;return final;
}
static int run(struct pgcd_context *final)
{const struct pwcq_io io={.context=0,.affinity=cpu_affinity};return pwcq_run(&io,final,2,native_on,cpu);}
 #ifndef POLARIS_CPU_RO_FIXTURE_ONLY
int main(int argc,char **argv)
{
    assert(argc==2&&!posix_memalign((void**)&arena,4096,0x101000));original=malloc(PGCI_IMAGE_BYTES);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;struct pgcd_context *final=prepare(0);
    struct pgcd_result *saved=malloc(sizeof(*saved));memcpy(saved,final->record,sizeof(*saved));
    struct pgcd_context original_context=*final;struct pgcd_lifetime original_ticket=*final->ticket;
    int initial=run(final);if(!initial)fprintf(stderr,"initial err%u core%u phase%u calls%u sources%u native%u tpl%llu maps%u\n",cpu->error,cpu->core.error,cpu->core.phase,affinity_calls,cpu->source_count,cpu->native_reads,(unsigned long long)cpu->core.TPL_initial,maps);
    assert(initial&&cpu->complete&&cpu->retired&&!pwcq_unsafe(cpu)&&cpu->calls==7&&cpu->issued==127&&cpu->returned==127);
    assert(cpu->off==127&&cpu->logical_all_OFF&&cpu->source_count==14&&cpu->native_reads==16&&maps==2&&!queries);
    assert(cpu->context.finished&&cpu->ticket.spent==1&&cpu->core.phase==3&&cpu->core.TPL_final==4);
    assert(!memcmp(saved,final->record,sizeof(*saved))&&!memcmp(&original_context,final,sizeof(*final))&&!memcmp(&original_ticket,final->ticket,sizeof(original_ticket)));checks++;
    unsigned was=affinity_calls;assert(!run(final)&&pwcq_unsafe(cpu)&&affinity_calls==was);checks++;
    const int64_t values[]={0,2,-1,3,INT64_C(0xffffffff),INT64_MIN,INT64_MAX};
    for(unsigned k=0;k<7;k++)for(unsigned v=0;v<7;v++){
        final=prepare(0);response[k]=values[v];assert(run(final)&&cpu->complete&&cpu->retired&&!pwcq_unsafe(cpu)&&!cpu->logical_all_OFF&&cpu->calls==7);
        assert(cpu->call[k].raw==values[v]&&cpu->off==(127u^(1u<<k)));
        assert((v==0?cpu->on:v==1?cpu->pending:v==2?cpu->unsupported:cpu->other)==(1u<<k));checks++;
    }
    for(unsigned faultcase=1;faultcase<=17;faultcase++){
        final=prepare(faultcase);int ok=run(final);
        if(ok||!pwcq_unsafe(cpu))fprintf(stderr,"fault%u ok%d err%u calls%u\n",faultcase,ok,cpu->error,affinity_calls);
        assert(!ok&&pwcq_unsafe(cpu)&&!cpu->retired&&!cpu->complete&&!final->ticket->spent&&!queries);checks++;
    }
    final=prepare(0);*native_on=1;assert(!run(final)&&pwcq_unsafe(cpu)&&!affinity_calls);checks++;
    final=prepare(0);final->ticket->spent=1;assert(!run(final)&&pwcq_unsafe(cpu)&&!affinity_calls&&!maps);checks++;
    final=prepare(0);final->opened=1;assert(!run(final)&&pwcq_unsafe(cpu)&&!affinity_calls&&!maps);checks++;
    final=prepare(0);native_on=(void*)(arena+0xf1000);assert(!run(final)&&pwcq_unsafe(cpu)&&!affinity_calls);checks++;
    printf("{\"passed\":true,\"checks\":%u,\"raw_bytes\":%zu,\"source_bytes\":%zu,\"call_bytes\":%zu,\"SOFTWARE_only\":true,\"actual_SMC_MMIO\":false}\n",checks,sizeof(*cpu),sizeof(struct pwcq_source),sizeof(struct pwcq_call));
    free(saved);free(original);free(arena);return 0;
}

#endif
