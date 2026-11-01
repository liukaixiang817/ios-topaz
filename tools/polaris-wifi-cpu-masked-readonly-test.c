/* Masked CPU-local software peer. Original Core PE is DATA only. */
#define EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION 1
#define POLARIS_CPU_RO_FIXTURE_ONLY 1
#include "polaris-wifi-cpu-readonly-test.c"
static unsigned mf,masked_active,mask_calls,restore_calls,masked_calls;
static int64_t masked_response[7];
static struct pgcd_context *final_context;
static int masked_arch(void *v,struct pgcd_arch *a)
{
    int ok=cpu_arch(v,a);
    if(masked_active){
        a->cpu.daif=0xc0;a->cpu.group1=0;
        if(masked_calls){
            if(mf==1)a->cpu.daif=0;
            if(mf==2)a->cpu.group1=1;
            if(mf==3)a->cpacr=0;
            if(mf==4)a->cpu.mpidr=0x100;
            if(mf==5)a->cpu.ticks+=3840001;
            if(mf==6)a->cpu.frequency=24000000;
        }
    }
    if(mf==29&&restore_calls)a->cpu.daif=0xc0;
    return ok;
}
static int guarded_map(void *v,struct efi_system *sys,struct pgcd_map *m,void *out)
{assert(!masked_active&&!cpu->masked.held);return cpu_map(v,sys,m,out);}
static int masked_affinity(void *v,uint64_t target,int64_t *raw)
{
    if(!masked_active)return cpu_affinity(v,target,raw);
    unsigned k=masked_calls++;assert(k<7&&target==0x100u+0x100u*k);
    struct pwrpc_masked_psci *q=&cpu->masked.call[k];
    assert(cpu->masked.held&&q->issued&&q->unknown&&cpu->outstanding==16+k);
    assert(maps==1&&!queries&&!restore_calls);*raw=masked_response[k];
    if(mf==7)cfg[0].table++;
    if(mf==8)put(core+0x1b098,8,8);
    if(mf==9)self->bytes--;
    if(mf==10)core[0x1000]^=1;
    if(mf==11)*native_on=1;
    if(mf==12)return 0;
    if(mf==13)q->fp.saved=0;
    if(mf==14)final_context->ticket->spent=1;
    if(mf==15)cpu->ticket.spent=0;
    if(mf==16)cpu->core.phase=3;
    if(mf==17)cpu->core.uncertain=1;
    if(mf==18)cpu->core.outstanding=1;
    if(mf==19)cpu->masked.last_ticks=UINT64_MAX;
    return 1;
}
static int local_mask(void *v,struct pwrpc_transition *t)
{
    (void)v;mask_calls++;assert(!masked_active&&affinity_calls==7&&maps==1);
    assert(cpu->masked.held&&cpu->masked.unknown&&cpu->outstanding==8);
    t->daif_before=0;t->group_before=1;t->daif_written=t->group_written=1;
    t->daif_observed=t->group_observed=1;t->daif_read=0xc0;t->group_read=0;masked_active=1;
    if(mf==20)return 0;
    if(mf==21)t->daif_written=0;
    if(mf==22)t->group_observed=0;
    if(mf==23)t->precondition_error=1;
    if(mf==24)t->group_read=1;
    return 1;
}
static int local_restore(void *v,struct pwrpc_transition *t)
{
    (void)v;restore_calls++;assert(masked_active&&masked_calls==7&&maps==1);
    assert(cpu->masked.source_count==15&&cpu->masked.source[14].complete);
    assert(cpu->masked.held&&cpu->masked.unknown&&cpu->outstanding==32);
    t->daif_before=0xc0;t->group_before=0;t->daif_written=t->group_written=1;
    t->daif_observed=t->group_observed=1;t->daif_read=0;t->group_read=1;
    if(mf==25)return 0;
    if(mf==26)t->group_read=0;
    if(mf==27)t->daif_observed=0;
    if(mf==28)t->precondition_error=1;
    masked_active=0;
    if(mf==30)core[0x1000]^=1;
    if(mf==31)*native_on=1;
    if(mf==32)final_context->ticket->spent=1;
    return 1;
}
static int masked_fp_restore(void *v,struct pgcd_fp_guard *g)
{int ok=cpu_restore(v,g);if(masked_active&&masked_calls&&mf==33){g->restored=0;return 0;}return ok;}
static struct pgcd_context *masked_prepare(unsigned f)
{
    struct pgcd_context *final=prepare(0);mf=f;masked_active=mask_calls=restore_calls=masked_calls=0;
    for(unsigned k=0;k<7;k++)masked_response[k]=1;
    final->io.arch=masked_arch;final->io.map=guarded_map;final->io.fp_restore=masked_fp_restore;
    final_context=final;return final;
}
static int masked_run(struct pgcd_context *final)
{
    const struct pwcq_io io={.affinity=masked_affinity,.mask=local_mask,.restore=local_restore};
    return pwcq_run(&io,final,2,native_on,cpu);
}
int main(int argc,char **argv)
{
    assert(argc==2&&!posix_memalign((void**)&arena,4096,0x101000));original=malloc(PGCI_IMAGE_BYTES);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;struct pgcd_context *final=masked_prepare(0);
    struct pgcd_result *saved=malloc(sizeof(*saved));memcpy(saved,final->record,sizeof(*saved));
    struct pgcd_context original_context=*final;struct pgcd_lifetime original_ticket=*final->ticket;
    int ok=masked_run(final);if(!ok)fprintf(stderr,"initial err%u core%u calls%u/%u sources%u/%u native%u held%u restore%u maps%u\n",cpu->error,cpu->core.error,affinity_calls,masked_calls,cpu->source_count,cpu->masked.source_count,cpu->native_reads,cpu->masked.held,restore_calls,maps);
    assert(ok&&cpu->complete&&cpu->retired&&!pwcq_unsafe(cpu)&&!masked_active);
    assert(cpu->off==127&&cpu->logical_all_OFF&&cpu->calls==7&&cpu->masked.calls==7);
    assert(cpu->masked.complete&&cpu->masked.restored&&!cpu->masked.held&&!cpu->masked.unknown);
    assert(cpu->masked.issued==127&&cpu->masked.returned==127&&cpu->masked.source_count==15);
    assert(cpu->native_reads==47&&mask_calls==1&&restore_calls==1&&maps==2&&!queries);
    assert(!memcmp(saved,final->record,sizeof(*saved))&&!memcmp(&original_context,final,sizeof(*final))&&!memcmp(&original_ticket,final->ticket,sizeof(original_ticket)));checks++;
    unsigned was=masked_calls;assert(!masked_run(final)&&pwcq_unsafe(cpu)&&masked_calls==was);checks++;
    const int64_t values[]={0,2,-1,3,INT64_C(0xffffffff),INT64_MIN,INT64_MAX};
    for(unsigned k=0;k<7;k++)for(unsigned v=0;v<7;v++){
        final=masked_prepare(0);response[k]=values[v];assert(masked_run(final)&&cpu->retired&&!pwcq_unsafe(cpu));
        assert(cpu->masked.declined&&!mask_calls&&!masked_calls&&!restore_calls&&!cpu->masked.held);checks++;
        final=masked_prepare(0);masked_response[k]=values[v];assert(!masked_run(final)&&pwcq_unsafe(cpu));
        assert(cpu->masked.held&&cpu->masked.unknown&&!restore_calls&&maps==1&&!cpu->retired);
        assert(cpu->masked.call[k].raw==values[v]&&cpu->masked.call[k].unknown);checks++;
    }
    for(unsigned k=1;k<=33;k++){
        final=masked_prepare(k);ok=masked_run(final);
        if(ok||!pwcq_unsafe(cpu))fprintf(stderr,"fault%u ok%d err%u masked%u restore%u\n",k,ok,cpu->error,masked_calls,restore_calls);
        assert(!ok&&pwcq_unsafe(cpu)&&!cpu->retired&&!cpu->complete&&cpu->masked.held&&maps==1);
        if(k<=24||k==33)assert(!restore_calls);checks++;
    }
    for(unsigned k=1;k<=17;k++){
        final=masked_prepare(0);cf=k;ok=masked_run(final);assert(!ok&&pwcq_unsafe(cpu));
        if(k>=6&&k<=9)assert(mask_calls==1&&restore_calls==1&&!masked_active);
        else assert(!mask_calls&&!restore_calls);checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"raw_bytes\":%zu,\"masked_bytes\":%zu,\"transition_bytes\":%zu,\"SOFTWARE_only\":true,\"actual_SMC_MMIO\":false}\n",checks,sizeof(*cpu),sizeof(cpu->masked),sizeof(struct pwrpc_transition));
    free(saved);free(original);free(arena);return 0;
}
