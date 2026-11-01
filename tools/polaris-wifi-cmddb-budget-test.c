/* Full capture admission + original known-client retirement, one SOFTWARE
 * execution chain. Original PE bytes are data, never instructions. */
#define EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION 1
#define POLARIS_CMDDB_BOUNDED_FIXTURE_ONLY 1
#include "polaris-wifi-cmddb-bounded-test.c"
static struct pwbd_result *budget;
static unsigned bf,bmaps;
static uint64_t extra,sample_ticks;
static int budget_arch(void *ctx,struct pgcd_arch *a)
{
    int ok=path_arch(ctx,a);a->cpu.ticks+=extra;
    if(!budget->retired&&budget->samples<PWBD_SAMPLES){
        struct pwbd_sample *q=&budget->sample[budget->samples];
        if(q->before.cpu.ticks&&!q->after.cpu.ticks){
            extra+=sample_ticks-100;a->cpu.ticks+=sample_ticks-100;
            if(bf==2)a->cpu.ticks=q->before.cpu.ticks-1;
            if(bf==3)a->cpu.ticks=q->before.cpu.ticks;
            if(bf==4)a->cpu.frequency=24000000;
            if(bf==5)self->bytes--;
            if(bf==6)put(core+0x1b098,8,8);
            if(bf==7)cfg->table++;
        }else if(bf==1&&budget->samples==0&&budget->context.opened)core[0x1000]^=1;
    }
    return ok;
}
static int budget_map(void *ctx,struct efi_system *sys,struct pgcd_map *m,void *out)
{
    int ok=path_core_map(ctx,sys,m,out);bmaps++;
    if(bmaps==2){
        if(bf==8)m->key++;
        if(bf==9)return 0;
        if(bf==10)core[0x1000]^=1;
    }
    return ok;
}
static int budget_restore(void *ctx,struct pgcd_fp_guard *g)
{int ok=fp_restore(ctx,g);if(bf==11&&bmaps==2){g->restored=0;return 0;}return ok;}
static void budget_reset(unsigned f,uint64_t duration)
{
    configure(0);bf=f;bmaps=0;extra=0;sample_ticks=duration;
    budget=(void*)(arena+0x440000);memset(budget,0,sizeof(*budget));
    assert((uint8_t*)budget+sizeof(*budget)<=arena+0x480000);
    c->io.arch=budget_arch;c->io.map=budget_map;c->io.identity=path_identity;c->io.fp_restore=budget_restore;
}
static int after_budget(void)
{
    if(!pwbd_run(c,2,budget)||!budget->admitted)return 0;
    nf=0;ntrans=flipped=original_queries=0;ns=&path->cmd.bounded_namespace[0];
    const struct paic_io memory={s,0,path_memory_arch,path_identity,order};
    const struct pwrcl_io client={{memory,path_locate,bounded_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original={memory,path_locate,bounded_map},.query=0,
        .namespace_io={0,0,bounded_AT}},.enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path};
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,bounded_body,&io);
}
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;
    budget_reset(0,100);struct pgcd_result before=*r;struct pgcd_lifetime lifetime=*ticket;
    assert(after_budget()&&budget->admitted&&budget->retired&&!pwbd_unsafe(budget));
    assert(budget->core.phase==3&&budget->samples==3&&budget->core.map[0].key==1&&budget->core.map[1].key==1);
    assert(budget->context.finished&&budget->ticket.spent==1&&budget->ticket.result==(uintptr_t)&budget->core);
    assert(!memcmp(&before,r,sizeof(before))&&!memcmp(&lifetime,ticket,sizeof(lifetime)));
    assert(cr->retired&&cr->client_returned&&!cr->client_held&&create_calls==1&&delete_calls==1);
    assert(path->cmd.stable&&path->cmd.database_bytes[0]==PWCD_DB_BYTES&&path->cmd.database_bytes[1]==PWCD_DB_BYTES);
    assert(budget->core.after.cpu.ticks<cr->core.before.cpu.ticks&&budget->core.before.cpu.ticks!=cr->core.before.cpu.ticks);
    assert(!original_queries&&!api_queries&&!psci_calls&&!modeled_stores);checks++;
    for(unsigned k=0;k<3;k++){assert(budget->sample[k].hash_count==5&&!budget->sample[k].hash_failed);checks++;}
    const uint64_t limit=(PWBD_PLAN_TICKS-PWBD_RESERVE_TICKS)/PWBD_CORE_CHECKPOINTS;
    budget_reset(0,limit);assert(pwbd_run(c,2,budget)&&budget->admitted&&budget->estimate_ticks==PWBD_PLAN_TICKS);checks++;
    budget_reset(0,limit+1);assert(!after_budget()&&budget->declined&&budget->retired&&!pwbd_unsafe(budget));
    assert(!create_calls&&!delete_calls&&!cr->attempted&&!path->attempted&&pwrcl_final_unopened(c));checks++;
    for(unsigned f=1;f<=11;f++){
        budget_reset(f,100);assert(!after_budget()&&pwbd_unsafe(budget)&&budget->unknown);
        assert(!create_calls&&!delete_calls&&!cr->attempted&&!path->attempted);checks++;
    }
    budget_reset(0,PGCD_FRESH_TICKS);assert(!after_budget()&&budget->unknown&&!create_calls);checks++;
    budget_reset(0,100);ticket->spent=1;assert(!pwbd_run(c,2,budget)&&budget->unknown&&!bmaps);checks++;
    budget_reset(0,100);assert(!pwbd_run(c,1,budget)&&budget->unknown&&!bmaps);checks++;
    budget_reset(0,100);budget->ticket.spent=1;assert(!pwbd_run(c,2,budget)&&budget->unknown&&!bmaps);checks++;
    budget_reset(0,100);assert(pwbd_run(c,2,budget));unsigned calls=bmaps;
    assert(!pwbd_run(c,2,budget)&&budget->unknown&&bmaps==calls);checks++;
    budget_reset(0,100);assert(pwbd_run(c,2,budget));pwbd_record=*budget;
    parent_report_capacity=2*(sizeof(pwrpt_record)+sizeof(pwrcl_record)+sizeof(pwbd_record))+2048;
    parent_report=calloc(1,parent_report_capacity+1);assert(parent_report);pwrpt_report(parent_append);
    check_raw_segment("WIFI_CMDDB_WORK_ADMISSION_RAW_V1_BEGIN\r\n","\r\nWIFI_CMDDB_WORK_ADMISSION_RAW_V1_END",&pwbd_record,sizeof(pwbd_record));checks++;
    assert(!pwbd_parent_unsafe());pwbd_record.unknown=1;assert(pwbd_parent_unsafe()&&pwrpt_parent_unsafe());checks++;
    printf("{\"passed\":true,\"checks\":%u,\"budget_raw_bytes\":%zu,\"sample_bytes\":%zu,\"same_final_ticket_unchanged\":true,\"complete_same_context_DB_after_budget\":true,\"phone_timing_proven\":false,\"physical_firmware_executed\":false}\n",checks,sizeof(struct pwbd_result),sizeof(struct pwbd_sample));
    free(parent_report);free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
