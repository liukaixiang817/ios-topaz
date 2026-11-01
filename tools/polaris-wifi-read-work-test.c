/* Same full current/private READ path, not a budget-only fake client. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
struct paic_io;struct pwrcl_result;struct pwrph_work;struct pgcd_context;
static int work_body(void*,const struct paic_io*,struct pwrcl_result*,struct pwrph_work*,struct pgcd_context*);
#define PWRPT_READ_BODY work_body
#include "polaris-wifi-current-read-test.c"
static unsigned work_fault;
static int work_body(void*v,const struct paic_io*m,struct pwrcl_result*p,struct pwrph_work*w,struct pgcd_context*g)
{
 if(work_fault==1)arches+=25000; /* consistent elapsed private time, no rebase */
 if(work_fault==2)prep->phase[0].target[0].hash_count=4;
 if(work_fault==3)prep->phase[2].target[16].source_hash[4][31]^=1;
 if(work_fault==4)prep->phase[3].target[16].after.cpu.ticks=prep->phase[3].target[16].before.cpu.ticks;
 if(work_fault==5)prep->phase[0].target[0].before.cpu.daif=0xc0;
 if(work_fault==6)prep->phase[0].target[0].after.cpacr=0;
 if(work_fault==7)prep->phase[1].target[5].after.cpu.ticks=prep->phase[1].after.cpu.ticks+1;
 if(work_fault==8)prep->phase[2].target[12].target_AT.returned=0;
 if(work_fault==9)prep->phase[0].target[0].after.cpu.ticks=prep->phase[0].after.cpu.ticks-1;
 if(work_fault==10)prep->phase[0].target[0].before.cpu.frequency=24000000;
 if(work_fault==11)prep->phase[0].target[0].target_AT.par|=1;
 if(work_fault==12)*native_on=1;
 if(work_fault==13)prep->phase[0].after.cpu.ticks=g->record->before.cpu.ticks+1;
 if(work_fault==14)((struct pwrpt_io*)v)->record->work.attempted=1;
 if(work_fault==15)prep->phase[0].target[0].hash_failed=1;
 if(work_fault==16)prep->phase[0].target[0].before.cpu.ticks=prep->phase[0].core.before.cpu.ticks-1;
 if(work_fault==17)prep->phase[0].core.TPL_final=8;
 if(work_fault==18)prep->phase[0].after.cpacr=0;
 if(work_fault==19)prep->phase[0].core.before.cpu.ticks=UINT64_MAX;
 if(work_fault==20)((struct pwrpt_io*)v)->record->work.samples=68;
 if(work_fault==21)((struct pwrpt_io*)v)->record->work.unknown=1;
 if(work_fault==22)((struct pwrpt_io*)v)->record->work.error=17;
 return pwrpt_body(v,m,p,w,g);
}
int main(int argc,char**argv)
{
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 unsigned checks=0;work_fault=0;assert(execute_read(19));
 const struct pwrpt_work*b=&path->work;assert(b->attempted&&b->complete&&b->admitted&&!b->declined&&!b->unknown&&b->samples==68&&b->source_units==18+path->prepared_cmd.pages);
 assert(b->ticket==(uintptr_t)&cr->core_ticket&&b->core==(uintptr_t)early&&b->preparation==(uintptr_t)prep);
 assert(b->estimate_ticks==b->maximum_ticks*b->source_units+960000+480000&&b->remaining_ticks+b->elapsed_ticks==PGCD_FRESH_TICKS);
 uint64_t maximum=0;for(unsigned j=0;j<68;j++){assert(b->sample[j].ticks==b->sample[j].after-b->sample[j].before);if(b->sample[j].ticks>maximum)maximum=b->sample[j].ticks;}
 assert(maximum==b->maximum_ticks&&requests==3&&acks==3&&delete_calls==1&&mask_calls==1&&unmask_calls==1&&pwrr_retired(&path->read)&&!pwrpt_unsafe(path));checks++;
 for(unsigned k=1;k<=22;k++){
  work_fault=k;int ok=execute_read(19);
  if(k==1){fprintf(stderr,"decline%u ok%d path%u work%u admitted%u declined%u elapsed%llu estimate%llu remain%llu private%u CPU%u\n",k,ok,path->error,path->work.error,path->work.admitted,path->work.declined,(unsigned long long)path->work.elapsed_ticks,(unsigned long long)path->work.estimate_ticks,(unsigned long long)path->work.remaining_ticks,cr->error,path->CPU.error);assert(ok&&path->work.complete&&path->work.declined&&!path->work.admitted&&path->known_refusal&&path->retired&&!pwrpt_unsafe(path));assert(path->error==PWRPT_WORK&&delete_calls==1&&!mask_calls&&!unmask_calls&&!modeled_stores&&path->prepared_cmd.closed);}
  else if(k==9){assert(ok&&path->work.admitted&&!path->work.declined&&path->retired&&!pwrpt_unsafe(path)&&requests==3&&delete_calls==1);assert(path->work.maximum_ticks==path->work.sample[0].ticks&&path->work.maximum_ticks>path->work.sample[1].ticks);}
  else{if(ok)fprintf(stderr,"workfault%u admitted=%u max=%llu\n",k,path->work.admitted,(unsigned long long)path->work.maximum_ticks);assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!mask_calls&&!modeled_stores);}
  checks++;
 }
 printf("{\"passed\":true,\"checks\":%u,\"body_bytes\":%zu,\"work_bytes\":%zu,\"SOFTWARE_only\":true,\"full_READ_not_budget_only\":true,\"resource_WRITE_reachable\":false}\n",checks,sizeof(*path),sizeof(path->work));
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
