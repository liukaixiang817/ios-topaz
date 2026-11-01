/* SAME real known-client/current namespace/Device/CPU/full retirement peer.
 * Original PE DATA only. No RSC store, READ request or fake completed engine. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
struct paic_io;struct pwrcl_result;struct pwrph_work;struct pgcd_context;
static int checkpoint_body(void*,const struct paic_io*,struct pwrcl_result*,struct pwrph_work*,struct pgcd_context*);
#define PWRPT_READ_BODY checkpoint_body
#include "polaris-wifi-current-read-test.c"
static unsigned checkpoint_fault,checkpoint_target;
static int checkpoint_affinity(void *ctx,uint64_t target,int64_t *raw)
{
 int ok=path_affinity(ctx,target,raw);
 if(checkpoint_fault==2&&psci_calls==checkpoint_target)*raw=0;
 if(checkpoint_fault==3&&psci_calls==checkpoint_target)*raw=2;
 if(checkpoint_fault==4&&psci_calls==checkpoint_target)*raw=-1;
 if(checkpoint_fault==5&&psci_calls==checkpoint_target)return 0;
 if(checkpoint_fault==6&&psci_calls==checkpoint_target)*native_on=1;
 if(checkpoint_fault==7&&psci_calls==checkpoint_target)core[0x1000]^=1;
 if(checkpoint_fault==8&&psci_calls==checkpoint_target)put(core+0x1b098,8,8);
 return ok;
}
static int checkpoint_mask(void *ctx,struct pwrpc_transition *t)
{
 int ok=path_mask(ctx,t);
 if(checkpoint_fault==9)t->group_observed=0;
 if(checkpoint_fault==10)return 0;
 return ok;
}
static int checkpoint_restore(void *ctx,struct pwrpc_transition *t)
{
 (void)ctx;assert(DAIF==0xc0&&!Group1&&pwrpt_checkpoint_zero_engines(path));
 assert(path->RAM[2].complete&&pwrpb_equal(&path->RAM[1],&path->RAM[2]));unmask_calls++;
 t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
 t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;
 if(checkpoint_fault==11)t->daif_observed=0;
 if(checkpoint_fault==12)return 0;
 if(checkpoint_fault==13)t->group_read=0;
 return 1;
}
static int checkpoint_Device_read(void *ctx,uint64_t at,uint32_t *value)
{
 int ok=path_read(ctx,at,value);
 if(checkpoint_fault==14&&path->CPU.retired&&at==PWRSC_BASE+0x10)*value^=2;
 return ok;
}
static int checkpoint_body(void*v,const struct paic_io*m,struct pwrcl_result*p,struct pwrph_work*w,struct pgcd_context*g)
{
 struct pwrpt_io io=*(const struct pwrpt_io*)v;
 io.access=(struct pwra_io){0};io.CPU=(struct pwrpc_io){0,checkpoint_affinity,checkpoint_mask,checkpoint_restore};
 io.device.read=checkpoint_Device_read;
 if(checkpoint_fault==1)arches+=25000;
 if(checkpoint_fault==15)io.record->access.retired=1;
 if(checkpoint_fault==16)io.access.read=current_read_load;
 if(checkpoint_fault==17)io.record->read.io.finished=1;
 return pwrpt_body(&io,m,p,w,g);
}
static void setup_images(int argc,char**argv)
{
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
}
int main(int argc,char**argv)
{
 setup_images(argc,argv);unsigned checks=0;checkpoint_fault=0;assert(execute_read(19));
 assert(path->error==PWRPT_CPU_CHECKPOINT&&path->known_refusal&&path->retired&&!pwrpt_unsafe(path));
 assert(cr->client_returned&&cr->retired&&!cr->client_held&&create_calls==1&&delete_calls==1&&!pwrcl_result_unsafe(cr));
 assert(psci_calls==14&&mask_calls==1&&unmask_calls==1&&path->CPU.local_restored&&path->CPU.retired&&!pwrpc_unsafe(&path->CPU));
 assert(!requests&&!acks&&!modeled_stores&&!api_queries&&!DAIF&&Group1==1&&!ticket->spent);
 assert(pwrpt_checkpoint_zero_engines(path)&&path->prepared_cmd.closed&&path->work.admitted);
 assert(path->device[0].reads==70&&path->device[1].reads==70&&path->device[0].queries==3&&path->device[1].queries==3);
 assert(pwrpb_equal(&path->RAM[0],&path->RAM[1])&&pwrpb_equal(&path->RAM[1],&path->RAM[2]));checks++;
 checkpoint_fault=1;assert(execute_read(19)&&path->work.declined&&path->known_refusal&&path->retired&&!pwrpt_unsafe(path));assert(!mask_calls&&!psci_calls&&delete_calls==1&&!modeled_stores);checks++;
 for(unsigned faultcase=2;faultcase<=8;faultcase++)for(unsigned k=1;k<=14;k++){
  checkpoint_fault=faultcase;checkpoint_target=k;int ok=execute_read(19);
  if((faultcase==2||faultcase==3)&&k<=7){assert(ok&&path->known_refusal&&path->retired&&!pwrpt_unsafe(path)&&delete_calls==1&&!mask_calls);}
  else{assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls);if(k<=7&&faultcase!=7)assert(!mask_calls);
   else assert(path->CPU.local_mask_held&&!unmask_calls);}
  assert(!modeled_stores&&!requests&&!acks);checks++;
 }
 for(unsigned k=9;k<=17;k++){
  checkpoint_fault=k;int ok=execute_read(19);
  if(ok)fprintf(stderr,"checkpointfault%u unexpected success\n",k);
  assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!modeled_stores&&!requests&&!acks);
  if(k==9||k==10)assert(path->CPU.local_mask_held&&!unmask_calls);
  if(k>=15)assert(!mask_calls&&!unmask_calls&&!psci_calls);checks++;
 }
 printf("{\"passed\":true,\"checks\":%u,\"full_body_bytes\":%zu,\"same_private_current_Device_CPU_restore_Delete\":true,\"TCS_READ_or_store\":false,\"SOFTWARE_only\":true}\n",checks,sizeof(*path));
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
