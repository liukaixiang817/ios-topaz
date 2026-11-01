/* Same real private caller, current full DB, checked geometry and retirement.
 * All firmware inputs are DATA. No software or physical command engine runs. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
struct paic_io;struct pwrcl_result;struct pwrph_work;struct pgcd_context;
static int observation_body(void*,const struct paic_io*,struct pwrcl_result*,struct pwrph_work*,struct pgcd_context*);
#define PWRPT_READ_BODY observation_body
#include "polaris-wifi-current-read-test.c"
static unsigned observation_fault,observation_target,RAM_translations;
static int observation_restore(void*ctx,struct pwrpc_transition*t)
{
 (void)ctx;assert(DAIF==0xc0&&!Group1&&path->access.retired&&!path->access.local_held);
 assert(pwra_zero(&path->read,sizeof(path->read))&&pwra_zero(&path->transaction,sizeof(path->transaction)));
 assert(path->RAM[2].complete&&pwrpb_equal(&path->RAM[1],&path->RAM[2]));unmask_calls++;
 t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
 t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int observation_RAM_AT(void*ctx,struct pgns_translation*t)
{
 int ok=current_read_RAM_AT(ctx,t);RAM_translations++;
 if(observation_fault==1&&RAM_translations==observation_target)t->restored^=1;
 if(observation_fault==2&&RAM_translations==observation_target)return 0;
 return ok;
}
static int observation_load(void*ctx,uint64_t at,uint32_t*value)
{
 int ok=current_read_load(ctx,at,value);
 if(path->access.attempted&&path->access.events==observation_target){
  if(observation_fault==3)return 0;
  if(observation_fault==4)*native_on=1;
  if(observation_fault==5)path->access.history[path->access.events-1].engine_event=1;
  if(observation_fault==6)path->read.io.finished=1;
  if(observation_fault==7)(void)pwra_reject_store(&path->access_context,at,0);
  if(observation_fault==8)core[0x1000]^=1;
  if(observation_fault==9)cmd_database[PWCD_DB_BYTES-1]^=1;
  if(observation_fault==10&&at==PWRSC_BASE)*value^=2;
  if(observation_fault==15)path->access.CmdDb[0].raw[0]^=1;
  if(observation_fault==16)path->access.CmdDb[0].current_AT[0].restored^=1;
  if(observation_fault==17)path->access.CmdDb[0].hashes[0][0]^=1;
  if(observation_fault==18)path->access.read_transaction^=8;
  if(observation_fault==19)path->access.client^=8;
  if(observation_fault==20)path->access.history[0].io.translation.restored^=1;
 }
 return ok;
}
static int observation_body(void*v,const struct paic_io*m,struct pwrcl_result*p,struct pwrph_work*w,struct pgcd_context*g)
{
 struct pwrpt_io io=*(const struct pwrpt_io*)v;io.CPU.restore=observation_restore;
 io.access.read=observation_load;io.access.RAM_translate=observation_RAM_AT;io.access.write=pwra_reject_store;
 if(observation_fault==11)io.access.write=current_read_store;
 if(observation_fault==12)io.record->access.retired=1;
 if(observation_fault==13)io.record->read.io.finished=1;
 if(observation_fault==14)arches+=25000;
 return pwrpt_body(&io,m,p,w,g);
}
int main(int argc,char**argv)
{
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 unsigned checks=0;observation_fault=0;RAM_translations=0;assert(execute_read(19));
 assert(path->error==PWRPT_ACCESS_CHECKPOINT&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path));
 assert(path->access.retired&&!path->access.local_held&&path->access.reads==70&&path->access.events==70&&!path->access.writes);
 assert(path->access.CmdDb[0].complete&&path->access.CmdDb[1].complete&&path->access.CmdDb[0].bytes==PWCD_DB_BYTES&&path->access.CmdDb[1].bytes==PWCD_DB_BYTES&&RAM_translations==64);
 assert(pwra_zero(&path->read,sizeof(path->read))&&pwra_zero(&path->transaction,sizeof(path->transaction))&&!requests&&!acks&&!modeled_stores&&!api_queries);
 assert(cr->retired&&cr->client_returned&&!cr->client_held&&create_calls==1&&delete_calls==1&&psci_calls==14&&mask_calls==1&&unmask_calls==1&&!DAIF&&Group1==1&&!ticket->spent&&path->prepared_cmd.closed);checks++;
 for(unsigned fault=1;fault<=2;fault++)for(unsigned k=1;k<=64;k++){
  observation_fault=fault;observation_target=k;RAM_translations=0;int ok=execute_read(19);
  if(ok)fprintf(stderr,"RAMfault%u/%u unexpected success\n",fault,k);
  assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!requests&&!acks&&!modeled_stores);checks++;
 }
 for(unsigned fault=3;fault<=10;fault++){
  observation_fault=fault;observation_target=fault==10?2:1;RAM_translations=0;int ok=execute_read(19);
  if(ok)fprintf(stderr,"accessfault%u unexpected success\n",fault);
  assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!requests&&!acks&&!modeled_stores);checks++;
 }
 for(unsigned fault=11;fault<=13;fault++){
  observation_fault=fault;RAM_translations=0;assert(!execute_read(19)&&pwrpt_unsafe(path)&&!mask_calls&&!psci_calls&&!delete_calls&&!modeled_stores);checks++;
 }
 observation_fault=14;assert(execute_read(19)&&path->work.declined&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path)&&delete_calls==1&&!mask_calls&&!psci_calls&&!modeled_stores);checks++;
 for(unsigned fault=15;fault<=20;fault++){
  observation_fault=fault;observation_target=36;RAM_translations=0;assert(!execute_read(19)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!modeled_stores&&!requests&&!acks);checks++;
 }
 printf("{\"passed\":true,\"checks\":%u,\"whole_body_bytes\":%zu,\"full_current_masked_DB_captures\":2,\"RAM_AT\":64,\"checked_geometry_reads\":70,\"READ_requests_TCSstores\":false,\"SOFTWARE_only\":true}\n",checks,sizeof(*path));
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
