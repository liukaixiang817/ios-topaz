/* Real private caller and unchanged original firmware as DATA. Only hardware
 * leaves are SOFTWARE peers; no masked MMIO reader is installed or called. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_DB_CHECKPOINT 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
struct paic_io;struct pwrcl_result;struct pwrph_work;struct pgcd_context;
static int database_body(void*,const struct paic_io*,struct pwrcl_result*,struct pwrph_work*,struct pgcd_context*);
#define PWRPT_READ_BODY database_body
#include "polaris-wifi-current-read-test.c"
static unsigned database_fault,database_target,RAM_calls,normal_loads;
static int database_normal_load(void *ctx,uint64_t at,uint32_t *value)
{assert(!DAIF&&Group1==1);normal_loads++;return current_read_load(ctx,at,value);}
static int database_restore(void*ctx,struct pwrpc_transition*t)
{
 (void)ctx;assert(DAIF==0xc0&&!Group1&&!path->access.acquired&&!path->access.local_held&&!path->access.retired);
 assert(path->access.CmdDb[0].complete&&path->access.CmdDb[1].complete&&!path->access.events);
 assert(pwra_zero(&path->read,sizeof(path->read))&&pwra_zero(&path->transaction,sizeof(path->transaction)));
 assert(path->RAM[2].complete&&pwrpb_equal(&path->RAM[1],&path->RAM[2]));unmask_calls++;
 t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
 t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int database_RAM_AT(void*ctx,struct pgns_translation*t)
{
 assert(DAIF==0xc0&&!Group1);int ok=current_read_RAM_AT(ctx,t);RAM_calls++;
 if(database_fault==1&&RAM_calls==database_target)t->restored^=1;
 if(database_fault==2&&RAM_calls==database_target)return 0;
 if(RAM_calls==(database_fault>=8?33u:1u)){
 switch(database_fault){
 case 3:cmd_image[0x1000]^=1;break;
 case 4:cmd_database[PWCD_DB_BYTES-1]^=1;break;
 case 5:*native_on=1;break;
 case 6:core[0x1000]^=1;break;
 case 7:((struct efi_loaded*)(arena+0x188000))->bytes^=4096;break;
 case 8:path->access.CmdDb[0].raw[0]^=1;break;
 case 9:path->access.CmdDb[0].hashes[0][0]^=1;break;
 case 10:path->access.CmdDb[0].current_AT[0].restored^=1;break;
 case 11:path->access.client^=8;break;
 case 12:path->access.events=1;break;
 case 13:path->access.acquired=1;break;
 case 14:path->access.retired=1;break;
 case 15:path->read.io.finished=1;break;
 case 16:path->access_context.io.read=current_read_load;break;
 case 17:path->access_context.io.translate=current_read_AT;break;
 case 18:path->access.history[0].io.issued=1;break;
 case 19:path->access.desired[0]=1;break;
 case 20:path->access.config=1;break;
 case 21:path->access.CmdDb[0].hash_count=4;break;
 case 22:path->access.CmdDb[0].bytes--;break;
 case 23:path->access_context.io.write=current_read_store;break;
 case 24:path->access.post_reads=35;break;
 case 25:arches+=50000;break; /* >200ms in the unchanged100tick/sample peer */
 }}
 return ok;
}
static int database_body(void*v,const struct paic_io*m,struct pwrcl_result*p,struct pwrph_work*w,struct pgcd_context*g)
{
 struct pwrpt_io io=*(const struct pwrpt_io*)v;io.CPU.restore=database_restore;
 io.device.read=database_normal_load;io.access=pwra_observation_io(m,&path->access_context);
 assert(!io.access.translate&&!io.access.read&&io.access.write==pwra_reject_store);
 io.access.RAM_translate=database_RAM_AT;
 struct paic_io wrong=*m;
 if(database_fault==26)io.access.read=current_read_load;
 if(database_fault==27)io.access.translate=current_read_AT;
 if(database_fault==28)io.access.RAM_translate=0;
 if(database_fault==29)io.access.context=&io;
 if(database_fault==30)io.access.memory=&wrong;
 if(database_fault==31)io.access.write=current_read_store;
 if(database_fault==32)arches+=25000;
 return pwrpt_body(&io,m,p,w,g);
}
int main(int argc,char**argv)
{
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 unsigned checks=0;database_fault=0;RAM_calls=normal_loads=0;assert(execute_read(19));
 assert(path->error==PWRPT_DATABASE_CHECKPOINT&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path));
 assert(path->access.attempted&&!path->access.acquired&&!path->access.local_held&&!path->access.retired);
 assert(path->access.CmdDb[0].complete&&path->access.CmdDb[1].complete&&RAM_calls==64&&normal_loads==140);
 assert(!path->access.events&&!path->access.reads&&!path->access.writes&&!path->access.pre_reads&&!path->access.post_reads);
 assert(!requests&&!acks&&!modeled_stores&&!api_queries&&pwra_zero(&path->read,sizeof(path->read))&&pwra_zero(&path->transaction,sizeof(path->transaction)));
 assert(cr->retired&&cr->client_returned&&!cr->client_held&&create_calls==1&&delete_calls==1&&psci_calls==14&&mask_calls==1&&unmask_calls==1&&!DAIF&&Group1==1&&!ticket->spent);checks++;
 for(unsigned fault=1;fault<=2;fault++)for(unsigned k=1;k<=64;k++){
  database_fault=fault;database_target=k;RAM_calls=normal_loads=0;assert(!execute_read(19));
  assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!requests&&!acks&&!modeled_stores);checks++;
 }
 for(unsigned fault=3;fault<=25;fault++){
  database_fault=fault;RAM_calls=normal_loads=0;int ok=execute_read(19);
  if(ok||!pwrpt_unsafe(path)||delete_calls||unmask_calls)fprintf(stderr,"databasefault%u ok%d error%u unknown%u access%u mask%u unmask%u\n",fault,ok,path->error,path->unknown,path->access.error,mask_calls,unmask_calls);
  assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!requests&&!acks&&!modeled_stores);checks++;
 }
 for(unsigned fault=26;fault<=31;fault++){
  database_fault=fault;RAM_calls=normal_loads=0;assert(!execute_read(19));
  assert(pwrpt_unsafe(path)&&!mask_calls&&!psci_calls&&!delete_calls&&!requests&&!acks&&!modeled_stores);checks++;
 }
 database_fault=32;assert(execute_read(19)&&path->work.declined&&path->retired&&!pwrpt_unsafe(path)&&delete_calls==1&&!mask_calls&&!psci_calls);checks++;
 printf("{\"passed\":true,\"checks\":%u,\"body_bytes\":%zu,\"full_masked_RAM_captures\":2,\"RAM_AT\":64,\"masked_RSC_callbacks\":false,\"no_access_acquired_held_retired_forged\":true,\"SOFTWARE_only\":true}\n",checks,sizeof(*path));
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
