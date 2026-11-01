/* NEW same actual outer reader-copy composition. Original PE is DATA;
 * hardware leaves are explicit SOFTWARE peers, never device evidence. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_DB_CHECKPOINT 1
#define EFI_XNU_WIFI_PRE_MASK_ARGUMENTS 1
#define EFI_XNU_WIFI_NORMAL_TO_MASKED_DB 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
#include "polaris-wifi-current-read-test.c"
static unsigned normal_fault,normal_target,normal_calls,outer_fault,DB_fault,DB_target,DB_calls,normal_loads;
static int normal_AT(void *ctx,struct pgns_translation*t)
{
 int ok=current_AT(ctx,t);
 if(path->arguments.attempted&&!path->arguments.complete){
  assert(!DAIF&&Group1==1&&!psci_calls&&!mask_calls);normal_calls++;
  if(normal_calls==normal_target)switch(normal_fault){
  case 1:return 0;
  case 2:t->restored^=1;break;
  case 3:t->par^=UINT64_C(0x4500000000000000);break;
  case 4:path->arguments.page[511].valid=1;break;
  case 5:arches+=25000;break;
  case 6:arches+=50000;break;
  case 7:path->work.estimate_ticks=0;break;
  }
 }
 return ok;
}
static int normal_load(void *ctx,uint64_t at,uint32_t*v)
{
 assert(!DAIF&&Group1==1);normal_loads++;
 if(DB_fault==33&&normal_loads==71)path->arguments.native_reads--;
 return current_read_load(ctx,at,v);
}
static int DB_AT(void *ctx,struct pgns_translation*t)
{
 assert(DAIF==0xc0&&!Group1&&path->CPU.local_mask_held&&path->CPU.local_quiescent);
 if(!DB_calls)assert(path->arguments.complete==1&&path->arguments.admitted==1);
 int ok=current_read_RAM_AT(ctx,t);DB_calls++;
 if(DB_calls==DB_target){if(DB_fault==1)t->restored^=1;if(DB_fault==2)return 0;}
 if(DB_calls==(DB_fault>=8?33u:1u))switch(DB_fault){
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
 case 25:arches+=50000;break;
 case 26:path->arguments.page[0].AT.par^=1;break;
 case 27:path->arguments.object[0].bytes++;break;
 case 28:path->arguments.native_reads--;break;
 case 29:path->arguments.page[511].valid=1;break;
 case 30:path->arguments.failed_object=0;break;
 case 31:path->arguments.admitted=2;break;
 case 32:path->arguments.object[9].complete=0;break;
 case 34:path->arguments.provider^=8;break;
 case 35:path->arguments.core^=8;break;
 case 36:path->arguments.ticket^=8;break;
 case 37:path->arguments.memory^=8;break;
 case 38:path->arguments.work^=8;break;
 case 39:path->arguments.native_address^=8;break;
 case 40:path->arguments.before.cpu.daif=0xc0;break;
 case 41:path->arguments.last.cpacr^=1;break;
 case 42:path->arguments.before.cpu.ttbr0^=4096;break;
 case 43:path->arguments.native_last=1;break;
 case 44:path->arguments.pages++;break;
 case 45:path->arguments.error=1;break;
 case 46:path->arguments.complete=0;break;
 case 47:path->arguments.before.cpu.ticks=0;break;
 case 48:path->arguments.last.cpu.ticks+=38400000;break;
 case 49:path->arguments.before.cpu.group1=path->arguments.last.cpu.group1=3;break;
 case 50:path->arguments.before.cpu.daif=path->arguments.last.cpu.daif=0x40;break;
 case 51:path->arguments.before.cpu.ticks=UINT64_MAX;break;
 case 52:path->arguments.before.cpacr^=1;path->arguments.last.cpacr^=1;break;
 case 53:path->arguments.before.cpu.ttbr0^=4096;path->arguments.last.cpu.ttbr0^=4096;break;
 case 54:path->arguments.before.cpu.mpidr^=0x1000000;path->arguments.last.cpu.mpidr^=0x1000000;break;
 case 55:path->work.estimate_ticks=0;break;
 case 56:path->work.sample[0].ticks++;break;
 case 57:path->work.preparation^=8;break;
 case 58:path->work.READ_ticks--;break;
 case 59:path->work.remaining_ticks++;break;
 case 60:path->work.admitted=2;break;
 case 61:path->work.sample[67].after++;break;
 case 62:path->work.maximum_ticks++;break;
 }
 return ok;
}
static int DB_restore(void*ctx,struct pwrpc_transition*t)
{
 (void)ctx;assert(DAIF==0xc0&&!Group1&&!path->access.acquired&&!path->access.local_held&&!path->access.retired);
 assert(path->access.CmdDb[0].complete&&path->access.CmdDb[1].complete&&!path->access.events);
 assert(path->RAM[2].complete&&pwrpb_equal(&path->RAM[1],&path->RAM[2]));
 assert(path->arguments.complete==1&&path->arguments.admitted==1&&!path->arguments.error);
 unmask_calls++;t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
 t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int actual_body(void*v,const struct paic_io*m,struct pwrcl_result*p,struct pwrph_work*w,struct pgcd_context*g)
{ns=&path->prepared_cmd.namespace;ng=g;if(outer_fault==10)arches+=25000;return pwrpt_body(v,m,p,w,g);}
static int execute_normal_masked(unsigned nf,unsigned nt,unsigned df,unsigned dt,unsigned argument)
{
 reset_bound(0);read_fault=19;outer_fault=argument;normal_fault=nf;normal_target=nt;DB_fault=df;DB_target=dt;
 normal_calls=DB_calls=normal_loads=0;
 const uint32_t other[3]={0x40900,0x40904,0x50000};for(unsigned k=0;k<3;k++)put(links+0x3004+24*k,other[k],4);
 hardware[0]=1;hardware[0x14/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[0x1c/4]=1;
 hardware[0x30/4]=0x10108;hardware[0x34/4]=0x50000;hardware[0x38/4]=0x77;memcpy(initial,hardware,sizeof(initial));
 c->io.query=path_descriptor;
 const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
 struct pwrpt_io io={.cmd={.original=client.reader,.query=0,.namespace_io={&client.reader.memory,0,normal_AT}},
  .device={&client.reader.memory,0,current_read_AT,normal_load},.CPU={0,current_read_affinity,path_mask,DB_restore},
  .access=pwra_observation_io(&client.reader.memory,&path->access_context),.enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
 io.access.RAM_translate=DB_AT;
 if(argument==1)io.access.memory=0;
 if(argument==2)io.device.memory=0;
 if(argument==3)io.cmd.namespace_io.memory=0;
 if(argument==4)io.cmd.original.memory.context=&io;
 if(argument==5)io.access.context=&io;
 if(argument==6)io.access.RAM_translate=0;
 if(argument==7)io.access.read=current_read_load;
 if(argument==8)io.access.translate=current_read_AT;
 if(argument==9)io.access.write=current_read_store;
 return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,actual_body,&io);
}
static void no_engine(void)
{assert(!requests&&!acks&&!modeled_stores&&!api_queries&&pwra_zero(&path->transaction,sizeof(path->transaction)));
 if(DB_fault==15)assert(path->read.io.finished==1); /* retain deliberate corruption */
 else assert(pwra_zero(&path->read,sizeof(path->read)));}
int main(int argc,char**argv)
{
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 unsigned checks=0;assert(execute_normal_masked(0,0,0,0,0));no_engine();
 assert(path->error==PWRPT_DATABASE_CHECKPOINT&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path));
 assert(path->arguments.complete==1&&path->arguments.admitted==1&&!path->arguments.error&&normal_calls==path->arguments.pages&&DB_calls==64);
 assert(normal_loads==140&&psci_calls==14&&mask_calls==1&&unmask_calls==1&&!DAIF&&Group1==1&&cr->client_returned&&!cr->client_held&&create_calls==1&&delete_calls==1);
 unsigned normal_pages=path->arguments.pages,targets[20],n=0;
 for(unsigned k=0;k<10;k++){unsigned first=path->arguments.object[k].pages_first+1,last=path->arguments.object[k].pages_first+path->arguments.object[k].pages;targets[n++]=first;if(first!=last)targets[n++]=last;}checks++;
 for(unsigned f=1;f<=2;f++)for(unsigned j=0;j<n;j++){
  assert(!execute_normal_masked(f,targets[j],0,0,0));no_engine();assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!psci_calls&&!mask_calls&&!unmask_calls);checks++;
 }
 for(unsigned j=0;j<n;j++){
  assert(execute_normal_masked(3,targets[j],0,0,0));no_engine();assert(path->error==16&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path)&&path->arguments.declined&&!path->arguments.admitted&&delete_calls==1&&!psci_calls&&!mask_calls&&!unmask_calls);checks++;
 }
 assert(!execute_normal_masked(4,1,0,0,0));no_engine();assert(pwrpt_unsafe(path)&&!delete_calls&&!psci_calls&&!mask_calls);checks++;
 assert(execute_normal_masked(5,1,0,0,0));no_engine();
 assert(path->work.admitted==1&&!path->work.declined&&path->arguments.admitted==1&&path->error==PWRPT_WORK&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path)&&delete_calls==1&&!psci_calls&&!mask_calls);checks++;
 for(unsigned f=6;f<=7;f++){assert(!execute_normal_masked(f,1,0,0,0));no_engine();assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!psci_calls&&!mask_calls);checks++;}
 for(unsigned f=1;f<=2;f++)for(unsigned j=1;j<=64;j++){
  assert(!execute_normal_masked(0,0,f,j,0));no_engine();assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&psci_calls==14&&mask_calls==1&&!unmask_calls);checks++;
 }
 for(unsigned f=3;f<=62;f++){
  if(f==33)continue;
  int ok=execute_normal_masked(0,0,f,0,0);no_engine();if(ok||!pwrpt_unsafe(path)||delete_calls||unmask_calls)fprintf(stderr,"fault%u ok%d body%u unknown%u access%u normalpages%u DBcalls%u\n",f,ok,path->error,path->unknown,path->access.error,normal_calls,DB_calls);
  assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
 }
 assert(!execute_normal_masked(0,0,33,0,0));no_engine();assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&unmask_calls==1&&!DAIF&&Group1==1);checks++;
 for(unsigned f=1;f<=9;f++){assert(!execute_normal_masked(0,0,0,0,f));no_engine();assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!normal_calls&&!psci_calls&&!mask_calls);checks++;}
 assert(execute_normal_masked(0,0,0,0,10));no_engine();assert(path->work.declined&&path->retired&&!pwrpt_unsafe(path)&&delete_calls==1&&!normal_calls&&!psci_calls&&!mask_calls);checks++;
 printf("{\"passed\":true,\"checks\":%u,\"actual_outer_reader_copy\":true,\"normal_SOFTWARE_pages\":%u,\"boundary_targets\":%u,\"fresh_masked_DB_snapshots\":2,\"masked_RAM_AT\":64,\"original200ms_no_reset\":true,\"no_masked_RSC_reader_access_lifetime_or_engine\":true,\"complete_known_retirement_before_USB\":true,\"SOFTWARE_only\":true,\"body_bytes\":%zu}\n",checks,normal_pages,n,sizeof(*path));
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
