/* Real outer lifecycle, SOFTWARE peers and synthetic status words only.
 * The actual photographed0183 status value remains UNKNOWN. */
#define POLARIS_CURRENT_WORD_READ_TEST_MAIN prior_current_word_read_main
#include "polaris-wifi-current-word-read-test.c"
static unsigned saved_command,own_target,own_bad_bit,prefix_mutation,prefix_phase,mutated,own_triggered_mask;
static uint32_t saved_status;
static int saved_status_load(void *v,uint64_t at,uint32_t *value)
{
 int ok=word_load(v,at,value);struct pwrsc_transaction *t=&path->read.io;
 if(at==pwrsc_tcs(t)+0x3c&&(t->phase==2||t->phase==4||t->phase==6)&&
    (own_triggered_mask&(1u<<(t->phase/2-1))))*value|=1;
 if(at==pwrsc_tcs(t)+0x3c&&t->phase==2*own_target&&own_target&&requests==own_target)
  *value^=UINT32_C(1)<<own_bad_bit;
 if(!mutated&&prefix_mutation&&t->attempted&&t->phase==prefix_phase&&at==pwrsc_tcs(t)+0x3c){
  mutated=1;
  switch(prefix_mutation){
  case 1:t->writes++;break;case 2:t->triggers++;break;case 3:t->completed++;break;
  case 4:t->acknowledged++;break;case 5:t->steps=1;break;
  case 6:path->read.response_seen^=1;break;case 7:path->read.valid=7;break;
  case 8:path->read.reserved=1;break;case 9:t->phase=1;break;
  case 10:t->history[t->events-1].phase^=1;break;
  case 11:path->access.command_status_OR[1]^=UINT32_C(1)<<29;break;
  default:assert(0);
  }
 }
 return ok;
}
static int saved_status_body(void *v,const struct paic_io *m,struct pwrcl_result *p,struct pwrph_work *w,struct pgcd_context *g)
{ns=&path->prepared_cmd.namespace;ng=g;return pwrpt_body(v,m,p,w,g);}
static int execute_saved_status(void)
{
 reset_bound(0);read_fault=19;word_calls=normal_calls=DB_calls=mutated=0;
 word_target=word_fault=word_byte=word_corrupt=normal_target=normal_fault=pre_corrupt=DB_target=DB_fault=after_fault=binding_fault=0;
 const uint32_t other[3]={0x40900,0x40904,0x50000};for(unsigned k=0;k<3;k++)put(links+0x3004+24*k,other[k],4);
 hardware[0]=1;hardware[0x14/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[0x1c/4]=1;
 hardware[0x30/4]=0x10108;hardware[0x34/4]=0x50000;hardware[0x38/4]=0x77;
 hardware[(0x3c+20*saved_command)/4]=saved_status;memcpy(initial,hardware,sizeof(initial));c->io.query=path_descriptor;
 const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
 struct pwrpt_io io={.cmd={.original=client.reader,.query=0,.namespace_io={&client.reader.memory,0,word_normal_AT}},
 .device={&client.reader.memory,0,current_read_AT,current_read_load},.CPU={0,current_read_affinity,path_mask,current_read_restore},
 .access={&client.reader.memory,&path->access_context,current_read_AT,saved_status_load,current_read_store,word_DB_AT},
 .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
 return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,saved_status_body,&io);
}
static void check_success(void)
{
 assert(path->retired&&path->error==PWRPT_READ_ONLY&&!pwrpt_unsafe(path)&&delete_calls==1&&unmask_calls==1);
 assert(requests==3&&acks==3&&pwrr_retired(&path->read)&&path->CPU.local_restored&&path->access.retired);
 assert(path->read.io.saved.command[saved_command][3]==saved_status);
 assert(path->access.command_status_OR[saved_command]==(saved_status|(saved_command?0:PWRSC_DONE)));
 assert(!memcmp(hardware,initial,0x30)&&votes[0]==8&&votes[1]==2&&votes[2]==1);
 assert(pwra_zero(&path->transaction,sizeof(path->transaction))&&pwra_zero(path->saved,sizeof(path->saved)));
}
#ifndef POLARIS_SAVED_STATUS_READ_TEST_MAIN
#define POLARIS_SAVED_STATUS_READ_TEST_MAIN main
#endif
int POLARIS_SAVED_STATUS_READ_TEST_MAIN(int argc,char **argv)
{
 assert(prior_current_word_read_main(argc,argv)==0);
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 unsigned checks=238;
 for(saved_command=0;saved_command<3;saved_command++){
  for(unsigned bit=0;bit<32;bit++){saved_status=UINT32_C(1)<<bit;assert(execute_saved_status());check_success();checks++;}
  saved_status=UINT32_MAX;assert(execute_saved_status());check_success();checks++;
 }
 saved_command=0;saved_status=UINT32_MAX;
 for(own_target=1;own_target<=3;own_target++)for(own_bad_bit=0;own_bad_bit<32;own_bad_bit++){
  if(own_bad_bit==0)continue; /* bit0 is the documented TRIGGERED field. */
  assert(!execute_saved_status()&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
  assert(requests==own_target&&acks==own_target-1&&path->read.io.completed==own_target-1);
  assert(path->access.history[path->access.events-1].io.value==(PWRSC_DONE^(UINT32_C(1)<<own_bad_bit)));
  if((UINT32_C(1)<<own_bad_bit)&~PWRSC_DONE)assert(path->access.error==PWRA_UNKNOWN_STATUS);
  else assert(path->read.io.error==PWRSC_COMPLETION);
  checks++;
 }
 own_target=0;saved_command=2;saved_status=0;
 for(unsigned phase=0;phase<2;phase++)for(prefix_mutation=1;prefix_mutation<=11;prefix_mutation++){
  if(phase==1&&(prefix_mutation==1||prefix_mutation==5))continue; /* writes/steps are nonzero here; full journal checks exact counts. */
  prefix_phase=phase?7:0;
  assert(!execute_saved_status()&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&mutated);
  if(prefix_mutation<10)assert(path->access.error==PWRA_PREFIX);
  checks++;
 }
 printf("{\"passed\":true,\"checks\":%u,\"prior_current_word_outer\":238,\"saved_status_all32bits_each3commands\":true,\"own_pending_bad_bit_cases\":93,\"snapshots_RAW_not_completion_or_grant\":true,\"full_status_OR_bound_to_journal\":true,\"new_IRQ_DONE_idle_fullRW_CPU_source_Delete_unchanged\":true,\"synthetic_words_not_actual0183_status\":true,\"SOFTWARE_only\":true}\n",checks);
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
