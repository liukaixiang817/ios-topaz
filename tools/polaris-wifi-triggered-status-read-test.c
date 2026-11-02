/* SOFTWARE full outer lifecycle. Physical0184 supplied CMD_STATUS10101,
 * not a CMD_RESP_DATA value or a successful completion/retirement receipt. */
#define POLARIS_SAVED_STATUS_READ_TEST_MAIN prior_saved_status_read_main
#include "polaris-wifi-saved-status-read-test.c"
int main(int argc,char **argv)
{
 assert(prior_saved_status_read_main(argc,argv)==0);
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 unsigned checks=450;prefix_mutation=own_target=0;saved_command=2;saved_status=UINT32_MAX;
 for(own_triggered_mask=0;own_triggered_mask<8;own_triggered_mask++){
  assert(execute_saved_status());check_success();
  for(unsigned k=0;k<3;k++)assert(path->read.io.status_OR[k]==(PWRSC_DONE|((own_triggered_mask>>k)&1)));
  assert(path->access.command_status_OR[0]==(PWRSC_DONE|(own_triggered_mask!=0)));
  assert(!path->CPU.unknown&&path->CPU.local_restored&&path->read.io.triggers==3&&path->read.io.completed==3&&path->read.io.acknowledged==3);
  checks++;
 }
 own_triggered_mask=7;assert(execute_saved_status());check_success();
 struct pwrr_transaction *copy=malloc(sizeof(*copy));assert(copy);
 for(unsigned k=0;k<3;k++)for(unsigned bit=0;bit<32;bit++){
  *copy=path->read;copy->io.status_OR[k]^=UINT32_C(1)<<bit;assert(!pwrr_retired(copy));checks++;
  *copy=path->read;unsigned found=0;
  for(unsigned n=0;n<copy->io.events;n++)if(copy->io.history[n].phase==2*(k+1)&&copy->io.history[n].address==pwrsc_tcs(&copy->io)+0x3c){
   copy->io.history[n].value^=UINT32_C(1)<<bit;found++;break;
  }
  assert(found&&!pwrr_retired(copy));checks++;
 }
 free(copy);
 for(own_target=1;own_target<=3;own_target++)for(own_bad_bit=1;own_bad_bit<32;own_bad_bit++){
  assert(!execute_saved_status()&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
  assert(requests==own_target&&acks==own_target-1&&path->read.io.completed==own_target-1);
  assert(path->access.history[path->access.events-1].io.value==((PWRSC_DONE|1)^(UINT32_C(1)<<own_bad_bit)));
  if(own_bad_bit==8||own_bad_bit==16)assert(path->read.io.error==PWRSC_COMPLETION);
  else assert(path->access.error==PWRA_UNKNOWN_STATUS);
  checks++;
 }
 printf("{\"passed\":true,\"checks\":%u,\"prior_affected_outer\":450,\"triggered_combinations_full_outer\":8,\"independent_summary_and_journal_corruptions\":192,\"triggered_missing_required_or_unknown_bits\":93,\"raw_status_preserved\":true,\"new_IRQ_required_DONE_idle_full_restore_Delete\":true,\"SOFTWARE_only\":true}\n",checks);
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
