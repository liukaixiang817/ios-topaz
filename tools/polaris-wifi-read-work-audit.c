/* Instrument unchanged production C functions in an existing SOFTWARE peer.
 * Original PE bytes are DATA; no SMC, AT or MMIO executes. */
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
#include "polaris-wifi-current-read-test.c"
static unsigned audit_active,audit_counts[9][3];
static __attribute__((no_instrument_function)) unsigned audit_stage(void)
{
 if(!path||!path->attempted)return 0;
 if(!path->CPU.attempted)return 1;
 if(!path->CPU.local_mask_held&&!path->CPU.retired)return 2;
 if(path->CPU.local_mask_held){if(!path->CPU.local_quiescent)return 3;if(!path->read.io.finished)return 4;if(!path->access.retired)return 5;return 6;}
 if(!path->prepared_cmd.closed)return 7;
 return 8;
}
void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void *fn,void *caller)
{
 (void)caller;if(fn==(void*)pwrcl_run_body)audit_active=1;
 if(!audit_active)return;
 if(fn==(void*)pgci_verify)audit_counts[audit_stage()][0]++;
 if(fn==(void*)pwrpi_verify)audit_counts[audit_stage()][1]++;
 if(fn==(void*)pwcdi_verify)audit_counts[audit_stage()][2]++;
}
void __attribute__((no_instrument_function)) __cyg_profile_func_exit(void *fn,void *caller)
{(void)caller;if(fn==(void*)pwrcl_run_body)audit_active=0;}
int main(int argc,char**argv)
{
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 assert(execute_read(19)&&path->retired&&!pwrpt_unsafe(path)&&cr->retired&&pwrr_retired(&path->read));
 unsigned total[3]={0},after[3]={0};printf("{\"SOFTWARE_only\":true,\"physical_calls\":false,\"selected_pages\":%u,\"stages_Core_RPMh_CmdDb\":[",path->prepared_cmd.pages);
 for(unsigned j=0;j<9;j++){printf("%s[%u,%u,%u]",j?",":"",audit_counts[j][0],audit_counts[j][1],audit_counts[j][2]);for(unsigned k=0;k<3;k++){total[k]+=audit_counts[j][k];if(j>=2)after[k]+=audit_counts[j][k];}}
 printf("],\"whole_private_counts\":[%u,%u,%u],\"from_CPU_begin_counts\":[%u,%u,%u],\"READ_events\":%u,\"READ_writes\":%u,\"checked_access_events\":%u,\"RAM_rows_fixture\":%u}\n",total[0],total[1],total[2],after[0],after[1],after[2],path->read.io.events,path->read.io.writes,path->access.events,path->RAM[0].rows);
 assert(after[0]==4+path->prepared_cmd.pages&&after[1]==4&&after[2]==3);
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
