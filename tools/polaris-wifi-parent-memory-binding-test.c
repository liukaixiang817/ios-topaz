/* Reproduce the physical preboot's OUTER incoming paic_io -> embedded private
 * reader copy -> body argument, instead of constructing IO inside the body.
 * Original firmware is DATA; only the hardware leaves use software peers. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
#include "polaris-wifi-current-read-test.c"
static const struct paic_io *expected_body_memory,*entry_memory;
static int binding_body(void *v,const struct paic_io *m,struct pwrcl_result*p,struct pwrph_work*w,struct pgcd_context*g)
{
 const struct pwrpt_io *io=v;
 assert(m==expected_body_memory&&m!=entry_memory);
 assert(m->system==entry_memory->system&&m->context==entry_memory->context&&m->arch==entry_memory->arch&&m->identity==entry_memory->identity&&m->order==entry_memory->order);
 ns=&path->prepared_cmd.namespace;ng=g;
 return pwrpt_body((void*)io,m,p,w,g);
}
static int binding_restore(void*ctx,struct pwrpc_transition*t)
{
 (void)ctx;assert(DAIF==0xc0&&!Group1&&path->access.retired&&!path->access.local_held);
 assert(pwra_zero(&path->read,sizeof(path->read))&&pwra_zero(&path->transaction,sizeof(path->transaction)));
 unmask_calls++;t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
 t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int execute_outer_binding(unsigned old_binding)
{
 reset_bound(0);read_fault=19;
 const uint32_t other[3]={0x40900,0x40904,0x50000};for(unsigned k=0;k<3;k++)put(links+0x3004+24*k,other[k],4);
 hardware[0]=1;hardware[0x14/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[0x1c/4]=1;
 hardware[0x30/4]=0x10108;hardware[0x34/4]=0x50000;hardware[0x38/4]=0x77;memcpy(initial,hardware,sizeof(initial));
 c->io.query=path_descriptor;
 const struct paic_io incoming={s,0,path_memory_arch,path_identity,order};
 const struct pwrcl_io client={{incoming,path_locate,current_read_map},client_create,client_drop,own_name};
 entry_memory=&incoming;expected_body_memory=&client.reader.memory;
 /* Same constructor as physical preboot. Only its address argument differs
  * between the preserved0173 bug and corrected caller. No permission bool. */
 struct pwra_io access=pwra_observation_io(old_binding?&incoming:&client.reader.memory,&path->access_context);
 access.translate=current_read_AT;access.read=current_read_load;access.RAM_translate=current_read_RAM_AT;
 assert(access.write==pwra_reject_store);
 struct pwrpt_io io={.cmd={.original={incoming,path_locate,current_read_map},.query=0,.namespace_io={&incoming,0,current_AT}},
  .device={&incoming,0,current_read_AT,current_read_load},.CPU={0,current_read_affinity,path_mask,binding_restore},.access=access,
  .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
 return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,binding_body,&io);
}
int main(int argc,char**argv)
{
 assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
 original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
 uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
 for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
 assert(!execute_outer_binding(1));
 assert(path->error==PWRPT_ARGUMENT&&path->unknown&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!mask_calls&&!psci_calls&&!unmask_calls);
 assert(!path->prepared_cmd.attempted&&pwra_zero(&path->read,sizeof(path->read))&&!modeled_stores&&!requests&&!acks);
 assert(execute_outer_binding(0));
 assert(path->error==PWRPT_ACCESS_CHECKPOINT&&!path->unknown&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path));
 assert(path->access.retired&&!path->access.local_held&&path->access.reads==70&&!path->access.writes&&path->access.CmdDb[0].bytes==PWCD_DB_BYTES&&path->access.CmdDb[1].bytes==PWCD_DB_BYTES);
 assert(cr->retired&&cr->client_returned&&!cr->client_held&&create_calls==1&&delete_calls==1&&psci_calls==14&&mask_calls==1&&unmask_calls==1);
 assert(!DAIF&&Group1==1&&!ticket->spent&&!modeled_stores&&!requests&&!acks&&pwra_zero(&path->read,sizeof(path->read))&&pwra_zero(&path->transaction,sizeof(path->transaction)));
 puts("{\"passed\":true,\"checks\":2,\"actual_outer_reader_copy_and_callback_composition\":true,\"old_binding_rejected_before_CPU\":true,\"same_pointer_guard_retained\":true,\"fixed_binding_full_observation_CPU_restore_Delete\":true,\"SOFTWARE_only\":true,\"actual0173_root_cause_proven\":false}");
 free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
