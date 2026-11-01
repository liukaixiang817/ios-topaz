/* Four complete RO preparations -> current known private client -> actual
 * composed bounded power body -> full restore/Delete, in SOFTWARE only. */
#define POLARIS_CMDDB_PREPARED_FIXTURE_ONLY 1
#include "polaris-wifi-cmddb-prepared-test.c"
static unsigned power_fault,masked_AT,load_phase;
static int power_RAM_AT(void *context,struct pgns_translation *t)
{
    masked_AT++;
    if(power_fault==2){t->issued=1;return 0;}
    int ok=current_AT(context,t);
    if(power_fault==3)t->restored++;
    if(jf==6)t->par^=0x200;
    if(power_fault==4&&!path->transaction.writes&&!injected){cmd_database[PWCD_DB_BYTES-1]^=1;injected=1;}
    return ok;
}
static int power_body(void *ctx,const struct paic_io *m,struct pwrcl_result *p,struct pwrph_work *w,struct pgcd_context *g)
{
    (void)ctx;ns=&path->prepared_cmd.namespace;ng=g;load_phase=1;
    if(power_fault==1)cmd_database[prep->resources[1][0].aux_offset+14]^=1;
    struct pwrpt_io io={.cmd={.original={*m,path_locate,ns_map},.query=0,.namespace_io={m,0,current_AT}},
        .device={m,0,path_AT,path_read},.CPU={0,path_affinity,path_mask,path_restore},
        .access={.memory=m,.context=&path->access_context,.translate=path_AT,.read=path_read,.write=path_write,.RAM_translate=power_RAM_AT},
        .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
    return pwrpt_body(&io,m,p,w,g);
}
static int execute_power(unsigned fault,unsigned oldfault)
{
    reset_bound(0);power_fault=fault;masked_AT=load_phase=0;jf=oldfault;
    if(oldfault==5)put(links+0x3004+48,0x30070,4);
    if(oldfault==10)cf=15;
    if(fault==5)put(rimage+0xd53c,2,4);
    if(fault==6)put(rimage+0xd228,3,4);
    c->io.query=path_descriptor;
    const struct pwrcl_io io={{{s,0,path_memory_arch,path_identity,order},path_locate,ns_map},client_create,client_drop,own_name};
    return pwrcl_run_body(&io,enumeration,2,c,early,cr,rw,power_body,0);
}
int main(int argc,char**argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;int ok=execute_power(0,0);
    if(!ok)fprintf(stderr,"newpower%u phase%u unknown%u private%u bound%u ns%u cpu%u access%u TX%u device%u/%u RAM%u/%u/%u\n",path->error,path->phase,path->unknown,cr->error,path->prepared_cmd.error,path->prepared_cmd.namespace.error,path->CPU.error,path->access.error,path->transaction.error,path->device[0].error,path->device[1].error,path->RAM[0].error,path->RAM[1].error,path->RAM[2].error);
    assert(ok&&path->retired&&!pwrpt_unsafe(path)&&path->prepared_cmd.closed&&cr->retired&&cr->client_returned&&!pwrcl_result_unsafe(cr));
    assert(!api_queries&&psci_calls==14&&mask_calls==1&&unmask_calls==1&&requests==2&&acks==2&&create_calls==1&&delete_calls==1);
    assert(path->access.CmdDb[0].complete&&path->access.CmdDb[1].complete&&masked_AT==64&&path->access.CmdDb[0].bytes==PWCD_DB_BYTES&&path->access.CmdDb[1].bytes==PWCD_DB_BYTES);
    assert(!memcmp(path->access.CmdDb[0].raw,prep->database[1],PWCD_DB_BYTES)&&!memcmp(path->access.CmdDb[1].raw,prep->database[1],PWCD_DB_BYTES));
    assert(votes[0]==8&&votes[1]==2&&votes[2]==1&&!memcmp(hardware,initial,0x30)&&!ticket->spent&&!DAIF&&Group1==1);
    for(unsigned k=0;k<32;k++)for(unsigned j=0;j<2;j++)assert(path->access.CmdDb[j].current_AT[k].issued==1&&path->access.CmdDb[j].current_AT[k].saved==path->access.CmdDb[j].current_AT[k].restored);
    for(size_t k=0;k<sizeof(path->cmd);k++)assert(((const uint8_t*)&path->cmd)[k]==0);
    assert(path->prepared_cmd.bound_after.ticks<=path->CPU.normal.cpu.ticks&&path->prepared_cmd.closed_after.ticks>=path->CPU.after.cpu.ticks);
    checks++;
    memcpy(&pwsp_record,prep,sizeof(pwsp_record));assert(!cached_parent());
    parent_report_capacity=2*(sizeof(pwsp_record)+sizeof(pwrcl_record)+sizeof(pwrpt_record))+2048;
    parent_report=calloc(1,parent_report_capacity+1);assert(parent_report);pwrpt_report(parent_append);
    check_raw_segment("WIFI_CMDDB_STAGED_RO_RAW_V1_BEGIN\r\n","\r\nWIFI_CMDDB_STAGED_RO_RAW_V1_END",&pwsp_record,sizeof(pwsp_record));
    check_raw_segment("WIFI_POWER_CLIENT_RAW_V1_BEGIN\r\n","\r\nWIFI_POWER_CLIENT_RAW_V1_END",&pwrcl_record,sizeof(pwrcl_record));
    check_raw_segment("WIFI_PREPARED_POWER_RAW_V1_BEGIN\r\n","\r\nWIFI_PREPARED_POWER_RAW_V1_END",&pwrpt_record,sizeof(pwrpt_record));
    assert(!strstr(parent_report,"WIFI_POWER_PATH_RAW")&&!strstr(parent_report,"ZERO_VOTE"));free(parent_report);checks++;
    pwsp_record.phase[0].unknown=1;assert(pwrpt_parent_unsafe());memset(&pwsp_record,0,sizeof(pwsp_record));checks++;
    memset(&pwrpt_record,0,sizeof(pwrpt_record));memset(&pwrcl_record,0,sizeof(pwrcl_record));
    for(unsigned fault=1;fault<=4;fault++){
        int v=execute_power(fault,0);if(v||modeled_stores)fprintf(stderr,"powerfault%u result%d stores%u access%u bound%u\n",fault,v,modeled_stores,path->access.error,path->prepared_cmd.error);assert(!v&&cr->client_held&&!delete_calls&&pwrpt_unsafe(path)&&!modeled_stores);checks++;
    }
    const unsigned old[]={1,2,3,4,5,6,7,8,9,10,11,12,13};
    for(unsigned k=0;k<sizeof(old)/sizeof(old[0]);k++){
        unsigned f=old[k];int v=execute_power(0,f);
        if(f==5){assert(path->prepared_cmd.closed);assert(v&&path->known_refusal&&cr->client_returned&&delete_calls==1&&!mask_calls&&!modeled_stores);}
        else if(f==9){assert(!v&&path->retired&&ticket->spent&&cr->client_held&&!delete_calls&&pwrcl_result_unsafe(cr));}
        else if(f==10){assert(!v&&path->retired&&delete_calls==1&&cr->client_held&&cr->outstanding&&!cr->client_returned&&pwrcl_result_unsafe(cr));}
        else{if(v||!cr->client_held||delete_calls||!pwrpt_unsafe(path))fprintf(stderr,"oldfault%u result%d held%u delete%u patherr%u CPU%u access%u tx%u\n",f,v,cr->client_held,delete_calls,path->error,path->CPU.error,path->access.error,path->transaction.error);assert(!v&&cr->client_held&&!delete_calls&&pwrpt_unsafe(path));}
        assert(!api_queries);checks++;
    }
    for(unsigned fault=5;fault<=6;fault++){
        assert(execute_power(fault,0)&&path->error==PWRPT_RAM&&path->RAM[0].error==PWRPB_SOURCE);
        assert(path->known_refusal&&path->prepared_cmd.closed&&cr->client_returned&&delete_calls==1);
        assert(!mask_calls&&!psci_calls&&!modeled_stores&&!pwrpt_unsafe(path));checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"same_preparation_private_power_restore_Delete\":true,\"new_full_body_bytes\":%zu,\"new_access_bytes\":%zu,\"old_unused_CmdDb_raw_still_zero\":true,\"original_CmdDb_Query\":0,\"physical_executed\":false}\n",checks,sizeof(*path),sizeof(path->access));
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
