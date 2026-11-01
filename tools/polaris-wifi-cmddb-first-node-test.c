/* Explicit first-node planned stop. Original firmware is DATA; SOFTWARE
 * callbacks never execute a phone API, physical translation or shared load. */
#define EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP 1
#define POLARIS_CMDDB_BOUNDED_FIXTURE_ONLY 1
#include "polaris-wifi-cmddb-bounded-test.c"
static unsigned stop_fault;
static int stop_AT(void *ctx,struct pgns_translation *t)
{
    if(ns->pass[0].count==1&&!flipped){
        if(stop_fault==40){put(core+PGNS_HEAD_RVA,(uintptr_t)nodes+88,8);flipped=1;}
        if(stop_fault==41){core[0x1000]^=1;flipped=1;}
    }
    return bounded_AT(ctx,t);
}
static int execute_stop(unsigned fault,unsigned cmd_fault)
{
    configure(cmd_fault);nf=stop_fault=fault;ntrans=flipped=original_queries=0;ns=&path->cmd.bounded_namespace[0];
    const struct paic_io memory={s,0,path_memory_arch,path_identity,order};
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,bounded_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original={memory,path_locate,bounded_map},.query=0,
        .namespace_io={0,0,stop_AT}},.enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path};
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,bounded_body,&io);
}
static void zero_target_work(void)
{
    assert(!original_queries&&!api_queries&&!psci_calls&&!mask_calls&&!unmask_calls&&!modeled_stores&&!requests&&!acks);
    assert(!path->device[0].attempted&&!path->CPU.attempted&&!path->access.attempted&&!path->transaction.attempted);
    for(unsigned pass=0;pass<2;pass++){
        assert(!path->cmd.database_bytes[pass]);
        for(unsigned page=0;page<PWCD_PAGES;page++)assert(!path->cmd.bounded_target[pass][page].attempted&&
            !path->cmd.namespace[pass][page].issued&&path->cmd.namespace[pass][page].status==UINT64_MAX);
    }
}
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    const unsigned stopped[]={0,2,3,4,5,13,14,17,18,19,23,24,27,28,29,30,31};unsigned checks=0;
    for(unsigned k=0;k<sizeof(stopped)/sizeof(stopped[0]);k++){
        unsigned fault=stopped[k];int ok=execute_stop(fault,0);zero_target_work();
        if(!ok)fprintf(stderr,"firstnode%u cmd%u ns%u client%u unknown%u count%u\n",fault,path->cmd.error,ns->error,cr->error,path->unknown,ns->pass[0].count);
        assert(ok&&!cached_parent()&&cr->client_returned&&delete_calls==1&&path->known_refusal);
        assert(!path->cmd.stable&&!ns->stable&&!ns->pass[0].complete&&!ns->pass[1].attempted);
        if(fault==13)assert(path->cmd.error==PWCD_DATABASE&&!ns->pass[0].count);
        else assert(path->cmd.error==PWCD_FIRST_NODE_STOP&&pgns_first_node_stopped(ns)&&ns->pass[0].count==1);
        checks++;
    }
    const unsigned unknown[]={7,8,9,10,11,12,16,20,25,40,41};
    for(unsigned k=0;k<sizeof(unknown)/sizeof(unknown[0]);k++){
        assert(!execute_stop(unknown[k],0));zero_target_work();
        assert(cached_parent()&&cr->client_held&&!delete_calls&&!path->retired);checks++;
    }
    for(unsigned fault=14;fault<=18;fault++){
        int ok=execute_stop(0,fault);zero_target_work();
        if(fault==18)assert(!ok&&cached_parent()&&cr->client_held&&!delete_calls);
        else assert(ok&&!cached_parent()&&cr->client_returned&&delete_calls==1);
        if(fault==14||fault==15)assert(!ns->attempted&&path->cmd.error==PWCD_DATABASE);
        else if(fault!=18)assert(pgns_first_node_stopped(ns));checks++;
    }
    assert(execute_stop(0,0)&&!cached_parent());parent_report_capacity=2*(sizeof(pwrpt_record)+sizeof(pwrcl_record))+2048;
    parent_report=calloc(1,parent_report_capacity+1);assert(parent_report);pwrpt_report(parent_append);
    check_raw_segment("WIFI_POWER_PATH_RAW_V2_BEGIN\r\n","\r\nWIFI_POWER_PATH_RAW_V2_END",&pwrpt_record,sizeof(pwrpt_record));
    assert(strstr(parent_report,"FIRST_CORE_NODE_PLANNED_STOP_PARTIAL_NAMESPACE_NO_DATABASE_LOAD"));checks++;
    static struct pgns_result forged;
    for(unsigned k=0;k<3;k++){
        forged=*ns;if(!k)forged.unknown=1;else if(k==1)forged.outstanding=1;else forged.pass[0].hash_count[1]=4;
        assert(!pgns_first_node_stopped(&forged));checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"path_raw_bytes\":%zu,\"namespace_raw_bytes\":%zu,\"planned_error\":%u,\"node_budget\":1,\"database_target_bytes\":0,\"namespace_full_or_stable\":false,\"UNKNOWN_cleared\":false,\"physical_firmware_executed\":false}\n",checks,sizeof(*path),sizeof(*ns),PWCD_FIRST_NODE_STOP);
    free(parent_report);free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
