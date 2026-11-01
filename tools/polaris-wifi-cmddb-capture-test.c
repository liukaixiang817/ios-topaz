/* Reuse the actual private-parent fixture; only software original PE data. */
#define POLARIS_POWER_PATH_FIXTURE_ONLY 1
#define EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY 1
#include "polaris-wifi-power-path-test.c"
_Static_assert(EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY==1,"explicit diagnostic configuration");
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);
    rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};
    size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    const unsigned cases[]={0,14,15,16,17,18};unsigned checks=0;
    for(unsigned k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
        unsigned scenario=cases[k];int ok=execute(scenario);
        assert(!api_queries&&!psci_calls&&!mask_calls&&!unmask_calls&&!modeled_stores&&!requests&&!acks);
        assert(!path->CPU.attempted&&!path->device[0].attempted&&!path->access.attempted&&!path->transaction.attempted);
        if(scenario==16||scenario==18){
            assert(!ok&&cached_parent()&&cr->client_held&&!delete_calls&&path->unknown);
            assert(scenario==16?path->cmd.error==PWCD_CHANGED:pwcd_unknown(&path->cmd));
        }else{
            assert(ok&&!cached_parent()&&delete_calls==1&&cr->client_returned&&cr->retired);
            assert(path->known_refusal&&path->retired&&path->refusal.retired&&!path->unknown);
            if(!scenario){
                assert(path->cmd.stable&&path->cmd.error==PWCD_CAPTURE_STOP);
                assert(path->cmd.database_bytes[0]==PWCD_DB_BYTES&&path->cmd.database_bytes[1]==PWCD_DB_BYTES);
                assert(!memcmp(path->cmd.database_raw[0],path->cmd.database_raw[1],PWCD_DB_BYTES));
                assert(path->cmd.hash_count[0]==5&&path->cmd.hash_count[4]==5&&path->cmd.hash_count[8]==5);
            }else assert(path->cmd.error==PWCD_DATABASE&&!path->cmd.database_bytes[0]);
        }checks++;
    }
    assert(execute(0)&&!cached_parent());
    parent_report_capacity=2*(sizeof(pwrpt_record)+sizeof(pwrcl_record))+2048;
    parent_report=calloc(1,parent_report_capacity+1);assert(parent_report);pwrpt_report(parent_append);
    check_raw_segment("WIFI_POWER_CLIENT_RAW_V1_BEGIN\r\n","\r\nWIFI_POWER_CLIENT_RAW_V1_END",&pwrcl_record,sizeof(pwrcl_record));
    check_raw_segment("WIFI_POWER_PATH_RAW_V1_BEGIN\r\n","\r\nWIFI_POWER_PATH_RAW_V1_END",&pwrpt_record,sizeof(pwrpt_record));
    assert(strstr(parent_report,"CMDDB_CAPTURE_ONLY_PLANNED_STOP_NO_QUERY_API_NO_CPU_CRITICAL_NO_RSC"));checks++;
    printf("{\"passed\":true,\"checks\":%u,\"software_only\":true,\"original_Query_calls\":0,\"critical_PSCI\":0,\"RSC_stores\":0,\"full_namespace_copies\":2,\"physical_firmware_executed\":false}\n",checks);
    free(parent_report);free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
