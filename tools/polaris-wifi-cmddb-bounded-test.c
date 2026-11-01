/* One actual private-client/finite-Core-namespace/CmdDb/retirement body;
 * original images, map, translation and external services are SOFTWARE. */
#define EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY 1
#define EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE 1
#define POLARIS_GCD_NAMESPACE_FIXTURE_ONLY 1
#include "polaris-wifi-gcd-namespace-test.c"
static unsigned original_queries;
static int no_original_GCD(void *ctx,uint64_t fn,uint64_t page,struct pgcd_descriptor *d,uint64_t *status)
{(void)ctx;(void)fn;(void)page;(void)d;(void)status;original_queries++;return 0;}
static int bounded_map(void *ctx,struct efi_system *sys,uint8_t *raw,struct paic_map_sample *sample)
{
    if(jf==16&&path->cmd.attempted&&path->cmd.maps[0].bytes)cmd_database[PWCD_DB_BYTES-1]^=1;
    return ns_map(ctx,sys,raw,sample)&&(jf!=18||!path->cmd.attempted);
}
static int bounded_AT(void *ctx,struct pgns_translation *t)
{
    if(ns->stable&&!flipped){
        if(nf==28){put(core+PGNS_HEAD_RVA,(uintptr_t)nodes+88,8);flipped=1;}
        if(nf==29){nodes[80+48]^=1;flipped=1;}
        if(nf==30){core[0x1000]^=1;flipped=1;}
        if(nf==31){t->issued=1;flipped=1;return 0;}
    }
    return ns_AT(ctx,t);
}
static int bounded_body(void *context,const struct paic_io *memory,struct pwrcl_result *p,
    struct pwrph_work *work,struct pgcd_context *g)
{
    ng=g;g->io.arch=ns_arch;g->io.query=no_original_GCD;
    fill_namespace(nf==17?512:nf==18?513:3);
    return pwrpt_body(context,memory,p,work,g);
}
static int execute_bounded(unsigned fault,unsigned cmd_fault)
{
    configure(cmd_fault);nf=fault;ntrans=flipped=original_queries=0;ns=&path->cmd.bounded_namespace[0];
    const struct paic_io memory={s,0,path_memory_arch,path_identity,order};
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,bounded_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original={memory,path_locate,bounded_map},.query=0,
        .namespace_io={0,0,bounded_AT}},.enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path};
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,bounded_body,&io);
}
#ifndef POLARIS_CMDDB_BOUNDED_FIXTURE_ONLY
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    const unsigned faults[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,23,24,25,27,28,29,30,31};
    unsigned checks=0;
    for(unsigned k=0;k<sizeof(faults)/sizeof(faults[0]);k++){
        unsigned fault=faults[k];int ok=execute_bounded(fault,0);
        assert(!original_queries&&!api_queries&&!psci_calls&&!mask_calls&&!unmask_calls&&!modeled_stores&&!requests&&!acks);
        assert(!path->device[0].attempted&&!path->CPU.attempted&&!path->access.attempted&&!path->transaction.attempted);
        if(fault==0||fault==1||fault==13||fault==17||fault==23||fault==24){
            if(!ok)fprintf(stderr,"bounded%u cmd%u ns%u phase%u count%u client%u unknown%u\n",fault,path->cmd.error,ns->error,ns->phase,ns->pass[0].count,cr->error,path->unknown);
            assert(ok&&!cached_parent()&&cr->retired&&cr->client_returned&&delete_calls==1&&path->known_refusal&&path->refusal.retired);
            if(fault==0||fault==17){
                assert(path->cmd.error==PWCD_CAPTURE_STOP&&path->cmd.stable);
                for(unsigned pass=0;pass<2;pass++){
                    assert(path->cmd.bounded_namespace[pass].stable&&path->cmd.database_bytes[pass]==PWCD_DB_BYTES);
                    assert(path->cmd.bounded_namespace[pass].pass[0].count==(fault==17?512u:3u));
                    for(unsigned page=0;page<PWCD_PAGES;page++){
                        assert(path->cmd.bounded_target[pass][page].complete&&path->cmd.bounded_target[pass][page].hash_count==5);
                        const struct pgcd_observation *q=&path->cmd.namespace[pass][page];
                        assert(!q->issued&&!q->returned&&!q->guard.entered&&q->status==UINT64_MAX&&q->descriptor.type==2);
                    }
                    assert(path->cmd.bounded_target[pass][PWCD_PAGES].complete);
                }
            }else assert(path->cmd.error==PWCD_DATABASE&&!path->cmd.database_bytes[0]);
        }else{
            assert(!ok&&cached_parent()&&path->unknown&&cr->client_held&&!delete_calls&&!path->retired);
            assert(ns->error||pwcd_unknown(&path->cmd));
        }checks++;
    }
    for(unsigned fault=14;fault<=18;fault++){
        int ok=execute_bounded(0,fault);
        if(fault==16||fault==18)assert(!ok&&cached_parent()&&cr->client_held&&!delete_calls);
        else assert(ok&&!cached_parent()&&cr->client_returned&&delete_calls==1);
        assert(!original_queries&&!api_queries&&!psci_calls&&!modeled_stores);checks++;
    }
    assert(execute_bounded(0,0)&&!cached_parent());
    parent_report_capacity=2*(sizeof(pwrpt_record)+sizeof(pwrcl_record))+2048;
    parent_report=calloc(1,parent_report_capacity+1);assert(parent_report);pwrpt_report(parent_append);
    check_raw_segment("WIFI_POWER_CLIENT_RAW_V1_BEGIN\r\n","\r\nWIFI_POWER_CLIENT_RAW_V1_END",&pwrcl_record,sizeof(pwrcl_record));
    check_raw_segment("WIFI_POWER_PATH_RAW_V2_BEGIN\r\n","\r\nWIFI_POWER_PATH_RAW_V2_END",&pwrpt_record,sizeof(pwrpt_record));
    assert(strstr(parent_report,"CMDDB_CAPTURE_BOUNDED_CORE_RAM_NAMESPACE_NO_ORIGINAL_GCD_QUERY_NO_CPU_CRITICAL_NO_RSC"));checks++;
    path->cmd.bounded_namespace[0].unknown=1;assert(cached_parent());path->cmd.bounded_namespace[0].unknown=0;checks++;
    path->cmd.bounded_target[0][0].complete=0;assert(cached_parent());checks++;
    printf("{\"passed\":true,\"checks\":%u,\"path_raw_bytes\":%zu,\"cmd_raw_bytes\":%zu,\"namespace_raw_bytes\":%zu,\"target_guard_bytes\":%zu,\"original_GCD_Query\":0,\"original_CmdDb_Query\":0,\"critical_PSCI\":0,\"RSC_stores\":0,\"physical_firmware_executed\":false}\n",checks,sizeof(*path),sizeof(path->cmd),sizeof(*ns),sizeof(struct pgns_target));
    free(parent_report);free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
#endif
