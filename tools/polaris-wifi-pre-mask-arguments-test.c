/* The physical outer reader-copy composition and complete original private
 * lifecycle, with explicit SOFTWARE hardware leaves. Original PE is DATA. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT 1
#define EFI_XNU_WIFI_READ_DB_CHECKPOINT 1
#define EFI_XNU_WIFI_PRE_MASK_ARGUMENTS 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
#include "polaris-wifi-current-read-test.c"
static unsigned argument_fault,argument_target,argument_AT_calls;
static int argument_AT(void *ctx,struct pgns_translation *t)
{
    int ok=current_AT(ctx,t);
    if(!path->arguments.attempted||path->arguments.complete)return ok;
    assert(!DAIF&&Group1==1&&!psci_calls&&!mask_calls&&!unmask_calls);
    argument_AT_calls++;
    if(argument_AT_calls==argument_target){
        switch(argument_fault){
        case 1:return 0;
        case 2:t->restored^=1;break;
        case 3:t->returned=0;break;
        case 4:t->issued=0;break;
        case 5:t->page+=4096;break;
        case 6:t->par^=1;break;
        case 7:t->par^=0x200;break;
        case 8:t->par^=UINT64_C(0xbb00000000000000);break;
        case 9:t->par^=4096;break;
        case 10:*native_on=1;break;
        case 11:arches+=50000;break;
        case 12:((struct efi_loaded*)(arena+0x188000))->bytes^=4096;break;
        case 13:path->arguments.unknown=1;break;
        case 16:path->arguments.object[0].address+=4096;break;
        case 17:path->arguments.object[0].bytes+=4096;break;
        case 18:path->arguments.pages++;break;
        case 19:path->arguments.outstanding=0;break;
        case 20:path->arguments.objects++;break;
        case 21:path->arguments.complete=1;break;
        case 22:path->arguments.declined=1;break;
        case 23:path->arguments.admitted=1;break;
        case 24:path->arguments.error=PWRPA_TRANSLATION;break;
        case 31:path->arguments.object[0].in_self=2;break;
        case 32:path->arguments.object[0].complete=1;break;
        case 33:path->arguments.page[0].valid=1;break;
        case 34:path->arguments.page[1].valid=1;break;
        case 35:path->arguments.object[1].address=8;break;
        case 36:path->arguments.page[0].AT.par^=1;break;
        case 37:path->arguments.failed_object++;break;
        case 38:path->arguments.failed_page++;break;
        }
    }
    return ok;
}
static int argument_body(void *v,const struct paic_io *m,struct pwrcl_result *p,struct pwrph_work *w,struct pgcd_context *g)
{ns=&path->prepared_cmd.namespace;ng=g;return pwrpt_body(v,m,p,w,g);}
static int execute_arguments(unsigned fault,unsigned target)
{
    reset_bound(0);read_fault=19;argument_fault=fault;argument_target=target;argument_AT_calls=0;
    const uint32_t other[3]={0x40900,0x40904,0x50000};for(unsigned k=0;k<3;k++)put(links+0x3004+24*k,other[k],4);
    hardware[0]=1;hardware[0x14/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[0x1c/4]=1;
    hardware[0x30/4]=0x10108;hardware[0x34/4]=0x50000;hardware[0x38/4]=0x77;memcpy(initial,hardware,sizeof(initial));
    c->io.query=path_descriptor;
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original=client.reader,.query=0,.namespace_io={&client.reader.memory,0,argument_AT}},
      .device={&client.reader.memory,0,current_read_AT,current_read_load},.CPU={0},
      .access=pwra_observation_io(&client.reader.memory,&path->access_context),.enumeration=enumeration,
      .native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
    if(fault==14)path->arguments.attempted=1;
    if(fault==15)path->arguments.page[511].valid=1;
    if(fault==25)io.access.memory=0;
    if(fault==26)io.device.memory=0;
    if(fault==27)io.cmd.namespace_io.memory=0;
    if(fault==28)io.cmd.original.memory.context=&io;
    if(fault==29)io.access.context=&io;
    if(fault==30)io.cmd.namespace_io.translate=0;
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,argument_body,&io);
}
static void no_CPU_access(void)
{
    assert(!psci_calls&&!mask_calls&&!unmask_calls&&!requests&&!acks&&!modeled_stores&&!api_queries);
    assert(pwra_zero(&path->CPU,sizeof(path->CPU))&&pwrpt_checkpoint_zero_engines(path));
    assert(!DAIF&&Group1==1&&!ticket->spent);
}
static void known_close(void)
{
    assert(path->error==PWRPT_ARGUMENT_CHECKPOINT&&!path->unknown&&path->retired&&path->known_refusal&&!pwrpt_unsafe(path));
    assert(path->prepared_cmd.closed&&path->refusal.retired&&cr->retired&&cr->client_returned&&!cr->client_held);
    assert(create_calls==1&&delete_calls==1);no_CPU_access();
}
int main(int argc,char**argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;assert(execute_arguments(0,0));known_close();
    struct pwrpa_result*a=&path->arguments;assert(a->attempted&&a->complete&&a->admitted&&!a->declined&&!a->error&&!a->unknown&&!a->outstanding&&a->objects==10&&a->pages&&a->pages<=512);
    unsigned pages=a->pages;assert(pages==argument_AT_calls&&a->before.cpu.daif==0&&a->last.cpu.daif==0&&a->before.cpu.group1==1&&a->last.cpu.group1==1);
    for(unsigned k=0;k<10;k++)assert(a->object[k].complete&&a->object[k].in_self&&a->object[k].pages);
    for(unsigned k=0;k<pages;k++)assert(a->page[k].valid&&a->page[k].AT.issued==1&&a->page[k].AT.returned==1&&a->page[k].AT.saved==a->page[k].AT.restored);checks++;
    unsigned targets[20],target_count=0;
    for(unsigned k=0;k<10;k++){
        unsigned first=a->object[k].pages_first+1,last=a->object[k].pages_first+a->object[k].pages;
        targets[target_count++]=first;if(last!=first)targets[target_count++]=last;
    }
    for(unsigned fault=1;fault<=5;fault++)for(unsigned t=0;t<target_count;t++){
        unsigned n=targets[t];
        assert(!execute_arguments(fault,n));assert(pwrpt_unsafe(path)&&path->arguments.unknown&&path->arguments.outstanding==n&&cr->client_held&&!delete_calls);no_CPU_access();checks++;
    }
    for(unsigned fault=6;fault<=9;fault++)for(unsigned t=0;t<target_count;t++){
        unsigned n=targets[t];
        assert(execute_arguments(fault,n));known_close();assert(path->arguments.complete&&path->arguments.declined&&!path->arguments.admitted&&path->arguments.error==PWRPA_TRANSLATION&&path->arguments.pages==n);checks++;
    }
    for(unsigned fault=10;fault<=38;fault++){
        assert(!execute_arguments(fault,fault==36?2:1));assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls);
        if(fault<25&&fault!=12)assert(path->arguments.unknown);no_CPU_access();checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"normal_objects\":10,\"SOFTWARE_pages\":%u,\"boundary_page_targets\":%u,\"argument_raw_bytes\":%zu,\"body_raw_bytes\":%zu,\"actual_outer_composition\":true,\"no_CPU_mask_access_or_engine\":true,\"SOFTWARE_only\":true}\n",checks,pages,target_count,sizeof(*a),sizeof(*path));
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
