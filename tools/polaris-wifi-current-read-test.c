/* Same complete preparation/private/source/Device/CPU/READ/restore/Delete
 * path, explicit SOFTWARE peers only. Original PE bytes are DATA. */
#define EFI_XNU_WIFI_ARC_READ_AVAILABLE 1
#define EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY 1
#define POLARIS_CMDDB_PREPARED_FIXTURE_ONLY 1
#include "polaris-wifi-cmddb-prepared-test.c"
static unsigned read_fault;
static int current_read_affinity(void *context,uint64_t target,int64_t *raw)
{
    int ok=path_affinity(context,target,raw);
    if(read_fault==23&&psci_calls==1)*raw=2;
    if(read_fault==24&&psci_calls==1)*raw=-1;
    if(read_fault==25&&psci_calls==1)*raw=3;
    if(read_fault==26&&psci_calls==1){*raw=0;return 0;}
    if(read_fault>=27&&read_fault<=29&&psci_calls==7){
        *raw=0;
        if(read_fault==28)path->CPU.affinity[0]=2;
        if(read_fault==29)path->CPU.guard[0].fp.restored=0;
    }
    return ok;
}
static int current_read_map(void *ctx,struct efi_system *sys,uint8_t *out,struct paic_map_sample *m)
{
    int ok=ns_map(ctx,sys,out,m);
    if(ok&&read_fault==18){
        uint8_t copy[4096];assert(m->stride==40&&m->bytes/40*48<=sizeof(copy));
        uint64_t n=m->bytes/40;memset(copy,0xa5,sizeof(copy));
        for(uint64_t k=0;k<n;k++)memcpy(copy+48*k,out+40*k,40);
        memcpy(out,copy,sizeof(copy));m->bytes=n*48;m->stride=48;
    }
    return ok;
}
static int current_read_AT(void *context,struct pwrmd_translation *t)
{
    int ok=path_AT(context,t);
    if(read_fault==2&&path->access.events&&path->access.history[path->access.events-1].operation==2)t->write_par|=1;
    return ok;
}
static int current_read_RAM_AT(void *context,struct pgns_translation *t)
{return current_AT(context,t);}
static int current_read_restore(void *context,struct pwrpc_transition *t)
{
    (void)context;assert(DAIF==0xc0&&!Group1&&pwrr_retired(&path->read)&&path->access.retired);
    assert(pwra_zero(&path->transaction,sizeof(path->transaction)));unmask_calls++;
    t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
    t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int current_read_load(void *context,uint64_t at,uint32_t *value)
{
    int ok=path_read(context,at,value);
    if(read_fault==9&&path->read.io.acknowledged==3&&at==PWRSC_BASE)path->read.response[0]^=1;
    if(read_fault==17&&path->read.io.events&&path->read.io.events==path->read.io.outstanding&&
       path->read.io.phase==7&&at==PWRSC_BASE+4)path->access.history[path->access.events-1].engine_event=1;
    return ok;
}
static int current_read_store(void *context,uint64_t at,uint32_t value)
{
    struct pwra_context *access=context;assert(access==&path->access_context&&path->access.outstanding&&path->access.local_held);
    assert(cr->client_held&&DAIF==0xc0&&!Group1&&path->CPU.local_quiescent&&!early->record->outstanding);
    assert(pwra_engine_writable(access,at,value));unsigned off=(unsigned)(at-PWRSC_BASE);modeled_stores++;
    assert(off&&off<sizeof(hardware));
    if(off==8){hardware[1]&=~value;acks++;return read_fault!=8;}
    unsigned within=off%PWRSC_STRIDE;
    assert(within==0x10||within==0x14||within==0x1c||within==0x30||within==0x34);
    uint32_t previous=hardware[off/4];hardware[off/4]=value;if(read_fault==3)return 0;
    if(within==0x14&&(value&PWRSC_TRIGGER)){
        assert(!(previous&PWRSC_TRIGGER));
        unsigned t=off-0x14;assert(requests==acks&&requests<3);requests++;
        assert(hardware[(t+0x30)/4]==PWRR_MESSAGE&&hardware[(t+0x34)/4]==pwcd_addresses[requests-1]);
        assert(hardware[(t+0x38)/4]==initial[(t+0x38)/4]);
        hardware[(t+0x3c)/4]=read_fault==6?(1u<<8):PWRSC_DONE;
        if(read_fault==7)hardware[(t+0x3c)/4]|=0x20000;
        hardware[(t+0x40)/4]=read_fault==1?UINT32_MAX:(uint32_t[]){0,4,7}[requests-1];
        if(read_fault!=4)hardware[1]|=1u<<(t/PWRSC_STRIDE);
        if(read_fault==5)hardware[1]|=128;
        if(read_fault==10)cmd_database[PWCD_DB_BYTES-1]^=1;
        if(read_fault==11&&requests==3)links[0x4004+0x3f]^=1;
        if(read_fault==12&&requests==3)((struct efi_loaded*)(arena+0x188000))->bytes^=4096;
        if(read_fault==13)*native_on=1;
    }
    if(read_fault==20&&path->read.io.phase==7&&within==0x1c&&value==1)hardware[1]|=1;
    return 1;
}
static int current_read_body(void *context,const struct paic_io *memory,struct pwrcl_result *p,
    struct pwrph_work *w,struct pgcd_context *g)
{
    (void)context;ns=&path->prepared_cmd.namespace;ng=g;
    struct pwrpt_io io={.cmd={.original={*memory,path_locate,current_read_map},.query=0,.namespace_io={memory,0,current_AT}},
        .device={memory,0,current_read_AT,current_read_load},.CPU={0,current_read_affinity,path_mask,current_read_restore},
        .access={.memory=memory,.context=&path->access_context,.translate=current_read_AT,.read=current_read_load,
            .write=current_read_store,.RAM_translate=current_read_RAM_AT},
        .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
#ifndef PWRPT_READ_BODY
#define PWRPT_READ_BODY pwrpt_body
#endif
    return PWRPT_READ_BODY(&io,memory,p,w,g);
}
static int execute_read(unsigned fault)
{
    reset_bound(0);read_fault=fault;
    /* The actual0164 cause: no cache entries for the three ARC addresses.
     * Three other valid rows stand in for its26 non-ARC rows in SOFTWARE. */
    const uint32_t other[3]={0x40900,0x40904,0x50000};
    for(unsigned k=0;k<3;k++)put(links+0x3004+24*k,other[k],4);
    if(fault>=19){
        hardware[0]=1;hardware[0x14/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[0x1c/4]=1;
        hardware[0x30/4]=0x10108;hardware[0x34/4]=0x50000;hardware[0x38/4]=0x77;
        memcpy(initial,hardware,sizeof(initial));
    }
    if(fault==21)hardware[0x14/4]|=2;
    if(fault==22)hardware[0x1c/4]=2;
    if(fault==14)jf=4;if(fault==15)jf=7;if(fault==16)jf=13;
    c->io.query=path_descriptor;
    const struct pwrcl_io io={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
    return pwrcl_run_body(&io,enumeration,2,c,early,cr,rw,current_read_body,0);
}
 #ifndef POLARIS_CURRENT_READ_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;
    for(unsigned sample=0;sample<4;sample++){
        unsigned fault=sample>=2?16+sample:sample;
        int ok=execute_read(fault);
        if(!ok)fprintf(stderr,"READ path%u unknown%u phase%u client%u CPU%u access%u read%u events%u T/C/A%u/%u/%u RAM%u/%u/%u\n",path->error,path->unknown,path->phase,cr->error,path->CPU.error,path->access.error,path->read.io.error,path->read.io.events,path->read.io.triggers,path->read.io.completed,path->read.io.acknowledged,path->RAM[0].error,path->RAM[1].error,path->RAM[2].error);
        assert(ok&&path->retired&&path->known_refusal&&path->error==PWRPT_READ_ONLY&&!pwrpt_unsafe(path));
        assert(cr->retired&&cr->client_returned&&!cr->client_held&&create_calls==1&&delete_calls==1&&!pwrcl_result_unsafe(cr));
        assert(requests==3&&acks==3&&psci_calls==14&&mask_calls==1&&unmask_calls==1&&pwrr_retired(&path->read));
        assert(path->access.read_retired&&!path->access.write_bound&&path->access.retired&&!path->access.local_held);
        assert(pwra_zero(&path->transaction,sizeof(path->transaction))&&pwra_zero(&path->cmd,sizeof(path->cmd)));
        assert(!ticket->spent&&!DAIF&&Group1==1&&!api_queries&&path->prepared_cmd.closed);
        assert(votes[0]==8&&votes[1]==2&&votes[2]==1);
        assert(!memcmp(hardware,initial,0x30));
        for(unsigned j=0;j<3;j++)assert(path->saved[j]==0&&path->desired[j]==0); /* unpublished RAW words */
        checks++;
    }
    for(unsigned fault=2;fault<=17;fault++){
        if(fault==16)continue; /* Fully returned normal ON is a known refusal. */
        int ok=execute_read(fault);
        if(ok||!pwrpt_unsafe(path)||delete_calls||unmask_calls)fprintf(stderr,"fault%u ok%d path%u CPU%u access%u read%u delete%u unmask%u\n",fault,ok,path->error,path->CPU.error,path->access.error,path->read.io.error,delete_calls,unmask_calls);
        assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
        assert(votes[0]==8&&votes[1]==2&&votes[2]==1&&pwra_zero(&path->transaction,sizeof(path->transaction)));checks++;
    }
    assert(!execute_read(20)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
    assert(requests==3&&acks==3&&path->read.io.unknown);checks++;
    for(unsigned fault=21;fault<=22;fault++){
        assert(execute_read(fault)&&path->error==PWRPT_DEVICE&&path->known_refusal&&path->retired&&!pwrpt_unsafe(path));
        assert(delete_calls==1&&!mask_calls&&!modeled_stores&&pwra_zero(&path->read,sizeof(path->read)));checks++;
    }
    for(unsigned n=0;n<3;n++){
        unsigned fault=(unsigned[]){16,23,27}[n];
        assert(execute_read(fault)&&path->error==PWRPT_CPU&&path->known_refusal&&path->retired&&!pwrpt_unsafe(path));
        assert(path->CPU.error==PWRPC_PSCI&&path->CPU.retired&&!path->CPU.unknown&&!path->CPU.local_mask_held);
        assert(delete_calls==1&&!mask_calls&&!unmask_calls&&!modeled_stores&&pwra_zero(&path->read,sizeof(path->read)));
        assert(path->prepared_cmd.closed&&!ticket->spent);checks++;
    }
    for(unsigned n=0;n<5;n++){
        unsigned fault=(unsigned[]){24,25,26,28,29}[n];
        assert(!execute_read(fault)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!mask_calls&&!unmask_calls&&!modeled_stores);
        checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"body_bytes\":%zu,\"access_bytes\":%zu,\"read_bytes\":%zu,\"same_prepare_private_Device_CPU_READ_restore_Delete\":true,\"ARC_missing_cache_not_zero\":true,\"resource_WRITE_reachable\":false,\"READ_RAW_not_qualified_vote\":true,\"physical_executed\":false}\n",checks,sizeof(*path),sizeof(path->access),sizeof(path->read));
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}

#endif
