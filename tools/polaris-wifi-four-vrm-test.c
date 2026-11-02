/* Complete original reader-copy/private lifecycle with SOFTWARE Device,
 * CPU, CmdDb word delivery and VRM peers. Original PE images are inert DATA. */
#define EFI_XNU_WIFI_FOUR_VRM_AVAILABLE 1
#define POLARIS_CURRENT_WORD_READ_TEST_MAIN unused_arc_word_read_main
#include "polaris-wifi-current-word-read-test.c"
static uint32_t vrm_values[4][4],vrm_saved[4][4],vrm_peaks[4];
static unsigned vrm_fault,vrm_target,vrm_slot,vrm_high=1,vrm_READs,vrm_WRITEs,vrm_injected;
static int vrm_restore(void*ctx,struct pwrpc_transition*t)
{
    (void)ctx;assert(DAIF==0xc0&&!Group1&&pwv_engine_prefix(&path->VRM)&&path->VRM.engines_retired&&path->access.retired);
    unmask_calls++;t->daif_before=DAIF;t->group_before=Group1;DAIF=0;Group1=1;
    t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static void vrm_configure(void)
{
    configure(0);sf=nf=0;ntrans=flipped=injected=original_queries=locates=0;
    /* Four entries in the original validated format. The real four-stage
     * preparation below reads this source; no completed record is forged. */
    uint8_t*h=cmd_database+24;put(h,4,2);put(h+2,0x200,2);put(h+4,0x1100,2);put(h+6,4,2);
    for(unsigned k=0;k<4;k++){uint8_t*e=cmd_database+144+0x200+24*k;memcpy(e,pwv_names[k],8);put(e+16,pwvm_addresses[k],4);}
    uint8_t*oldrp=rimage,*oldcmd=cmd_image;
    relocate_image(arena+0x700000,oldrp,PWRPI_IMAGE_BYTES,pwrpi_relocs,PWRPI_RELOC_COUNT);rimage=arena+0x700000;
    relocate_image(arena+0x720000,oldcmd,PWCDI_IMAGE_BYTES,pwcdi_relocs,PWCDI_RELOC_COUNT);cmd_image=arena+0x720000;
    ((struct efi_loaded*)(arena+0x188000))->base=rimage;((struct efi_loaded*)(arena+0x188100))->base=cmd_image;
    put(own_client+8,(uintptr_t)rimage+0xaf50,8);self->bytes=r->self_owner.bytes=r->self_bytes=0x600000;
    prep=(void*)(arena+0x460000);memset(prep,0,sizeof(*prep));assert((uint8_t*)path+sizeof(*path)<(uint8_t*)prep);
    assert((uint8_t*)prep+sizeof(*prep)<arena+0x600000);
    c->io.arch=staged_arch;c->io.map=staged_map;c->io.query=no_original_GCD;c->io.identity=path_identity;
    ns=&prep->phase[0].namespace;ng=&prep->phase[0].context;fill_namespace(3);
    assert(staged_execute()&&prep->complete&&prep->parts==4&&!pwsp_unsafe(prep));
    assert(!create_calls&&!delete_calls&&!api_queries&&!psci_calls&&!modeled_stores);
    c->io.arch=path_arch;c->io.map=current_map;c->io.query=no_original_GCD;prepared_fault=body_entered=0;
}
static int vrm_load(void*ctx,uint64_t at,uint32_t*value)
{
    int ok=word_load(ctx,at,value);const struct pwv_result*v=&path->VRM;
    const struct pwrsc_transaction*t=path->access.write_bound?&v->write.io:&v->read.io;
    if(t->outstanding&&t->phase&&!(t->phase&1)&&at==pwrsc_tcs(t)+0x3c&&vrm_fault==1&&t->triggers==vrm_target)*value^=4;
    if(path->access.write_bound&&t->phase==0&&vrm_fault==2){
        static const unsigned offsets[19]={0x14,0x1c,0x10,0x18,0x30,0x34,0x38,0x3c,0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x68};
        if(at==pwrsc_tcs(t)+offsets[vrm_target-1])*value^=0x80000000;
    }
    if(path->access.write_bound&&t->phase==0&&at==PWRSC_BASE+4&&vrm_fault==12&&!vrm_injected++)path->VRM.read.io.history[10].address^=4;
    if(vrm_fault==13&&!vrm_injected&&path->VRM.read.io.triggers==1){vrm_injected=1;path->VRM.resources[1][0].address+=4;}
    if(vrm_fault==14&&!vrm_injected&&path->access.write_bound&&t->phase==1){vrm_injected=1;path->VRM.write.rail[1].saved_enable^=1;}
    if(vrm_fault==15&&!vrm_injected&&path->CPU.local_restored){
        vrm_injected=1;
        switch(vrm_target){
        case 1:path->VRM.read.response[0]^=1;break;
        case 2:path->VRM.write.io.history[0].value^=1;break;
        case 3:path->access.command_status_OR[0]^=1;break;
        case 4:path->VRM.resources[2][0].address+=4;break;
        case 5:path->access.CmdDb[0].word.last_word^=1;break;
        }
    }
    if(vrm_fault==3&&path->access.write_bound&&!t->triggers&&at==PWRSC_BASE+4)arches+=10000;
    return ok;
}
static int vrm_store(void*ctx,uint64_t at,uint32_t value)
{
    struct pwra_context*access=ctx;assert(access==&path->access_context&&access->VRM==&path->VRM&&path->access.outstanding&&path->access.local_held);
    assert(cr->client_held&&DAIF==0xc0&&!Group1&&path->CPU.local_quiescent&&pwva_writable(access,at,value));
    unsigned off=(unsigned)(at-PWRSC_BASE),within=off%PWRSC_STRIDE;assert(off&&off<sizeof(hardware));modeled_stores++;
    if(vrm_fault==4&&path->access.write_bound)return 0;
    if(off==8){assert(value==(1u<<vrm_slot));hardware[1]&=~value;acks++;return 1;}
    uint32_t previous=hardware[off/4];hardware[off/4]=value;
    if(within==0x14&&(value&PWRSC_TRIGGER)){
        assert(!(previous&PWRSC_TRIGGER)&&requests==acks);requests++;unsigned t=off-0x14;
        if(!path->access.write_bound){
            unsigned n=vrm_READs++,k=n/4,field=n%4;assert(n<16);
            assert(hardware[(t+0x30)/4]==0x108&&hardware[(t+0x34)/4]==pwvm_addresses[k]+4*field);
            assert(hardware[(t+0x38)/4]==initial[(t+0x38)/4]);
            hardware[(t+0x3c)/4]=0x10101;hardware[(t+0x40)/4]=vrm_values[k][field];
        }else{
            unsigned edge=vrm_WRITEs++,restore=edge>=4,k=restore?7-edge:edge;assert(edge<8);
            for(unsigned j=0;j<2;j++){
                unsigned field=restore?(j?0:1):(j?1:0);uint32_t address=pwvm_addresses[k]+4*field;
                uint32_t expected=restore?vrm_saved[k][field]:field?1:
                    (vrm_saved[k][0]>pwvm_min_mV[k]?vrm_saved[k][0]:pwvm_min_mV[k]);
                assert(hardware[(t+0x30+20*j)/4]==PWRSC_MESSAGE&&hardware[(t+0x34+20*j)/4]==address&&hardware[(t+0x38+20*j)/4]==expected);
                vrm_values[k][field]=expected;hardware[(t+0x3c+20*j)/4]=0x10101;hardware[(t+0x40+20*j)/4]=edge*2+j;
            }
            if(!restore)vrm_peaks[k]=vrm_values[k][0];
        }
        hardware[1]|=1u<<vrm_slot;
    }return 1;
}
static int vrm_execute(unsigned f)
{
    vrm_configure();vrm_fault=f;read_fault=0;word_calls=normal_calls=DB_calls=vrm_READs=vrm_WRITEs=vrm_injected=0;
    word_target=word_fault=word_byte=word_corrupt=normal_target=normal_fault=pre_corrupt=DB_target=DB_fault=after_fault=binding_fault=0;
    if(f==5){DB_fault=1;DB_target=vrm_target;}
    if(f==6){normal_fault=1;normal_target=vrm_target;}
    if(f==7)pre_corrupt=vrm_target;
    if(f==8)word_corrupt=vrm_target;
    if(f==9){normal_fault=5;normal_target=1;}
    if(f==10)read_fault=23;
    uint32_t values[4][4]={{0,0,5,13},{1800,1,7,14},{0,0,5,15},{3200,1,7,16}};
    memcpy(vrm_values,values,sizeof(values));if(f==11)vrm_values[2][2]=2;
    memcpy(vrm_saved,vrm_values,sizeof(vrm_saved));memset(vrm_peaks,0,sizeof(vrm_peaks));
    for(unsigned k=0;k<3;k++)put(links+0x3004+24*k,(uint32_t[]){0x40900,0x40904,0x50000}[k],4);
    hardware[0]=1u<<vrm_slot;unsigned t=vrm_slot*PWRSC_STRIDE;
    hardware[(t+0x14)/4]=vrm_high?PWRSC_AMC|PWRSC_TRIGGER:PWRSC_AMC;hardware[(t+0x1c)/4]=vrm_high;
    for(unsigned k=0;k<3;k++){hardware[(t+0x30+20*k)/4]=0x10108;hardware[(t+0x34+20*k)/4]=0x50000+4*k;hardware[(t+0x38+20*k)/4]=0x77+k;}
    memcpy(initial,hardware,sizeof(initial));c->io.query=path_descriptor;
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original=client.reader,.query=0,.namespace_io={&client.reader.memory,0,word_normal_AT}},
        .device={&client.reader.memory,0,current_read_AT,vrm_load},.CPU={0,current_read_affinity,path_mask,vrm_restore},
        .access={&client.reader.memory,&path->access_context,current_read_AT,vrm_load,vrm_store,word_DB_AT},
        .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,word_body,&io);
}
static void vrm_success(void)
{
    assert(!path->error&&!pwrpt_unsafe(path)&&path->retired&&delete_calls==1&&unmask_calls==1&&cr->retired);
    assert(pwvr_retired(&path->VRM.read)&&pwvm_retired(&path->VRM.write)&&pwv_engine_prefix(&path->VRM)&&path->VRM.engines_retired);
    assert(vrm_READs==16&&vrm_WRITEs==8&&requests==24&&acks==24&&!memcmp(vrm_values,vrm_saved,sizeof(vrm_values)));
    assert(vrm_peaks[0]==800&&vrm_peaks[1]==1800&&vrm_peaks[2]==1304&&vrm_peaks[3]==3200);
    assert(pwra_zero(&path->read,sizeof(path->read))&&pwra_zero(&path->transaction,sizeof(path->transaction)));
    assert(path->VRM.read.io.tcs==vrm_slot&&path->VRM.write.io.tcs==vrm_slot&&!memcmp(hardware,initial,0x30));
    for(unsigned k=0;k<3;k++)for(unsigned j=0;j<3;j++)assert(hardware[(vrm_slot*PWRSC_STRIDE+0x30+20*k+4*j)/4]==initial[(vrm_slot*PWRSC_STRIDE+0x30+20*k+4*j)/4]);
}
int main(int argc,char**argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t*data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;
    for(vrm_high=0;vrm_high<2;vrm_high++)for(vrm_slot=0;vrm_slot<4;vrm_slot++){
        int ok=vrm_execute(0);if(!ok)fprintf(stderr,"body%u access%u CPU%u read%u write%u\n",path->error,path->access.error,path->CPU.error,path->VRM.read.io.error,path->VRM.write.io.error);
        assert(ok);vrm_success();checks++;
    }
    vrm_slot=0;vrm_high=1;
    assert(vrm_execute(0));vrm_success();unsigned pages=path->arguments.pages;
    for(vrm_target=1;vrm_target<=16;vrm_target++){
        assert(!vrm_execute(1)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    for(vrm_target=1;vrm_target<=19;vrm_target++){
        assert(!vrm_execute(2)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!vrm_WRITEs);
        assert(modeled_stores==path->VRM.read.io.writes);checks++;
    }
    for(unsigned f=3;f<=4;f++){
        assert(!vrm_execute(f)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    for(vrm_target=1;vrm_target<=64;vrm_target++){
        assert(!vrm_execute(5)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    for(vrm_target=1;vrm_target<=pages;vrm_target++){
        assert(!vrm_execute(6)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!modeled_stores&&!mask_calls);checks++;
    }
    for(vrm_target=1;vrm_target<=11;vrm_target++){
        assert(!vrm_execute(7)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&!vrm_READs);checks++;
        assert(!vrm_execute(8)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&vrm_WRITEs==8);checks++;
    }
    assert(vrm_execute(9)&&path->error==PWRPT_WORK&&path->known_refusal&&delete_calls==1&&!mask_calls&&!modeled_stores);checks++;
    assert(vrm_execute(10)&&path->error==PWRPT_CPU&&path->known_refusal&&delete_calls==1&&!mask_calls&&!modeled_stores);checks++;
    assert(vrm_execute(11)&&path->error==PWRPT_PLAN&&path->known_refusal&&delete_calls==1&&unmask_calls==1&&vrm_READs==16&&!vrm_WRITEs&&path->VRM.known_refusal);checks++;
    for(unsigned f=12;f<=14;f++){
        assert(!vrm_execute(f)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
        if(f==12||f==14)assert(modeled_stores==path->VRM.read.io.writes);
    }
    for(vrm_target=1;vrm_target<=5;vrm_target++){
        assert(!vrm_execute(15)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&unmask_calls==1);checks++;
    }
    assert(vrm_execute(0));vrm_success();
    printf("{\"passed\":true,\"checks\":%u,\"SOFTWARE_only\":true,\"actual_outer_reader_copy\":true,\"READ_events\":%u,\"WRITE_events\":%u,\"normal_objects\":%u,\"normal_pages\":%u,\"parent_bytes\":%zu,\"full_known_Delete\":true,\"no_MSS_or_radio\":true}\n",checks,path->VRM.read.io.events,path->VRM.write.io.events,path->arguments.objects,path->arguments.pages,sizeof(*path));
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
