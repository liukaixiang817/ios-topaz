#ifndef POLARIS_CURRENT_WORD_VOTE_TEST_MAIN
#define POLARIS_CURRENT_WORD_VOTE_TEST_MAIN main
#endif /* Actual outer lifecycle; SOFTWARE peers, inert original PE DATA. */
#define EFI_XNU_WIFI_CURRENT_WORD_VOTE 1
#define POLARIS_CURRENT_WORD_READ_TEST_MAIN unused_word_read_main
#include "polaris-wifi-current-word-read-test.c"
static uint32_t vote_input[3]={6,3,0};
static unsigned vote_fault,vote_target,vote_bit,vote_status_bits=7,write_rounds,late_corrupt,vote_enabled=15;
static uint32_t vote_peak[3];
static int vote_restore(void *v,struct pwrpc_transition *t)
{
    assert(pwrr_retired(&path->read)&&path->access.retired);
    if(path->access.write_bound)assert(pwrsc_retired(&path->transaction));
    else assert(pwra_zero(&path->transaction,sizeof(path->transaction)));
    (void)v;unmask_calls++;t->daif_before=DAIF;t->group_before=Group1;
    DAIF=0;Group1=1;t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;
    t->daif_read=DAIF;t->group_read=Group1;return 1;
}
static int vote_load(void *v,uint64_t at,uint32_t *value)
{
    int ok=word_load(v,at,value);struct pwrsc_transaction *t=&path->transaction;
    if(!path->access.write_bound&&path->read.io.attempted){
        struct pwrsc_transaction *q=&path->read.io;
        if((q->phase==2||q->phase==4||q->phase==6)&&at==pwrsc_tcs(q)+0x3c)*value|=1;
    }
    if(t->attempted&&t->outstanding){
        unsigned k;for(k=0;k<3&&at!=pwrsc_tcs(t)+0x3c+20*k;k++){}
        if(k<3&&(t->phase==2||t->phase==4)&&t->completed+1==t->triggers){
            *value|=(vote_status_bits>>k)&1;
            if(vote_fault==1&&vote_target==3*(t->triggers-1)+k+1)*value^=UINT32_C(1)<<vote_bit;
        }
        if(vote_fault==2&&t->triggers==1&&at==PWRSC_BASE+4)*value=0;
        if(vote_fault==3&&t->triggers==1&&at==PWRSC_BASE+4)*value|=128;
        if(vote_fault==4&&t->triggers==1&&at==pwrsc_tcs(t)+0x18)*value=0;
        if(vote_fault==5&&t->phase==0&&at==pwrsc_tcs(t)+0x3c)arches+=8000;
    }
    if(DB_calls==64&&late_corrupt){
        unsigned which=late_corrupt;late_corrupt=0;
        if(which==1)path->transaction.status_OR[0]^=2;
        if(which==2)path->transaction.response_OR[1]^=1;
        if(which==3)path->access.command_status_OR[2]^=1;
        if(which==4)path->read.response[1]^=1;
        if(which==5)path->arguments.page[0].AT.par^=1;
    }
    return ok;
}
static int vote_store(void *v,uint64_t at,uint32_t value)
{
    if(!path->access.write_bound){
        unsigned prior=requests;int ok=current_read_store(v,at,value);
        if(requests!=prior){
            unsigned t=(unsigned)(at-PWRSC_BASE)-0x14;
            hardware[(t+0x40)/4]=vote_input[requests-1];
        }return ok;
    }
    struct pwrsc_transaction *t=&path->transaction;
    assert(v==&path->access_context&&path->access.local_held&&path->CPU.local_mask_held&&cr->client_held);
    assert(pwrsc_writable(t,at,value));unsigned off=(unsigned)(at-PWRSC_BASE);
    assert(off&&off<sizeof(hardware)&&at!=PWRSC_BASE);modeled_stores++;
    if(off==8){hardware[1]&=~value;acks++;return vote_fault!=6;}
    unsigned within=off%PWRSC_STRIDE;assert(within==0x10||within==0x14||within==0x1c||
        within==0x30||within==0x34||within==0x38||within==0x44||within==0x48||within==0x4c||
        within==0x58||within==0x5c||within==0x60);
    uint32_t previous=hardware[off/4];hardware[off/4]=value;
    if(vote_fault==7)return 0;
    if(within==0x14&&(value&PWRSC_TRIGGER)){
        assert(!(previous&PWRSC_TRIGGER)&&requests==acks&&write_rounds<2);requests++;write_rounds++;
        unsigned base=off-0x14;
        for(unsigned k=0;k<3;k++){
            unsigned resource=write_rounds==1?k:2-k;
            assert(hardware[(base+0x30+20*k)/4]==PWRSC_MESSAGE);
            assert(hardware[(base+0x34+20*k)/4]==pwcd_addresses[resource]);
            uint32_t want=write_rounds==1?(vote_input[resource]>path->desired[resource]?vote_input[resource]:path->desired[resource]):vote_input[resource];
            assert(hardware[(base+0x38+20*k)/4]==want);votes[resource]=want;
            if(write_rounds==1)vote_peak[resource]=want;
            hardware[(base+0x3c+20*k)/4]=PWRSC_DONE;hardware[(base+0x40+20*k)/4]=0x40+write_rounds+k;
        }
        hardware[1]|=1u<<(base/PWRSC_STRIDE);
    }
    return 1;
}
static int execute_vote(unsigned fault)
{
    reset_bound(0);read_fault=fault==12?23:19;word_calls=normal_calls=DB_calls=0;write_rounds=0;vote_fault=fault;
    word_target=word_fault=word_byte=word_corrupt=normal_target=normal_fault=pre_corrupt=DB_target=DB_fault=after_fault=binding_fault=0;
    if(fault==8){DB_fault=1;DB_target=vote_target;}
    if(fault==9){DB_fault=7;DB_target=vote_target;}
    if(fault==10){normal_fault=1;normal_target=vote_target;}
    if(fault==11){normal_fault=5;normal_target=1;}
    const uint32_t other[3]={0x40900,0x40904,0x50000};for(unsigned k=0;k<3;k++){
        put(links+0x3004+24*k,other[k],4);votes[k]=vote_input[k];vote_peak[k]=0;
    }
    hardware[0]=vote_enabled;hardware[0x14/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[0x1c/4]=1;
    hardware[0x30/4]=0x10108;hardware[0x34/4]=0x50000;hardware[0x38/4]=0x77;
    /* The first READ restores its inherited high latch. The writer must
     * dynamically select a different enabled, idle, untriggered TCS. */
    memcpy(initial,hardware,sizeof(initial));c->io.query=path_descriptor;
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original=client.reader,.query=0,.namespace_io={&client.reader.memory,0,word_normal_AT}},
        .device={&client.reader.memory,0,current_read_AT,current_read_load},.CPU={0,current_read_affinity,path_mask,vote_restore},
        .access={&client.reader.memory,&path->access_context,current_read_AT,vote_load,vote_store,word_DB_AT},
        .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,word_body,&io);
}
static void vote_success(void)
{
    if(path->error||pwrpt_unsafe(path)||delete_calls!=1||unmask_calls!=1)
        fprintf(stderr,"result body%u unknown%u retired%u client%u access%u read%u write%u T/C/A%u/%u/%u delete%u unmask%u values%u/%u/%u target%u/%u/%u\n",path->error,path->unknown,path->retired,cr->error,path->access.error,path->read.io.error,path->transaction.error,path->transaction.triggers,path->transaction.completed,path->transaction.acknowledged,delete_calls,unmask_calls,path->read.response[0],path->read.response[1],path->read.response[2],path->prepared_cmd.resources[1][0].index,path->prepared_cmd.resources[1][1].index,path->prepared_cmd.resources[1][2].index);
    assert(path->retired&&!path->error&&!pwrpt_unsafe(path)&&delete_calls==1&&unmask_calls==1);
    assert(pwrr_retired(&path->read)&&pwrsc_retired(&path->transaction)&&path->access.retired&&path->access.write_bound);
    assert(requests==5&&acks==5&&write_rounds==2&&word_calls==32768&&DB_calls==64);
    assert(path->read.io.tcs==0&&path->transaction.tcs!=0&&path->CPU.local_restored&&path->prepared_cmd.closed);
    assert(cr->retired&&!cr->client_held&&!DAIF&&Group1&&!ticket->spent);
    assert(!memcmp(hardware,initial,0x30));
    for(unsigned k=0;k<3;k++)assert(votes[k]==vote_input[k]&&path->saved[k]==vote_input[k]&&
        vote_peak[k]==(vote_input[k]>path->desired[k]?vote_input[k]:path->desired[k]));
    assert(path->transaction.last-path->read.io.started<=PWRSC_DEADLINE);
}
int POLARIS_CURRENT_WORD_VOTE_TEST_MAIN(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;
    for(vote_status_bits=0;vote_status_bits<8;vote_status_bits++){
        int ok=execute_vote(0);
        if(!ok)fprintf(stderr,"body%u CPU%u access%u read%u write%u phase%u T/C/A%u/%u/%u events%u\n",path->error,path->CPU.error,path->access.error,path->read.io.error,path->transaction.error,path->phase,path->transaction.triggers,path->transaction.completed,path->transaction.acknowledged,path->transaction.events);
        assert(ok);vote_success();checks++;
    }
    vote_status_bits=7;assert(execute_vote(0));vote_success();
    struct pwrsc_transaction *copy=malloc(sizeof(*copy));assert(copy);
    for(unsigned k=0;k<3;k++)for(unsigned bit=0;bit<32;bit++){
        *copy=path->transaction;copy->status_OR[k]^=UINT32_C(1)<<bit;assert(!pwrsc_retired(copy));checks++;
        *copy=path->transaction;copy->response_OR[k]^=UINT32_C(1)<<bit;assert(!pwrsc_retired(copy));checks++;
    }
    for(unsigned n=0;n<path->transaction.events;n++){
        const struct pwrsc_event *e=&path->transaction.history[n];
        if(e->phase==0||(e->phase==4&&e->operation==1)){
            *copy=path->transaction;
            copy->history[n].value^=e->address==pwrsc_tcs(copy)+0x18?1u:UINT32_C(1)<<31;
            /* Unknown unrelated TCS snapshots are still retained; only
             * selected-TCS and final/global fields are semantic here. */
            if(e->address==PWRSC_BASE||e->address==PWRSC_BASE+4||
               (e->address>=pwrsc_tcs(copy)&&e->address<pwrsc_tcs(copy)+0x68)){
                if(pwrsc_retired(copy))fprintf(stderr,"undetected mutation event%u phase%u at%llx value%x\n",n,e->phase,(unsigned long long)e->address,e->value);
                assert(!pwrsc_retired(copy));checks++;
            }
        }
    }
    free(copy);
    for(unsigned enabled=5;enabled<=9;enabled+=4){
        vote_enabled=enabled;assert(execute_vote(0));vote_success();
        assert(path->transaction.tcs==(enabled==5?2u:3u));checks++;
    }vote_enabled=15;
    const uint32_t alternatives[2][3]={{8,4,7},{0,0,0}};
    for(unsigned n=0;n<2;n++){
        memcpy(vote_input,alternatives[n],sizeof(vote_input));assert(execute_vote(0));vote_success();checks++;
    }
    vote_input[0]=15;assert(execute_vote(0)&&path->error==PWRPT_PLAN&&path->known_refusal&&path->retired&&!pwrpt_unsafe(path));
    assert(requests==3&&acks==3&&!write_rounds&&delete_calls==1&&unmask_calls==1&&pwra_zero(&path->transaction,sizeof(path->transaction)));checks++;
    memcpy(vote_input,(uint32_t[]){6,3,0},sizeof(vote_input));
    for(vote_target=1;vote_target<=6;vote_target++)for(vote_bit=1;vote_bit<32;vote_bit++){
        assert(!execute_vote(1)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
        assert(path->access.unknown||path->transaction.unknown);checks++;
    }
    vote_target=0;
    for(unsigned f=2;f<=7;f++){
        assert(!execute_vote(f)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
        if(f==5)assert(path->access.error==PWRA_TIME&&!path->CPU.error&&path->transaction.last-path->transaction.started<PWRSC_DEADLINE);
        checks++;
    }
    for(unsigned f=1;f<=5;f++){
        late_corrupt=f;int ok=execute_vote(0);
        if(ok||unmask_calls||delete_calls)fprintf(stderr,"late corruption%u ok%d CPUrestore%u Delete%u\n",f,ok,unmask_calls,delete_calls);
        assert(!ok&&pwrpt_unsafe(path)&&!delete_calls&&!unmask_calls&&cr->client_held);checks++;
    }
    for(vote_target=1;vote_target<=64;vote_target++){
        assert(!execute_vote(8)&&pwrpt_unsafe(path)&&!delete_calls&&!unmask_calls&&cr->client_held);
        assert(requests==(vote_target>32?5u:0u));checks++;
    }
    for(vote_target=1;vote_target<=33;vote_target+=32){
        assert(!execute_vote(9)&&pwrpt_unsafe(path)&&!delete_calls&&!unmask_calls&&cr->client_held);checks++;
        assert(!execute_vote(10)&&pwrpt_unsafe(path)&&!delete_calls&&!mask_calls&&!requests);checks++;
    }
    assert(execute_vote(11)&&path->error==PWRPT_WORK&&path->known_refusal&&!pwrpt_unsafe(path));
    assert(delete_calls==1&&!mask_calls&&!requests&&path->work.admitted);checks++;
    assert(execute_vote(12)&&path->error==PWRPT_CPU&&path->known_refusal&&!pwrpt_unsafe(path));
    assert(delete_calls==1&&!mask_calls&&!requests&&path->prepared_cmd.closed);checks++;
    printf("{\"passed\":true,\"checks\":%u,\"actual_outer_reader_copy\":true,\"READ3_then_WRITE2_new_IRQ_DONE_idle\":true,\"raise_max_saved_target_CX_MX_MSS_reverse_saved_restore\":true,\"dynamic_different_idle_TCS\":true,\"full_CPU_source_namespace_known_Delete\":true,\"combined_READ_WRITE50ms_original200ms_all68_reserve25\":true,\"SOFTWARE_only\":true}\n",checks);
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
