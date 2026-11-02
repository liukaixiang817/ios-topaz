/* Fresh real outer lifecycle with the actual own IRQ-enable1/high-latch
 * shape, explicit SOFTWARE MMIO/CPU/AT peers and inert original PE DATA. */
#ifndef EFI_XNU_WIFI_CURRENT_WORD_VOTE_LATCHED
#define EFI_XNU_WIFI_CURRENT_WORD_VOTE_LATCHED 1
#endif
#define POLARIS_CURRENT_WORD_VOTE_TEST_MAIN unused_unlatched_vote_main
#include "polaris-wifi-current-word-vote-test.c"
static unsigned snapshot_fault,latched_high_tcs;
static int latched_load(void *v,uint64_t at,uint32_t *value)
{
    int ok=vote_load(v,at,value);struct pwrsc_transaction *t=&path->transaction;
    if(path->access.write_bound&&t->attempted&&t->phase==0&&t->outstanding){
        if(vote_fault==5&&at==pwrsc_tcs(t)+0x3c)arches+=200;
        static const unsigned offsets[19]={0x14,0x1c,0x10,0x18,0x30,0x34,0x38,0x3c,0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x68};
        if(snapshot_fault&&snapshot_fault<=19&&at==pwrsc_tcs(t)+offsets[snapshot_fault-1])*value^=UINT32_C(1)<<31;
    }
    return ok;
}
static int execute_latched(unsigned fault)
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
    unsigned base=PWRSC_STRIDE*latched_high_tcs;
    hardware[0]=vote_enabled;hardware[(base+0x14)/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[(base+0x1c)/4]=1;
    hardware[(base+0x30)/4]=0x10108;hardware[(base+0x34)/4]=0x50000;hardware[(base+0x38)/4]=0x77;
    memcpy(initial,hardware,sizeof(initial));c->io.query=path_descriptor;
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original=client.reader,.query=0,.namespace_io={&client.reader.memory,0,word_normal_AT}},
        .device={&client.reader.memory,0,current_read_AT,current_read_load},.CPU={0,current_read_affinity,path_mask,vote_restore},
        .access={&client.reader.memory,&path->access_context,current_read_AT,latched_load,vote_store,word_DB_AT},
        .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,word_body,&io);
}
#define execute_vote execute_latched
static void latched_success(void)
{
    assert(path->retired&&!path->error&&!pwrpt_unsafe(path)&&delete_calls==1&&unmask_calls==1);
    assert(pwrr_retired(&path->read)&&pwrsc_retired(&path->transaction)&&path->access.retired&&path->access.write_bound);
    assert(path->transaction.tcs==path->read.io.tcs&&path->transaction.IRQ_enable==vote_enabled);
    assert(path->transaction.observed.control==path->transaction.saved.control&&path->transaction.observed.enable==path->transaction.saved.enable);
    if(path->transaction.saved.control&PWRSC_TRIGGER)assert(path->transaction.saved.control==(PWRSC_AMC|PWRSC_TRIGGER)&&path->transaction.saved.enable==1);
    assert(requests==5&&acks==5&&write_rounds==2&&!memcmp(hardware,initial,0x30));
    for(unsigned k=0;k<3;k++)assert(votes[k]==vote_input[k]);
    unsigned high=0,low=0;for(unsigned n=0;n<path->transaction.events;n++){
        const struct pwrsc_event *e=&path->transaction.history[n];
        if(e->operation==2&&e->address==pwrsc_tcs(&path->transaction)+0x14){
            if(e->value&PWRSC_TRIGGER){assert(e->phase==1||e->phase==3);high++;}else low++;
        }
    }assert(high==2&&low>=2);
}
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *data[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;vote_enabled=1;vote_status_bits=7;
#if !EFI_XNU_WIFI_CURRENT_WORD_VOTE_LATCHED
    assert(!execute_vote(0)&&path->transaction.error==PWRSC_BUSY&&path->transaction.phase==0);
    assert(!path->transaction.triggers&&!path->transaction.writes&&path->read.io.phase==8);
    assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
    printf("{\"passed\":true,\"checks\":1,\"old_writer_busy_regression_IRQenable1_same_READ_high_latch\":true,\"SOFTWARE_only\":true}\n");
#else
    for(vote_status_bits=0;vote_status_bits<8;vote_status_bits++){
        int ok=execute_vote(0);if(!ok)fprintf(stderr,"body%u access%u write%u\n",path->error,path->access.error,path->transaction.error);
        assert(ok);latched_success();checks++;
    }
    vote_status_bits=7;
    vote_enabled=4;assert(execute_vote(0));latched_success();assert(path->transaction.tcs==2);checks++;
    for(latched_high_tcs=2;latched_high_tcs<=3;latched_high_tcs++){
        vote_enabled=1u<<latched_high_tcs;assert(execute_vote(0));latched_success();assert(path->transaction.tcs==latched_high_tcs);checks++;
    }
    latched_high_tcs=0;
    vote_enabled=1;assert(execute_vote(0));latched_success();
    struct pwrsc_transaction *copy=malloc(sizeof(*copy));assert(copy);
    for(unsigned k=0;k<3;k++)for(unsigned bit=0;bit<32;bit++){
        *copy=path->transaction;copy->status_OR[k]^=UINT32_C(1)<<bit;assert(!pwrsc_retired(copy));checks++;
        *copy=path->transaction;copy->response_OR[k]^=UINT32_C(1)<<bit;assert(!pwrsc_retired(copy));checks++;
    }
    for(unsigned n=0;n<path->transaction.events;n++){
        const struct pwrsc_event *e=&path->transaction.history[n];uint64_t t=pwrsc_tcs(&path->transaction);
        *copy=path->transaction;
        if(e->operation==2&&e->address==t+0x14&&!(e->value&PWRSC_TRIGGER)){
            copy->history[n].value|=PWRSC_TRIGGER;assert(!pwrsc_retired(copy));checks++;
        }
        if(e->operation==1&&(e->phase==0||e->phase==2||e->phase==4)&&
           (e->address==PWRSC_BASE||e->address==PWRSC_BASE+4||(e->address>=t&&e->address<t+0x68))){
            *copy=path->transaction;copy->history[n].value^=e->address==t+0x18?1u:UINT32_C(1)<<31;
            assert(!pwrsc_retired(copy));checks++;
        }
    }
    free(copy);
    for(vote_target=1;vote_target<=6;vote_target++)for(vote_bit=1;vote_bit<32;vote_bit++){
        assert(!execute_vote(1)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    vote_target=0;
    for(unsigned f=2;f<=7;f++){
        int ok=execute_vote(f);
        if(ok)fprintf(stderr,"fault%u success combined%llu writer%llu READ%llu\n",f,(unsigned long long)(path->transaction.last-path->read.io.started),(unsigned long long)(path->transaction.last-path->transaction.started),(unsigned long long)(path->read.io.last-path->read.io.started));
        assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
        if(f==5)assert(path->access.error==PWRA_TIME&&!path->CPU.error&&
            path->CPU.after.cpu.ticks-path->read.io.started>PWRSC_DEADLINE&&
            path->CPU.after.cpu.ticks-path->transaction.started<PWRSC_DEADLINE);
    }
    for(unsigned f=1;f<=5;f++){
        late_corrupt=f;assert(!execute_vote(0)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    for(vote_target=1;vote_target<=64;vote_target++){
        assert(!execute_vote(8)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    for(snapshot_fault=1;snapshot_fault<=19;snapshot_fault++){
        assert(!execute_vote(0)&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
        assert(!path->transaction.triggers&&modeled_stores==path->read.io.writes);checks++;
    }
    snapshot_fault=0;
    printf("{\"passed\":true,\"checks\":%u,\"actual_outer_reader_copy\":true,\"same_fresh_READ_high_latch_IRQenable1\":true,\"dynamic_TCS_no_IRQenable_type_write\":true,\"WRITE_new_edges_exactly2_no_restore_high_write\":true,\"full_CPU_source_namespace_Delete\":true,\"SOFTWARE_only\":true}\n",checks);
#endif
    (void)checks;
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
