/* Complete real outer reader-copy and private lifecycle. Original PE bytes
 * are DATA; word/Device/CPU/IRQ leaves here are explicit SOFTWARE peers. */
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 1
#define EFI_XNU_WIFI_PRE_MASK_ARGUMENTS 1
#define EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS 1
#define EFI_XNU_WIFI_DB_WORD_CAPTURE 1
#define EFI_XNU_WIFI_CURRENT_WORD_READ 1
#define POLARIS_CURRENT_READ_FIXTURE_ONLY 1
#include "polaris-wifi-current-read-test.c"
static unsigned word_calls,word_target,word_fault,word_byte,word_corrupt;
static unsigned normal_calls,normal_target,normal_fault,pre_corrupt,DB_calls,DB_target,DB_fault,after_fault,binding_fault;
static int pwra_test_word_load(uint64_t at,uint64_t *value)
{
    assert(at>=PWCD_UEFI_DB_BASE&&at+8<=PWCD_UEFI_DB_BASE+PWCD_DB_BYTES&&!(at&7));
    unsigned slot=path->access.outstanding&1,off=(unsigned)(at-PWCD_UEFI_DB_BASE),page=off/4096;
    struct pwra_cmd_snapshot *s=&path->access.CmdDb[slot];struct pwra_word_capture *q=&s->word;
    assert(path->access.outstanding==(0x20000u|slot)&&DAIF==0xc0&&!Group1&&cr->client_held);
    assert(s->page_issued[page]==1&&s->page_returned[page]==1&&s->current_AT[page].returned==1);
    assert(q->issued==q->returned+1&&q->load_pending==1&&!q->compare_pending&&q->pending_address==at);
    assert(s->bytes==off&&q->compared_bytes==off&&q->failed_byte==UINT32_MAX);word_calls++;
    if(word_calls==word_target&&word_fault==1)return 0;
    memcpy(value,cmd_database+off,8);
    if(word_calls==word_target&&word_fault==2)((uint8_t*)value)[word_byte]^=1;
    if(slot==1&&!off&&word_corrupt){
        struct pwra_word_capture *p=&path->access.CmdDb[0].word;
        switch(word_corrupt){
        case 1:p->issued--;break;case 2:p->returned--;break;
        case 3:p->load_pending=1;break;case 4:p->compare_pending=1;break;
        case 5:p->compared_bytes--;break;case 6:p->failed_byte=0;break;
        case 7:p->last_valid=0;break;case 8:p->reserved=1;break;
        case 9:p->pending_address-=8;break;case 10:p->last_address-=8;break;
        case 11:p->last_word^=1;break;default:assert(0);
        }
    }
    return 1;
}
static int word_normal_AT(void *ctx,struct pgns_translation *t)
{
    int ok=current_AT(ctx,t);
    if(path->arguments.attempted&&!path->arguments.complete){
        assert(!DAIF&&Group1&&!psci_calls&&!mask_calls);normal_calls++;
        if(normal_calls==normal_target)switch(normal_fault){
        case 1:return 0;case 2:t->restored^=1;break;
        case 3:t->par^=UINT64_C(0x4500000000000000);break;
        case 4:path->arguments.page[511].valid=1;break;
        case 5:arches+=25000;break;case 6:arches+=50000;break;
        case 7:path->work.estimate_ticks=0;break;
        }
    }return ok;
}
static int word_DB_AT(void *ctx,struct pgns_translation *t)
{
    int ok=current_read_RAM_AT(ctx,t);DB_calls++;
    assert(DAIF==0xc0&&!Group1&&path->CPU.local_mask_held&&path->arguments.admitted==1);
    if(DB_calls==DB_target)switch(DB_fault){
    case 1:return 0;case 2:t->restored^=1;break;
    case 3:path->arguments.page[0].AT.par^=1;break;
    case 4:path->arguments.provider^=8;break;
    case 5:path->work.sample[67].after++;break;
    case 6:arches+=50000;break;
    case 7:*native_on=1;break;
    case 8:cmd_image[0x1000]^=1;break;
    case 9:core[0x1000]^=1;break;
    }
    return ok;
}
static int word_load(void *ctx,uint64_t at,uint32_t *value)
{
    int ok=current_read_load(ctx,at,value);
    if(DB_calls==32&&!path->read.io.attempted&&pre_corrupt){
        unsigned f=pre_corrupt;pre_corrupt=0;struct pwra_word_capture *p=&path->access.CmdDb[0].word;
        switch(f){
        case 1:p->issued--;break;case 2:p->returned--;break;
        case 3:p->load_pending=1;break;case 4:p->compare_pending=1;break;
        case 5:p->compared_bytes--;break;case 6:p->failed_byte=0;break;
        case 7:p->last_valid=0;break;case 8:p->reserved=1;break;
        case 9:p->pending_address-=8;break;case 10:p->last_address-=8;break;
        case 11:p->last_word^=1;break;default:assert(0);
        }
    }
    if(DB_calls==64&&after_fault){unsigned f=after_fault;after_fault=0;switch(f){
    case 1:path->arguments.native_reads--;break;
    case 2:path->work.READ_ticks--;break;
    case 3:path->access.CmdDb[0].word.last_word^=1;break;
    }}
    return ok;
}
static int word_body(void *v,const struct paic_io *m,struct pwrcl_result *p,struct pwrph_work *w,struct pgcd_context *g)
{ns=&path->prepared_cmd.namespace;ng=g;return pwrpt_body(v,m,p,w,g);}
static int execute_word_read(unsigned rf,unsigned nf,unsigned nt,unsigned df,unsigned dt,unsigned af)
{
    reset_bound(0);read_fault=rf;word_calls=normal_calls=DB_calls=0;
    normal_fault=nf;normal_target=nt;DB_fault=df;DB_target=dt;after_fault=af;
    const uint32_t other[3]={0x40900,0x40904,0x50000};
    for(unsigned k=0;k<3;k++)put(links+0x3004+24*k,other[k],4);
    if(rf>=19){
        hardware[0]=1;hardware[0x14/4]=PWRSC_AMC|PWRSC_TRIGGER;hardware[0x1c/4]=1;
        hardware[0x30/4]=0x10108;hardware[0x34/4]=0x50000;hardware[0x38/4]=0x77;
        memcpy(initial,hardware,sizeof(initial));
    }
    c->io.query=path_descriptor;
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},path_locate,current_read_map},client_create,client_drop,own_name};
    struct pwrpt_io io={.cmd={.original=client.reader,.query=0,.namespace_io={&client.reader.memory,0,word_normal_AT}},
        .device={&client.reader.memory,0,current_read_AT,current_read_load},.CPU={0,current_read_affinity,path_mask,current_read_restore},
        .access={&client.reader.memory,&path->access_context,current_read_AT,word_load,current_read_store,word_DB_AT},
        .enumeration=enumeration,.native_flag=(uintptr_t)native_on,.record=path,.preparation=prep};
    switch(binding_fault){
    case 1:io.access.memory=0;break;case 2:io.device.memory=0;break;
    case 3:io.cmd.namespace_io.memory=0;break;case 4:io.cmd.original.memory.context=&io;break;
    case 5:io.access.context=&io;break;case 6:io.access.translate=0;break;
    case 7:io.access.read=0;break;case 8:io.access.write=0;break;
    case 9:io.access.RAM_translate=0;break;case 10:path->read.io.attempted=1;break;
    }
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,word_body,&io);
}
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);
    rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *data[]={original,npa_original,rp_original,cmd_original};
    size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;
    for(unsigned rf=0;rf<=19;rf+=19){
        int ok=execute_word_read(rf,0,0,0,0,0);
        if(!ok)fprintf(stderr,"body%u CPU%u access%u read%u phase%u norm%u DB%u words%u T/C/A%u/%u/%u\n",path->error,path->CPU.error,path->access.error,path->read.io.error,path->phase,normal_calls,DB_calls,word_calls,requests,path->read.io.completed,acks);
        assert(ok&&path->error==PWRPT_READ_ONLY&&path->retired&&!pwrpt_unsafe(path));
        assert(requests==3&&acks==3&&word_calls==32768&&DB_calls==64&&pwrr_retired(&path->read));
        assert(delete_calls==1&&unmask_calls==1&&path->access.retired&&!path->access.local_held&&path->access.read_retired);
        assert(path->arguments.admitted&&path->arguments.pages==normal_calls&&path->CPU.local_restored);
        assert(path->prepared_cmd.closed&&cr->retired&&!cr->client_held&&!ticket->spent);
        assert(votes[0]==8&&votes[1]==2&&votes[2]==1&&!memcmp(hardware,initial,0x30));
        assert(pwra_zero(&path->transaction,sizeof(path->transaction))&&pwra_zero(path->saved,sizeof(path->saved)));
        for(unsigned slot=0;slot<2;slot++)assert(path->access.CmdDb[slot].word.returned==16384&&
            !memcmp(path->access.CmdDb[slot].raw,cmd_database,PWCD_DB_BYTES));checks++;
    }
    unsigned pages=normal_calls;
    for(unsigned nf=1;nf<=2;nf++)for(unsigned target=1;target<=pages;target+=pages-1){
        assert(!execute_word_read(19,nf,target,0,0,0));
        assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!mask_calls&&!requests&&!word_calls);checks++;
    }
    assert(execute_word_read(19,3,1,0,0,0)&&path->known_refusal&&path->error==PWRPT_ARGUMENT_CHECKPOINT);
    assert(delete_calls==1&&!mask_calls&&!requests&&path->arguments.declined);checks++;
    assert(execute_word_read(19,5,1,0,0,0)&&path->known_refusal&&path->error==PWRPT_WORK);
    assert(delete_calls==1&&!mask_calls&&!requests&&path->work.admitted);checks++;
    for(unsigned nf=4;nf<=7;nf++){
        if(nf==5)continue;
        assert(!execute_word_read(19,nf,1,0,0,0)&&pwrpt_unsafe(path)&&!delete_calls&&!mask_calls&&!requests);checks++;
    }
    for(unsigned df=1;df<=2;df++)for(unsigned target=1;target<=64;target++){
        assert(!execute_word_read(19,0,0,df,target,0));
        assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
        assert(requests==(target>32?3u:0u));checks++;
    }
    for(unsigned df=3;df<=9;df++)for(unsigned target=1;target<=33;target+=32){
        assert(!execute_word_read(19,0,0,df,target,0));
        /* CmdDb image tampering after its last masked source capture is
         * detected by the later normal full source close. Retain the actual
         * preceding CPU restoration; this still cannot Delete or export. */
        unsigned restored=df==8&&target==33;
        assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&unmask_calls==restored);checks++;
    }
    for(unsigned af=1;af<=3;af++){
        assert(!execute_word_read(19,0,0,0,0,af));
        assert(pwrpt_unsafe(path)&&requests==3&&acks==3&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    for(unsigned corrupt=1;corrupt<=11;corrupt++){
        pre_corrupt=corrupt;assert(!execute_word_read(19,0,0,0,0,0));
        assert(pwrpt_unsafe(path)&&!requests&&!acks&&!path->access.acquired&&!path->access.local_held);
        assert(path->access.error==PWRA_PREFIX&&cr->client_held&&!delete_calls&&!unmask_calls);checks++;
    }
    for(unsigned corrupt=1;corrupt<=11;corrupt++){
        word_corrupt=corrupt;assert(!execute_word_read(19,0,0,0,0,0));
        assert(pwrpt_unsafe(path)&&requests==3&&acks==3&&path->access.error==PWRA_PREFIX);
        assert(cr->client_held&&!delete_calls&&!unmask_calls&&word_calls==32768);checks++;
    }word_corrupt=0;
    for(unsigned slot=0;slot<2;slot++)for(unsigned end=0;end<2;end++){
        unsigned off=end?PWCD_DB_BYTES-8:0;word_target=slot*16384+off/8+1;word_fault=1;
        assert(!execute_word_read(19,0,0,0,0,0));
        struct pwra_cmd_snapshot *s=&path->access.CmdDb[slot];
        assert(pwrpt_unsafe(path)&&s->word.load_pending&&!s->word.compare_pending&&s->bytes==off);
        assert(s->word.issued==off/8+1&&s->word.returned==off/8&&s->word.pending_address==PWCD_UEFI_DB_BASE+off);
        assert(!delete_calls&&!unmask_calls&&requests==(slot?3u:0u));checks++;
        for(word_byte=0;word_byte<8;word_byte++){
            word_fault=2;assert(!execute_word_read(19,0,0,0,0,0));s=&path->access.CmdDb[slot];
            assert(s->word.failed_byte==off+word_byte&&s->word.compared_bytes==off+word_byte&&s->bytes==off+word_byte+1);
            assert(s->word.compare_pending&&!s->word.load_pending&&pwrpt_unsafe(path)&&!delete_calls&&!unmask_calls);checks++;
        }
    }
    word_fault=0;word_target=0;
    for(unsigned rf=2;rf<=17;rf++){
        if(rf==14||rf==15||rf==16)continue; /* Those injected work/CPU cases are tested in their own scopes. */
        int ok=execute_word_read(rf,0,0,0,0,0);
        if(ok)fprintf(stderr,"unexpected READ fault %u succeeded\n",rf);
        assert(!ok&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
        assert(pwra_zero(&path->transaction,sizeof(path->transaction))&&votes[0]==8&&votes[1]==2&&votes[2]==1);checks++;
    }
    for(unsigned rf=20;rf<=20;rf++){
        assert(!execute_word_read(rf,0,0,0,0,0)&&pwrpt_unsafe(path)&&requests==3&&acks==3);
        assert(!delete_calls&&!unmask_calls&&path->read.io.unknown);checks++;
    }
    for(binding_fault=1;binding_fault<=10;binding_fault++){
        assert(!execute_word_read(19,0,0,0,0,0)&&pwrpt_unsafe(path)&&cr->client_held);
        assert(!delete_calls&&!psci_calls&&!mask_calls&&!requests&&!word_calls&&!normal_calls);checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"normal_pages\":%u,\"actual_outer_reader_copy\":true,\"full_3_READ_new_IRQ_complete_restore_Delete\":true,\"full_masked_DB_bytes\":262144,\"masked_DB_AT\":64,\"resource_WRITE_reachable\":false,\"original200ms_all68_READ50_reserve25\":true,\"SOFTWARE_only\":true}\n",checks,pages);
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
