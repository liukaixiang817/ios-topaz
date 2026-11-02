/* Real outer reader-copy/retirement path; original PE images are DATA and
 * the Normal RAM word leaf is a SOFTWARE peer. No device execution. */
#define EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS 1
#define EFI_XNU_WIFI_DB_WORD_CAPTURE 1
#define POLARIS_NORMAL_MASKED_TEST_MAIN legacy_normal_masked_main
#include "polaris-wifi-normal-masked-database-test.c"
static unsigned word_calls,word_target,word_fault,word_byte,word_corrupt;
static int pwra_test_word_load(uint64_t at,uint64_t *value)
{
    assert(at>=PWCD_UEFI_DB_BASE&&at+8<=PWCD_UEFI_DB_BASE+PWCD_DB_BYTES&&!(at&7));
    unsigned slot=path->access.outstanding&1,off=(unsigned)(at-PWCD_UEFI_DB_BASE),page=off/4096;
    struct pwra_cmd_snapshot *s=&path->access.CmdDb[slot];struct pwra_word_capture *q=&s->word;
    assert(path->access.outstanding==(0x20000u|slot)&&DAIF==0xc0&&!Group1&&cr->client_held);
    assert(s->page_issued[page]==1&&s->page_returned[page]==1&&s->current_AT[page].returned==1);
    assert(s->current_AT[page].par==(UINT64_C(0xff00000000000b80)|(at&~UINT64_C(4095))));
    assert(q->issued==q->returned+1&&q->load_pending==1&&!q->compare_pending&&q->pending_address==at);
    assert(s->bytes==off&&q->compared_bytes==off&&q->failed_byte==UINT32_MAX);
    word_calls++;
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
static int word_execute(unsigned f,unsigned target,unsigned b,unsigned corrupt)
{
    word_calls=0;word_fault=f;word_target=target;word_byte=b;word_corrupt=corrupt;
    return execute_normal_masked(0,0,0,0,0);
}
int main(int argc,char **argv)
{
    assert(legacy_normal_masked_main(argc,argv)==0);
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);
    rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *data[]={original,npa_original,rp_original,cmd_original};
    size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(data[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=260;
    assert(word_execute(0,0,0,0));no_engine();assert(word_calls==32768&&DB_calls==64);checks++;
    assert(path->retired&&path->known_refusal&&!pwrpt_unsafe(path)&&create_calls==1&&delete_calls==1);
    for(unsigned slot=0;slot<2;slot++){
        struct pwra_cmd_snapshot *s=&path->access.CmdDb[slot];
        assert(s->bytes==PWCD_DB_BYTES&&s->word.issued==16384&&s->word.returned==16384);
        assert(!memcmp(s->raw,cmd_database,PWCD_DB_BYTES));
    }
    /* Every page's first/last word, each snapshot: an undelivered leaf
     * retains the previous delivered word, byte prefix and pending address. */
    for(unsigned slot=0;slot<2;slot++)for(unsigned page=0;page<32;page++)for(unsigned end=0;end<2;end++){
        unsigned off=4096*page+(end?4088:0),target=slot*16384+off/8+1;
        assert(!word_execute(1,target,0,0));no_engine();struct pwra_cmd_snapshot *s=&path->access.CmdDb[slot];
        assert(word_calls==target&&pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls);
        assert(path->access.error==PWRA_IO&&s->word.issued==off/8+1&&s->word.returned==off/8);
        assert(s->word.load_pending==1&&!s->word.compare_pending&&s->bytes==off&&s->word.compared_bytes==off);
        assert(s->word.pending_address==PWCD_UEFI_DB_BASE+off&&s->word.failed_byte==UINT32_MAX);
        assert(s->word.last_valid==(off!=0));
        if(off)assert(s->word.last_address==PWCD_UEFI_DB_BASE+off-8&&!memcmp(&s->word.last_word,cmd_database+off-8,8));
        assert(!memcmp(s->raw,cmd_database,off)&&pwra_zero(s->raw+off,PWCD_DB_BYTES-off));checks++;
    }
    /* All eight mismatch positions in first/last words of first/last pages;
     * preserve the whole delivered word and only the actually copied prefix. */
    for(unsigned slot=0;slot<2;slot++)for(unsigned page=0;page<32;page+=31)for(unsigned end=0;end<2;end++)for(unsigned b=0;b<8;b++){
        unsigned off=4096*page+(end?4088:0),target=slot*16384+off/8+1;
        assert(!word_execute(2,target,b,0));no_engine();struct pwra_cmd_snapshot *s=&path->access.CmdDb[slot];
        assert(pwrpt_unsafe(path)&&cr->client_held&&!delete_calls&&!unmask_calls&&word_calls==target);
        assert(path->access.error==PWRA_CHANGED&&s->word.returned==off/8+1&&!s->word.load_pending&&s->word.compare_pending==1);
        assert(s->bytes==off+b+1&&s->word.compared_bytes==off+b&&s->word.failed_byte==off+b);
        assert(s->word.last_valid==1&&s->word.last_address==PWCD_UEFI_DB_BASE+off);
        uint64_t expected;memcpy(&expected,cmd_database+off,8);((uint8_t*)&expected)[b]^=1;
        assert(s->word.last_word==expected&&!memcmp(s->raw,cmd_database,off+b));
        assert(s->raw[off+b]==(uint8_t)(cmd_database[off+b]^1)&&pwra_zero(s->raw+off+b+1,PWCD_DB_BYTES-off-b-1));checks++;
    }
    for(unsigned k=1;k<=11;k++){
        assert(!word_execute(0,0,0,k));no_engine();assert(pwrpt_unsafe(path)&&path->access.error==PWRA_PREFIX);
        assert(cr->client_held&&!delete_calls&&!unmask_calls&&word_calls==32768);checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"actual_outer_reader_copy\":true,\"source_word_loads\":32768,\"full_fresh_DB_bytes\":262144,\"masked_AT\":64,\"undelivered_page_boundary_cases\":128,\"first_bad_byte_cases\":64,\"retirement_prefix_corruption_cases\":11,\"word_record_bytes\":%zu,\"body_bytes\":%zu,\"SOFTWARE_only\":true,\"physical_speedup_UNOBSERVED\":true}\n",checks,sizeof(struct pwra_word_capture),sizeof(*path));
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
