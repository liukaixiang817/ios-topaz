/* Real native mailbox callbacks and handoff body over host memory.
 * Radio READY and privileged CPU/cache/translation leaves remain software. */
#define PWKR_TEST_ENTRY unused_handoff_main
#include "polaris-wifi-runtime-handoff-test.c"
#define EFI_XNU_WIFI_MAILBOX_NATIVE_AVAILABLE 1
#include "uefi-wifi-mailbox-native.h"
static uint8_t*shared_page;
static int kernel_live(void*ctx){return ctx==shared_page;}
static int kernel_copy(void*ctx,unsigned off,void*p,unsigned n,unsigned write)
{CHECK(ctx==shared_page&&off<PWMB_BYTES&&n<=PWMB_BYTES-off);if(write)memcpy(shared_page+off,p,n);else memcpy(p,shared_page+off,n);return 1;}
static int kernel_cache(void*ctx,unsigned off,unsigned n,unsigned clean)
{CHECK(ctx==shared_page&&off<PWMB_BYTES&&n<=PWMB_BYTES-off&&clean<=1);return 1;}
static int kernel_sequence(void*ctx,unsigned off,uint64_t*n,unsigned write)
{CHECK(ctx==shared_page&&!(off&7)&&off<=PWMB_BYTES-8);if(write)memcpy(shared_page+off,n,8);else memcpy(n,shared_page+off,8);return 1;}
int main(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,0x200000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    boot_payload=mmap(0,PMMN_TEST_PAYLOAD_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(boot_payload!=MAP_FAILED);test_payload_base=(uintptr_t)boot_payload;
    kernel_shadow=mmap(0,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(kernel_shadow!=MAP_FAILED);
    handoff_setup();CHECK(launch());boot_ap->stage=1;boot_ap->mpidr=0x700;CHECK(pwkr_poll(parent)==2);
    shared_page=kernel_shadow+0x4000;
    struct pwmn_state*native=(void*)(arena+0x194000);CHECK(sizeof(*native)<0x10000);memset(native,0,sizeof(*native));
    int begun=pwmn_begin(native,parent);if(!begun)fprintf(stderr,"mailbox begin=%d attempted=%u err=%u owner=%u/%u image=%llx+%llx state=%llx bytes=%zu\n",begun,native->attempted,native->error,owner->unknown,owner->error,(unsigned long long)(uintptr_t)early->image.base,(unsigned long long)early->image.bytes,(unsigned long long)(uintptr_t)native,sizeof(*native));CHECK(begun&&pwmn_current(native));CHECK(!pwmn_begin(native,parent));
    struct pwmn_state*second=(void*)(arena+0x1a4000);memset(second,0,sizeof(*second));CHECK(!pwmn_begin(second,parent));
    struct pwmb_bus bus={shared_page,kernel_live,kernel_copy,kernel_cache,kernel_sequence};
    struct pwmb_link peer[PWMB_LANES]={0};
    for(unsigned k=0;k<PWMB_LANES;k++)CHECK(pwmb_link_open(&peer[k],k,pwmn_producer(k)?PWMB_CONSUMER:PWMB_PRODUCER,owner->opening));
    uint8_t ready[16]={1},data[64]={0};struct pwmb_message message;uint64_t number=1;
    CHECK(pwmn_send(native,PWMB_EVENT,PWMB_NOTIFY,ready,16)==1);
    CHECK(pwmn_send(native,PWMB_EVENT,PWMB_NOTIFY,ready,16)==0);
    CHECK(pwmb_receive_poll(&peer[PWMB_EVENT],&bus,&message)==1&&message.operation==PWMB_NOTIFY&&message.sequence==1);
    CHECK(pwmb_receive_complete(&peer[PWMB_EVENT],&bus)==1);
    CHECK(pwmn_send(native,PWMB_EVENT,PWMB_NOTIFY,ready,16)==1&&native->lane[PWMB_EVENT].state.next==2);
    CHECK(pwmn_receive(native,PWMB_CONTROL,&message)==0);
    CHECK(pwmb_send(&peer[PWMB_CONTROL],&bus,PWMB_STATE,0,0)==1);
    CHECK(pwmn_receive(native,PWMB_CONTROL,&message)==1&&message.operation==PWMB_STATE);
    CHECK(pwmn_receive(native,PWMB_CONTROL,&message)==0);
    CHECK(pwmn_complete(native,PWMB_CONTROL)==1&&pwmb_send_ack_poll(&peer[PWMB_CONTROL],&bus)==1);
    uint8_t join[112]={2,0,0,0,3,8,1};memcpy(join+16,"lab",3);memcpy(join+48,"12345678",8);
    CHECK(pwmb_send(&peer[PWMB_CONTROL],&bus,PWMB_JOIN,join,112)==1);
    CHECK(pwmn_receive(native,PWMB_CONTROL,&message)==1&&!memcmp(message.data,join,112));
    CHECK(pwmn_complete(native,PWMB_CONTROL)==1&&pwmb_send_ack_poll(&peer[PWMB_CONTROL],&bus)==1);
    CHECK(pwmb_zero(native->lane[PWMB_CONTROL].wire,PWMB_RECORD)&&pwmb_zero(shared_page+PWMB_LINE,PWMB_DATA));
    pwmb_clear(&message,sizeof(message));pwmb_clear(join,sizeof(join));
    for(unsigned lane=0;lane<PWMB_LANES;lane++){
        unsigned base=lane*PWMB_SLOT;unsigned producer=pwmn_producer(lane);
        CHECK(!pwmn_copy(native,base+(producer?PWMB_ACK_OFFSET:0),data,16,1));
        CHECK(!pwmn_cache(native,base+(producer?PWMB_ACK_OFFSET:0),PWMB_LINE,1));
        CHECK(!pwmn_sequence(native,base+(producer?PWMB_ACK_OFFSET:0)+24,&number,1));
        CHECK(!pwmn_copy(native,base+(producer?0:PWMB_ACK_OFFSET)+24,&number,8,1));
    }
    CHECK(!pwmn_copy(native,PWMB_BOOTSTRAP_OFFSET,data,16,1));
    CHECK(!pwmn_cache(native,PWMB_BOOTSTRAP_OFFSET,PWMB_LINE,1));
    CHECK(!pwmn_sequence(native,PWMB_BOOTSTRAP_OFFSET+24,&number,1));
    shared_page[PWMB_BOOTSTRAP_OFFSET]^=1;
    CHECK(!pwmn_current(native)&&owner->unknown&&owner->held);
    CHECK(pwmn_send(native,PWMB_EVENT,PWMB_NOTIFY,ready,16)==-1&&native->unknown);
    CHECK(!munmap(boot_payload,PMMN_TEST_PAYLOAD_BYTES)&&!munmap(kernel_shadow,0x10000));
    if(descriptor_protected)CHECK(!mprotect(&share->page,host_page,PROT_READ|PROT_WRITE));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u native mailbox checks; actual host page, software CPU/radio/cache\n",checks);return 0;
}
