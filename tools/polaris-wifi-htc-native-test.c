/* Full native MSS/CE transport plus real HTC worker. Only privileged leaves,
 * CPU/device cache views and target responses are SOFTWARE. */
#include <stdint.h>
static void htc_tx(unsigned,unsigned,const unsigned char*),htc_post(unsigned),htc_copy_done(uint64_t,void*,unsigned,unsigned);
#define EFI_XNU_WIFI_HTC_NATIVE_AVAILABLE 1
#define PMCT_TEST_TX_HOOK htc_tx
#define PMCT_TEST_POST_HOOK htc_post
#define PMCT_TEST_COPY_DONE_HOOK htc_copy_done
#define PMCT_TEST_ENTRY unused_transport_suite
#include "polaris-wifi-ce-transport-test.c"
#include "uefi-wifi-htc-native.h"
static struct pmhc_state*htc;
static unsigned htc_fault,htc_scenarios,htc_ready_posted,htc_requests,htc_wmi_messages,rx_cursor[12];
static void target_frame(unsigned pipe,const uint8_t*frame,unsigned bytes)
{
    const struct pwdm_pipe*p=&transport->rings.layout.pipe[pipe];unsigned slot=rx_cursor[pipe];
    CHECK(slot<p->destinations&&owned[pipe][slot]==1&&bytes<=p->buffer_bytes);
    uint8_t*desc=device_at(CE_ALLOCATION+p->destination+16*slot,16);
    memcpy(device_at(pwcr_get(desc,8),bytes),frame,bytes);put(desc+8,bytes,2);owned[pipe][slot]=2;
    rx_cursor[pipe]=(slot+1)&(p->destinations-1);
}
static void control_frame(const uint8_t*body,unsigned bytes)
{uint8_t frame[64]={0};CHECK(bytes+8<=sizeof(frame));phtc_put(frame+2,bytes);memcpy(frame+8,body,bytes);target_frame(2,frame,bytes+8);}
static void htc_post(unsigned pipe)
{
    if(!htc||pipe!=2||htc_ready_posted)return;htc_ready_posted=1;
    if(htc_fault==1)return;
    uint8_t ready_message[]={1,0,32,0,0,1,9,0,1,32,0x80,0};if(htc_fault==4)ready_message[5]=0;
    control_frame(ready_message,sizeof(ready_message));
}
static void htc_copy_done(uint64_t at,void*private,unsigned bytes,unsigned write)
{
    (void)at;(void)bytes;if(!htc||write||private!=transport->receive)return;
    const struct pwcr_transfer*t=&transport->rings.pending;CHECK(t->receive==2&&owned[t->pipe][t->index]==2);owned[t->pipe][t->index]=0;
}
static void htc_tx(unsigned pipe,unsigned slot,const uint8_t*desc)
{
    (void)slot;CHECK(htc&&pmhc_live(htc));unsigned bytes=(unsigned)pwcr_get(desc+8,2);
    const uint8_t*frame=device_at(pwcr_get(desc,8),bytes);CHECK(bytes>=8&&phtc_u16(frame+2)+8==bytes);
    unsigned eid=frame[0];CHECK(pwcr_get(desc+10,2)==(uint64_t)(eid<<4));
    if(eid){
#ifdef PMHC_TEST_WMI_HOOK
        PMHC_TEST_WMI_HOOK(pipe,frame,bytes);return;
#endif
        CHECK(htc->client.phase==8&&eid==htc->client.wmi&&pipe==3&&bytes==40&&frame[1]==1);htc_wmi_messages++;
        for(unsigned n=0;n<32;n++)CHECK(frame[8+n]==(uint8_t)(0xa0+n));
        uint8_t reply[]={2,2,12,0,8,0,0,0,0x56,0x34,0x12,0,1,4,0,0,2,1,0,0};target_frame(2,reply,sizeof(reply));return;
    }
    CHECK(pipe==0&&!frame[1]);htc_requests++;unsigned message=phtc_u16(frame+8);
    if(htc_requests==3){CHECK(message==5&&bytes==20);for(unsigned n=10;n<20;n++)CHECK(!frame[n]);return;}
    unsigned service=htc_requests==1?0x300:htc_requests==2?0x100:0x600;
    CHECK(htc_requests<=4&&message==2&&bytes==16&&phtc_u16(frame+10)==service&&phtc_u16(frame+12)==(service==0x100?0x100:8));
    uint8_t response[8]={3,0,0,0,0,0,0,0};phtc_put(response+2,service);response[5]=(uint8_t)(htc_requests==4?3:htc_requests);phtc_put(response+6,service==0x300?256:2048);
    if(htc_fault==2&&service==0x100)response[4]=1;control_frame(response,sizeof(response));
}
static void htc_setup(unsigned kind)
{
    htc=0;transport_setup(0);htc=(void*)(arena+0x7320000);
    CHECK(sizeof(*transport)<0x20000&&sizeof(*htc)<0x10000);memset(htc,0,sizeof(*htc));memset(rx_cursor,0,sizeof(rx_cursor));
    htc_fault=kind;htc_ready_posted=htc_requests=htc_wmi_messages=0;htc_scenarios++;
    CHECK(pmhc_begin(htc,transport));
    for(unsigned n=0;n<13&&!htc->opened;n++)CHECK(pmhc_step(htc)==1);
    CHECK(htc->opened&&htc_ready_posted&&transport->posts==28);
    if(kind==3)transport_fault=1;
}
#ifndef PMHC_TEST_ENTRY
#define PMHC_TEST_ENTRY main
#endif
int PMHC_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);ce_shadow=aligned_alloc(4096,PWDM_BYTES);device_memory=aligned_alloc(4096,PWDM_BYTES);
    CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory&&ce_shadow&&device_memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned kind=0;kind<=5;kind++){
        htc_setup(kind);int done=1;
        if(kind==1)advance_to(htc->client.deadline+1);
        for(unsigned n=0;n<40&&done==1;n++){done=pmhc_step(htc);if(done==1)advance_to(owner->last+19200);}
        if(!kind||kind==5){
            if(done!=3)fprintf(stderr,"HTC result=%d error=%u client=%u phase=%u requests=%u transport=%u frame=%u\n",done,htc->error,htc->client.error,htc->client.phase,htc_requests,transport->error,htc->frame_kind);
            CHECK(done==3&&pmhc_live(htc)&&htc_requests==4&&htc->client.htt==1&&htc->client.wmi==2&&htc->client.pktlog==3);
            if(!kind){
                uint8_t body[32];for(unsigned n=0;n<32;n++)body[n]=(uint8_t)(0xa0+n);
                CHECK(pmhc_send(htc,2,body,sizeof(body))==1&&htc_wmi_messages==1&&!htc->client.endpoint[2].credits);
                int received=1;for(unsigned n=0;n<20&&received!=2;n++){advance_to(owner->last+19200);received=pmhc_step(htc);CHECK(received>0);}
                CHECK(received==2&&htc->frame_kind==1&&htc->client.rx_eid==2&&htc->client.rx_bytes==4&&htc->client.endpoint[2].credits==1);
                CHECK(pwcr_get(htc->client.rx,4)==0x123456&&pmhc_ack(htc)&&!htc->frame_kind);
                fprintf(stderr,"native HTC: actual CE READY, HTT/WMI/setup/pktlog, WMI shadow TX and returned credits/payload PASS\n");
            }else{
                uint8_t raw[13];for(unsigned n=0;n<sizeof(raw);n++)raw[n]=(uint8_t)(0xf0+n);target_frame(5,raw,sizeof(raw));
                int received=1;for(unsigned n=0;n<20&&received!=2;n++){advance_to(owner->last+19200);received=pmhc_step(htc);CHECK(received>0);}
                CHECK(received==2&&htc->frame_kind==2&&htc->raw_pipe==5&&htc->raw_bytes==sizeof(raw)&&transport->frame_ready&&!memcmp(transport->receive,raw,sizeof(raw)));
                CHECK(pmhc_ack(htc)&&!transport->frame_ready);
            }
        }else{
            CHECK(done==-1&&htc->unknown&&htc->error&&owner->held);
            if(kind==1||kind==3||kind==4)CHECK(!htc_requests);
            if(kind==2)CHECK(htc_requests==2&&!htc->client.wmi);
            unsigned writes=transport_writes;CHECK(pmhc_step(htc)==-1&&writes==transport_writes);
        }
    }
    wlan_unprotect();free(msa_shadow);free(device_memory);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native HTC checks, %u scenarios; SOFTWARE target/cache/MMIO/UEFI, no actual Wi-Fi scan\n",checks+nv_checks,htc_scenarios);return 0;
}
