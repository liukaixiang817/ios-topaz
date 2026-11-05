/* Real startup -> copied payload -> handoff -> mailbox/radio worker.
 * CPU/hardware/firmware/kernel peers remain SOFTWARE. CPU0 mailbox cache
 * publication moves bytes to/from a separate kernel/device view. */
#include <stdint.h>
static void runtime_prepare(void),runtime_drive(void);
static int runtime_regulatory(unsigned,const unsigned char*,unsigned);
#define PMST_TEST_OTHER_WMI runtime_regulatory
#define EFI_XNU_MSS_FIRMWARE_OFFSET 0x10000
#define PMMN_TEST_PAYLOAD_BYTES (64061440+EFI_XNU_MSS_FIRMWARE_OFFSET)
#define EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE 1
#define POLARIS_WIFI_RUNTIME_SOFTWARE_PEER 1
#define EFI_XNU_WIFI_MAILBOX_NATIVE_AVAILABLE 1
#define EFI_XNU_WIFI_WORKER_NATIVE_AVAILABLE 1
#define PWNS_TEST_BEFORE_PREPARE runtime_prepare
#define PWNS_TEST_AFTER_READY runtime_drive
#include "polaris-wifi-parent-composed-test.c"
#include "uefi-wifi-worker-native.h"
static uint8_t *kernel_memory,*mailbox_memory;
static uint8_t kernel_page[PWMB_BYTES];
static struct polaris_payload *runtime_payload;
static struct pwks_image *runtime_copy;
static struct polaris_efi_ap *runtime_ap,peer_ap;
static struct polaris_plan runtime_plan;
static struct pwwn_state *worker;
static struct pwmb_link kernel_lanes[PWMB_LANES];
static unsigned runtime_caches,runtime_cpu_calls,scan_events,ready_events,link_events,regulatory_commands;
static int runtime_regulatory(unsigned pipe,const unsigned char*f,unsigned bytes)
{
    if(pwmi_get(f+8)!=0x4001)return 0;
    CHECK(pipe==3&&bytes==36&&pwmi_get(f+12)==0x00510014&&pwmi_get(f+16)==0x64&&pwmi_get(f+28)==0xff&&pwmi_get(f+32)==0xff);
    regulatory_commands++;wmi_frame(f,0,2);return 1;
}
static void runtime_vectors(void)
{
    const char*path=getenv("POLARIS_TEST_WPA_VECTORS");CHECK(path);FILE*f=fopen(path,"rb");CHECK(f);uint8_t magic[8];
    CHECK(fread(magic,1,8,f)==8&&!memcmp(magic,"PWPA001",8));
    CHECK(fread(pmk_vector,1,32,f)==32&&fread(nonce_vector,1,32,f)==32&&fread(ptk_vector,1,48,f)==48&&fread(gtk_vector,1,16,f)==16);
    for(unsigned n=0;n<9;n++){uint8_t b[4];CHECK(fread(b,1,4,f)==4);lengths[n]=pwmi_get(b);CHECK(lengths[n]<=640&&fread(messages[n],1,lengths[n],f)==lengths[n]);}
    CHECK(fgetc(f)==EOF&&!fclose(f));
}
static int pwkr_cache(uint64_t address,uint64_t bytes,unsigned clean)
{
    CHECK(address&&bytes&&clean<=1);runtime_caches++;
    uintptr_t first=(uintptr_t)mailbox_memory;
    if(address>=first&&address-first<PWMB_BYTES){
        CHECK(!(address&63)&&!(bytes&63)&&bytes<=PWMB_BYTES-(address-first));
        if(clean)memcpy(kernel_page+(address-first),(void*)(uintptr_t)address,bytes);
        else memcpy((void*)(uintptr_t)address,kernel_page+(address-first),bytes);
    }else if(address==(uintptr_t)runtime_ap){
        CHECK(bytes==sizeof(*runtime_ap));
        if(clean)peer_ap=*runtime_ap;else *runtime_ap=peer_ap;
    }else{
#ifdef PWRUNTIME_OTHER_CACHE
        if(PWRUNTIME_OTHER_CACHE(address,bytes,clean))return 1;
#endif
        CHECK(clean&&(address==(uintptr_t)arena+0x1f30000||address==(uintptr_t)arena+0x1f40000));
    }
    return 1;
}
static int64_t pwkr_cpu_on(uint64_t entry,uint64_t context)
{
    CHECK(++runtime_cpu_calls==1&&entry==(uintptr_t)arena+0x1f30000&&context==(uintptr_t)runtime_ap);
    CHECK(*native_flag==1&&*held_input.state==4&&owner->phase==4&&owner->runtime.issued);
    CHECK(!pmsc_live(owner)&&owner_peers==14&&runtime_caches==4);
    struct pwmb_identity id;CHECK(pwmb_bootstrap_parse(kernel_page+PWMB_BOOTSTRAP_OFFSET,&id));
    CHECK(id.epoch==owner->opening&&!memcmp(id.mac,wmi->client.mac,6));
    CHECK(peer_ap.entry==runtime_plan.entry_pa&&peer_ap.args==runtime_plan.args_pa);
    peer_ap.stage=1;peer_ap.mpidr=0x700;return 0;
}
static void runtime_prepare(void)
{
    CHECK(!posix_memalign((void**)&kernel_memory,PWMB_BYTES,0x10000));memset(kernel_memory,0,0x10000);
    mailbox_memory=kernel_memory+0x4000;runtime_payload=(void*)auth_payload;
    memset(auth_payload,0,4096);struct polaris_payload*p=runtime_payload;
    memcpy(p->magic,"SWEETXNU",8);p->version=1;p->nsegs=2;p->virt_base=UINT64_C(0xfffffe0006000000);
    p->kernel_end=p->virt_base+0x8000;p->entry_va=p->virt_base;p->phys_base=(uintptr_t)kernel_memory;p->mem_size=0x10000;p->adt_size=8;
    unsigned source=0x4000;CHECK(source+0x8000<=EFI_XNU_MSS_FIRMWARE_OFFSET);
    p->segs[0]=(struct polaris_segment){p->virt_base,0x4000,source,64};
    p->segs[1]=(struct polaris_segment){p->virt_base+0x4000,0x4000,source+0x4000,0x4000};
    memset(auth_payload+source,0,0x8000);auth_payload[source]=0xa5;auth_payload[source+0x4000]=0x50;auth_payload[source+0x4001]=0x57;
    runtime_copy=(void*)(arena+0x1f00000);memset(runtime_copy,0,sizeof(*runtime_copy));
    CHECK(pwks_begin(runtime_copy,p,PMMN_TEST_PAYLOAD_BYTES));
    memcpy(kernel_memory,auth_payload+source,64);CHECK(pwks_verify(runtime_copy,0));
    memcpy(mailbox_memory,auth_payload+source+0x4000,0x4000);CHECK(pwks_verify(runtime_copy,1));
    runtime_plan=(struct polaris_plan){(uintptr_t)kernel_memory+0x8000,(uintptr_t)kernel_memory+0xc000,(uintptr_t)kernel_memory+0x10000,(uintptr_t)kernel_memory};
    runtime_ap=(void*)(arena+0x1f20000);memset(runtime_ap,0,sizeof(*runtime_ap));
#ifdef PWRUNTIME_AFTER_PREPARE
    PWRUNTIME_AFTER_PREPARE();
#endif
}
static int kernel_live(void*p){return p==kernel_page&&pmsc_persistent(owner);}
static int kernel_copy(void*p,unsigned at,void*q,unsigned bytes,unsigned write)
{CHECK(kernel_live(p)&&at<PWMB_BYTES&&bytes<=PWMB_BYTES-at);if(write)memcpy(kernel_page+at,q,bytes);else memcpy(q,kernel_page+at,bytes);return 1;}
static int kernel_cache(void*p,unsigned at,unsigned bytes,unsigned clean)
{CHECK(kernel_live(p)&&at<PWMB_BYTES&&bytes<=PWMB_BYTES-at&&clean<=1);return 1;}
static int kernel_sequence(void*p,unsigned at,uint64_t*q,unsigned write)
{CHECK(kernel_live(p)&&!(at&7)&&at<=PWMB_BYTES-8);if(write)memcpy(kernel_page+at,q,8);else memcpy(q,kernel_page+at,8);return 1;}
static struct pwmb_bus kernel_bus={kernel_page,kernel_live,kernel_copy,kernel_cache,kernel_sequence};
static void runtime_turn(void)
{
    advance_to(owner->last+19200);int status=pwwn_step(worker);
    if(status!=1)fprintf(stderr,"runtime status%d worker%u phase%u owner%u scan%u network%u transport%u glink%u\n",status,worker->error,worker->phase,owner->error,worker->scan.error,worker->network.error,transport->error,glink->error);
    CHECK(status==1);
    struct pwmb_message event;int r=pwmb_receive_poll(&kernel_lanes[PWMB_EVENT],&kernel_bus,&event);CHECK(r>=0);
    if(r){CHECK(event.operation==PWMB_NOTIFY);unsigned id=pwmb_u32(event.data);if(id==1)ready_events++;if(id==2)scan_events++;if(id==3)link_events++;
        CHECK(pwmb_receive_complete(&kernel_lanes[PWMB_EVENT],&kernel_bus)==1);}
    if(network&&network->early_ready&&held_bytes){
        CHECK(!network->wpa.opened&&!station->client.station.associated);wmi_frame(held_assoc,held_bytes,1);held_bytes=0;
    }
}
static struct pwmb_message reply;
static void runtime_control(unsigned operation,const uint8_t*input,unsigned bytes)
{
    CHECK(pwmb_send(&kernel_lanes[PWMB_CONTROL],&kernel_bus,operation,input,bytes)==1);
    unsigned ack=0,received=0;
    for(unsigned n=0;n<100&&!received;n++){
        runtime_turn();if(!ack){int r=pwmb_send_ack_poll(&kernel_lanes[PWMB_CONTROL],&kernel_bus);CHECK(r>=0);ack=r;}
        int r=pwmb_receive_poll(&kernel_lanes[PWMB_REPLY],&kernel_bus,&reply);CHECK(r>=0);
        if(r){CHECK(pwcb_reply_valid(reply.data,reply.bytes)&&pwmb_u32(reply.data+8)==operation&&!pwmb_u32(reply.data+12));
            CHECK(pwmb_receive_complete(&kernel_lanes[PWMB_REPLY],&kernel_bus)==1);received=1;}
    }
    CHECK(ack&&received);
}
static void runtime_drive(void)
{
    *runtime_ap=(struct polaris_efi_ap){.entry=runtime_plan.entry_pa,.args=runtime_plan.args_pa,.sctlr=owner->current.cpu.sctlr,.cpacr=owner->current.cpacr,.stack=(uintptr_t)arena+0x1f44000};
    CHECK(pwkr_begin(parent,runtime_copy,runtime_ap,(uintptr_t)arena+0x1f30000,(uintptr_t)arena+0x1f40000,0x4000,&runtime_plan,runtime_payload->virt_base+0x4000)==1);
    CHECK(pwkr_poll(parent)==2&&pmsc_persistent(owner)&&runtime_cpu_calls==1);
    worker=(void*)(arena+0x7100000);CHECK(sizeof(*worker)<0x100000);memset(worker,0,sizeof(*worker));
    CHECK(pwwn_begin(worker,parent,36));scan=&worker->scan;
    for(unsigned n=0;n<PWMB_LANES;n++)CHECK(pwmb_link_open(&kernel_lanes[n],n,pwmn_producer(n)?PWMB_CONSUMER:PWMB_PRODUCER,owner->opening));
    runtime_control(PWMB_STATE,0,0);CHECK(ready_events==1&&pwmb_u32(reply.data+16)==1);
    runtime_control(PWMB_SCAN,0,0);
    for(unsigned n=0;n<100&&worker->phase==PWWN_SCAN;n++)runtime_turn();
    CHECK(worker->phase==PWWN_SCANNED&&scan_events==1&&scan->client.count==1&&scan_commands==3);
    uint8_t index[4]={0};runtime_control(PWMB_SCAN_ENTRY,index,4);
    CHECK(pwmb_u32(reply.data+20)==2437&&reply.data[40]==7&&!memcmp(reply.data+48,"fixture",7));
    runtime_vectors();CHECK(!memcmp(parent_nonces+PWNP_HEADER,nonce_vector,32));
    station=&worker->station;network=&worker->network;
    uint8_t join[112]={2,0,0,0,7,32,2};memcpy(join+16,"fixture",7);memcpy(join+48,pmk_vector,32);
    runtime_control(PWMB_JOIN,join,sizeof(join));memset(join,0,sizeof(join));
    for(unsigned n=0;n<500&&worker->phase!=PWWN_LINK;n++)runtime_turn();
    CHECK(worker->phase==PWWN_LINK&&link_events==1&&regulatory_commands==1&&network->ethernet.authorized&&key_commands==3&&eapol_commands==2);
    CHECK(parent->nonce.pool.used==1&&pwmb_zero(worker->pmk,32)&&pwmb_zero(network->pmk,32)&&pwmb_zero(network->nonce,32));
    uint8_t payload[100],outgoing[114];for(unsigned n=0;n<100;n++)payload[n]=(uint8_t)(n+14);
    network_receive(0x800,payload,100,1,0,2);struct pwmb_message packet;int received=0;
    for(unsigned n=0;n<100&&!received;n++){runtime_turn();received=pwmb_receive_poll(&kernel_lanes[PWMB_RX],&kernel_bus,&packet);CHECK(received>=0);}
    CHECK(received==1&&packet.bytes==114&&!memcmp(packet.data+14,payload,100)&&pwmb_receive_complete(&kernel_lanes[PWMB_RX],&kernel_bus)==1);
    memset(outgoing,255,6);memcpy(outgoing+6,wmi->client.mac,6);outgoing[12]=8;outgoing[13]=0;memcpy(outgoing+14,payload,100);
    CHECK(pwmb_send(&kernel_lanes[PWMB_TX],&kernel_bus,PWMB_ETHERNET_TX,outgoing,114)==1);unsigned ack=0;
    for(unsigned n=0;n<100&&(!ack||!ethernet_commands||network->tx_wait);n++){runtime_turn();if(!ack){int r=pwmb_send_ack_poll(&kernel_lanes[PWMB_TX],&kernel_bus);CHECK(r>=0);ack=r;}}
    CHECK(ack&&ethernet_commands==1&&!network->tx_wait);
    advance_to(owner->opening+PMSC_TOTAL+19200);runtime_control(PWMB_STATE,0,0);
    CHECK(pmsc_persistent(owner)&&worker->phase==PWWN_LINK&&runtime_cpu_calls==1&&pwmb_u32(reply.data+16)==3);
    fprintf(stderr,"complete startup/runtime worker scan/PMK JOIN/keys/mailbox RX+TX and beyond180s PASS; SOFTWARE CPU/kernel/radio, no IP or physical claim\n");
#ifdef PWRUNTIME_AFTER_TRAFFIC
    PWRUNTIME_AFTER_TRAFFIC();
#endif
}
