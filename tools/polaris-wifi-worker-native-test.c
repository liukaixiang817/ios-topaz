/* Actual worker/control/PBKDF2 and mailbox transport bodies, SOFTWARE radio
 * responses/runtime qualification. This is not the whole native parent test. */
#define EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE 1
#define EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE 1
#ifndef EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE 1
#endif
#define POLARIS_WIFI_NETWORK_NONCE_TEST 1
#define PMWN_TEST_ENTRY unused_network_suite
#include "polaris-wifi-network-native-test.c"
#define POLARIS_WIFI_RUNTIME_SOFTWARE_PEER 1
#define EFI_XNU_WIFI_MAILBOX_NATIVE_AVAILABLE 1
#include "uefi-wifi-mailbox-native.h"
static int pwkr_cache(uint64_t a,uint64_t n,unsigned c){(void)a;(void)n;(void)c;return 0;}
static int64_t pwkr_cpu_on(uint64_t a,uint64_t b){(void)a;(void)b;return -1;}
static struct pwns_parent model_parent;
static uint8_t page[PWMB_BYTES];
static struct pwmb_link native_lanes[PWMB_LANES],kernel_lanes[PWMB_LANES];
static unsigned qualified=1,radio_polls,scan_result=1,net_result=1,tx_busy=1,tx_accepted,rx_acked,reg_commands,station_begins;
static unsigned force_fault,reap_calls,reap_index,reap_fault;
static int bus_live(void*p){return p==page;}
static int bus_copy(void*p,unsigned at,void*q,unsigned bytes,unsigned write)
{CHECK(p==page&&at<PWMB_BYTES&&bytes<=PWMB_BYTES-at);if(write)memcpy(page+at,q,bytes);else memcpy(q,page+at,bytes);return 1;}
static int bus_cache(void*p,unsigned at,unsigned bytes,unsigned clean)
{CHECK(p==page&&at<PWMB_BYTES&&bytes<=PWMB_BYTES-at&&clean<=1);return 1;}
static int bus_sequence(void*p,unsigned at,uint64_t*q,unsigned write)
{CHECK(p==page&&at<=PWMB_BYTES-8&&!(at&7));if(write)memcpy(page+at,q,8);else memcpy(q,page+at,8);return 1;}
static struct pwmb_bus model_bus={page,bus_live,bus_copy,bus_cache,bus_sequence};
static int model_current(struct pwmn_state*s){return qualified&&s->parent==(uintptr_t)&model_parent;}
static int model_send(struct pwmn_state*s,unsigned lane,unsigned op,const uint8_t*p,unsigned n)
{
    CHECK(model_current(s));struct pwmb_link*l=&native_lanes[lane];
    if(l->state.stage==2){int r=pwmb_send_ack_poll(l,&model_bus);if(r!=1)return r;}
    return pwmb_send(l,&model_bus,op,p,n);
}
static int model_receive(struct pwmn_state*s,unsigned lane,struct pwmb_message*m)
{CHECK(model_current(s));return pwmb_receive_poll(&native_lanes[lane],&model_bus,m);}
static int model_complete(struct pwmn_state*s,unsigned lane)
{CHECK(model_current(s));return pwmb_receive_complete(&native_lanes[lane],&model_bus);}
static int model_sent(struct pwmn_state*s,unsigned lane)
{
    CHECK(model_current(s)&&lane==PWMB_REPLY);struct pwmb_link*l=&native_lanes[lane];
    return l->state.stage?pwmb_send_ack_poll(l,&model_bus):1;
}
static int model_scan_begin(struct pmwsn_state*s,struct pmwi_state*w,unsigned id)
{s->ready=1;return pwsc_open(&s->client,&w->client,id,model_parent.owner.last);}
static int model_scan_restart(struct pmwsn_state*s,unsigned id)
{return pwsc_restart(&s->client,id,model_parent.owner.last);}
static int model_scan_step(struct pmwsn_state*s)
{radio_polls++;if(scan_result==3){s->client.completed=1;s->client.phase=5;}return scan_result;}
static int model_data_poll(struct pmhd_state*s){(void)s;radio_polls++;return force_fault?-1:1;}
static int model_htc_send(struct pmhc_state*h,unsigned endpoint,const uint8_t*p,unsigned bytes)
{CHECK(endpoint==h->client.wmi&&bytes==28&&pwmi_get(p)==0x4001);reg_commands++;h->client.pending=1;return 1;}
static int model_station_begin(struct pmst_state*s,struct pmwsn_state*q,struct pmhd_state*d,unsigned i,unsigned security,const struct pwst_channel*c)
{(void)d;CHECK(!model_parent.htc.client.pending&&reg_commands==1&&security==2&&c->max_power==40);station_begins++;s->ready=1;s->client.station.target=q->client.bss[i];return 1;}
static const uint8_t expected_pmk[32]={0xf4,0x2c,0x6f,0xc5,0x2d,0xf0,0xeb,0xef,0x9e,0xbb,0x4b,0x90,0xb3,0x8a,0x5f,0x90,0x2e,0x83,0xfe,0x1b,0x13,0x5a,0x70,0xe2,0x3a,0xed,0x76,0x2e,0x97,0x10,0xa1,0x2e};
static int model_network_begin(struct pmwn_state*s,struct pmst_state*p,const uint8_t*pmk,struct pmnp_state*n)
{(void)p;(void)n;CHECK(station_begins==1&&!memcmp(pmk,expected_pmk,32));s->ready=1;return 1;}
static int model_network_step(struct pmwn_state*s)
{radio_polls++;if(net_result==5||net_result==3)s->ethernet.authorized=1;if(net_result==4)pmwn_close(s);return net_result;}
static int model_network_send(struct pmwn_state*s,const uint8_t*p,unsigned n)
{CHECK(s->ethernet.authorized&&n==60&&pwmb_u32(p+14)==0x12345678);if(tx_busy)return 0;tx_accepted++;return 1;}
static int model_network_ack(struct pmwn_state*s){CHECK(s->ethernet.rx_ready);s->ethernet.rx_ready=0;rx_acked++;net_result=5;return 1;}
static int model_reap(struct pmct_state*t,unsigned pipe)
{
    CHECK(t==&model_parent.transport&&pipe==3&&t->rings.source[pipe].posted);
    reap_calls++;return reap_fault?-1:pwcr_complete_tx(&t->rings,pipe,reap_index);
}
#define pwmn_current model_current
#define pwmn_send model_send
#define pwmn_receive model_receive
#define pwmn_complete model_complete
#define pwmn_sent model_sent
#define pmwsn_begin model_scan_begin
#define pmwsn_restart model_scan_restart
#define pmwsn_step model_scan_step
#define pmhd_poll model_data_poll
#define pmhc_send model_htc_send
#define pmst_begin model_station_begin
#define pmwn_begin_pool model_network_begin
#define pmwn_step model_network_step
#define pmwn_send model_network_send
#define pmwn_ack model_network_ack
#define pmct_reap model_reap
#define EFI_XNU_WIFI_WORKER_NATIVE_AVAILABLE 1
#include "uefi-wifi-worker-native.h"
static struct pwwn_state worker;
static void worker_setup(void)
{
    memset(&worker,0,sizeof(worker));memset(&model_parent,0,sizeof(model_parent));memset(page,0,sizeof(page));
    memset(native_lanes,0,sizeof(native_lanes));memset(kernel_lanes,0,sizeof(kernel_lanes));
    qualified=1;force_fault=0;reap_calls=reap_index=reap_fault=0;worker.ready=1;worker.country=36;worker.mailbox.parent=(uintptr_t)&model_parent;
    model_parent.owner.last=100;model_parent.wmi.client.phase=4;model_parent.wmi.client.epoch=77;model_parent.wmi.client.mac[0]=2;
    pwmi_put(model_parent.wmi.client.regulatory,0x60);model_parent.htc.client.wmi=1;
    for(unsigned n=0;n<PWMB_LANES;n++){
        CHECK(pwmb_link_open(&native_lanes[n],n,pwmn_producer(n)?PWMB_PRODUCER:PWMB_CONSUMER,77));
        CHECK(pwmb_link_open(&kernel_lanes[n],n,pwmn_producer(n)?PWMB_CONSUMER:PWMB_PRODUCER,77));
    }
}
static struct pwmb_message output;
static void control(unsigned op,const uint8_t*p,unsigned n,unsigned error)
{
    CHECK(pwmb_send(&kernel_lanes[PWMB_CONTROL],&model_bus,op,p,n)==1);
    CHECK(pwwn_step(&worker)==1&&pwmb_send_ack_poll(&kernel_lanes[PWMB_CONTROL],&model_bus)==1);
    CHECK(pwmb_zero(&worker.request,sizeof(worker.request))&&pwmb_zero(page+128,PWMB_DATA));
    CHECK(pwwn_step(&worker)==1&&pwmb_receive_poll(&kernel_lanes[PWMB_REPLY],&model_bus,&output)==1);
    CHECK(pwcb_reply_valid(output.data,output.bytes)&&pwmb_u32(output.data+8)==op&&pwmb_u32(output.data+12)==error);
    CHECK(pwmb_receive_complete(&kernel_lanes[PWMB_REPLY],&model_bus)==1);
}
int main(void)
{
    worker_setup();control(PWMB_STATE,0,0,0);CHECK(pwmb_u32(output.data+16)==1);
    control(PWMB_SCAN,0,0,0);CHECK(worker.phase==PWWN_SCAN&&worker.scan_id==1);
    control(PWMB_SCAN,0,0,16);scan_result=3;CHECK(pwwn_step(&worker)==1&&worker.phase==PWWN_SCANNED);
    scan_result=1;control(PWMB_SCAN,0,0,0);CHECK(worker.scan_id==2&&worker.scan.client.phase==1); /* No second VDEV_CREATE. */
    scan_result=3;CHECK(pwwn_step(&worker)==1&&worker.phase==PWWN_SCANNED);scan_result=1;
    struct pwsc_bss*b=&worker.scan.client.bss[0];worker.scan.client.count=1;
    b->bssid[0]=2;b->bssid[5]=9;b->frequency=2437;b->ssid_bytes=4;memcpy(b->ssid,"IEEE",4);b->observations=2;b->snr=-5;b->ie_bytes=6;b->ies[1]=4;memcpy(b->ies+2,"IEEE",4);
    uint8_t index[4]={0};control(PWMB_SCAN_ENTRY,index,4,0);CHECK(output.bytes==86&&pwcb_bss_valid(output.data+16,output.bytes-16));
    uint8_t join[112]={2,0,0,0,4,8,1};memcpy(join+16,"IEEE",4);memcpy(join+48,"password",8);
    join[16]='x';control(PWMB_JOIN,join,112,2);join[16]='I';control(PWMB_JOIN,join,112,0);
    CHECK(worker.phase==PWWN_PMK&&!station_begins&&!reg_commands);
    unsigned before=radio_polls;
    for(unsigned n=0;n<300&&worker.phase==PWWN_PMK;n++)CHECK(pwwn_step(&worker)==1);
    CHECK(radio_polls>=before+250&&worker.phase==PWWN_REGULATORY&&reg_commands==1&&!station_begins&&model_parent.htc.client.pending);
    CHECK(pwmb_zero(&worker.derivation,sizeof(worker.derivation))&&!memcmp(worker.pmk,expected_pmk,32));
    for(unsigned n=0;n<8;n++)CHECK(pwwn_step(&worker)==1&&!station_begins);
    model_parent.htc.client.pending=0;CHECK(pwwn_step(&worker)==1&&station_begins==1&&worker.reg_published&&worker.phase==PWWN_JOIN&&pwmb_zero(worker.pmk,32));
    CHECK(pwwn_step(&worker)==1&&worker.phase==PWWN_JOIN);net_result=5;CHECK(pwwn_step(&worker)==1&&worker.phase==PWWN_LINK);
    control(PWMB_STATE,0,0,0);CHECK(pwmb_u32(output.data+16)==3);
    uint8_t ethernet[60]={0};memset(ethernet,255,6);memcpy(ethernet+6,model_parent.wmi.client.mac,6);ethernet[12]=8;pwmb_put32(ethernet+14,0x12345678);
    CHECK(pwmb_send(&kernel_lanes[PWMB_TX],&model_bus,PWMB_ETHERNET_TX,ethernet,60)==1);
    before=radio_polls;for(unsigned n=0;n<10;n++)CHECK(pwwn_step(&worker)==1&&worker.tx_pending&&!tx_accepted&&pwmb_send_ack_poll(&kernel_lanes[PWMB_TX],&model_bus)==0);
    CHECK(radio_polls==before+10);tx_busy=0;CHECK(pwwn_step(&worker)==1&&!worker.tx_pending&&tx_accepted==1&&pwmb_send_ack_poll(&kernel_lanes[PWMB_TX],&model_bus)==1);
    /* A forbidden EAPOL frame from the BSD data lane is dropped, not wedged. */
    ethernet[12]=0x88;ethernet[13]=0x8e;CHECK(pwmb_send(&kernel_lanes[PWMB_TX],&model_bus,PWMB_ETHERNET_TX,ethernet,60)==1);
    CHECK(pwwn_step(&worker)==1&&worker.tx_dropped==1&&pwmb_send_ack_poll(&kernel_lanes[PWMB_TX],&model_bus)==1);
    ethernet[12]=8;ethernet[13]=0;memcpy(worker.network.ethernet.receive,ethernet,60);worker.network.ethernet.rx_bytes=60;worker.network.ethernet.rx_ready=1;net_result=3;
    CHECK(pwwn_step(&worker)==1&&rx_acked==1);
    worker.network.ethernet.rx_ready=1;net_result=3;CHECK(pwwn_step(&worker)==1&&rx_acked==1); /* Kernel RX backpressure. */
    CHECK(pwmb_receive_poll(&kernel_lanes[PWMB_RX],&model_bus,&output)==1&&!memcmp(output.data,ethernet,60));
    CHECK(pwmb_receive_complete(&kernel_lanes[PWMB_RX],&model_bus)==1&&pwwn_step(&worker)==1&&rx_acked==2);
    control(PWMB_DISCONNECT,0,0,45);CHECK(worker.phase==PWWN_LINK); /* Explicitly unsupported, not false completion. */
    CHECK(pwwn_quiesce_begin(&worker)&&!pwwn_quiesce_begin(&worker));
    model_parent.transport.rings.started=1;
    model_parent.transport.rings.source[3]=(struct pwcr_ring){.entries=32,.write=1,.posted=1};
    CHECK(pwwn_step(&worker)==1&&worker.closing==1&&!worker.network.closed&&reap_calls==1);
    reap_index=1;model_parent.data.rings.tx_owner[4]=2;
    CHECK(pwwn_step(&worker)==1&&worker.closing==1);model_parent.data.rings.tx_owner[4]=0;
    CHECK(pwwn_step(&worker)==2&&worker.closing==2&&worker.network.closed&&worker.phase==PWWN_CLOSED);
    CHECK(reap_calls==2&&!model_parent.transport.rings.source[3].posted&&model_parent.transport.rings.source[3].completed==1);
    before=radio_polls;CHECK(pwwn_step(&worker)==2&&radio_polls==before); /* No new post after drain. */
    memset(worker.pmk,0x5a,32);qualified=0;before=radio_polls;
    CHECK(pwwn_step(&worker)==-1&&worker.unknown&&pwmb_zero(worker.pmk,32)&&radio_polls==before);
    worker_setup();worker.turns=UINT64_MAX;CHECK(pwwn_step(&worker)==-1&&worker.unknown);
    worker_setup();force_fault=1;memset(worker.request.data,0x33,112);CHECK(pwwn_step(&worker)==-1&&worker.unknown&&pwmb_zero(&worker.request,sizeof(worker.request)));
    worker_setup();force_fault=0;worker.phase=PWWN_LINK;worker.network.ready=1;net_result=5;
    CHECK(pwwn_quiesce_begin(&worker));model_parent.owner.last=worker.close_deadline+1;
    CHECK(pwwn_step(&worker)==-1&&worker.unknown&&worker.error==15);
    worker_setup();worker.phase=PWWN_LINK;worker.network.ready=1;net_result=5;reap_fault=1;
    model_parent.transport.rings.source[3].posted=1;CHECK(pwwn_quiesce_begin(&worker));
    CHECK(pwwn_step(&worker)==-1&&worker.error==15&&worker.closing==1&&reap_calls==1);
    for(unsigned which=0;which<3;which++){
        worker_setup();worker.phase=which==0?PWWN_IDLE:which==1?PWWN_SCANNED:PWWN_LINK;
        worker.network.ready=which==2;net_result=5;
#if EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE
        CHECK(pwmb_send(&kernel_lanes[PWMB_CONTROL],&model_bus,PWMB_POWER_OFF,0,0)==1);
        CHECK(pwwn_step(&worker)==1&&worker.terminal_requested&&worker.closing==1);
        CHECK(pwmb_send_ack_poll(&kernel_lanes[PWMB_CONTROL],&model_bus)==1);
        for(unsigned n=0;n<5;n++)CHECK(pwwn_step(&worker)==1&&!worker.network.closed&&worker.closing==1);
        CHECK(pwmb_receive_poll(&kernel_lanes[PWMB_REPLY],&model_bus,&output)==1);
        CHECK(output.bytes==16&&pwmb_u32(output.data+8)==PWMB_POWER_OFF&&!pwmb_u32(output.data+12));
        CHECK(pwmb_receive_complete(&kernel_lanes[PWMB_REPLY],&model_bus)==1);
        CHECK(pwwn_step(&worker)==2&&worker.network.closed&&worker.closing==2);
#else
        control(PWMB_POWER_OFF,0,0,45);CHECK(!worker.terminal_requested&&!worker.closing);
#endif
    }
    printf("PASS %u worker checks; actual wire/crypto, SOFTWARE radio/runtime\n",checks+nv_checks);return 0;
}
