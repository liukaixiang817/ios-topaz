#include <assert.h>
#include <stdio.h>
#include <string.h>
#define POLARIS_WIFI_KERNEL_MAILBOX_SOFTWARE 1
#include "polaris-wifi-kernel-mailbox.c"
static unsigned checks,preemption,platform=1,shutdown_pending,cache_calls,cache_fault;
static uint64_t cpu=0x700;
#define CHECK(x) do{assert(x);checks++;}while(0)
static uint8_t device[PWMB_BYTES],wire[PWMB_RECORD],reply[32],packet[64],event[16],bootstrap[PWMB_LINE];
static struct pwmb_state firmware[PWMB_LANES];
static struct pwmb_message message,received;
static void pwk_preempt_disable(void){preemption++;}
static void pwk_preempt_enable(void){CHECK(preemption);preemption--;}
static uint64_t pwk_cpu(void){return cpu;}
static int pwk_platform(void){return platform;}
static int pwk_shutdown(void){return shutdown_pending;}
static int pwk_cache_leaf(unsigned off,unsigned n,unsigned clean)
{
    CHECK(preemption==1&&pwk.gate&&off+n<=PWMB_BYTES&&!(off%128)&&!(n%128));cache_calls++;
    if(cache_calls==cache_fault)return 0;
    if(clean)memcpy(device+off,polaris_wifi_mailbox_page+off,n);
    else memcpy(polaris_wifi_mailbox_page+off,device+off,n);return 1;
}
static void setup(void)
{
    CHECK(!preemption);memset(&pwk,0,sizeof(pwk));memset(device,0,sizeof(device));memset(polaris_wifi_mailbox_page,0,PWMB_BYTES);
    memset(firmware,0,sizeof(firmware));cache_calls=cache_fault=shutdown_pending=0;platform=1;cpu=0x700;
    struct pwmb_identity id={.epoch=91,.mac={2,3,4,5,6,7}};
    CHECK(pwmb_bootstrap_make(&id,bootstrap));memcpy(device+PWMB_BOOTSTRAP_OFFSET,bootstrap,PWMB_LINE);
    for(unsigned n=0;n<PWMB_LANES;n++)CHECK(pwmb_open(&firmware[n],n,n==PWMB_CONTROL||n==PWMB_TX?PWMB_CONSUMER:PWMB_PRODUCER,91));
}
static void attach(void)
{
    struct pwmb_identity identity={0};CHECK(!polaris_wifi_mailbox_attach(&identity)&&identity.epoch==91&&!memcmp(identity.mac,bootstrap+32,6));
    CHECK(!preemption&&!polaris_wifi_mailbox_status());
}
static void firmware_send(unsigned lane,unsigned operation,const uint8_t*p,unsigned n)
{
    struct pwmb_state*s=&firmware[lane];unsigned base=lane*PWMB_SLOT;
    if(s->stage){uint8_t*a=device+base+PWMB_ACK_OFFSET;uint64_t seq=pwmb_u64(a+24);CHECK(pwmb_ack(s,a,seq,seq)==1);}
    CHECK(pwmb_prepare(s,operation,p,n,wire));memcpy(device+base,wire,PWMB_RECORD);CHECK(pwmb_tx_published(s,s->next,1)==1);
}
static void firmware_receive(unsigned lane)
{
    struct pwmb_state*s=&firmware[lane];unsigned base=lane*PWMB_SLOT;uint64_t seq=pwmb_u64(device+base+24);
    CHECK(pwmb_receive(s,device+base,seq,seq,&received)==1);CHECK(pwmb_ack_prepare(s,wire));
    memcpy(device+base+PWMB_ACK_OFFSET,wire,PWMB_LINE);CHECK(pwmb_rx_ack_published(s,seq,1)==1);
}
static void notify(unsigned kind,unsigned status,uint64_t detail)
{
    memset(event,0,sizeof(event));pwmb_put32(event,kind);pwmb_put32(event+4,status);pwmb_put64(event+8,detail);
    firmware_send(PWMB_EVENT,PWMB_NOTIFY,event,16);CHECK(polaris_wifi_mailbox_poll(PWMB_EVENT,&message)==1);
}
int main(void)
{
    for(unsigned n=0;n<sizeof(packet);n++)packet[n]=(uint8_t)n;
    setup();struct pwmb_identity id;
    platform=0;CHECK(polaris_wifi_mailbox_attach(&id)==ENXIO&&!cache_calls);platform=1;
    cpu=0;CHECK(polaris_wifi_mailbox_attach(&id)==ENXIO&&!preemption&&!cache_calls);cpu=0x700;
    device[PWMB_BOOTSTRAP_OFFSET]=0;CHECK(polaris_wifi_mailbox_attach(&id)==EAGAIN&&!pwk.initialized&&!preemption);
    memcpy(device+PWMB_BOOTSTRAP_OFFSET,bootstrap,PWMB_LINE);attach();
    CHECK(polaris_wifi_mailbox_transmit(packet,64)==ENETDOWN);
    uint64_t sequence_number=0;CHECK(polaris_wifi_mailbox_request(PWMB_SCAN,0,0,&sequence_number)==EAGAIN);
    CHECK(!polaris_wifi_mailbox_request(PWMB_STATE,0,0,&sequence_number)&&sequence_number==1);
    firmware_receive(PWMB_CONTROL);CHECK(received.operation==PWMB_STATE);
    CHECK(polaris_wifi_mailbox_request(PWMB_STATE,0,0,&sequence_number)==EWOULDBLOCK);
    memset(reply,0,sizeof(reply));pwmb_put64(reply,1);pwmb_put32(reply+8,PWMB_STATE);
    firmware_send(PWMB_REPLY,PWMB_RESPONSE,reply,16);CHECK(polaris_wifi_mailbox_poll(PWMB_REPLY,&message)==1&&!pwk.control_pending);
    notify(1,0,0);CHECK(polaris_wifi_mailbox_status()==1);
    CHECK(!polaris_wifi_mailbox_request(PWMB_SCAN,0,0,&sequence_number)&&sequence_number==2);firmware_receive(PWMB_CONTROL);
    pwmb_put64(reply,2);pwmb_put32(reply+8,PWMB_SCAN);firmware_send(PWMB_REPLY,PWMB_RESPONSE,reply,16);
    CHECK(polaris_wifi_mailbox_poll(PWMB_REPLY,&message)==1);notify(2,0,3);CHECK(polaris_wifi_mailbox_status()==1);
    firmware_send(PWMB_RX,PWMB_ETHERNET_RX,packet,64);CHECK(!polaris_wifi_mailbox_poll(PWMB_RX,&message)&&pwmb_zero(&message,sizeof(message)));
    notify(3,0,1);CHECK(polaris_wifi_mailbox_status()==3);
    CHECK(!polaris_wifi_mailbox_transmit(packet,64));CHECK(polaris_wifi_mailbox_transmit(packet,64)==EWOULDBLOCK);
    firmware_receive(PWMB_TX);CHECK(received.bytes==64&&!memcmp(received.data,packet,64));
    firmware_send(PWMB_RX,PWMB_ETHERNET_RX,packet,64);CHECK(polaris_wifi_mailbox_poll(PWMB_RX,&message)==1&&!memcmp(message.data,packet,64));
    CHECK(pwmb_zero(pwk.lane[PWMB_TX].wire,PWMB_RECORD));
    notify(4,0,19);CHECK(polaris_wifi_mailbox_transmit(packet,64)==ENETDOWN&&polaris_wifi_mailbox_status()==1);
    CHECK(!polaris_wifi_mailbox_seal()&&polaris_wifi_mailbox_status()==8&&polaris_wifi_mailbox_attach(&id)==ENXIO);
    CHECK(polaris_wifi_mailbox_poll(PWMB_RX,&message)==-ENXIO&&!preemption);
    setup();attach();device[PWMB_BOOTSTRAP_OFFSET+16]^=1;
    CHECK(polaris_wifi_mailbox_poll(PWMB_EVENT,&message)==-ENXIO&&pwk.fault&&!preemption);
    setup();attach();notify(5,EIO,0);CHECK(polaris_wifi_mailbox_status()==4&&polaris_wifi_mailbox_attach(&id)==ENXIO);
    setup();attach();pwmb_put64(reply,17);pwmb_put32(reply+8,PWMB_STATE);firmware_send(PWMB_REPLY,PWMB_RESPONSE,reply,16);
    CHECK(polaris_wifi_mailbox_poll(PWMB_REPLY,&message)==-EIO&&pwk.fault&&!pwmb_u64(device+PWMB_REPLY*PWMB_SLOT+PWMB_ACK_OFFSET+24));
    setup();attach();memset(event,0,sizeof(event));pwmb_put32(event,3);pwmb_put64(event+8,1);firmware_send(PWMB_EVENT,PWMB_NOTIFY,event,16);
    CHECK(polaris_wifi_mailbox_poll(PWMB_EVENT,&message)==-EIO&&pwk.fault&&!pwk.link);
    setup();attach();notify(1,0,0);notify(3,0,1);shutdown_pending=1;
    CHECK(polaris_wifi_mailbox_transmit(packet,64)==ENXIO&&!preemption);CHECK(!polaris_wifi_mailbox_seal());
    setup();attach();pwk.gate=1;CHECK(polaris_wifi_mailbox_seal()==EBUSY&&pwk.seal_requested&&!preemption);
    pwk.gate=0;CHECK(polaris_wifi_mailbox_request(PWMB_STATE,0,0,&sequence_number)==ENXIO);
    CHECK(!polaris_wifi_mailbox_seal()&&pwk.sealed);
    setup();attach();notify(1,0,0);
    uint8_t join[112]={0};pwmb_put32(join,2);join[4]=4;join[5]=8;join[6]=1;memcpy(join+16,"test",4);memcpy(join+48,"password",8);
    CHECK(!polaris_wifi_mailbox_request(PWMB_JOIN,join,112,&sequence_number));
    CHECK(!memcmp(device+PWMB_LINE+48,"password",8));firmware_receive(PWMB_CONTROL);
    CHECK(pwk.control_pending&&!memcmp(received.data+48,"password",8));pwmb_clear(&received,sizeof(received));
    CHECK(!polaris_wifi_mailbox_poll(PWMB_EVENT,&message));
    CHECK(pwk.control_pending&&pwmb_zero(device+PWMB_LINE,PWMB_DATA)&&pwmb_u64(device+24)==sequence_number&&pwmb_zero(pwk.lane[PWMB_CONTROL].wire,PWMB_RECORD));
    CHECK(!pwmb_receive(&firmware[PWMB_CONTROL],device,sequence_number,sequence_number,&received));
    CHECK(!polaris_wifi_mailbox_seal());pwmb_clear(join,sizeof(join));
    setup();attach();cache_fault=cache_calls+1;
    CHECK(polaris_wifi_mailbox_poll(PWMB_EVENT,&message)==-ENXIO&&pwk.fault&&!preemption);
    printf("PASS %u actual kernel mailbox adapter checks; SOFTWARE preemption/CPU/cache/boot context, no registered ifnet or phone\n",checks);return 0;
}
