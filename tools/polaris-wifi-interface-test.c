#define POLARIS_WIFI_INTERFACE_SOFTWARE 1
#include "polaris-wifi-interface.c"
static unsigned checks,mailbox_attached,mailbox_sealed,mailbox_seal_busy,mailbox_tx_busy,mailbox_tx,mailbox_control;
static unsigned mailbox_control_busy,mailbox_hook_seal,mailbox_poll_error;
static uint8_t sent[1514],control_copy[112];static unsigned sent_bytes;
static uint64_t control_sequence;
static struct pwmb_message incoming[PWMB_LANES];
static unsigned available[PWMB_LANES];
#define CHECK(x) do{assert(x);checks++;}while(0)
bool polaris_ram_overlay_allowed(void){return mock_gate;}
int polaris_uefi_shutdown_pending(void){return mock_shutdown;}
int polaris_wifi_mailbox_attach(struct pwmb_identity*i)
{mailbox_attached++;i->epoch=91;memcpy(i->mac,"\002\003\004\005\006\007",6);return 0;}
int polaris_wifi_mailbox_seal(void)
{mailbox_sealed=1;return mailbox_seal_busy?EBUSY:0;}
int polaris_wifi_mailbox_poll(unsigned lane,struct pwmb_message*m)
{
    CHECK(lane==PWMB_EVENT||lane==PWMB_REPLY||lane==PWMB_RX);
    if(mailbox_poll_error)return -EIO;
    if(mailbox_sealed)return -ENXIO;
    if(!available[lane])return 0;
    *m=incoming[lane];available[lane]=0;
    if(mailbox_hook_seal){mailbox_hook_seal=0;CHECK(polaris_wifi_interface_seal()==EBUSY);}
    return 1;
}
int polaris_wifi_mailbox_request(unsigned op,const uint8_t*p,unsigned n,uint64_t*seq)
{
    CHECK(mock_locked&&pwmb_payload(PWMB_CONTROL,op,p,n));
    if(mailbox_sealed)return ENXIO;if(mailbox_control_busy)return EWOULDBLOCK;
    mailbox_control++;memcpy(control_copy,p,n);*seq=++control_sequence;return 0;
}
int polaris_wifi_mailbox_transmit(const uint8_t*p,unsigned n)
{
    CHECK(mock_locked&&n>=14&&n<=1514);
    if(mailbox_sealed)return ENXIO;if(mailbox_tx_busy)return EWOULDBLOCK;
    mailbox_tx++;sent_bytes=n;memcpy(sent,p,n);return 0;
}
static void setup(void)
{
    CHECK(!mock_locked);memset(&pwif,0,sizeof(pwif));memset(&mock_interface,0,sizeof(mock_interface));
    memset(incoming,0,sizeof(incoming));memset(available,0,sizeof(available));
    mock_superuser=mock_platform=mock_gate=1;mock_shutdown=mock_alloc_failure=mock_copy_failure=mock_kernel_error=0;
    mock_freed=mock_inputs=mock_events=mock_event_last=mock_attach=mock_threads=mock_stat_sent=mock_stat_errors=0;
    mailbox_attached=mailbox_sealed=mailbox_seal_busy=mailbox_tx_busy=mailbox_tx=mailbox_control=0;
    mailbox_control_busy=mailbox_hook_seal=mailbox_poll_error=0;control_sequence=0;
    pwif.started=1;CHECK(!polaris_wifi_mailbox_attach(&pwif.identity));
}
static int turn(void)
{pwif.worker_active=1;int result=pwif_turn();pwif.worker_active=0;CHECK(!mock_locked);return result;}
static void event(unsigned kind)
{
    struct pwmb_message*m=&incoming[PWMB_EVENT];memset(m,0,sizeof(*m));m->bytes=16;m->operation=PWMB_NOTIFY;
    pwmb_put32(m->data,kind);if(kind==3)pwmb_put64(m->data+8,1);available[PWMB_EVENT]=1;
}
static mbuf_t packet(unsigned length,unsigned seed)
{
    mbuf_t m=calloc(1,sizeof(*m));CHECK(m&&length<=sizeof(m->data));m->bytes=length;
    for(unsigned n=0;n<length;n++)m->data[n]=(uint8_t)(seed+n);return m;
}
static int ioctl_record(unsigned command,uint8_t*r)
{
    struct ifdrv64 request={.ifd_cmd=PWIF_COMMAND,.ifd_len=PWIF_BYTES,.ifd_data=(uintptr_t)r};
    return pwif_ioctl(&mock_interface,command,&request);
}
static void request(uint8_t*r,unsigned op)
{memset(r,0,PWIF_BYTES);pwmb_put32(r,PWIF_VERSION);pwmb_put32(r+4,op);}
static void reply(unsigned operation,unsigned bytes)
{
    struct pwmb_message*m=&incoming[PWMB_REPLY];memset(m,0,sizeof(*m));m->bytes=bytes;m->operation=PWMB_RESPONSE;
    pwmb_put64(m->data,control_sequence);pwmb_put32(m->data+8,operation);available[PWMB_REPLY]=1;
}
int main(void)
{
    setup();pwif.started=0;CHECK(!polaris_wifi_interface_seal()&&!mailbox_sealed);
    mock_platform=0;polaris_wifi_interface_start();CHECK(!mock_threads&&!pwif.started);
    mock_platform=1;mock_gate=0;polaris_wifi_interface_start();CHECK(!mock_threads);
    mock_gate=1;polaris_wifi_interface_start();polaris_wifi_interface_start();CHECK(mock_threads==1&&pwif.started);
    CHECK(!turn()&&!mock_attach&&!pwif.interface);event(1);CHECK(!turn()&&mock_attach==1&&pwif.radio&&!pwif.link&&!mock_events);
    CHECK(pwif_output(&mock_interface,packet(100,0))==ENETDOWN&&mock_freed==1&&!pwif.count);
    event(3);CHECK(!turn()&&pwif.link&&mock_event_last==KEV_DL_LINK_ON);
    for(unsigned n=0;n<PWIF_QUEUE;n++)CHECK(!pwif_output(&mock_interface,packet(100,n)));
    CHECK(pwif_output(&mock_interface,packet(100,0))==ENOBUFS&&pwif.count==PWIF_QUEUE);
    mailbox_tx_busy=1;CHECK(!turn()&&pwif.count==PWIF_QUEUE&&!mailbox_tx);
    mailbox_tx_busy=0;
    for(unsigned n=0;n<PWIF_QUEUE;n++){CHECK(!turn()&&sent_bytes==100&&sent[0]==n&&sent[99]==(uint8_t)(99+n));}
    CHECK(!pwif.count&&pwif.sent==PWIF_QUEUE&&mock_stat_sent==PWIF_QUEUE);
    CHECK(pwif_output(&mock_interface,packet(1515,0))==EMSGSIZE);
    mock_copy_failure=1;CHECK(pwif_output(&mock_interface,packet(100,0))==EFAULT&&!pwif.count);mock_copy_failure=0;
    struct pwmb_message*m=&incoming[PWMB_RX];m->bytes=100;m->operation=PWMB_ETHERNET_RX;
    for(unsigned n=0;n<100;n++)m->data[n]=(uint8_t)n;
    available[PWMB_RX]=1;CHECK(!turn()&&mock_inputs==1&&mock_input_bytes==86&&mock_input[0]==14&&pwif.received==1);
    mock_alloc_failure=1;available[PWMB_RX]=1;CHECK(!turn()&&pwif.rx_drops==1);mock_alloc_failure=0;
    mock_copy_failure=1;available[PWMB_RX]=1;CHECK(!turn()&&pwif.rx_drops==2);mock_copy_failure=0;
    mock_kernel_error=EIO;available[PWMB_RX]=1;CHECK(!turn()&&pwif.rx_drops==3);mock_kernel_error=0;
    uint8_t record[PWIF_BYTES];request(record,PWMB_SCAN);mock_superuser=0;
    CHECK(ioctl_record(SIOCSDRVSPEC64,record)==EPERM&&!pwif.pending);
    CHECK(ioctl_record(SIOCGDRVSPEC64,record)==EPERM);mock_superuser=1;
    record[22]=1;CHECK(ioctl_record(SIOCSDRVSPEC64,record)==EINVAL);record[22]=0;
    CHECK(!ioctl_record(SIOCSDRVSPEC64,record)&&pwif.pending&&pwif.request==1&&!pwif.submitted);
    CHECK(ioctl_record(SIOCSDRVSPEC64,record)==EBUSY);mailbox_control_busy=1;
    CHECK(!turn()&&pwif.pending&&!pwif.submitted&&!mailbox_control);mailbox_control_busy=0;
    CHECK(!turn()&&pwif.submitted&&mailbox_control==1&&!pwif.completed);
    CHECK(!ioctl_record(SIOCGDRVSPEC64,record)&&pwmb_u64(record+16)==1&&!pwmb_u64(record+24));
    reply(PWMB_SCAN,16);CHECK(!turn()&&!pwif.pending&&pwif.completed==1);
    CHECK(!ioctl_record(SIOCGDRVSPEC64,record)&&pwmb_u32(record+12)==16&&pwmb_u64(record+24)==1);
    request(record,PWMB_JOIN);pwmb_put32(record+8,112);uint8_t*j=record+64;
    pwmb_put32(j,2);j[4]=4;j[5]=8;j[6]=1;memcpy(j+16,"test",4);memcpy(j+48,"password",8);
    CHECK(!ioctl_record(SIOCSDRVSPEC64,record)&&!memcmp(pwif.control+48,"password",8));
    CHECK(!turn()&&pwif.submitted&&pwmb_zero(pwif.control,sizeof(pwif.control))&&!memcmp(control_copy+48,"password",8));
    CHECK(!ioctl_record(SIOCGDRVSPEC64,record)&&pwmb_zero(record+64,PWMB_DATA));
    reply(PWMB_JOIN,17);CHECK(turn()==EIO&&pwif.completed==1&&pwif.pending&&pwif.response_bytes==0);
    CHECK(!polaris_wifi_interface_seal()&&pwif.sealed&&!pwif.link&&mock_event_last==KEV_DL_LINK_OFF);
    CHECK(pwif_output(&mock_interface,packet(100,0))==ENETDOWN);
    request(record,PWMB_STATE);CHECK(ioctl_record(SIOCSDRVSPEC64,record)==ENXIO);
    setup();event(1);CHECK(!turn());event(3);mailbox_hook_seal=1;
    CHECK(turn()==ENXIO&&pwif.sealed&&!pwif.link&&!mock_events);
    CHECK(!polaris_wifi_interface_seal());
    setup();event(1);CHECK(!turn());event(3);CHECK(!turn());
    CHECK(!pwif_output(&mock_interface,packet(100,0)));pwif.worker_active=1;
    CHECK(polaris_wifi_interface_seal()==EBUSY&&pwif.sealed&&pwif.count==1&&pwif.link);
    pwif.worker_active=0;mailbox_seal_busy=1;CHECK(polaris_wifi_interface_seal()==EBUSY&&!pwif.count&&!pwif.link);
    mailbox_seal_busy=0;CHECK(!polaris_wifi_interface_seal()&&pwmb_zero(pwif.frames,sizeof(pwif.frames)));
    setup();event(1);mock_alloc_failure=1;CHECK(turn()==ENOMEM&&!pwif.interface);mock_alloc_failure=0;
    setup();event(1);CHECK(!turn());mailbox_poll_error=1;CHECK(turn()==EIO);
    setup();event(1);CHECK(!turn());event(3);CHECK(!turn());
    CHECK(!pwif_output(&mock_interface,packet(100,0)));event(4);
    CHECK(!turn()&&!pwif.count&&!pwif.link&&pwif.tx_drops==1&&pwmb_zero(pwif.frames,sizeof(pwif.frames)));
    event(3);CHECK(!turn()&&!mailbox_tx);
    setup();event(1);CHECK(!turn());mock_shutdown=1;
    request(record,PWMB_JOIN);CHECK(ioctl_record(SIOCSDRVSPEC64,record)==EINVAL);
    request(record,PWMB_STATE);CHECK(ioctl_record(SIOCSDRVSPEC64,record)==ENXIO);
    for(unsigned length=16;length<=17;length++){
        setup();event(1);CHECK(!turn());request(record,PWMB_POWER_OFF);
        mock_superuser=0;CHECK(ioctl_record(SIOCSDRVSPEC64,record)==EPERM&&!pwif.pending);mock_superuser=1;
        CHECK(!ioctl_record(SIOCSDRVSPEC64,record)&&pwif.pending);
        CHECK(!turn()&&pwif.submitted&&pwif.control_operation==PWMB_POWER_OFF);
        reply(PWMB_POWER_OFF,length);CHECK(turn()==(length==16?0:EIO));
        CHECK(pwif.completed==(length==16?1u:0u));
    }
    printf("PASS %u actual BSD interface checks; SOFTWARE KPI/mailbox, no phone or IP success\n",checks);return 0;
}
