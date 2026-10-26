/* Emulator harness only, NEVER embedded in the phone's inventory driver.
 * Exercise the real driver at its actual EFI callback/TPL and call ABI.
 * This models the QCOM protocol API, not a physical USB controller/PHY. */
#include "uefi-usb.h"
static struct efi_system *mock_st;
static int mock_init,mock_connected,mock_rx,mock_tx,mock_command,mock_uploads,mock_rejected,mock_cancelled;
static uint8_t *mock_receive;static uint64_t mock_receive_size,mock_tx_bytes;
static void *mock_tx_buffer;static unsigned mock_selected;static uint64_t mock_remaining;
static int mock_data_phase,mock_first;
static const char *mock_commands[]={"getvar:product","oem logs","upload","oem memmap","upload",
                                    "oem screenshot","upload","flash:boot","download:00000010"};
static void mock_print(const char *s)
{
    while(*s){
        uint16_t b[128];unsigned n=0;while(*s && n<127)b[n++]=(uint8_t)*s++;
        b[n]=0;mock_st->out->string(mock_st->out,b);
    }
}
static void mock_fail(const char *s)
{
    mock_print("USB_MOCK_FAIL: ");mock_print(s);mock_print("\r\n");
    for(;;)mock_st->boot->stall(1000000);
}
static int mock_equal(const uint8_t *data,uint64_t bytes,const char *s)
{
    unsigned n=0;while(s[n])n++;if(bytes!=n)return 0;
    for(unsigned i=0;i<n;i++)if(data[i]!=(uint8_t)s[i])return 0;return 1;
}
static void mock_notify(void *e,void *c){(void)e;(void)c;mock_init=1;}
static efi_status mock_start(struct polaris_usb_descriptors *d)
{
    if(!mock_init || !d || d->string_count!=4 || ((const uint8_t*)d->device)[0]!=18)
        mock_fail("init event/descriptor layout");
    return 0;
}
static efi_status mock_alloc(uint64_t n,void **p){return mock_st->boot->allocate_pool(2,n,p);}
static efi_status mock_free(void *p){return mock_st->boot->free_pool(p);}
static efi_status mock_stop(void){return 0;}
static efi_status mock_abort(uint8_t ep){(void)ep;return 0;}
static efi_status mock_send(uint8_t ep,uint64_t bytes,void *buffer)
{
    if(!buffer || !bytes || bytes>65536)mock_fail("invalid transfer bound");
    if(ep==1){mock_rx=1;mock_receive=buffer;mock_receive_size=bytes;return 0;}
    if(ep!=0x81 || mock_tx)mock_fail("endpoint/overlapping transfer");
    const uint8_t *p=buffer;
    if(mock_data_phase){
        if(bytes>mock_remaining)mock_fail("upload exceeds declared length");
        if(mock_first){
            if(mock_selected==1 && (bytes<7 || p[0]!='P' || p[1]!='O'))mock_fail("RAM log prefix");
            if(mock_selected==2 && (bytes<32 || p[0]!='P' || p[1]!='E' || p[2]!='F'))mock_fail("EFI map prefix");
            if(mock_selected==3 && (bytes<11 || p[0]!='P' || p[1]!='6' || p[2]!='\n'))mock_fail("GOP PPM prefix");
            mock_first=0;
        }
        mock_remaining-=bytes;if(!mock_remaining)mock_data_phase=0;
    }else if(bytes==12 && p[0]=='D' && p[1]=='A' && p[2]=='T' && p[3]=='A'){
        if(mock_remaining)mock_fail("overlapping DATA phase");
        for(unsigned i=4;i<12;i++){
            unsigned v=p[i]>='0' && p[i]<='9'?p[i]-'0':p[i]>='a' && p[i]<='f'?p[i]-'a'+10:255;
            if(v>15)mock_fail("invalid DATA length");mock_remaining=mock_remaining*16+v;
        }
        if(!mock_remaining || mock_remaining>16*1024*1024)mock_fail("DATA bound");
        mock_data_phase=mock_first=1;
    }else if(mock_equal(p,bytes,"OKAY")){
        if(mock_command==2)mock_selected=1;
        else if(mock_command==4)mock_selected=2;
        else if(mock_command==6)mock_selected=3;
        else if(mock_command==3 || mock_command==5 || mock_command==7){
            if(mock_remaining || mock_data_phase)mock_fail("early upload success");mock_uploads++;
        }else mock_fail("unexpected empty success");
    }else if(mock_command==1 && mock_equal(p,bytes,"OKAYpolaris-uefi-diag")){
    }else if(mock_command>=8 && bytes>=4 && p[0]=='F' && p[1]=='A' && p[2]=='I' && p[3]=='L')mock_rejected++;
    else mock_fail("unexpected response");
    mock_tx=1;mock_tx_buffer=buffer;mock_tx_bytes=bytes;return 0;
}
static efi_status mock_event(uint32_t *kind,uint64_t *size,union polaris_usb_event *data)
{
    if(*size<sizeof(*data))return EFI_TOO_SMALL;*kind=0;
    if(!mock_connected){*kind=1;data->state=0;mock_connected=1;return 0;}
    if(mock_tx){*kind=2;data->transfer.status=1;data->transfer.endpoint=0x81;
        data->transfer.bytes=mock_tx_bytes;data->transfer.buffer=mock_tx_buffer;mock_tx=0;return 0;}
    if(mock_rx){
        if(!mock_cancelled){
            mock_cancelled=1;mock_rx=0;*kind=2;data->transfer.status=2;
            data->transfer.endpoint=1;data->transfer.bytes=0;data->transfer.buffer=mock_receive;return 0;
        }
        if(mock_command>=9)mock_fail("extra command read");const char *s=mock_commands[mock_command++];
        mock_print("USB_MOCK_COMMAND ");mock_print(s);mock_print("\r\n");
        uint64_t n=0;while(s[n]){if(n>=mock_receive_size)mock_fail("RX capacity");mock_receive[n]=(uint8_t)s[n];n++;}
        *kind=2;data->transfer.status=1;data->transfer.endpoint=1;data->transfer.bytes=n;
        data->transfer.buffer=mock_receive;mock_rx=0;return 0;
    }
    if(mock_command==9){
        if(mock_uploads!=3 || mock_rejected!=2 || !mock_init || !mock_cancelled)mock_fail("incomplete host script");
        mock_print("USB_MOCK_UPLOADS=0x0000000000000003\r\nUSB_MOCK_WRITE_REJECTIONS=0x0000000000000002\r\nUSB_MOCK_CANCEL_RECOVERY=0x0000000000000001\r\nUSB_MOCK_PASS\r\n");
        for(;;)mock_st->boot->stall(1000000);
    }
    return EFI_ERROR|6;
}
static void mock_install(struct efi_system *st)
{
    mock_st=st;
    static const efi_guid guid={0xd9d9ce48,0x44b8,0x4f49,{0x8e,0x3e,0x2a,0x3b,0x92,0x7d,0xc6,0xc1}};
    static const efi_guid init={0x1c0cffce,0xfc8d,0x4e44,{0x8c,0x78,0x9c,0x9e,0x5b,0x53,0x0d,0x36}};
    static struct polaris_usb_protocol protocol={0x10000001,0,mock_send,mock_event,mock_alloc,mock_free,
                                               mock_stop,mock_abort,0,mock_start};
    efi_handle handle=0;void *event=0;
    if(st->boot->install_protocol(&handle,&guid,0,&protocol)&EFI_ERROR)mock_fail("InstallProtocolInterface");
    if(st->boot->create_event_ex(0x200,8,mock_notify,0,&init,&event)&EFI_ERROR)mock_fail("init event registration");
}
