/* Generic-EDK2 test harness: LoadImage/StartImage the real boot-service driver,
 * then signal the same ReadyToBoot event group used by the phone's BDS. The
 * driver must finish its inventory and hold. No device/variable/file writes. */
#include "uefi.h"
#include "probe-driver.inc"
#ifdef POLARIS_EFI_USB_MOCK
#include "uefi-usb-mock.inc"
#endif
static void unused(void *event,void *context){(void)event;(void)context;}
efi_status EfiMain(efi_handle image,struct efi_system *st)
{
    static const efi_guid group={0x7ce88fb3,0x4bd7,0x4679,{0x87,0xa8,0xa8,0xd8,0xde,0xe5,0x0d,0x2b}};
    if(!st || !st->boot || st->boot->hdr.size<376)return EFI_ERROR|2;
#ifdef POLARIS_EFI_USB_MOCK
    mock_install(st);
#endif
    efi_handle driver=0;uint64_t bytes=0;
    efi_status s=st->boot->load_image(0,image,0,driver_bytes,sizeof(driver_bytes),&driver);
    if(s&EFI_ERROR)return s;
    s=st->boot->start_image(driver,&bytes,0);
    if(s&EFI_ERROR)return s;
    void *event=0;
    s=st->boot->create_event_ex(0x200,8,unused,0,&group,&event);
    if(s&EFI_ERROR)return s;
    st->boot->signal_event(event);
    return EFI_ERROR|7; /* The hold driver must not return. */
}
