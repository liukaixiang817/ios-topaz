/* QCOM peripheral ABI: HackiOS d82c64a3 xnuloader/efi.h (MIT attribution in
 * userland/gpu/LICENSE.hackios), checked against this phone's UsbDeviceDxe
 * 267f404d40a513b7...: table0x90e0 revision0x10000001, StartEx at offset72.
 * No block I/O or NVRAM interface is exposed to the diagnostic service. */
#ifndef POLARIS_UEFI_USB_H
#define POLARIS_UEFI_USB_H
#include "uefi.h"
union polaris_usb_event {
    uint32_t state;
    struct {uint32_t status;uint8_t endpoint;uint64_t bytes;void *buffer;} transfer;
    uint64_t raw[8];
};
struct polaris_usb_descriptors {
    const void *device;const void **configs;const void *ss_device;const void **ss_configs;
    const void *qualifier,*bos;uint8_t string_count;const void **strings;
};
struct polaris_usb_protocol {
    uint64_t revision;void *start;
    efi_status (*send)(uint8_t,uint64_t,void *);
    efi_status (*event)(uint32_t *,uint64_t *,union polaris_usb_event *);
    efi_status (*allocate)(uint64_t,void **);
    efi_status (*free)(void *);
    efi_status (*stop)(void);
    efi_status (*abort)(uint8_t);
    efi_status (*stall_endpoint)(uint8_t,uint8_t);
    efi_status (*start_ex)(struct polaris_usb_descriptors *);
};
struct polaris_gop_info {uint32_t version,width,height,format,masks[4],stride;};
struct polaris_gop_mode {uint32_t max_mode,mode;struct polaris_gop_info *info;uint64_t info_bytes,base,bytes;};
struct polaris_gop {
    void *query,*set;
    efi_status (*blt)(struct polaris_gop *,void *,uint32_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
    struct polaris_gop_mode *mode;
};
struct polaris_usb_diag {
    void *context;
    int (*transmit)(void *,const uint8_t *,uint64_t);
    int (*stage)(void *,unsigned,const uint8_t **,uint64_t *);
    const uint8_t *staged;uint64_t staged_bytes;
};
/* Command parsing is shared by the native host test and the real EFI driver. */
int polaris_usb_command(struct polaris_usb_diag *,const uint8_t *,uint64_t);
int polaris_usb_ppm(const struct polaris_gop_mode *,uint8_t *,uint64_t,uint64_t *);
efi_status polaris_efi_usb_serve(struct efi_system *,const uint8_t *,const uint64_t *,
                                const uint8_t *,uint64_t,void (*)(const char *,uint64_t));
_Static_assert(sizeof(struct polaris_usb_protocol)==80,"QCOM USB method table");
_Static_assert(offsetof(struct polaris_usb_protocol,start_ex)==72,"QCOM StartEx");
_Static_assert(sizeof(struct polaris_usb_descriptors)==64,"QCOM descriptor set");
_Static_assert(sizeof(union polaris_usb_event)==64,"QCOM event payload");
_Static_assert(offsetof(union polaris_usb_event,transfer.bytes)==8,"QCOM completion length");
_Static_assert(offsetof(union polaris_usb_event,transfer.buffer)==16,"QCOM completion buffer");
#endif
