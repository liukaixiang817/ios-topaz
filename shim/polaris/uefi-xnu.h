/* RAM-only EFI/XNU handoff; code, stack and firmware allocations stay outside
 * the explicitly claimed XNU bank. USB stays on firmware CPU0. */
#ifndef POLARIS_UEFI_XNU_H
#define POLARIS_UEFI_XNU_H
#include "uefi-usb.h"
#include "payload.h"
struct polaris_efi_ap {
    uint64_t entry,args,sctlr,cpacr,stack,stage,fault_esr,fault_elr,fault_far,mpidr;
};
extern void polaris_efi_ap_entry(void);
uint32_t polaris_efi_crc32(const uint8_t *,uint64_t);
#endif
