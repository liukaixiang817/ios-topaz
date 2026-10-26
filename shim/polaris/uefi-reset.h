#ifndef POLARIS_EFI_RESET_H
#define POLARIS_EFI_RESET_H
#include "uefi.h"

/* Original PM8998 PmicDxe: PON revision10001, GUID97044b58, vtable
 * Get/SetSpareReg at8/16 (no This). Verified against the phone's PE.
 * Qualcomm EFIPmicPon.h blob9f344ba6 and own qpnp-power-on.c agree on
 * SOFT_SPARE3 =0x88f. PM8998 is Gen2: reason occupies bits7:1.
 * See Linuxv6.12 drivers/power/reset/qcom-pon.c, pm8998-pon match.
 * This API exposes only one masked restart marker, never power controls. */
struct polaris_efi_pon {
    uint64_t revision;
    efi_status (*get)(uint32_t,uint32_t,uint8_t *);
    efi_status (*set)(uint32_t,uint32_t,uint8_t,uint8_t);
};
struct polaris_efi_reset_marker {uint8_t before,after;efi_status status,restore_status;};

static inline int polaris_efi_pon_marker(struct polaris_efi_pon *pon,unsigned mode,
                                        struct polaris_efi_reset_marker *result)
{
    if(!result)return 0;
    *result=(struct polaris_efi_reset_marker){0};
    if((mode!=1&&mode!=2)||!pon||pon->revision!=0x10001||!pon->get||!pon->set)return 0;
    uint8_t before=0,after=0,value=mode==2?0x04:0x44;
    result->status=pon->get(0,3,&before);result->before=before;
    if(result->status)return 0;
    result->status=pon->set(0,3,value,0xfe);
    if(!result->status)result->status=pon->get(0,3,&after);
    result->after=after;
    if(!result->status&&after==(uint8_t)((before&1)|value))return 1;
    /* A failed write/readback must not leave a different next-boot mode. */
    result->restore_status=pon->set(0,3,before,0xfe);
    if(!result->restore_status){
        uint8_t restored=0;result->restore_status=pon->get(0,3,&restored);
        if(!result->restore_status&&(restored&0xfe)!=(before&0xfe))result->restore_status=EFI_ERROR|7;
    }
    return 0;
}
#endif
