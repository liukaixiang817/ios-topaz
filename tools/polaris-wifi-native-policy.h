/* Native read-only Wi-Fi probe admission. No operation or hardware address is
 * accepted from a host pointer. DT enable alone is never MPU/read permission. */
#ifndef POLARIS_WIFI_NATIVE_POLICY_H
#define POLARIS_WIFI_NATIVE_POLICY_H
#include <stdint.h>
#include <stdbool.h>
enum polaris_wifi_native_error {
    PWN_OK, PWN_BAD_DT, PWN_BAD_BOOT_MODE, PWN_BAD_BOARD, PWN_DRAINING,
    PWN_BAD_CPU, PWN_MPU_READ_UNKNOWN, PWN_MAPPING_FAILED, PWN_TRANSLATION,
    PWN_UNSAFE_READ, PWN_ALLOCATION, PWN_PROBE_FAILED
};
struct polaris_wifi_native_admission {
    uint32_t version,enable,uefi,el;
    uint64_t frequency;
    bool board,overlay,root,draining,independent_mpu_read;
};
static inline unsigned polaris_wifi_native_admit(const struct polaris_wifi_native_admission *a)
{
    if(!a||a->version!=1||a->enable!=1)return PWN_BAD_DT;
    if(a->uefi!=1)return PWN_BAD_BOOT_MODE;
    if(!a->board)return PWN_BAD_BOARD;
    if(a->draining)return PWN_DRAINING;
    if(a->el!=4||a->frequency!=19200000)return PWN_BAD_CPU;
    if(!a->root||!a->overlay)return PWN_BAD_BOOT_MODE;
    if(!a->independent_mpu_read)return PWN_MPU_READ_UNKNOWN;
    return PWN_OK;
}
#endif
