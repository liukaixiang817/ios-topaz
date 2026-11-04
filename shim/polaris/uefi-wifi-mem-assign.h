/* Unconnected default-OFF one-round SCM64 leaf. The real parent must own and
 * retain all buffers, perform cache maintenance, serialize secure calls and
 * preserve UNKNOWN before this leaf can be wired. No setup, loop or cleanup. */
#ifndef POLARIS_UEFI_WIFI_MEM_ASSIGN_H
#define POLARIS_UEFI_WIFI_MEM_ASSIGN_H
#ifndef EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE
#define EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE && defined(__aarch64__) && !defined(POLARIS_EFI_TEST_QEMU)
#include "../../tools/polaris-wifi-mem-assign.h"
static inline void pwma_actual_round(struct pwma_registers*raw)
{
    register uint64_t x0 __asm__("x0")=raw->x[0];register uint64_t x1 __asm__("x1")=raw->x[1];
    register uint64_t x2 __asm__("x2")=raw->x[2];register uint64_t x3 __asm__("x3")=raw->x[3];
    register uint64_t x4 __asm__("x4")=raw->x[4];register uint64_t x5 __asm__("x5")=raw->x[5];
    register uint64_t x6 __asm__("x6")=raw->x[6];
    __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3),"+r"(x4),"+r"(x5),"+r"(x6)::
        "x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    raw->x[0]=x0;raw->x[1]=x1;raw->x[2]=x2;raw->x[3]=x3;raw->x[4]=x4;raw->x[5]=x5;raw->x[6]=x6;
}
#endif
#endif
