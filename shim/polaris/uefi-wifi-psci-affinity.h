/* Shared fixed AFFINITY_INFO64 primitive. Only logical-state observation;
 * no CPU_ON/OFF, lease, mask, firmware protocol or resource write. */
#ifndef POLARIS_UEFI_WIFI_PSCI_AFFINITY_H
#define POLARIS_UEFI_WIFI_PSCI_AFFINITY_H
static inline int pwrpc_actual_affinity(void *ctx,uint64_t target,int64_t *raw)
{
    (void)ctx;
#if defined(__aarch64__) || defined(__arm64__)
    register uint64_t x0 __asm__("x0")=UINT64_C(0xc4000004),x1 __asm__("x1")=target,x2 __asm__("x2")=0,x3 __asm__("x3")=0;
    __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::"x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");*raw=(int64_t)x0;return 1;
#else
    (void)target;(void)raw;return 0;
#endif
}
#endif
