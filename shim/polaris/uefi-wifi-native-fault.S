/* Terminal CPU0 exception evidence, linked only by an explicit firmware-only
 * diagnostic. All sixteen 128-byte entries use an independent owned stack.
 * No exception return, firmware call, reset or hardware watchdog operation. */
#if !defined(POLARIS_WIFI_NATIVE_FAULT_VECTORS) || POLARIS_WIFI_NATIVE_FAULT_VECTORS != 1
#error Native fault vectors require the separate explicit diagnostic build
#endif
#if defined(__APPLE__)
#define PF_NAME_(n) _##n
#define PF_NAME(n) PF_NAME_(n)
#else
#define PF_NAME(n) n
#endif
 .text
 .p2align 11
 .globl PF_NAME(polaris_wifi_fault_vectors)
PF_NAME(polaris_wifi_fault_vectors):
 .macro PF_SLOT n
 b .Lpolaris_wifi_fault_\n
 .space 124
 .endm
 PF_SLOT 0
 PF_SLOT 1
 PF_SLOT 2
 PF_SLOT 3
 PF_SLOT 4
 PF_SLOT 5
 PF_SLOT 6
 PF_SLOT 7
 PF_SLOT 8
 PF_SLOT 9
 PF_SLOT 10
 PF_SLOT 11
 PF_SLOT 12
 PF_SLOT 13
 PF_SLOT 14
 PF_SLOT 15
 .globl PF_NAME(polaris_wifi_fault_vectors_end)
PF_NAME(polaris_wifi_fault_vectors_end):
 .macro PF_STUB n
.Lpolaris_wifi_fault_\n:
 mov x0,#\n
 b .Lpolaris_wifi_fault_common
 .endm
 PF_STUB 0
 PF_STUB 1
 PF_STUB 2
 PF_STUB 3
 PF_STUB 4
 PF_STUB 5
 PF_STUB 6
 PF_STUB 7
 PF_STUB 8
 PF_STUB 9
 PF_STUB 10
 PF_STUB 11
 PF_STUB 12
 PF_STUB 13
 PF_STUB 14
 PF_STUB 15
.Lpolaris_wifi_fault_common:
 msr daifset,#15
 msr ICC_IGRPEN1_EL1,xzr
 dsb sy
 isb
 mrs x1,esr_el1
 mrs x2,elr_el1
 mrs x3,far_el1
 mrs x4,spsr_el1
 mov x5,sp
 mrs x6,sp_el0
 mrs x7,cntvct_el0
#if defined(__APPLE__)
 adrp x16,PF_NAME(polaris_wifi_fault_stack)@PAGE
 add x16,x16,PF_NAME(polaris_wifi_fault_stack)@PAGEOFF
#else
 adrp x16,PF_NAME(polaris_wifi_fault_stack)
 add x16,x16,:lo12:PF_NAME(polaris_wifi_fault_stack)
#endif
 add x16,x16,#4,lsl #12
 mov sp,x16
 b PF_NAME(polaris_wifi_fault_hold)
 .globl PF_NAME(polaris_wifi_fault_code_end)
PF_NAME(polaris_wifi_fault_code_end):
