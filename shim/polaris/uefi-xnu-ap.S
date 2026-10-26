/* Started by PSCI on the one explicitly admitted non-firmware core.
 * No firmware calls execute under the kernel's16KiB translation regime.
 * x0=physical context, MMU/caches off. Addresses are runtime-relocated PE VAs
 * which the admission check must prove are identity mapped. */
 .text
 .p2align 6
 .globl polaris_efi_ap_entry
polaris_efi_ap_entry:
 msr daifset,#15
 mov x19,x0
 mrs x9,CurrentEL
 cmp x9,#4
 b.ne ap_bad_el
 ldr x9,[x19,#32]
 mov sp,x9
 adr x9,ap_vectors
 msr vbar_el1,x9
 ldr x9,[x19,#24]
 msr cpacr_el1,x9
 ldr x9,[x19,#16]
 bic x9,x9,#1
 bic x9,x9,#4
 bic x9,x9,#0x1000
 msr sctlr_el1,x9
 isb
 mrs x9,mpidr_el1
 str x9,[x19,#72]
 mov x9,#1
 str x9,[x19,#40]
 dsb sy
 ldp x9,x0,[x19]
 br x9
ap_bad_el:
 str x9,[x19,#48]
 mov x9,#3
 str x9,[x19,#40]
 dsb sy
 b ap_wait
ap_fault:
 adrp x19,polaris_efi_ap_state
 add x19,x19,:lo12:polaris_efi_ap_state
 mrs x9,esr_el1
 str x9,[x19,#48]
 mrs x9,elr_el1
 str x9,[x19,#56]
 mrs x9,far_el1
 str x9,[x19,#64]
 mov x9,#2
 str x9,[x19,#40]
 dsb sy
ap_wait:
 wfe
 b ap_wait
 .p2align 11
ap_vectors:
 .rept 16
 b ap_fault
 .p2align 7
 .endr
