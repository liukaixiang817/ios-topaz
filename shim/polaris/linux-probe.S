/* Run before the known recovery kernel, then resume its original entry.
 * Linux boot inputs x0..x3 and incoming SP are preserved. No MMIO.
 */
.section .text.head, "ax"
.global linux_probe_entry
linux_probe_entry:
    mov x9, sp
    adr x10, linux_probe_stack_end
    mov sp, x10
    stp x0, x1, [sp, #-48]!
    stp x2, x3, [sp, #16]
    str x9, [sp, #32]
    bl linux_probe_record
    ldp x0, x1, [sp]
    ldp x2, x3, [sp, #16]
    ldr x9, [sp, #32]
    mov sp, x9
.global linux_probe_resume
linux_probe_resume:
    b . /* Patched by the builder to the original kernel branch target. */
.section .stack, "aw", %nobits
.balign 16
    .space 8192
linux_probe_stack_end:
