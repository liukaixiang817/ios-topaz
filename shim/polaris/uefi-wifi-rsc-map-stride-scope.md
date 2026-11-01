# 0166: honor the actual EFI map descriptor stride

Actual0165 completed the new preparation/private body, then refused before
the first Device GCD getter. Its frozen 1941984-byte body records DEVICE/MAP,
unknown=0, retired=1 and known_refusal=1. Original known Delete returned.
The complete CPU, READ, WRITE and checked-access records are zero; no Device
AT or register load was issued. This is a safe refusal, not a READ result.

The same captured private GetMemoryMap records both return DescriptorSize48,
2880 bytes, with the known EFI descriptor prefix occupying40 bytes. Replaying
only the pure map exclusion predicate against these actual bytes reproduces
the refusal at `stride != sizeof(struct efi_memory)`. None of the descriptors
overlaps the three RSC pages. Absence is exclusion only, never MMIO permission.
This does not explain any older missing ACK or unexpected0164 exit.

The fix reuses `polaris_efi_memory_check`, the existing complete bounded map
validator. It accepts the firmware's aligned descriptor stride, checks complete
map bounds, nonzero/aligned page ranges, overflow and disjointness, then walks
only the known prefix at each stride. Opaque padding is preserved and is not
interpreted as an additional descriptor. Existing overlap rules still reject
RAM/reserved/unknown ownership, virtual aliases and unsupported attributes.
Registered GCD Device UC descriptors and fresh exact NS Device R/W translations
are still mandatory after exclusion. No allocation, mapping or permission is
introduced by the map validator.

The capture-only READ scope, 200 ms private deadline, 50 ms/256 steps/1024
events, full raw, source/namespace/CPU gates, exact touchedRW restoration and
UNKNOWN quarantine are unchanged. Resource WRITE remains compiled out. No
original submit/internal entry, cleanup fallback or replacement policy is used.
The new exact source/profile is distinct; old0165 manifests and consumed boot
record remain immutable. Software checks include nonzero stride48 padding in
the complete READ/restore/Delete path and malformed/overlapping maps. They do
not prove a physical READ, hardware ownership or networking.
