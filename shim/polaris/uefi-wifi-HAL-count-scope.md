# Original HAL configured count and logical DRV binding

This scope retains the complete prepared/current/private bounded power path,
all runtime predicates and the full10MiB raw log from the prepared power/FFS
scopes. It corrects a field interpretation; it does not relax admission.

Actual0163 completed four independent full namespace/DB preparations, current
private namespace plus three selected-byte passes and known Create/Delete.
The RAM reader returned PWRPB_SOURCE before any Device/CPU/RSC operation.
The complete actual HAL runtime header had count1; static d208+20 was ID2.
The old predicate incorrectly compared those two different fields. No rail
vote, critical mask, PSCI or RSC MMIO executed in that attempt. Its known
refusal retired normally and independent FASTBOOT was observed05:06:34Z.

Exact original RpmhDxe b718efb605db2c1d7be3b5e84d13adb148e24eebae66496e9569cfe9b34bfdc5
shows7284..7298 loading static header d238 and storing it to runtime d538+4.
Original70a0 uses that count as a loop limit, while each12B static row begins
with the logical ID used to index the24B runtime entries. Static d228 is the
logical ID of the current row, not a configured-row count. Display-only text
bytes were independently matched to the original PE .text; no firmware code
was run or patched for this audit. Actual source proof SHA256:
d05b22ceb2dcbaf01b6980d70772717395efa1b909b218e63cd9866eb4b00900.

The corrected predicate requires d238 count to equal the independently read
current root configuration count1, d228 logical ID to equal current drv_row
logical2, runtime d538+4 to equal that configured count, and the same unique
initialized logicalDRV2/base179c0000/bank2/8TCS/16cmd geometry. Wrong count2,
wrong static ID and changed count all refuse. No fixture copies the logical
ID into the runtime count anymore. Full chain success and safe refusal are
covered using original PE as DATA only. This is not physical power success.

The same current full cache/pool/mode/TCS/queues, actual GCD and NS R/W AT,
CPU0/seven-peer exclusion, original200ms, full masked128KiB comparisons,
checked bounded RSC completion and reverse saved restoration still precede
known Delete and final Clock/GCD. Missing active state is not zero. UNKNOWN
quarantine/no cleanup, complete raw, dynamic TCS and IRQ enable/type
preservation remain mandatory. This only attempts the existing conditional
trusted-boot APPSDRV2 scope; it does not infer secure EE/EL3/VMID/MPU authority.
Original blocking Submit, RET locks and fallback are forbidden. No MSS start,
remote NV service or scan/join/data claim is authorized by this field fix.
New source/profile/freeze are required; consumed0163 cannot be replayed.
