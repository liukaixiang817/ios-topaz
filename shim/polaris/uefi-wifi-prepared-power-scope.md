# Prepared ARC data in the conditional APPS DRV2 experiment

This new scope combines the complete0161 RO preparation with the existing
conditional APPS DRV2 experiment reviewed in `uefi-wifi-power-scope.md`.
It does not extend that trusted original boot/platform assumption into an
EL3/VMID/MPU grant, MSS startup, shared DMA or radio permission. Its actual
runtime cache/TCS/CPU/Device prerequisites remain mandatory; no document,
preparation flag, private handle or host boolean grants a raw store.

`--wifi-power-prepared-transaction` is default OFF, requires full staged RO
and rejects the capture-only label. Four independently retired64KiB RO phases
precede any private client. The final Clock/GCD ticket stays unopened. Only a
complete actual preparation may enter one newly opened original known-client
interval. It never adopts a preparation context, resets a spent ticket or
renews either original200ms deadline. Old capture and work-admission scopes
are preserved separately.

The same private interval creates one original no-explicit DRV2 client and
revalidates current CmdDb registration, its actual loaded owner, five source
hashes, full relocated protocol table and globals. A new complete two-pass
current Core namespace admits the entire header and three selected entry/aux
ranges. Each page's selected loads immediately follow the original complete
source/head/lock/node/NS-WB AT/PAR guard. Two complete selected captures must
match the prepared bytes and the existing ARC decoder output. These are
current observations, not invented original Query statuses. No CmdDb Query
or original DB descriptor getter executes.

The existing complete provider RAM/cache/perDRV72/pool/mode/TCS/queues/HAL
and registered Device R/W mapping checks then run. Missing saved active
votes remain a refusal, never zero. The existing fourteen normal/masked
PSCI checks, literal native CPU_ON flag, source/owner/TPL/FP checks and exact
local masking remain. No original service/SMC/dispatch runs during active RSC.
The original conditional APPS-bank concurrency argument and its limits are
unchanged; secure assignment or rail-off is not inferred from PSCI/AT/masks.

Crucially, this change does NOT remove the masked full database checks:
all128KiB are read and compared to the complete prepared data immediately
before first RSC store and after complete engine retirement. Each page now
also retains explicit NS/WB AT issue/return, raw PAR and actual saved/readback
restoration. A changed byte anywhere, including an unselected entry or
padding, blocks a store/retirement. No earlier selected-byte success replaces
those full comparisons.

The existing bounded engine preserves dynamic ACTIVE TCS choice, raised
`max(saved,index)` CX/MX/MSS votes, new IRQ/all-three-DONE/idle confirmation,
reverse saved-vote restoration, append-only prefix and full touched-RW
readbacks. IRQ enable/type remain unchanged. No original blocking submission,
RET lock, retry, unknown cleanup, commandset fallback or threshold/PLL write
is added. Full provider RAM must remain identical; immutable sources precede
exact CPU restoration. After the final original Device/GCD services, another
selected-byte/source/namespace closure precedes known Delete. Admission and
closure timestamps remain separate raw observations. Clean pre-mask refusals
also close current CmdDb and revalidate full pool/client/source before Delete.
Any partial/UNKNOWN/held local mask reaches the existing nonreturn RAM-only
quarantine and cannot return to USB/Console/Stall/native/PON/receipt.

Complete raw records are exported under distinct STAGED_RO_RAW_V1,
POWER_CLIENT_RAW_V1 and PREPARED_POWER_RAW_V1 labels. The legacy CmdDb record
inside the new body remains wholly unused/zero, not a fake full capture.
The new body is1892336B, current binding233520B and checked access401800B;
preparation1660544B and client227104B remain complete. Firmware log12MiB and
bound host snapshot16MiB+128 preserve all records; default/old8MiB host scope
and historical profiles are unchanged. Log capacity only bounds upload after
exact image/source admission; it cannot authorize a boot, scope or command.

The new exact compiled source/profile, full EFI/parent checks, two serial
whole EFI/XNU terminal models, original81 whole codec, current root/NV and
normal previous retirement, independent freeze and ONE helper are required
before an actual attempt. Software success is not physical completion.
Actual hardware predicates may decline; rejection never enables a weaker
scope or replay. Wi-Fi scan/join/data, sound and camera remain unfinished.
