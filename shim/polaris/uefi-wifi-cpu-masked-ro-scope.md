# 0170: fresh CPU-local masked observations and exact restoration

0169 physically completed normal-IRQ AFFINITY_INFO64 for all seven own-DT
peer MPIDRs, full source/FP/TPL/map retirement and normal native shutdown.
It does not establish masked CPU state or explain the older opaque failures.
This new scope isolates the remaining CPU-local transition, without entering
any private RPMh client, TCS, RSC READ/vote, rail, MSS or remote-NV operation.
It cannot make Wi-Fi available and does not claim a hardware lease.

The default-OFF --wifi-cpu-masked-ro-admission requires the independent
--wifi-cpu-ro-admission scope, excluding all inventory/private/READ flags.
One fresh resident context and spent-once ticket cover both rounds and exact
restoration, within the original 200ms freshness limit. No old ticket or
past OFF observation is borrowed, reset, rebased or renewed. The final
Clock/GCD ticket remains unopened and byte-for-byte unchanged throughout.

All seven normal calls retain the original DAIF0/Group1-on service guard,
full immediate Core identity, FP/architecture/TPL/native-flag checks. If a
fully returned normal round observes a non-OFF state, the masked round is
not attempted; the independent RO lifecycle still requires its full close.
A completed all-OFF normal round only admits this diagnostic local mask.

The original pwrpc typed transition functions and raw layouts are extracted
without semantic changes into uefi-wifi-cpu-local-mask.h. DAIF I/F is set to
0xc0, then Group1 to zero, with barriers and actual readback of both. Held
and unknown are recorded before delivery. Partial or uncertain transitions
never initiate cleanup or return to original firmware services.

Seven fresh masked calls preserve their full raw64 returns, FP state and
before/after CPU0/MMU/TPL/owner/table/config/source context. Full Core hashes
immediately precede and follow each call. Only our bounded RAM/AT/register
readers, FP primitives and the seven typed PSCI calls run while held. No
original UEFI service, allocation, Console, USB, Stall, WFI/WFE or provider
method occurs in the successful masked interval. A new pure masked checker
does not relax the ordinary pgcd_live or original-service IRQ contract.

Masked non-OFF, unsupported/unrecognized values, nonreturn, time/source/
architecture/FP/native-flag/ticket uncertainty remain terminal UNKNOWN with
held state. After seven valid OFF returns, an additional complete source and
masked context checkpoint precedes restoration. Group1 is restored to one,
then DAIF to zero, with exact before/target/actual readback, followed by the
normal architecture and full source checkpoint BEFORE any original GetMap.
Only after those checks can held/unknown be retired. Full second map,
source/config/owner/lock equality, zero literal &wln_cpu_on_issued and the
unopened final ticket remain mandatory for the complete independent close.

CPU_MASKED_RO_ADMISSION_RAW_V1 is 50800B, including both rounds, all 15 masked
source checkpoints, post-restore source, two 72B transitions and up to 64
native-flag samples. Normal-only ABI39344B and its label remain unchanged.
The 1MiB firmware log, actual-size snapshot and default6MiB+128 host capacity
retain the entire new raw. Any UNKNOWN/held state/log overflow explicitly
blocks Clock/native/PON/receipt. The parent appends RAM and enters its local
mask/nonreturn hold without Console/USB/Stall/ACK/reset/cleanup; no claim of
remote recovery or physical walltime interruption of a nonreturning SMC.

Even complete masked success is only CPU-local evidence. It is not a DRV2,
EE/EL3/VMID/MPU grant, rail state or permission for a later private interval.
New exact source-bound host policy, two serial whole-EFI/XNU terminal models,
original81 codec, independent freeze and unique ONE helper are required
before a candidate. Fresh0169 strictRO qualification may be reused after its
controlled normal exit and actual FASTBOOT; consumed boots cannot replay.
