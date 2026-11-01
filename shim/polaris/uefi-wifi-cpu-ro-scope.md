# 0169: independent normal CPU call evidence before any private interval

0168 did not return a boot ACK or new CPU/RSC raw. The user physically
recovered FASTBOOT, independently confirmed at07:55. No actual failing
predicate, normal/masked CPU state, READ count, quarantine or panic is known.
This new default-OFF diagnostic narrows that uncertainty; it is not Wi-Fi.

The new --wifi-cpu-ro-admission scope excludes NPA/RPMh inventory, private
client, staged CmdDb, READ and resource-WRITE flags. It executes before Clock
allocation and before the still-unopened final GCD ticket. Its own resident
context and spent-once ticket open once and finish once; the final context is
never opened, reset, rebased or used as an old lease. The literal native flag
is &wln_cpu_on_issued and must stay zero at all sixteen recorded reads.

The original fixed AFFINITY_INFO64 primitive is extracted byte-for-byte from
pwrpc_actual_affinity, shared without altering its functionID, target/level
registers, clobbers or raw64 return. No reference scripts or prebuilts run.
Own0114 live DT has cpu@100..700 and PSCI1.0/methodSMC. These establish source
correspondence, not the current state of any peer. Each of seven normal-IRQ
calls has the existing complete Core/owner/config/map/FP/architecture/TPL
service guard and immediate full Core hash checks before and after. Every
observed raw64 value, including unsupported and unrecognized values, remains
in its original slot. Numeric classification is published only after full
return/guard/source validation. An unissued zero is UNOBSERVED, not CPU_ON.

This scope captures logical states only. AllOFF does not continue into the
private or critical path, and no state grants CPU/DRV2/EE/EL3/VMID/MPU lease.
It offers no mask, CPU_ON/OFF, TCS write, RSC READ/vote, original client API,
MSS, SMEM writer or remote NV service. The seven-call API itself cannot abort
a nonreturning SMC: original200ms freshness is checked around returned work,
and a physical walltime bound has NOT been demonstrated.

After all calls, a second guarded GetMap and full source/config/owner/lock
snapshot must match; TPL must remain4, the native flag zero and the final
GCD ticket still unopened. Only then is the independent RO context retired.
A partial/nonreturned call, failed FP/source/architecture/clock/map/flag,
changed final ticket or reentry stays UNKNOWN. No UNKNOWN is cleared for
reporting. The parent blocks Clock/native/PON/receipt and keeps complete raw
in RAM before its existing local-mask/nonreturn hold, with no Console/USB/
Stall/reset/cleanup/ACK. Log overflow enters that same gate before this phase
and after report. The final Clock/GCD lifecycle remains separately guarded.

The complete CPU_RO_ADMISSION_RAW_V1 is39344B: original Core/maps/ticket/context,
seven496B call records, fourteen384B immediate source records and all flag/
status masks. A new1MiB firmware log and the actual-size snapshot keep full
records; no old ZERO_VOTE/client/READ success label is reused. Default-OFF and
QEMU remove the physical caller/record, with a distinct compiled-out marker.

Software peers and two whole-EFI terminal models are not physical SMC or
Wi-Fi evidence. New exact host admission, full original81 codec, a NEW strict
RO root/NV transition after0168's unknown exit, independent freeze and unique
ONE helper are required before any candidate can be sent. Old consumed
sessions/images/payloads and frozen controllers must never be replayed.
