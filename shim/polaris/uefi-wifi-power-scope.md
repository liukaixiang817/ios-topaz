# Conditional APPS DRV2 runtime experiment

This review is limited to the physical-body firmware source selected by the
new literal host profile and its exact 80 compiled inputs (0154 used
`1f55e44e14e0c56af2e5cd6f84d68bb63ba721b6`). It qualifies a **runtime-gated
experiment**, not a previously observed hardware lease or working Wi-Fi.
No runtime prerequisite can be replaced by this document or a host boolean.

The 0154 physical trial returned a known pre-mask refusal with zero RSC stores.
Both original CmdDb cached/platform pointers were 0x85fe0000; the five immutable
hashes, relocated table and provider owner matched. The prior SMEM lower-bound
test rejected that separate namespace before its first GCD/AT/read or Query.
Own DT supplies an indirection register at 0x0c3f000c, not a direct mapping
inferred from the node name. The new reader and masked recheck accept only
the exact 0x85fe0000/128KiB RO region, still requiring the complete current
map, GCD descriptor, NS/WB translations and unchanged source. Those checks
have not yet passed on this phone. This correction leaves the 0x86000000/2MiB
SMEM writer bounds unchanged and grants no allocator, MPU/VMID or radio scope.

The original Polaris RpmhDxe configures one logical DRV2 at bank2 of the
APPS RSC. Its immutable source and its registered live provider, runtime HAL,
mode, pool, cache and queues must agree. Own DT independently identifies
APPS DRV2 at 0x179e0000, with TCS registers at 0x179e0d00. These addresses
do not authorize other banks. The original firmware's **current** ACTIVE
mode and IRQ-enabled eligible TCS determine selection; Linux DT counts and
Mi8's fixed TCS1 are not substituted.

The [pinned upstream binding](https://kernel.googlesource.com/pub/scm/linux/kernel/git/soc/soc/+/add9f6f30e54b5c07e7a0260cda459ef1d9646b7/Documentation/devicetree/bindings/soc/qcom/rpmh-rsc.txt)
corroborates this bank geometry and distinguishes software ACTIVE requests
from firmware SLEEP/WAKE/CONTROL requests. It does not certify the current
state of this phone or an EL3/MPU/VMID grant. The operating assumption is the
original trusted boot platform and its APPS bank assignment, not protection
against a compromised secure firmware changing that assignment.

## Evidence that must be obtained in the same runtime interval

1. `pwrcl_run_body` creates exactly one known no-explicit private DRV2 client,
   verifies its current pool membership/empty queues and preserves the original
   provider/Core identities, source hashes and original FP/arch/TPL guard.
   The separate final GCD ticket remains unopened throughout this phase.
2. `pwcd_collect`, `pwrpb_capture` and `pwrmd_collect` obtain current complete
   CmdDb/ARC levels, valid saved active votes, original provider/cache/pool/
   queue/mode/HAL state and registered GCD descriptors. Absent or invalid
   saved votes are a refusal, never a guessed zero. Both actual read and
   write translations must identify the same NS Device page; translation
   alone does not grant this scope. No mapper changes permissions.
3. `pwrpc_begin` executes on CPU0/EL1 with the exact admitted MMU, CPACR,
   TPL and system/owner tables. Seven normal guarded PSCI queries must report
   OFF, followed by the exact local DAIF I/F and Group1 mask, seven further
   typed guarded OFF queries and a fresh immutable source/owner checkpoint.
   The actual source-bound native CPU_ON-issued flag must still be zero.
   OFF is logical state; it does not mean rail-off or secure ownership.
4. A new complete masked RAM capture must equal the normal capture. The
   original provider's active/pending/sleep/wake work must be empty, and its
   ACTIVE TCS must be idle with no pending IRQ. `pwra_acquire` re-reads actual
   bank geometry, IRQ and all eight TCS control/status/enable words while
   masked, and obtains another complete current CmdDb copy. Other bank or
   firmware sleep/wake/control slots are never borrowed.

Only the conjunction of those actual observations permits the checked
backend's local NS interval. Its concurrency argument is specific: all other
NS CPUs were observed OFF after masking; CPU0 runs this source-bound busy
path with no original firmware service, SMC, WFI/WFE, event dispatch or native
CPU_ON until retirement. The original provider cannot run another NS request
in that interval. CPU0 remains active, so this code does not request the
all-CPU-off condition used for firmware sleep/wake transitions. This is not
a claim that a CPU mask controls EL3 or grants secure memory access.

The 0153 parent link fixes the only exit from an uncertain interval: a local
terminal mask/hold without returning to opaque UsbFn/Console/Stall services.
There is no response ACK, cleanup, reset or retry on that path. The current
phone has **not** executed it, and no new hardware observations are claimed.

## Operations and retirement

`pwra_transfer` binds every transfer to the current engine event, original
CPU/source context, own register whitelist and fresh read/write AT/PAR
restoration. The finite transaction raises only CX/MX/MSS ARC votes to
`max(saved, requested-index)` for the current original raw384 tables, then
restores saved votes in reverse order. It does not program PLLs, direct PMIC
voltage/current/protection registers, IRQ enable/type or any other resource.

Each request needs a new selected IRQ, all three issued/completed indications
and idle before ACK. Unknown bits, partial delivery, timing regression or
foreign state are sticky. Retirement requires independent complete append-only
prefix validation, exact touched-RW readbacks, another full CmdDb copy,
identical full source RAM, source checks before exact CPU unmask and a final
registered GCD/Device check before known-client Delete. The original 200ms
ticket and transaction's 50ms/256-step bounds are never renewed or relaxed.
Original blocking submission/churn and RET lock stubs are never used.

## Host admission and limits

The new exact profile may admit one RAM image whose only new power action
is this conditional experiment. Its runtime preconditions have not yet passed
on hardware. The builder's `candidate_ready=false` and
`hardware_ownership_independently_qualified=false` remain truthful build-time
observations: it did not create an independently reviewed/frozen image or
measure hardware. Host review permits the attempted qualification above;
it does not change those observations into a blanket hardware grant.

The source, all 80 inputs, complete raw evidence layout, new markers, log
capacity, source review and two current terminal models must match exactly.
The old profiles stay immutable. Rejected runtime predicates cannot be
changed/retried under another policy. Successful compilation/model execution
or a later command ACK is not a physical completion or reset observation.

This scope cannot start MSS, call SMEM getters/allocators or acquire SFPB,
assign VMIDs/MSA/RMTFS memory, serve NV, enable a radio, scan/join, or prove
working sound/camera. Each remains a later independently qualified lifecycle.
Android, Windows, original NV/root/ESP/GPT and persistent storage stay untouched.
