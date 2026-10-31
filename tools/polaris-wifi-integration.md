# Polaris Wi-Fi transport integration

This is executable SMEM FIFO / GLINK / QRTR / WLFW CAP transport code. It is
not an attached ICNSS/ath10k radio driver and does not provide scan or join.
There is no boot registration, radio power, MPU programming, firmware copy,
DMA setup, storage action, or physical-device call in these files.

The GLINK/QRTR core adapts the MIT original `bsd/dev/mi8_glink.{c,h}` from
Dipper `e930c26c4303283d7f2f5fc87479946d46409783`. Its native QRTR callback
contract matches pinned HackiOS kernel `8e61187098f2c26c5daee8f9f72b6416aa64b9ab`;
port objects remain explicitly typed and must not be cast. No reference
scripts/prebuilts, foreign calibration, WCN6750/ath11k/IPCC route, or Linux
initialization tables were copied. The MIT notice is retained in the source.

Own MiCode `c7cb50c18f812629b9620b2b8fa684bc40d82080` independently establishes
legacy descriptor478=32B and FIFO479/480, read/write index order, uncached TX,
and cached-first RX. Original Polaris DT binds SMEM0x86000000/2MiB with MPU
and the mpss doorbell0x1799000c/mask0x1000; that is a route to admit, not a
hardcoded WLFW node. WLFW0x45/v1/instance0 must actually be discovered.

## First physical read-only entry

`polaris_wifi_smem_readonly_probe(io, own_remote, result, workspace)` takes
existing native/UEFI mapping callbacks. Reserve the workspace outside the
kernel/UEFI stack. Each callback must enforce the same current lifetime epoch;
`translate_read` returns actual PA and raw PAR, and `read` must contain access
faults. No mapping/permission adjustment or SMEM protocol getter/allocator may
be used to make a failed read pass. Such getters can write the shared header.

The entry validates all512 pages before/after, inventories only bounded
metadata, captures the descriptor twice, checks exact indices and rechecks the
inventory. It never reads FIFO data or another host's partition header. It
retains raw descriptor/PAR evidence and the first failure. A successful CPU
translation/read does not prove hardware MPU configuration, exclusive APPS
ownership, remote lifecycle, or the identity of the WLAN service. Those output
permissions deliberately remain false. Save the result/PAR/raw records in the
new candidate's append-only evidence before considering any transmit lease.

## Admitted transport path

1. Establish current native mapping/MPU/exclusive APPS producer-consumer and
   remote-lifecycle evidence independently. Bind the exact inventory and epoch
   to mandatory `cfg.scope`; the callback must fail on stale/unknown changes.
   A metadata parser success or boolean in a host JSON file is insufficient.
2. Bind checked read/write, RX-cache invalidation, device ordering, own route
   doorbell, monotonic time and bounded sleep callbacks. Successful write32
   means a known whole write; any uncertainty returns false. The module
   restricts writes to existing uncached TX FIFO, descriptor+4 TX producer,
   and descriptor+8 RX consumer. It cannot write an allocation header,
   remote-owned index, another region, or reset an existing FIFO.
3. Create/start once. Nonempty queues reject without resetting indices. Poll
   to negotiate GLINK version1 and IPCRTR, exchange intents, learn actual QRTR
   peers and service announcements. No guessed host4/13 WLFW address is used.
4. `polaris_wifi_cap_open/request/poll` discovers the unique actual WLFW
   service, issues one own CAP request and accepts only its bound node/port /
   transaction/message/TLV response. It retains the raw response. A second
   peer, removed service, timeout, malformed response or transport failure is
   sticky; no automatic request replay. Identity success is not firmware /
   ICNSS DMA / radio / scan / association proof.
5. Close clients, poll on the same lease, call stop until actual data DONE,
   CLOSE_ACK and empty TX/RX queues. Stop is nonblocking EBUSY while unresolved.
   Faulted/uncertain transport is never destroyable through retry. Native
   shutdown must also refuse to label this as RAM_DRAINED/durableSAFE; this
   module's quiescent bit covers only its own transport, not native VFS/GPU/
   CPU, storage persistence, ICNSS/CE or any external DMA.

The remaining radio work is own ICNSS/SNOC lifecycle, original firmware/cal
identity, memory-request/MPU permission evidence and real ath10k12-CE TX/RX,
completion, stop and restoration, then native network interface/Userland Wi-Fi
registration. The pinned Mi8 Linux shim/userland is a useful next source after
those own hardware contracts; compiling this transport is not that milestone.

## RMTFS NV RAM-shadow service (0145, serial Wi-Fi work)

`polaris-wifi-rmtfs.c/.h` implements the real service14/version1/instance1
endpoint on this GLINK transport. It adapts the MIT Dipper e930c26
`mi8_hostsvc.c` protocol, checked against own DT client1/dynamic2MiB/guard-memory.
It is a callable service, not a native boot registration or an MSS power driver.
There is no physical provider or default address, and the current0144 kernel
does not contain this new service. No radio operation is established.

Creation takes all four whole, immutable, owned NV RAM inputs, exact own GPT
sizes (three8MiB plus FSC256KiB), SHA256 digests and a mandatory callback that
revalidates their current whole-NV/GPT provenance. Copies are hashed before
publication. Historical20261023 modemst1/2/fsg inputs currently fail physical
freshness: capture their24MiB at the next already-needed controlled RO
transition, with fresh GPT/ranges and before/after hashes. FSC alone already
matches fresh0139. Do not boot solely for this capture, feed old NV to a remote,
or fake the freshness callback. The private originals remain untouched.

The provider must supply genuinely allocated/shared/guarded2MiB memory,
actual MPU/VMID ownership, checked RX invalidate/TX clean, device ordering,
selected MSS node and lifetime epoch. `scope` verifies those facts on access;
it does not create permission. No camera carveout, SMEM getter/allocator,
clock/rail/reset/PAS/SCM operation, or partition-write callback is supplied.

The real QMI messages are OPEN1, CLOSE2, RW3, ALLOC4, DEVERR5 and SYNC6.
OPEN accepts only `/boot/modem_fs1`, `/boot/modem_fs2`, `/boot/modem_fsg` and
`/boot/modem_fsc`; these remain reference paths until the own remote requests
them. Unknown paths, including Mi8's synthetic OEM blank areas, are refused.
ALLOC checks client1 and the admitted memory size. Handles belong to the
bound node/epoch and can move between that MSS's QRTR ports. Entire vector
batches are checked before I/O; incoming batches are staged before any NV
shadow modification. Outgoing partial/faulted writes retain UNKNOWN.

Receive callbacks only enqueue. The sole workloop dispatches bounded batches
and handles callbacks reentered by QRTR send. Recent16 full requests/responses
are retained before sending; exact repeats do not repeat memory I/O, and a
recent transaction collision freezes the service. There is no exactly-once
guarantee beyond this bounded replay history or automatic send retry. SYNC
acknowledges volatile RAM only; status always reports `durable_nv=false`.

Close all handles, finish queued requests, withdraw the endpoint, and retain
the same transport/lifetime until actual DONE. `stop` additionally requires
the provider's actual remote-stop/DMA-drain/memory-handback witness; `destroy`
rechecks it before scrubbing/freeing shadows. Pending replies cannot be
overridden by that witness. Fault/UNKNOWN has no clear/force-release path.
This service's retirement is separate from native VFS/GPU/CPU drain and UFS
persistence. Physical MSS/RMTFS/SMEM integration, original NV freshness,
WLFW/ath10k scan/join/data remain unfinished.

`python3 tools/polaris-wifi-rmtfs-check.py --out <private-directory>` runs
the new service through actual software FIFO/QRTR frames under ASAN/UBSAN,
plus the affected existing transport regression. It covers all four shadows,
client1, both copy directions, batch rejection, replay, port changes, malformed
TLVs, wrong peers, callback reentry, pending DONE/retirement and eight sticky
fault cases. `--native-command <audited-command.json>` can compile one ARM64
object against the real locally staged XNU headers; this is not a kernel
link/build, boot, MPU witness or hardware success. No new kernel CI is needed
until this service is actually added to a separately reviewed native profile.

## Validation

`python3 tools/polaris-wifi-check.py --out <private-evidence-directory>` builds
and runs a software remote peer under ASAN/UBSAN. It negotiates actual FIFO
frames, wraps RX, uses remote intent0, delivers NEW_LOOKUP replies and performs
an actual QMI CAP request/response through the transport. It exercises checked
lease/read/write/cache/order/ring failure, pending queues, finite gate/clock,
backward time, and remote close with unresolved intent retention. The separate
RO-probe model denies FIFO/foreign-host reads and all116 failed read stages;
CPU translation changes reject and may_transmit always stays false.

A separate local check emitted ARM64 objects for all3 native sources against
actual CI39965897634 flags/headers. It is not a native link, boot, physical
SMEM read, MPU/owner proof or Wi-Fi operation. The source-only0905 patch adds
these objects to the kernel build but deliberately supplies no automatic
hardware activation. Parent integration owns the actual read-only entry and
later individually reviewed transmit admission.

## Own MSS power path correspondence (0145)

The original81 NpaDxe PE (73728B, SHA256
`0e4a6ce1eb72400ab70e281eea1f478ca3a35b209d3ff7ee75d10e680354b715`)
provides another possible route for separately owned resource votes. Static
inspection establishes GUID `79d6c870-725e-489e-a0a1-27e7a5d0cb35`, revision
`0x10002`, table RVA `0x100b0`, and installation at `0x1c64`. This does not
establish the current loaded instance, live namespace or permission to vote.

These original protocol functions take their ordinary NPA arguments directly;
they have **no leading This argument**. Selected table offsets and code are:

| Table offset | Operation | Wrapper RVA | Internal target |
| --- | --- | --- | --- |
| 0x10 | CreateSyncClientEx | 0x1c80 | 0x37d0 |
| 0x18 | CompleteRequest | 0x1cac | 0x4568 |
| 0x28 | IssueScalarRequest | 0x1cdc | 0x4020 |
| 0x70 | ResourceAvailable | 0x1df0 | 0x9a80 |
| 0x78 | DestroyClient | 0x1e1c | 0x46c8 |
| 0x98 | CreateQueryHandle | 0x1e7c | 0x974c |
| 0xa0 | DestroyQueryHandle | 0x1ea8 | 0x9774 |
| 0xa8 | QueryByHandle | 0x1ec0 | 0x98d0 |

CreateSyncClientEx takes resource/name/type/value/data/output in x0..x5.
Its wrapper returns EFI0 even when the internal result is NULL; the actual
output handle and its identity must be checked. ResourceAvailable similarly
returns its real status through the uint32 output at x1. Its internal path
looks up RAM links rooted at image+0x108b0, checks the resource definition,
and returns status0 for available or2 for missing. The current list must be
bounded, source/descriptor/identity checked and stable before a live call;
the original name lookup itself has no finite traversal limit.

QueryByHandle is not an unconditional read-only observation: it can invoke a
definition's query callback before the standard query cases. DestroyClient
calls CompleteRequest at RVA0x4730 and can invoke resource/plugin callbacks;
it is not a harmless detach or a safe cleanup after an unknown operation.
Original Clock strings contain `/arc/client/rail_cx`, `rail_mx`, `rail_xo`
and `/vcs/vdd_gx`. These are source names only. Absence of an MSS resource
string in that scan is not proof the live NPA namespace lacks one. Do not
guess `/arc/client/rail_mss`, create a client or issue a vote from these facts.

Own DT's three MSS supplies are ARC level regulators for `cx.lvl`, `mx.lvl`
and `mss.lvl`; each request is `0x181`. The pinned own regulator API applies
offset1, so this denotes raw level384, not385 microvolts or an arbitrary
maximum. Reusing the actual5600B own debugfs collection from2026-10-24
(SHA256 `861858b1296a3ba4ff9a421429affe58e11696e03a61079b03dee6bc673cf55a`)
binds command addresses0x30000/0x30010/0x30060 and original indices7/4/7.
Preserve MX's duplicate16 entries. This historical table is not current
aggregate vote state, ownership of a TCS, or permission to program a rail.

Mi8's W2b requests the tops and restores only MSS to zero while retaining
CX/MX. That is not an own saved-state restoration path. A physical provider
still needs a current admitted namespace, private client lifetime, actual
before/after votes and complete stop/restore. No NPA function, rail, clock,
reset or SCM operation was executed in this static review; current0144 and
all existing native/GPU/WLED code remain unchanged. Exact per-wrapper hashes,
call targets and own source identities are private0145/wifi/original-Npa-
provider-0001/static-ABI-and-own-MSS-level-proof.json.

The new explicit `--wifi-npa-readonly-pe` builder flag now wires a source-bound
live collector into the actual EFI prepare path. It runs after Clock's handle
allocations and before the first GCD query. This order keeps GCD's original
exact map-key interval intact. The collector reuses that same boot's completed
loaded-image enumeration, rechecks every followed RAM span and NpaDxe owner,
verifies five immutable relocated spans twice, and captures the bounded live
namespace twice. It calls only two LocateProtocol and two GetMemoryMap entries
under the existing FP/architecture/TPL original-service guards. No original NPA
function or plugin is called. Unknown delivery retains its operation and blocks
native startup/reset through the existing parent gate.

The real0145 trial returned128 distinct nodes and then a nonzero129th cursor.
It retained the complete RAW_V1 record and stopped with `PWNPA_LIMIT`, with no
unknown original call. The first five immutable hashes passed and the two
issued BootServices calls returned under restored FP/architecture/TPL guards.
The recorded128-node prefix took13036us. This proves neither a complete graph
nor absence of later MSS/CX/MX names. The original128-node scope and frozen0145
controller remain separate and unchanged.

The new0146 source keeps the walk finite at512 nodes and retains all fields in
each of two passes. RAW_V2 is470496B, with the same448B node layout and the
same200ms whole-observation deadline. Source/owner/map/namespace identity,
per-span owned RAM, cycle, partial-record and original-service guards are
unchanged. The larger capacity is not a relaxation of write permissions or
hardware protection thresholds. If the real graph or time exceeds the new
limit it still stops and keeps the raw partial record. Two passes are required
before calling a graph stable; the13ms prefix is not a prediction of success.

The complete hex NPA record takes940992B. A1572864B firmware log also fits the
retained pre-NPA scope's262144B bound plus bounded labels. Snapshot allocation
still uses the actual buffer's `sizeof`; the host native-log bound is now
4MiB+1572864+128. The old frozen controllers keep their old exact transport
sources. New typed metadata explicitly declares512/RAW_V2/470496; no legacy
manifest is relabelled or stripped to admit this scope.

`polaris-wifi-npa-check.py --driver <new-driver-directory> --out <private-dir>`
checks26 focused sanitizer cases, including complete256-node and512-node
collector runs, full target records after node128, changed tail data, a late
whole-observation deadline after129 nodes and513-node rejection. Relocated
original PE bytes are data only. The test fixture's NPA record was moved to a
larger isolated arena, with the original GCD configuration table outside its
self-image span; the real guards were not weakened to make the fixture pass.
Actual combined AArch64 COFF/Mach-O coordinator builds retain1024B maximum
frames, and the complete EFI links with65 inputs. The7d24 native kernel and
63cb payload remain unchanged; no native CI is needed. Two affected serial
whole EFI/XNU terminal models must bind the new65 inputs and all eight literal
physical-body compiled-out markers. None of these software checks proves the
new full physical NPA graph, original-provider calls, rail ownership or Wi-Fi.
A separate new host profile, image, source freeze and normal old-boot drain are
required before the next physical trial. No NPA client, vote, plugin or MSS
startup is authorized by the namespace observation.


The physical0146 scope now completes two identical189-node passes with four
returned BootServices calls, no error/unknown/outstanding, all four restored
FP/architecture/TPL guards, and ten immutable hashes independently matched to
the original PE. Both full432B relocated protocol-table copies also match.
This resolves the diagnostic128-node truncation. It does not start a radio.
The latest real UI remains the default7400 lockscreen with Melbourne time and
actual FG3/SMB2 battery data; the source retains the native backlight/GPU paths.

There are185 non-NULL definition pointers. Four names are unresolved placeholders:
`/arc/client/rail_xo`, `/arc/client/rail_mx`, `/vcs/vdd_gx`, and
`/arc/client/rail_cx`. Their definition/plugin pointers are NULL in both passes.
The exact original definition-state routine8904 and mask4 lookup6510 classify
these as unavailable, inferred from captured RAM; no ResourceAvailable API was
called. Name presence cannot admit a rail vote. No literal MSS name occurs in
this complete snapshot; that is not absence of every MSS power provider.

The original81 inventory also contains a separate61440B RpmhDxe, whole SHA256
b718efb605db2c1d7be3b5e84d13adb148e24eebae66496e9569cfe9b34bfdc5.
Its original protocol GUID is e1d0b573-f29f-495d-9352-ca0dd42a0a74,
revision10001/table RVAd0d8. Verified wrappers take no This argument. The
CreateHandle form at slot0x20 has drvID/name/low8flag and an output handle atx3;
the flag1/flag0 variants at0x28/0x30 output atx2. DeleteHandle is slot0x48→0x2ee8,
not0x38 or0x40. These are mutating operations with allocation/lock/logger paths;
unknown handles cannot be cleaned up speculatively. Init0x08→0x3ea8 writes the
initialized flag at0xd2e8 before the full initialization finishes, and is not a
readiness getter. Do not call Init or sleep/wake/invalidate to force a baseline.

The original IsDrvValid slot0x10 writes an8-bit output atx1. Its source0x5aa4
walks a configuration root via RVA0xb100, count at0, row pointer at0x20, stride0x30;
the static template has one configured ID,2. This is not live ownership.
Other getters/Create assert through0x6cd8 and can spin forever at0x6d20 on an
invalid ID, so guessing0/1 or importing a reference's DRV number is unsafe.
Before a real MSS client lifecycle, bind the actual registered RPMh provider,
current initialized/configuration/DRV/TCS state, own DT/ARC units and complete
private-client stop/restore. Account for allocator map-key changes before the
final Clock/GCD interval; keep its existing gates. Static ABI evidence and the
complete NPA graph grant no MMIO, rail, reset, authentication or VMID action.
The private static proof and display-only disassembly never execute or modify
the original PE. Current may_start_MSS/may_serve_NV_to_remote remain false.


0147 adds an explicit default-off source-bound RPMh initialization and queue
RAM snapshot to the actual preboot coordinator. The original Init entry writes
its initialized flag before completing its allocations; flag1 with missing
per-DRV queue/TCS state is therefore retained and refused as NOT_READY. The
reader follows only bounded BootServices RAM extents with actual identity checks,
keeps full partial bytes, and repeats the complete snapshot under the existing
200ms/architecture and original service FP/TPL guards. It calls LocateProtocol
and GetMemoryMap only, after Clock handle allocations and before first GCD.
It never calls RPMh Init, IsDrvValid, Create/Delete, sends a vote, accesses MMIO
or starts MSS. Software TCS state is not hardware TCS ownership. Actual stable
provider/config/queue evidence and the subsequent owned private-client/stop,
MSS/authentication, memory and GLINK/RMTFS work remain required before Wi-Fi.


Actual0147 retained a zero-call RPMh BASELINE refusal: NPA had already opened
the same GCD service context, while the RPMh reader called pgcd_open again.
The original GCD error stayed zero and NPA completed189 nodes twice. The0148
fix shares only the current pre-query stage2/phase1 context, requiring the
exact spent ticket/result, no error, outstanding operation, page query or final
checkpoint. It never resets or reopens the ticket. Each provider observation
still enters the unchanged original source/owner/FP/architecture/TPL guard.
The executable combined NPA-to-RPMh regression failed before this correction
and now passes without adding another GCD map read; six stale/forged/finished
contexts refuse before any new service call. This corrects integration order,
not a physical owner, RPMh initialization or Wi-Fi completion claim.


Actual0148 confirms the corrected shared context: all four original services
returned with FP/TPL restored, both complete RPMh snapshots match, the live
configured driver is2, and initialized flag1 accompanies192 bytes of TCS state
and populated per-driver request queues. The host independently matched all
ten immutable hashes and both relocated200-byte protocol tables to the exact
original firmware. These are RAM/source observations, not hardware TCS idle,
exclusive ownership, direct Init completion or rail-vote permission. No RPMh
provider API, client, vote, SMC, MMIO or MSS operation was issued. Original
DeleteHandle's42d4 path scans the client pool without a bound and spins at4330
if the handle is missing; returning a RAM slot is not hardware completion or
restoration. A future actual private-client lifecycle must validate membership
and use a distinct preparatory stage before the final Clock/GCD map interval.
