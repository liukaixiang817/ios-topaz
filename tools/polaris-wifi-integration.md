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
