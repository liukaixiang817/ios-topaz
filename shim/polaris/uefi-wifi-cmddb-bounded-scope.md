# Focused CmdDb capture with a bounded original-Core namespace

`--wifi-power-cmddb-bounded-gcd` is default OFF and requires both the existing
capture-only opt-in and the exact original Core/private-client/CmdDb sources.
It changes the same pre-final-Clock/GCD private phase. It does not start a
standalone namespace boot or enable the power writer.

The existing source-bound Create and known Delete remain guarded original
services. The new CmdDb branch replaces its original GetMemorySpaceDescriptor
call with finite reads of the exact original Core's RAM list. Node80B and its
signature, head, lock and fields are bound to the own original binary and
template digest. There are at most512 nodes, complete raw two-pass snapshots,
cycle/backlink/range checks, five immutable source hashes at each checkpoint,
and current owned RAM/loaded-image exclusion/NS-WB translation checks. Every
checkpoint/node translation and partial byte count stays in the record.

Each database page is read only after an immediate same-context recheck of
the captured head, released-lock observation, exact target node, five source
hashes, fresh target S1E1R and actual PAR restoration readback. The complete
current map and exact reserved-or-BSData/WB descriptor conditions still apply.
The database is exactly the observed `85fe0000/128KiB` namespace, separate from
the own SMEM writer range. A final target guard follows each full copy.

The original GCD API observations remain unissued and have status UINT64_MAX.
The reader does not fabricate EFI_SUCCESS or fall back to the old API after
refusal. Released lock1 and stable RAM snapshots are observations; they grant
no CPU/EE/EL3/MPU/VMID or hardware ownership. No lock/TPL service, allocation,
original CmdDb Query, critical PSCI admission, RSC write or remote NV serving
is reachable from this capture body. Other unchanged boot services remain in
the parent, including the later original final GCD checks.

Complete client RAW_V1 and path RAW_V2 are distinct labels. The new path is
1656240B and includes two183064B namespace results plus66 target guards832B.
The existing8MiB RAM log uses a compile-time assertion over actual sizeof;
snapshots retain sizeof(actual buffer), and new host admission remains separate.
UNKNOWN/outstanding or an incomplete target guard explicitly blocks the parent.
The non-return local quarantine, no firmware return/USB/Console/reset behavior,
and original200ms ticket remain unchanged. No ticket reset, retry or cleanup.

This diagnostic narrows a known unbounded source call after two startup ACK
failures. It does not establish that either failed attempt reached that call,
and it is not Wi-Fi scan/join/data completion. Software peers, original PE data
and cross-compiles are offline evidence. New exact host admission, wrapping,
source audit, independent freeze, fresh post-recovery strict-RO root/NV review
and an independently observed correct FASTBOOT are still required for a new
physical candidate. The consumed0155/0156 artifacts must never be replayed.
