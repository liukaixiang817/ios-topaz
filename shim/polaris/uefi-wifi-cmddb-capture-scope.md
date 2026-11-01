# Focused CmdDb capture diagnostic after the 0155 unknown startup

The 0155 startup acknowledgement timed out. Its later UEFI query was unavailable
and no power-path record was exported. The execution stage and physical cause
remain unknown. Human recovery and an independent product query subsequently
confirmed Polaris FASTBOOT. These facts do not establish that a query, CPU
critical section or RSC transaction ran, failed or completed.

The new default-OFF `--wifi-power-cmddb-capture-only` scope tests the previously
unobserved CmdDb namespace reads. It is a separate committed-source candidate,
not a new policy for retrying the consumed 0155 image. The normal transaction
implementation and all historical exact profiles remain separate.

The diagnostic uses the same original known private client and complete source,
owner, protocol, memory-map, GCD and exact NS/WB translation checks. Only the
original runtime cached/platform pair at 0x85fe0000 and its exact 128KiB RO
namespace can qualify. It retains two complete copies, complete validated ARC
footprints and source checkpoints, with the original 200ms bound. The Android
DT's indirection and the 0x86000000/2MiB SMEM writer bounds are unchanged.

There is no original CmdDb Query callback in this configuration. The parent's
CPU/Device/RSC continuation is removed from its preprocessed execution body,
and those callback fields are zero. A complete stable capture deliberately
returns `PWCD_CAPTURE_STOP` (13), not success. The parent preserves that raw
record and can retire only through its existing full source/pool/known-client/
empty-queue checks and known Delete. A partial, changed, foreign or UNKNOWN
result still blocks Delete, native continuation, PON and receipt; no cleanup,
retry, timestamp renewal or permission change is added.

The raw ABI and complete client/path markers are retained, with an explicit
capture-only scope line. Max original Query, critical PSCI, RSC steps and RSC
events are all zero in the new typed metadata. Existing startup CPU/GPU and
native WLED behavior are separate unchanged features, so the diagnostic's zero
limits must never be described as zero CPU or WLED actions for the whole boot.

Successful offline software peers, full linkage or a returned diagnostic stop
would not prove a physical ARC vote, exclusive hardware lease, MSS startup,
NV service or Wi-Fi scan/join/data. A separately reviewed new host profile,
fresh strict-RO root/NV audit after physical recovery, original whole-image
codec check, independent source freeze and one-use helper are required before
this candidate can be attempted. The consumed 0155 image is never replayed.
