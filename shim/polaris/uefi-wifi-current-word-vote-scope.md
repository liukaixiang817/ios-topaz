# Fresh READ-derived HLOS/DRV2 ARC round trip

The default-OFF `--wifi-power-current-word-vote` requires the complete explicit
current-word READ, normal argument, prepared CmdDb, work, CPU and GOP dependencies.
It enables one bounded round trip, before any WiFi VRM, MSS, NV service or radio.

[Qualcomm's Maulik Shah, 2025-10-23](https://lkml.iu.edu/hypermail/linux/kernel/2510.2/06910.html)
explicitly identifies ARC/BCM/VRM READ results as HLOS/DRV2 votes and excludes
aggregation across DRVs. The same thread identifies hardware support since
SDM845. This resolves the specific semantic gap left after the successful 0185
READs. It does not establish an EE/EL3, VMID/MPU, DMA or radio grant.

The own SDM845 source and original HAL bind DRV2/bank2, eight 672-byte TCS blocks,
16 commands per TCS and the current active mask. Own current CmdDb binds the
three ARC addresses and auxiliary corner tables. A NEW session must obtain new
owner/source/namespace/cache/Device NS/RW/AT/CPU admission and three new READs.
Historical `6/3/0` is never a new session's saved state. Missing ARC cache rows
are not zero votes; zero is accepted only as a delivered, fully retired READ
response satisfying the fresh corner checks.

The writer raises `max(saved,target)` in CX, MX, MSS order, then restores the
three exact saved votes in MSS, MX, CX order. It dynamically selects an enabled,
idle, untriggered TCS. The READ path's narrowly admitted inherited high latch
does not qualify that TCS for WRITE. Neither IRQ enable/type nor CMD status is
written. Each of two triggers requires a new selected IRQ, all three required
DONE fields, idle, then acknowledgement. Documented CMD_STATUS bit0 is retained;
other unknown pending CMD status bits retain UNKNOWN. Initial and final RO
snapshots remain raw evidence rather than completion evidence.

The existing clock adapter already enforces one combined READ-start to
WRITE-finish 50ms interval and 256 combined steps. Retirement additionally
reconstructs that interval. Original opening time, 200ms qualification, all 68
work samples including the slowest, 50ms READ estimate plus 25ms reserve,
source hashes, FP/DAIF/G1 rules and complete restoration remain unchanged.
There is no ticket rebase, lease renewal or second 50ms allocation.

The explicit writer independently reconstructs the selected TCS' full initial
and final snapshots and pending status/response/IRQ OR summaries from original
events. After the second full masked DB and geometry capture, both engine and
access prefixes are rechecked before releasing access or restoring CPU state.
The caller then requires full RAM/source/Device/namespace/pool/client closure
and known Delete before USB export. Failure preserves the original UNKNOWN,
held masks and full raw record; no cleanup, generic reset or extra failure-time
hardware sampling is added.

`WIFI_CURRENT_PRIVATE_WORD_ARC_VOTE_RAW_V1` keeps the complete existing 1969216
byte C ABI. Terminal V7 uses the existing 16 resident numeric rows, projecting
WRITE phase/triggers/completed/error instead of inventing post-failure samples.
Flag-OFF execution and existing READ-only labels remain unchanged. Software
peers, compilation and model results do not demonstrate physical voting or
WiFi scan/join/data.
