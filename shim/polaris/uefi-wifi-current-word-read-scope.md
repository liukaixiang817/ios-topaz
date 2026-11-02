# Current private word-capture READ scope (0184 saved-status fix)

Default OFF: `--wifi-power-current-word-read` is an explicit new composition.
It requires prepared current capture-only ARC READ, unchanged all-68 work
admission, pre-mask argument admission, CPU live failure diagnostics, full
word database capture and terminal GOP diagnostics. It rejects the prior
CPU/access/database checkpoints, normal-to-masked database stop and independent
CPU RO scopes. Their flags, policies, records and consumed sessions are retained.

0182 physically completed both full masked databases and CPU/source/private
retirement. Those records are historical observations, never a ticket or
permission for this READ. Each new attempt must freshly acquire the actual
known client, current namespace, selected CmdDb sources, full RAM cache,
normal Device namespace/NS R/W AT, all ten typed argument ranges, original
CPU qualification, masked sources and full databases in the same interval.
No EE/EL3/VMID/MPU grant is inferred from OFF, AT, a callback or a lock.

The normal argument prefix is rechecked before mask, before first READ,
after READ/access retirement before CPU restoration, and before known Delete.
The original work sample/estimate/decision remains unchanged. After normal
argument capture, compare its remaining original interval to the original
estimate. A known late budget refusal closes completely; expiry, partial
returns or changed source/prefix remain sticky UNKNOWN. No renewed lease or
rebase exists. The original 200ms, all 68 samples/slowest, full READ 50ms and
25ms reserve, 256 steps and 1024-event bound remain unchanged.

The original READ leaf dynamically selects an eligible idle active TCS whose
IRQ is enabled. It performs three single READ messages (0x108) for 0x30000,
0x30010 and 0x30060. Before every new rising edge it writes TRIGGER low and
reads it back; it never writes CMD_DATA, IRQ enable/type or a resource WRITE.
Each response requires its own new IRQ, all issued commands DONE and idle.
W1C IRQ ACK follows these checks. Saved command message/address, wait, enable
and control are restored and read back; a saved high latch is retained from
the completed third new edge instead of writing high and retriggering it.
Full independent engine and checked-access journals close before restoring
CPU DAIF/G1. The first full word database delivery prefix is validated before
opening access/READ; both full prefixes are validated before closing access. Full RAM/source/namespace/pools/empty queues and known Delete
must finish before USB export. A later source-close failure preserves any
already completed CPU restoration but blocks Delete/export as UNKNOWN.

Both fresh masked database snapshots remain 128KiB/32 fresh per-page NSWB
same-PA AT/PAR restore each. Only this already qualified Normal RAM uses
aligned64 word loads. Device/MMIO loads and stores remain checked32-bit.
Two normal Device captures still perform 140 loads and six original queries;
masked geometry, engine reads, launch stores and IRQ ACKs are additionally
reachable here. No claim of total MMIO zero is made.

The independent raw tag is `WIFI_CURRENT_PRIVATE_WORD_READ_RAW_V3`; the whole
parent record is 1,969,216 bytes, access402,048, CPU10,096, arguments25,216.
V6's same 16-row GOP projection reads only existing resident diagnostics,
access/engine issued/returned flags and pending address, original failure
sample, database byte/word prefixes and CPU held/restored fields. It adds no
failure-time clock/register/firmware read. Missing attempted/issued evidence
means UNOBSERVED. Partial-source/time/native/AT/engine uncertainty retains
all raw bytes and UNKNOWN/held state, appends RAM, masks locally and holds
nonreturning WFE; no USB/Console/SMC/reset/cleanup or forged receipt is added.

RAW responses do not establish qualified per-DRV ARC saved votes. Resource
WRITE, CX/MX/MSS/WiFi rail votes, MSS/MSA/GLINK/remote NV, WLFW, ath10k and
scan/join/data remain disabled. Software peers and QEMU do not prove hardware
READ, interrupt ownership, secure grants or Wi-Fi functionality.

0183's physical photograph located a returned saved CMD0_STATUS read at
0x179e0d3c, engine phase0, before any new request. The checked access layer
had applied its new-issued completion mask to this initial RO snapshot.
The status word itself was not projected and remains unknown; synthetic
software values used to reproduce the boundary are not that physical word.

For this default-OFF current-word READ composition, initial phase0 (zero
write/trigger/completion/ACK/step/response state) and final phase7 (three
new triggers/completions/ACKs, all three responses, no final publication yet)
retain each delivered CMD_STATUS as RAW observation. No bit is cleared,
rewritten, masked from raw or used to claim completion/ownership. Other
phases must be this engine's pending CMD0 in phase2/4/6 with exact matching
trigger/completion/ACK counters. Required issued/completed bits remain
0x10100. Bit0 is the documented TRIGGERED field and may accompany those
required bits; other bits remain UNKNOWN. A new IRQ, response, idle, readback
and full independent journal retirement remain required. The access aggregate status OR must equal the
OR of every corresponding delivered full-prefix engine status sample.
Phase mismatch, malformed snapshot counters, partial/late read or any new
issued status error remain sticky UNKNOWN. Resource WRITE stays unreachable.
V6 projects the last already retained I/O value and command0 status OR when
there is no CPU failure sample; CPU failures retain their original failed
ticks. No new hardware or clock observer is added.

Primary register correspondence was checked against pinned Linux commit
7acf90feab8b009fde7def08ff2c622d0f10e99f, rpmh-rsc.c blob
f881af35ecfc51d4dbcc7d2d3c32eea854210d5e (2.7 STATUS0x3c/RESP0x40,
command20/TCS672). This is a generic source reference, not a Polaris secure
grant; its interrupt-only completion behavior is not imported.
https://code.googlesource.com/linux/torvalds/linux/%2B/7acf90feab8b009fde7def08ff2c622d0f10e99f/drivers/soc/qcom/rpmh-rsc.c

0184's actual V5 photograph supplied CMD0_STATUS0x10101 after the first new
trigger, at phase2 with completion0 and CPU held. The old 0x10100-only mask
rejected bit0 before reading CMD_RESP_DATA. No response, completion, idle,
ACK or retirement is inferred from that photograph. The session was consumed
and physically recovered, and its evidence is retained unchanged.

Own MiCode Polaris commit c7cb50c18f812629b9620b2b8fa684bc40d82080,
drivers/mailbox/qcom-rpmh-mailbox.c blob
00ebed9b4eeda5298e6fdbb4df2cb9f8babc7640 has the same STATUS0x3c,
RESP0x40, command20/TCS672. Its IRQ handler checks ISSUED and required COMPL
independently before the READ response path; it does not reject bit0.
Qualcomm's authored register decoder explicitly names bit0 TRIGGERED,
bit8 ISSUED and bit16 COMPL. This supports treating 0x10101 as known status,
while requiring both completion bits and our own new IRQ and idle checks.
No original unbounded submission, callback, cleanup or IRQ policy is copied.

The current-word scope alone accepts 0x10100 or 0x10101 at pending completion.
The full delivered word is retained in both journals and every OR field.
The independent retirement verifier recomputes each request's pending status
OR from its original samples and compares the summary exactly; changing bit0
in only a sample or summary fails. The generic/write engine and flag-OFF
READ paths retain their previous behavior. This source fix is not physical
READ success or qualified ARC vote semantics. Source-only review artifacts
remain private; the referenced mail is a register description, not a grant.

https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/mailbox/qcom-rpmh-mailbox.c
https://lists.openwall.net/linux-kernel/2026/10/05/508
