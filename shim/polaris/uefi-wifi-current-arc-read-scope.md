# 0165: three current ARC RAW responses, complete TCS restoration

This is a default-OFF extension of the current prepared private-client path.
It is a first hardware READ experiment, not a rail vote or a Wi-Fi driver.
`--wifi-power-current-arc-read` requires the existing prepared transaction.
The builder fixes `EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY=1`; the resource WRITE
body is preprocessed out. There is no CLI switch that qualifies a response
or enables a vote. Unknown response bits remain in the full raw record.

The exact original Polaris RPMh image is 61440 bytes, SHA256
`b718efb605db2c1d7be3b5e84d13adb148e24eebae66496e9569cfe9b34bfdc5`.
Its bank-2 HAL setup at RVA 8610..870c encodes descriptor type 2 as WRITE=0,
RESP_REQ=1, and a four-bit length. Length 8 gives message 0x108. Its bank-2
response load at RVA 8328..8354 uses command stride 20, TCS stride 672 and
offset 0x20d40, returning all 32 bits. These are static instruction facts,
not evidence that a returned ARC word is this DRV's restorable saved vote.
The original setup also writes CMD_DATA. Our READ core does not write that
register, consistent with the pinned generic upstream single-command READ.
Neither the original HAL nor public submission code is called or patched.

All three addresses come from the two completed current CmdDb captures and
are revalidated within the new, independently bounded private interval.
Full original namespace/source/owner and current relevant CmdDb bytes,
complete RAM cache/queues/mode/TCS headers, actual GCD and NS Device R/W AT,
CPU0 identity, native CPU_ON flag and both seven-peer admission rounds are
required before checked stores. The local masked interval excludes original
firmware services while RSC is active. This conditional original APPS DRV2
scope does not assert an EE/EL3/VMID/MPU grant or physical peer rail-off.
Device mapping, a callback result, RET locks and instantaneous PSCI OFF do
not independently grant ownership.

The engine dynamically selects one idle, enabled ACTIVE TCS. It issues one
command at a time for CX, MX and MSS. It never writes IRQ enable/type or
CMD_DATA. New IRQ, all required issued/completed status, unchanged response
and idle precede each ACK. It restores every touched RW value, reads back
the entire touched set and finally verifies IRQ enable/status. An independent
full-prefix audit is cross-bound to actual checked I/O and precedes exact
CPU restoration, full RAM/source/namespace retirement and known Delete.
The existing 50 ms, 256-step, 1024-event and private 200 ms bounds are not
reset, rebased or relaxed. The independent final Clock/GCD ticket is unopened.

Partial, unknown, changed, late and overflowing evidence is sticky. The parent
retains all raw records and enters the existing local mask/nonreturn WFE
quarantine without Console, USB, Stall, ACK, reset, cleanup or known Delete.
This is not successful restoration and may require physical recovery.

The new 1941984-byte body includes the complete 49488-byte READ record and
401936-byte checked-access record. Existing preparation and private-client
raw remain complete. Their hex plus the existing 1 MiB reserve fit the
10 MiB firmware log; host capture remains 14 MiB plus 128 bytes. Default-OFF
and QEMU builds omit this physical body. Software peers and terminal models
do not establish actual ownership, response semantics, restoration or Wi-Fi.

Only actual three-response/completion/full-restore evidence can advance this
experiment. A later source-bound scope must independently establish ARC
per-voter response semantics before planning max(saved, requested) and reverse
saved restoration. Missing cache entries are never zero. MSS startup, remote
NV serving, scan, join and network data remain unimplemented and disabled.
