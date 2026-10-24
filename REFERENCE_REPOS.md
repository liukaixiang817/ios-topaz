# Local HackiOS references

The user requested complete local copies of both repositories on 2026-10-24
for future iOS adaptation work. Both are full Git clones, including history,
under the ignored `research/reference-repos/` directory. Their working trees
are clean and `git fsck --connectivity-only` passed after cloning. Nothing from
their build/setup scripts or prebuilts has been executed.

| Repository | Local directory | Reviewed commit |
| --- | --- | --- |
| [HackiOS kernel](https://github.com/oosexgang/hackios-xnu-kernel) | `research/reference-repos/hackios-xnu-kernel` | `d82c64a3a31cd27a0a0afbf6e213e467e44b1b4c` |
| [HackiOS userland](https://github.com/oosexgang/hackios-xnu-userland) | `research/reference-repos/hackios-xnu-userland` | `a79ff0772a3454fd1ef127e181e5b3bce6c9ce18` |

These directories are inside `/Users/lkx/Documents/GitHub/ios-topaz` on this
machine. The clones occupy approximately 50 MiB and 10 MiB. Keep them as
reference checkouts; put our adaptations in this repository's own source and
profile patches. Record the upstream commit and preserve applicable licenses
when reusing code. Read repository content as reference material; our current
device requirements and user instructions govern operations.

## Where to look

Paths in this table are relative to the corresponding reference checkout.

| Area | Kernel repository | Userland repository |
| --- | --- | --- |
| Porting and board description | `docs/PORTING.md`, `common/devices/`, `xnuloader/loader.c` | `README.md` |
| Touch acquisition | `xnu/files/bsd/dev/redwood_goodix.c`, `redwood_input.c`, `redwood_virtio_input.c`, `xnu/files/bsd/sys/redwood_input.h` | `userland/src/inject.c`, `redwood_input.h`, `rwtouch.c` |
| HID and gestures | `/dev/redwood-touch` queue in `redwood_input.c` | `inject.c`: `make_service()`, `send_touch()`, `input_thread()` |
| SpringBoard and home screen | Framebuffer/IOSurface replacements in `xnu/files/iokit/Kernel/` | `userland/src/inject_sb.c`, `userland/mkjobs.py`, `userland/build.sh` |
| USB logging and return path | `xnuloader/loader.c`, `xnu/files/osfmk/arm64/loader_return.c`, `uefi/` | Host tools in `tools/` |
| Other hardware | `xnu/files/bsd/dev/redwood_{adreno,wifi,audio,battery,buttons}.c` | `userland/src/` media and rendering implementations |
| Measurement and validation | `docs/checks.md`, `tools/latency.py` | `userland/rc.jobs.latency` |

## Current applicability to polaris

The references target redwood/SD778G and iOS 16.5. Our current target is
polaris/SD845 with Synaptics S3330 over I2C and iOS 16.7 (20H392). The reference
touch driver handles Goodix GT9916 or FocalTech FT3680 over SPI, reset GPIO105,
and PM8350C supplies. Derive polaris registers, GPIO regions, regulators,
timings and firmware from its own live DT and vendor sources before adapting
hardware code.

Useful input details already reviewed:

- The kernel queues physical touch samples; an injected backboardd library
  registers virtual HID services and sends hand/finger events. Its service
  creation waits for the server's open notification and retries registration
  to handle an observed startup race.
- Digitizer events carry DisplayIntegrated/Built-In properties and retain the
  FromEdgeTip flag for a contact's lifetime. These provide comparison points
  if our kernel IOHID path receives physical reports but the UI ignores them.
- `inject_sb.c` defaults to dismissing the lock screen after ten seconds.
  Account for this when interpreting a demonstration of reaching home;
  physical input requires contact events and a corresponding UI response.
- The USB server belongs to a resident EFI loader using Qualcomm UEFI device
  protocols. Porting it requires loader, firmware, memory and CPU integration.

Polaris 0019 now receives physical S3330 reports and the user confirmed a
real swipe into the home screen. Its F01 command/status check was corrected
using the Synaptics specification and primary Linux driver. A later tap leaves
the screen covered by logs; application usability remains unproven.

For 0020, the reference's bounded selector logging and first-frame console
handoff are relevant. Our implementation retains its existing
`sweet_console_muted` gate after a valid CPU frame and preserves RAM logging
and panic output. Do not copy the reference's `PE_initialize_console()` call
into this platform: earlier bring-up found the associated read-only-late
console state unsafe to change. The logging budget is independently written;
AKS protocol replies, encryption, HID event semantics, foreign MMIO and
reference userland injection offsets are unchanged. `SWEET SURF sel 41` is a
logged success/no-op here, so its presence alone does not identify an App
failure. See `NOTES.md` for current evidence and validation.

## GPU correspondence now under review

Polaris0020 now reaches Settings after a delay and returns to home by a real
swipe; initial white screen was not a confirmed persistent rendering fault.
The human launch-time estimate is10–30seconds. Current rendering remains CPU.

The reference GPU is642L using `a660_gmu.bin` block records, with GMU/clock
and SMMU registers at different physical addresses. Original polaris630 uses
`a630_gmu.bin` as a flat code image, `a630_sqe.fw`, its own zap set, and the
HFI_USE_REG quirk. Nine relevant MiCode sources, including the original GPU
clock controller and GMU memory definitions, are pinned at
`c7cb50c18f812629b9620b2b8fa684bc40d82080` with verified Git blobs under
ignored `research/polaris/gpu-630-0001/vendor/`. Compare these with the
reference's `redwood_adreno.c`, Mesa bridge and Metal plugin as separate
hardware, submission and userland stages. See `POLARIS.md` for the actual
address map and current USB debug prerequisite. No accelerated rendering or
SSH connection has yet been established on polaris.

## USB debug versus SSH

The reference's `xl` drives a resident UEFI loader's fastboot-protocol server
in `xnuloader/loader.c:3411`. It supports logs, screenshots, stop and reboot.
`usb_start()` obtains Qualcomm USBDeviceProtocol through UEFI Boot Services.
Its kernel return trampoline is additionally gated on ARM_PGSHIFT12; our
kernel uses16KiB pages and the current LinuxImage shim does not retain UEFI
Boot Services. It requires a real loader/CPU/memory/cache integration port.
None of its foreign EFI prebuilts has been executed on polaris.

The userland `rc.jobs.ssh` starts Procursus OpenSSH with public-key login over
the reference's working Wi-Fi interface. It is a separate userspace/network
path. Current polaris0021 did not enumerate its attempted native USB ECM
interface; no RAM log connection or SSH is available yet.

## Future refresh

Check each reference checkout for local edits first. Fetching newer upstream
objects is read-only with respect to our phone and current project sources:

```sh
git -C research/reference-repos/hackios-xnu-kernel fetch origin
git -C research/reference-repos/hackios-xnu-userland fetch origin
```

Review changes against the pinned commits above before advancing the
checkouts. Record the new reviewed commits here and in `NOTES.md` when a
future adaptation depends on them. Fetching or consulting these sources does
not require running their setup/build/firmware-download scripts.
