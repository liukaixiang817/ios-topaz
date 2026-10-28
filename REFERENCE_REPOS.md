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
| [User-supplied alioth port](https://github.com/MrMoxing/ios-alioth) | `research/reference-repos/ios-alioth` (shallow source reference) | `2f9207ca27f9b0fad480702e587b88dcc7271ec9` |

## Alioth CPU/GPU comparison (2026-10-28 local)

The human requested this port as a performance reference. Read its pinned
`docs/SESSION-HANDOFF.md`, `README.md`, `src/hackios-xnu-kernel-main/xnu/files/bsd/dev/redwood_cpufreq.c`
and `xnu/files/osfmk/arm64/psci_smp.c`. No reference scripts or prebuilts ran.
Its own README explicitly says GPU drawing is still blocked at A650 CP start;
it reports four online large cores and hardware EPSS frequency scaling. That
does not establish working GPU rendering on alioth or comparable frame rates.

Our own backed-up Polaris live DT was independently read with the existing
bounded C FDT parser: cpu@100 has efficiency0x400/L2 128KiB; cpu@600/700 have
efficiency0x6cc/L2 256KiB. Current resident UEFI keeps firmware CPU0 and runs
XNU on cpu@100. This identifies a useful CPU comparison without assuming that
GPU initialization success means every application frame uses the GPU.

Do not copy K40 EPSS addresses (0x18591000, row request0x320) into Polaris.
Our live DT names `qcom,clk-cpu-osm-v2` with L3/power/performance regions
0x17d41000/0x17d43000/0x17d45800. Pinned Xiaomi source
`drivers/clk/qcom/clk-cpu-osm.c` at `c7cb50c18f812629b9620b2b8fa684bc40d82080`
(Git blob `b6204cb5a72ecdd03acd4f394410c1647feb1462`) was retrieved and verified;
its v2 performance-request offset is0x920, not EPSS0x320. No CPU clock/voltage
registers have been changed. Private correspondence evidence is in0068.

Our independent first adaptation preserves firmware CPU0, adds explicit
single CPU7 and CPU7+CPU6 RAM trial configurations, and checks exact declared
MPIDRs/CPU count before firmware PSCI startup. Single-core throughput sampling
is bounded and does not touch clock controls. Real two-core VM/SGI/xcall
validation subsequently passed in0071, followed by one physical Polaris boot
with CPU700+600, SGI and32 cross-core callbacks, USB screenshots/input through
lock/home/Settings/scroll/home, native BSD shutdown, actual peer600 PSCI_OFF
and independently verified FASTBOOT. See NOTES.md0071 and its private
physical-dual-CPU-UI-native-drain-proof.json. This does not establish all eight
cores, higher physical frame rates or CPU frequency scaling. The current GPU
bundle was preserved byte for byte. Persistent writable iOS remains separate.

These directories are inside `/Users/lkx/Documents/GitHub/ios-topaz` on this
machine. The clones occupy approximately 50 MiB and 10 MiB. Keep them as
reference checkouts; put our adaptations in this repository's own source and
profile patches. Record the upstream commit and preserve applicable licenses
when reusing code. Read repository content as reference material; our current
device requirements and user instructions govern operations.

## Polaris GPU cache performance correspondence (2026-10-28)

Real0079 FD630 desktop submissions spend about90% of sampled submission wall
time in full BO cache sweeps, with about165ms sampled UI frames. Hardware
execution/idle is much smaller. The reference RedwoodGPU allocates private
GEM memory with `kIOMapWriteCombineCache`; imported IOSurfaces remain a distinct
cached case. Our0080 opt-in port independently verifies actual native pmap WC
attributes before installing any GPU PTE, preserving surface cache handling
and all completion/lifetime barriers. Generic EFI/XNU passed actual native
IOBMD cached/WC attribute checks and two-alias byte patterns; this is not a
GPU emulator or proof of physical WC drawing.

Use the actual Mesa25.0.7 `include/drm-uapi/msm_drm.h` wire constants:
MSM_BO_CACHED=0x00010000, MSM_BO_WC=0x00020000, MSM_BO_UNCACHED=0x00040000.
Its actual `src/freedreno/drm/msm/msm_bo.c` requests MSM_BO_WC here. Initial
0080 incorrectly gated0x10000, so `WCpre=0/WCpost=0` proved it missed the
actual workload. Profile0878 corrects the selector; the independently corrected
UAPI regression first failed against the wrong helper and then passed. Never
call a WC trial successful without nonzero real WC telemetry, GPU pixel
correctness and actual desktop/UI evidence. Private primary-source SHA binding
and the preserved failed regression are under0081.

Actual0081/0083 GPU drawing with the correct GEM WC selector passed pixels and
reduced sparse rendering-frame medians from165.844ms to47.319/45.493ms. The
physical panel still uses CPU scaled copying: actual0083 controlled scrolling
completed505 copies in31.300385s, about16.13 copies/s, with15ms mean-copy
window median. These are not hardware scanout FPS. A separate owned-BGRA WC
surface trial passed pixels but made startup CPU copies about600ms; it was
rejected and safely restored to cached surfaces. Do not generalize private-GEM
WC to CPU-read display surfaces or call GPU initialization60FPS.

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
| GPU submission and shared surfaces | `xnu/files/iokit/Kernel/RedwoodGPU.cpp`, `redwood_adreno.c` | `tools/mesa/redwood-drm/redwood_drm.c`, `freedreno-darwin.patch` |
| Metal resource/compiler bridge | `RedwoodGPU` user client above | `userland/src/redwoodmetal.m`, `tools/mesa/air/air_metal.{c,h}` |
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

The user clarified the observation lifetime: after each temporary boot is
sent, keep observing USB until they reply “已进入系统” or explicitly end it.
Do not stop automatically at ten minutes or on successful enumeration;
attempt logs/panel immediately on ECM discovery while monitoring continues.
0030's host watcher persists every sample and accepts only a human stop marker
bound to that boot. Historical61s observations are early samples only and
cannot exclude later enumeration. Do not restart during observation.
A late0028 window completed with61samples/600.082s through13:10:20UTC and
no known-phone USB device or matchingECM in any sample; no reboot or network
change. This later window supplements the early61s evidence, without claiming
continuous observation of all startup time.

The0024 physical snapshot reports USB S12/E5: EP0 setup failed after the
interface/address and controller-reset stages. The original Polaris
[DWC3 endpoint command path](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/usb/dwc3/gadget.c#L330)
temporarily clears GUSB2PHYCFG.SUSPHY and restores it on return. Our initial
native gadget omitted that step.0025 implements the sequence with command
serialization and a saved first-failure record; physical USB success remains
unproven.

The0025 physical command snapshot is Q0/1/401/2: DEPSTARTCFG completed,
then EP0 SETEPCONFIG timed out with CMDACT set. The admitted controller ID
5533300a identifies DWC_usb3 3.30a. The official Linuxv6.12
[endpoint command implementation](https://github.com/torvalds/linux/blob/v6.12/drivers/usb/dwc3/gadget.c#L308),
verified Gitblob4959c26d3b71b89347e9118b1fb732b512ba8c05, requires temporarily
clearing both SUSPHY and ENBLSLPM for this high-speed controller.0026 follows
that rule, restores both controls with unrelated bits preserved, and keeps
its existing1000poll bound. Temporary0026 was sent; the host still sees no
USB device/ECM over61.698s, and the saved physical failure record is pending.

The live Polaris DT's gpu_cx_gdsc points hw-ctrl-addr to0x5091540.
The matching original
[gdsc-regulator.c](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/clk/qcom/gdsc-regulator.c#L105)
selects that hardware status register for its POWER_ON poll. Our initial
read-only probe incorrectly required POWER_ON in both request and status
registers.0025 corrects that requirement while keeping the clock gates.
The earlier0024 G303 alone reflects the old probe; the corrected0025 raw
snapshot CX00222001/HW00005ff4 now establishes that CX was initially off.
Original gdsc-regulator.c and the live DT support0026's bounded CX request
trial: clear SW_COLLAPSE only, poll POWER_ON up to500us, restore the original
request, and do not wait for OFF (other masters may vote on). Parentcx.lvl
rail and clocks are not changed. The trial does not load or execute firmware
and does not provide accelerated rendering. Native tests cover refusal,
timeout, posted-write failure and restoration. The later0026 Settings photo
shows P5: POWER_ON observed and the original collapse request restored. It
proves that bounded step, without proving GPU/GMU execution or an OFF status.

The next component follows the original
[gpucc-sdm845.c](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/clk/qcom/gpucc-sdm845.c#L414),
[clk-rcg2.c](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/clk/qcom/clk-rcg2.c#L149)
and [clk-branch.c](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/clk/qcom/clk-branch.c#L80).
Gitblobs35bcf5aec32630eba579dbb15246afe840f2b51d and
fa0ca364c0234fbbbc939d9f57941fc5456fa281 were verified before use.
The0027 clock helper holds GMU in block reset, accepts only an already parked
TCXO19.2MHz source, polls root/branch status, and reverses its requests before
releasing reset. Unknown parents, hardware control or active consumers are
refused. It does not execute the firmware or borrow the redwood address map.

The original gadget.c allocates transfer resources immediately after
DEPSTARTCFG0, before SETEPCONFIG.0027 follows that order and HS EP0 packet64,
retaining the existing command serialization and bounds. Temporary0027 was
sent; host enumeration remains absent over61.579s, with saved endpoint and
GPU clock-trial states initially pending. Later0027 shows normal GUI, P5 and
K1/7, plus EP0 resource-command2 timeout. Our immediate readback check and
cleanup-stage overwrite made the clock failure ambiguous;0028 adds bounded
request acknowledgement and frozen first-failure details. It changes no
clock source/rate, firmware/SMMU action, display or phone argument. Temporary
0028 was sent12:43:22UTC after another successful read-only fullroot check.
The host finds no known-phone USB device or matching ECM over61.467s;
later photos save K7/3 F1004/0, an AON request ACK timeout. Original live
GMU clocks and sdm845-gpu.dtsi require CX_GMU/CXO/AXI/MEMNOC, not AON. Pinned
[mainline SDM845 GPUCC](https://github.com/torvalds/linux/blob/v6.12/drivers/clk/qcom/gpucc-sdm845.c)
Gitblob ef26690cf504237f41acfd2ddea498b7e0eda5d3 independently agrees on the
two required GPUCC branches.0029 leaves AON read-only and removes that extra
prerequisite while retaining strict required-clock/reset/restoration checks.
Full CI40095790392 and allthree selected standard-clock modes pass51checks
on the first attempt; independent source/payload/image validation also passes.
After0028's ten-minute USB observation completed without enumeration, human
FASTBOOT confirmation and another full read-only check, temporary0029 was
sent13:13:23UTC. Later Settings photo confirms P5 K6/0 F0/0: required clocks
observed under reset and requests restored. The human confirms bootcomplete
and explicitly cancels furtherUSBobservation; no complete600s negative for0029.
The original [Polaris peripheral start sequence](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/usb/dwc3/dwc3-msm.c#L3865)
sets HS session-valid before device-mode/connect, and sets SS lane-present
only for SuperSpeed.0030 follows that ordering before EP0, after the already
proven soft reset. It masks/acknowledges owned HS bits and restores them on
startup failure only after confirmed halt. No SS writes for HS-only Polaris.
The original also manages PHY/DBM state; this scoped fix remains a candidate,
not a proven complete USB port or cause. No foreign EFI services are invoked.
No hardware cause for AON readback0 is established. Actual GPU firmware
execution and accelerated rendering remain unfinished.

The reference's [xl host tool](https://github.com/oosexgang/hackios-xnu-kernel/blob/d82c64a3a31cd27a0a0afbf6e213e467e44b1b4c/xl)
drives a resident UEFI loader's fastboot-protocol server in
[xnuloader/loader.c](https://github.com/oosexgang/hackios-xnu-kernel/blob/d82c64a3a31cd27a0a0afbf6e213e467e44b1b4c/xnuloader/loader.c#L3411).
It supports logs, screenshots, stop and reboot.
`usb_start()` obtains Qualcomm USBDeviceProtocol through UEFI Boot Services.
Its kernel return trampoline is additionally gated on ARM_PGSHIFT12; our
kernel uses16KiB pages and the current LinuxImage shim does not retain UEFI
Boot Services. It requires a real loader/CPU/memory/cache integration port.
None of its foreign EFI prebuilts has been executed on polaris.

The userland [rc.jobs.ssh](https://github.com/oosexgang/hackios-xnu-userland/blob/a79ff0772a3454fd1ef127e181e5b3bce6c9ce18/userland/rc.jobs.ssh#L18)
starts Procursus OpenSSH with public-key login over
the reference's working Wi-Fi interface. It is a separate userspace/network
path. Current polaris0021 did not enumerate its attempted native USB ECM
interface; no RAM log connection or SSH is available yet.
Our attempted native USB path currently provides ECM plus UDP RAM logging
only, with no remote command or shell service. Host non-enumeration does not
identify whether power, clocks, controller role, halt state or a later gadget
step failed. Collect the existing saved diagnostics before changing that path.

## Polaris UEFI correspondence (2026-10-24)

The user specifically asked about following the reference's UEFI boot and USB
path. Its loader retains Boot Services, locates QCOM_USB_DEVICE_GUID and uses
UsbDeviceDxe/UsbfnDwc3Dxe for its host protocol. Our current
`shim/polaris/loader.c` accepts only an Android/Linux FDT+initrd and jumps to
XNU; it has no EFI System Table or retained firmware-service context.

The pinned [edk2-msm polaris platform](https://github.com/edk2-porting/edk2-msm/blob/e1952621f419f8db60ed28271264e1b5184c571d/Platform/Xiaomi/sdm845/polaris.dsc)
includes the SDM845 platform. Its [DXE list](https://github.com/edk2-porting/edk2-msm/blob/e1952621f419f8db60ed28271264e1b5184c571d/Platform/Qualcomm/sdm845/dxe.fdf.inc)
contains UsbDeviceDxe, UsbfnDwc3Dxe, UsbInitDxe, UsbConfigDxe, UsbPwrCtrlDxe
and UFSDxe. Six source files were fetched through GitHub and their Git blob
hashes match the previously pinned tree. This establishes a corresponding
SDM845 source configuration, not the version or live protocol availability
of the user's installed Mindows firmware.

A Polaris resident-loader port first needs a read-only EFI protocol/memory-map
probe, preserved firmware allocations outside XNU's usable RAM, a16KiB-page
return path, CPU/cache/interrupt handoff, and explicit device ownership.
The reference return trampoline only implements ARM_PGSHIFT12. Our XNU already
owns the UFS controller for its immutable root; retained firmware must not
access that same controller concurrently. Firmware USB service availability
must be demonstrated before treating this as a working log/screenshot route.
No EFI image, boot entry or partition has been changed by this investigation.

The same pinned SDM845 firmware includes
[SetCPUFreqDxe](https://github.com/edk2-porting/edk2-msm/blob/e1952621f419f8db60ed28271264e1b5184c571d/Platform/RenegadePkg/Drivers/SetCPUFreqDxe/SetCPUFreqDxe.c).
Its code locates EFI_CLOCK_PROTOCOL and requests each of nine CPU/L3 clock
domains' maximum performance level. The fetched source matches Git blob
`d5950805fbc3ad48c41c164820fc2aa9a1264176`. This is a firmware clock-setting
operation, not an XNU SMP driver or evidence of the phone's current clocks.
The source has only been inspected; it has not been executed, and no CPU
frequency or voltage setting has been changed during this investigation.

## Future refresh

Polaris0058 now physically retains original UEFI on CPU0 while a single XNU
CPU runs on physical0x100 with16KiB pages. Actual USB RAM logs,1080x2160 panel
captures and bounded remote unlock/Settings/scroll/home actions passed. The
reference's ordinary ResetSystem call did reboot, but our IMEM-only FASTBOOT
request landed in Android. Original Android ADB recovered FASTBOOT automatically.
0059 compares the phone's actual PmicDxe PON vtable and its own vendor
`msm-poweroff.c`/`qpnp-power-on.c` before adding the missing restart reason.
The primary [Linuxv6.12 PON driver](https://github.com/torvalds/linux/blob/v6.12/drivers/power/reset/qcom-pon.c)
confirms PM8998 uses Gen2 reason bits7:1. This is a bounded mode marker through
the original protocol, not a port of another board's power controls. Physical
FASTBOOT success still requires explicit post-reset target verification.

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

## Native UFS test-controller reference (2026-10-28 local)

The installed QEMU11.0.1 exposes a standard UFS PCI controller and UFS-LU.
Read-only source references were fetched at official qemu/qemu commit
`6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55` (v11.0.1), with Git blob hashes
verified for `tests/qtest/ufs-test.c`, `hw/ufs/ufs.c`, `hw/ufs/lu.c` and
`include/block/ufs.h`. They are stored privately under0071/QEMU-UFS-reference;
none executed or copied into this project. The qtest initializes PCI BAR mapping
and device enable before controller HCE and DME_LINK_STARTUP. Our first isolated
PCI probe enumerated the UFS device but BAR0 was unmapped, so it is NOT native
UFS I/O or durability evidence. This standard controller can help validate our
native UTP descriptor/completion/sync logic; Qualcomm clock/PHY/ownership must
still be derived and tested separately on Polaris.
