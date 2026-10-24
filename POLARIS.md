# MIX 2S (polaris): current bring-up and safety constraints

The requested target is **Android + Mindows Windows 11 + iOS 16**, preserving
existing data. The current temporary build **0020** runs real iOS 16.7.16
(20H392) on the MIX 2S. The user confirms physical swipe into the home screen,
Settings content after a wait, and swipe back home. Settings launch currently
needs about 10–30 seconds by human estimate. Latency/FPS are not instrumented.
GPU acceleration, Wi-Fi, full App compatibility and a persistent UEFI iOS entry
remain unfinished. Read `NOTES.md` for the current source, image and handoff.

The 16GiB HFSX root file already exists inside Android userdata. Its base is
immutable; all logical iOS writes go into a 512MiB volatile RAM COW. Keep
`ufsrw=0`, use only temporary `fastboot boot`, and preserve every existing
Android/Windows partition and backup. Never replay or repair the outer
pending Android ext4 journal as part of a boot check.

## Current GPU and debug work

USB debug build0021 uses a separate versioned board node and `polarisusb=2`.
It checks the SDM845 USB power, clock and halted-device state before entering
the existing CDC-ECM code. It does not power up clocks or a PHY. Enumeration,
IP and RAM log reception still require an actual phone test; no SSH daemon is
installed. The macOS receiver is `tools/polaris-usb-log.py`; its plan mode
changes no network configuration. The debug profile disables repeated caller
stack sampling; the effect on App launch time has not been measured.

The GPU port is based on this phone's live DT and Xiaomi's original
[polaris GPU sources](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/tree/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/gpu/msm),
compared with the local HackiOS kernel and userland references in
`REFERENCE_REPOS.md`.

| Polaris component | Physical range / requirement |
| --- | --- |
| Adreno630 | DT chip ID `0x06030001`; registers `0x05000000` / `0x40000` |
| GPU clock controller | `0x05090000` / `0x9000` |
| GMU / power sequencer | `0x0506a000` / `0x30000`; PDC `0x0b200000` / `0x300000` |
| GPU SMMU | `0x05040000` / `0x10000` |
| Original firmware | `a630_gmu.bin`, `a630_sqe.fw`, `a630_zap` image set |

The reference boots an Adreno642L with a660 block firmware and a different
GMU memory layout. Polaris's original driver loads a flat A630 GMU image and
its DT enables the HFI register quirk. Port power/clock admission, firmware
mapping, HFI, SMMU, secure zap loading, command completion and the Mesa bridge
in that order, verifying each stage. An advertised GPU service by itself
would not establish command execution or accelerated iOS rendering.

The initial A630 HFI component is implemented in
`tools/polaris-a630-hfi.h`: original queue table layout, command packing and
bounded wraparound command/response rings. An independent wire fixture and
ASan/UBSan check pass; the helper also compiles against actual XNU ARM64
headers. It is not linked into build0021. Device cache maintenance, GMU
startup, SMMU mappings, doorbells and GPU command execution remain to be
connected and tested before the Metal/Mesa userland bridge can accelerate Apps.

Original GPU firmware collection is staged for the next known headless
recovery session. It reads only the GPT-pinned vendor partition through a
read-only, noload mount, compares hashes, and unmounts without repair. Raw
firmware and device sources stay in ignored `research/polaris/gpu-630-0001/`.

## Standalone boot diagnostic 0001

An isolated polaris probe now cross-compiles and passes QEMU checks. It reads
the CPU feature registers, checks the supplied FDT's model/SoC/splash range,
draws a 1080×2160 framebuffer console and parks. **It does not boot iOS.**
No disk driver, XNU loader, SCSI command, persistent log or power-control code
is linked. A non-polaris tree is refused before framebuffer writes.

```sh
python3 tools/build-polaris-probe.py --zig /path/to/zig \
  --mkbootimg /path/to/AOSP/mkbootimg.py --dtb /path/to/verified/live.dtb
python3 tools/qemu-polaris-probe.py --qemu /path/to/qemu-system-aarch64 \
  --dtb /path/to/verified/live.dtb
```

The builder uses Clang for `aarch64-none-elf` with general-register-only code,
Zig 0.15.2 for the ELF link, and the AOSP Android 10 mkbootimg for boot header
v1. It rejects absolute relocations in allocated C sections, validates the
Linux Image header, and compares the packed kernel and ramdisk with inputs.
The empty ramdisk has no executable init. The device's verified DTB is appended
to the Image. On hardware, fastboot accepted this raw image but the user saw
a black screen; execution and scanout were not established by that attempt.
Outputs are ignored under `shim/out/polaris-probe-0001/`.

QEMU's Cortex-A76 runs the actual Image from RAM with FP/SIMD disabled. The
matching-tree case must show the expected console and parked state without
exceptions; the wrong-board case must leave framebuffer RAM untouched. This
does not emulate Qualcomm ABL, XPUs or the physical display.

The framebuffer address (`0x9d400000`), size (1080×2160), stride (4320) and
a8r8g8b8 layout are corroborated by `polaris.dsc`, `sdm845.dsc` and
`SimpleFbDxe.c` at upstream edk2-msm commit
`e1952621f419f8db60ed28271264e1b5184c571d`. Actual scanout still needs an
on-device observation.

## Automatic entry-register capture through recovery

`tools/build-polaris-linux-probe.py` adds a small wrapper to the hash-pinned,
previously verified headless recovery. It records CPU registers into a fixed
112-byte property in the in-memory FDT, then resumes the original Linux entry.
Only the original Image's entry branch and advertised size change; the rest
of its original bytes and the headless ramdisk are preserved. Each of the
65 appended DTBs gets the preallocated property. No flash command is included.

```sh
python3 tools/build-polaris-linux-probe.py --zig /path/to/zig \
  --fdtput /path/to/fdtput --mkbootimg /path/to/AOSP/mkbootimg.py
python3 tools/qemu-polaris-linux-probe.py --qemu /path/to/qemu-system-aarch64 \
  --fdtput /path/to/fdtput --dtb /path/to/verified/live.dtb
```

QEMU checks the actual wrapper, the original branch target, preservation of
x0..x3/SP, exact FDT write boundaries, and unchanged FDT on wrong-board or
bad-marker inputs. The original Linux entry is parked in this test.

The temporary hardware boot **returned to root ADB automatically**. The raw
entry registers were EL=4 (EL1), MIDR=0x517f803c, MPIDR=0x81000000,
MMFR0=0x101122, MMFR1=0x10212122, PFR0=0x11112222, SCTLR=0xc00800,
CNTFRQ=0x124f800 (19.2MHz), DAIF=0x1c0. MMFR0 confirms 16KiB granule support.
The property is readable at
`/sys/firmware/devicetree/base/chosen/polaris,boot-registers`.
This establishes CPU entry conditions; it does not establish a working
framebuffer or an XNU/iOS hardware boot. Logs remain in ignored `research/`.

`tools/package-polaris-ram-boot.py` packages a reviewed shim with the same
gzip format, original 65-DTB table, text offset and boot options as the working
headless recovery. It verifies the packed bytes, decompression and unchanged
DTB table. It accepts an explicit ramdisk (empty archive for diagnostics or
validated RAM payload for the XNU loader). It contains no phone commands;
packaging alone does not establish execution or display on hardware.

Diagnostic0002 using this packaging displayed diagnostic text on the actual
MIX 2S (user observation). The exact cause of the first raw-image black screen
is not isolated because gzip, DTB table and header fields changed together.
This establishes shim execution and framebuffer output. A subsequent pure-RAM
XNU boot reached static PID 1 on hardware and repeatedly printed its heartbeat.
The test program occupies `/sbin/launchd` in mockfs; it is not Apple launchd.

## Full OS partition backups

```sh
python3 tools/polaris-backup.py mindowswin --adb /path/to/adb --jobs 4
# userdata is permitted only when unmounted in an offline root recovery:
python3 tools/polaris-backup.py userdata --adb /path/to/adb --su none --jobs 4
```

This reads 4 GiB chunks in parallel and streams gzip to ignored `backup/`.
It checks gzip integrity and raw length, then hashes the concatenated raw
contents in order and compares with a fresh SHA-256 of the original phone
partition. Only then does it remove `.partial` suffixes and mark the manifest
verified. Mounted target devices are refused. These commands do not enter
recovery or mount/unmount anything themselves. Do not reboot or switch OS
until the backup and source verification finish.

Windows is fully backed up and verified: 128534437888 raw bytes,
31879606683 compressed bytes, whole raw SHA-256
`f0bef9ef67242a445a401eaf27d3f19328bedcb85e8ec97887a2162f37950d0a`.
The local manifest is under `backup/polaris-full-mindowswin-20261023-195539/`.
Android userdata is now fully verified too: 115167178752 raw bytes,
21389839339 compressed bytes, whole raw SHA-256
`b1af42b854345e101854dcccab182928512c9f749542da89fc1100aa2303dd97`.
System, vendor and cust are also fully backed up with matching source hashes.
The local `backup/polaris-recovery-index-20261023.json` lists all manifests.
Together the five full partitions are 236.78GiB raw /52.46GiB compressed.
Gzip chunks represent ordered raw byte ranges, not Android sparse images;
reconstruct in manifest order and verify the whole raw hash before any restore.
Keep these device-specific files private.

## Read-only collection

With Google platform-tools and existing Magisk access:

```sh
python3 tools/polaris-preflight.py --adb /path/to/adb --backup-critical
```

This checks for a single USB-connected `polaris`, reads the live device tree,
backs up both GPT regions of all six UFS disks, validates both header and array
CRCs, checks for overlaps and reports unallocated ranges. It also saves small
boot LUNs, boot/recovery/dtbo/ABL, calibration partitions, modem and the Mindows
ESP. Every binary file must match a second SHA-256 computed on the phone before
it is promoted from `.partial` to a verified backup.

Old MagiskSU creates a PTY under `adb exec-out`; raw terminal mode and redirected
`dd` statistics are essential for binary integrity. Initial live trials caught
both newline conversion and merged statistics, and rejected those incomplete
files. The successful collection passed size and remote hash checks.

Output stays under ignored `backup/`; never commit it or its device tree. The
tool contains no partition writes, mounting, filesystem repair, reboot or flash
operation. **It does not back up Android or Windows user data.** A mounted,
changing filesystem is not a consistent raw backup; full OS backups need an
offline recovery/Windows workflow and a separate destination.

Host-only GPT checks:

```sh
python3 -m unittest discover -s tools/tests -p 'test_polaris_preflight.py' -v
```

## Observed on the connected MIX 2S, 2026-10-23

| Item | Observation |
| --- | --- |
| Android | Android 13, kernel 4.9.336, unlocked bootloader; Magisk at `/debug_ramdisk/su` |
| Android data | ext4, file encryption, about 18 GiB used / 86 GiB available |
| UFS | Six disks, 4096-byte logical blocks; sysfs `start`/`size` use 512-byte sectors |
| `userdata` | `sda22`, 107.258 GiB, GPT LBAs 33161216–61278202 |
| Mindows ESP | `sda23`, 0.293 GiB, GPT LBAs 1703936–1780736 |
| Mindows Windows | `sda24`, 119.707 GiB, GPT LBAs 1780738–33161215 |
| Free partition space | Largest gap on `sda`: 4096 bytes; no existing 64 GiB iOS partition |
| Existing boot / recovery | Android boot header v1, page size 4096; current shim build uses v4 |
| CPU DT `reg` values | `0x000`, `0x100`, …, `0x700`; PSCI via `smc` |
| GIC DT ranges | `0x17a00000 + 0x10000`, `0x17a60000 + 0x100000`, stride `0x20000` |
| Timer DT | 19.2 MHz; virtual timer INTID 19 |
| UFS DT range | `0x1d84000 + 0x2500` |
| Memory DT ranges | `0x80000000 + 0x100000000`, `0x180000000 + 0xfc8a0000` (reserved regions still require analysis) |
| Splash reservation | `0x9d400000 + 0x2400000`; this is a reservation, not proof of the scanout address/stride |
| Selected display | Kernel command line selects `dsi_jdi_fhd_nt35596s_video_display` |

The repository currently hard-codes different GIC/UFS/framebuffer addresses,
CPU topology and memory ranges in the shim, ADT builder and kernel patches.
Copying one of these values alone does not produce a working port. The
repository's recovery history also reports GPT loss after past iOS UFS writes
on topaz; the later guard patch does not establish safety on polaris.

## Remaining work, in order

1. Obtain and verify complete Android and Windows data backups before any
   storage migration. The current Mac has about 103 GiB free, less than the
   roughly 227 GiB combined raw partition sizes. A later macOS Important Usage
   capacity check reported about 499.5 GB including reclaimable space, matching
   the user's screenshot; compressed backups can proceed. The critical
   backups already made cannot substitute for these user-data backups.
2. Implement an isolated polaris shim/platform configuration. Verify reserved
   RAM, framebuffer format/stride and bootloader handoff from the actual device;
   do not reuse topaz's Gold-core handoff or its appended-v4-image assumption.
   First tests should be temporary RAM boots, without UFS writes or persistent
   disk logs. Then port XNU CPU/GIC/display/input and validate with RAM roots.
3. Validate the UFS driver read-only on polaris and review every write path,
   DMA bound and selected-root bound. A future root must be explicitly named
   `iosroot`, with no fallback to `userdata`. Boot arguments alone do not port
   a driver. Validate GPT copies before and after every trial.
4. Only after a working port and backups, propose an offline ext4 shrink of
   Android (or a Windows-native NTFS shrink) and a separate 64 GiB `iosroot`.
   Free space inside a filesystem is not GPT-unallocated space. Never reduce
   a GPT boundary before shrinking and checking the filesystem inside it.
   Present exact boundaries and obtain the user's confirmation before any
   shrink, GPT edit, format or image write. No resize plan is approved yet.
5. Build and validate the iOS root and test it with temporary boots. Investigate
   the installed Mindows UEFI version and its supported loader mechanism
   before designing a persistent third boot entry. Preserve the current ESP,
   BCD, Android boot/recovery and firmware.

Hardware source references for future work:
[Xiaomi polaris kernel](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/tree/polaris-o-oss)
and [edk2-porting firmware](https://github.com/edk2-porting/edk2-msm).
These are references; the installed Mindows UEFI version has not been identified.

## First XNU build profile (CI and QEMU pass; no hardware result)

GitHub Actions now accepts `target_platform=polaris`. This stages sweet's
0001–0079 baseline plus the isolated polaris overlay, excluding topaz's drivers
and CPU assumptions. It remains the `SWEET` machine configuration internally,
with a `POLARIS_RAM_ONLY` compile flag that refuses UFS initialization before
mapping registers. The overlay selects Kryo 385/platform personalities and an
explicit Cortex-A75 ARMv8.2 compiler target to avoid Apple CPU defaults.

The splash starts 20 MiB into a 32 MiB translation block. Its early mapping
therefore retains the aligned physical block at `0x9c000000`, with pixels and
the final virtual alias offset by `0x1400000`. Replacing the block descriptor's
base with `0x9d400000` would be invalid. Console height is 2160.

`tools/mkadt-polaris.py` produces a single-CPU RAM-root ADT for the observed
8GB phone, using the upper bank at `0x180000000 + 0xfc8a0000`. It publishes no
UFS/WLAN/display-service nodes. `--qemu` substitutes the emulator GIC/timer.
Bus and memory frequency fields inherited from the scaffold are compatibility
placeholders, not measurements. CPU0's 1.7664 GHz maximum was read from Linux.

Patch hunks have been checked against source reconstructed through 0079, and
host tests cover profile isolation, ADT serialization and mapping bounds.
The first CI run is [39933084495](https://github.com/liukaixiang817/ios-topaz/actions/runs/39933084495),
commit `b50a1063fe9d1734bc341d676c4689c0b0facb47`; **successful**. The
17485224-byte arm64 kernel SHA-256 is
`30a8a7502adb35d6d1d6b4dbdf54b2d7b4864fbce39cb203cfa6d7de60eda2b6`.
The CI log confirms the overlay and compiler flags. Disassembly confirms the
UFS root-device entry calls printf and returns ENXIO without controller access.
No XNU hardware validation has happened.

Use `tools/qemu-sweet.py PAYLOAD OUTDIR --platform polaris --qemu /path/to/qemu
--nm /usr/bin/nm --kernel MATCHING_KERNEL` with the **QEMU** polaris ADT.
This selects the 1080×2160 framebuffer at 0x9d400000 for both boot arguments and
snapshots. The runner sizes emulator RAM to cover the payload’s upper bank.
A host ABI check covers the 64-bit addresses above 4GiB and video fields.
Both direct loading and the actual new polaris shim reach **PID1** with the
static RAM init and repeated five-second heartbeats in 150-second QEMU runs,
with zero undecodable glyphs and no visible panic. This tests a synthetic
init, not Apple launchd or an iOS GUI.

## Offline Android backup image

`tools/build-polaris-backup-recovery.py` accepts only the official polaris
TWRP 3.7.0_9-0 image with SHA-256
`54905f7abae89b345c4b1a03d12fe74c1ff06cf5aa41119f1a7228dc22765ea0`.
It preserves its kernel and archive metadata, retains property symlinks and
replaces only `init.rc` and the regular property file. Only ueventd and root
adbd are started; no recovery UI, factory-reset job, persistent filesystem
mount or filesystem repair is configured. Root ADB is temporary to this image.

The resulting ignored `shim/out/polaris-backup-recovery/` image is for
temporary RAM boot only. Host archive/configuration checks passed. On 2026-10-23, fastboot temporarily
booted the image (61896KB sent, booting OKAY, 1.543s); root ADB works and
mountinfo confirms no persistent block filesystem is mounted. The full
107.258GiB userdata backup completed successfully with a matching fresh
whole-partition source SHA-256; no filesystem was mounted during either read. Keep the official image and backups
local; do not distribute the downloaded recovery binary through this repo.

## Bounded RAM loader core

The separate `shim/polaris/boot.c` + `loader.c` + `payload.c` core reads the
v1 `/chosen/linux,initrd-start/end` properties without scanning. It validates
all payload source/destination/ADT/boot argument bounds before copying,
requires the observed upper bank, and rejects overlap and invalid entry points.
The handoff checks CPU0, EL1, caches/MMU off and the 16KiB granule. No storage
code is linked into this loader. The kernel itself must also be the verified
polaris RAM-only profile; a loader cannot make an arbitrary kernel safe.

```sh
python3 tools/build-polaris-ram-loader.py --zig /path/to/zig
python3 tools/qemu-polaris-ram-loader.py --qemu /path/to/qemu-system-aarch64
```

The builder currently emits only an ELF and Image for emulator testing, with
no ready Android boot image or XNU kernel. The QEMU cases use a synthetic
parked entry: one proves the copy/BSS/boot_args layout above4GiB; another proves
an out-of-bounds segment leaves destination RAM unchanged. Both pass without
exceptions. Neither is an XNU/iOS boot or hardware test.

Actual shim integration can be tested with `qemu-sweet.py --platform polaris
--loader-image shim/out/polaris-ram-loader/Image --linux-dtb INPUT.dtb` plus
the normal payload/kernel arguments. Copy the verified Linux FDT and set its
`/chosen/linux,initrd-start/end` to the raw payload at0x84000000. In this mode
QEMU does **not** preload the kernel destination: the real shim validates,
copies and jumps. The successful integration result is under ignored
`research/polaris/qemu-xnu-loader-0001/`.
