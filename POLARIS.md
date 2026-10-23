# MIX 2S (polaris): preflight, not an installable port

The requested target is **Android + Mindows Windows 11 + iOS 16**, preserving
existing data and reserving about 64 GiB for iOS. The existing topaz installation
procedure does not satisfy this: it replaces `userdata`. The first polaris XNU
kernel builds and runs a static test init in QEMU. No XNU hardware boot,
iOS root, iOS GUI or UEFI iOS entry has been tested on this phone.

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
to the Image; ABL acceptance of this raw uncompressed image remains untested.
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
Android userdata is still in progress; do not reboot during backup.

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
107.258GiB userdata backup is in progress, and must pass a whole-partition
source SHA-256 comparison before it is marked verified. Keep the official image and backups
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
