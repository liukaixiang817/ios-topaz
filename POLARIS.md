# MIX 2S (polaris): preflight, not an installable port

The requested target is **Android + Mindows Windows 11 + iOS 16**, preserving
existing data and reserving about 64 GiB for iOS. The existing topaz installation
procedure does not satisfy this: it replaces `userdata`. No polaris XNU kernel,
boot image, iOS root or UEFI iOS entry has been built or tested here.

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
   roughly 227 GiB combined raw partition sizes. The critical backups already
   made cannot substitute for these user-data backups.
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
