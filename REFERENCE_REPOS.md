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
| [User-supplied UniXNU](https://github.com/UniXNU/UniXNU) | `research/reference-repos/unixnu-audit` (selected pinned source audit, not a full clone) | `40d21cc65171c3a24faa130a2a8e899f85790485` |
| [User-supplied Mi 8 port](https://github.com/youzjuzi/dipper-xnu) | `research/reference-repos/dipper-xnu` (shallow source reference) | `e930c26c4303283d7f2f5fc87479946d46409783` |

## Dipper / SDM845 comparison (0109)

The human requested this reference for display, touch, GPU, networking and its
fuller iOS version. Read the pinned README, STATUS, VALIDATION, BUILD, INSTALL,
upstream locks, licensing and all relevant patch sections. Its 45 published
checksums and 35 independently extracted added text files match its manifests.
No reference setup/build script, binary, firmware or device command was run.
Private evidence is under `research/polaris/uefi-ios-0109`.

Its stated development results include A630 desktop drawing and WCN3990 Wi-Fi
with Safari. Its STATUS/VALIDATION explicitly distinguish those historical
results from public-package reproducibility; audio is not complete. It still
reports stutter and GPU-SMMU/modem restoration issues. Treat this as source
correspondence, not a verified drop-in image or proof our port has those features.

- Display: dipper's EA8074 **OLED command-mode** panel uses DCS 0x51/0x28/0x29.
  Polaris's own live DT identifies **JDI NT35596S video-mode LCD + PMI8998 WLED**.
  Its brightness/lock-screen DSI writes cannot switch our LCD backlight. Dipper's
  TE timings, 2248-line counter, DPU pipe/scaler addresses and splash allocation
  also require independent own-panel/memory ownership evidence before any port.
- Touch: dipper's ST FTM5 on I2C0x49 / SE14 differs from our verified Synaptics
  RMI F01/F12 on0x20. Preserve the working Polaris discovery, geometry, release
  handling and transport. Do not replace it with dipper GPIO/regulator/reset data.
- GPU: same A630/Freedreno family; partial damage tracking and frame completion
  are useful design references. Its sysmem rendering does not validate a sysmem
  switch in our currently GMEM-tested bundle. Keep the proven pixels, cache,
  authentication, ownership, unknown-DMA retention and native shutdown guards.
  Do not import its GPL initialization tables or weaken our recovery to match it.
- Wi-Fi: the useful path is SMEM/GLINK -> QRTR/QMI WLFW69(decimal,0x45)/v1 ->
  ath10k SNOC. Our own c7cb50c1 `glink_smem_native_xprt.c` independently confirms
  descriptor478 (32 bytes), FIFO479/480 and cached-first RX lookup. New
  `tools/polaris-glink-inventory.h` extends our existing read-only SMEM inventory
  with bounded allocation-header traversal, padding/duplicate/overlap checks and
  exact metadata rereads. This is an offline component, not a mapped transport,
  SMEM write permission, DSP startup or radio/scan/join success. Dipper's observed
  QMI settings and calibration assumptions must be checked against our ICNSS and
  factory files; do not copy a synthetic chip identity or omit board data by fiat.

The recommended user space is **iOS16.5 /20F66 /iPhone10,3 or10,6**. We obtained
BuildManifest.plist by a partial download from Apple's original restore URL;
version/product types and these three paths match dipper's documentation:
`096-04088-077.dmg` (OS), `096-04666-078.dmg` (OS cryptex),
`096-03536-083.dmg` (App cryptex). Component preparation is private/offline.
The current20H392 injector/QuartzCore UUID and vtable checks MUST be rediscovered
for20F66; XNU8796 family alone does not prove ABI compatibility. Keep our custom
Polaris kernel/DT, UEFI USB/control and existing root unchanged until a separate
compatible RAM candidate is verified. Its destructive darwin/GPT installation
recipe is outside this phone's data-preservation authorization.

0110 completed the offline input preparation: the OS, both cryptex images and
kernelcache whole SHA384 match Apple's BuildManifest. A native macOS UDRO
conversion followed by bounded raw/ignored-run export produces the documented
5628755968-byte APFS root. Its used-run CRC matches the UDIF table, and the
root+OS-cryptex+App-cryptex concatenation matches dipper's published
`9efb156f417e32b6f92d709af33c0e8e584693c3fbd29eaf139b57eee3735560` exactly.
This establishes byte correspondence of the complete three-part source package,
not a bootable Polaris image, ABI compatibility or an installation. Our current
kernel is xnu8796.141.3; theirs is8796.121.2. No proprietary files enter Git.

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

## Frame-clock reference scope (0105)

The HackiOS userland reference implements `ca_vbl=1` in its legacy `inject.c`
by setting `CA_FORCE_TIMER` before CoreAnimation initializes. Our actual
graphics builder compiles `polaris-inject.c`; at0105 it contained neither this
option nor those old window-server vtable hooks. Adding the legacy boot argument
alone could not activate that reference path. Do not copy its function addresses:
the current20H392 cache has different IOMFBDisplay/EAGLServer targets.

Read-only inspection of our actual QuartzCore20H392 (UUID
9E40B2EB-260C-3AF1-AE45-A1A551A8C1B9) confirms the `CA_FORCE_TIMER` string and
the `CADeviceUseVBL` environment branch. This is an ABI/source observation,
not evidence of the branch selected by the running compositor. After0105
measured the GL-library tail and pre-frame API work as small, separately
validate compositor preparation, clock/callback timing and native display
publication before choosing a clock-policy change. Keep GPU completion and
memory-lifetime barriers intact.

The independent0106 candidate implements the exact scoped `ca_vbl=0|1`
environment choice in `polaris-bbd-wrapper.c`, after pixel acceptance and before
exec, plus a read-only target-UUID/code/bounds-checked observer in the actual
injector. Its fixed state/once addresses were independently decoded from the
current20H392 block, store and separate load sites. It does not install the
reference window-server hooks, alter native display deadlines or establish
phone performance before a physical A/B trial.

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

## Own SD845 OSM inventory and bounded performance candidate (2026-10-28)

Actual0087 read-only hardware inventory succeeded after exact payload argument
binding was fixed. Own performance bank0x17d45800 reports enabled3, shared
CORE_DCVS_CTRL0,27LUT rows and initial shared request0 (nominal825.6MHz).
Row22 is the highest normal FOUR-core entry at2649.6MHz. Rows23..26 are
ONE-core boost entries; do not request them for the four online big cores.
This snapshot precedes secondary startup. A request/counter is not a claim of
instantaneous UI-load frequency; raw evidence and the viewed lock screen are
bound in private0087/physical-stock-OSMv2-readonly-proof.json.

Pinned own `clk-cpu-osm.c` uses offset0x920 plus a posted enable-register read
for performance-state requests. Its perfcl parent has no separate software
vdd_class (unlike its little/L3 parents); do not transplant a K40 PLL, voltage
vote or EPSS write. Profile0885 independently implements an explicit default-OFF
RAM candidate that only writes the big-cluster request, choosing verified
normal4 row22. It restores saved0 after250ms idle, caps continuous high request
at30seconds followed by10seconds at the saved request, and requires native
shutdown restore/readback before any peer powers off. Existing LUT/PLL/voltage,
thermal configuration, little-cluster/firmware core and storage are untouched.
This bounded policy does not establish temperature protection, actual higher
frequency or60FPS until physical measurements pass.

## Full-frame and stock CPU comparison (2026-10-28)

Physical0090 steady Settings scrolling completed552 consecutive full EAGL
frames, median37.2235ms, all over16.667ms. Twelve matched native windows
with479 frame completions show7.405 submissions/completion and aggregate
window ratios of3.163ms pre-cache,16.127ms submission,3.154ms post-cache.
Execute/idle15.651ms is a subset of submission wall time, including polling
and preemption, not a hardware busy counter. All27 CPU-request observations
under this actual workload remained index0 (nominal825.6MHz).

The same kernel/GPU/ADT/four-core RAM A/B with the bounded original-table CPU
request policy completed585 frames at34.639ms median, a6.943% reduction;
panel-copy mean-window median fell15.745->14.114ms. Submission remained
16.116ms. This excludes CPU clock requests as a sufficient fix for60FPS.
Actual native shutdown restored saved request0 before all three peers really
powered off; actual Polaris FASTBOOT was independently verified. It does not
establish all-seven-core performance, instantaneous CPU frequency, repeated
benchmark stability or60FPS. Raw cooldown/idle transitions were retained.

The current A630 native post-start path still requests performance index1
(257MHz in our original-device HFI table) and bandwidth index4
(1200000KB/s). Compare `tools/polaris-a630-post.h` and `tables.h` against the
pinned original `adreno_a6xx.c:a6xx_gmu_dcvs_nohfi` and `kgsl_gmu.c:gmu_dcvs_set`
before a bounded factory-table GPU/bus trial. Those constants are configured
requests, not a live frequency measurement. Do not copy a newer reference
GMU/EPSS protocol, remove completion barriers, or assume maximum votes fix
all14ms of final CPU scaled copying.

The native serial console truncates single records at255 bytes without
synchronous drain. The long full-stage record therefore lost postcheck/byte
fields. Intact prefixes and METHOD counts were independently matched, but
full core decomposition is explicitly unproven. The host parser now rejects
missing or duplicate fields. Split future stage records below that bound
rather than treating missing timing as zero.

## Live GPU clock diagnostics (profile0887)

The native observer runs only after successful completed desktop submissions,
under the same existing GPU lock and explicit performance diagnostics. It
reads the original GMU request/return mailboxes and two fixed GPUCC snapshots;
no arbitrary offsets, writes, clock changes or counter programming are exposed.
The host requires full read masks, matching timestamp groups, stable PLL/RCG
state, a known original parent and a locked/running Fabia PLL. It follows the
pinned MiCode16-bit fraction, post-divider and RCG HID integer rounding order.
A configured clock inferred from these registers is still not instantaneous
frequency, utilization or proof a request has been executed. A configured rate
below its requested floor remains explicitly distinguishable.

All native diagnostic records now fit255 bytes including newline, even with
maximum-width integer fields; split parts require matching identifiers and
no omissions/duplicates. The actual native C++ formatter has been compiled
under sanitizers and its output consumed by the host phase analyzer. These
synthetic callback inputs validate the protocol, not physical GPU performance.
Kernel source972b065/full CI40660265209 adds this observer; physical results
must be checked in NOTES.md before claiming a live GPU frequency.

## Original Polaris buttons, Wi-Fi and audio correspondence (2026-10-28)

For physical keys consult the reference redwood_buttons.c only for the input
architecture. Own saved DT and MiCode c7cb50c18f812629b9620b2b8fa684bc40d82080
drivers/spmi/spmi-pmic-arb.c (blob15fb561ca224d11fce6f65929724a83870708324),
drivers/pinctrl/qcom/pinctrl-spmi-gpio.c (blob164ed1aa96e18ed0ff22fcf4770fe6b1b7d573e9)
and original qpnp-power-on.c govern the actual addresses and status bits.
PM8998 SID0 PON0800 RT bits0/1 are power/volume-down; volume-up DT specifier6
is ONE-based physical GPIO6 atc500, active-low, confirmed by its pinctrl
node's literal gpio6 and original of_xlate/gpio_idx implementation. The first
zero-based GPIO7 interpretation was rejected before hardware access. Redwood's
PON1300/PMK8350 and SID1/PM7325 mapping is incompatible. Derive512 v5 APIDs
from our1100-byte core resource; do not copy a reference FEATURES assumption.
First0095 actual firmware reads identified arb50000000, PON APIDac with
type/subtype0104 and GPIO6 APIDbe with1010. A wrong guessed PON type08 was
rejected before GPIO config/status reads. The corrected strict identity is
type01/subtype04, and metadata/RT checks now run before CPU_ON so refusal can
remain in controlled UEFI without booting iOS. The actual key presses/HID/UI
responses still have not passed a physical test. No PMIC configuration is
written; only observer READ command words are emitted.

Own Wi-Fi is ICNSS18800000/SNOC/stream40 with12CE interrupts, not Redwood's
WCN6750/WPSS/ath11k. Original drivers/soc/qcom/icnss.c blob
649d0ff9a41d8b250f0951eba75a25f0a1c04e74 is saved/verified privately. Actual
WLAN firmware identity, original QMI/SMEM/GLINK/calibration and association
remain to implement. Own audio is SDM845 Tavil SLIM/NGD171c0000 plus TAS2559
I2C4c and TAS2560I2C4d onGENI894000; reference PCM wrappers do not initialize
these devices. The verified own audio-card source is
techpack/audio/asoc/sdm845.c (blob4b74f55b9fecca122c74bef72cb692931155f410),
not sound/soc/msm/sdm845.c. Speaker output uses the ADSP quaternary MI2S DAI
msm-dai-q6-mi2s.3 to tas2559 ASI1; Tavil SLIM alone is insufficient. Preserve
original firmware/calibration/routing; neither
audio playback nor Wi-Fi scan/join has passed a physical test yet.

## Polaris ICNSS wire codec validation (2026-10-29 local)

The independent `tools/polaris-wlfw.h` is only a bounded capability-message
codec. It does not initialize WLAN, discover a service, authenticate a remote
port, map DMA, scan or join. The actual original MiCode codec at Git blob
`d7221d8982388ea3f12bddde1c2956fec46e75d7`, full WLFW descriptor blob
`96e7d6891cc381ea9c21172b8688bd242ce1d310`, and common response descriptor
from `qmi_interface.c` blob`0b952a48a33e77c41f6224207238e074525bfde0`
were privately compiled unchanged, replacing only the Linux host environment.
Ninety-six optional-field and string-length combinations matched under
ASan/UBSan. The first harness incorrectly supplied capacity249 to an original
message declared max203; its rejection was retained, and only the harness
was corrected. The production independent decoder also rejects missing or
duplicate result fields, stale transactions and malformed nested strings.
The example chip IDs in those tests are synthetic, not a measured chip ID.

Own pinned `smem.c` blob`18ec52f2078aab2b27d0675ced0158908b4275ea` and
`glink_smem_native_xprt.c` blob`187c80d8ca121e6316c4ac5e901dff13b120427b`
are available privately for the next transport work. Own DT SMEM is86000000,
2MiB with the original IRQ doorbell at1799000c; do not copy Redwood's IPCC
408000 or WPSS host13. No SMEM/GLINK writes or radio firmware boot have been
performed by this codec. Actual raw source identities and test artifacts are
under0095/own-vendor and0096/wifi-codec-primary, outside Git.

The same pinned tree contains two SMEM APIs. Its original GLINK transport
includes `soc/qcom/smem.h` and calls `smem_alloc` / `smem_get_entry`, supplied
by `CONFIG_MSM_SMEM` -> `msm_smem.c` (blob
`1bbd7514188f82a7b4404c51ee7da7f83fbd82c5`). The separate `CONFIG_QCOM_SMEM`
uses `smem.c` and `qcom_smem_get`. Compare the former and the original
`SmemDxe` before implementing the transport. Do not infer the active binary
configuration from a filename: the guessed `polaris_defconfig` path was absent.

A known RAM recovery read68 original WLAN/audio files without writes; whole
vendor/modem partition hashes matched before and after, vendor also matched
its original4GiB backup, with all GPT/critical/ESP baselines unchanged. The
actual `wlanmdsp.mbn`, board variants, ADSP segments, TAS firmware and left/right
configuration plus ACDB are private under0096. The TAS2559 image header and
size match the pinned original parser. This is source/format correspondence,
not execution, association, speaker playback or a live radio chip ID.

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

## Complete physical submission phases (0092)

Short timestamp-bound records now give complete native decomposition. Of
15.847ms submit wall time per completion,15.418ms is execute/idle polling;
prior/ring/visibility/halt/postcheck together are about0.4ms. This is not a
hardware busy counter. Cached output surface sweeps still cost3.228+3.174ms
and final CPU scaling about14.221ms per copy window. Firmware mailbox
request1/bus4/return0 was actually read, but the downstream clock graph
formula rejects all53 live snapshots. The host decoder exposes only a
reference-graph rate and explicitly leaves physical clock frequency unknown.
Do not invent a divide-by-two adjustment to fit the request. A bounded
original-device HFI request A/B is the next candidate, not an achieved gain.

## Physical bandwidth request A/B (0093)

The default original HFI bandwidth request4 (table IB1200000KB/s) was an
actual major performance limit. In the default-OFF mode1 RAM experiment,
only the active bandwidth request changes to8 (3072000KB/s); GPU performance
request stays1. These are requests, not measured DDR/GPU frequency. Same
GPU bundle/tree/four-core CPU policy and40 consumed warm/measured gestures
produce845 measured full frames: median34.526->17.971ms, about47.95% lower.
Complete native window ratios show pre/post cache3.228/3.174->1.077/1.070ms,
execute/idle15.418->9.032ms and panel-copy median14.221->5.718ms. Fixed first
second after release has43 frames at18.412ms median, versus23/36.693ms.
This single cross-boot comparison includes bounded idle/cooldown transitions;
it is neither repeated stability nor60FPS/hardware VSYNC proof.

Actual native shutdown verified GPU1/BW4 restoration after VFS0/busy0, then
CPU request0 and all three peers really OFF, matching RAM_DRAINED and
independently observed Polaris FASTBOOT. The follow-up mode3 held active BW8
and requested original-table GPU performance4:919 actual full frames median
14.560ms/p9516.281ms (25 exceed16.667ms), versus17.971ms in mode1. Native
execute/idle fell9.032->6.241ms, while cache and panel costs remained near
1.1+1.1ms and6ms. The same kernel, GPU/tree, CPU policy and exact40 consumed
motions are bound to separate actual case records. Both trials completed native
GPU1/BW4 and CPU0 restoration before all peer cores OFF, then independent real
FASTBOOT. GPU frequency remains unknown; these are original HFI requests.

The bounded30s-high/10s-backoff experiment itself caused35.6..41ms frames
when it returned to1/4 inside the fixed post-release window. A separate fixed
first1s after six extra swipes had no request transition,53 full frames with
14.950ms median rendering and17.305ms median begin period. This is not stable
60FPS or hardware scanout proof. Next work must measure ready-to-copy queue
latency and design a justified continuous policy, rather than discard barriers
or disable the experiment's guard without original-device evidence.

## Presentation wake and original thermal correspondence (0094)

Original XNU8796 IOInterruptEventSource explicitly supports a providerless
source as a software workloop poke. Profile0889 uses that existing mechanism
only behind an explicit opt-in, preserves the independent VSYNC/copy deadlines
and records native publication/copy times. Four actual EFI/XNU tests execute
native workloop delivery/coalescing/re-publication and genuine native shutdown;
this does not emulate the phone panel/GPU or establish a performance gain.
The current reference userland eagl.c frame_end() still waits for drawing;
no completion, cache, auth or lifetime guard was removed to reduce the timing.

The phone's own live DT maps gpu0/gpu1 to TSENS0 sensors11/12 at TM0xc263000.
The other board's reference adreno_minute() instead reads TSENS1 sensors1/2
at0xc265000. Do not transplant those sensor addresses/IDs. Original pinned
[tsens2xxx.c](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/thermal/tsens2xxx.c)
and [tsens.h](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/thermal/tsens.h)
were fetched read-only and verified against Git blobs50c847febf73d9dbded5830b1f0440f4f4aab161
and ae4741ddc1a573b2bf34b8b1da490f769eed89b2. They describe status0xa0+4*ID,
valid bit21 and a signed12-bit temperature in100millidegreesC units. Source/DT
correspondence is not a live temperature, enabled sensor or continuous-policy
proof. No native thermal mapping, threshold write or removal of the experimental
30s/10s backoff has been performed in0094.


## Original Polaris legacy SMEM metadata correspondence (2026-10-29 local)

The pinned own GLINK driver uses CONFIG_MSM_SMEM's `msm_smem.c` and legacy
`smem_get_entry`/`smem_alloc`, rather than the separate `qcom_smem_get` driver.
Own commit c7cb50c18f812629b9620b2b8fa684bc40d82080, msm_smem.c blob
1bbd7514188f82a7b4404c51ee7da7f83fbd82c5, supports master versions0xb and0xc;
0xc uses the common partition. Its security TOC has32-byte header,48-byte
entries with four exclusion sizes; partition headers are32 bytes. The legacy
fixed header plus512 allocation entries occupies8400 bytes. Original host
numbers are APPS0/Q62/WCNSS4, with ten known hosts; the common pair is0xfffe.
Redwood's common/APPS partition approach is useful, but its physical addresses
and Wi-Fi host must not be transplanted.

The independent `tools/polaris-smem-inventory.h` only inventories bounded
metadata via a caller-supplied read function. Private0096 checks compile the
verbatim own original wire declarations and verify15 layout/host assertions;
actual AArch64 freestanding compilation uses192 bytes of wrapper stack.
ASan/UBSan mutation, read-failure, observed metadata-change and foreign-header
isolation cases pass. This is not an atomic remote snapshot, lock, SMEM item
reader/allocator, GLINK/QMI transport, radio startup or working Wi-Fi/audio.
The phone's original SmemDxe getter ABI and safe mapping still need binding
before physical read-only diagnostics; no such access is claimed here.


## UniXNU display, backlight and OS correspondence (2026-10-29 local)

The user supplied UniXNU as a further60FPS reference and permitted considering
a more complete iOS boot image. The read-only audit pins main40d21cc65171c3a24faa130a2a8e899f85790485,
its complete1147-entry tree, selected docs/profiles/catalog and actual
GopFramebuffer submodule33e941a878dcf01b98dbd9160d798bd56e7551ea. Sources are
Gitblob-verified under the ignored audit directory; no scripts or binaries ran.

The actual NativeGOPPresenter offers one retained frame, hands its mapped
buffer to the GPU client and matches sequence-tagged completions. Its client
loss path abandons the outstanding swap. NativeLegacyDisplay discusses
pipelining retirement separately from GPU transfer completion. These are useful
references for our remaining serialized render/copy and frame-gap investigation;
retirement must not release or reuse our source BO before actual DMA completion.
Do not transplant A740 PM4/HFI, SM8550 DPU/SMMU addresses or its policy requests
to this A630/SD845 phone. The reference distinguishes requested timer rate from
actual display counters; its generic GOP power states explicitly make no
physical panel/backlight power claim.

Sheng's actual brightness implementation targets KTZ8866 over GENI I2C.
Our selected original Polaris JDI NT35596S video LCD instead uses PMI8998 WLED
via SPMI (SID3, ctrl d800/sink d900). Own pinned leds-qpnp-wled.c blob
dcb3ec986243e17fc81505e602bdfa82a1c39a00 changes module-enable bit7 at ctrl+46
for zero brightness and retains the level registers, with soft-start and IRQ/
optional-PSM sequencing. The reference OS-facing backlight interface is useful;
its hardware transport and register encoding are not this phone's.

0111 distinguishes volatile status from configuration using the original
Polaris driver above and Qualcomm-authored PmicLib sources (public source
mirror `David112x/android-firmware-qti-sdm660`). `pm_wled.h` Gitblob
`eff87f29b50bf331572156a9a3685072dc191c14` defines the WLED IRQ enum in
ILIM/OVP/SC order; `pm_wled.c` blob
`7e6be3d48e5d2cbd0e08b454a51a92754cd9c48a` uses `1 << irq` when reading
real-time status. This identifies RT bit0 as ILIM; it does not establish
hardware health or make an ILIM pulse harmless. Own Polaris OVP handling
records ILIM and only enters OVP calibration for bit1. The independent OEM
policy retains both raw status words and rejects every bit except ILIM,
while comparing all64 non-status snapshot bytes exactly. Original strict
mode/refusals remain intact. The new policy is currently QEMU-only; no
physical writer/image/control admission or true-darkness result is implied.
Private source/oracle/model evidence is under `research/polaris/uefi-ios-0111`.
0112 adds an independent bounded raw journal and a final reset response that
extends it with both actual reset-gate observations. Actual EFI memory dumps
are checked by the host against the full history, rather than treating the
earlier cycle-completion print or empty ACK as the final evidence. Nine
software-PMIC EFI cases pass; physical USB/power/darkness and the native lock
screen remain unproven, and physical OEM image admission remains disabled.

The audited UniXNU OS profile is iPadOS17.7.11/21H461 with XNU10063.141.1 and
new MobileGraphics/IOSurface/IOHID ABI integration. Our current iOS16/XNU8796
kernel and graphics bundle cannot simply consume that profile or root image.
First audit a fuller matching16.x userland and preserve verified RAM boot,
USB and native shutdown. Image completeness alone does not implement the
ICNSS, DSP or amplifier hardware paths. No Apple image was downloaded, no
reference code executed and no existing root or partition changed in this audit.

## TSENS readonly observation prerequisite for sustained performance (0099)

The same saved original Polaris DT maps the four gold CPU zones to TSENS0
IDs7,8,9,10; GPU zones use11,12. The bounded offline helper reads only
status0xa0+4*ID inside TM0xc263000/0x1ff. Signed12-bit decoding and validbit21
match the pinned own tsens2xxx.c; critical status, read failures, implausible
values, inconsistent successive observations and clock bounds reject the
whole result without publishing partial temperatures. It does not map MMIO,
enable sensors, configure thresholds/interrupts or change CPU/GPU requests.
The original sensor enable register is outside the DT's four-byte SROT
resource, so this helper deliberately does not probe it by assumption.
A local observation timestamp is not proof of sensor freshness. Native
platform admission and actual phone observations remain prerequisites to
replacing the existing bounded30s/10s experiment with a sustained policy.

0099 actual phone publication timing showed a near16.9ms median interval
before the stock backoff and43.8ms after it, within one fresh-publication
window. This is a display-publication observation, not physical scanout Hz
or a pure GPU-frequency measurement. Full EAGL tracing was disabled by the
omitted touch_lat token; keep that limitation explicit in comparisons.

0100 subsequently admitted the native kernel-only read-only mapping and
observed all six own sensors during real UI work, with raw pass pairs bound
to each reported temperature. In the measured29-second contact bracket,
gold reached71.1C and GPU51.2C. One earlier transient VALID=0 was retained as
an error. Full EAGL tracing was restored. A fixed first-second animation
window straddles a30.000473-second high-request expiry: median drawing time
changes14.743->36.748ms, with nearest prior temperatures63.8C gold/50.9C GPU.
This strengthens the fixed-backoff diagnosis; it does not measure live clock
frequency, prove hardware sensor freshness, isolate CPU from GPU throttling,
or establish physical scanout60.

The0101 offline eligibility component independently decodes complete native
sample words and requires bounded observation age, several successive valid
observations and recent value changes, with invalid/hot/clock/stop refusal.
Its proposed75/70C gold and60/55C GPU hysteresis are conservative experiment
limits, not values copied from the original thermal trips. There is no native
caller or clock-control admission yet. The next GPU-only bounded experiment
must retain original ownership/idle/restoration rules, an unrenewable hard
run budget and confirmed-low cooldown; CPU policy stays unchanged initially.

## Transient TSENS status re-read correspondence (0102)

The0101 native thermal experiment is now integrated and physically measured;
the preceding offline-only description is historical. Its100-scroll phone run
found two explicit INVALID status words followed by actual sensor-triggered
low requests and ten-second cooldowns. The pinned own tsens2xxx.c
(c7cb50c1, Git blob50c847febf73d9dbded5830b1f0440f4f4aab161) re-reads the same
status up to three times. We adopt only that bounded VALID recovery sequence.
Its final all-invalid/majority-code fallback is deliberately excluded: every
accepted word must have VALID, and critical/read/range/persistent-invalid,
two-pass disagreement and time-limit errors still reject the whole sample.
No thresholds, performance limits, register mappings or writers change.
The0102 native retry probe uses explicit synthetic words, not actual sensors;
physical retry recovery and sustained panel60 still require new evidence.

## Own thermal interface and extended-duration experiment (0103)

The original live Polaris DT's gold7..10 and GPU11..12 user-space zones
carry125C passive event trips. That is neither a safe operating target nor
a substitute for Android's userspace/skin/battery thermal management, which
has not been ported. Our separate default-OFF duration experiment retains
the conservative75/70C CPU and60/55C GPU limits, all valid/read/age failures,
idle and confirmed-low restoration. It changes only a bounded GPU cycle
from120 to600 seconds, preserving the same factory4/8 request. It does not
copy the reference Redwood EPSS top-row policy or raise voltage/PLL/trips.
A selected duration cannot be changed or renewed within a native session.
Actual thermal and frame behavior still requires a new validated phone trial.

## Bounded duration trial outcome (2026-10-29 local)

0103 retains the actual Polaris factory PERF4/BW8 request and changes only a
separately admitted experiment limit120s to600s. Full new macOS27 kernel CI,
196 actual EFI/XNU checks and a physical500-scroll test completed. The physical
600s expiry objective was **not observed**: two whole temperature observations
were rejected for paired readings differing by more than2000mC, and a23.58s
host pause between the400+100 phases also caused expected idle restoration.
All these resets remain in the evidence. Synthetic-time native600s checks are
not a substitute. Actual drawing median15.333ms and recurring2.5..2.7ms gaps
still do not prove sustained60FPS. Retain conservative thermal/error handling;
do not copy an unbounded reference clock policy or interpret a valid table
request as measured frequency. Next work must address the observed failures
and exact remaining timing boundaries rather than lengthening the limit again.
