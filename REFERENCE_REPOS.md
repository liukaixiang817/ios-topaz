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

0151 rechecked Dipper's RPMh supply path against own DT and original81 firmware.
Its fixed CmdDb85fe0000 and raw TCS1 selection are Mi8 observations, not Polaris
ownership evidence. It votes CX/MX/MSS to the top and clears its TCS even after
uncertain completion; those writes/restoration rules were not ported. Own DT
uses ARC APIoffset1/raw384, not microvolts. Original Polaris CmdDb's public Query
has a required `This` plus separate uint32 CmdDb status and uint64 EFI result;
our default-OFF adapter validates the live cached namespace and reads exact ARC
auxiliary tables through that ABI. Its 35 software cases and AArch64 objects
are not physical query, supply or Wi-Fi evidence. Original RPMh churn methods
have unbounded waits; its completion service takes DRV ID2, not IRQ ID0, and may
process foreign queues/callbacks. A bounded private power transaction still
requires actual current cache/TCS ownership, completion and complete restoration
before Delete. Private evidence is in0151/wifi; no reference scripts or prebuilts
were executed and no standalone inventory boot was introduced.

The subsequent0151 full submit trace also finds `330c ->35bc ->2fb8` inside
original public submission itself: slots78/98 can enter the unbounded churn
before returning. An outer finite polling loop cannot make those calls bounded.
Original RPMh lock/unlock targets2b70/2b74 are RET stubs. The separate new RSC
transaction core therefore implements finite completion and reverse saved-vote
restoration without invoking or patching that submission code. Its72 software
checks include the real CmdDb adapter's modeled output flowing into two modeled
requests; they do not establish a physical CPU0/DRV2 lease or authorize MMIO.
Actual original resource cache/TCS/mode/queue state, RSC geometry and write-map
identity plus exclusive lifetime and parent retirement gates still precede any
new physical candidate. No Mi8 fixedTCS1/top-vote/uncertain-cleanup rule was used.

The next0151 caller components preserve the original driver's retired-request
pool separately from active/pending queues and read its full392B runtime HAL
table rather than inferring a mapping from static configuration. CPU-local
PSCI/interrupt exclusion and source/protocol/hash checks are connected to full
transaction-prefix retirement before interrupt restoration. A separate actual
GCD+NS read/write translation adapter admits only finite own-register reads;
it exposes no writer. The119 software cases and AArch64 component objects do
not prove an exclusive DRV2/EE/EL3 lease, a physical vote or working Wi-Fi.

0152 connects those own-source components through one private-client body,
including bounded CmdDb/ARC transactions and full source/CPU/namespace
retirement before known Delete. It adds a second guarded PSCI round after
masking to close a local admission gap; logical CPU state is not a physical
rail or secure-memory grant. No Mi8 fixedTCS/top-vote/uncertain cleanup was
adopted. The86 affected and integrated software cases plus AArch64 objects
remain offline evidence; parent registration, hardware ownership qualification
and a new physical candidate are still outstanding.

0153 wires that path into the actual pre-Clock/final-GCD parent and literal
native CPU_ON flag, with complete raw publication and a nonreturning RAM-only
quarantine on UNKNOWN. Full physical-body EFI and actual parent COFF/MachO
compile; two serial terminal models compile the power body OUT. The pinned
upstream RPMh binding corroborates own DRV2/bank2 address geometry and the
ACTIVE versus firmware sleep/wake distinction; neither it nor Mi8's runtime
grants current exclusive ownership. This remains an offline link: the old
host policy correctly refuses it and no new image has been sent.
No standalone inventory boot, original blocking submission, borrowed Mi8 TCS
or unqualified register store was enabled.

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

### User-requested ath11k comparison, 2026-11-02

The user asked whether ath11k can accelerate Polaris WiFi work. It is not
running on the current iOS target. Our implementation/reference route remains
own SDM845 ICNSS/SNOC and Mi8's WCN3990 ath10k/XNU integration; real association
and traffic are still unfinished.

[Linux ATH10K_SNOC Kconfig](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/ath/ath10k/Kconfig)
explicitly identifies WCN3990. [ath11k documentation](https://wireless.docs.kernel.org/en/latest/en/users/drivers/ath11k.html)
describes its newer802.11ax device family. This is a hardware/transport mapping,
not proof that a Linux module can run in XNU.

The actual [ath10k QMI source](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/ath/ath10k/qmi.c)
provides the more direct MSA region-count/range checks, permission handover and
IND_REGISTER/HOST_CAP/MSA_INFO/MSA_READY/CAP correspondence. The
[ath11k QMI source](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/ath/ath11k/qmi.c)
is useful for comparing event-driven memory requests, board-data loading and
firmware-ready/error lifetimes. Its different memory-request protocol, rings,
chip constants and reset/calibration assumptions are not WCN3990 defaults.
Retain own firmware/board identity and explicit bounded region/DMA ownership;
do not copy a skip-hostcap/BDF, fixed-memory or coldboot reset quirk by analogy.
Upstream master was read only for this comparison; any future imported code
must first be pinned and matched to own vendor/DT evidence. This review changed
no running firmware, radio state or device partition.

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
The phone's original SmemDxe getter ABI was subsequently bound offline in0114.
It was re-extracted byte-for-byte from the original81-file Mindows firmware.
Its table revision0x10001 and Get slot16 match the unmodified EFISmem header:
int item, uint32 size pointer, address pointer, with no protocol This argument.
The wrapper returns EFI_SUCCESS even when its returned address is null, so
status alone is insufficient. Its conditional cold path includes a shared
version-header store; that path has not been observed running on this phone.
Do not invoke this getter as a strictly read-only inventory operation. The
legacy lock entry/exit are RET stubs, not proof of remote synchronization.
The25 binary/DT checks and10 AArch64 layout assertions are static evidence;
no protocol was located/called and no physical shared memory was mapped.

The original DT's SMEM86000000/2MiB region is MPU-enabled. Its own SMEM IRQ
resource17911008 differs from GLINK-modem doorbell1799000c/mask0x1000.
Dipper's svc_item selects APPS/MODEM(remote1); the radio chip's WCNSS name
alone does not select host4 or prove the route of Polaris's WLFW service.
First inventory own metadata through a separately admitted bounded read-only
mapping, then authenticate the actual QRTR service path. Do not copy Redwood
IPCC, allocate via firmware or write FIFO indexes during that inventory.


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
screen remain unproven, and physical OEM image admission remains disabled
at that historical0112 checkpoint.0113 now adds a separate physical-only
admission, bound to the real Polaris inventory/timeline and Qualcomm source
oracle. Eleven OEM full-EFI cases cover success, timeout, three zero-write
preparation paths and six serious-status faults; the original strict control
also passes. All raw binary receipts are independently decoded. This is a
prepared no-OS RAM candidate, not a phone OFF/optical/native lock-screen proof.
The original strict path and saved register scope remain intact; dormant
zero-write diagnostics never grant writer permission.

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


## Original Polaris amplifier firmware catalog (0115)

The own TAS2559 driver-format0x401 firmware can now be cataloged offline by
`tools/polaris-tas-firmware.h`. It preserves raw program/configuration fields
and bounded command spans without executing them. The private original
MiCode core parser (blobe17bef78...) and structures (blob530e7000...) were
compiled verbatim with host allocation/logging stubs and compared against
the original96,514-byte phone firmware:5PLLs,4programs,18configurations,
73blocks and90,560 payload bytes agree. The original register-loading path
was excluded. Only our independent bounded parser received truncation and
mutation inputs. Checksum values are retained, not device-verified; successful
parsing does not authenticate a chip, authorize register replay or prove sound.

Future hardware work still requires the own GENI/I2C identity, original left/
right calibration, bounded TAS initialization and CRC checks, ADSP/APR and
quaternaryMI2S routing, owned PCM completion and stop/restoration. No regulator,
I2C/MMIO, calibration/persist write or audio playback occurred in this work.
The ready0113 backlight RAM candidate and current display bundle stay unchanged.


## Polaris physical LCD backlight result (0116)

**0123 update:** the separate native runtime has now booted actual iOS on
Polaris. The human tested the power key and confirmed “背光熄灭，唤醒正常”.
Session-bound raw records show native OFF/ON, then restoration from a later OFF
before native drain and the actual FASTBOOT return. All80 raw observations,
the four-read WLEXIT05 tail and two new WLR5 final observations independently
decode;12 issued commands completed. This is native LCD lock/wake evidence,
not OLED-register reuse, touch-to-wake, sustained60Hz or persistent installation.
One post-wake screenshot has unresolved composition/capture artifacts; a clean
stable-home visual regression is not claimed. The user now prioritizes fuller
20F66 iOS16.5 and another focused Dipper CPU/GPU comparison, preserving these
own-device drivers and restoration guards.

The independent original-UEFI RAM WLED cycle now has actual Polaris evidence:
module enable80->00->80, saved OVP notification02->00->02, all four issued
commands completed and the final full raw-history receipt validated before
reset. An independent product query then verified actual Polaris FASTBOOT.
After the human requested a separately recorded identical-image retry, they
confirmed “有，真的关闭了2秒背光”. This establishes physical backlight OFF in
the bounded pre-XNU test. It is not native iOS lock-screen integration or a
claim that a black screenshot proves backlight power. No OS, root, storage,
firmware file or NVRAM write occurred; original hardware protection stayed.

Next integrate a separately admitted display-workloop/firmware handshake and
restore-before-reset gate. The original one-cycle image must not become a
runtime writer simply by changing a flag. Future iOS tests still require a
fresh strict read-only root/journal audit; the outstanding journal issue was
not repaired or waived by this hardware-only milestone.


## Focused Dipper CPU/GPU recheck for20F66 migration (0124)

Pinned e930c26 source uses the same SDM845 OSM cluster bases and stock big row22
already present on Polaris. Its default DDR16 vote and busy-GEM-unmap behavior
do not establish an improvement over own bounded thermal/restoration and DMA
lifetime guards. Keep current GMEM, WC GEM/cached surface and four-big policy.
The compatible20F66 QuartzCore/EAGL targets have been independently decoded from
the actual official cache and integrated into a version-matched graphics bundle;
four current common binaries remain byte-identical. Bounded damage rectangles
are a promising future optimization, pending own ABI, bounds/lifetime, full first
wake frame and actual pixel/timing verification. No foreign hardware writes or
reference scripts/prebuilt execution; no claim that this proves faster CPU/GPU.


## Exact Dipper wallpaper and injection recheck (0128)

User requested checking the loader-permission diagnosis directly against Mi8.
Dipper e930c26 locks HackiOS kernel8e61187098f2c26c5daee8f9f72b6416aa64b9ab
and userland906425b75e02b4f99eb5d7bb1ef7c9583472d772. Read these exact Git objects,
not the newer local userland HEAD; fetched only the missing pinned source commit.
No reference scripts, prebuilts or firmware were executed. Private source hashes
and comparison:0128/dipper-wallpaper-and-loader-comparison.json.

- Its PID1 configures `/etc/inject.conf` through `kern.exec_inject`; the kernel
  adds the library environment during exec. `kern_minimac.c` answers AMFI0x5a
  with0xff for general dynamic-loader options. Own Polaris deliberately only
  handled the verified BBD executable, and actual0127 PBF wrapper ran but no
  preview constructor appeared before the same nil-queue exception.
- The exact userland `inject_sb.c:poster_switcher_allowed` returnsNO: its comment
  describes a foreground PosterBoard scene whose hosted context still renders
  black. Its publication is not evidence of a complete working wallpaper picker.
  We found no PBFHomeScreenPreviewImageBuilder imageForView replacement there.
- `inject_media.c` explains that the four HEIC layers of stock16 wallpaper need
  mediaserverd's VideoToolbox software decoder; otherwise only a gradient appears.
  Its bounded portrait-prewarm compatibility is a later relevant source to verify
  against actual20F66 media code, not proof own decode/audio/camera already works.
- Our0900 adaptation follows the loader correspondence with a separate exact
  PosterBoard executable-vnode/original UID/GID/mode/size/wholeSHA/root/RAM-overlay identity and only mask2
  (path variables, per Apple's dyld1066.8), leaving GPU caller/reporter identity
  and all CPU/GPU/WLED/storage gates unchanged. It does not copy generic0xff,
  hide the picker, fake Metal, or add GPU-device access for PBF. Physical loading,
  preview bitmap and wallpaper selection still require the new actual build.


## Exact extension registration state correspondence (0129)

Actual0128 proves the PBF full-file identity, mask2 library load, exact-method
installation and real375x811 UIKit bitmap creation; its Add New Wallpaper sheet
still displays empty. NoPBF terminating exception is in capture3/4. This is not
working-wallpaper evidence. NoCollectionsPoster/provider exec appears in that
captured window; that absence alone does not isolate the full cause.

The pinned Dipper kernel8e611870 `kern_minimac.c` also handles AMFI request0x60,
returning its software non-enforcement state0x86. We independently decoded the
actual20F66 libamfi wrapper (0x1d11ef55c: policy AMFI, call0x60,8-byte output) and
ExtensionFoundation (0x19371fa9c: error leaves signing-disabling booleanfalse;
only successful output masked0x86 changes it). The actual ExtensionKit feature
`enforce_xpc_cache_code_signing` isEnabled. CurrentPolaris AMFI had no0x60 handler.
The stock138-entry extensions.plist containscom.apple.posterkit.provider; its
104731 bytes SHAe92ee2b85cea78e17f951169c674a55d717be53e331a4b0a5a26de8221c095a4
and metadata0:80/0644 are independently checked. This establishes a missing
compatibility prerequisite, not a physical query trace or sole-cause proof.

Own0901 validates that exact original table read-only once during verified
20F66 RAM overlay staging, beforeApplePID1. Only that successful root/metadata/
wholehash check enables the non-PID1 0x60 state query. PID1 and an unverified or
changed table keep ENOPOLICY; copyout errors remain errors. It changes no boot
argument/NVRAM/file/signature, no existing dyld0x5a orGPUcaller/reporter role,
and no CPU/GPU/WLED/storage/thermal guard. Actualclient queries, provider
registration and usable wallpaper remain to be verified on the new physical
candidate. Graphic bundleba69 remains byte-identical. Evidence under0129.

## Actual media decode correspondence (0130, still incomplete)

Actual0129 gallery has categories/text but white thumbnail cards; the user sees
only a single-color wallpaper. The provider's check-in timeout stack resolves to
CoreMedia FigSemaphoreWaitRelative, VideoToolbox VTDecompressionSessionRemote_DecodeTile
and CMPhoto auxiliary HEIC decode. Mediaserverd allocates L008 decoder surfaces;
no media-server crash is observed in that captured prefix. This identifies a
blocked decode path, not its underlying cause or proof the GPU texture format is wrong.

Pinned Dipper906425b skips CMCapture's portrait-filter GPU prewarm to keep its
software HEVC service alive. Our actual20F66 cache independently matches method
1a2115c0c/184B/SHA d2430aa3e309a5cfb86a991aa1b2191e58eb85c4f6c581f7651df5a20c82f18e,
UUIDdb6cb6b3-a26b-3a86-9e55-299cf1c485be. The actual Objective-C encoding is
v24@0:8I16B20: unsigned version, unlike the reference C int spelling. Own0130
candidate checks exact UUID, all method bytes and ABI before replacing this
portrait-only prewarm; no decoder, Metal, camera/audio device or hardware writes
are invented. Exact original mediaserverd vnode/owner/mode/size/wholehash in the
verified RAM root admits only dyld pathbit2, with no GPU caller/reporter role.
Only its launchd job and existing PBF job gain scoped wrappers/console in RAMCOW;
all Apple service names, user and argv stay intact. Real loading and HEVC completion
remain unproven until the new actual build. Mesa/GL/wrapper/test stay byte-identical.

## Exact media launch comparison (0132)

Pinned Dipper kernel8e61187098f2c26c5daee8f9f72b6416aa64b9ab and
userland906425b75e02b4f99eb5d7bb1ef7c9583472d772 deliver the media library
through exec environment injection, after launchd. Their comment explicitly
states launchd drops DYLD job variables. Polaris0131 proved original media
exec and path-variable policy, but retained stdio hid constructor evidence;
its gallery still has white cards and a real tile-session creation timeout.
0132 ports only fixed, exact-original-media target delivery, with whole-file
identity and the verified RAM overlay, preserving original argv/job/stdio.
It records preexisting variable bits and bounded media-owned snapshots to
distinguish loading, portrait prewarm and genuine decoder waits. This is not
yet physical proof of variable filtering or a completed HEIC/wallpaper fix.
No reference flashlight/camera code, broad injection sysctl or hardware
tables were copied. The existing MIT reference attribution remains in
polaris-media-compat.c and LICENSE.hackios.

The first real0132 trace confirms this launch difference on Polaris:
`MEDIA EXEC preenv0/1 added1 status0` (DYLD absent, compatibility flag retained),
then the genuine media constructor, actual CMCapture image, full method
identity and installation notices all pass. This supersedes the earlier
permission-only inference. Genuine portrait callback, HEVC completion and
wallpaper pixels still require their own subsequent physical observations.
Private proof:0132/actual-media-exec-loading-and-exact-method-proof.json.

## Explicit Mi 8 Wi-Fi source comparison (0169)

On2026-11-01 the user again requested using the Mi8 Wi-Fi implementation.
Re-read the actual added C in pinned e930c26, without running scripts/prebuilts:
`patches/xnu-mi8.patch` (`mi8_rproc.c`, `mi8_glink.c`, `mi8_hostsvc.c`,
`mi8_wlfw.c`) and `patches/hackios-kernel.patch` (`lx_ath10k_bus.c`,
`lx_ath10k_qmi.c`). This is source correspondence, not Polaris radio success.

| Reference source | Polaris correspondence and required integration |
| --- | --- |
| `mi8_rproc_init`, `wlan_power`: four Wi-Fi supplies ON before MSS for `mi8rp_wlfw=4` | Own0114DT `qcom,icnss@18800000` points to phandles140..143: `ldoa5/7/17/25`. Include these VRM rails and their saved-state restoration in the power path; CX/MX/MSS ARC alone is insufficient. This does not authorize a voltage/enable store. |
| `mi8_wlfw.c:arrive`: IND_REGISTER → HOST_CAP → MSA_INFO → assign returned bounded regions → MSA_READY → CAP | Reuse the protocol structure after owned allocation/VMID/MPU/cache/remote-DMA lifecycle exists. The ownDT logical MSA request is1MiB; an independently allocated/aligned2MiB MPU envelope is a separate ownership requirement, not a new1MiB/2MiB claim on reserved memory. |
| `mi8_glink.c`: descriptor478, TX479, RX480 | Own vendor transport correspondence was already checked; preserve cached-first lookup and bounded ownership. No blind SMEM allocation or failed-trylock unlock. |
| `mi8_wlfw_process` and `mi8_wlfw_enable`: MSA_READY / board data → FW_READY → WLAN_CFG → MISSION | Polaris must use its own firmware/calibration and actual chip/board responses. Do not inherit `skip_bdf`, host-cap quirk or default CE configuration solely because Mi8 used them. |
| `lx_ath10k_bus.c`, `lx_ath10k_qmi.c`: WCN3990 SNOC, 12 CE IRQs, WLFW bridge, mission-gated work/IRQ lifetime | OwnDT confirms18800000/8MiB, stream40, SPI414..425. This is the native driver/transport path to adapt after power, MSA and DMA ownership; firmware-ready and a driver object alone do not prove scan/join/data. |
| `com.redwood.wifi.plist`: configd setup and wait for en0 address | Configuration is downstream of a real interface and association. Do not replace hardware/network bring-up with an icon or a forced Settings capability. |

OwnDT voltage constraints remain authoritative: L7 is1.8V, L17 is1.3V;
ICNSS requests its CX/MX supply at0.8V and CH0 within0x2f5d00..0x328980uV,
while the L25 regulator has its own3.0V init/min and3.312V max. The reference's
fixed3.3V/HPM/enable writes and unconditional disable are not a saved baseline.
The exact current VRM addresses/units/cache requests and full touched-register
restore must be qualified before using this sequence. Do not inherit Mi8's
fixed TCS or permanent top CX/MX votes. The user explicitly requires complete
restoration, actual completion and UNKNOWN retention.

Actual0169 independently captured seven normal-IRQ PSCI OFF replies and
completed its Core/source/map retirement. It does not establish a current
maskedCPU/DRV2/EE/EL3/VMID/MPU lease. The next qualification remains the
CPU-local masked interval and exact restoration, then the fresh source-bound
bounded RSC path. Carry the complete Mi8 Wi-Fi chain above into subsequent
VRM/MSS/GLINK/WLFW/ath10k integration; do not repeat completed inventory boots.

## Four Wi-Fi VRM encoding correspondence (0188, offline)

The original Polaris DTB (f7762357...) was read with `fdtget`, including the
properties which `dtc` renders as strings. Exact rail constraints are L5
800000 uV, L7 1800000 uV, L17 **1304000 uV**, and L25 3000000..3312000 uV
with 3000000 init; the ICNSS CH0 consumer requests 3104000..3312000 uV.
Earlier “1.3 V” is a nominal description, not a 1300000 uV programming value.

Each regulator declares `pmic4-ldo`, supported generic modes 2/4, init2, and
active+sleep set3. The [family-aware Qualcomm driver](https://android.googlesource.com/kernel/msm/+/28f2b66a16e50693a0796b323d652ed1669115b1/drivers/regulator/rpmh-regulator.c)
and its actual included
[`qcom,rpmh-regulator-levels.h`](https://android.googlesource.com/kernel/msm/+/28f2b66a16e50693a0796b323d652ed1669115b1/include/dt-bindings/regulator/qcom,rpmh-regulator-levels.h)
map generic LPM2/HPM4 to PMIC4 raw5/7. This matches the DT vocabulary; it does
not identify the exact running Android kernel build. The older c7cb regulator
source uses a direct raw-mode binding and cannot interpret those DT cells by
itself. The similarly named `qcom,rpmh-regulator.h` at the newer commit is not
included by that driver and must not supply its constants.

Both source generations encode VRM voltage in mV; field offsets are voltage0,
enable4, raw mode8, headroom12. A voltage request rounds its uV minimum upward
to mV and checks the maximum. Linux getters return cached software requests.
Absent init-enable and DT init voltage/mode do not supply a saved live vote.
Primary source copies and original DT data remain private. Review proof:
`0188/wifi/four-VRM-primary-semantics-0001/proof.json` SHA
287084d662db5c872c261c1f8a36590170d9ea3340fff4b78a995351ee4066f8.
No source import, firmware change, phone command, model or test rerun occurred.
Own ICNSS consumer load/settling sequence, original HAL offset scope, and
fresh live snapshot/ordered supply/complete restoration remain to qualify.

## Own ICNSS supply consumer and finite VRM component (0188)

Pinned own [MiCode ICNSS consumer](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/soc/qcom/icnss.c)
blob649d0ff9a41d8b250f0951eba75a25f0a1c04e74 was independently matched to the
GitHub Contents API. `icnss_get_vreg_info` takes min/max from the first two
config cells; load and settle delay require separate third/fourth cells.
Our original DT provides two cells for CX/MX and CH0, no override for XO/RFA;
the resulting four load/delay entries stay zero. `icnss_vreg_on` sets voltage,
conditionally requests nonzero load, enables, then conditionally delays, in
L5/L7/L17/L25 order. Its Linux shutdown/unwind is not an exact saved baseline
and is not copied into the temporary RAM scope.

Own original HAL bank2 command serialization8610..8760 packs slave+logical
address, operation/length and data into the already mapped TCS. It does not
supply a permission grant or validate the supply consumers. No original
routine, internal entry, RET lock, arbitrary MMIO or reset is called.
Private source/representation proof560eaf7a022c3775e26de5d2c0f7404e0b61a32edcd645fab1fa3ac28349c56d.

The new independent finite VRM component is default OFF and has no physical
parent, builder option, host profile or boot helper. It implements four ordered
voltage/enable requests and reverse exact saved restoration, preserving mode
and headroom. Its complete returned journal must independently retire. OwnDT
address/voltage/enable/raw-mode bounds are rechecked before backend entry;
dirty or consumed records are rejected without resetting them. SOFTWARE
ASAN/UBSAN1952checks and standalone COFF/MachO/generalregs/maxframe1024 compile
pass. Component proof976297e86c0f62ecfe5a033ddcb833eace93effe24dcfbaf9563c103c6d5a74d.
Physical integration still needs fresh current VRM READs, exact CmdDb/source/
owner/cache/Device/CPU scope, the original combined deadlines, full retirement,
and the complete new candidate admission. No supply or Wi-Fi success is claimed.


## Polaris remote-memory allocation correspondence (2026-11-02 local)

The own pinned c7cb50c18f812629b9620b2b8fa684bc40d82080
[sharedmem-uio allocator](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/uio/msm_sharedmem/msm_sharedmem.c)
was newly inspected for the missing physical RMTFS provider. Its exact Git blob
is8be3e36f72783c37a520477430b0d50d9cfd38d2,6709B. Own DT client1 has a dynamic
2MiB region plus guard-memory: backing is0x202000B, with one4KiB guard at each
end; the exposed address is backing+0x1000 and its size remains0x200000. This is
separate from WLFW MSA's logical1MiB and independently owned/aligned2MiB envelope.
The source requests HLOS and MSS_MSA read/write access to the exposed interior.
Its permission error is only logged and its remove path has no secure handback;
our provider must retain UNKNOWN/ownership and require actual DMA stop/handback.
This correspondence does not establish current VMIDs, secure permission, free
reserved memory, an allocation or the exact Android kernel build.

The same source family's
[RFSA provider](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/uio/msm_sharedmem/sharedmem_qmi.c)
and [wire header](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/c7cb50c18f812629b9620b2b8fa684bc40d82080/drivers/uio/msm_sharedmem/remote_filesystem_access_v01.h)
are blobsfd95deeb6133201824a8a1d5e335d570153bc2fb/11857B and
7ea8ce66a5bfc9e9c69fac6667f49068d150ba5d/1291B. RFSA uses0x1c/v1/instance1,
GET_BUFF_ADDR0x23 and a nonzero client-bounded size. It is distinct from existing
RMTFS0x14/v1/1. Neither an actual RFSA request nor a need for this route has
been observed on the phone; keep that distinction when implementing the real
shared-memory provider, without recreating the finished RMTFS service. All
reference bytes remain private; no vendor initialization code was imported.

The original own Core allocator's descriptor-pool path was checked separately:
a request inside one original entry needs at most two temporary descriptors;
an empty free list can cause a recursive type4 page allocation. Current
adapter checks retain both complete original lists, key/depth/lock/prefixes,
but do not close asynchronous mutation between a TPL4 check and the API.
Private sourceproofe17898461cd1c2abef4a439d818fddde50e57b2200c75f09ffc6e65f49bf9aa4
and SOFTWARE3445checks are prerequisites, not physical admission.

[UEFI2.10 Boot Services, TPL restrictions and RaiseTPL/RestoreTPL](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html?highlight=exitbootservice)
places memory allocation services at or below TPL_NOTIFY. Own Core BS
slots24/32 are a2c8/c6d4; its4→16 raise skips interrupt disable. A qualified
registered TPL16 bracket is a proposed next step, with exact saved-TPL/FP/CPU
restoration and higher-priority firmware paths still to qualify. No direct
global write, masked-CPU BS call, secure/DMA grant, parent hook or new boot
is authorized by this source correspondence.

The later registered-TPL SOFTWARE implementation supersedes that proposal-only
state: source675ef81b89ccfca7722c3a3a2af27903c93a4b70 now brackets the actual
page adapter at4→16→saved4, retains a complete protected post-page map and
requires the normal-TPL map to match it exactly.3792 ASAN/UBSAN checks and
independent full-prefix decoding passed; this is still standalone defaultOFF,
with no parent/builder/profile import or physical API admission.

Targeted original-Core inspection also found a higher-priority path that the
public CreateEvent TPL4/8/16 restriction does not cover. Internal dad4 accepts
notify levels5..30; actual call99a0 creates a TPL30 checker atcb24, stored in
1cbc8. Timer IRQcbf8 updates1dc00 and signals that checker. It walks current
TimerList1c3f0 under locks1c400/1c3d8, uses event TimerLink98/triggera8/periodb0,
signalsca90 and can reinsert/requeue viaa5e4. No direct AllocatePages call was
found in that checker; its complete current list and transitive runtime bound
remain unqualified. Empty17..31 queue snapshots are not a future lease. Private
sourceprooff5eca699a1b8653cd02501276bb16a230a013e60fec06883d4e035d0fb4cdb6f
and softwareproof8c5da01ff9156239d9836395431e6bd2fcee35fb2f01118d76e43b8bfd548413
record this limit. Original firmware bytes were only inspected as private DATA.
Physical parent/native/current-image bindings and cache/secure/DMA handback
still must be qualified before any new integrated candidate or device action.

The subsequent one-shot timer gate (source8d8ffdfed8bf2dcccde410aa14ed5bff882dd9a7)
now binds the complete current TimerList (max32/full184B nodes) and complete
checker object to those original paths. Nonperiodic period0 takes cbc4's
skip-reinsert branch; with flag58=0, SignalEvent uses c7f0's fixed queue work,
and notify8/16 callbacks defer atTPL16. Periodic cbf0 requeue and arithmetic
wrap can defeat that bound, so all periodic timers are refused. No firmware
timer is cancelled, rearmed or unlinked.1122 independent ABSTRACT branch cases
max32 removals and4732 SOFTWARE adapter checks do not execute the original PE.
Private sourceproof3b00591bd1d3e6e49a6676ff6661c3776e2766b0078c5f07327442284e5389b6
records the exact scope. Current physical TimerList/periodic timers, foreign
IRQ rearm, deferred normal-TPL effects and timer/CPU interrupt-provider bindings
remain unqualified; empty snapshots or finite one-shot paths are not a lease
or a global execution-time guarantee. The physical parent is still not wired.

The next own-original provider audit identifies exact ArmTimerDxe/ArmGicDxe/
ArmCpuDxe PEs efbe4f1a.../add88fe4.../311318e6..., not a borrowed Mi8 driver.
Core1cb80→TimerArch table2038, Timer2070→HardwareInterrupt, Core1c8f8→CPUArch
table53d8 and CPU IRQ slot5438→the selected GIC IRQ entry1294/1acc form the
fresh chain still to bind. GIC's full dynamic handler array3120/count3150 and
current VBAR must be qualified, not inferred from image availability.
TimerIRQ10c8 raises TPL31; its114c..1158 step-add/CVAL catch-up loop has no
built-in iteration cap and zero-step/wrap hazards. Default period10000 is a
literal, not current state.7740 independent ABSTRACT arithmetic cases and
private proofa476bec7351539cfa7ff245742de4fc4707a33055992fafef773026dfc247b98
record the exact source scope. No original PE, interrupt dispatcher, IAR/EOI,
timer setter or hardware provider was called.

The same own Core's1cb78 global was previously called a profiling hook. Its
descriptor1c190 instead binds GUIDf4ccbfb7-f6e0-47fd-9dd4-10a8f150c191:
[official SmmBase2 ABI](https://github.com/tianocore/edk2/blob/edk2-stable202402/MdePkg/Include/Protocol/SmmBase2.h)
and [MmBase GUID](https://github.com/tianocore/edk2/blob/edk2-stable202402/MdePkg/Include/Protocol/MmBase.h)
identify slot0 as InSmm. The exact official Git blobs were independently
verified; this does not establish the original firmware's build tag. Current
source815be8ffd286d13cd278fc6ca898580899a0a9c2 corrects only the legacy RAW
field comment, keeping fresh-zero refusal and all behavior/layout unchanged.
Full enabled preprocessed C equals the4732-tested source; unchanged tests were
reused. No SMM protocol call, authority inference or physical admission follows.

The subsequent actual adapter source787d62df280e0eeeda6c6be3452af0a9142a1786
implements the fresh original Timer/GIC/CPU reader, retaining the three PEs as
private inert DATA. The digest/RVA-only generator binds exact full input SHAs;
five complete immutable-span checkpoints add70 provider hashes per operation.
All three image maps/per-page NSWB ATs, registered tables, selected mutable
state windows and complete32..1020-entry handler array are retained. Only the
four original timer callbacks and matching CPU/GIC vector chain are admitted.
Two read-only CurrentEL/VBAR/CTL/CVAL/frequency/counter samples and checked
period/step/debt/product/wrap arithmetic use the original operation's200ms.
No interrupt acknowledge, provider call, register write or original firmware
instruction runs in the6582 SOFTWARE checks. Complete112192B fixture prefixes
are independently decoded; actual COFF/MachO/defaultOFF exports also pass.
Private softwareproofbaa868f0b3ca0dff46052ebe19e021221c9115c6adbbcd4a3914bb2f45f17e50
records the exact scope. CPU mutable BSS/exception stack is not an immutable
image span. This reader does not establish an installed physical provider,
future interrupt ownership or a global execution deadline. Physical parent
native/current-image/root bindings, whole-path work and deferred callback
bounds, cache/secure assignment/DMA stop/handback still need qualification.
No new candidate, model/codec, image/helper or device action follows; NEW0189
remains defaultOFF and NOTREADY. Physical0188/last actual FASTBOOT10:05 is
unchanged. The original source-only4732-check handoff above remains history.

The actual adapter's next source79044854b70d3a0d7bf890360fc2428c5a3bb3fd
adds the missing paired-return dispatch guard. Original RestoreTPLc6d4 may
dispatch any pending level above saved4 and call event.NotifyFn atc7c8; the
existing17..31 checks alone did not cover5..16. Complete pending/counter/twelve
queue heads are now retained before Raise/page/Restore, with nonempty lower
queues refused without walking or clearing them. Original SignalEventca90
skipsc7f0 when Type.bit9 is clear: timer-only/NotifyWait paths remain finite,
while every NotifySignal timer is refused pending actual callback source/bound
qualification. Neither a far-future trigger nor an existing signal count is
authority. This does not ban unrelated unqueued signal subscribers or imply
future interrupt ownership. The existing exact original source proofs are
reused; no provider inventory or source audit was repeated.8334 SOFTWARE
checks and complete112928B independently decoded prefixes pass, as do actual
COFF/MachO/defaultOFF exports. Private proof5c424a5919958c35422ffb2b102cec3027a75ba78135c84837caff962a8fefb8
records the limited scope. Initial generic GetMap/bootstrap callback admission,
whole-path budget and actual parent object/native bindings remain unqualified,
along with real cache/secure/DMA handback. No physical action or candidate.

The subsequent targeted initial-GetMap source check identifies a separate
dynamic dependency of originald3ec: GCD lock1bd48/list1bd60 uses80B nodes,
whereas the existing allocator captures64B map/free nodes at1b358/1bcc0.
GetMap also reads15x48B type-policy rows1be68 and uses154a8/1dc0 for output
merging/compaction. Returned-map capacity cannot bound skipped GCD entries.
The exact originalaf90→af88 RET0 makes the feature16 gap path and feature19
debug-provider branch cold; no new debug or memory-test dependency is inferred.
Private sourceproofe8f68be097ce6cd4434aad8b731a56cca747571e1249297f818c5783957aece1
records17 independently decoded direct BL targets, without executing PE code.
The actual parent's map_snapshot omits GetMap's local key/call witness and its
admission maps precede a later payload allocation, so it cannot be relabeled
current for MSS bootstrap. A fresh real parent call/map/object/source binding
and complete initial transitive work qualification are still required; no
closed ticket, artificial opened/valid state, key match or AT alone supplies
that authority. Comment-only source9a79f96c7ce2364f577d4486802d2cc23f6f9a3a
preserves the entire enabled149831B preprocessed C byte-for-byte;8334 SOFTWARE
checks/347280B component and exports are reused, not rerun. No physical action.

Source06a37e60039c2dfe61711ab82d431abcbe2fdb06 now connects real incoming
GetMap call evidence to the actual parent, under the defaultOFF remote-memory
flag. Exactly its two existing admission calls are wrapped, with no added map
query or allocator call. Independent67232B records retain actual entry/return/
key/full output tail, loaded-image metadata/BS tables, real parent native flag and FP/
architecture witnesses. Both phases still precede payload allocation and
explicitly cannot be renamed a later current MSS map or private owner grant.
Unknown/error/input corruption reaches RAM append then terminal hold before
Console/USB/reset.1452 new SOFTWARE checks and independent complete struct/
hashlib decode pass; full parent/wrapper COFF/MachO/generalregs/maxframe1024
compile and QEMU refusal also pass. Original allocator149831B enabled C and
old parent182485 OFF tokens are unchanged;8334 prior cases are reused.
Private proofa56dae13dee48e68f8ef51098d18fb3557df6b5462e93ce6e57ff9ddb390cf3f
records the limited scope. No original PE or device action ran. The necessary
later parent object/map and initial dynamic GCD/type-policy/callback work,
MSS allocations/cache/secure/DMA handback and whole candidate qualification
remain unfinished. No new model/codec/profile/image or firmware variant.

The subsequent parent-only integration retains the existing complete LoadedImage
handle enumeration and every96B metadata object twice (up to256), using the two
existing cache maps and fresh metadata/array page AT/PAR/native records. No new
GetMap/enumeration/allocation/provider call is added. It records loader/boot/
runtime classifications without reading image code or treating runtime pages
as reclaimable. Both snapshots precede the original handle-array FreePool;
metadata is not full immutable-source or future image/IRQ ownership evidence.
5141 new SOFTWARE checks and an independent252488B struct/hashlib decoder pass;
actual full parent/export COFF/MachO/generalregs/maxframe1024 pass. DefaultOFF
parent tokens and the old149831B enabled allocator remain equal; old8334/1452
checks are reused. Private proofda5102581b1e9b8410fc35c18d66b2220095de3292aa4faf66f2b7ad9ecf1e71
records the scope. No reference source review, firmware instruction or physical
action was repeated. Payload/root/source frames, the necessary later private
GetMap full dynamic GCD/type-policy/callback/work admission, real remote-memory
and secure/DMA lifecycle remain unfinished. NEW0189 NOTREADY; no new candidate.

The next real parent integration relays the existing opening/retirement GCD
GetMap callbacks after payload/log allocation, with no extra map or provider
call. It retains real active context/ticket/source, complete previous image
metadata and global native/load/payload/plan bindings. The payload metadata is
bound after the original successful finish CRC/layout validation and compared
with a fresh typed-map/readonly AT read. Root policy bytes remain metadata;
root/RAMCOW is not resident here and no disk/NV/remote-DMA authority is inferred.
Both calls use the original context opening/200ms without reopening or renewal.
The distinct later phase3/8192B relay cannot be entered through the incoming
phase1/2/65536B public wrapper.2341 new SOFTWARE checks,1452 affected incoming
checks, full parent/export COFF/MachO/generalregs/maxframe1024 and an independent
713376B generic-flow pair decode pass; old8334/5141 are reused. Private proof
7dab11e0a047368836e84ae643b67aa0dc17831e043e992ab36e39baa8aaed91 records
the limited scope. First private GetMap complete dynamic GCD/type-policy/
callback/work qualification, whole-call temporalIRQ and real MSS memory/cache/
secure/DMA lifecycle are still missing. NEW0189 NOTREADY; no physical action,
reference audit, image/helper/model/codec/CI or radio/scan/join/data occurred.


A subsequent actual-parent composition check found a concrete fail-closed bug
in e59f185: four pwsp_piece contexts and pwrcl_run_body's private client inherit
final->io, while its newly installed relay accepted only the final resident's
map addresses. The first preparation opening would stop before the Core map
leaf; no device ran this defaultOFF path. The parent now binds six exact
source/context/ticket objects and retains their eleven EXISTING private maps:
four readonly pairs, client opening only, final query/finish pair. No extra map
or provider call, synthetic query mask/finished state or renewed ticket exists.
Route selection rejects foreign/interior/mismatched map/buffer pointers before
following context fields. A readonly close remains the original phase1 and
zero-query shape; client closing is refused. Its retained opening digest and
original lifetime are checked separately for every route.
167 new ASAN/UBSAN SOFTWARE routing/composition checks and2341 affected prior
checks pass; independent struct/hashlib verifies all eleven356688B V2 frames
plus the zero unused client closing slot (4280256B total). These tests execute
generic GCD opens/maps/queries/finish with explicit peers, not the whole power
preparation/client constructors; full composed serial models remain required.
Full parent/export COFF/MachO/generalregs/maxframe1024 and complete defaultOFF
preprocessed byte equivalence pass. New48B dispatch fault raw and ON25MiB log
are not a resource/profile qualification. Private proof
91b69fc0557edb9939e507ff82d5c36483ce0c7572df40b191fbab2b3ae1b163
records the limited scope; previous proofs and RAW are untouched. Existing
allocator/incoming/image modules remain unchanged. No reference re-audit or
physical action occurred. First private GetMap dynamic GCD/type-policy/source/
callback/work/temporal admission and real MSS allocation/cache/secure/DMA
lifecycle still block a necessary candidate. NEW0189 NOTREADY; WiFi firmware,
driver and scan have not run physically, and there is no reliable usable-WiFi
completion date.

The correction is source dddb6af10b038eb3c7114f049c458efb9e7f6716, directpushed
and independently lsremote matched. Source/software receipt25e1061f31dac6b80d1a70f81f52c789e75d34d9cbb2edee8b723db8e2324b91
remains private; all jobs ended and the device status did not change.


A new narrow own-Core SOURCE check addresses the separate80B GCD node's
allocation provenance for first-GetMap admission. Split-node request80 reaches
type4 AllocatePool via7f44/dab8/d880/d82c/4884; initial node copy uses
9138/dd80/dd44/d82c. This differs from the existing64B allocator descriptors.
The ordinary source path uses a24B header,80B payload and16B tail (120B),
first128B pool class and8B slack. The original class geometry implies a
single-page container for a surviving ordinary allocation; this is not a
runtime node observation or an address/owner permission. Request type4 selects
Core1d1a0, but its type field is zero in source DATA and runtime initialization
is UNOBSERVED. Used-byte totals and free bins do not enumerate live allocated
blocks; tags/type/size/tail/alignment can only be integrity conditions alongside
current typed/page/source/native/AT/lifetime inputs. No old cache map, map key
or pool snapshot becomes an owner lease. No pool method was called and no
new runtime reader/admission was implemented. Private source-only proof
ff8490e0f6baa362f4322bc7e53418a348abec8c3302ce7f38ebc1117260656d
records36 independent word decodes and the limited inferences. Earlier source
reviews are reused. Functional source dddb6af and all software tests remain
unchanged, without ASAN/model/CI/crosscompile/device reruns. First private
GetMap complete dynamic inputs/callback/work/temporal qualification still
blocks real remote-memory lifecycle and a necessary NEW0189 candidate.


The subsequent implementation adds a real parent input PRODUCER at the existing
final cache slot1 GetMap, before handle-array FreePool. It does not add a map,
enumeration, allocation or provider call. Internal phase4 preserves the original
64KiB output/call witness and original cache opening200ms; public incoming
phases1/2 still reject3/4. Complete64B current EFI-map nodes, full120B containers
for80B GCD nodes (both chains max256),15x48B policy, full232B pool descriptor,
three locks/heads/key/depth/busy/SMM/TPL and all typed/native/readonly NSWB AT/PAR
prefixes are retained. Runtime pool type4 is checked separately from source
DATA zero. Container geometry/tags/accounting are integrity conditions, never
an active allocation inventory or owner/IRQ/secure/DMA lease.
The new309664B SOFTWARE record/input96B/node256B/clock128B is distinct from all
prior records.1564 new ASAN/UBSAN checks and affected1452/2341/167 serial checks
pass. Independent struct/hashlib decodes two full normal3/max256 records, all
73/326 ATs and76/329 clocks, ten full Core hashes, complete node/policy/map raw,
unused tails and SHA. Actual parent/export COFF/MachO/generalregs/maxframe1024,
export exact PAR restoration/noSMC, whole parent defaultOFF and standalone
allocator-prefix equivalence pass. Old8334/5141 evidence is reused; no whole
cache/power-constructor model, firmware instruction, new reference review or
physical action was performed. Private producer proof
10f4853d3c47465d79d506527e4885c4510c95f70de44a27e90f5afb19c625ef
records the limited scope and preserves early compile/fixture failures.
This producer uses its own incoming UEFI standardGetMap contract; it is NOT
pre-call qualification of that same call. FreePool can change the graph/key
before later private maps. Fresh exact-context consumer/source/callback/work/
whole-call temporalIRQ admission still must be implemented; no old map/AT/key/
tag/counter becomes permission. Real MSS allocation/cache/secureVMID/MPU/
remoteDMAstop/handback and full retirement, two serial whole constructor models
and new profile/resource/codec/transition/freeze/helper remain prerequisites.
NEW0189 NOTREADY. WiFi firmware/driver/scan/join/data have not run physically;
there is no reliable working-WiFi completion date. Sound and camera remain STOP.

Producer source3505113548ff2ff97ec864ca37c648db42234569 was directpushed under
the actual standing source/text authorization; independent lsremote matched.
Only the seven reviewed source/text paths were published. Raw/private artifacts
remain local, all jobs ended, and physical0188 status is unchanged.


A new narrow original-Core SOURCE check addresses the EXISTING handle-array
FreePool between that producer and later private maps. Registered
LocateHandleBuffer2790 allocates bytes from its first sizing query through
d8b4(type4)->d82c, while reporting count from the second query. Returned count
alone therefore does not prove allocated capacity/header.Size. Registered
FreePool3be0->3b7c locks1c1f8, calls38b0 and unlocks1f48. Its ordinary successful
path loads actual header.Size and subtracts it from selected descriptor
UsedSize+8 before free-bin/backing work. Small free rewrites the block header
and free bin; a wholly free backing granule can enter3850->aec0->165d0(type7),
changing map topology/key. This does not promise an exact net return delta:
RestoreTPL and existing callbacks may perform further work. Matching later
keys/tags/counters or bytes cannot exclude free/reuse or prove ownership;
requiring the entire producer pool prefix unchanged would reject ordinary
release rather than qualify a current consumer. The actual target/container
and release transition need binding before later fresh source/typed/callback/
work/temporal admission. No old source review or reference port was repeated.
Private source-only proof
454d9d62bf2c9adb43559a599249eac7de2adc4e0b0543ff0576206b7417ed68
records45 independent PE-word/registered-slot decodes, without executing source
instructions or firmware. Functional source3505113, all C/header/test/schema
bytes and prior software results remain unchanged; no rerun/model/cross/CI,
new query, inventory boot or device action occurred. NEW0189 NOTREADY; no
WiFi firmware/driver/scan/join/data milestone or reliable completion date.
