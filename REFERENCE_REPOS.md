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

## Auth assignment control evidence after native MBA readiness (0189, 2026-11-06)

Physical992D5165 from restart-page-map-0001 reaches PWNS_AUTH19 with boot0,
auth2, owner0 and propagated power12. The parent cannot reach this stage
without native MBA ready and pmsn_begin returning; actual modem authentication
and WLAN are still unproven. Error2 is the common pmsn_secure failure path,
not enough to attribute a secure-monitor denial, timeout or source failure.
The existing own DT/pil-msa metadata/MP_ASSIGN references below remain the
hardware protocol authority. No foreign VMID/SMC, ownership assumption or
changed timeout is introduced to guess a fix.

Failure display adds only saved control evidence: bounded assignment/event
indices, phase/pending/flags, transaction error/step/counts/elapsed ticks,
source check stage/TPL, descriptor AT results, saved SMC x0/x1 and cache
status. It never dereferences the descriptor page or transferred target, and
makes no new call/retry. All code outside this one GOP evidence function is
byte-identical to702277b; all native headers are unchanged.336 additional
extracted production cases cover five assignment slots, boundary indices,
zero/valid/overflow events, saved64bit values and CPU_ON/display guards.

## Own MSS restart page namespace/mapping (0189, 2026-11-06)

Physical406C0C17 from pdc-leaf-map-0001 reaches MBA MAP HOLD, target0c2b0000,
GCD type0/matches1, cap/attr0, no EFI overlap, gap0c266000..0c3fffff. By the
actual reset producer order this follows PDC map preparation and PDC/ALT-on
operations; it is not a direct PTE dump or an MBA-ready indication.
Own live DT5572..5573 names restart_reg=0c2b0000/4. Own pil-msa.c229..255
writes the direct restart register when present/non-secure, then mb/2us;
264..281 orders PDC,ALT,restart and inverse release. Current own DT has no
secure restart resource property. Existing typed reset command sequence is
unchanged; no secure-call substitution or foreign address is introduced.

Only0c2b0000 gains empty-type0/no-EFI admission; its whole observed gap does
not. A separate retained restart mapping state keeps an already-valid Device
page untouched or applies the same stable-zero L2/L3 insertion machinery,
exact single leaf(index176), live exclusive owner, qualified WB source/table,
zero-only publication and strict post R/W AT. Existing PDC/QDSP mappings are
checked throughout. Nonzero/valid foreign entries, adjacent pages and changed
ancestors still refuse. RESET PAGE HOLD exposes the failing page and DESC3.
Software fixtures reproduce the actual gap and exercise all three mapping
groups independently and simultaneously. No actual restart/MBA/WLAN success
is claimed. The earlier Arm/EDK2 and local HackiOS review still applies;
no reference supplies this phone's resource ownership or physical results.

## Own PDC existing-L3 empty leaf (0189, 2026-11-06)

Physical945DC9B8 reports PDC PAGE HOLD, error2/no publication, walk error3,
levels4/stable1, reader error0, BEFORE0=80f, and a nonzero L2 table pointer.
Its DESC3 was not displayed. Therefore an invalid L3 descriptor is observed;
exact zero must be proved at runtime, not assumed from the photograph.

The same own PDC preparation now accepts a four-level stable walk ONLY when
its last descriptor is exactly zero and all ancestors are unrestricted table
entries. The existing loaded-image-excluding/writable-WB RAM reader qualifies
that precise8byte source twice. One zero-only exclusive store installs only
0b2e0000 as Device/EL1-RW/PXN/UXN, preserving every neighboring L3 entry.
No new table is allocated/copied/published on this path. Cache/TLB ordering,
strict post-AT, retained ancestor/leaf checks and no-retry/held-owner failure
semantics are unchanged. Nonzero invalid and valid leaves both refuse.
QDSP/RMB keeps its separately verified invalid-L2-only path. The diagnostic
now shows PDC DESC3 explicitly. This is not permission to map arbitrary holes.
Primary Arm/EDK2 insertion references and own DT/vendor proof remain those
listed below; this adds no foreign address or reset sequence.

## Own PDC namespace and conditional mapping (0189, 2026-11-06)

PhysicalA0343D90 from mss-page-map-0001 reaches MBA MAP HOLD for0b2e0000,
GCD0/matches1 (explicitly confirmed by human), cap/attr0, no EFI overlap.
Reaching this command after mapping preparation implies QDSP/RMB translation
checks and the initial QDSP DEBUG read passed; it does not prove MBA ready.
Own live DT lines5572..5573 names pdc_sync=0b2e0100/4 and line5594 sets bit9.
Own pil-msa.c lines201..216 read-modify-write only that mask, ordering and2us
wait; reset ordering is264..281. No foreign PDC register or mask imported.

Namespace policy now permits the same strictly empty type0 record for ONLY
this additional page0b2e0000. Active Device identity R/W AT still gates every
real access. Preparation keeps an already-valid page untouched; otherwise
it requires a stable invalid L2 and uses a separate resident one-leaf table
(index224, other511zero), the same exclusive CPU owner/RAM qualification/
zero-only publication/post-AT checks as the QDSP/RMB pair. There is no
adjacent-page grant, valid block split or generic mapper. PDC table lifetime
is retained with both existing MSS pages. Unexpected table geometry refuses
without guessing. Physical PDC publication/reset success still needs a trial.

## Own MSS invalid-L2 mapping repair (0189, 2026-11-06)

Physical8C01476D shows three stable table descriptors: two tables followed by
zero at L2 for04080000. Reader error0, issued/returned1, bytes8. This is an
unmapped region, not a valid mapping to physical0. The TCR low digit in the
photo is ambiguous; use the actual retained register, never a guessed digit.

Own DT/vendor resources above remain the authority for exactly04080000 and
04180000. Both lie inside the same invalid2MiB L2 slot. The complete native
parent may now install one resident BSS L3 table containing ONLY these two
4KiB Device-nGnRnE/EL1-RW/PXN/UXN entries; the other510 entries stay zero.
The helper requires the observed4KiB/WBWA/inner-shareable/40bit-PA TCR format
with root level0 (T0SZ16..24), stable zero L2 and unrestricted ancestors,
qualified writable WB source/table RAM and the still-exclusive CPU0 owner.
Already-valid Device mappings need no mutation. Mixed, occupied, malformed,
changed or unsupported walks are refused. One zero-only exclusive store;
cache/TLB synchronization; both read/write AT must then independently match
the exact identity Device pages. Every later MBA owner check retains all
ancestor/leaf entries. No allocation, firmware callback, valid-entry overwrite,
MMIO policy bypass, failure retry or partition write. Table lifetime matches
the retained parent; there is no generic mapping/unmapping service.

TianoCore primary references reviewed:
[ArmMmuLibCore.c](https://github.com/tianocore/edk2/blob/edk2-stable202411/ArmPkg/Library/ArmMmuLib/AArch64/ArmMmuLibCore.c)
ReplaceTableEntry distinguishes invalid from live-block replacement;
[ArmLibSupport.S](https://github.com/tianocore/edk2/blob/edk2-stable202411/ArmPkg/Library/ArmLib/AArch64/ArmLibSupport.S)
orders table writes and TLB invalidation. This implementation performs a
stronger broadcast invalidation while all seven peer CPUs are held OFF.
Neither reference nor HackiOS supplies hardware addresses or replaces this
phone's actual descriptor/DT/CPU-owner evidence. Private source hashes and
physical evidence reside in mss-page-map-0001 and mba-table-diagnostic-0001.

## MSS translation evidence after first target admission (0189, 2026-11-06)

Own06A68979 physical screen reports both read/write PAR output PA zero for
requested QDSP page04080000, with equal saved/restored PAR and all AT flags1.
The actual generated pmni_translate uses the retained target page as both AT
operands. This is not evidence that reading physical0 is permitted.

Arm's [PAR register definition](https://documentation-service.arm.com/static/5e7e1405b471823cb9de57ae)
describes the translated output address separately from attributes. The own
live TTBR0/TCR must determine any table diagnosis; no HackiOS/redwood table
address substitutes for it. HackiOS XnuLoader.c logs these registers but does
not establish this phone's mapping. No foreign mapping code was imported.

Failure-only diagnostics now decode only 4KiB TTBR0,16..39 T0SZ, <=48-bit PA
formats. At most four descriptors are read through the existing live owner,
BootServicesData/image exclusions and WB identity translation reader; every
entry is reread for stability. Raw tables, source addresses/PAR/flags and
reader refusal codes remain recorded. Decoded PA is evidence only, including
zero. No leaf PA dereference, table update, TLB change, access-policy change,
firmware call or hardware timing change is introduced.

## Own MSS pages absent from firmware resource enumeration (0189, 2026-11-06)

Physical468560A1 shows QDSP page04080000 inside one GCD type0 record with
capabilities/attributes0, no EFI overlap; initial DEBUG load never issued.
The [PI GCD definitions](https://uefi.org/specs/PI/1.9/V2_Services_DXE_Services.html)
call type0 NonExistent. That record is not a CPU mapping, device permission,
or proof of real MMIO accessibility. Preserve its actual type in evidence.

Independent own live DT SHAebdff5c2c30ccb69b5f9f35684cbc968e150d34e2aacead1a4f5aff8ca47c7b1
lines5570..5593 names qdsp6_base04080000/100, rmb_base04180000/20,
alt_reset04180044/4 and qdsp6v65-1-0. Own pil-msa.c SHAde6fab1d... and
pil-q6v5.c SHAa15e83d2... specify DEBUG18/SLEEP3c/CORE400/CMD404 and RMB
status40, including explicit offsets beyond the short DT spans, all within
the same two4KiB pages. No HackiOS/other phone addresses or inherited power
assumptions substitute for these own resources. Source/photo proof remains
private in mss-dt-pages-0001.

Only these two pages may use a type0 GCD record with zero cap/attr/padding/
image-owner/device-owner and NO EFI overlap. Fresh node equality, current
exclusive owner, typed exact command and native Device read/write identity
AT checks remain mandatory; failed translation cannot issue a Device load or
store. No GCD/page-table mutation or firmware service call. Other pages,
including adjacent04084000, keep the existing registered-MMIO requirement.
Physical Device accessibility, MBA-ready and Wi-Fi still require actual proof.

## VRM read-response fields (0189, 2026-11-06)

Physical supply-values screen shows all19 baseline reads retired: ARC6/3/0,
minimum7/4/7; four VRMs each raw voltage/enable0x80000000 and mode/headroom0.
The [Qualcomm VRM vote-table header](https://github.com/Rivko/android-firmware-qti-sdm670/blob/20bb8ae36c93fc16bbadda0e0a83f930c0c8a271/aop_proc/core/pmic/vrm/target/670/hwio/vrm_votetable_hwio.h)
(blob eb2ae240f06f2d160555aca82787413e49d1c029) defines bit31 RESP_REQ separately
from voltage13/enable1/mode3/headroom9 data bits. Its HAL uses field offsets
0/4/8/c. This agrees with own PMIC4 DT/vendor correspondence below and the
observed response pattern. Reference SDM670 firmware is NOT the exact running
Polaris build; no foreign addresses or firmware binaries are imported.

The supply consumer now retains raw responses/hashes in request/event evidence
and separately decodes logical READ values for baseline, verification and
restoration. Reject other reserved bits and ARC bit31; never replay response
metadata as regulator CMD_DATA. Own voltage/mode/order/time constraints remain.
Private source provenance/photo/software proof: vrm-read-format-0001. This is
not proof of physical voltage readiness, MSS start or WLAN operation. The local
HackiOS references do not replace own DT/vendor semantics for this hardware.

## Own MSS descriptor-page allocation (0189, 2026-11-06)

Physical delta shows one conventional page at0x17017b000 becoming type4 outside
our below4GiB metadata claim. Exact original DxeCore SHA61236b079f66c1340bfb3e9e15e055ecfe9bdfa2e7eabed157832147bc8f3609
has free-entry replenishment b3a8..b3b8: type4/pages1/alignment4096/guard0 to
c16c, followed by64 entries. Compare primary
https://github.com/tianocore/edk2/blob/edk2-stable202411/MdeModulePkg/Core/Dxe/Mem/Page.c
AllocateMemoryMapEntry/CoreFreeMemoryMapStack (retained source SHA
d3ae3b2141f3459520b71f02bfd66dda6748cd297d1f186dee29c59b4992486b).
This supports one firmware-owned auxiliary page; it grants no caller ownership
or radio permission. MSS-only policy accepts at most4096 type7->4 bytes above
4GiB outside own DT/image/bank/retained/claim exclusions, with all remaining
map bytes and coverage exact. Early allocation policy unchanged. No HackiOS
radio/allocator or foreign hardware mapping is ported. Private source/photo/
software evidence: mss-map-heap-0001; actual fix still requires temporary boot.

## Own AOP QMP connection (0189, 2026-11-06)

The own msm_qmp.c blob d6e41ae5d88db0f91e1c6fd13f1005dbb5e56481
uses LINK_DISCONNECTED -> LINK_NEGOTIATION -> LINK_CONNECTED, then local
channel open and remote channel acknowledgment. QMP_TOUT_MS is5000 and
QMP_TX_TOUT_MS is1000. Current physical photo proves the descriptor is
readable, with remote link UP and the AP/channel fields DOWN; the earlier
connected-only transport therefore cannot start. Mailbox offsets/sizes remain
runtime descriptor inputs, never numbers inferred from a blurred photograph.
The native path only opens a pristine, twice-confirmed idle endpoint under
continuous exclusive AP ownership. It writes ucore.link_ack, mcore.link_state,
mcore.ch_state and ucore.ch_ack UP, with Device readback/order/doorbell. It
preserves remote-owned ACKs and mailbox allocation; unlike cold Linux init it
does not redundantly overwrite already-DOWN remote ACK words. Remote UP-only
transitions are accepted at the matching phase; resets/mixed inherited states,
allocation changes and nonempty RX/TX refuse without draining or canceling.
One absolute5s connection budget precedes the existing2s transport budget;
TX consumption retains its1s bound. The fixed2048-event journal may refuse
sooner if exhausted. OFF never reopens a channel or renews connection time.
Private evidence: aop-handshake-0001. Software tests do not prove physical
AOP negotiation, MSS boot or Wi-Fi networking.

## Own AOP message-RAM resource (0189, 2026-11-06)

Rechecked own live.dts qcom,qmp-aop@c300000: message RAM c300000/1MiB,
IRQ1799000c/mask1 and descriptor offset0. Own msm_qmp.c Git blob
 d6e41ae5d88db0f91e1c6fd13f1005dbb5e56481 obtains those named DT resources
and maps them noncacheable. UEFI PI1.9 GCD service definitions distinguish
resource registration from CPU translation. The observed UEFI GCD type0/zero
attributes and absent EFI descriptor alone supply no hardware permission.
Our native AOP path uses the exact own-DT resource, requires no EFI/image
backing and a current zero/unallocated whole-aperture GCD node, then unchanged
identity Device R/W translations before each access. Actual type0 is retained;
no generic MMIO acceptance, GCD/page-table mutation or foreign mapping is used.
Private source/DT provenance: aop-own-resource-0001. The subsequent photo
proves actual descriptor reads; connection protocol and Wi-Fi remain unverified.

## Own userland launch probe (0189, 2026-11-06)

Reviewed the retained HackiOS userland build.sh (same a79ff077 reference,
SHA71e311d72936b92c2643bf8141f4ddb1cdbe3e6b880e2388b139c46a15754427):
its lines538/624 distinguish job-directory selection from the existing iOS
xpc/launchd.plist cache. Our existing20F66 init already edits that real cache
in RAM COW; the new optional root probe adds one job there and preserves the
Apple jobs. It calls our own polaris en0 control channel backed by the phone's
DT/firmware/AU implementation, not a reference radio. No DHCP implementation
or persistent root change is added. Software plist/ioctl and signed compile
results remain distinct from physical scan/networking.

## Own userland DHCP control (0189, 2026-11-05)

Compared HackiOS userland net_test.m at the pinned a79ff077 reference with
Apple bootp bootplib/ipconfig.defs blob6bc2246f4e3559481779792664bf07473979be3d
and ipconfig_types.h blob389f6416413a6a28b388d2bf1f5824866b8409ae. Our existing
BSD en0 has no reference IOKit radio implementation; its private native status
must report an authorized link before requesting configd DHCP. A generated
bounded Mach client preserves set_service ID20011 and uses real CF plist.
No reference driver, guessed IP, DHCP lease or DNS state is adopted. Software
IPC/helper tests and signed iOS16 compile do not prove physical networking.

## Native regulatory/control integration (0189, 2026-11-05)

Compared ath/regd.c, regd.h and regd_common.h at the same primary Linux commit
458c6079fc1d41d564c37679c8ace02cd83ee817 (Git blobs independently verified) with
ath10k TLV SET_REGDOMAIN and half-dBm channel encoders. Pinned upstream
wireless-regdb db.txt at40095bd16e53d5c5682fd6e7e3dbbbfaf0fe5410 from
https://kernel.googlesource.com/pub/scm/linux/kernel/git/wens/wireless-regdb
supplies the explicitly human-selected AU rule. Own narrower20MHz/20dBm,
channels1..11 profile keeps factory CTL limits and firmware frequency bounds.
Unsupported EEPROM mappings refuse; no beacon/host-locale country inference.
Private source/provenance: ath-regulatory-source-0001. Native worker and source
checks remain software/compile evidence, not completed physical networking.

## Own native CE startup (0189, 2026-11-05)

The later BSD endpoint compares HackiOS redwood_net's XNU ether/ifnet API use
with retained actual8796 kpi_interface/kpi_mbuf/if.c sources. Polaris's own
fixed mailbox supplies all radio frames/events; no reference radio driver,
firmware address, capabilities, connected-state assumption or Topaz provider
is adopted. Private root-only bring-up control remains separate from wifid.

Compared primary WCN3990 ce.c/hw.c/snoc.c with own ICNSS18800000 DT aperture,
35-bit DMA limit, SID40/41 and S1-bypass implementation. Independent CE allocation,
current native zero/cache/SMMU/CFG/MISSION and empty host ring initialization
now pass full software composition. Firmware opposite rings remain untouched;
source WI publication must use ICNSS+32000+4*pipe shadows, and source completion
uses DDR RRI. RX descriptors require cache-line ownership for safe recycling
on current WB CPU mapping. No hardware DMA, scan, runtime handoff or data yet.

## Own WLAN configuration and SMMU prerequisite (0189, 2026-11-05)

Official Linux v7.0.14 ath10k62 source files are retained with Git-blob verification
under ath10k-source-0001 at458c6079fc1d41d564c37679c8ace02cd83ee817. Its SNOC
WCN3990 CE/HTC maps were converted to own ICNSS QMI wire arrays;10 configuration,
MISSION/OFF scenarios pass with software modem, without native activation.
Own DT SID0x40/mask1 and icnss_smmu_init require explicit S1-bypass attachment.
Own arm-smmu.c uses S2CR TRANS + stage1/S2-bypass CB with SCTLR.M clear; DT alone
is not current route evidence. Native CE DMA/backing/runtime handoff remain.

## Own native shutdown and permission return (0189, 2026-11-05)

Own pil-msa shutdown/reset/clock ordering and ICNSS HLOS_ALL permission lists
were compared to the retained reference. Actual native composition now covers
fresh STOP ACK, AXI halt/reset, clock/proxy/supply/AOP retirement and exact inverse
MSA/RMTFS/modem grants, with software privileged leaves. This remains pre-CE,
unregistered, CPU-held and not physical Wi-Fi. Dipper's ath10k build explicitly
stubs missing driver/mac80211 symbols; its object is not a complete traffic
implementation. Primary Linux stable v7.0.14 commit458c6079fc1d41d564c37679c8ace02cd83ee817
is being retained for own CE/ath10k comparison without executing foreign scripts.

## Own WLFW/MSA startup (0189, 2026-11-05)

Compared HackiOS redwood_wlfw (WCN6750/ath11k), the retained Dipper ath10k
adapter and own c7cb50c1 ICNSS/wlan_firmware_service_v01 plus own live DT.
Polaris uses register20 -> MSA-info2d -> returned-region MP_ASSIGN -> ready2e
-> CAP24/FW_READY21; logical MSA1MiB. Secure regions omit WLAN_CE25, nonsecure
include it with MSS15/WLAN24. Own DT has four supplies and no optional ICNSS
clock property, so the reference's synthetic optional clocks are not adopted.
The new native producer chain tests pass with software leaves; actual runtime
handoff, CE/DMA/driver registration, retirement and phone validation remain.

## Own MBA secure assignment caller (0189, 2026-11-04)

Own pil_mss_reset_load_mba copies/assigns the independent MBA before reset.
The actual UEFI parent now optionally consumes its own staged record and
performs the HLOS3->MSS15 RW request with retained descriptor/continuations,
CPU0/peer/FP/source checks and descriptor-free UNKNOWN logging.69 software
scenarios,101 ABI/85 corruption checks and both full native formats pass.
No reference memory pointer/PAS identity, privileged execution or DMA handback
is inferred. Persistent power and actual MSS startup remain next; see NOTES.

## Own staged MBA and metadata (0189, 2026-11-04)

Own pil_mss_reset_load_mba copies MBA before HLOS3->MSS15 RW and reset;
own metadata authentication uses separate page-rounded storage. The actual
UEFI parent now optionally copies verified own MBA/MDT into its new retained
allocations with per-page AT/readback/CIVAC, before any secure or power action.
Own firmware parser and private data bundle preserve all28 relocatable modem
segments for the next loader; no borrowed carveout/firmware/DT pointer is used.
88 software scenarios, independent codec and both native parent formats pass.
References remain comparative only; physical packaging, secure/power lifetime
and MSS/GLINK/WLFW are not established by staging. See current NOTES/evidence.

## Own independent MSS allocations (0189, 2026-11-04)

Own MDT has28 relocatable loadable segments, span120MiB, first alignment1MiB.
Own loader sorts by PA, copies exact filesz, zeros BSS, verifies full memsz.
The real UEFI parent now optionally allocates separate modem/MBA/metadata
from current conventional memory; no HackiOS fixed bank or Dipper camera
reservation is reused.7261 software checks, independent codec and two whole
parent native formats pass. Staging/VMID/persistent power are still required;
the driver is not a new physical boot candidate. See latest NOTES/evidence.

## Own metadata authentication and return (0189, 2026-11-04)

Own pil_msa_auth_modem_mdt and pil_assign_mem_to_linux establish the separate
metadata allocation, RMB length/address/command1, status3/negative-error and
MSS15->HLOS3 RWX return order. The new finite protocol and default-OFF native
adapter use this own path, not a reference PAS ID or fixed reserved pointer.
20883 software checks and two native exports pass; parent staging/cache and
complete lifetime remain unimplemented, so no free or hardware claim follows.

## Own self-auth MBA boot (0189, 2026-11-04)

Own pil-msa.c/pil-q6v5.c and live DT select qdsp6v65-1-0, DEBUG preservation,
reset pulse, RMB image publication and SLEEP/BOOT FSM/PBL/MBA status ordering.
The present minidump-id makes PBL/MBA timeouts3s each. New finite protocol and
default-OFF native adapter pass63161 software checks and both native exports;
existing389737 checks also pass. Dipper's generic staged remoteproc approach
was consulted, but no reserved allocation, inherited power, PAS ID or guessed
permission is adopted. MBA-ready is not authenticated modem or WLAN-ready.

## Own MSS active-clock lifetime and native leaves (0189, 2026-11-04)

Pinned own gcc-sdm845.c, clk-branch.c/h, clk-regmap.c and sdm845.dtsi establish
the named six-clock order and HWCG/voted/gate delays. Dipper's register table
was compared, but its staging order and inherited power assumptions were not
adopted. Live DT numeric IDs differ from this vendor header; named clock/DTS
correspondence, not numeric-ID casting, is used. New persistent clock protocol
and default-OFF actual MMIO/AT leaves pass389737 software assertions and two
native exports. Parent GCD/source/exclusive lifecycle, proxy power and actual
hardware are still unqualified. No software result grants secure handback.

## Own MSS shutdown reset sequence (0189, 2026-11-04)

Own c7cb50c1 pil-msa.c and current phone DT establish PDC b2e0100 bit9,
ALT4180044, RESTARTc2b0000, ordering and2us/200us delays. The new finite
composition follows fresh stop ACK and all three AXI halts; it does not copy
Dipper power assumptions or invent ALT/RESTART reads.19946 software checks
and two native exports pass. A reset pulse is not complete DMA retirement or
permission return; real native clock/power/MMIO ownership remains required.

## Own RMTFS native secure caller (0189, 2026-11-04)

The own sharedmem consumer's client1 HLOS+MSS RW request is now implemented
by a default-OFF native caller over the actual early/retained allocation.
It zeros/cache-cleans the inner2MiB, excludes both guards, retains descriptor
storage and every interrupted secure result, then restores CPU/FP exactly.
66 software scenarios (60178 assertions), real host guard/protection tests and
two native exports pass. No reference reserved address or owner assumption was
ported. No physical enable, remote lifecycle or handback is established.
Own ICNSS MSA uses remote-provided secure/nonsecure regions and remains separate.

## Incoming UEFI independent claims (0189, 2026-11-04)

New default-OFF producer uses original UEFI allocation services before payload
and remote startup, retaining separate own-sized MSA/RMTFS claims below4GiB.
UEFI2.10 section7.2 supplies the incoming allocation contract; it supplies no
Qualcomm VMID/DMA ownership. Own-DT exclusions and original Core binding remain
required. No Dipper camera carveout or HackiOS fixed payload reservation is
borrowed.1110 protocol plus708 actual-caller software-peer checks pass; original
firmware is inert hash data only. See NOTES for remaining physical integration.

## Own MSS stop acknowledgment and AXI order (0189, 2026-11-04)

Own pinned msm_smp2p/private/smem sources and own DT establish APPS428/MSS435,
master-kernel STOP0/slave-kernel ACK3 and distinct SMP2P0x4000 pulse at1799000c.
The protocol keeps STOP asserted and starts the existing three-port AXI halt
only after a fresh ACK.2506 sanitizer checks and two native exports pass.
Dipper's request pattern was compared; its ADSP identity, reserved allocation
and unconditional request-clear were not copied. No native backend, hardware
retirement grant or whole-gate completion. See latest NOTES and private proof.

## Own secure descriptor cache and continuation (0189, 2026-11-04)

Pinned own cache.S/assembler.h confirm CTR DminLine and whole-line CIVAC/IVAC
plus DSB SY. New default-OFF leaf processes one exclusive retained descriptor
page; a finite protocol preserves interrupted x0..x6 and compares4096 immutable
bytes only after post-return invalidation.501 sanitizer checks and six native
compile/assembly variants pass; no hardware, owner update or release. Dipper
uses a descriptor-page CIVAC loop; its guessed owner/reserved spans remain
excluded. Original CPU EnableInterrupt clears I/F; Arm DAI0492v3 pp15-16 means
Group1 alone cannot be called complete interrupt exclusion. The first-allocation
bootstrap remains unqualified; no bypass or new operational route was added.

## Own secure memory assignment ABI (0189, 2026-11-04)

Pinned MiCode c7cb50c1 secure_buffer.h/c and scm.h/c Git blobs were verified
from Contents API. Together with the existing own ICNSS and sharedmem consumer
sources they establish MP_ASSIGN0x16/service0xc, SCM64 argument info0x1117,
VMIDs HLOS3/MSS_MSA15/WLAN24/WLAN_CE25 and24-byte destination entries.
Own RMTFS shares RW with HLOS+MSS; own MSA secure/nonsecure destinations differ
by WLAN_CE. Dipper's ABI agrees, but its camera-region allocation and initial
owner assumptions remain excluded. No vendor implementation was imported.
The independent encoder and default-OFF one-round leaf are unconnected;
4150 SOFTWARE checks, five full-byte comparisons and six native compiles are
not a secure handback, allocation lifetime or physical Wi-Fi result.

## Own payload page exclusion follow-up (0189, 2026-11-04)

Later parent and graph checks now exclude the full rounded payload allocation,
including its 2,720-byte tail, with overflow refusal and unchanged logical RAW
lengths. SOFTWARE baseline16/new34 and existing parent1452/current-map2341
checks pass; four wholeparent native compiles pass. No physical Wi-Fi claim.
The local HackiOS kernel loader excludes its complete fixed payload reservation;
our Polaris parent instead allocates pages dynamically and begin requires the
exact compiled payload length. No reference constants, scripts or binaries were
ported. Userland README confirms loader ownership belongs to the kernel tree.
No DT/vendor hardware mappings changed. See the latest NOTES handoff and private
payload-page-exclusion-0001 proof for scope and outstanding lifetime/bootstrap.

## Own parent payload allocation returned span (0189, 2026-11-04)

The actual parent now checks page alignment and the full returned payload
allocation extent with bounded subtraction. The old unsigned addition could
accept wrapped high addresses; no such firmware result was physically observed.
Same actual AllocateMaxAddress arguments, no new service/cleanup/free/retry.
Four actual physical wholeparent COFF/MachO ON/OFF compiles pass; one new
LLVM IR plus exact prior-source IR integer DATA confirm the range branches.
No LLVM/native/firmware execution, old suites/models/CI or device action.
Current parent SHA14fb822b1f43c41037529caf76872ecab7261badabc39f23d641ec0b7425d43b.
Private payload-allocation-returned-span-0001/proof.json
SHA39d5ceceace97a97ebd61f2b3f7e86dce70fae83e5873455f0daebd8dbf01291.

First-allocation-bootstrap-inputs-0001/result.json records the exact remaining
cycle: first Map precedes Core/config/TPL checks; later graph/provider/timer/
event inputs depend on that returned Map. Resident scalars and linked IO are
available but do not qualify the external call or lifetime. Six existing routes
were not expanded, no old-context/incoming-map reuse or minimum bypass. Next
work is payload full-allocation lifetime/exclusion extent. Whole gates complete
NONE, partial gate2 only. WiFi and next physical startup remain NOTREADY.
No HackiOS/vendor/firmware source was imported, executed or published here.

## Own parent log allocation result refusal (0189, 2026-11-04)

The actual parent now refuses a successful AllocatePool result with NULL
log_snapshot before GOP/normal service use. This is one source predicate,
not new lifetime/ownership qualification or a callback wrapper. Existing
EFI error propagation and admission-refused static-buffer rescue remain.
Four actual wholeparent COFF/MachO REMOTE_ON/DEFAULT_OFF compiles pass with
generalregs/frame1024; original and new LLVM IR confirm the new refusal edge.
No runtime test, original firmware/native execution, old suites/models/CI or
operational image/helper/device action. Prior OFF equality is historical.

Private log-snapshot-null-result-refusal-0001/proof.json
SHA1a03e1462eb24e73d232666953819a2243cfdf1f5332c5c683c7ecde91ea493f.
Parent SHA9b83788a2c730cf237c2c6874e2310da0f998c8cbf64b5d6a473af3faa6c810d.
The matching log address/length bindings already exist and were not rebuilt.
Earlier callsite discovery's 0x9d400000 AllocatePages is QEMU-only, not a real
Polaris allocation; old records stay unmodified. Whole gates complete NONE,
this is partial gate2 only; WiFi and safe startup remain NOTREADY.

## Own Polaris current-relay result effects (0189, 2026-11-04)

Published own source/text a7dff4cce2249968f41974c8f42d1102616ac8d9 through the
same original directpush, ENDED0, with subsequent independent lsremote match.
Exact five source/text paths exclude all private/device/firmware bytes. Receipt
SHA2c8977076b99500a7a73d986dbcecaf0e3ea069998fc7b0593a06d080da3eac3.
This handoff edits only NOTES and this reference index; no repeated tests.

The original published e4b4 SOFTWARE Map peer wrote the first byte beyond its
8192-byte declared capacity inside the retained65536-byte RAW and was accepted
through fresh graph/outer FP. This is a constructed peer observation, not phone
firmware behavior. The active relay now closes the resident356688-byte result
outside actual leaf output objects at its eight existing return boundaries,
after its original304-byte control seal and before source follow. Map permits
only36-byte metadata plus8192-byte DATA; no ABI or runtime RAW layout changed.

2292 new ASAN/UBSAN cases and all affected2341/167/2879/336/4553/1488/1275/2885
full suites passed strictly serially. Unaffected allocator/producer/release/
images/parentmap original whole host objects equal published e4b4; four parent/
relay native exports compile and OFF matchingtarget preprocessed pairs equal.
Independent DATA0004 rebuilds the40 full failed PCMP records, taking actual
leaf output spans as observed input and rebuilding every other after byte.
The42 paired bundles/11 normal records do not qualify external effects,
IRQ/ABA/owner/lifetime/precall or wholecall timing. Added own-record hash input
is5689112 bytes per normalMap; old4864-byte controls and existing work remain.

Private proof:0189/wifi/later-map-output-extent-0001/proof.json
SHAe8989422917c74890a7280dc89a0a993e32d680e2e1afc0ddb2e8a718e000ebc;
source/software SHAe653388a50014d194b1194e8572dfbfc02fea06dad0727a433376132bbf37c50.
No reference clone, vendor/firmware byte or original PE executed or published.
Main REMOTE_MEMORY defaultOFF, no new model/CI/codec/helper/freeze/USB/native
startup. Five-gate reporting is now required: completed whole gates NONE;
this is partial gate1 work, with gates1–5 still incomplete. Wi-Fi remains
physically unstarted; sound/camera wait for real scan/join/IP/DNS/data.

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


The next actual-parent implementation reads the real returned handle-array's
normal pool allocation container immediately after the GCD producer and both
pending metadata prefixes, before the existing FreePool. It adds no GetMap,
enumeration, allocation/provider/release call. Fresh typed4 readonly NSWB AT/
PAR precedes header and container pages. Actual header.Size48..2088 must cover
returned handles plus overhead, with full bytes/padding/tail preserved;
Size-40 is declared payload bytes, not class slack or a count-derived size.
The PCLI record retains unknown1/complete0/closing0 rather than a false early
finish. Full old records are sealed at entry/retirement, every live decision
prefix on callbacks, and the whole new record except exact outputs on each
callback. Key/Core/BS/roots/pool/policy/known graph/native/original200ms are
rechecked with ten additional hashes; no owner/IRQ/DMA or later map grant.
474 new ASAN/UBSAN SOFTWARE checks, independent full14784+309664+252488-byte
bundle decoding (two576936B artifacts), actual full parent/export COFF/MachO/
generalregs/maxframe1024 and whole defaultOFF equivalence pass. Old modules/
checks are reused, not rerun. Early compile, deliberate excessive-history-hash
iteration stop and test selector failure are preserved; all final cases remain.
No original20Core+70providerhash or raw evidence is reduced. Private proof
b0ae4a357ccc54211f06708c7f640d7a1f532903719f52096accd6e3a23e6217
records this narrow SOFTWARE scope. No original PE instruction, FreePool or
whole cache/power constructor executes in these tests. The exact real release
call/effects, post-release current source/typed/callback/work/temporal admission,
real MSS/cache/secure/DMA lifecycle, full normalUNKNOWN retirement and necessary
new candidate checks/profile/resource/codec/freeze/helper remain unfinished.
NEW0189 NOTREADY; no device/CI/model/image action and no WiFi feature milestone.

Container-reader source dbe6416121b5626787d1c10ece8f9eb2b0af21c4 was directpushed
under the actual standing source/text authorization, with independent lsremote
match. Only the five reviewed source/text paths were published; all raw/private
artifacts remain local and physical0188 status is unchanged.


The actual parent now wraps its EXISTING registered handle-array FreePool with
an ABI/source/return witness. The standard BS slot72 is compared with exact
Core+3be0, actual API issued/returned/status is separate from logical relay
markers, and no query/enumeration/allocation/provider/release call is added.
It archives the original14784B target/309664B producer/252488B pending PCLI,
recaptures the target through the same typed reader under the original200ms,
and preserves full callback envelopes, native/FP/source inputs and25+10 extra
Core hashes. It never reads a released target or follows new node/head pointers.
Fixed Core provider-global snapshots after return are incoming-contract raw,
not a current typed map, full allowed-effects proof, ownership or future lease.
535 ASAN/UBSAN SOFTWARE cases pass, including a simulated peer making retired
target host pages PROT_NONE; affected474 cases also pass with unchanged old case
loops. Independent struct/hashlib decodes the full596496B record and both full
576936B archived/fresh input bundles; actual wholeparent/export COFF/MachO/
generalregs/maxframe1024 and flagOFF equivalence pass. The export calls the
compared registered slot once and only writes PAR for exact restoration.
The initial host-page fixture failure and COFF timestamp comparison failure
are preserved; final evidence proves unchanged executing code without editing
object timestamps. Original PE/BS/AT/clock peers remain explicit SOFTWARE DATA,
not real FreePool or whole power constructor execution. Private proof
4d8fc7cbe8d0de988c381e6e9d47003cccfa2c30945275f4b61c73628b4a060b
limits this result to the call witness. Complete permitted pool/map/backing/
callback effects and fresh later typed/source/work/whole-call temporal inputs
remain unfinished, followed by real MSS allocation/cache/secure/DMA retirement
and the required new candidate checks/profile/resource/codec/freeze/helper.
NEW0189 NOTREADY; no physical device/CI/model/image action or WiFi feature
milestone occurred. No new reference/source audit was repeated this turn.

Release-call source dfa2692b076df9c68de89d0ea99c602bb50a50e0 was directpushed
under the actual standing public source/text consent; separate lsremote matched.
The first automatic disclosure rejection is preserved. Read-only verification
of the actual future-consent record, exact origin and eight reviewed committed
blobs resolved it; the same direct command succeeded without transport bypass
or a new human question. Private artifacts remain local; physical0188 unchanged.


The included real-parent FreePool body now admits a deliberately restricted
ordinary type4 small-free path and checks its exact fixed provider-prefix
effects. The class fits one backing page, a retained/currently compared GCD
container occupies its base, the selected bin is empty, and the full class
footprint avoids retained EFI-map/GCD nodes. Other valid geometries refuse before service.
Twenty new original-word checks identify the granule-walk bypass and empty-bin
insertion footprint; enabled0xaf target poisoning remains in the source path.
No previous entry/provider/GetMap review was repeated. After return, only the
actual Size subtraction and selected-head target links may differ in the full
232B pool; roots/key/policy must match. No freed page or new node is followed.
This conditional source slice and fixed-prefix check do not exclude callback
ABA, establish a fresh typed graph or prove whole-call temporal/owner authority.
771 ASAN/UBSAN SOFTWARE cases, affected474 cases, independent full596496B and
two576936B bundle decoding, actual parent/export cross-compiles and same-command
OFF baseline equality pass. Old535 loops remain with changed-key success now
refused, plus232 prefix-byte faults and four unsupported geometries. The old
61st AT fault remains in an independent cross-page fixture; its initial trigger
failure is preserved. Header-invocation comparison failures are also preserved;
new freestanding640972B equality does not replace old hosted644957B evidence.
Private proof c3a434f79851d6736ae44af4619672f2bf87f1174c71896fa93009431d98aba9
keeps this SOFTWARE scope. No original firmware instruction, device action or
whole constructor model was executed. Full callbacks/work/temporal and later
current source/typed admission remain required before actual MSS lifecycle and
new candidate checks/profile/resource/codec/freeze/helper. NEW0189 NOTREADY;
WiFi firmware/driver/scan/join/data still have not run physically.

Restricted small-free source bebea9d66137516e8957e9871afb7bf4c5e85880 was
published by the authorized same-repository direct push; independent lsremote
matched exactly. Only the five reviewed source/text paths were published.
All jobs ended and private evidence/physical0188 remain unchanged.


A new narrow own-Core SOURCE result closes the enabled nonzero poison-fill
leaf's address/work question, reusing the earlier entry/bin/granule results.
32 independently decoded original words propagate0xaf to a nonzero64-bit
pattern. CCMP at17290 leaves Z clear for every supported Size, so this call's
DCZID/DC ZVA zero-fill branch is cold; this is not a global zeroing claim.
Independent ABSTRACT interval arithmetic for256 actual Size values and5404
supported backing offsets proves exact [target,target+Size) coverage, including
overlapping writes: <=32 loop iterations,67 A64 store instructions,2128 summed
logical bytes/2088 distinct bytes,144 leaf/149 fill-chain architectural
instructions. None of these counts is hardware time, bus transactions, future
IRQ authority or whole-call qualification. The immutable Core binding already
covers the leaf; no source/runtime guard/hash budget is changed. Private proof
ef5e331405b53d6a0ea42744397e9d603e4e52fdbee880ebe89b5f55b251412d
is SOURCE DATA and arithmetic only, without original instruction execution or
new host ASAN/cross/model/CI/device work. Functional source bebea9d and all prior
raw/schema/software evidence remain unchanged. Remaining unlock/RestoreTPL/
asynchronous callbacks, full temporal/work and fresh later typed/source graph
inputs, MSS lifetime and new candidate qualification are still required.
NEW0189 NOTREADY; physical WiFi firmware/driver/scan/join/data have not run.

The poison-fill SOURCE text milestone bed76fdc58f50c0eccafee255c19bcfea5278874
was directpushed under the actual same-project public text consent; independent
lsremote matched. Only NOTES/REFERENCE_REPOS were published, with no runtime
source change, private evidence disclosure or physical action.


The actual parent now reuses a shared form of the allocator's existing deferred
reader at its EXISTING FreePool leaf. Pre/post pending/counter and every queue
head5..31 are retained in a separate1488B record, with the actual enclosing
live frame and service-boundary witness seal checked before source pointers.
Known pending/nonempty/inconsistent queues refuse; no queue traversal, clearing,
callback dispatch, IRQ/register write or extra service/query/AT/clock call.
The original allocator12-head/736B path and347280B ABI are preserved and all8334
cases pass against the CURRENT header;771 release regressions and646 new ASAN/
UBSAN composition cases also pass. Independent struct/hashlib checks the full
597984B paired raw, both576936B bundles,112928B allocator prefixes and service-
boundary/live/FP seals, without executing captured pointers. Actual parent/new
export and allocator exports cross-compile for COFF/MachO with general registers
and1024B frame limit; OFF baseline remains exact. No old proof or raw is edited.
A SOFTWARE enqueue-shaped mutation followed by restoration deliberately passes:
these snapshots cannot exclude intervening callbacks/ABA or grant IRQ ownership,
whole-call time or a fresh typed graph. That remaining source/work/temporal and
six-context current admission, MSS lifetime and new candidate qualification are
still open. Private proof
1a914e7e0c8bcba8b148732a81df9c63d73d68d7ce1e946c38619371ef7bf214
limits this to SOFTWARE refusal evidence. No original provider/PE instruction,
whole power constructor, model/CI/freeze/image/helper or device was executed.
NEW0189 NOTREADY; WiFi firmware/driver/scan/join/data remain physically unrun.

Shared-dispatch integration source b0db3abe639c24217fef28df619d8a0cf4a35146
was directpushed under actual same-project public source/text consent; separate
lsremote matched. Exactly eight reviewed source/text paths were published;
all private artifacts remain local, all jobs ended and physical0188 unchanged.

0189 corrects a concrete counter-domain bug in the existing own-source allocator
before reusing its Timer/GIC/provider path at bootstrap. Its generic actual arch
uses CNTVCT, but physical timer CVAL/regs/raise/final use CNTPCT. The previous math
mixed their epochs; equal-epoch peers missed it. A constructed arithmetic probe
returned bound1 before the fix versus6 through the physical conservative horizon.
No phone counter offset or hardware behavior was observed. The physical ceiling
now derives from the first physical sample plus one full duration, with checked
monotonicity/order/overflow. The unchanged original virtual opening200ms still
controls admission. scope_end_ticks retains its offset but now describes this
physical work ceiling, never a renewed lease or whole-call walltime bound. Old
RAW/proofs retain their old source semantics; no CNTVOFF assumption/reader added.

The affected standalone suite passes8487 ASAN/UBSAN SOFTWARE checks (old8334 plus
135 independent128-bit/domain cases and18 allocator compositions), including
widely different counter epochs and original virtual expiry. Independent numeric
struct/hashlib decoding verifies112928B prefixes and three full347280B records,
six complete provider prefixes and420 source hashes. Actual whole parent/allocator
exports cross-compile for both COFF/MachO; parent MachO and OFF640972B are equal to
the same-command baseline, COFF differs only its typed timestamp. Native inline
assembly and source/native/FP/deferred gates are unchanged. Private evidence is
0189/wifi/allocator-counter-domain-0001; no reference port code, firmware execution,
whole cache/pwsp/client constructor model or physical action. Fresh bootstrap
provider/typed graph/callback/work/wholecall temporal inputs and secure/DMA life
cycle still remain. NEW0189 NOTREADY; no physical WiFi feature milestone or ETA.

Publication correction for this counter fix: b73a178 is LOCAL ONLY. Two SAME
standard directpush attempts were refused by automatic approval before execution,
including after readonly exact payload/connected destination/standing-consent
checks. Independent lsremote remains3639d80 (published functional b0db3ab). The
reviewer explicitly requires a trusted new user approval for this concrete public
push; b73a178 plus the current two-document handoff is awaiting that reply. No
alternative upload transport or device action was attempted. All validation and
private rejection evidence are retained, and no source/model checks are rerun
unchanged while this public-push question is pending.

Publication is now resolved by the actual new human response to questionItemId
call_868184b064aa4c6c8b7f5db205cb2c06, explicitly approving this and future similar
source/text public pushes (private authorization SHAce8ce4fd0c92c7f3e295289969531be7dfde562c1acac53c7adbc19eab8f37e3).
SAME directpush completed0 and independent lsremote matches9cca708, publishing
b73a178 and its two-document handoff. Earlier rejection/pending records are
immutable history, no longer a pending question. This publication correction
changes only two text documents; no source/test changes or reruns, reference
porting, device/USB/native/CI/model/image/helper/freeze action. All remaining
bootstrap/current-input/typed/callback/temporal and secure/DMA gates are unchanged.

0189 reuses the allocator's exact existing six readonly native MRS operations in
the actual parent before/after its EXISTING registered handle-array FreePool.
This adds a separate312B current-register input bound to real caller/witness/
source/FP/native envelopes, without a fake allocator context or new service/map/
allocation call. The original1488B queue and596496B release schemas remain.
VBAR is retained as numeric raw, never followed; physical epochs stay separate
from the original virtual200ms. Snapshots do not establish provider identity,
postrelease typed ownership, ABA exclusion or whole-call temporal admission.

All1725 ASAN/UBSAN SOFTWARE cases pass (old646 plus1079 new register/partial/
callback/service-record/foreign-storage cases); released target plus GCD page
remain host PROT_NONE. All leaves including MRS are peers, not native execution.
Independent struct/hashlib verifies full598296B and both576936B bundles. The old
allocator8487 suite is reused: full optimized peer LLVM IR and native MachO are
byte-identical, COFF only differs in typed timestamp. Six actual parent/export/
allocator cross-compiles pass, dispatch MSR only exactPARrestore/noSMC and OFF
640972B matches. Private evidence:0189/wifi/cache-handle-timer-inputs-0001. No
reference port, source opcode audit, model/CI/device/image/helper/freeze run.
Full bootstrap provider/current-source/callback/work/temporal/fresh postrelease
graph and secure/DMA lifecycle remain unfinished. NEW0189 NOTREADY; no WiFi
firmware/driver/scan/join/data milestone or reliable time estimate.

Timer-input source1d9e56153de8cf868d2e990760bc90059f75d106 is published under
actual current/future source/text consentce8ce4fd; independent lsremote matches.
This later handoff is two text documents only, with no source/test/schema/RAW
change or repeated checks. Current work remains the first bootstrap admission
group, not physical WiFi. Full provider/callback/temporal/postrelease input and
secure/DMA lifecycle gates still block a necessary candidate; no reliable ETA.

## Polaris0189 existing-release provider INPUT binding (latest source scope)

The actual parent now reuses the original Timer/GIC/CPU immutable-image, AT
replay and binding leaves at its existing registered FreePool interval. The
new separate20344B record preserves actual source roots, three complete image
states/method tables, selected GICv2/v3 table and full32..1020 handlers, with
real caller/witness/source closure. Existing timer MRS inputs bind VBAR as a
numeric retained CPU-image offset. No provider method or new BS service runs.

This is pre-input source binding against the retained typed map with fresh
AT, not a fresh postrelease map, owner/IRQ/ABA exclusion or wholecall deadline.
Post work deliberately never follows provider/handler or released target/GCD
pages; a SOFTWARE PROT_NONE case checks that boundary. Main stays defaultOFF;
no consumer/builder/CLI/new profile/resource/model/codec/helper/phone candidate.

FINAL2352 ASAN/UBSAN SOFTWARE cases PASS1725.4419106669957s, old1725 plus627.
Shared-helper factoring changed allocator objects/IR, so affected8487 reran
PASS173.2350442079478s; default release fixture771 PASS217.98769291699864s.
Whole parent/dispatch/allocator COFF+MachO/generalregs/maxframe1024 PASS; final
parent complete/closed guard checked on both targets. OFF640972B equal.
Independent numeric struct/hashlib verifies full618640B paired raw, both
576936B archived/fresh bundles and112928B six-prefix fixture; no PE or captured
pointer execution. All old RAW/proofs/timestamps remain untouched privately.

Private evidence:0189/wifi/cache-handle-provider-inputs-0001/proof.json
SHA ccb051c679ee42cac2e842f9770e0c74bee8f7e3df2600e8f313212fc75d8c70;
source/software b7ebe2bf4facf1f87973d3dae0007c74ade56825448bfd33a4ca98bf9511ba46.
Remaining transitive callback/work/wholecall temporal and fresh postrelease
typed graph/source in six actual contexts, real MSA/RMTFS/secure/DMA lifecycle
and full candidate qualification remain NOTREADY. WiFi firmware/driver/scan/
join/data have never succeeded physically; no credible completion date.
No new USB/physical run, no pending human/authorization issue.

Provider-input functional source6e5f58dc2128cf847aeaf1f1798b5cb180fca289 is
now published by the same directpush under actual current/future source/text
consentce8ce4fd; independent lsremote matches6e5f58d. Exact eight own UTF8
source/text paths only, all sensitive/private/firmware bytes excluded. Private
source receipt SHA434af65f09f21a3c9be6e1ad48a6c944b60356dd760bd9e857f206a6ea00dc87. This
subsequent handoff edits only NOTES/REFERENCE_REPOS; no code/test/RAW/proof edit
or repeated checks. The provider INPUT scope above stays SOFTWARE/NOTREADY.

## Polaris0189 virtual-clock handoff between existing nested and outer release

The source-only provider composition exposed a real software temporal gap:
old C accepted before20700 → nested virtual close23000 → outer final22999 and
restored FP. The existing guarded-release callback now produces its actual
latest virtual sample into a local scalar; the outer existing arch guard
requires a same-domain nondecreasing close before FP restore. Zero/missing or
out-of-original-window guarded output refuses. No new clock/service/reader/
wrapper/owner grant, no rebased200ms, no physical-counter epoch conversion.
Record schemas remain unchanged; the original firmware FreePool ABI is intact.

FINAL2364 ASAN/UBSAN SOFTWARE cases PASS1718.9069488330279s=all2352+12 temporal
cases. Affected standalone release771 PASS218.90741966699716s, current shim
FIRST/-H. Wholeparent/affected export COFF+MachO/generalregs/maxframe1024 PASS;
OFF640972B equal, export MSR only PAR restore/noSMC. Unaffected allocator8487,
other checks/models/CI were not repeated. Independent numeric struct/hashlib
verifies normal/refused full618640B and baseline616840B plus full archives and
all source/FP/control seals. The refused raw retains actual APIstatus0/1/1,
unknown/error6 and no FP restore/later sampling; every byte is accounted for
using a new derived buffer, never editing original RAW or executing pointers.

Private0189/wifi/cache-handle-temporal-handoff-0001/proof.json
SHA7a1e6feb0cf155865a4d02a37c151ce25d583791d5ca75258ad2dbc9b90165a9;
source/software5724781acacc3a41dd61153d90e81e52684e9c77de7d2e9b2aff7abd656ee283.
This fixes only temporal composition. Full callback/work/wholecall temporal,
fresh postrelease typed graph/source across six new contexts and real remote
secure/DMA lifecycle/full candidate qualification are still NOTREADY. No
physical WiFi, scan/join/data, new boot/helper or credible completion date.

Temporal-handoff functional source9e985718bd2b91233d485abb1cab3974b1752cd4
is published through the same directpush under actual source/text consent
ce8ce4fd; independent lsremote matches9e98571. Exact five UTF8 own source/text
paths, excluding all firmware/private/sensitive bytes. Private source receipt
SHA90fb2ade01a0fad411c5d4046b217da8de8552da0a54cd027bb68ae5fb2a1b9a. Subsequent handoff changes only
NOTES/REFERENCE_REPOS, no code/test/RAW/schema edit or repeated checks. This is
a SOFTWARE temporal fix; full physical WiFi/candidate admission stays NOTREADY.

## Polaris0189 actual pre-release event/timer graph input integration

The existing bounded event/timer DATA walkers are shared with the actual
parent's guarded registered-FreePool interval. Genuine allocator context
callbacks remain intact; no fabricated opened context, owner/ticket, firmware
callback or new service. Separate86616B graph RAW retains full event/checker/
nonperiodic timer nodes, partial prefixes,322 AT and324 virtual-clock slots,
real caller/control/service seals and all unused bytes. Old record schemas
remain unchanged. Normal SOFTWARE adds9 fresh AT leaves/11 virtual samples;
old provider20 AT/23 virtual samples/two six-MRS slots retain their scope.
All NotifySignal timers refuse. Failure is stickyUNKNOWN with no guessed
restore/cleanup. Postservice graph/provider pages are never followed; full
PROT_NONE positive explicitly demonstrates the unsupported postsource scope.

FINAL2863 ASAN/UBSAN SOFTWARE PASS3261.4731801670277s=all2364+499 graph cases,
including128 events/32 timers, refusing excess before following another node.
Affected allocator8487 PASS171.63756125001237s; release771
PASS219.76547491701785s; current shim FIRST/-H. Six parent/export/allocator
COFF/MachO/generalregs/maxframe1024 PASS. OFF pairs equal within each target:
MachO640972B/COFF640999B. Export MSR only exactPARrestore/noSMC; parent old FP/
terminalmask not zero-write. Other checks/models/CI were not repeated.
Independent numeric struct/hashlib checks normal/refused705256B, max86616B,
full archived/fresh bundles and old112928B prefixes without executing pointers.
Initial derived decoder path-depth and OFF expected-target-size mistakes are
retained privately and corrected in new evidence; no production guard lowered.
Pre pending refusal now occurs earlier in the new event reader; every original
fault case remains, and untouched queue samples remain truthfully unobserved.

Private0189/wifi/cache-handle-timer-graph-inputs-0001/proof.json
SHAc90033ffca102d2cfc1c72410089f659ac3df242e907201f1ec8324cfc347ab1;
source/software2e6094ddbbf7a50a7113b2b7f474fe8a4c51b36f8b493be6a0abba08cc7759ee.
This is retained-map/fresh-AT/source INPUT, not full transitive callbacks/work,
wholecall temporal, postrelease typed graph/source, future IRQ/owner or ABA
qualification. Original200ms is not renewed. Remaining six NEW context
composition and actual MSA/RMTFS secure/cache/DMA lifecycle/full candidate
qualification stay NOTREADY. No physical run, new kernel/image/helper/freeze,
WiFi firmware/scan/join/data success, human action pending or credible date.
Older reference/current/source results above retain only their historical
source scope; all original private RAW/proofs/schema/SHA/timestamps remain.

Graph-input functional source37cc382c8f41226d744070e9c4ccbc5d19f1119b is now published
through the original directpush with independent lsremote matching37cc382.
Exact eight own UTF8 source/text paths under actual current/future consent
ce8ce4fd; all sensitive/private/firmware bytes excluded. Private source receipt
SHAc3af456827709f77dfed6313074d67b5b13a173eef219e9abf0c1159e5f26748. This publication handoff edits only
NOTES/REFERENCE_REPOS, no code/test/RAW/proof/schema change or repeated checks;
full physical WiFi/candidate admission remains NOTREADY.

## Polaris0189 actual finite timer-work input consistency

The original finite timer-work DATA arithmetic now receives the actual
bootstrap's retained pre-provider state, pre-call timer counter and existing
two physical-register samples around registered FreePool. The old allocator
wrapper retains its real source/context/raise inputs. No fabricated opened or
finalized IRQ path, new service/permission/owner boolean, record or hardware
call. Invalid period/step/missed/counter/catchup arithmetic and a physical
sample beyond first+3840000 refuse before the next native flag read. The
original virtual200ms stays fixed, with no cross-epoch arithmetic or new lease.
Post math uses retained DATA and does not establish post-provider lifetime,
wholecall walltime, callbacks, futureIRQ/owner or ABA qualification.

FINAL2880 ASAN/UBSAN SOFTWARE PASS3290.1226351660443s=all2863+17 real composition
cases. Affected allocator8487 PASS172.88610024994705s. Default release771 body
reused without rerun: optimized SOFTWARE LLVM instructions unchanged, exactly
five typed !srcloc offsets differ; NEW derived comparison excludes only those,
original IR intact. Initial forced-baseline include ordering failure retained;
comparison0002 restores the genuine include order. Six parent/export/allocator
COFF/MachO/generalregs/maxframe1024 builds PASS. Export onlyPARrestore/noSMC;
OFF MachO640972/COFF640999 equal within each same-command pair. Other checks,
models and CI were not repeated, all source guards/cases remain.
Independent numeric struct/hashlib/arbitrary-precision decode checks four
705256B bundles, max86616B, both archived/fresh bundles and old112928B prefixes.
Period0 refuses before API; post physical-ceiling refusal preserves real mock
APIstatus0/1/1 with no outer closing sample/FP restore. Every refused byte is
reconstructed in new buffers; no original RAW, pointer or PE execution.

Private0189/wifi/cache-handle-timer-work-inputs-0001/proof.json
SHA76eb16680790359c4893e20ec87ea25f758e1d414f7a748cb131914ffbbc33e8;
source/software927ee2b8ff9ebee9e20daada907bd030825cadb88fb0dc1e0d2dabe55c8d696c.
This is SOURCE/SOFTWARE input consistency, not full transitive source/effects/
work/wholecall temporal or postrelease typed graph/source admission. Six NEW
contexts, real MSA/RMTFS secure/cache/DMA lifecycle and full new candidate
qualification stay NOTREADY. No physicalUSB, new kernel/image/helper/freeze,
WiFi firmware/scan/join/data success or credible completion date. All old
private proof/RAW/schema/SHA/timestamps retain only their original scope.

Finite timer-work input functional source303f790799b7d625ebd50811ff693331160a9a3b is now
published through the original directpush; independent lsremote matches303f790.
Exact five own UTF8 source/text paths under actual current/future consent
ce8ce4fd, excluding all firmware/private/sensitive bytes. Private source receipt
SHAaac79f46bc18df9b7de44bce18fec7c18c842dc46bc2d6076fc57b8dcdeb92cd. This subsequent publication handoff
edits only NOTES/REFERENCE_REPOS, with no source/test/RAW/schema/proof edit or
repeated checks. Full physical WiFi/candidate admission remains NOTREADY.

## Polaris0189 source/release page disjointness at the real FreePool caller

The existing parent witness, supported small-free geometry and captured
identity-AT pages now refuse release-page sharing with the parent image/Core/
Timer/GIC/CPU/handler/event/checker/timer source. No new reader, service,
record, hardware call or ownership flag. Whole-page sharing is deliberately
unsupported, even when byte geometry could otherwise be valid; this does
not prove source lifetime, full callbacks/wholecall time, futureIRQ/owner/ABA
or the phone's geometry. Original200ms is unchanged; no lease is renewed.

Constructed SOFTWARE baseline with303f790 production headers accepted three
same-page sources in class slack. New source refuses them before physical-
timer six-MRS slots/queues/API/FP, retaining graph and partial provider raw.
Adjacent previous/next4K pages pass. FINAL2885 ASAN/UBSAN SOFTWARE
PASS3263.3984556670184s=all2880+5 cases. Four affected parent/export COFF/MachO/
generalregs/maxframe1024 builds PASS; export onlyPARrestore/noSMC. OFF640972/
640999 same-command pairs equal. Unaffected allocator8487/release771/other
checks/models/CI were not repeated; changed provider header is not in their
body/include graph. No original firmware/native/wholeconstructor execution.
Independent numeric struct/hashlib checks seven full705256B bundles, max86616B,
four archived/fresh bundles and reconstructs every baseline/refused byte in
new buffers, without editing RAW or executing captured pointers.

Private0189/wifi/cache-handle-release-source-alias-0001/proof.json
SHA2dbb2e5f5f51ad5a95e41b857e76cd6c03f6bfe2b1d11134e2c1b19928cf82fd;
source/softwarea6f435906d99a02b274e3ff03afc877fdf1fa1f4147dd1bb701f37fda8e68330.
Full transitive effects/work/wholecall temporal and six-context fresh later
map/source/typed/policy qualification plus secure/cache/DMA lifecycle remain
NOTREADY. All three cache maps precede FreePool; later11 existing calls are
later boundaries, never self-precall proof. No physical WiFi run or credible
date. All original private proof/RAW/schema/SHA/timestamps retain their scope.

Source/release geometry functional source7f2c0add37552cec4a05d594b369efb6211f7ffb is now
published through the original directpush; independent lsremote matches7f2c0ad.
Exact four own UTF8 source/text paths under actual current/future consent
ce8ce4fd, excluding all firmware/private/sensitive bytes. Private source receipt
SHAbda8bc2774423fa92b9b15e18e5e2b109c12262104a5241af7d966e4327eb1d2. This subsequent publication handoff
edits only NOTES/REFERENCE_REPOS, no source/test/RAW/schema/proof change or
repeated checks. Conservative geometry/full-candidate/WiFi scope stays NOTREADY.

## Polaris0189 producer clock sequence before DATA-walk reuse

The actual existing phase4 producer now rejects same-CNTVCT rollback against
its preceding retained sample, preserving the original map-closing check and
opening200ms. A constructed original-code baseline accepted1200→1300→1299.
No new reader/service/contract/context, IO, hardware write or schema is added;
this does not establish fresh later maps, wholecall time, source lifetime or
IRQ/ownership/ABA. Failure preserves raw and stops before native-after/further
sampling, with no cleanup/restore/free guess. Equality remains valid.

FINAL1789 ASAN/UBSAN SOFTWARE PASS109.20405841700267s=all1564+225 cases at75
actual subsequent clock positions. Eight fresh normal target fixtures compare
all309664 old/new producer bytes within each invocation; all equal. Actual
target/release/dispatch exports equal in MachO and COFF excluding typed
TimeDateStamp. Their unchanged474/771/2885 suites and unaffected checks/models/
CI were not repeated or claimed as new wholeconstructor qualification. Four
affected parent/producer and four comparison builds PASS both ARM64 formats,
generalregs/maxframe1024. Producer writes only exactPARrestore/noSMC; whole
parent old FP/terminalmask is not zero-write. OFF640972/640999 pairs equal.
Independent numeric struct/hashlib checks four full309664B records and builds
every refused byte in a new buffer; no captured pointer/PE execution or RAW edit.

Private0189/wifi/map-graph-clock-order-0001/proof.json
SHA74b6036b2234b16bae0412a6db71d2cc4f0869f7405258d5c35dbab5b78a575e;
source/softwareb601728c026e63de012b2859dd1ecd21e7cea5e242ebeff5c609367f87524c1a.
Fresh postrelease graph integration remains missing. Later relay IO contains
an expired pcmp_live stack pointer after its caller returns; completed records
must never supply future executable IO. Bind existing DATA readers to genuine
active callers/six NEW contexts, original opening and real source closures.
No physicalUSB/native/firmware/WiFi run, new candidate/codec/image/helper/freeze
or completion date. All old proofs/RAW/schema/SHA/timestamps keep their scope.

Producer clock-order functional source627b04a364e495104520c04d3eaeafcb239472af is now
published by the original directpush under actual standing source/text consent;
independent lsremote matches627b04a. Exact four own UTF8 source/text paths;
all firmware/private/sensitive bytes excluded. Private authorized source receipt
SHA6ec2db7ad6046a2450e52073a2670d20f69502da9e5b8adb217af2a8e76085c9. This subsequent handoff
changes only NOTES/REFERENCE_REPOS; no source/test/RAW/schema/proof edits or
repeated checks. Fresh graph/full candidate and physical WiFi remain NOTREADY.


### 0189 later Core/EFI/GCD/policy graph INPUT, source/SOFTWARE only

Own existing bounded DATA walk now runs inside the actual active later-map
caller across six parent routes and11 EXISTING Map boundaries. It uses that
caller's original IO/context/source/ticket/opening; captured relay IO is never
executed after its stack expires. Three cache Maps remain before FreePool.
Old producer phase4/cap65536 and232B DATA view remain; separate288B active
controls support genuine phase3/cap8192 caller input. No extra firmware Map,
allocator/provider method, fabricated context or ownership grant. No new
external reference audit or vendor/Apple/firmware publication was needed.

New versioned graph RAW V3 is310480B, binding408/live304 around unchanged
309664B producer. All356688B older PCMP bytes are covered by original freshly
rechecked prefix/call hashes plus3104 uncovered seal bytes; no hash phase or
guard removed. Native flag reads are recorded by shared walk; old pcmp native
read retains its position. Full raw, poisoned flags and partial API results
remain before UNKNOWN terminalhold; no guessed restore/free/retry/cleanup.
Log48MiB is RAW capacity, not candidate resource/profile qualification.

FINAL4463 ASAN/UBSAN SOFTWARE PASS1323.4109002909972s; affected producer1789
PASS109.46323541703168s, current2341 PASS84.66187058400828s, dispatch167
PASS4.136711708037183s. Six final actual parent/producer/graph ARM64 COFF/MachO
cross builds PASS generalregs/maxframe1024. Exports write only exactPARrestore,
noSMC; whole parent old FP/terminalmask is not zero-write. Eight full309664B
same-invocation normal seed comparisons equal with actual peer target reads;
target/release/dispatch MachO equal, COFF only typed TimeDateStamp differs.
OFF preprocessed640972/640999 pairs equal with changed headers excluded.
Unchanged474/771/2885/8487/1452/5141/models/CI not repeated. All original PE is
inert DATA; no original firmware/native/whole power constructor execution.

Independent struct/hashlib verifies8006016B normal archive and five667168B
max/refused bundles,16 records, full source/frame seals and every failed aux
byte in new expected buffers. Old RAW/proof/schema/timestamps remain untouched;
V1/V2 artifacts keep their own source/version scope, never reinterpreted asV3.
Private0189/wifi/later-map-graph-inputs-0001/proof.json
SHA70bfdcfbe412dafceb1e43ef45aa06e1a84151a431e09fcdf8933be7acc9a46e;
source/softwarec509ba35e9b8e609399bd4b2e3911f1ee6da9a776d9a179491bc382f5f034417.

This closes later graph INPUT snapshots, not precall/postprovider lifetime,
owner/ABA/futureIRQ or wholecall timing. Graph last CNTVCT is later than old
pcmp.final_arch; enclosing temporal handoff remains unfinished. Bind remaining
transitive Timer/GIC/provider/currenttimer/deferred source/effects/work and
lifetime qualification to six NEW contexts without renewing original opening.
Then actual MSA/RMTFS secure/cache/DMAstop/handback and full new candidate
qualification. Main REMOTE_MEMORY defaultOFF; no consumer/builder/CLI/profile/
resource connected, no device or physical WiFi success/credible date. Sound
and camera STOP. All host/build jobs ENDED; no new USB/native/MMIO/SMC/model/
CI/codec admission/image/payload/helper/freeze.

Later graph INPUT functional source7867f376ee2ac1ef1b08acae444b602c67a176a8 is now
published by the original directpush under actual standing source/text consent;
independent readonly lsremote matches7867f37. Exact nine reviewed own UTF8
source/text paths; all firmware/private/sensitive bytes excluded. Private
authorized source receipt
SHA50c064f33991fd2e9e6c71f7fd24815a864022a5589bbd088579fea2bb941ee5. This subsequent handoff
changes only NOTES/REFERENCE_REPOS, with no source/test/RAW/schema/proof changes
or repeated tests. Wholecall/owner/secureDMA/new candidate and physical WiFi
remain NOTREADY; no additional authorization or physical action is pending.


### 0189 later-graph to enclosing Map CNTVCT handoff, SOFTWARE only

Baseline7867 actually accepts constructed opening1100/header1400/graphlast8300/
outer8299 with outer FP restored. Current actual pgcd_map_read obtains the
already observed last CNTVCT from the exact six-route completed PCMP/graph
DATA into a local uint64 before its next existing arch sample. Full records,
original context/ticket/opening and pending boundary are checked; captured
caller/relay pointers stay numeric DATA. Invalid/zero/corrupt handoff refuses
before next arch; rollback/arch refusal stops before outer FP restore. Equal
is legal. Actual API status and partial/raw results remain. No new firmware
service/clock/AT/MRS/nativeflag call or RAW/ABI change; ordinary DATA/hash work
is added. Original window never renews or mixes physical/virtual epochs.

FINAL4553 ASAN/UBSAN SOFTWARE PASS1470.98928441701s=old4463+90;115 earlier was
only normal/max/new temporal subset. Six actual Map routes/11 existing calls,
77 outer sample cases and13 completed-DATA refusals. All original cases/guards
remain, including known ABA limitations; no originalFW/native/whole power or
client constructor execution. Six final actual parent/producer/graph COFF and
MachO builds PASS generalregs/maxframe1024. Export MSR only exactPARrestore,
noSMC; whole parent old FP/terminalmask is not zero-write. Default producer/
current/dispatch/allocator full preprocessed outputs are same-invocation byte
equal with the old header, so1789/2341/167/8487 and other unaffected suites/models/
CI not repeated. Unchanged release/dispatch native MachO equal, COFF only typed
TimeDateStamp differs. OFF preprocessed640972/640999 pairs equal; ON changes.

Independent struct/hashlib checks8006016B normal archive, four667168B old-shape
max/refused and five697392B baseline/new outer bundles. Every failed30224B
outer record byte and zero-handoff310480B aux byte reconstructed in NEW buffers;
original RAW/version/proof/objects untouched, pointers numeric. Refused8299
preserves API0/1/1 with outer error5/unknown/no FP restore; equal8300 succeeds.
Original1100..3841100 expiry remains. Private probe main macro error and early
MAX first-error test expectation are preserved; production guard unchanged.
Private0189/wifi/later-map-temporal-handoff-0001/proof.json
SHAe1e1fc4f7860a6cb0f553aa5792619dd82ffc97a154db57bda7eb10d079c94dc;
source/software1da9a54e2f639a72293e336e5a675a6736b0854b01b206a32d11c05b5b6e878f.

This closes same-counter stage ordering, not wholecall walltime/preemption/
fault/latency or remaining Timer/GIC/provider/deferred source/effects/work/
lifetimes, precall/owner/ABA/IRQ/lease or secureDMA retirement. These and actual
MSA/RMTFS claims/cache/secureVMID/MPU/DMAstop/handback/full new candidate remain.
Main defaultOFF; no builder/consumer/CLI/profile/resource admission, no device,
physical WiFi success or credible date. All host/build jobs ENDED; no physical
USB/native/MMIO/SMC/originalPE/model/CI/codec admission/image/payload/helper/freeze.
Sound and camera STOP. No new external reference/vendor/firmware audit needed.

Later-map temporal handoff functional source98ef301f7877f99ede6473210ef3f933523e0387
is published by the original directpush under actual continuing source/text
consent; subsequent independent readonly lsremote matches98ef301. Exact six
own UTF8 source/text paths, no private/firmware/device bytes. Private source
receipt SHAe6841a56db1d74ed84513ec407f36bc5f414f73130d3380b27b69e3b506d0093.
This subsequent handoff changes only NOTES/REFERENCE_REPOS, with no code/test/
RAW/schema/proof changes or repeated checks. Wholecall/owner/secureDMA/new
candidate and physical WiFi remain NOTREADY. No new human action is needed.


### 0189 fresh later Timer/GIC/CPU provider INPUT, source/SOFTWARE only

Actual six parent routes/11 EXISTING later Maps now reuse the original
incoming-provider DATA walk after each fresh Core/EFI/GCD/policy graph, while
the genuine caller remains active. Old pbhi source/context/page/range guards
and error stages remain. No fake opened context/ticket/owner, expired relay
execution or new original firmware service. Fresh graph classification plus
AT qualifies subsequent DATA reads only; it does not qualify prior GetMap,
release-backing lifetime, inventory/IRQ/owner/ABA or a future lease.

Separate provider RAW V1=20456B/binding400/live408/path12400; all old RAW schemas
unchanged. Full original image hashes/states/tables/selected GICv2/v3/all32..1020
handlers, actual caller/PCMP/graph and all control/output bytes close across
callbacks before pointer follow. Final immutable hashes follow the last foreign
callback. New normal20AT/23virtualarch, max22AT/25arch for1020 handlers/3pages;
10 Core+28 provider hashes. Generic arch contains readonly MRS; AT restores
exact PAR. Path.finalized0/regs/math/raise/final unobserved. Original window
never renews/mixes counter epochs. New last CNTVCT feeds existing outer guard;
partial/poisoned raw remains before terminalhold, no guessed restore/cleanup.
Log48MiB is RAW capacity only, not resource/profile qualification.

Full new1124 ASAN/UBSAN SOFTWARE PASS1644.5910789580084s and affected old graph
4553 PASS1492.8020886249724s; all original graph cases/guards retained. Earlier
14/264/34 runs only their saved source scope. All services/AT/FP/arch peers,
original PE inert DATA, no originalFW/native/whole power/client constructors.
Allocator optimized peer IR1780275B byte-equal; producer/cache only3/5 typed asm
source locations differ in NEW derived comparisons, metadata scope verified.
Their8487/1789/2885 and unaffected checks/models/CI not rerun. Native cache
exports actually differ (COFF82210/81388, MachO110656/109824), not called equal.
Six final actualparent/provider/cache exports COFF/MachO PASS generalregs/
maxframe1024; MSR only exactPARrestore/noSMC, whole parent not zero-write.
OFF preprocessed640972/640999 same-command pairs equal; ON changes.

Independent struct/hashlib verifies8432832B normal archive plus seven717848B
bundles,18 new provider records. Full normal/max/partial new records rebuilt
bytewise from original DATA/relocations/source hashes, states/tables/handlers/
AT/clocks/control/source seals/unused/padding/digest; original canonical5+5+4
provider ranges verified. Paired failed outer/PCMP/graph and zero handoff also
reconstructed in NEW buffers; no captured pointer execution or old RAW/proof/
object/timestamp edits. SOURCE failures preserve actual bad caller/graph raw;
SOFTWARE10600->10599 refuses before outerFP, equal10600 succeeds, original Map
API0/1/1 remains. Private declaration-order error and temporal peer scope error
retained; no production guard lowered.
Private0189/wifi/later-provider-inputs-0001/proof.json
SHA4ffa2118fdfe71c19df7f610a72e5f5bf4e24eed1c8d1b372a871f46ca0eb831;
source/software7e43c140426c265dc8ba8f05743195f0333d64845d7e2bdd8f95dbb0aca01599.

Next actual current physical timer/deferred/event/transitive callback source/
effects/work, postsource/release-backing lifetimes and wholecall time/owner/
IRQ/ABA/precall qualification remain. Then real MSA/RMTFS secure/cache/DMAstop/
handback/full normal+UNKNOWN retirement and complete new candidate admission.
Main defaultOFF, no builder/consumer/CLI/profile/resource or device admission,
physical WiFi success or credible date. All host/build jobs ENDED; no new USB/
native/MMIO/SMC/model/CI/codec admission/image/payload/helper/freeze. Sound/camera
STOP. Own existing DATA lifecycle reused; no new external/vendor/FW audit needed.

Fresh later-provider INPUT functional source63dcecc7ff377699ba56a4cf5541454024357a13
is published by the original directpush under actual continuing source/text
consent; subsequent independent readonly lsremote matches63dcecc. Exact nine
own UTF8 source/text paths; all private/firmware/device bytes excluded. Private
source receipt SHA75bf99189fcb8352ee995162c51ad210c55c8e1b4f058c436c80d90784566eb2.
This subsequent handoff changes only NOTES/REFERENCE_REPOS, no code/test/RAW/
schema/proof changes or repeated checks. Lifetimes/wholecall/owner/secureDMA/
new candidate/physical WiFi remain NOTREADY. No new human action is needed.

### Own0189 later-provider trailing RAW padding closure

Functional source572aa4ab925f36a1da79c6d6ad7705f534032960 is published by the
SAME original directpush under actual continuing source/text consentce8ce4fd;
push ENDED0 and subsequent independent readonly lsremote matches572aa4a.
Exact four own UTF8 paths are NOTES/REFERENCE_REPOS/current-provider header/
current-provider test, no private/firmware/Apple/vendor/NV/backup/RAW/photo/
serial/password bytes. Receipt authorized-source-push-0001.json
SHAcba3db6a08893fa63941d9e8e71429e88aa7b689e118adc56debfdd58e243968.
This later handoff is text only, no repeated checks or source/RAW changes.
Actual physicaltimer/lifetimes/wholecall/owner/secureDMA/WiFi remain NOTREADY.

The actual later-provider reader now retains all graph8 trailing padding bytes
at entry and across its existing leaves; its actual completed scalar handoff
also requires those8 and own-provider4 padding bytes to remain zero. The old
prefix digests/schemas keep their exact historical meanings. Original f3ac787
SOFTWARE accepted all8 graph byte faults with outer FP restored; the subsequent
graph-only intermediate source accepted all4 own-provider handoff byte faults.
No phone corruption or physical/owner/lifetime result is implied. No reference
scripts/prebuilts or original firmware code executed, no new hardware call.

Final1488 ASAN/UBSAN SOFTWARE PASS2155.333568541042s preserves1124 old cases
and adds364 actual composition faults. Four current wholeparent/provider export
COFF+MachO/generalregs/maxframe1024 builds PASS; source snapshots match current.
Independent struct/hashlib reconstructs33 provider records from8432832B normal
archive plus22x717848B baseline/current bundles in NEW expected buffers, preserving
dirty padding and every original RAW/proof/offset/timestamp. Native export MSR
only exactPARrestore/noSMC; wholeparent old FP/terminalmask not zero-write.
Current provider f6833e7626d093ef1e42c5d4a8960a06ce7ae3ffdbd19e6666d0cf5754ab4a60;
test 6be9f21a1c6686710204666273817b523968b22fd4adfd7b171e47d684b8f4bb.
Private later-provider-graph-padding-0001/proof.json
SHAdd23e1135baeeb60a913405d0521cf6711f78e99e25e99cd11763e1853a7cbfb;
source/software8ad4b9f20e356d99674e568a8ffc44c610b899ea1e4884dd48487f39b88d7d07.

These are DATA integrity checks. Actual physicaltimer/deferred/event/transitive
callback effects/work, postsource/release-backing lifetimes/active allocation,
wholecall walltime/IRQ/owner/ABA/precall and secure-DMA handback/new candidate
admission remain open. No repeated old audits/models/boot/USB; WiFi physically
never scanned/joined/networked, no credible date; audio/camera STOP.

### Own0189 current physical-timer/deferred INPUT in the active later caller

Functional sourcedafb101605da07e4e168fd90e53eb6d48a31f6a9 is published by the
SAME original directpush under actual continuing source/text consentce8ce4fd;
push ENDED0, subsequent independent readonly lsremote matchesdafb101. Exact
seven own UTF8 paths: NOTES/REFERENCE_REPOS/current-provider header/new timer
header/actual parent/current-provider fixture/new timer test. No firmware/
Apple/vendor/NV/backup/RAW/photo/serial/password/private bytes. Receipt
authorized-source-push-0001.json
SHA55283b617da4075aff46125dc5f2214c429df480311fab487cbb461cd33b8b86.
This later handoff is text only, no repeated checks/source changes. Physical
timer/source lifetime/IRQ-owner/secureDMA/new candidate/WiFi remain NOTREADY.

The actual six-route/11-existing-Map parent now reuses the original readonly
six-MRS leaf twice and bounded levels5..31 deferred-head reader inside the
genuine ACTIVE provider caller. Its new2136B RAW/binding496 records both
physical inputs, full/prefix27-head samples, four native flags, two post-leaf
Core counters and complete before/after448B active control. Old RAW schemas
and the timer-disabled408B control remain unchanged. New physical inputs do
not finalize the old allocator path or synthesize RaiseTPL/context/owner.

Control/provider-snapshot seals close before pointer follow. Known invalid
physical DATA refuses before new Core/provider/graph RAM follow; bad EL with
entire host Core/provider/graph source mappings PROT_NONE still refuses.
The actual old closing virtual samples preserve the first200ms window;
physicalfirst+3840000 only bounds DATA work consistency, never a new lease,
precall proof, IRQ/ABA/lifetime/wholecall walltime grant. No reference scripts,
prebuilts, firmware methods or original PE code executed; MRS are SOFTWARE
peers in the host checks. No new BS/GetMap/allocator/provider/IRQ-dispatch/
IAR/EOI/timerSet/mask/MMIO/SMC/sysreg write, extra AT or generic arch sample.

Final336 ASAN/UBSAN SOFTWARE PASS582.7755754169775s, four actualwholeparent/
timer-export COFF+MachO/generalregs/maxframe1024 builds PASS. Native timer
export is six readonly MRS/no MSR/SMC; wholeparent old FP/PAR/mask not zero-write.
OFF is same-command matchingtarget PREPROCESSED pairs640999/640972, not binaries.
The timer-disabled default provider host MachO objects155976B are original
byte-equal with old/new headers; IR only five typed source offsets and one
proven identical PHI predecessor/value permutation in NEW derived buffers.
Other old tests/models/CI not repeated or promoted to wholeconstructor results.

Independent struct/hashlib/arbitrary precision reuses the existing decoder
functions:8458464B normal archive plus16x719984B paired bundles,27 complete/
partial new records and linked source/failed bytes rebuilt in NEW buffers.
Captured stack/function pointers remain numeric inputs only. All original
RAW/proofs/schemas/offsets/objects/timestamps unchanged. Private
later-current-timer-deferred-inputs-0001/proof.json
SHA5b8a315a4f8a158ab5724c5fb17a141ca580e723bfcf17242ee4abf8625645cd;
source/softwarea0b23cc9a33db279ef5e89130e9975b5a520510084a457dfa4d7b8f891ae52ef.

Fresh event/checker/nonperiodic timer and transitive callback effects/work,
postsource/release-backing/active allocation lifetimes, wholecall/IRQ-owner/
ABA/precall, secure-DMA handback and new candidate admission still precede
device execution. Main REMOTE_MEMORY defaultOFF, no new allocator consumer/
builder/CLI/profile/resource. No USB/device/newCI/model/image/payload/helper/
freeze. WiFi never physically scanned/joined/networked, no credible date;
audio/camera STOP.

### Own0189 fresh later event/checker/nonperiodic-timer graph INPUT

The actual ACTIVE pcmp caller now reuses existing bounded event/timer DATA
walks after completed fresh provider/physical inputs, on the same six real
routes/11 EXISTING later Maps. No additional GetMap, NotifyFn, timer/provider
method, IRQ dispatch, fake opened context/ticket or expired relay execution.
Fresh later RAM classification plus fresh AT/NSWBsamePA/PAR restore precedes
each node copy. Full552B control/304B actual parent/full PCMP and complete
graph/provider/timer/new output seals close across callbacks before pointers
are followed. Before/after10Core+28provider hashes finish after the last foreign
callback. Existing pending/128event/32timer/all NotifySignal-timer refusals stay.

Separate V2 RAW91488B/binding488/live552 retains full events18544/timers8048,
AT322/clock324 capacity, actual C bool statuses/issued/returned/native/partial/
after-control/unused/digests. Unpublished draft V1=88896B remains historical;
old RAW schemas unchanged. Normal new stage7AT/9virtual samples; max fixture
163AT/165samples. Generic arch contains MRS, AT restores PAR; added RAM/hash/
read work is not zero-work or wholecall/IRQ/owner/lifetime qualification.
The original first200ms window is not renewed/rebased/reopened; completed
known resident route DATA provides a local latest minimum to existing outer
arch, with no captured LoadedImage descriptor or expired stack/relay follow.

Full capture1274 ASAN/UBSAN SOFTWARE PASS2494.268533415976s at full3 source.
Final narrow completion/old argument-guard ordering changes are qualified by
byteequal capture prefix and ORIGINAL capture-only export objects both targets,
plus final118 closing cases PASS352.5490578750032s; counts overlap. Current eight
source/test files equal closing snapshot. Four affected suites run SERIAL:
8487/336/1488/2885 PASS172.83276320795994/583.8131137079909/2151.833943250007/
3271.0076306660194s. Old graph/release original whole objects equal,4553/771
not rerun; other unmodified tests/models/CI not promoted to new qualification.
Four final wholeparent/events exports COFF+MachO/generalregs/maxframe1024 PASS;
export old six readonly MRS/no MSR/SMC, wholeparent old PAR/FP/mask not zero-write.
OFF PREPROCESSED matchingtarget pairs640999/640972 equal, not binary equality.

Independent Python rebuilds every new byte of35 records (two9556320B normal
archives plus13x811472B pairs) and linked inner DATA/selected failed outer/PCMP;
normal outer only restore boundary checked. Original PE is inert DATA, captured
pointers numeric, original RAW/proofs/objects/timestamps preserved. Services/
AT/FP/arch/physical MRS are peers; no original firmware/native/wholeconstructor
execution. SOFTWARE head-shaped ABA still PASSES; terminal longjmp not physical
retirement. Private later-current-event-graph-inputs-0001/proof.json
SHA1c37f846c6e5463c1213a663e69d41f065437cf3caa6ba8caf45578ff2cdd693;
source/software21c8af8640decded49b81721e527761c1eebaedfd1f55972813ee70925bfa6c4.

Transitive callback effects/work, postsource/release-backing and true active
allocation lifetimes, wholecall walltime/preemption/fault/latency/IRQowner/ABA/
precall, independent MSA/RMTFS/secure-DMA stop/handback and full new candidate
admission remain. REMOTE_MEMORY defaultOFF, allocator consumer/builder/CLI/
profile/resource unconnected; no PA publish/MSS/NVserve/radio/device. No new
reference review/script/prebuilt/model/CI/operational codec/image/helper/freeze.
WiFi never physically scanned/joined/networked, no credible date; audio/camera STOP.

This event-input functional source is publicly committed as `5684bd08ce18a6db0193413f8dae239c4240e6e1`,
same original direct push ENDED0 and subsequent independent lsremote matched.
Exact ten own UTF8 source/text paths only, standing consentce8ce4fd; all private
or firmware/Apple/vendor/NV/backup/RAW/photo/serial/password bytes excluded.
Private authorized-source-push-0001.json SHA97e7b55f685f2af654cbbfffe2aa4e51a62ba4d942731a8251a14b6cf78d6d4e.
This subsequent handoff edits only NOTES/REFERENCE_REPOS; no repeated checks,
new device grant or completed WiFi claim. No pending physical/auth question.

### Own0189 earlier active Map relay control closure

The actual existing pcmp relay now hashes all304 active control bytes across
three arch returns, FP save/restore, Map, order and header AT, comparing before
following returned control pointers. Original e4fd SOFTWARE accepted equal-DATA
caller_input pointer substitution at all8 boundaries and restored outer FP.
New pcmp error8/UNKNOWN refuses; void order uses existing sticky records and
the parent call checks them before source/native reads or further callbacks.
No new wrapper/service/reader/context/ticket/permission/owner flag or RAW ABI.
Private SOFTWARE copies controls while ACTIVE; retired pointers remain numeric.

New2879 ASAN/UBSAN PASS110.35326879099011s, actual six generic contexts/11 Maps,
all304 bytes/8 boundaries and every actual route/slot, aliases/bad pointers/
PROT_NONE. Direct2341/167/1452 PASS83.5345797080081/4.152791750035249/
1.178030916955322s. Seven affected full suites SERIAL:1789/771/336/4553/1488/
1275/2885 PASS107.93301258300198/218.91298979200656/586.3587330839946/
1489.2254830840393/2154.6439244170324/2478.577342582983/3276.919940916996s.
Original cases/guards retained. Earlier normal/max subsets are not wholemodels.
8487/5141 original whole host objects equal baseline, not rerun;474/models/CI
not rerun. Initial graph-export comparison exposed emitted address-taken changed
relay functions, so no object-equality claim; full affected suites followed.

Four actualwholeparent/relay COFF+MachO/generalregs/maxframe1024 builds PASS.
Relay export has no MRS/MSR/SMC/AT, IO remains callbacks; wholeparent old PAR/
FP/mask not zero-write. OFF PREPROCESSED pairs640999/640972 equal, not binaries.
Independent DATA verifier checks43records/32 reconstructed304B control copies,
binding/full-complete digests and partial native/FP/phase fields. Not every
failed PCMP/outer byte reconstructed; outer restore/UNKNOWN boundaries only.
Original RAW/proofs/objects/timestamps remain intact, pointers numeric, PE DATA.
Private later-map-relay-control-0001/proof.json
SHA88ac513008f7362f1911be3d91380643a0a814e40bad0366b33a2adf7a97e913;
source/software6b6bcad49ee5d46bb064843bf93ce51e24e1bdfdda40ba50a40ec7d252780a90.

Extra4864B control hashing per Map is real work, with no additional hardware
calls/reads or renewed200ms window. Inner FP may already have restored before
the refusal; outer FP is retained UNKNOWN. Old guarded-return flags are not
relabeled original service-return evidence. Equal-after control still passes,
so source lifetime/ABA/IRQ/wholecall/precall/secure-DMA qualification remains.
No reference review/script/prebuilt/USB/native/originalPE/newmodel/CI/codec/image/
payload/helper/freeze. REMOTE_MEMORY defaultOFF and consumer/profile unconnected.
No PA publish/MSS/NVserve/radio or physical WiFi success; audio/camera STOP.

The relay-control functional source `a9c3d42b7b22250fec9435b8bfe1ef94d80462e7` is published:
same original direct push ENDED0, subsequent independent lsremote matched.
Exact five own UTF8 source/text paths only under standing consentce8ce4fd,
sensitive/private bytes excluded. Private authorized-source-push-0001.json
SHA77901b21710bb407df13b4ca08a4bca9291af078835523ec85570bd3958fe5d3. This later handoff edits only
NOTES/REFERENCE_REPOS; no repeated checks or new hardware/owner permission.
