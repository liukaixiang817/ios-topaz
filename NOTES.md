# Active target: MIX 2S / polaris (2026-10-23)

**Read this before the historical sweet/topaz notes below.** The current user
has a rooted MIX 2S (SDM845), Android 13 + Mindows Windows 11, and requests a
third iOS 16 system with about 64 GiB while preserving all existing data.
Earlier permissions to erase sweet/topaz userdata belong to different phones
and DO NOT authorize erasing this phone. On 2026-10-24 the user explicitly
approved ONLY the proposed minimal userdata metadata repair, then continuing
iOS adaptation. No erase/format/resize/GPT or Windows write is approved.

## Current handoff, 2026-10-24 (Australia/Melbourne)

### CURRENT NEXT ACTION —0017 no lockscreen; IRQ direction and early startup

- NEW0017 photos B8114285... (two) and2226B4B6... (later) saved privately as
  touch-0017/hardware-no-lockscreen-{1..3}.jpg +hardware-no-lockscreen.json.
  User confirms no lockscreen. Samples18..27: SpringBoard/lsd/MCM all found0,
  FB calls/swaps/present/pixels0; COW45/32768,dirty584KiB/written748KiB stable,
  UFS-error0/refused0. This boot has not reached the observed0016 GUI stage.
  Earliest startup cause unknown; no evidence touch failure causes this stall.
- D TOUCHphase9/result15/done1/frames0/down0;fw300/status0/irq0;TIFfifo1/
  tx0/rx0/path2/lines0/bus0. D TWstep1/error2/changed0/rollback0/lines0.
  D TG en3c3/3,reset201/0,was201/0;TRMIreg357d000/n8/data201/0. Exact source
  identifies GPIO125 IRQ direction guard: GPIO output low, not input. Wake
  made NO GPIO writes; GPIO23 already output high, reset99 still asserted.
  lines0/bus0 are unmeasured defaults. Failed touch worker has ended.
- LiveDT ts_active8d explicitly GPIO99/125,GPIO mux,16mA,pull-up; MiCode
  Synapticscore set_gpio configures IRQ as input before power/reset. Verified
  pinctrl-v2 GPIO125 EAST. Plan0018 separately opted-in IRQ125 input release,
  only from observed GPIO/output-low state while reset held, with rollback;
  preserve old opt-in behavior. Also add bounded PID1/early startup diagnostics
  when focused GUI targets are absent. Do not infer the GUI stall's cause.
- Keep current0017 running; swipe question ANSWERED no lockscreen. No new
  physical reboot request. Newsource/native+actual-header builds/fullCI and
  newkernelQEMU/preparedimage required before asking FASTBOOT. Exact0017
  source snapshots saved touch-0018/originals/ before changes. Full local
  HackiOS references remain indexed in REFERENCE_REPOS.md.
- IMPLEMENTED0018: separate ADT irq-input125 (requires wake opt-in). Only
  observed GPIO125cfg201/io0 while reset99 held low may become GPIO/input/
  pull-up16mA per liveDT; no IRQ latch write, reject foreign mux/high latch/
  running controller. Readback, retained D TI before/after, and rollback after
  restoring reset preserve inherited state on failure. Absent new marker
  preserves0017 behavior. Native actual-sequence electrical/timing model+
  exact shipped header2tests,10ADT+3profiletests ALL PASS (15total);5 actual
  CI-header ARM64 objects PASS;0814/0815 all6files apply+MATCH.
- Added0018 early startup diagnostics: when focused GUI target absent, bounded
  process rows and PID1 (regardless executable name), max3threads/12resident
  frames, saved wait_event/continuation. D BOOT retains bsdinit/initialexec
  stage/error and iOS exec-policy check count. No faulting user pages or waits
  for exec transitions. Normal focused samples unchanged. Need real-kernel
  QEMU fallback case plus existing modes; native tests are not phone proof.
- 0018 source173eda1e48dfe66e2eb2e446b39bc09e7f3130c3 committed+pushed;
  CI40065872971/job120788889616 building. Private touch-0018/ source-audit,
  native-adt-profile.log/object-compile.json/patch-check.json retain proofs.
  Synthetic missing-GUI fixture caller-bootstrap.raw prepared, SHA
  94e5a98094e58733183d1bc28480669be3955d414b33b544e56e32732d00343c;
  rename only synthetic SpringBoard child/init path, six children still wait.
  New phone ADT candidate adds only irq-input125; removal restores0017 exactly.
  No0018 kernel downloaded/QEMU run/prepared phone image/phone boot yet.

### 0017 actual temporary boot history

- User answered "已到 FASTBOOT". Fresh0017 readonly preflight exec14876
  exit0 PASS, battery32C. Full16GiB base SHA689a8cd1... MATCH in77.449s; fresh182maps
  before/after and boot's additional map all match. Outer4KiBheader remains
  7c19bb29..., GPThead unchanged, userdata unmounted/RO1. Android pending
  journal left unchanged; no replay/repair/staging/partition write.
- 0017 temporary boot SENT exec37061exit0, FASTBOOT1.173s,
  **2026-10-24T05:06:26.929975+00:00 =16:06:26 Australia/Melbourne**.
  Exact prepared image/kernel/payload hashes below matched; C copy-plan,
  all3QEMU provenances, explicit wake ADT delta and same cmdline verified.
  Same live recovery boot ID/fresh proof<600s and remaining admissions all
  passed before adb bootloader + fastboot boot. Transport success only;
  actual0017 lockscreen/touch/home not observed yet. Physical FASTBOOT request
  answered; bottom-edge swipe result question now pending. No further reboot
  request. Private touch-0017/boot.json/boot-phone-sanitized.log/boot.log/
  preflight.json/full-image-readonly-verification.json/deployment-state.json
  saved. No USB restart/log/control path in current XNU.
- NEXT: wait for user0017 lockscreen/swipe report. If no response, request
  clear NEW0017 photo of D TOUCH/TW/TG/TIF/TRMI through ordinary chat (not
  upload request in async tool). Decode using hardware-decoder.json; retained
  wake failure snapshots may precede rollback. Actual contact/HID down-up and
  matching UI response required for physical input proof. Do not reuse0016
  phase4/result12/reset-low values as new0017 observations.

### 0017 preparation and validation history

- 0017 prepared before the temporary phone boot recorded above. All three actual-kernel QEMU modes
  gate200s/default200s/nodiag90s now PASS, 67checks; validation-retry exec93080
  exit0. Gate passed first attempt; default required ONE identical retry after
  timer IRQ panic below; nodiag passed first attempt. Exact default kernel,
  cmdline/ADT/fixture/payload provenance matches the failed attempt. Full
  failure remains in verification.json and qemu-default-identical-retry.json;
  do not describe this as all-first-attempt success. Synthetic fixtures only,
  no hardware power/reset/I2C/touch/home proof.
- Actual C payload copy-plan validator PASS. New ADT adds ONLY wake-version1
  and wake-gpios23,99 relative0016; removing them restores0016 byte-for-byte,
  removing the touch node restores0014. Factory identity, file manifest and
  cmdline unchanged; ufsrw0/RAM512/cpus1/copy5Hz/visibleconsole retained.
  Image shim/out/polaris-xnu-touch-0017/polaris-xnu-touch-0017.img,
  47304704bytes, SHA
  d0f67e1c3198edd53c8dfbef70b605e478daba5069aff44a94f213de44c59c2b;
  payload642656c5e2d02b6e2edf0f64d3c7c485c29e1f0f83bd045eb7ffb149b3ab9470.
  Private touch-0017/prepared.json/verification.json/qemu-check.json/
  deployment-state.json retain the full admissions. Source-derived new
  D TW/TG/phase9/result15 guide: touch-0017/hardware-decoder.json.
- Physical Power+VolumeDown FASTBOOT request answered; readonly preflight and
  temporary boot completed above using touch-0017/run-device-step.py.
  Require fresh full16GiB hash,182maps/knownheader/GPT/same recovery boot and
  readonly unmounted userdata, as before. No journal replay/repair/staging.
  No new phone USB log/restart path. Need actual0017 lockscreen/swipe and retained
  D TW/TG/TIF/TRMI observations before claiming physical input/home success.
- User-requested full local reference clones and index completed; commit
  3677a59 pushed. Failure handoff eb26321 also pushed. Future agents read
  REFERENCE_REPOS.md and consult the ignored local kernel/userland clones.

- 0017 source **3a5f1363e0e81671bc59385285c4d29ed018afad** committed and
  pushed. CI **40063497975**, job **120781795518**, SUCCESS, build4m21s.
  Full gh log: research/polaris/ci-40063497975.log. Local native,
  ADT/profile and four actual-header ARM64 object checks passed as below.
  Exact-kernel download/profile/ZIP CRC/SHA verified: artifact12547524758,
  60387285bytes; kernel SHA
  cd92119429903240ea29b45515d7b84a9d66c3e2f4653e6875e73b68213fa8dd.
  Sequential QEMU gate200/default200/nodiag90 and the prepared phone image
  are now verified as recorded above. Physical FASTBOOT request was answered;
  current phone was 0016 when that request was sent and0017 has now been sent.
- New-kernel QEMU gate200s PASS (29checks). Default200s FIRST ATTEMPT FAILED:
  rtclock_intr took25.383008ms, threshold13.631488ms, after PID1 alive, before
  synthetic target sampling. Physical touch disabled/no board marker; no
  hardware wake code armed. Timer handler resolved from this exact kernel.
  Cause unestablished; emulator/host scheduling is a possibility, not a fact.
  Full ring/screen/QEMU log/provenance retained under touch-0017/
  qemu-0017-default-attempt1 plus qemu-default-attempt1-failure.json and
  validation-attempt1.log. One identical default retry subsequently PASSED;
  earlier passed gate retained. No timeout/panic checks weakened. This failure
  and retry preceded the physical0017 boot recorded above.
- User supplied HackiOS references. Read and pinned kernel
  **d82c64a3a31cd27a0a0afbf6e213e467e44b1b4c** and userland
  **a79ff0772a3454fd1ef127e181e5b3bce6c9ce18**. Private source copies and blob
  manifest: research/polaris/reference-hackios-20261024/. No upstream scripts,
  binaries or phone operations executed. Sources:
  https://github.com/oosexgang/hackios-xnu-kernel/blob/d82c64a3a31cd27a0a0afbf6e213e467e44b1b4c/docs/PORTING.md
  and userland/src/inject.c in the userland repository.
- Both repositories now fully cloned locally with history (not shallow):
  research/reference-repos/hackios-xnu-kernel (50MiB) and
  research/reference-repos/hackios-xnu-userland (10MiB). HEADs match the pins
  above; clean checkouts and git connectivity checks PASS. These ignored
  checkouts remain outside our Git history. REFERENCE_REPOS.md indexes them
  for future work; AGENTS.md points future agents to that index.
- Reference findings: redwood SD778G uses Goodix GT9916/FocalTech FT3680 SPI,
  PM8350C ldoc2 RPMh and reset GPIO105. Those addresses, regulators, firmware
  and timings do not describe polaris SD845/S3330 I2C. Its vendor-order power
  setup supports checking power/reset before report parsing, but 0017 timings
  and pins come from polaris live DT/MiCode, not this foreign driver.
- Reference input path: kernel /dev/redwood-touch queue -> injected backboardd
  virtual HID service -> hand/finger events with DisplayIntegrated/Built-In
  and sticky FromEdgeTip. make_service() retries until the server opens the
  service, addressing a documented startup race. Useful future comparison if
  polaris produces physical frames but UI ignores them; current 0016 stops
  before I2C, so no evidence yet that its HID path is the blocker. Our path
  remains the existing kernel IOHID service; no injector/root image change.
- Reference inject_sb.c also defaults to forced unlock after ten seconds;
  reaching home under that mode is not proof of physical swipe/input. The
  resident EFI loader's USB server uses Qualcomm UEFI protocols and optionally
  another CPU; this is an architectural port, not an available restart command
  for the current bare shim/XNU boot. Retain physical-key workflow for 0017.

- NEWfour0016photos6BD07919... savedprivatelytouch-0016/hardware-reset-low-
{1..4}.jpg +hardware-reset-low.json. D TOUCH phase4/result12/done1/frames0/
 down0;fw300/status0/irq0;D TIFfifo1/tx0/rx0/path2/lines0/bus0;lastreg3963000,
 n8/data201/0. ActualFIFOinterfaceDISABLED,emptyqueues,GPIOfallbackselected.
 GPIO99NORTHcfg201=GPIO/output/2mA/pulldown,IO0=resetassertedLOW. Stopped
 BEFOREGPIOlinechecks/I2C;lines0/bus0arenotmeasuredlowbus/ACKsuccess.
 NoRMIframes/physicalinput/home. Photo4PosterBoard237SIGTRAP,userprocess
 crash,notkernelpanicornamedtouchcause. COW24427/32768,dirty390636KiB,
 UFS-error0/refused0,not exhausted. Keep0016boot;no newFASTBOOTrequestyet.
- ExactliveDTtouchvdd-supply88 ->tp_vddio_vreg fixedactivehighGPIO23,
 startup4ms/booton. GPIO23SOUTH@3d17000 verifiedpinctrl-v2;GPIO99NORTH@3963000
 resetactive-low,active5ms/delay200ms. avddPM8998L28=3.1V,dispL14=1.8V,
 LAB/IBBsharedpanel:doNOTreuseforeignRPMhdriver/changePMICwithoutfacts.
 MiCodepolaris-o-oss Synapticscore enablesbus/power thenreset;sourceprivate
 display-0009/synaptics_dsx_core.c lines4095-4145/4263-4304;blob99cd6034....
- IMPLEMENTED0017explicitADTtouchwakeoptin;exactGPIOownership guards,
 fixedGPIO23enableonlywhileownresetalreadyasserted,>=5mssettle/low then
 GPIO99deassertonly(no pulseonrunningcontroller),200mssettle/readbacks;
 requirephysicalSDA/SCLhighbeforedeassert,rollbackfailedwakeonlychangesowned
 bynewhelper. NoPMIC/voltage/FW/diskwrite. Newrawenable/resetstates retained.
 Nativeactualsharedsequence+exactheader2testsPASS withASan/UBSan;9ADT+3profiletestsPASS,patchbothfilesapplyMATCH,actualCI-header4ARM64objectsPASS. CI/newkernelQEMU+preparedimage still requiredbeforephysicalkeyrequest. 0017sourceimplementedas0814patch;new --touch-wake optionalADT version1/gpios23,99;defaultrequiresnoextraMMIO/writes. NewretainedD TW/TG showstep/error/changes/rollback/power+resetbefore/attempt.

### 0016 build, boot and prior report history

- 0016preparedandSENT asbelow;source d75b8a315894e84320eb0b7e0529bac213adbae0,
0813-polaris-gpio-i2c-fallback.patch committed+pushed. CI40061321613 SUCCESS,
 job120775252245,build4m58s;artifact12548065591/60375087bytes. Exactpolaris
 profile/source+ZIPCRC+kernelSHA VERIFIED;fullghlog ci-40061321613.log.
 Kernel xnu/out-polaris-0016/kernel.development.sweet,
 SHAe902583256841aed95d1d91af3d9ef6866ece894d56dc99a46b70376e937d13f.
- Nativewiremodel+ASan/UBSan test andexactshippedheader testPASS;3profiletests
 PASS;actualCI-headerARM64objects4PASS;patchbothfilesapplyMATCH. Covers
 repeatedSTART/read80/finalNACK/clockstretch/address+dataNACK/busybus/timeout/
 arbitration/bounds/admission. SharedGPIOheader isactualshippedcode,notmock.
 ActualnewkernelQEMUgate200s/default200s/nodiag90s ALLFIRSTATTEMPTPASS,
67checks,exec37105exit0. PID1/display/callerrotation/completeRAMring/screen
 no panic,0unknown glyphs;default/missingmarker/outerdiag gates. Synthetic
 fixture+nohardwaretouchADT;noactualGPIO/controllerdata/physicaltouchproof.
- ActualCpayloadcopyplanvalidatorPASS. PhoneADTBYTE-IDENTICAL0015,cmdline
 unchanged;onlykernelchanges. Sameverifiedfactoryidentity andimmutablefile
 manifest;ufsrw0/RAM512/cpus1/visibleconsole/copy5Hz retained. Image
 shim/out/polaris-xnu-touch-0016/polaris-xnu-touch-0016.img,47304704bytes,
 SHAd107ef9724b9f0ba70c44ba4cbc501dc2b74946bebef484af10e0c95310ac000;
 payloadb259b20fc77e397e069ebf46efd56a4e58850e5c84ec115a1a454b81da031b59.
 Allprivate touch-0016/prepared.json/verification.json/qemu-check.json/
 deployment-state.json/native-gpio.log/profile-tests.log/object-compile.json.
- CURRENTPHONE0016temporarybootSENT exec96008exit0,FASTBOOT1.177s,
2026-10-24T04:28:54.087967+00:00 (=15:28:54 Australia/Melbourne). Exact
 image/kernel/payload hashesabove rechecked plusCcopyplan/all3QEMUprovenances,
 identical0015ADT/samecmdline. Freshreadonlypreflightexec85430PASS,33C:
 full16GiBSHA689a8cd1... MATCH in77.820s;182mapsbefore/after andboot
 freshmapagain;outer4KiBheaderunchanged7c19bb29...,GPTheadmatches,unmounted
 RO1. PendingAndroidjournalleftunchanged. Noreplay/repair/staging/partition
 write. SameliverecoverybootID/proof<600s andalladmissionspassedbeforeadb
 bootloader+temporaryfastbootboot. Privateboot.json/boot-phone-sanitized.log/
 boot.log/preflight.json/full-image-readonly-verification.json/
 deployment-state.json saved. Source+handoffs d75b8a3/f8cc613/93f7519 pushed.
- NEW0016USERREPORT: "锁屏出现，但触摸无反应". Savedprivate touch-0016/
 hardware-user-report-no-response.json +deployment-state.json. Lockscreen
 reportedbyuser;noNEWphoto/statevaluesyet. Home/physicalinput/App NOTproven.
 PriorbottomswipequestionANSWERED;noFASTBOOTrequestpending. Keep0016running.
 NeedNEW0016photo D TOUCH/TREG/TIF/TRMI,especiallyD TIF path/lines/bus plus
 phase/result. DoNOTreuse0015phase3/result11as0016stateorassumeGPIOfallback
 wasselected. HardwareGPIOownership/power/pullups/ACK/data stillunknown.
 hardware-decoder.json explainscodes. NoUSBcontrol/restart/logport. No new
 source/CI/reboot solelyfromnonspecificnoresponse;waitdiagnostic evidence.
 Latestprevioushandoff963dd5c pushed;thisreport recordedbeforestop.
- EVIDENCE:four0015photos F16F697B.../7F7501AC... savedprivatelytouch-0015/
 hardware-clock-stop-{1..4}.jpg +hardware-clock-stop.json. Actualred4:10lock
 screen/camera amidconsoleoverdraw. D TOUCH phase3/result11/done1/frames0/
 down0;fw300/status0/irq0;lastreg0/n0/data0/0. Clocks+SEmap passed,protocol3
 I2C,idle,stoppedBEFORE GCCcfgsnapshot/RMI. RemainingguardcausesFIFOdisabled
 OR nonemptyTX/RX,not distinguishablein0015. Noactualtouch/HIDevents/home.
 Logsaftertouchwerenotphysicalinputproof. No needadditionalold0015samples.
- IMPLEMENTATION:exactboard/flag gates unchanged. 0016requiresprotocol3+
 M/Sidle,onlydisabled/nonemptyFIFO choosesGPIOfallback,neverdrainsinherited
 FIFO/reconfiguresGSI/loadsFW. Validateinheritedreset99high/IRQ125input,
 GPIO33/34muxGPIO0/qup14only,physicalSDA/SCLreleasedhigh before+after input
 remux. Zerooutputlatch,OEonlysinks/releases,NEVERhighdrive. Fixedslave20,
 TX<=2/RX<=80,repeatedSTART/ACK/NACK/clockstretch/arbitration,shared24msdelay
 budget/finitebitloops;releaseonerror,nobusclearclocktrain. SameRMIfunction
 discovery andnormalF01byte. NoPMIC/hardwarereset/firmware/diskwrites.
 RetainsD TIF:rawIF/TX/RX/path/lines/lastbusresult evenifworkerstops. Physical
 power/pullups/GPIOownership/ACK/data remainunknown untilactualtest. MiCode
 pinctrl-v2exactfactsverified;primaryi2c-algo-bit reference private,blob
 a8e89df665b904d77b86586853a3fb5f010f92e0. Handoffcommitf8cc613 also local.

### 0015 build, boot and user-report history

- 0015 temporaryimagebuilt andSENT asbelow. Source35fe4d492b6a7a50e5c7115beaa7dfee514af9c4,
 CI40058661910/job120767328465 SUCCESS (build4m41s). Artifact12546850582/
60363320bytes,exactprofile/source+ZIPCRC+kernelSHA verified. Kernel
 xnu/out-polaris-0015/kernel.development.sweet,
 SHA8e3c3e3d9c0198fd43004f555b46975cfdfc7c86b94a6eb40b0d9cced862fb88.
 Fullgh log research/polaris/ci-40058661910.log. Initial0811-only40058349228
 CANCELLED bysupersedingpush,not acompilefailure;neverdeploy it.
- Newkernel sequentialQEMU gate200s29checks/default200s29checks PASS.
 nodiag90s FIRSTattemptFAILED rtclock_intr16.6ms >13.631488ms IRQhygiene
 threshold afterPID1alive. Touchhardwarewasdisabled/exactADTmarkerabsent.
 CauseNOTestablished;emulator/hostscheduling suspected,not proven. Failed
 ring/screen/fullqemulog retainedtouch-0015/qemu-0015-nodiag-attempt1 plus
 qemu-nodiag-attempt1-failure.json. OneUNCHANGEDkernel/args/ADT/fixture90s
 retryPASS. No panicchecks weakened. Gate/defaultresults reusedsamekernel
 andchecksreapplied;no gratuitousrerun. All3modes/67checks nowPASS exec37099
(exit0),validation-retry.log;initialexec70365exit1 retained. Synthetictests
 provePID1/display/callerrotationanddefault/missingADT/outerdiagnosticgates;
 noactualI2C/powerretention/physicaltouch/GUIproof. VerificationJSON retains
 firstfailure explicitly. LocalactualCI-header4ARM64objects+native4ASan/
 UBSan+8ADT+3profiletestsPASS;0811all7/0812bothpatchfilesapplyMATCH.
- ActualCpayloadcopyplanvalidatorPASS;phoneADTminusnewpolaris-touchnode
 byte-identical0014ADT/sameverifiedfactoryidentity. CmdlineONLYadds touch1
 andCPUdisplaycopy1->5Hz;visibleconsole,ufsrw0/RAM512/diagnostics unchanged.
 Image shim/out/polaris-xnu-touch-0015/polaris-xnu-touch-0015.img,
47304704bytes,SHAf1586d93492868a59c48dcc06a9be830e00407074cc6af07415b6431f3939e1e;
 payload7edf67f4e87cb7a409b5929031690eac34cb591858d5e5e56d1aae98534fb415.
 Privateprepared.json/verification.json/qemu-check.json saved.
- CURRENTPHONE0015 temporarybootSENT exec79316exit0,FASTBOOT1.174s,
2026-10-24T03:54:48.439539+00:00 (=14:54:48 Australia/Melbourne).
 Exactimage/payload/kernel hashesabove matched;Ccopyplan/all3QEMUprovenances
 andADT/cmdline rechecked. Freshreadonlypreflight exec42180PASS,32C:
 full16GiBbaseSHA689a8cd1... MATCH in77.495s;182mapsbefore/after andbootfreshmap
 unchanged,outer4KiBheaderunchanged7c19bb29...,GPTheadmatches,unmountedRO1.
 PendingAndroidjournalleftunchanged;no replay/repair/staging/partitionwrite.
 Bootscript verifiedsameliverecoverybootID/freshproof<600s andalladmissions,
 thenadbbootloader+temporaryfastbootboot. Wrapperredactedserial fromoutput.
 Privateboot.json/boot-phone-sanitized.log/boot.log/preflight.json/
 full-image-readonly-verification.json/deployment-state.json retained.
- NEW0015USERREPORT: "触摸后冒了一堆log，但是依旧无反应". Savedprivate
 touch-0015/hardware-user-report-no-response.json +deployment-state.json.
 Thisisreportedtemporalassociation,NOTyetproofcontroller/HIDeventswork;
 exactloglines andnew0015screenunavailable. Successfulhome/App NOTproven.
 No furtherphysicalrebootrequest. Keepcurrent0015running andrequestclear
 NEWlogphoto (ordinarychat,NOTuploadrequestinasynctool). PreferPOLARIS TOUCH:
 contacts=/SWEET HID: touch down/up andD TOUCH/TREG/TRMI savedstatus.
 ActualsourcecontactslinefiresonlyafterrealRMIframe andHIDcall;SWEETHID
 down/up loggedbefore dispatchEvent,notproofbackboarddconsumed. Periodic
 D TOUCH linesalonearenotcontactproof;phase7aloneisnotphysicalinputproof.
 DefaultconsoleoverdrawcanobscureUIindependently;needphotobeforefix/newbuild.
 Legacydifferentphone notes show1CPUtouchlatency~1min;possiblehypothesisonly,
 NOTcurrentdiagnosis andNOTpermissiontoenableuntestedSDM845SMP.
 NoUSBcontrol/restartport. No newsourcechange/CI initiatedwithoutlog evidence.
 Source/handoff35fe4d4,a7d9e15,b98272a,e807d06 pushed;latestreporthandoff below.

-0811source24d2bfbd6e10233b578bcaf3608f9e6b2eb24e93 pushed;initialCI
40058349228/job120766219551 building. Beforehardwaretest added0812 retained
 touchstatus:3boundedlines inperiodicRAMdiagnostics evenafterinitialthread
 stops. Atomic32bit savedphase/result/firmware/status/IRQ/lastreg+8data bytes/
 frames/contactmask;reporter neveraccessesbus orwaits onlocks. Phase1delay,
2HID,3clock/fwownership,4pins/FIFO,5RMI,6configured,7polling,8probecomplete;
 done1meansworkerended,notnecessarilyfailure. Errors10HID/11clock/12engine/
13configured/14mapping;RMI1IO/2format/3unsupported/4reset. Details private
 retained-status-patch-check.json. Both0812filesapply+MATCH;4actualCI-header
 ARM64compilesPASS includingtouch andstorage reporter. Fullnative/testedheader
 contracts unchanged. NeednewcompletekernelCIfor0812,thenQEMUandpreparedimage;
 original0811CI isbaselineonly andmaycancelonnewpush. No phone0015bootyet.

-0811 INPUT implementation staged locally: newbsd/dev/polaris_touch.c,
 shared testedGENI/RMI/mapheaders;BSDlateinit caller;Polaris-only HIDinverse
 mapping/2160pxbottomedge. Explicitpolaristouch1input/2probe AND exactADTnode;
 defaultnoMMIO. GPIO33/34mux2onlyfromGPIO/expectedmux,reset99/IRQ125 untouched,
 inheritedhighreset required. OnlyGCCAHB1/S6votes20/21/28,XO/1selection;
 loadedI2Cfw/idle32bitFIFO required. NoPll/PMIC/reset/firmware/diskwrites.
 BoundedRMI10pagePDT/F01/F12 discovery,currentCtrl28stride,Data15presence,
 finger/gloveonly,20mspoll,threebadreadsrelease/stop;normalvolatileF01byte.
 NativeASan/UBSan4tests PASS includingexactshippedheaders,protocolcapabilities,
 down/move/up/invalidbounds,FIFOshortword/NACK/timeout/foreignbusy/abortfail,
 monotoneinversefit/homeedge;8ADT+3profiletestsPASS. All7patchfilesapply+MATCH.
 ThreeactualCI-headerARM64objectcompilesPASS (newdriver,BSDinit,SweetHID).
 touch-0015/source-audit.json +test/compilelogs retained. FullCI NOTbuilt yet.
 tools/polaris-ios-touch.cmdline adds polaristouch1 andraisesCPUcopy1->5Hz
 forinteraction;consolevisible,ufsrw0/RAM512/rootimage protectionsunchanged.
 NeedfullCI/newkernelQEMUthenpreparedhardwareimagebeforephysicalkeyrequest.
 ActualICpower/firmwareretention unknown;driver maystop safely withdiagnosis,
 notyetphysicaltouch/homeproof. Current0014running,doNOTrequestrebootyet.

- NEW0014 HARDWARE:threephotos 13A41938... savedprivately as wifi-identity-0014/
 hardware-lockscreen-no-input-{1,2,3}.jpg +hardware-lockscreen-no-input.json.
 Red/pink4:15clock,camera,homeindicator,charging icon visible withconsoleoverlay.
 Userreports touches doNOTwork/cannotenterhome. Actual0014GUIlockscreen now
 confirmed;home/input/Appunfinished. No timingbenefit inferredfromMACchange.
 COWmax26819/32768,dirty427876KiB,reserved512MiB,UFS-error0/refused0,notfull.
- Sourcecause confirmed:POLARIS_RAM_ONLY returns polaris_file_root_init before
 common sweet_keys_init/sweet_touch_init;SweetHIDTouch onlypublishes event
 service. DoNOTenableforeignGoodix/Focaltech GPIO8/9/90driver. LiveDT bound
 Synaptics@0x20,S3330,/soc/i2c@a98000,wrapper1/S6,GPIO33/34qup14 mux2,
 reset99 NORTH,IRQ125 EAST. Exact MiCode polaris-o-oss pinctrl-v2/geniI2C/
 Synaptics sources fetched throughGitHubconnector;private touch-0015/.
 GCC S6RCG18738/branch18734,AHB1800c/18010,votebits20/21/28 verified.
 SharedHID currently assumes1080x2400/centercrop;needs inverse997x2160fit
 and2160height/edgegesture forpolaris. PlanexplicitADT+bootarg gated driver,
 boundedRMI functiondiscovery/currentreportlayout,realcontacts only;no fake
 swipe/firmwareflash/PMICreset/persistentwrites. Currentphonekeep0014XNU;
 no newbuild/phonebootyet. Snapshotoriginals saved before source edits.

- CURRENT PHONE:0014 temporaryboot SENT,exec4554exit0,FASTBOOT1.181s,
 2026-10-24T02:56:05.002993+00:00 (2026-10-24 Australia/Melbourne). Exactprepared
 imageSHA6e6eb1b6661c08024b9244593ac43d9c1a2b57444c2ee8f09be1934c128b25b3,
 payload6accc02c770941f99046d0a4061b206421d0588a762915f7bff7258f6053a5da,
 same0013kernelab50b65d...;Ccopyplan/newQEMU/priorall5provenances rechecked.
 Freshreadonlypreflightexec75654PASS34C:full16GiB baseSHA689a8cd1... MATCH
 in77.461s,fresh182maps before/after/exactpayloadmap;outer4KiBheader
 unchanged7c19bb29...,GPTheadmatches,userdataunmountedRO1. Headerstillpending
 Androidjournal,not certifiedclean;NOreplay/repair/staging/devicepartitionwrite.
 Bootscript repeatedfreshmap/header/GPT/RO/temp checks then adbbootloader+
 fastbootboot. boot.json/phone-boot.log/preflight.json/full-image-readonly-
 verification.json/deployment-state.json retainedprivately. Actual0014screen
 nowobserved above:lockscreen works,physicalinput fails.
 Keepthisboot;no USBrestart/logchannel;doNOTrequestanotherrebootsolelyforlogs.
 GUIhome,touch/USB,Apps,persistent64GiB/tripleboot remainunfinished.

- NEW REAL GUI MILESTONE on0013 BEFORE any0014boot: user supplied threephotos
 10145E3A... retainedprivately as launchservices-0013/hardware-late-lockscreen-
{1,2,3}.jpg +hardware-late-lockscreen.json. Photo3shows red/pink date/time
 Wednesday,December31/4:28,camera affordance,bottomhomeindicator;real iOSlock
 screen rendered amid visiblekernelconsole remnants. This ISactual GUI proof,
 NOT successfulunlock/home/input/App proof. Wrongdate/coloredclock alone are
 not panic evidence. Photo2 vmd425/thread4613 CPUwarning ~51%over174s,spindump
 exec;no panic shown. RAMCOW26356/32768,dirty420556KiB,reserved512MiB,UFS-error0/
 refused0;not exhausted. Real0013 eventuallyprogressed: priorwaitsnapshots
 doNOTestablishpermanentstall/deadlock;doNOTcredit not-yet-booted0014forGUI.
- User explicitly returnedFASTBOOT afterthelate0013GUIphotos;keep-screen
 suggestion superseded by physicalstate. Freshreadonlypreflight and0014boot
 nowcompleteabove. Retains diagnosticconsole/args for identity-only comparison.
 Actual0013GUI cannotbeattributed to0014identitychange;earlierwaitsamples
 represented transientstate,not provenpermanentstall. Neednew0014screen.

-0014 PREPARATION record (nowSENT asabove): tools/mkadt-polaris.py explicit --wifi-mac-file
 accepts only6raw nonzero unicast bytes;adds /chosen/mac-address-wifi0 only.
 No address default,no WLAN node/network driver. All7ADTtests PASS inclfull
 tree serialization roundtrip/default restoration/invalid inputs. Real0014tree
 minus one property is byte-identical to0013phone.adt;no args/kernel changes.
 Image shim/out/polaris-xnu-wifi-identity-0014/polaris-xnu-wifi-identity-0014.img
47288320bytes,SHA6e6eb1b6661c08024b9244593ac43d9c1a2b57444c2ee8f09be1934c128b25b3,
 payloadSHA6accc02c770941f99046d0a4061b206421d0588a762915f7bff7258f6053a5da.
 ActualCpayloadvalidator PASS. Reuses exact0013kernel ab50b65d...;gh rechecked
 CI40001585107 attempt2 success/source1d06f9ea. New syntheticidentity QEMUon
200s PASS,exec13889exit0,26checks:PID1alive/displaystartup,targetrotation,
 exact12/2frame traces,unbackedFPstop,no panic fullring/screen,0unknownglyphs.
 Othergates reuse prior exactkernel all5regressions;not rerun. NativeAppleMG
 lookup/GUI/UFS/input/App NOTexecuted in QEMU;real0014screen pending.
 Private0014prepare.py,
 native-path-analysis.json,prepared.json,preflight.py,boot-phone.py retained.
 Preflight requires sameknownouterheader,RO1/noload,fresh182maps before/after
 full16GiB imageSHA,unchangedheader/GPT,unmount,temp<45C;no repair/replay/write.
 Source commit4798fe7 +hardware-recorda8b85f8 pushed to origin. Readonly
 exactphoneUSB check:noFASTBOOT/noADB while0013XNU. Userhasnowreturned
 FASTBOOT;new0014readonlypreflight/temporaryboot nowcompleteabove. Never
 reuseoldpreflight orreenableUFSwrites. GUIhome/input/Appunfinished.

- NEW0013 HARDWARE OBSERVED: user photos hardware-focus-{1..4}.jpg and clearer
 hardware-focus-later-{1,2}.jpg under research/polaris/launchservices-0013/.
 hardware-focused-state.json + corrected hardware-focus-later-symbols.json
 retain observations. Cache slide3c540000; samples20/21/22/23 rotate correctly.
 Real SpringBoard3/3 selection now observed (QEMU fixture still1thread/task).
 SpringBoard26/TID210 synchronous NSXPC -> _LSCopyServerStore+768; TID1141
 waits CoreServices gSessionLock,addr21e2b24b8/value102,owner unestablished.
 lsd108/TID399 sc=-36 semaphore_wait_trap -> libdispatch -> MobileGestalt
 19c57c430/644/084 ->19c5716e8 Wi-Fi MAC query. Clearer photo shows runtime
 1d8abc0f8,NOT early blurry c8f8 candidate; valid direct call at19c57c0f4.
- Exact20H392 disassembly identifies native first path
 IODeviceTree:/chosen/mac-address-wifi0 (CFData),then sdio/wlan/marconi-wifi
 local-mac-address,then IONetworkController matched-notification fallback.
 Fallback dispatches CFRunLoop worker with5s run duration and waits semaphore
 FOREVER in caller. Current tree lacks address and WLAN/network service;
 snapshot identifies a real missing identity path but does NOT prove deadlock
 or explain every remaining blocker. lsd main waits kevent_id,another thread
 dispatch_group_wait;5/8otherthreads unobserved. MCM64 first3/4threads ordinary
 CFRunLoop/workq waits. Do not bypass MG,locks,errno or fabricate Wi-Fi driver.
- Verified original persist.img backup SHA matches its manifest; readonly host
 debugfs extracted /wlan_mac.bin (18byte wlan0= +12hex),valid6byte unicast
 factory address. Backup hash unchanged;no mount/replay/device writes. Private
 factory-wifi-identity.json/factory-wifi-mac.raw;never commit device address.
 Explicit ADT identity opt-in nowimplemented as0014above through native
 /chosen path,retaining absent WLAN node/no foreign driver. Same0013kernel;
 serialization/default preservation/payload/newQEMU PASS.
 Keep currentphone XNU until concrete newimage verified;no USBrestart channel.
- Actual FBmask284000238429178,swaps7/presents5/pixels10767600 static across
 observed focused samples;contents unknown,NOhome/App proof. COW max21287/
32768,dirty339580KiB,reserved512MiB,UFS-error0/refused0,NOTexhausted. No panic
 visible in snapshots;not lifetime health. GUI/touch/USB/Apps/64GiB unfinished.

- CURRENT PHONE STATE:0013 temporary boot SENT,exec64648exit0,FASTBOOT1.170s,
 2026-10-24T02:25:14.942595Z (=2026-10-24 Australia/Melbourne). Transport
 acceptance then actual0013focused screen observed above;GUI unfinished. Image/kernel/
 payload hashes below unchanged,all5QEMU+Cpayloadprovenances rechecked.
 Keep this boot forNEWfocusedcaller evidence;no USBrestart/logchannel. First
 sample60s afterBSD,then15s pertarget,SpringBoard/lsd/containermanagerd rotate.
 Capturefullheader/slide and T/M/L/B,including o=6 deeperframes and thirdthread;
 45svideo/fullscreen burst around2min shouldcover all3focusphases. Old0012
 photos are not0013evidence. Fullhome/touch/USB/Apps/persistent64GiB unfinished.
- User returnedFASTBOOT;knownhashrecovery booted,theninitial preflight STOPPED
 before filesystem mount:newouter ext4 needs_recovery bit. Currentstate1,
 incompat10046 (afterapprovedrepair10042),mountcount3;cause/unobservedAndroid
 boot unknown. DoNOTinferwritecause or callthisclean. GPTmatches,rootrecovery,
 userdataunmountedRO1,temp31C. No journalreplay/repair/staging done thisturn.
- StrongerREADONLYfile-root verification performed instead of touchingext4:
 ro,noload,nodev,nosuid,noexec mount on alreadyRO1device;verifiedoldSHA2helper,
 fresh182FIEMAP exactly matchespayload,full17179869184byte imageSHA
689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b MATCH
 originalimmutablebase in74.656s;secondFIEMAPsame,thenunmounted. Outer4KiBheader
 byte-identical before/after verification,GPTmatches. Preflight expressly says
 outer_filesystem_clean=false,needs_journal_recovery=true;Android journal left
 unchanged. File-root XNU nevermountsouterext4:reads onlytheseverifiedrawextent
 bytes;alllogicalwrites remainRAMCOW512/ufsrw0. DoesNOTcertifyAndroidFShealth.
- Finalhostadmission requiresknownext4state1/onlyknownRECOVERfeaturedifference,
 full16GiBSHA/freshmapproof<600s,same liverecoverybootID,unchangedouterheader,
 userdataunmountedRO1,size/deviceidentity,GPThead,temp<45C. Bootscriptchecks
 all5samekernel/QEMU,Cpayload,exactpreparedimageSHA,fresh182mapagain,then
 adb rebootbootloader + temporaryfastbootboot. Temp33C. No flash,GPT,Windows,
 baseimage orAndroidmetadatawrites. Finish-readonly-preflight.py,
 full-image-readonly-verification.json,preflight-stopped.json,preflight.json,
 boot.json/boot.log/phone-boot.log/deployment-state.json retainedprivately.
 NEXT:decodeNEW0013focusedhardwarecallers before anyfix/bypass oranotherboot.
-0013 source1d06f9ea19c6fb9d9f8a9bc23a5c0e30ff0d6503,0810focused diagnostics.
 CI40001585107 attempt2 SUCCESS/job120593650207,build5m16s;fullgh log
 research/polaris/ci-40001585107.log. Attempt1job120578752139 failed before
 any steps,hostedmacOS runnercapacity;rerun same source succeeded. Artifact
12523873372/60322627bytes,polaris profile/exactcommit/ZIPentryCRC/kernelSHA
 verified:xnu/out-polaris-0013/kernel.development.sweet,
 SHAab50b65d640233492cad41540e10db4323c532df2e0769513c71d2eb42d80bc9.
- ALL5 sequential newkernel QEMUtests PASS,exec33288exit0,102assertions:
 focuson300s,stackoff200s,missingexplicitCPUargument200s,nodiag90s,legacy180s.
 Focus rotates SpringBoard/lsd/containermanagerd,masks2/80/100,one perpass in
 syntheticfixture;14passes on300s. Exact12frame chain in two6address lines,
 lsd exact2frames,unbackedMCMFP n0/e2;off/CPUargument guard allB n0/e4;outergate
 no sampler/counters;legacy old5targets/mask67/exact6framecap. PID1alive,
 displaystart,no panic screen/fullRAMrings,0unknown glyphs. Samekernel/fixture
 provenances for all5. NOApple services,GUI,App,UFS,touch,or actualSMP proof.
 Fixture1thread/target;3thread selection is a codebound,not positive3threadtest.
 PriorREFERENCE0012kernel180s also passed newfixture/legacychecker ONLY.
-0013 temporary image PREPARED/SENT and SHA rechecked,47288320bytes:
 shim/out/polaris-xnu-launchservices-0013/polaris-xnu-launchservices-0013.img
 imageSHAc62a879e185646b87a75edd6d6d4f9cec16d301598a564246d15615bd3bc5647,
 payloadSHAd3988402a8a1caa4a82c3d4ab4144d59892b17065ae7a346509058021df4e041.
 ActualCpayload copy-plan validator PASS. prepared.json/verification.json/
 qemu-check.json and per-modechecks/provenances in launchservices-0013/.
 Cmdline tools/polaris-ios-launchservices-diagnostic.cmdline retains ufsrw0,
 polarisramcow1/512MiB,rootrw1,sweetlog0,sweetscan=-,explicitcpus1,CPUdisplay,
 visibleconsole1Hz,polarissample1/polarisstack1;adds polariswait1 only.
-0013bootnowSENT as above;doNOTrerun initialpreflight.py fromXNU or waive
 pendingjournalchecks. Futurebootneedsfreshmap/fullimageproof asappropriate;
 neverrepair/stageagain orenableufsrw1. Actualfocusedhardwarecaller evidence
 nowdecoded above;current0013photos still doNOTconfirmGUI.
-0810 explicitpolariswait1 focuses one service perpass,first60s,interval15s,
 36passes,max3threads/12frames. Six addresses per192byteboundedline,offseto,
 savedMachargs for allselectedMachwaits. Withoutfocus flag legacy2threads/
6frames/oldnames preserved. Residentreader/map/CPUguards byte-identical to
0809;2actualCI-header ARM64 object compiles,exactpatchapply/output,native
 ASan/UBSan incl12framecap PASS. Generic armedbanner stilldescribeslegacy
 defaults;per-passfocusbanner is authoritative for focus limits. No startup,
 locking,errno,filesystem,display/input hardware behavior bypass added.
-0012 HARDWARE:fivephotos wait-callers-0012/hardware-sample-7-8-{1,2}.jpg,
 hardware-sample-15-{1,2}.jpg,hardware-sample-16.jpg;transcription/symbol JSON.
 Realnofaultcallerwalk WORKS,cache slide41030000;SpringBoard26/3threads,
 backboardd56/14threads,usermanagerd84. FBmask284000238429178,swaps7/present4/
 pixels8614080 unchanged across samples7/8/15/16:realCPU copies,contentsunknown,
 NOhome/Appproof. RAMCOW20252..20334/32768,reserved512MiB,dirty<=324712KiB,
 UFS-error0/refused0,not exhausted. FirstMCMmkdir group90/e2/rootlogslookup.
- Exact20H392 callers:SpringBoard212 waits UL_UNFAIR_LOCK op1000002/valueb02,
 address222da24b8 = CoreServices gSessionLock (unslid1e1d724b8),
 _LSContextInitCommon+212 ->LSApplicationRecord bundlelookup from
 CCSModuleRepository modulefilter. SpringBoard287 waits synchronous NSXPC
 reply;6frames truncate at Foundation waiting-for-reply marker. Actualendpoint
 and thirdthread/lockowner not yet identified,NOdeadlock proof. Backboardd307/
 usermanagerd330 in ordinaryCFRunLoop receive-only waits,opt507000806:
 messageID meaningless withoutSEND. Backboardd361 groupwait mainbinary+18a78
 is BKButtonHapticsController assetcallback,NOTestablishedwindowserverblocker.
 Exactdisassembly saved. lsd/MCM launchdjobs present;lsdentry jumps to
 CoreServices _LSServerMain unslid181cec36c. Framebuffernotify usesCanDrop,
 zero-timeout send;doesnot prove timeralive. Do not bypass checks from guesses.
-0012 temporary boot SENT exec46178exit0,fastboot1.166s,
 2026-10-23T18:01:42.248259Z (=2026-10-24 Australia/Melbourne). Guarded boot
 rechecked exact280fsource/profile/kernelSHA,all4QEMUresults/provenances,
 Cpayloadvalidator,exactimageSHA,phonepolaris/root/size,userdataunmountedRO1,
 fresh182extents/GPT head identical,temp<45C. Earlier preflight85081PASS35C.
-0012 source280f1288d6dd1743ea6b788670ab535b14777e4d; CI39996796313/
 job120562312461 SUCCESS,full gh log research/polaris/ci-39996796313.log.
 Exact source/polaris profile/artifact12519894168 (60315294bytes),ZIP entryCRC
 and kernelSHA verified. Kernel xnu/out-polaris-0012/kernel.development.sweet
 SHA25eb4cc035318a35f3aa1be677bf847679d560cf98e483fa926e0b1f37e37850.
 All new source baselines/private scripts/test results wait-callers-0012/.
- ALL4 new-kernel sequential QEMU tests PASS exec92409:enabled200s,
 stackoff180s,missingexplicitcpus180s,nodiag90s.3exact resident2frame chains
 [0x10000045c,0x10000044c],unbackedFP n0/e2,correct savedPC/sc93,mask67,
 multiple samples,all frame/CPU-argument/outergates correct,PID1/displaystart
 intact,no panic screen/full rings,0unknown glyphs. All4same25eb4cc0... kernel
 and fixture provenance. Full qemu-check.json/verification.json saved.
 Tests synthetic ONLY,not Apple services,physical UFS,touch,GUI,Apps,or SMP.
- Phone image same prepared/validated artifact used above:
 shim/out/polaris-xnu-wait-callers-0012/polaris-xnu-wait-callers-0012.img,
 47288320bytes,SHA1ee4940efa9fbe7e85d6cf98801e350dae7bdfb5a21762538182e07da6087133,
 payloadSHA78f1d98c7ca3a287a09d71eed2160e1ae96bac45d50e5d6c8bf19b1ece373478.
 ActualCcopy-plan PASS. boot.json/boot.log/phone-boot.log record sent state.
 Guarded script is not a reason to reboot again before current evidence.
-0809 adds compact max2threads/task and optional polarisstack1 reader,6frames.
 Explicitcpus1 AND maximum possible CPU0/online1 required,or no frame reads.
 Task/map/thread refs with try-only tasklock; all locks released before reads.
 Each16byte aligned frame: disablepreemption/IRQs on singleCPU,switch active
 map,nofault AT translation,pmap_valid_address/default RAM cache check,checked
 kernel-aperture ml_nofault_copy,restore oldmap/IRQs/preemption. No copyin,
 vm_fault,allocations,KDP-only APIs,user writes,process suspension,or syscall
 bypass. Strict increasing FP within1MiB ofSP;zeroLR terminates,not a scan.
 Actual3CI-header ARM64 object compiles PASS,no stubs; shared walker native
 ASan/UBSan bounds/cycle/failedread/limit/overflow/zeroLR PASS;exactpatchapply
 PASS. Reader audit JSON saved. Source/startup/locking checks preserved.
- Adds independent relaxed framebuffer counters printed per sample: FB calls
 is selector0..63 BITMASK (0 does NOT rule out higher-selector calls),swaps,
 presents,pixels are cumulative. Snapshots not a coherent frame transaction;
 pixels>0 does NOT identify home screen or proveApp operation. New M fields
 are saved mach_msg2 options/packed ports+id+recv metadata (no message data),
 L fields ulock args;B lines caller addresses,not heap/string contents.
 tools/polaris-ios-caller-diagnostic.cmdline preserves512MiB volatileCOW,
 ufsrw0/rootrw1/sweetlog0/sweetscan=-,CPU display/consolevisible1Hz,sampler1;
 adds polarisstack1. Native display/input/storage behavior otherwise preserved.
- New synthetic64MiB fixture caller-test.raw has3known valid2frame sleepers
 plus usermanagerd unbackedFP. Prior0011-kernel90s smoke:PID1/four child entries
 alive/no panic,armed banner,but no periodic sample yet. ExactPC/FP checks
 unexercised (original incomplete checker retained),NOT code failure/passed
 proof. Expanded off/CPU-argument windows180s instead of dropping assertions.
-0011 HARDWARE evidence:5photos process-sample-0011/hardware-sample-5.jpg,
 hardware-sample-6.jpg,hardware-sample-10-11-{1,2,3}.jpg; structured
 hardware-process-state.json,hardware-sample-5-symbols.json. Real sampler works,
 PS END5,6,10,11 found4/mask47:launchd,SpringBoard,backboardd,usermanagerd;
 no selected migration process at those instants. SpringBoardPID26,3threads,
 slide4675c000,mh100140000; t0ID210 _mach_msg2_trap+8/_mach_msg2_internal+76,
 t1ID1153 __ulock_wait+8/__os_unfair_lock_lock_slow+172,t2ID1177 parkedworker.
 Same waits across several30s samples,NOT deadlock or successfulGUI proof.
 Backboardd only t5..7 visible (IPC receive);main overwritten by67x67circular
 console. Need caller frames+main backboardd and FB counters before fix/bypass.
 Current COW groups20474..20520/32768,dirty326744..327472KiB,reserved512MiB,
 UFS-error0,refused0:NOTexhausted. FirstMCMmkdir e2/lookup root logs dir retained
 atgroup12515; mount_hfs/fairplayd.H2/bluetoothd exec seen,launchd worker IDs
 change. No panic in snapshots,NOT lifetime health/desktop/touch/App proof.
- PRIOR0011 phone boot exec4751 exit0,fastboot1.170s,2026-10-23T17:23:44.830990Z;
 imageSHAc5a717a71ee5aa08d9198c80e59676ddef828c5847765964ca477ac7886bec52,
 payloadSHA5db2b09fcfd8bdf5c66a20adb42f86611c0b57c5b427df8daa40999b22a3cd1b.
 Kernel66ec476e4ff8a33dc285d245db1932bff4774b3887121fcf61b3d0710dee8dd5,
 CI39991203030/source8160426. All3sequential simulations passed; subsequent
 hardware PS evidence above. User then returnedFASTBOOT/recovery as above.
- Need after0012 boot: full-screen photo when FB/PS/T/M/L/B printed (~2min),
 preservingcache slide+PID headers and both GUI thread caller lines; burst or
 45s video if wrapping. USB log/restart not ported; keep new boot until evidence
 saved. Do not ask repetitive FASTBOOT just from COW text. Full home,physical
 touch,USB,Apps,persistent64GiB and tripleboot still unfinished.

-0009 user observation (2026-10-24): static Apple Logo WITHOUT progress bar
 for over3min. No photo/video yet; no visible daemon logs available. This is
 NOT proof of stable SpringBoard, stuck migration, kernel panic, or GUI success.
 Read-only exact-device USB check found neither ADB nor FASTBOOT control while
 XNU running. Source confirms noconsole1 mutes console after first valid CPU
 presentation; later first GUI fatal signal would unmute. Need readable logs
 before choosing any root/filesystem/daemon changes. Do not infer migration or
 bypass startup checks from the logo alone.
- Console0010 prepared on Mac, SAME kernel907/fbfda0c7 (CI39984984336 already
 validated). ONLY parameter changes vs0009: sweetfb_noconsole1->0 and sweetfb_hz
 5->1, allowing diagnostic text between frames. Marked ADT byte-identical to0009;
 ufsrw0/polarisramcow1/budget512/base immutability unchanged. Actual C payload
 copy-plan validator PASS; image47288320bytes,
 shim/out/polaris-xnu-display-console-0010/polaris-xnu-display-console-0010.img,
 SHA9bdb9e564df240f1d6757506f4950c93b111edf85224d4021f0dc21886ee4a42.
 Prepared.json and guarded boot-display-console-0010.py under research/polaris;
 requires same tested kernel/provenance and exact prepared-image SHA, then fresh
 phone RO map/GPT/temp checks. No new kernel CI needed (no kernel code change).
- User returned FASTBOOT; temporary known recovery/read-only preflight currently
 running exec session from this turn; check display-console-0010/preflight.json
 and result before boot. Current physical state transitioning recovery, not yet
 new XNU boot. DO NOT rerun repair/staging/format or enable UFS writes.
 Physical touch,USB,App operation,persistent64GiB/tripleboot unfinished.

- PRIOR0009 DISPLAY temporary boot SENT,exec82812 exit0,
 2026-10-23T16:32:38.530021Z (=2026-10-24 Australia/Melbourne),fastboot1.183s.
 Guarded boot-display-0009.py: exact907 kernel/profile/hash,all QEMU guards
 and matching provenance, actual C copy-plan validator PASS. Just before reboot:
 correct polaris/rootrecovery/partition size,userdataunmountedRO1,fresh182extents
 identical,GPT first1MiB identical,temp<45C. No flash/GPT/Windows/base writes.
 Image shim/out/polaris-xnu-display-0009/polaris-xnu-display-0009.img,
 47288320bytes,SHA8ca5f1481a3424f9c4da50b1466c1b886fb11c98e7a5bb79450f20392f8b0f07;
 payloadSHAfdefc493f14e2ebd17da2a8a30fda3efdd865ec01df8461a84d529a02dc8b79b.
 Canonical display args preserve ufsrw0/rootrw1/polarisramcow1/budget512,
 polarisdiag1/crashslot0x1dcff9a70,sweetlog0,sweetscan=-; newpolarisdisplay1,
 sweetfb_noconsole1,sweetfb_hz5. Marked ADT adds disp0 only; WLAN absent.
 First successful bounded CPU copy may mute text; SpringBoard/backboardd crash
 unmutes it so subsequent diagnostics visible. Transport acceptance does NOT
 prove a real panel frame, SpringBoard stability, physical touch or working App.
 Need current screen photo or15-20s video after about1minute; retain this boot
 until actual screen evidence saved. XNU USB log/reboot not ported. DO NOT ask
 for FASTBOOT again until new evidence collected. Physical touch,USB,
 persistent64GiB/tripleboot,App interaction remain unfinished. Latest kernel
 and all provenance/boot/QEMU evidence in display-0009/,CI39984984336.

-0009 sequential QEMU suite COMPLETE PASS (exec59300): display-on150s and
 default/off150s both PID1 alive,no panic in screen or complete RAM ring,
 0unknown glyphs. Explicit missing-argument guard30s confirms driver refusal
 and CPU initialization (no PID1 boot claim). Default/off replays synthetic
 valid mkdir0705 twice + failed mkdir/fcntl/crash slots, first errors retained
 with[cow=0/0],all assertions PASS. check-qemu.json (actual filenameqemu-check.json)
 ties all three provenance kernelSHAs tofbfda0c7...; service,fit,gate checks PASS.
 Native blitter tests and actual two-file local compile previously PASS; no
 actual Apple GUI or panel presentation proof yet. Guarded boot-display-0009.py
 ready to run next using markedphoneADT and same tested kernel. Phone currently
 root RO recovery; all new persistent files so far only on Mac.

- Verified0009 kernel SHA256
 fbfda0c765677b7e74b4e5ec96efb8e91116e1a885fdcba5de033dcd0b12ba9e,
 xnu/out-polaris-0009/kernel.development.sweet; artifact12516160902,
 60292214bytes. Profile source9073927/platformpolaris,ZIP entryCRC/kernelSHA
 checked, full gh log ci-39984984336.log confirms0807 applied.
 QEMU gated30s: explicit missing bootarg refused driver, CPU initialized,
 no panic; PID1 NOT reached in30s, so this is ONLY guard validation. Initial
 run-checks.py had overbroad PID1 assertion for this short test; scope corrected,
 same captured test retained, no kernel protection/timeout bypass.
 QEMU display-on150s PASS: actual driver prints CPU fit1125x2436->997x2160
 at41,0 on1080x2160; AppleCLCD default surface1 registered using0x9d400000,
 stride4320. PID1 alive,no panic in ring/screen,0unknown glyphs. No actual
 IOSurface presentation/Apple GUI/user input exercised by the RAM init.
 Default/off150s synthetic diagnostic regression CURRENTLY RUNNING exec59300;
 then check-qemu.py + guarded boot-display-0009.py. Phone still RO recovery.

- CI39984984336/job120521705845 now SUCCESS; Build16:18:55..16:23:15Z,
 full compile/link and artifact collection completed. Source90739277724a905ab3401a930f84364c5fac211b.
 Download/profile/entryCRC/kernelSHA verification ongoing; gh full log being
 saved research/polaris/ci-39984984336.log. New-kernel QEMU tests not yet run;
 phone still ROOT RO RECOVERY. Avoid parallel QEMUs after0008 interrupt timing
 panic; planned gated30s,on150s,off150s sequential, then check-qemu.py and guarded
 boot-display-0009.py. Off fixture actual synthetic diagnostic children from0008.

- Display source commit90739277724a905ab3401a930f84364c5fac211b pushed;
 CI39984984336/job120521705845 queued on macos-14 at last check. Watch session
 90985/private display-0009/ci-watch.log. Phone remains RO recovery. Exact-source
 downloader download-ci-kernel-0009.py and marked phone/QEMU ADTs prepared;
 QEMU on150s,off150s,gated30s checks and boot-display-0009.py NOT executed yet.
 Need wait full CI,download/hash/profile verify,run actual new-kernel simulations,
 then guarded temporary boot. Public current patch does not enable physical
 touch or the foreign sweet_touch.c; never call that unmodified on polaris.

-0008 hardware milestone: six photos saved root-capacity-0008/hardware-
 springboard-{1,2,3}.jpg and hardware-springboard-later-{1,2,3}.jpg, JSON.
 COW active1,512MiB reserved,13162->15273/32768groups,UFS-error0,refused0;
 written up288448KiB. Only retained mkdir error visible: containermanager
 e2 fd-2 lookup /private/var/root/Library/Logs/MobileContainerManager,
 first at12514/32768. Earlier cryptex/locationd/lockdown failures NOT visible
 in these snapshots; not proof of permanent health. SpringBoard repeatedly
 SIGTRAP5 ns2/code5,PC0x1a7b18ca8,cache slide0xc1b0000,unslid0x19b968ca8:
 FrontBoardServices -[FBSDisplayMonitor _initWithBookendObserver:transformer:]
 +1160. Exact disassembly nil main-display object branch -> crashlog + BRK0.
 Current polaris ADT intentionally omits disp0, consistent with this failure.
 backboardd IOK and many daemons progress; no GUI/apps/physical touch proof.
 securityd selector10 returns0xe00002c7 from compatibility stub; not proven
 cause of SpringBoard crash. Actual new evidence does NOT show RAM exhaustion.
- User returned FASTBOOT. Known recovery temporarily booted exec53563 exit0;
 display-0009/preflight.json PASS: fresh182extent map/GPT identical,outerext4
 clean,userdataunmountedRO1,33C,CPU caps1056000. CURRENT PHONE ROOT RECOVERY.
 No persistent filesystem writes or repair this turn.
-0807 PREPARED: opt-in ADT disp0 + polarisdisplay1 bootarg; driver requires
 verified0x9d400000,1080x2160,stride4320,32bpp, rejects native canvas. CPU-only
 bounded nearest resampling fits logical1125x2436 into997x2160 at41,0 with
 narrow black sidebars; preserves source endpoint pixels. Existing topaz
 behavior untouched. No display controller registers or storage code changed.
 Persistent column workspace avoids allocation/division inside pixel loops.
 Actual shared-header ASan/UBSan tests cover complete frame corners,padded
 strides,source offsets,onepixel source,clipping,invalid lengths/overflow and
 400 small destination cases. ADT default remains no display/WLAN; --display
 creates only the marked display. Seven tests PASS. Two actual CI-header
 single-file cross-compiles PASS. Patch dry-run PASS; full CI/new-kernel QEMU
 and hardware not yet run. GUI fatal signal unmutes console; first successful
 fitted frame may mute it with sweetfb_noconsole1, diagnostic RAM ring retained.
 tools/polaris-ios-display.cmdline uses budget512 and5Hz CPU presentation.
 Physical touch, USB, persistent64GiB/tripleboot and working Apps unfinished.

- PRIOR0008 temporary boot SENT, exec73225 exit0,
 2026-10-23T16:03:28.665376Z (=2026-10-24 Australia/Melbourne),fastboot total
 1.171s. Guarded boot-capacity-0008.py passed actual C payload validator,
 exact tested kernel SHA/provenance, QEMU checks, root recovery identity,
 userdata unmounted/runtimeRO1,size115167178752bytes,fresh182extents identical,
 GPT first1MiB identical,temp<45C. No flash/GPT/Windows/base-image writes.
 Image shim/out/polaris-xnu-capacity-0008/polaris-xnu-capacity-0008.img,
 47288320bytes,SHA32113028a643f67e7c8f21b1e96cd2f36af0f1afae160da0378307df71128827;
 payloadSHA8052f935ce0ea78e22b948becfa1aefb0ab301041cc43fc9a211f970f7db4548.
 Canonical diagnostic args polarisrammb=512,polarisdiag1,crashslot0x1dcff9a70,
 ufsrw0/rootrw1/polarisramcow1,sweetlog0,sweetscan=-. Logical iOS writes remain
 volatile only; base immutable. Boot transport acceptance NOT proof of hardware
 reservation/root mount/Apple services. Need current15-20s video or photo of
 D COW/D RAM/D CRASH/D MKDIR/D FCNTL; first-error lines append[cow=used/limit].
 Keep screen running until captured; XNU USB log/reboot unavailable. Do NOT ask
 for FASTBOOT again before collecting screen evidence. No home screen/apps
 validated, no persistent64GiB/triple-boot menu completed. Next use FIRST failure
 snapshot, not just later exhausted accounting, to guide the actual fix.
 Private boot.json/boot.log and verification.json in root-capacity-0008/.

-0008 kernel downloaded/verified SHA256
  4da8b6d2dfb715a9c4b711a1d73cce7bf4b6b00fbf73c3d53d6d1a3f3ca03a1a,
  xnu/out-polaris-0008/kernel.development.sweet. Artifact12513099018,
  60292491bytes; exact0d source/profile,ZIP entryCRC and kernelSHA verified.
  0806 applied in complete gh log; no new kernel compile/link failures.
  QEMU diagnostic150s PASS: exact cryptex mkdir0705 succeeds twice, synthetic
  first failures retained with[cow=0/0], mkdir/fcntl records repeated, PID1 alive,
  no panic/0unknown glyphs. QEMU arena negative test reads actual kernel globals:
  reserved536870912bytes,used0,base nonzero,then expected host/link refusal and
  root-unavailable panic6 (QEMU has NO UFS host); this is NOT a successful boot.
  Initial RAM run alongside the other two QEMUs: PID1 alive then interrupt-mask
  duration42.998992ms exceeded13.631488ms; preserved qemu-0008-ram-first/.
  Isolated repeat SAME kernel/args150s PASS, PID1 alive,no panic in screen/ring,
  0unknown glyphs. Host scheduling cause plausible but NOT proven; no hygiene
  protection disabled. No actual Apple service/UFS COW/GUI validation in QEMU.
  Private verification.json and per-test provenance SHA saved. Phone boot script
  now requires all these checks and exact matching tested SHA. Phone still RO
  recovery until boot.json confirms sent; no new persistent phone writes.

- Latest source commit0d5066dfca2181c711c30f254e8500c0f60a2995 (0806 arena,
  first-failure COW snapshots), after ac9d97c54d2ebaee2348b49f55dcbd97398c9362.
  CI39981234529/job120509720556 SUCCESS, full compile/link and artifact upload;
  full gh log research/polaris/ci-39981234529.log. Earlier ac9 CI39980680792
  cancelled as superseded. Downloading exact0d artifact with profile/entryCRC/
  kernelSHA checks. New-kernel QEMU RAM/diagnostic/512MiB arena negative test
  NOT YET run; hardware still recovery, no new boot. Private scripts prepared
  under root-capacity-0008; boot-capacity-0008.py gates exact kernel SHA across
  all QEMU results and fresh phone RO filemap/GPT/temp checks. Negative test
  privately adds only file-root metadata to QEMU ADT, expects missing UFS host
  refusal AFTER reserve; that ADT must NEVER be used on the phone.

- NEW DECISIVE0007 PHOTOS: hardware-retained-errors-{1,2,3}.jpg/.json in
  daemon-loops-0007/. D COW active1,8192/8192groups,UFS-error0:128MiB backing
  EXHAUSTED. First retained errors: cryptexd mkdir e22 fd3 stage=create,
  relative com.apple.security.cryptexd; MCM mkdir e2 fd-2 stage=lookup,
  /private/var/root/Library/Logs/MobileContainerManager. lockdownd local workers
  init error(-1,underlying detail truncated); locationd assertion
  CLAutoCohortUtilities.mm:111 createDirectoryAtPath; backboardd abort() called.
  No retained MCM SQLite fatal text seen this boot. Error records lack original
  timestamps/group counts: NOT proof that ENOSPC caused the FIRST mkdir EINVAL.
  Reporter DID continue running; earlier absence in photos was not evidence
  of a diagnostic-thread deadlock. HID user clients opened, not real touch proof.
- User returned FASTBOOT; known recovery temporarily booted (exec39600),
  root-capacity-0008/preflight.json PASS: fresh182extents identical, GPT head
  identical, ext4 clean,userdata unmountedRO1,35C,CPU caps1056000.
  No new persistent filesystem writes/repair; phone CURRENTLY ROOT RECOVERY.
- cryptexd disassembly: opens /var/db with0x100100, mkdirat(fd,
  com.apple.security.cryptexd,0705), unexpected errors fatal at main+0x343c4.
  Independently reproduced exact flags/path/mode on0007 QEMU RAM HFS:
  VALID_MKDIRAT_0705_PASS twice,150s no panic/0unknownglyphs. Does not reproduce
  actual phone image attributes or the UFS COW path. Source root journal is8MiB,
  not128MiB (read-only journal geometry saved). No blanket mkdir errno bypass.
-0806 PREPARED: explicit polarisrammb16..512(default128), phone profiles512.
  Reserve wired RAM before UFS lock/commands; finite16KiB arena allocator does
  NO runtime VM allocation/reclaim during storage requests. Shared COW maximum
 32768groups,512MiB plus bounded metadata, dirty/written-block accounting.
  Existing CDB read-only allowlist unchanged; ufsrw must0, no base/UFS writes.
  Diagnostic accounting uses try-lock, never waits for storage; reports actual
  reserved bytes,dirty/write volume/refusals. Allocation-refusal logs bounded.
  Follow-up adds atomic used/limit snapshots to FIRST retained failure lines,
  so a later full overlay cannot be mistaken for the state at the first error.
  Native ASan/UBSan6tests PASS, including real8200groups crossing old8192 limit,
  readbacks, overwrites with full arena, failed allocation preserving data,
  bounds and invalid budgets. Actual CI-header single-file Apple clang PASS.
  Local tree research/polaris/buildtree-0004 now includes0806+updated shared
  header; originals and evidence in root-capacity-0008/. Full CI/new-kernel QEMU
  and hardware not yet run. Remaining GUI/input/persistent64GiB unfinished.

- LATEST0007 PHOTO: hardware-later-daemon-crashes.jpg/.json in private
  daemon-loops-0007/. Startup DID progress past usermanagerd: fmfd/contactsd/
  privacyaccountingd/coreduetd, backboardd IOK lookup visible. Not established
  as a usermanagerd hang. cryptexd[206] SIGABRT ns18/code2, same
  "unexpected failure: mkdirat: [22: Invalid argument]"; locationd[209]
  SIGABRT ns2/code6. Cache slide0x30ab0000. IOAccessoryManager lookup0found.
  Many coreduetd AKS selector17 logs obscure output; success0 is from the
  compatibility implementation, NOT proof real keystore hardware works.
  This photo does NOT include the retained POLARIS DIAG block. Need a15-20s
  video of the current screen (report every10s) or a photo capturing D CRASH,
  D MKDIR/path/stage, D FCNTL, D COW. Especially actual MCM err/xerr still
  unknown. Do not request another reboot or declare errors fixed before
  collecting those records. Current phone remains0007 XNU, no new boot/write.

- NEW0007 PHOTO (2026-10-24): hardware-early-startup.jpg/.json privately in
  daemon-loops-0007/. Explicit POLARIS DIAG and D COW active=1,groups31->43
  /8192,UFS-error=0: FIRST direct hardware confirmation of enabled RAM COW
  and changing allocation count (43groups=704512bytes at photographed stage).
  Actual corecrypto FIPS POST all tests PASSED/result=true. keybagd reports
  System Keybag loaded, then launchd exec usermanagerd. Warnings: /private/var
  mount does not support Data Protection, cannot set tmp classD, options DT
  entry absent. These warnings are followed by continued startup; not proof
  of a fatal condition. No D CRASH/MKDIR/FCNTL or panic visible in this image.
  Do NOT conclude0006 daemon failures fixed, no later-service/GUI/app proof.
  Leave phone running; ask whether logs still progress, only unchanged COW
  reports recur, or retained errors appear. Later photo above answers the
  prior async state question: startup progressed and crashes appeared.
  Do NOT request FASTBOOT or restart merely from this early photograph.
  If genuinely stalled at usermanagerd, the old sweetsample boot argument
  alone won't work on polaris: sweet_sample_start is currently only called
  below the non-polaris sweet_ufs_init branch, bypassed by file-root init.

- LATEST PHONE STATE:0007 temporary diagnostic boot SENT SUCCESSFULLY
  (exec28408,return0,total1.176s),2026-10-23T15:24:09.901701Z
  =2026-10-24 Australia/Melbourne. Guarded script boot-diagnostic-0007.py:
  kernel/profile/commit checks, both new QEMU checks PASS, actual C loader
  validator PASS, exact phone/product/partition size, userdata unmountedRO1,
  fresh182extents identical, GPT first1MiB identical,temp<45C before reboot.
  No flash/GPT/Windows writes. Image
  shim/out/polaris-xnu-diagnostic-0007/polaris-xnu-diagnostic-0007.img,
  47288320bytes,SHA44da994895015ff8a866e817586fbff6438fc4a9d6429890943e93cfb87fcea2;
  payloadSHA86caa7bbcb4c045c965ac5401f0c7524e9322868615feb1a221d453bfb815c1d.
  Canonical diagnostic cmdline has polarisdiag=1,
  polariscrashslot=0x1dcff9a70,sweetscan=- plus previous RAM-COW args;
  ufsrw=0 sweetlog=0, bounded128MiB volatile writes only.
  Fastboot acceptance alone was not hardware success; early hardware evidence
  now confirms the reporter/COW mode above, not later Apple-service success.
  Need photo/video of POLARIS DIAG / D CRASH / D MKDIR / D FCNTL / D COW,
  especially actual MCM err/xerr and cryptexd pathname/stage. Records reprint
  every10s but other daemon logs can scroll over them. Keep current screen
  until evidence saved. XNU USB log/reboot control not ported; do not ask for
  FASTBOOT again until the new screen evidence is captured. Then recovery
  physical power+vol-down is still necessary. No home screen/apps verified.
  Private boot.json/boot.log under research/polaris/daemon-loops-0007/.

-0805 diagnostic overlay prepared: explicit polarisdiag=1 retains first
  per-category failures in a fixed3.75KiB RAM table, reprints every10s via
  the existing startup reporter. mkdir error stage/path for cryptexd/MCM,
  MCM fcntl errno/cmd, and six GUI/bootstrap daemons' __os_crash messages.
  20H392 libsystem_c disassembly verifies message slot0x1dcff9a70; explicit
  polariscrashslot boot argument + current cache slide, bounded copyin/copyinstr,
  no dereferencing user pointers in kernel. No syscall result changes or
  storage write policy changes. Diagnostic profile disables large heap dumps.
  Local four-file Apple-clang compile with actual CI headers/options PASS
  (no stubs); full CI/kernel link and QEMU integration PASS below.
  Private sources/originals/logs in daemon-loops-0007/.
- Commit0cb4726e8640e4b33dabf31a869b60c4911154cd pushed; CI39975701824,
  job120489586542 SUCCESS; full compile/link and0805 applied. Downloaded
  xnu/out-polaris-0007/kernel.development.sweet, SHA256
  958c532f9d4079c0f56fdd1fcfb463ef4714f7033cd908ab939009ea4cc829ac;
  profile/commit/ZIP entry CRC/kernel SHA verified, ci-39975701824.log saved.
  Artifact12511633153,60287891bytes.
  Native ASan/UBSan COW + map/CDB policy
  checks PASS (4unittests). Patch dry-run against exact pre0805 sources PASS.
  Synthetic64MiB QEMU fixture prepared with named MCM/cryptex children for
  invalid-fd mkdir/invalid fcntl/crash-slot capture; expected synthetic crashes
  do NOT represent Apple-service validation. Fixture validated on0006:
  both named children exec/trap, PID1 stays alive150s,no panic,0unknownglyphs.
  New0007 QEMU RAM+diagnostic tests PASS150s each (exec2529,47958),
  no panic observed,0unknownglyphs. Actual simulated MCM/cryptex crash strings
  recovered through the configured user-space slot and reprinted; mkdir badfd
  errno9/path/stage and fcntl errno25/cmd32767 captured; first mkdir error
  retained despite second different pathname. diagnostic-check.json PASS.
  Default profile prints no POLARIS DIAG; PID1 alive. This validates diagnostic
  plumbing, NOT Apple services/UFS COW/GUI. Guarded phone boot sent above.
- Offline GUI audit: common SweetFramebuffer.cpp uses PE_current_console /
  physical IOSurface plus CPU memcpy, no DSI/MDP register access in this path.
  Polaris ADT currently intentionally removes disp0. Existing fallback presents
  iPhone X1125x2436 but CROPS to physical dimensions; on1080x2160 this would
  lose138logical pixels at each vertical edge. Future display enablement needs
  explicit polaris opt-in/verified geometry and full-frame scaling or another
  suitable layout; do not claim a complete screen from service publication.
- USB offline audit for future unattended logs: live DT DWC3@a600000,
  high-speed, QUSB2@88e2000 and SMMU s1-bypass, wrapper0xa600000+0xf8c00;
  USB30_PRIM GDSC absolute0x10f004. MiCode official polaris-o-oss
  drivers/clk/qcom/gcc-sdm845.c shows master CBCR0xf00c, sleep0xf010,
  mock-utmi0xf014, clkref0x8c008. Existing sweet_usb.c uses DIFFERENT
  master/sleep/utmi/clkref offsets0xf010/0xf014/0xf018/0x8c010! Do not enable
  it unchanged. cfg-noc0x502c,aggre0x8201c,ahb2phy0x6a004 match.
  Source saved privately daemon-loops-0007/gcc-sdm845.c and summarized JSON.
  No USB MMIO/probe/gadget startup or network setup on this phone this turn.
- Prior recovery state (2026-10-24): user returned FASTBOOT after two0006
  photos; known recovery temporarily booted. daemon-loops-0007/preflight.json
  PASS: root recovery, fresh182extent map identical, GPT head byte-identical,
  ext4 state1/no needs_recovery, userdata unmounted/runtimeRO1,35C and CPU
  caps1056000. No persistent filesystem writes or repair this turn.
-0006 hardware photos DO verify real Apple launchd starts Apple daemons;
  repeated crashes/respawns, PIDs187..2600+, NOT a desktop or working apps.
  No kernel panic visible. Shared cache slide0x8478000 (not0x84780000).
  containermanagerd trap PC0x1cd16183c = unslid0x1c4ce983c:
  +[MCMSQLiteDB openDBWithURL:error:]+896. Disassembly proves sqlite_open_v2
  succeeded, but sqlite3_exec(schema/PRAGMA initialization) failed, followed by
  _os_crash("Failed to initialize database, err = %d, xerr = %x") and BRK.
  Error numbers/database path are not yet known; do NOT assume RAM limit,
  missing container parent dirs, or repair by disabling failures.
  lockdownd main+0x94150 is "Failed to intialize local workers" fatal path.
  cryptexd ns18/code2: unexpected failure: mkdirat: [22: Invalid argument].
  locationd SIGABRT repeatedly. GUI/rendering/input/persistent writes remain
  unfinished. Private photos/hardware-result.json in ram-cow-0006/.
- Official ipsw3.1.738 verified/install under ignored research/host-tools/,
  archive SHA151b71da8c73912dbfbb95fc64e6b4929524279cb8cf5a3839932586e4ab8154.
  Read-only Apple cache indexed to daemon-loops-0007/dsc/cache.a2s;
  mcm-sqlite.disass.txt and lockdown-trap.disass.txt saved privately. Next:
  identify precise SQLite and mkdirat errors, add bounded opt-in diagnostics
  if necessary, keeping ufsrw=0/base immutable. No destructive actions authorized.

### Prior0006 boot/build record (superseded by0007 above)

- LATEST PHONE STATE:0006 temporary boot SENT (exec10746,return0),
  send46180KB1.078s,boot0.091s,total1.180s. No flash/GPT/Windows writes.
  Image shim/out/polaris-xnu-ram-cow-0006/polaris-xnu-ram-cow-0006.img,
  47288320bytes,SHA33143c51dca1d23ce362f7c881f05a888c34e20fe0ce2ee6118eb3d7955447b9.
  PayloadSHA1138e54bdeb9d034be5ede55820fa9129b683292e1a7a5c578e41e9631d9c123.
  Actual C loader validator PASS. Immediately before reboot root recovery:
  model/serial/size/path checked, fresh182extent map equal, GPT head equal,
  userdataRO1/unmounted,temp<45C. ram-cow-0006/boot.{json,log}.
  Args from tools/polaris-ios-ramcow.cmdline: polarisramcow=1 rootrw=1 ufsrw=0
  plus platform/ignition/cache args. Logical HFS writes use128MiB RAM overlay;
  underlying UFS always read-only. NEVER set ufsrw=1 to work around a failure.
  This is volatile bring-up: all writes vanish on reboot; persistent64GiB,
  triple-boot menu, home screen/apps remain unfinished. Fastboot accepted image;
  no proof yet RAM COW enabled on hardware or launchd/services advanced.
  Need user photo of final lines now; current XNU has no USB log/reboot control.
  Preserve screen until photographed; later physical power+vol-down needed if
  panic/stop. Do not blindly run recovery/staging/repair scripts again.
- Kernel0006 downloaded and verified:0b54be84305229ebf7d5f22975dd4137b87a2ef867175ce86a3345fad026e7f5,
  xnu/out-polaris-0006/kernel.development.sweet, CI39969996591/job120469836157
  SUCCESS,profilecommit877bf3ef8756954af4e554f8bf32da0abff9f70f.
  ZIP CRC/SHA/profile checked; ci-39969996591.log saved. New kernel QEMU RAM
  regression exec9791 PASS150s,PID1/heartbeats,no panic observed,0unknownglyphs.
  qemu-ram-cow-0006-ram includes full RAM console ring. This is default RAM
  path regression; actual COW data engine tested natively, hardware still pending.
  Actual-Apple minimal fixture exec75497 reaches exec launchd + libignition
  hello from launchd.1, then expected DYLD namespace6/code1 missing libSystem/cache
  (fixture deliberately excludes shared cache). Not a normal-system boot PASS.
  qemu-ram-cow-0006-apple/expected-result.json records scope; HFS md0 journal
  shutdown also prints unsupported flush0x19 (md0 fixture only). Hardware path
  RAM-COW sync ioctl returns0 without SCSI, source never writable.
  Full RAM logs captured. Guarded temporary phone boot now sent; see top.
- Read-only GUI hardware metadata saved under gui-hardware-0001/ while
  recovery idle. Input device registered synaptics_dsx; I2C3 address0x20
  dsx-i2c-force; additional3-0038 ft5x46 entry needs binding verification,
  existence/name alone is not proof of hardware. Recovery fb0 advertises
  dummy640x400/stride2560, NOT the proven ABL splash1080x2160/stride4320;
  do not substitute recovery fb0 geometry into the XNU phone ADT.
  No input events or I2C transactions read/sent; descriptions/sysfs only.
- Additional local single-file cross-compile PASS (exit0), using actual previous
  CI buildtree artifact12507665954 (ZIP SHA256+CRC verified), exact patched
  source+generated headers/config and real CI command flags; local Apple clang,
  NO XNU builtin/type-verification stubs. Only bsd/dev/sweet_ufs.c syntax, not
  full kernel/link proof. Private buildtree-0004/cow-local-compile.{log,json}.
  Original gh run download was slow; verified IPv4 ranged download completed.
  CI39969996591/job120469836157 SUCCESS after queue; artifact12508314362
  (60297205bytes), download/range verification in progress.0804 applied in logs.
  Prepared ignored run-qemu-0006.py {ram,apple} and boot-ram-cow-0006.py for
  validation/boot; run boot script only after new kernel and both QEMU results.
- RAM COW overlay0804 implemented, native ASan/UBSan tests PASS (actual shared
  header, randomized full-image reference model, collisions/overlap, bounds,
  ENOSPC and allocator failure with no exposure of uninitialized RAM).
  4KiB logical blocks,16KiB groups,8192groups maximum128MiB plus bounded
  metadata. Reads overlay dirty RAM blocks on immutable file; writes perform
  base-read/merge then RAM copy only. CDB read-only gate remains unchanged;
  never calls ufs_write_blocks on POLARIS, sync is RAM-only/no SCSI flush.
  Explicit polarisramcow=1 rootrw=1 ufsrw=0; default file root stays readonly.
  No topaz logger/input/USB startup. All changes disappear on reboot; persistent
  iOS writes/64GiB/GUI/apps still pending. Commit877bf3e pushed; CI39969996591/job120469836157 SUCCESS.
  New-kernel RAM regression and Apple exec tests complete (scope above);
  hardware result pending photo.
- Recovery read-only preflight exec(resume) PASS: fresh182extent map identical,
  GPT first1MiB byte-identical, ext4 clean/state1/no needs_recovery; userdata
  unmounted/runtimeRO1,35C, CPU caps1056000. Evidence launchd-compat-0005/
  preflight.json. Phone idle in root temporary recovery.0005 compat image
  packaged but NOT booted; prefer upcoming0006 RAM COW boot once CI/tests pass.
- NEW HARDWARE EVIDENCE (user photo,2026-10-24):0004 verifies GPT+HFSX,
  16384MiB/182extents/READ ONLY; BSD root ufsroot0; hfs mounted iOSRoot.
  Then /sbin/launchd exec dies namespace9 code0xe = OS_REASON_EXEC /
  EXEC_EXIT_REASON_WRONG_PLATFORM (Apple xnu-8796.141.3 reason.h defines14;
  kern_exec.c macOS-platform check, DEVELOPMENT unentitled_ios_sim_launch).
  This is NOT a bad file SHA or invalid-page signature failure. Actual kernel
  contains tunable. Missing compatibility args were an avoidable omission;
  canonical tools/polaris-ios-readonly.cmdline now includes known working
  unentitled_ios_sim_launch=1 ignition_level=1 launchd_unsecure_cache=1.
  Private file-root-0001/hardware-result.json + hardware-hfs-mounted-platform-panic.jpg.
- QEMU0005 runs actual Apple launchd/dyld (hashes equal verified source) from
  minimal64MiB HFS RAM fixture with corrected args: exec launchd, then namespace35
  LIBIGNITION / failed to reserve stdin descriptor /dev/null (fixture omitted
  /dev, so devfs mount failed ENOENT). Proves platform gate and Apple EL0 entry;
  does NOT validate normal launchd initialization/shared cache/services.
  qemu-launchd-compat-0005/compatibility-result.json. No new kernel CI needed.
- Corrected minimal fixture adds /dev,private/tmp,var/log,SystemVersion;
  QEMU0005-v2 reaches Apple libignition "hello from launchd.1",platform2,
  ignition_level1, then expected DYLD namespace6/code1 missing libSystem/shared
  cache (fixture deliberately has none). Captured whole RAM console via HMP
  pmemsave with quoted path. qemu-launchd-compat-0005-v2/{console-ring.txt,
  compatibility-result.json}. Confirms Apple dyld entry, NOT full launchd/services.
- User returned FASTBOOT; known recovery temporarily booted exec6044,send1.427s,
  boot0.091s,total1.534s. Initial wait wrongly expected get-state=device; actual
  ADB state=recovery, so timed out though recovery was online. Corrected and
  resumed read-only preflight. Phone is root temporary recovery, not XNU now.
  Need volatile root-write layer (RAM COW) for launchd startup without raw UFS
  writes; currently planning/implementing, no phone data write authorized.
- PRIOR PHONE BOOT (superseded by new recovery above): exec1963 temporary fastboot boot SENT SUCCESSFULLY,
  46180KB send1.065s,boot0.092s,total1.169s,return0. Image0004 and payload
  hashes below. Immediately before reboot: fresh RO FIEMAP exactly equals
  staged182extents; LUN0 first1MiB exactly equals original backup; all persistent
  partitions unmounted,userdataRO1,temp<45C; exact private serial/product checked.
  Ignored evidence file-root-0001/boot.json + boot.log. Boot success here means
  fastboot accepted the temporary image, NOT proof XNU mounted HFS or launchd ran.
  Current XNU has no USB control/log return. Need user photo of final screen
  (especially POLARIS FILE ROOT, BSD root, hfs, launchd or panic). Do not reboot
  until evidence captured. No boot/recovery/GPT flash; existing Android+Windows
  preserved. This is a readonly16GiB first-stage root, NOT complete triple boot,
  64GiB installed system, SpringBoard or working apps.
- USER-AUTHORIZED MINIMAL REPAIR COMPLETE (exec52177). Whole phone userdata
  SHA matched original verified backup: b1af42b854345e101854dcccab182928512c9f749542da89fc1100aa2303dd97
  (115167178752bytes,526.2s with tested ARM SHA2 helper). Applied exactly
  e2fsck -f -y -E fixes_only: exit1; journal orphan cleanup, two malformed
  empty orphan entries, free counters and quotas corrected, consistent with
  host-clone experiment. Subsequent -f -n -E fixes_only: exit0, all five passes,
  no outstanding warnings/repair requests. Header clean(state1),needs_recovery
  cleared; block RO restored, all persistent partitions unmounted,37C.
  Private evidence research/polaris/userdata-repair-0001/result.json and logs.
  IMPORTANT: use adb shell for remote fsck exit status; adb exec-out can return
  transport0 despite failed remote command. Prior read-only logs were NOT clean.
  User approval applies only to this completed minimal repair, not formatting.
  Image staging and read-only XNU driver now complete; hardware result awaited.
  Final64GiB layout, writes/data overlay, GUI/apps and triple-boot menu pending.
  Earlier “not authorized/no phone writes” paragraphs below are historical.
- New read-only file-root implementation0803 committed f0b30fd and pushed;
  CI39965897634/job120455570100 SUCCESS. Kernel downloaded to
  xnu/out-polaris-0004/kernel.development.sweet; ZIP CRC/profile/commit/SHA
  verified:7ab50370045b23b1a5c27fa4985f61e9d398384dfb23033fe070b4bb5ab2bb04.
  Artifact12506739001,60270259bytes; ci-39965897634.log saved;0803 applied.
  Implementation: explicit polarisfileroot=1,
  exact DT geometry, contiguous logical FIEMAP coverage/no physical overlap,
  bounded per-extent READ(10), hard rejection of all write commands, GPT head
  CRC plus independent userdata bounds validation, first/last image block CRC
  and HFSX geometry checks. Timeout latches further I/O off, retains DMA.
  No topaz input/USB/persistent logger startup. Default RAM path unchanged.
  tools/polaris_file_root.py builds private metadata, mkadt-polaris supports it.
  ASan/UBSan actual C map/GPT/CDB tests and manifest/ADT roundtrip PASS;
  original probe allowlist and ADT tests PASS. Patch dry-run and kernel CI PASS. QEMU RAM and negative metadata checks PASS;
  actual file-root result awaited; do not claim Apple launchd/GUI success.
- tools/polaris-sha256.c uses attributed public-domain ARM SHA2 compression;
  static aarch64-musl build,12 phone vectors against hashlib PASS (empty,abc,
  padding/block boundaries,1MiB and1MiB+7). Read-only/O_NOFOLLOW source;
  block devices require runtime RO and exact full size. Full userdata hash
  succeeded. CPU limits restored to1056000 after repair,37C.
- New kernel QEMU RAM regression exec46493 PASS150s: PID1/heartbeats,
  no panic observed,0unknown glyphs. qemu-file-root-0004-ram/. Initial attempt
  exec31907 never started QEMU (sandbox denied local monitor socket); preserved
  separately in *-sandbox-refused, rerun with socket permission succeeded.
  Negative missing-map test:30s snapshot too early (CPU init), extended run
  exec14660; QMP physical RAM console ring shows explicit
  POLARIS FILE ROOT: REFUSED metadata; no MMIO, followed by expected
  IOFindBSDRoot: SWEET UFS root ufsroot0 unavailable:22 panic. This is an
  intentional negative test, not a successful boot or regression failure.
  qemu-file-root-0004-refuse-long/{console-ring.txt,negative-check.json}.
  Hardware temporary boot now sent; see latest phone state at top.
  Phone payload file-root-0001/phone-payload.bin SHA256
  286d3a832f1fc403b2bd7f918dea4e30e3db797911826776c76209f149d66adc;
  actual freestanding C loader validator PASS. Packaged temp image
  shim/out/polaris-xnu-file-root-0004/polaris-xnu-file-root-0004.img,
  47288320bytes,SHA0f57ba516ed169b6dc630b9e7ea7d5c2f6387a40563559314d5bb381f0ffbd98.
  No RAM root in phone payload; rd=ufsroot0 polarisfileroot=1 ufsrw=0 rootrw=0
  sweetlog=0. File-root init never starts unrelated topaz input/USB/log drivers.
  Private boot-file-root-0004.py checks QEMU evidence, artifact SHA, freshRO
  FIEMAP equality and GPT-head byte equality before temporary fastboot boot.
- Independent16GiB image STAGED AND VERIFIED on phone (exec48672 exit0):
  /polaris-ios/root-20H392-v1.img,17179869184bytes, SHA256 matches host
  689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b.
  New parent root0:0/0700, no fscrypt policy; file0600. ADB copy503.115s,
  32.6MB/s. RO FIEMAP182extents, all allocated/unencrypted/bounded; actual C
  validator accepts real GPT/map. Outer ext4 -fn -E fixes_only exit0, clean
  log. Unmounted/runtimeRO1,38C; remaining FS available74996064256bytes.
  Private file-root-0001/staging.json=staging_verified,extents.json,manifest.json,
  actual-c-map-validation.json,after-staging-fsck.log; phone.adt11260bytes.
  No Android boot or writable remount since mapping. Re-export if either occurs.
  First attempts exited during RO preflight (missing/not-executable tmpfs tool),
  before any copy; known inspectors pushed/chmod700 then success. No overwrite
  of an existing file, GPT/Windows untouched. Final64GiB capacity still pending;
  this16GiB root establishes the read-only Apple-userspace boot path first.
- **Hardware UFS read VERIFIED by latest user photo**: repeated
  POLARIS UFS RESULT: MATCH CRC32 91045173 expected 91045173;
  POLARIS UFS QUEUE: restored (no new I/O), plus live init heartbeats.
  The bounded LUN0 LBA0/count256 read (1MiB,4KiB blocks) matches the initial
  backup CRC and GPT signatures. Repeated display reports saved outcome,
  NOT repeated disk reads. Evidence ignored/private xnu-ufs-probe-0003/
  hardware-ufs-match.jpg and hardware-result.json. Hardware UFS transport
  works for this one bounded range; no iOS root/GUI/general-write validation.
- Next: read-only filesystem inspection for a data-preserving image-file
  placement, since no64GiB unallocated partition exists. No shrink/format/GPT
  or userdata erasure permission. Must verify encryption, space, file extent
  stability and boot-time validation before considering any file-backed disk.
  User returned FASTBOOT; known backup recovery temporarily booted exec37245
  send61896KB1.442s,boot0.091s,total1.546s; root ADB returned. Logs under
  research/polaris/root-placement-0001/. Phone now headless recovery34C,
  CPU max1056000kHz; userdata UNMOUNTED and runtime blockdev RO=1. No phone
  writes. Host root image complete; no sudo rebuild needed.
- Read-only filesystem inspection: userdata115167178752bytes,ext4/4KiB,
  INCOMPAT10046,needs_recovery=true (journal replay required). Set block RO=1
  BEFORE mount ro,noload,nodev,nosuid,noexec. No journal replay on phone.
  C inspector tools/polaris-fs-inspect.c cross-compiled aarch64-linux-musl
  with Zig -Wall -Wextra -Werror; binary pushed only to /dev (tmpfs).
  FS_IOC_GETFLAGS + GET_ENCRYPTION_POLICY confirm root inode2 NOT encrypted,
  ENODATA/no policy; /local IS encrypted (flags80800,policy ioctl success).
  Do not place raw-readable iOS image in /data/local/tmp. statvfs available
  92165570560bytes; df gives different reserved-space view. Initial lsattr
  did not display encryption and /local/tmp lookup failed; use ioctl evidence.
  Unmounted after inspection; first4096bytes match preinspection exactly.
- Host backup reconstruction COMPLETE: initial exec42818 stopped at8GiB reserve;
  macOS subsequently reported287GiB free. Resumed exec66870 rehashed all22
  completed chunks from disk, decoded remaining5 and verified115167178752bytes,
  SHAb1af42b854345e101854dcccab182928512c9f749542da89fc1100aa2303dd97.
  userdata-workcopy.img is0400,63,681,003,520 allocated bytes; original gzip
  backups untouched. No duplicate reconstruction needed.
- Installed host e2fsprogs1.47.4; APFS clonefile copies only for experiments:
  journal-only exit0 then full read-only check exit4 (exec87476); normal preen
  exit4 (unexpected orphan-chain inconsistency); unrestricted host-clone fix
  exit1 then read-only check0 (exec76607). Finally MINIMAL host clone
  `e2fsck -f -y -E fixes_only` exit1, subsequent `-fn` exit0 (exec72764).
  Evidence root-placement-0001/offline-fixes-only.json and minimal-*.log.
  Fixes_only skips extent-tree optimization. Journal replay clears3 ordinary
  orphaned inodes;2 additional malformed orphan entries (3711784,4710489)
  have links0,size0,blocks0; fixes empty orphan metadata, free block/inode
  counters and quota accounting. No claim of application-level data recovery.
  Phone remains UNMOUNTED, blockdev RO=1,34C, no filesystem repairs/writes.
  **Do not silently apply any host repair to phone. User has not approved it.**
- New tools/polaris-file-extents.c + polaris-extent-policy.h inspect only a
  regular allocated unencrypted image on readonly ext4. Reject unknown flags,
  holes, delayed/unwritten/encoded/shared extents, overflow and physical overlap.
  statvfs blocks EXCLUDE ext4 overhead; bound physical ranges using exact
  mounted device sysfs size instead. No sync ioctl, no mounts/raw writes.
  Native ASan/UBSan boundary tests PASS; aarch64-musl Zig cross-compile PASS.
  Phone RAM-only32MiB ext4 fixture exec37583 PASS: exported8KiB file mapping
  reconstructs exact host fixture bytes, sparse and tmpfs inputs refused;
  readonly loop detached and userdata RO rechecked. First fixture run passed
  mapping but redundant loop detach returned ENXIO (umount auto-released it);
  verified no loop/mount remained, fixed cleanup and reran successfully.
  Evidence extent-fixture-0001/hardware-result.json. Never treat FIEMAP snapshot
  as persistent write permission; phone iOS file not created.
- Static phone e2fsck1.47.4 BUILD SUCCESS (exec8821 configure0/build0).
  Binary research/host-tools/e2fsprogs-polaris-build/e2fsck/e2fsck,
  SHAc0f15d9832a098adab25bd858907605ad432b9f777d83e0e9f4cb8cd02bf0c94.
  Official source SHA2cec05f39c20ee621f14926195664e66e6017190ac8e4bbdb16d86082e43c5da
  checked against Homebrew formula. ARM64 ELF static/no interpreter checked.
  Build/configure in that ignored directory; build-manifest.json records identity.
  Zig conftest calls from build cwd stalled; compiler wrapper normalizes path
  arguments and runs from repository root, after which configure/build succeeded.
  No claim of a diagnosed Zig root cause. Obsolete probe processes stopped.
- Phone RAM fixture exec47648 PASS: intentionally bad inode refcount + free
  counter detected by -fn (exit4, SHA unchanged), -fy -E fixes_only repaired
  (exit1), -fn then0; synthetic file content unchanged. Original counter-only
  fixture returned0 despite a warning: **do not judge cleanliness by exit alone**.
  Evidence extent-fixture-0001/phone-fsck-result.json,phone-fsck-*.log.
  Actual userdata READ-ONLY inspection exec34069: exit0 but journal skipped
  and logs DO report corrupt orphan list, bitmap/count/xattr/quota differences.
  This is NOT clean: pending journal can explain some differences; host-clone
  replay still leaves the two empty orphan entries and accounting errors above.
  Header4096bytes unchanged, block RO1, all persistent volumes unmounted,35C.
  root-placement-0001/phone-readonly-fsck.{json,log}. No phone repair performed.
- Minimal repair proposal prepared in ignored root-placement-0001/
  repair-proposal.json: exact device + full partition SHA recheck against
  verified backup before any write; `e2fsck -f -y -E fixes_only` ONLY userdata,
  then read-only check/log review and restore runtime RO. No format/shrink/GPT,
  Windows/bootloader writes or extent optimization. User confirmation REQUIRED
  before applying to phone; original request preserves all data. Host experiment
  passes but cannot promise application-level integrity or zero risk.
- Commits1e586ce (UFS hardware evidence + directory inspector) and7202b7a
  (extent inspector + offline checks) pushed to origin/codex/polaris-preflight.
  Additional backing-device RO check added to inspector and verified again
  on phone RAM fixture exec96906 (PASS). iOS file not yet placed on phone;
  general UFS root/file mapping driver, Apple userspace, GUI/apps still pending.
- Prior0002 photo showed only queue restored and PID1; its CRC was unobserved.
  That ambiguity is now resolved by0003, not by reinterpreting old evidence.
- Added0802 retained-report overlay: save CRC/error/refusal and queue status;
  completed CPU startup thread prints saved report every10s using IOSleep,
  only when explicit polarisufsprobe=1 was accepted. No repeated UFS requests
  or register reads in reporter; original command allowlist unchanged. Patch
  dry-run PASS and existing policy/ADT tests5 PASS. Commitcdd0fb0 pushed;
  CI39948294850 SUCCESS,job120396248096. Kernel downloaded and CRC/SHA
  f632d230c4fcea02a6c9c071a24e197625c8a130ee5f60f30cee6d4f00fa595a verified,
  xnu/out-polaris-0003/kernel.development.sweet; build log saved. User returned
  FASTBOOT; exact device confirmed. QEMU exec10775 PASS150s,exit0 with
  polarisufsprobe=1 but no hardware probe ADT node: repeated REFUSED metadata
  + queue not taken + PID1/heartbeats,0unknown glyphs,no panic observed.
  Evidence qemu-ufs-report-0003/.
  Phone payload ea299dd93ced0903bf7da884894d085d52a3445fa24887c0a49b12605f88ae3a,
  actual C validator PASS. Image temporary boot SENT (never flashed):
  shim/out/polaris-xnu-ufs-probe-0003/polaris-xnu-ufs-probe-0003.img,
  47280128bytes,SHA40584739a6bcea233bf72c735216bbc10d60c1b1e09ffe100f635db6c739c5ec.
  Exec10998 exit0,send46172KB1.073s,boot0.091s,total1.173s.
  research/polaris/xnu-ufs-probe-0003/{boot.log,boot.json}. Hardware MATCH
  observed in latest photo; see above. Phone on temporary XNU pending user
  return to FASTBOOT; no USB control/logging.
  Kernel artifact12499616895,60261462bytes; logsci-39948294850.log.
  Local root image remains verified; no user sudo/rebuild needed.

- User requires real home screen/apps and preservation of Android + Windows.
  Full iOS/triple boot is NOT complete. No partition/GPT/format/flash changes.
  Original sweet's home screen/app failures are not polaris validation.
- **Mac root image BUILD SUCCESS**, privileged exec68967 exit0. User authorized
  agent-run local administrator authentication; no credentials saved in repo.
  research/polaris/ios16-root-20H392-macos-v1.img,17179869184bytes,
  SHA256689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b.
  Same-stem JSON complete=true; launchd/dyld/SystemVersion content hashes,
  root ownership/modes verified. HFSX geometry16GiB, fsck_hfs read-only OK.
  Image detached, user-owned0600. DO NOT ask user to rebuild/run sudo again.
  Root tweaks warn mobileactivationd container absent/data ark skipped.
  Apple launchd/SpringBoard/apps NOT tested by this host-image verification.
- Initial root build failed before copy: -format UDRW invalid for blank image.
  Fixed -type UDIF and fsck_hfs via read-only/nomount raw device (13da2b7).
  Empty failed directory preserved*.failed-create.build; 64MiB smoke PASS.
- **CI39944761112 SUCCESS**, job120384578742, commit49c69a642b1170d2f848eaacc9c04324114c8d5c.
  xnu/out-polaris-0002/kernel.development.sweet downloaded; ZIP CRC and SHA256
  d2028c1e22122b7d80bdaa88f5cc923160269d5aa44a7a69954c595d9a1ea5ef PASS.
  Explicit -R liukaixiang817/ios-topaz required for gh (default resolves upstream).
  Artifact12498490081 (60255768bytes), buildtree12497473676; buildtree NOT downloaded.
  Logs research/polaris/ci-39944761112.log. Slow full downloadexec20464 stopped;
  download-ci-kernel-0002.py ranges exec10951 completed. Kernel symbol
  _polaris_ufs_probe confirmed; policy tests5 PASS (actual C under ASan/UBSan,
  exhaustive single-byte CDB mutations, CRC vector, ADT checks).
- New0801 opt-in probe requires polarisufsprobe=1 AND /polaris-ufs-probe exact
  reg1d84000+2500 and backup-head CRC metadata. After CPU startup it permits
  only LUN0 TUR + READ10 LBA0/count256 (1MiB), before any descriptor/doorbell.
  WRITE/UNMAP/SYNC/other ranges rejected even with ufsrw. Checks response
  tag/residual, GPT signatures, CRC; restores old idle queue on completion,
  retains permanent DMA/queue on timeout without reset/abort. Normal UFS root
  remains ENXIO, no BSD disk/mount/persistent log/input/USB startup. The0003
  hardware test now verifies transport for the allocated DMA and1MiB read;
  this is not proof for arbitrary allocations, ranges or write commands.
- Earlier read-only Linux handoff snapshot succeeded (commit8246b44):
  research/polaris/ufs-handoff-0001/{registers.bin,registers.json,boot.log}.
  CAP1587031f (64-bit DMA),VER210,HCS10f,HCE1,IS400,IE0,
  UTRLBA9b9ef000/upper0,DBR0,RSR1,UTMRLDBR0/RSR0. Host/link enabled and idle;
  does not prove XNU transport. Current LUN0 first1MiB matches original
  backup byte-for-byte; private ufs-head-current-check.json records it.
- Before latest boot phone root ADB temporary headless recovery,36C, all
  persistent partitions unmounted. QEMU default/no-probe exec46256 reached
  PID1/heartbeats but PANICKED on interrupt hygiene at~104s guest time:
  handler14.51ms >13.631488ms threshold. Evidence qemu-ufs-kernel-0002/.
  Apple original machine_routines_common.c:893 confirms timing assertion.
  Host scheduling/IO delay is a hypothesis, not proven. SAME kernel/payload
  idle-host repeat exec94256 exit0,150s,qemu-ufs-kernel-0002-idle/: PID1 and
  23 still-alive lines,0unknown glyphs,no panic observed. No timeout guards
  disabled or kernel patch made. Both results retained; initial failure not
  silently discarded. Original issue was after userspace, no UFS probe enabled.
- Hardware probe payload prepared research/polaris/ufs-probe-phone-0002.bin,
  SHA55de6f04e1d5092f41836121ecc55768c4483bcf15170708567bec364850e4b8.
  Actual C copy validator PASS entry18149a488,args182518000,top18251c000.
  Temporary image shim/out/polaris-xnu-ufs-probe-0002/polaris-xnu-ufs-probe-0002.img,
  47280128bytes,SHA7eb804d68b15829a998f5768e1c80c318fa774128d7608c01adc44c8a7f4565f.
  **Temporary fastboot boot SENT**, exec80317 exit0; same device identity,
  image SHA and no persistent mounts rechecked before automatic adb reboot.
  send46172KB OKAY1.081s,bootOKAY0.091s,total1.184s. Private records
  research/polaris/xnu-ufs-probe-0002/{boot.log,boot.json}. No flashing.
  User photo received: queue restored and PID1, but CRC line not visible;
  see latest observation above. No CRC result confirmed. Current XNU has no USB logs/control;
  may require physical buttons after observation. Do not claim UFS success
  or ask user to run the completed Mac root build again.
- Root transport/persistent file storage and eventual64GiB layout unresolved.
  Userdata backup superblock is ext4,4KiB,INCOMPAT10046 (encryption supported).
  Do NOT infer an unencrypted image file path or erase userdata. No partition
  shrinking/GPT edits/format authorized. Preserve all verified OS/critical backups.

### Confirmed XNU synthetic PID1 hardware milestone

- **Hardware userspace milestone CONFIRMED by user photographs**. Second
  photo shows `BSD root: md0`, `/sbin/launchd` load attempt, explicit
  `*** SWEET userspace: init running as PID 1 ***` and many repeated
  `SWEET init: still alive` lines. This is the static test init from
  tools/sweet-init.S (served by mockfs), NOT Apple's launchd or an iOS GUI.
- First photo showed CPU/VM initialization and last line `1/1 CPUs initialized,
  SGI1 verified`; it was intermediate progress. **Do not diagnose a timer
  hang from that earlier photo**: later photo proves progress to userspace.
  No timer workaround or new kernel build was started for that hypothesis.
- Proven hardware stack: bounded loader, polaris CI kernel39933084495
  (30a8a750...eda2b6), phone ADT/payloadc7984033..., RAM md0, user-mode
  syscalls/devfs console and repeated select-based heartbeat. Single CPU.
  Build/image identity and send logs are in the launch details below.
- Private evidence saved (ignored, photos0600) at research/polaris/xnu-ram-0001/
  hardware-bootstrap.jpg,hardware-pid1.jpg,hardware-result.json. Keep out of git.
- Phone currently running this RAM-only XNU test; **no ADB USB stack in XNU**,
  no pending user-action question. It can remain in test loop; eventual return
  to FASTBOOT requires physical Power+VolumeDown. Do not assume USB can reboot it.
- Next substantive work: establish a read-only SDM845 UFS path and/or verified
  root image transport, build ownership-correct iOS root on host, then bring
  up Apple userspace. Touch/power/graphics service drivers remain unported.
  Existing sweet/topaz MMIO must not be reused unreviewed. The polaris kernel
  currently explicitly returns ENXIO before UFS controller access, no UFS DT node.
- Full iOS/triple boot is **not complete**. No partition resize/GPT edit/format,
  filesystem writes or installation performed; all five OS backups remain.
  User's data-preserving requirement still controls; no destructive permission.

### First XNU RAM boot packaging and launch details

- Automatic raw entry-register capture is committed/pushed **a878ce8**;
  real CPU EL1/16KiB support now established (details below).
- Added package-polaris-ram-boot.py: hash-pinned known recovery supplies
  gzip+unchanged65compiledDTBs, boot-v0 options and text_offset80000. Verifies
  exact packed kernel/ramdisk and gzip roundtrip. No phone commands in tool.
- Diagnostic0002 uses same diagnostic code as0001; only packaging changed.
  shim/out/polaris-probe-0002/polaris-probe-0002.img,30380032bytes,
  SHA7fb2d9812c88676ac5d79fb9531131a6bbd93f04350ef06890a309f0af44dc94.
  New exact Image passed QEMU matching/wrong-board cases,0exceptions;
  evidence research/polaris/qemu-probe-0002/. Host syntax/diff checks pass.
- **Temporary hardware boot sent**: exec81270 exited0,29668KB sendOKAY0.693s,
  bootOKAY0.091s,total0.792s. research/polaris/probe-0002-boot.log.
  **User confirmed diagnostic text is visible**. This establishes execution
  and framebuffer output for the gzip/compiled-DTB packaging. The first raw
  image black screen cause is not isolated (several packaging fields changed).
  User then entered FASTBOOT as requested. Identity matched original backup.
  Diagnostic display milestone committed433f96d.
- RAM-only XNU boot image **sent via temporary fastboot boot**:
  shim/out/polaris-xnu-ram-0001/polaris-xnu-ram-0001.img,47280128bytes,
  SHAb0d3cf98d0093d19c95f7d55d734d15b05238304b7e20e892b561e8d355fcd32.
  Contains bounded loader plus phone-specific validated payloadc7984033...
  and known DTB table; no storage support in polaris XNU. Image/payload/CI
  kernel SHA256 rechecked and match. Exec51585 exited0: send46172KB
  OKAY1.069s,bootOKAY0.091s,total1.171s. Logs under ignored
  research/polaris/xnu-ram-0001/{boot.log,boot.json}.
  User photographs subsequently confirm hardware PID1 and repeated
  still-alive heartbeats; see current milestone above.
  No iOS root or GUI installed. Latest packaging commit e8aba2b pushed.

### Automatic hardware register capture succeeded

- Standalone diagnostic0001 fastboot send560KB/boot both OKAY (0.110s), but
  **user saw black screen**. No execution/framebuffer proof from that attempt.
  User held Power+VolumeDown; known backup recovery temporarily booted again
  (61896KB,1.545s), root ADB returned. Pstore mounted empty, no last_kmsg;
  recovery lacks /dev/mem and exposes only MIDR/REVIDR in sysfs. Data unmounted.
- Implemented **Linux entry wrapper** for automatic register capture. Source
  recovery is pinned SHAf9ad6529..., original gzip kernel+65DTBs preserved
  except entry branch/Image size; adds12KiB wrapper after original image_size
  and112-byte /chosen/polaris,boot-registers property to each tree. Wrapper
  records read-only CPU registers into RAM FDT, resumes original Linux branch
  at offset0x1d80000. Same headless ramdisk, boot options/OS header preserved.
- New tools build-polaris-linux-probe.py / qemu-polaris-linux-probe.py and
  shim/polaris/linux-probe.{S,c}. QEMU3 cases PASS: valid register capture;
  wrong board and bad marker no FDT writes; original entry and x0..x3/SP
  preserved;0exceptions. python compile/diff checks pass. No kernel CI needed.
- **Actual hardware automatic roundtrip SUCCESS** (exec94392 exited0):
  shim/out/polaris-linux-probe-0001/polaris-linux-probe-0001.img,
  63397888bytes,SHA799fb4447515428351d68378f19b3bdc37f3640aaf19a618d89f63540b071ea0.
  fastboot send61912KB/boot OKAY,total1.540s; root ADB returned automatically.
  research/polaris/linux-probe-0001/{boot.log,registers.bin,registers.json}.
  Raw **EL4 (EL1),MIDR517f803c,MPIDR81000000,MMFR0101122,MMFR110212122,
  PFR011112222,SCTLRc00800,CNTFRQ124f800 (19.2MHz),DTB841c0000,DAIF1c0**.
  Record completion1. TGran16=1 confirmed; MMU/DC off; CPU affinity0.
- Phone NOW in instrumented temporary headless recovery, root ADB. Last37C,
  all persistent filesystems unmounted; CPU max1056000kHz reapplied runtime.
  No user action currently pending. User requests maximum unattended work.
- Next: resolve standalone raw-Image black screen/container/display and build
  a bounded RAM-only XNU hardware image using the proven gzip+DTB packaging.
  Do not infer working display from register capture. No XNU phone boot yet.
- Phone-specific host payload validated (NOT hardware booted/packaged):
  shim/out/polaris-ram-loader/payload-phone-0001.bin,16903360bytes,
  SHAc79840337f8e39d1d1fc5e7a02d6f4c26f4f2987e2c5575f2a5bb2f74559bcf6.
  Actual C validator PASS, embedded hardware GIC17a00000/17a60000,timer19,
  19.2MHz checked; no UFS node. Entry18149a488,args182518000,top18251c000.
  Synthetic RAM init only, NOT Apple launchd/iOS; never use QEMU ADT on phone.
- All5 full/critical backups remain verified, no persistent partition writes,
  GPT/resize/format/iOS install. Previous handoff commitdb91249.

### Previous backup completion / cooldown handoff

- **ALL5 full partition backups verified**; userdata exec91104 exited0:
  backup/polaris-full-userdata-20261023-203417/,115167178752raw,
  21389839339compressed, rawSHA256
  **b1af42b854345e101854dcccab182928512c9f749542da89fc1100aa2303dd97**,
  elapsed2310s. Source hash PID1216 finished; no backup process still needed.
- Recovery index **backup/polaris-recovery-index-20261023.json** (ignored,0600)
  includes all5 full manifests plus both critical snapshot manifests. Full
  partitions combined236.78GiBraw/52.46GiBcompressed. Chunk filenames/lengths
  rechecked; all promoted from.partial. system/vendor/cust sourceSHA:
  system d68d9360f573472ad9aaa3a614025d862536d83eab8a547308b8b25f7465ed79
  vendor af8db49c6e7a3573664582cb10f8f495f082150ddcdbfb2343be54e817560b3b
  cust68af470a48607f9a0e98c381795df293151c229283c112830cb04b033f107ea9.
- Phone still in custom temporary root-ADB recovery (never flashed). Last
  measured battery500 (=50C), charging85%; clocks capped1056000kHz runtime.
  **Asked user via async to unplug USB, ventilate/cool, then reconnect and
  reply “已接回”. Awaiting response.** Do not assume unplug/reconnect happened.
  All backups are now complete so unplugging/rebooting no longer interrupts
  a backup. Read temperature after reconnect before the next experiment.
- Next phone action after cooling: temporary fastboot boot diagnostic0001,
  shim/out/polaris-probe-0001/polaris-probe-0001.img, SHA256
  4fb6d76f1cc335caaccae71c86d664fbb26046680c9d89ac22c30f80c1d5611a.
  Bind adb/fastboot to the one same phone without serial in git. Send/boot
  OKAY establishes only ABL acceptance; require user physical screen report
  of EL/MIDR/MPIDR/MMFR0/CNTFRQ. Probe has no storage/power driver and parks;
  no ADB expected. User may need hold Power+VolDown to return fastboot.
- Kernel CI39933084495+direct/integrated QEMU PID1 proven; commits **3fcc754**
  (actual-shim integration), **05999ab** (earlier QEMU evidence), f9c74f7
  (offline coverage), a2fa680(loader),242c910(QEMUvideo). Branch pushed through
  3fcc754; no duplicate CI from notes/shim-only pushes. No XNU hardware boot.
- No GPT edit, filesystem resize/format, root flash or iOS installation yet.
  Android/Windows retain their partitions. No destructive step authorized.
- Apple sources remain readonly mounts per attachment records; ownership test
  image is detached. True iOS root build remains pending root-preserving copy
  and driver bring-up. Computer Use manifest exists but tools/skill not loaded
  this turn; no desktop operation performed. GitHub issue solved through CLI.

### Integrated shim+XNU QEMU result

- Exec43952 completed0: actual polaris shim cold-loads the verified polaris
  XNU+RAM init, reaches PID1 and repeated heartbeats,150seconds,no visible
  panic,0unknown glyphs. result.json actual_shim=true. No host kernel segment
  preloading in this mode. Evidence research/polaris/qemu-xnu-loader-0001/.
- tools/qemu-sweet.py new integration flags validated by actual execution;
  ABI unit test still passes. No XNU phone packaging/boot attempted yet.

### Backup/thermal update ~21:10 local

- system/vendor/cust all fully verified (exec37168 exited0); manifests under
  backup/polaris-full-system-20261023-205755/, vendor-20261023-210355/,
  cust-20261023-210608/. userdata1216 still source-hashing,~93.85GB of115.17GB
  read,0writebytes. Wait for exec91104 final VERIFIED before reboot.
- Battery observed85%, temp520 (=52C), charging. Both cpufreq governors were
  performance. Runtime-only maximum reduced to supported1056000kHz on cpu0
  andcpu4 clusters to cool during remaining verification; minfreq300000/825600.
  This is sysfs runtime tuning, no persistent partition write. User told keep
  USB attached and place phone somewhere ventilated. Wait for cooldown before
  a hardware experiment. Record actual next temperature; do not assume cooled.
- Apple sources remain3 read-only mounts (recorded above). Small local HFS
  ownership test created research/polaris/ownership-test.dmg: hdiutil from
  folder under ordinary user maps source root owner0:0 to501:20 even with
  -anyowners; do NOT use that result for iOS root. Test image detached. A real
  Mac root-image builder needs privileged ownership-preserving copy (or other
  verified implementation). No root image built yet; no sudo requested yet.
- tools/qemu-sweet.py adds optional --loader-image + --linux-dtb (polaris only)
  to test actual shim cold-RAM copy/handoff; no host kernel RAM load in this
  mode. Integrated run exec43952 in research/polaris/qemu-xnu-loader-0001,
  same verified kernel/QEMU ADT/init; running150seconds. Source Linux FDT is
  verified Android live.dtb with only chosen initrd-start/end edited by fdtput
  for0x84000000..0x8501ecc0. Not a phone boot. Result still pending.

### XNU QEMU userspace milestone ~21:05 local

- Kernel **downloaded + ZIP CRC + SHA256 VERIFIED**, 17485224bytes,
  xnu/out-polaris-0001/kernel.development.sweet, expected30a8a750...eda2b6.
  8x256KiB HTTP range fetching completed; generic60MB downloads unnecessary.
  CI log saved research/polaris/ci-39933084495.log (27MB), confirms overlay
  applied and POLARIS_RAM_ONLY/cortex-a75 compiler flags. No buildtree yet.
- Mach-O arm64, cpusub0, entryVAfffffe000749a488. Disassembly of exported
  sweet_ufs_rootdev: calls printf, returns6 (ENXIO), no MMIO. Static init/open
  helpers optimized away. Use CLT llvm-objdump --disassemble-symbols (without
  --macho); LLDB crashes in CTF symbol reader on this kernel (host tool bug).
- **Actual polaris XNU reaches userspace PID1 in QEMU**,150seconds,
  research/polaris/qemu-xnu-0001/{fb.png,fb.txt,regs.txt,qemu.log,result.json}.
  Screen shows BSD root md0, init runningPID1 and repeated5second heartbeats;
  exact glyph decoder0 unknown, no visible panic. QEMU log has6 Data Aborts
  (ordinary VM faults possible),0 Undefined Instructions; do NOT call the
  XNU log exception-free. This is synthetic static init, not Apple launchd/UI.
- First QEMU attempt was sandbox-denied Unix monitor socket and exited1;
  rerun with escalation completed successfully. Emulator only, no phone I/O.
- Actual payload payload-qemu-0001.bin also passes the real C loader validator:
  physbase180000000, entryPA18149a488, bootargs182518000, top18251c000;
  RAM init at18250c000+8000. No integrated real-shim+XNU test or hardware XNU yet.
- **system full backup verified**: backup/polaris-full-system-20261023-205755/.
  vendor now running, then cust (exec37168). userdata sourceSHA still running
  (exec91104), last observed~69GB of115GB read,0writebytes; do not reboot.
- Apple OS/SystemOS/AppOS all downloaded, ZIP CRC + BuildManifestSHA384 pass.
  Mac hdiutil can read them; all3 attached **read-only** for local root prep:
  research/ipsw-x/{mount-os,mount-systemos,mount-appos}. Attachment records:
  research/ipsw-x/*-attachment.plist and active-attachments.json. Current base
  devices disk6 (OS),disk8(SystemOS),disk10(AppOS); detach ONLY using recorded
  image identity, never assume IDs remain constant. No copy/edits made yet.
- Removed ONLY old interrupted Windows partial7757365248bytes at
  backup/polaris-full-mindowswin-20261023-194150/ after verified Windows hash
  checked; that directory contained only the incomplete partial. All verified
  backups remain intact. Critical incomplete earlier small dumps remain.

### First XNU CI success / offline backup milestone ~20:55 local

- **CI39933084495 SUCCESS**, actual Build completed09:46:57UTC,
  job completed09:47:19UTC. Commit b50a106; profile artifact says
  target_platform=polaris, machine_config=SWEET. Kernel expected SHA256
  **30a8a7502adb35d6d1d6b4dbdf54b2d7b4864fbce39cb203cfa6d7de60eda2b6**,
  17485224 bytes raw,6576057 compressed. Not downloaded/verified yet.
- GitHub Azure artifact transport is extremely slow. Kernel artifact12493370896
  is60MB, mostly a53MB compressed link archive; only kernel+hash+profile needed.
  Official signed HTTP ranges obtained SHA256SUMS and build-profile.txt with
  ZIP CRC checks. Exec49464 runs ignored research/polaris/download-ci-kernel.py
  with8 parallel256KiB ranges and final CRC+SHA check. Do not print signed URLs
  or credential-bearing exceptions. Full redundant downloads were SIGINTed.
  Old exec3349 gh run-view --log may still be fetching logs (0bytes last check).
- Android userdata **all27 chunks received and gzip/length checked**; exec91104
  now computing source SHA-256 on phone after local concatenated digest.
  Do NOT reboot until final VERIFIED. Need retain current offline state.
- New offline critical collection **backup/polaris-20261023-205328/**:
  **38 files,934958000 bytes**, all local hashes and fresh phone hashes pass.
  Adds keystore/ssd/frp/fsg/vbmeta/keymaster_a/b/tz_a/b. ALL12 GPT head/tail
  regions byte-identical to initial collection; common boot/recovery/firmware
  also match. live.dtb differs (TWRP vs Android); persist.img differs between
  earlier Android snapshot and offline snapshot. Preserve both. Timing/source
  of persist changes not proved; no persistent filesystems mounted in custom
  environment and no write command issued by our tools.
- tools/polaris-preflight.py now supports --su none for root recovery and adds
  the key-material partitions; full backup tool permits system/vendor/cust.
  Started sequential offline full backups of these3 to complement userdata.
- Apple CDN metadata extracted via remotezip, ZIP CRC checked. BuildManifest
  confirms16.7.16/20H392/d22ap. IM4P DeviceTree SHA384 matches manifest:
  e2574f463f5b5bbb45ba8c939e107865c27b4e5d06600cda77bfa033959ca88562045dd389a3a96afd6c9e7bad5dac94.
  compression_tool LZFSE decompress:186084-byte ADT, SHA256
  9e670987c80493bd69aba7be62e3179c04663324d9249b0973675baac175dbf1.
  /product has61 properties; regenerated polaris phone/QEMU ADTs6592bytes.
  Downloaded SystemOS+AppOS pass manifestSHA384; OS stilldownloadingexec36263.
  All Apple files ignored under research/ipsw-x, never commit.
- RAM init built from tools/sweet-init.S using Clang+mkinit.py,16635bytes,
  SHA256f5de3714ff95e6a3b9ece30723f677de0f3f74ec5eb985a00c5ae872f0ac9bf1.
  research/polaris/ram-init; for mockfs rd=md0 QEMU test when kernel is verified.
  No XNU QEMU or phone boot yet. Loader core committed **a2fa680** and pushed.

### RAM loader core milestone

- Commit `242c910` adds polaris QEMU framebuffer/boot_args geometry (22 tests).
- New separate `shim/polaris/{boot,loader,payload}.c`, payload.h implement the
  bounded v1 FDT-initrd handoff. Destination RAM must be exactly
  0x180000000+0xfc8a0000; payload source stays in lower bank, maximum128MiB;
  no magic scanning/embedded fallback. Validate every segment/ADT/boot_args
  bound and destination overlap before any copy, require entry in initialized
  bytes, CPU0/EL1/MMU+DC off and TGran16=1. No storage code linked.
- `tools/build-polaris-ram-loader.py` cross-compiles the core only (86016-byte
  Image, no Android boot packaging or kernel). All allocated C sections pass
  absolute-relocation audit. Preserve the earlier diagnostic0001 separately.
- **27 host tests pass**, including actual C validator truncation/overflow/
  overlap/source-bank cases. `tools/qemu-polaris-ram-loader.py` runs actual
  Image under Cortex-A76: valid-copy reaches synthetic parked entry
  0x180004000, checks9-byte copy+BSS clearing+upper-bank736-byte boot_args;
  malformed destination leaves entire first64KiB destination unchanged.
  Both cases have no QEMU exceptions/invalid accesses. Results under ignored
  `research/polaris/qemu-ram-loader/result.json`. This is **NOT an XNU boot**.
- CI39933084495 now observed in_progress, Build step; dependencies succeeded.
  userdata exec91104 continues; at last output16 of27 chunks passed (indices
  are completion-order, not contiguous). No phone restart during this backup.

### QEMU tooling milestone (before the first kernel result)

- `tools/qemu-sweet.py --platform polaris` uses 0x9d400000 /1080x2160/4320
  in boot_args, framebuffer dumps, PNG and glyph decoding. Original sweet
  defaults retained. --qemu and --nm support explicit host executable paths;
  nm uses -U -n, accepted by macOS and LLVM nm. Existing RAM sizing covers
  0x180000000+0xfc8a0000 (9GiB QEMU RAM starting at0x40000000).
- New ABI test checks actual packed boot_args, upper-bank physical pointers,
  segment bytes and entry stub literals; **22 host tests pass**. No actual
  polaris XNU QEMU run yet; awaiting the first CI kernel. Do not confuse the
  earlier standalone diagnostic QEMU result with XNU.

### Milestone update ~20:45 local

- First polaris XNU CI successfully registered by qualifying branch push.
  **Run 39933084495**, commit **b50a1063fe9d1734bc341d676c4689c0b0facb47**:
  https://github.com/liukaixiang817/ios-topaz/actions/runs/39933084495
  Observed queued, job120345897284. Branch event defaults target_platform to
  polaris, machine SWEET, macOS13.5, DEVELOPMENT; RAM-only overlay/UFS refused.
  Do not dispatch a duplicate. Registration issue resolved without browser.
- Offline userdata backup continues (exec91104); do not reboot. At early check
  1/27 chunks validated and ~3GB compressed received; ~52GiB immediate host free.
  No disk edits or iOS installation; kernel not built or booted yet.

### Milestone update ~20:40 local

- Temporary backup image sent with fastboot boot: sending 61896KB OKAY,
  booting OKAY, total 1.543s. **Live root ADB works**, device polaris; mountinfo
  contains only RAM/kernel/configfs/functionfs filesystems, no persistent block
  devices. userdata=sda22, Windows=sda24. No image was flashed.
- Full userdata backup is running in exec **91104**, output directory
  `backup/polaris-full-userdata-20261023-203417/` (115167178752 bytes,27 chunks).
  Do not reboot until final VERIFIED and source SHA comparison. Offline root
  mode uses --su none. Initial chunk passes gzip/length checks.
- User saw no fork-enable button and explicitly requested Computer Use.
  Plugin manifest exists but its local skills directory is empty, and no
  desktop-control tool is exposed in ALL_TOOLS, even after the plugin tag.
  Do not claim desktop interactions happened. Continue via gh.
- Actions permission API PUT enabled=true succeeds but workflows still empty.
  Default topaz has xnu.yml; its only push branch was main, so no qualifying
  push has registered a workflow in this new fork. Add a branch-specific push
  trigger for codex/polaris-preflight and default that branch to polaris;
  this is a registration attempt, not yet an observed successful run.

### Milestone update ~20:35 local

- Windows backup **VERIFIED**: `backup/polaris-full-mindowswin-20261023-195539/`,
  manifest verified=true, 128534437888 raw bytes, 31879606683 compressed bytes,
  raw SHA-256 **f0bef9ef67242a445a401eaf27d3f19328bedcb85e8ec97887a2162f37950d0a**.
  All 30 chunks pass gzip/length checks and concatenated SHA matches a fresh
  full phone-side SHA. Exec 1260 exited 0. Safe to leave Android for the next
  temporary backup environment; Android userdata remains NOT backed up yet.
- User completed gh login; repo ADMIN permission verified. Branch through
  `116435f` pushed to origin/codex/polaris-preflight. Actions permissions show
  enabled=true, but workflows list is empty despite xnu.yml on origin/topaz.
  Both workflow dispatch and enable-by-filename return 404. **No CI run yet.**
  Asked user to open repository /actions and enable fork workflows if prompted.
- Ready RAM-only backup recovery hash rechecked against f9ad6529...18bd99.
  Next: temporary fastboot boot (never flash), verify root ADB and no persistent
  block mounts, then start full userdata backup. No phone reboot yet at this
  milestone; no partition write/resize/format.

### Milestone update ~20:00 local (supersedes details below where different)

**Further update ~20:25 local:**
- **`08a3ca8`** adds CI `target_platform=polaris`, a profile stager, isolated
  `xnu/profiles/polaris/0800-polaris-ram-only-platform.patch`, and
  `tools/mkadt-polaris.py`. Stager chooses 79 sweet patches + 3 stage scripts +
  one overlay (83 files); excludes ALL topaz 0080+ drivers/assumptions. Machine
  config internally remains SWEET. `POLARIS_RAM_ONLY=1` returns ENXIO at the
  start of sweet_ufs_init, before DT lookup or MMIO. CPU/platform personalities
  use qcom,kryo385 / xiaomi,polaris. Compiler explicitly cortex-a75 ARMv8.2.
- Important console mapping detail: polaris framebuffer 0x9d400000 is NOT a
  32MiB block boundary. Keep early block descriptor PA **0x9c000000**, point
  early C pixels at 0x9d400000, stage-0 marker row2128, height2160, and relocate
  final VA to SWEET_EARLY_FB_VA + **0x1400000**. Last displayed byte fits in
  that block. Host tests cover bounds; not a hardware proof.
- Reconstructed relevant first-79-patch source files from Apple's
  xnu-8796.141.3 in `research/polaris/xnu-fixture/`; pre-overlay copies under
  `research/polaris/pre-kernel-profile/`. New overlay passes git apply --check
  against those source copies. No generated kernel headers/buildtree yet, so
  no single-file XNU compile or full kernel build yet. **No CI dispatched.**
- 21 host tests now pass. ADT 3904 bytes with no /product (Apple d22ap.adt not
  downloaded), 1 CPU0, no UFS/WLAN/display service nodes, RAM
  0x180000000+0xfc8a0000. Generated under shim/out/polaris-probe-0001/.
  Both bus/memory clock properties still compatibility placeholders; do not
  call them measurements. Linux CPU0 max actually 1766400kHz, MIDR sysfs
  **0x517f803c**. MMFR0 sysfs absent: still need real diagnostic observation.
- **`0798719`** adds `tools/build-polaris-backup-recovery.py` plus archive and
  init-policy tests. Official polaris TWRP downloaded to
  `research/polaris/twrp-3.7.0_9-0-polaris.img`, 63467520 bytes, official
  SHA-256 **54905f7abae89b345c4b1a03d12fe74c1ff06cf5aa41119f1a7228dc22765ea0**.
  Do not flash this source image or use its UI during raw backups.
- Ready custom temporary backup image:
  **shim/out/polaris-backup-recovery/polaris-backup-recovery.img**,
  63381504 bytes, SHA-256
  **f9ad6529c1632fa2116377ec5f12c78f6d5cf7f5a1baa0b0f1bec4b5a518bd99**.
  Header v0, original kernel unchanged. Only init.rc and regular prop.default
  changed; default.prop -> prop.default symlink preserved. Minimal init starts
  only /sbin/ueventd and /sbin/adbd, exports LD_LIBRARY_PATH=/sbin, root adbd,
  configfs/functionfs USB at a600000.dwc3; no UI/factoryreset/disk mounts/fsck.
  Reboot property handler retained. NOT booted yet. Need live root/USB and
  mountinfo verification before any userdata backup. Earlier hashes in tool
  logs from intermediate builder revisions are superseded by f9ad6529 above.
- Windows exec **1260**: all 30 chunks read, gzip/length checks pass, concatenated
  raw SHA-256 computed locally; currently computing **source SHA-256 on phone**.
  Still do NOT reboot until final VERIFIED line / manifest verified=true.
- Official gh 2.103.0 at
  research/host-tools/gh/gh_2.103.0_macOS_arm64/bin/gh; verified release checksum.
  No existing login. Asked user via async question to run gh auth login --web
  with their repo account; waiting for reply. Do not try to extract credentials
  or claim CI ran. After login, push branch and dispatch xnu.yml with
  target_platform=polaris, machine_config=SWEET, macos_version=13.5.
- User offered to operate phone if needed; told them no action needed during
  backup, keep USB attached and do not reboot/switch Windows. No phone restart
  has happened as of this update. No resize, filesystem edit or partition write.

- **`541cd86`**: standalone polaris CPU/FDT/framebuffer probe, builder and QEMU
  runner committed. 11 host tests pass. Actual probe executes in QEMU
  Cortex-A76 with FP/SIMD disabled; matching FDT draws expected screen and
  parks, wrong-board FDT leaves framebuffer untouched. Both have zero guest
  exceptions/invalid-memory logs. Screenshot and result:
  `research/polaris/qemu-probe/matching/fb.png`, `.../result.json`. This is CPU
  emulation, NOT a hardware boot or an iOS/XNU boot.
- Ready diagnostic **`shim/out/polaris-probe-0001/polaris-probe-0001.img`**,
  573440 bytes, SHA-256
  **`4fb6d76f1cc335caaccae71c86d664fbb26046680c9d89ac22c30f80c1d5611a`**.
  Linux Image `_end`/image_size = 81920, appended verified live DTB, empty cpio
  ramdisk; boot header v1 / 4096 pages / base 0 / kernel_offset 0x8000 /
  ramdisk_offset 0x1000000 / tags_offset 0x100 / OS field 0x1a00016c matches
  backed-up Android boot. No UFS/SCSI/loader/persistent-log/reset code linked.
  ABL acceptance and real scanout are **not tested**. No reboot yet.
- Build with Clang `-target aarch64-none-elf -mcpu=cortex-a53
  -mgeneral-regs-only`, and Zig 0.15.2 as linker. **Do not compile probe C with
  Zig's cc driver:** its output contained SIMD despite the general-regs-only
  flag and trapped with ESR 0x1fe00000 before console; using host Clang fixes
  it. Zig's host objcopy also fails with this macOS 27 SDK; builder flattens
  checked zero-based ELF PT_LOAD segments directly. It retains `.text.head`
  with KEEP in the shared linker script (Zig links with section GC).
- Verified host tools: official Zig archive SHA-256
  3cc2bab367e185cdfb27501c4b30b1b0653c28d9f73df8dc91488e66ece5fa6b,
  under `research/host-tools/zig-aarch64-macos-0.15.2/`; official AOSP
  Android 10 r1 `research/host-tools/mkbootimg.py`, SHA-256
  4d87cfb5482efcd556008cfe563ae442a934acb7ef0df082d422307f26a120b7.
  That mkbootimg expects YYYY-MM-DD patch dates, not YYYY-MM.
- Upstream edk2-msm source pinned at
  e1952621f419f8db60ed28271264e1b5184c571d confirms framebuffer 0x9d400000,
  1080x2160, stride 4320, BGRX; downloaded references in research/polaris/.
  This corroborates the splash reservation but does not prove real scanout.
- Added and verified `misc.img` (4194304 bytes, empty BCB command) and
  `switch.img` (16384 bytes) to the existing critical manifest: now **29 files,
  914858049 bytes**. The preflight collector includes them on future runs.
- User said backup space is ready and sent a screenshot showing ~500 GB.
  `df` still reports ~95 GiB because it excludes reclaimable space. Unsandboxed
  Foundation capacity API for backup/: immediate ~101.5 GB, **important usage
  499526999111 bytes**; user screenshot is consistent. Do not claim no space.
  Never delete user's snapshots/files to free space without their request.
- **Windows full backup IN PROGRESS**: `tools/polaris-backup.py mindowswin
  --adb research/host-tools/platform-tools/adb --jobs 4`, exec session **1260**,
  output **`backup/polaris-full-mindowswin-20261023-195539/`**. Four independent
  read-only 4-GiB chunk streams, gzip/size checks, then whole raw stream SHA-256
  vs fresh device-side sha256sum. Do not reboot or boot Windows during this.
  Do not mark complete until manifest `verified=true` and final VERIFIED line.
  First single-stream attempt at `...-194150/` was interrupted (SIGINT, cleaned
  up its adb child); ~7.8GB `.partial` is incomplete, NOT a valid backup.
- Current Android userdata is mounted; the backup tool was tested and correctly
  refused it. Need an offline root ADB environment with userdata unmounted.
  Existing installed recovery is stock MIUI (ro.debuggable=0); it has a
  factoryreset service. Do not boot its UI casually or pass wipe/format args.
  Extracted privately at research/polaris/recovery/. Preparing an isolated
  RAM-only recovery environment with no recovery/factoryreset service and no
  userdata/cache mounts is a possible next step. Official TWRP polaris page
  lists twrp-3.7.0_9-0-polaris.img; not downloaded yet, never flashed.
- No kernel CI dispatched, no iOS root built, no GPT/filesystem change. Next:
  finish Windows backup, prepare offline Android backup, then temporary probe
  boot and record physical screen/CPU facts. Actual XNU polaris work remains.

- Base `e477291`, branch `codex/polaris-preflight`. Completed preflight commit
  **`fe89171`** adds `tools/polaris-preflight.py`, six host GPT tests,
  `POLARIS.md`, and a README warning. Six tests pass; live collection succeeds.
- User confirmed Shell root access. MagiskSU is `/debug_ramdisk/su`, outside
  adb's PATH. `adb exec-out` still gets an old Magisk PTY: use
  `stty raw -echo 2>/dev/null` inside su, and redirect dd stderr to avoid binary
  corruption. The tool rejects size/hash mismatches; two earlier collections
  retain incomplete `.partial` files and MUST NOT be used as verified backups.
- Official Google adb/fastboot downloaded to ignored
  `research/host-tools/platform-tools/`; version 37.0.1. USB access needs host
  sandbox escalation. `adb -d` selects the one USB phone; do not log its serial
  in git. Root is uid 0, Magisk domain. No phone reboot or partition write done.
- **Verified recovery materials:** `backup/polaris-20261023-193109/` contains
  27 binary files, **910647361 bytes**, each checked against a second phone-side
  SHA-256 and rechecked locally against `manifest.json`. Both GPT regions of
  all six UFS LUNs, full sdb/sdc/sdd/sdf, boot/recovery/dtbo/abl_a/abl_b/devinfo,
  persist/persistbak/modem/mindowsesp, plus live.dtb. `inventory.txt`,
  `layout.json`, private `cmdline.txt` are also local. All backup/research files
  are ignored. **No complete Android or Windows user-data backup exists yet.**
- Both GPT headers and arrays pass CRC on every LUN; no overlaps. Logical
  sector size 4096; sysfs sizes/starts are in 512-byte units. LUN0 biggest gap
  is only 4096 bytes. `userdata` = sda22 (107.258 GiB, GPT LBAs
  33161216..61278202); mindowsesp = sda23 (0.293 GiB,
  1703936..1780736); mindowswin = sda24 (119.707 GiB,
  1780738..33161215). `/data` is ext4 with file encryption, about 18 GiB used /
  86 GiB free. Free filesystem capacity is not unallocated partition space.
- Boot and recovery images have Android header **v1**, 4096-byte pages.
  Current topaz `shim/build.sh` emits v4; do not assume it boots on polaris.
- Live FDT decompiled to ignored `research/polaris/live.dts`. Verified DT facts:
  GICD 0x17a00000/0x10000, GICR 0x17a60000/0x100000 stride 0x20000; UFS
  0x1d84000/0x2500; timer 19.2MHz, virtual INTID19; PSCI SMC; CPU reg values
  0x0,0x100,..0x700. RAM ranges 0x80000000+0x100000000 and
  0x180000000+0xfc8a0000; reserved carve-outs still need review. Splash
  reservation 0x9d400000+0x2400000 does NOT establish scanout base/stride.
  Actual boot command selects dsi_jdi_fhd_nt35596s_video_display. Do not infer
  active hardware from all the inactive panel/touch nodes in the FDT.
- No polaris kernel/boot image/root/UEFI entry exists; no kernel CI run was
  dispatched. Historical CI IDs and on-phone iOS claims below refer to other
  hardware. RECOVERY.md reports previous topaz GPT loss after UFS writes;
  later guard patches do not establish safety on this phone.
- User is arranging backup space and explicitly requested **continue other
  adaptation first**. Mac had ~103 GiB free; combined raw userdata+Windows
  need ~227 GiB, excluding firmware and working space. Proceed with offline
  polaris shim/platform work while they arrange storage. Do not resize or
  format anything or reuse a default userdata root. First eventual hardware
  experiments must be temporary boots with RAM roots and no UFS/log writes.
- Next concrete work: isolate a polaris shim build/profile using measured
  CPU/GIC/boot format, verify framebuffer from firmware/DT without guesses,
  cross-compile locally; then separate XNU platform config. See POLARIS.md
  for the longer sequence. Filesystem shrinking/GPT changes need full backups,
  a concrete reviewed boundary plan and immediate user confirmation.

---

# Historical iOS 16 on sweet (Redmi Note 10 Pro, SM7150) - working notes

## Agent handoff / active work (2026-10-15, latest)

### >>> UPDATE 2026-10-18 (read first, then the 10-17 handoff below) <<<

**LIVE LOG over USB (0077, boot 0077s): no more recovery round-trips.** Boot an image with `sweetusb=2`, run `tools/sweet-usbnet.sh logs/live-NAME.txt` on the PC: it waits for the phone's CDC-ECM interface, sets 192.168.7.1/24 (sudo) and prints/saves the kernel console the phone streams every 100 ms as UDP to 192.168.7.1:5140 (starts with the last 64 KiB). `ping 192.168.7.2` checks the link. Current image: `shim/out/shim-boot-0077s.img` (kernel 0077, ADT sweet-0069hi, cpus=6, sweetfb_noconsole=1, sweetfb_hz=30, sweetusb=2). The recovery pull (`tools/sweet-log-pull.sh`) is still the way after a panic/hang before USB comes up.

**🎉 USB networking works (boot 0076s, 18:24 local): `ping 192.168.7.2` from the PC answers in ~1 ms, 0 % loss (200-packet burst, 1500-byte frames, 512/1024-byte frames).** 0075: CDC-ECM function (bulk 0x81/0x01, interrupt 0x82 NETWORK_CONNECTION; host MAC 02:00:5e:77:ee:01) + kernel ethernet ifnet `ue0` (legacy output, header strip like if_fake) with 192.168.7.2/24 set from the kernel (proto_plumb + SIOCAIFADDR on an in-kernel socket). 0076: received frames into one cluster mbuf (mbuf_allocpacket gave a first mbuf of length 0 -> panic "Failed mbuf validity check: len -14"). Host side (Linux cdc_ether, interface `enp0s20f0u3u1`): `nmcli dev set IF managed no; sudo ip addr add 192.168.7.1/24 dev IF; sudo ip link set IF up`. Boot image `shim/out/shim-boot-0076s.img` (`sweetusb=2`). iOS itself does not see ue0 yet (configd needs an IONetworkInterface in IOKit).

**USB device mode works (boot 0074s, 17:45 local): the host enumerates the phone at high speed as `1209:0001 ios-sweet "Sweet iOS (USB bring-up)"`.** 0072 read-only probe: ABL leaves the USB30_PRIM GDSC and all 7 USB clocks on, DWC3 v3.20a (GSNPSID 0x5533320a) in device mode (GCTL 0x00112000), halted (DCTL RUN_STOP 0, DSTS 0x00d3de04), event buffer still at ABL's 0xfdfc8000, QUSB2 PHY alive. 0073 (`sweetusb=2`): DCTL soft reset, own event buffer (polled, interrupt masked), ep0 DEPSTARTCFG/SETEPCONFIG/SETTRANSFRESOURCE, setup TRB, RUN_STOP; control-transfer state machine as Linux ep0.c; descriptors: vendor class, no data endpoints. It ran but no event came: **0074** forces the VBUS session in the Qualcomm wrapper (QSCRATCH 0xa6f8800: HS_PHY_CTRL |= UTMI_OTG_VBUS_VALID(20)|SW_SESSVLD_SEL(28), SS_PHY_CTRL |= LANE0_PWR_PRESENT(24), as Linux dwc3_qcom_vbus_override_enable) -> connect + enumeration. Image `shim/out/shim-boot-0074s.img`. Black Phone app: main thread waits in -[VMVoicemailManager fetchAccounts] (sync XPC; voicemail needs the modem).

**Navigation works (boot 0071s on v14, log `logs/boot-0071s.txt`):** swipe up from the bottom edge returns to the home screen; app switcher works. Two fixes: **0070** pid_hibernate (syscall 435 was nosys on the macOS config -> SIGSYS killed SpringBoard in -[SBToAppsWorkspaceTransaction _didComplete] when an app left the foreground; the only CONFIG_EMBEDDED-only entry in syscalls.master); **0071** touches starting within 48 px of an edge carry kIOHIDDigitizerEventFromEdgeTip (UIKit `_UIEventHIDTouchEdgeTypeForHIDEvent` reads the digitizer EventMask 0xb0007 bits 0x800/0x1000/0x2000/0x40000). Diagnosed, not fixed: Settings (Preferences) SIGTRAP in PodcastsUI func_1cdc47c58: force-unwrap of `URL.volumeTotalCapacity` (nil on our HFS+ root). Phone/Photos/Messages show black (MobilePhone launches, no crash) - next: stack samples via boot-arg `sweetsample=MobilePhone,MobileSlideShow,MobileSMS,SpringBoard` (image `shim/out/shim-boot-0071s.img`).

**🎉🎉 MILESTONE 2026-10-18 ~15:30 local: iOS 16.7 SPRINGBOARD HOME SCREEN ON THE PHONE** (boot `shim/out/shim-boot-0069s.img` = kernel 0069 + ADT `shim/out/sweet-0069hi.adt`, image **v14**; log `logs/boot-0069s-v14-HOMESCREEN.txt`). Home screen with a few apps, Settings opens, Control Center / lock screen / notification center work, touch + buttons work, 6 A55 cores (`cpus=6`), `sweetfb_noconsole=1 sweetfb_hz=30`. Known issue: cannot leave Settings (home gesture / AssistiveTouch home do nothing) - to investigate.
What it took today (in order): 0058 HID services (Apple IOHIDFamily-1915 user client), 0059 iPhone X identity (hw.product etc.), 0060 SPMI keys + GENI touch, 0061 1125x2436 presented display, 0062 RPMh L11C touch power + IOPMPowerSource battery, 0063 GENI FIFO packing (Goodix GT9896), 0064 PRIV_WORK_INTERVAL grant (SpringBoard "Failed to create work interval"), 0065 SMP via PSCI (6 A55), 0066 crash map regions, 0067 console mute without cons_ops write, 0068 IOSurface lookup of an already-mapped surface returns base -1 (backboardd snapshot crash), 0069 UFS log flush 10 s. Image v13: CommCenter removed from launchd.plist, BKNoWatchdogs. **Image v14** = v13 + Setup skipped (`/var/mobile/Library/Preferences/com.apple.purplebuddy.plist` SetupDone/SetupFinishedAllSteps true, SetupVersion 11, daemonizeNeedsToRun false; purplebuddy.notbackedup mini-buddy flags false; managedconfiguration.notbackedup LockdownActivationIndicatesCloudConfigurationAvailable false; springboard MCForceShowCloudConfigurationUI false) + mobileactivationd data ark seeded (`/private/var/containers/Data/System/D90C94C4-F94E-4FCF-8A28-A93BE3846D8E/Library/internal/data_ark.plist`, -ActivationState Activated etc.) + MediaToolbox D22/D221/Default SubServerConfiguration StartRecorderServer=false (mediaserverd crash loop: portrait-filter prewarm called NULL GL). **Activation:** ADT /chosen certificate-production-status 0, effective-production-status-ap 0, certificate-security-mode 1, effective-security-mode-sep 1 -> mobileactivationd's native Hactivation branch (Codex `codex/activation/report.md`; alternative 4-byte daemon patch documented there). Fallback image v13; v12 deleted.

**🎉 TOUCH WORKS (boot 0063u on image v13, 2026-10-18 ~13:15 local):** tapping (i) on Setup's Hello opens the device-info sheet; swipe-up is recognised (spinner, then back to Hello - under investigation). Chain: RPMh L11C vote (0062, `bsd/dev/sweet_rpmh.c`) -> GT9896 @0x5d on GENI SE7 (0063 fixed FIFO packing: register address went out byte-swapped) -> sweet_hid_touch -> SweetHIDTouch -> backboardd. Battery icon OK (0062 SweetBattery IOPMPowerSource, static 100 %). **Image v13** (= v12 + CommCenter jobs removed from launchd.plist + `BKNoWatchdogs`=true and `FBLaunchWatchdogExceptions{com.apple.purplebuddy:100}` in /var/mobile/Library/Preferences/com.apple.springboard.plist): Setup no longer killed by the scene-create watchdog (it blocked in CoreTelephony getSubscriptionInfo -> CommCenter, Codex `codex/setup/report.md`; that report also lists how to skip Setup: SetupDone/SetupFinishedAllSteps/SetupVersion=11 in com.apple.purplebuddy.plist + activation check). v9 deleted, fallback = v12. Input latency ~1 min with 1 CPU -> Codex task 11 = SMP via PSCI (`codex/smp/`).

**INPUT WORKS (boot 0060u on a freshly flashed v12, log `logs/boot-0060u.txt`):** power, volume up, volume down reach iOS (PMIC -> sweet_keys.c -> SweetHIDButtons -> backboardd). Power locks/unlocks (screen "off" shows the kernel console because the panel never really turns off). **Device identity fixed: iPhone X** (home indicator, Face-ID-style Setup). Earlier test (0059u, `sweethidtest=15` fake Home presses) advanced Setup from Hello to the language list.
- **0058** HID: `iokit/Kernel/arm/hid/`: IOHIDEventServiceUserClient + IOHIDEventServiceQueue + IOHIDEvent compiled UNCHANGED from Apple IOHIDFamily-1915.140.3 (= exact version of the iOS 16.7 IOHIDLib, clone in `research/iohid-1915`) over our minimal IOHIDEventService (SweetHID.cpp: SweetHIDButtons consumer page 0x0C power 0x30 / vol 0xE9/0xEA / menu 0x40; SweetHIDTouch digitizer collections). C hooks `sweet_hid_key(key, down)` (0 power, 1 vol+, 2 vol-, 3 home) and `sweet_hid_touch(finger, down, x, y)`. HID logs go to IOLog. Boot-arg `sweethidtest=N` = fake Home press every N s.
- **0059** identity: hw.machine/hw.model/hw.target/hw.product from the ADT (macOS-config kernel used to answer "iPad8,6"/"Redmi Note 10 Pro"). mkadt: root compatible `D22AP|iPhone10,3|xiaomi,sweet|...`, model iPhone10,3, target-type D22, `/product` copied from the real D22AP device tree (`research/ipsw-x/d22ap.adt`, extracted from the IPSW, NOT in git), `/buttons home-button-type 2`. Codex report `codex/mg/report.md`: MG ProductType = sysctl **hw.product** (unrecognized -> iPod), HWModelStr = hw.target, HomeButtonType = `/buttons/home-button-type`; disk cache `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist` (keyed by build + UUID only -> stale iPod answers survived; reflashed clean v12 to clear it).
- **0060** drivers by Codex (`codex/input/hw-report.md`): `bsd/dev/sweet_keys.c` (SPMI arbiter v5 observer reads, PON 0x810 bits KPDPWR/RESIN SID0, PM6150L GPIO2 SID4 0xc110; works), `bsd/dev/sweet_touch.c` (GENI SE7 I2C @0xa84000, starts 45 s after boot). Touch result: SE7 fw ok (proto 3) but **0x5d and 0x38 both time out -> touch IC unpowered** (L11C LDO needs an RPMh vote). Codex task 8 = RPMh client (`codex/rpmh/`), task 7 = battery (`codex/battery/`).
- **0061** (CI 39117078444): red status bar "rdar:45025538" = UIKit "No status bar visual provider for screen" (360x800 pt is no real iPhone). AppleCLCD now presents **1125x2436** (iPhone X) and shows the centered 1080x2400; touch mapped the same; ADT canvas 1125x2436. `sweetfb_native=1` reverts.
- Images: `shim/out/shim-boot-0060b.img` (0060 + /buttons ADT `sweet-0060hi.adt`). Next: 0061 image with ADT from current mkadt.

### >>> HANDOFF 2026-10-17 late (read this first) <<<

**STATE: iOS 16.7 Setup.app "Hello" screen is ON THE PHONE** (boot `shim/out/shim-boot-0057u.img` on image v12). Photo `/run/media/dipa/android/ios-sweet-work/MILESTONE-setup-hello-2026-10-17.jpg`. SpringBoard + backboardd + Setup run; nothing crashes in the GUI path. Remaining crash/relaunch loops: installcoordinationd (should be fixed by 0057, unverified), mediaserverd (VirtualAudio removed in v12, unverified), mobileactivationd (~100/boot, not analysed), bluetoothd + fairplayd.H2 relaunch constantly (no hardware).

**What is on the phone now:** userdata = image **v12** (`/run/media/dipa/android/ios-sweet-ipsw/ios16-root-20H392-v12.img` + `.simg` + `.sha256`; v9 kept as fallback, v8/v10/v11 deleted or superseded). Kernel **0057** (`xnu/out-0057`, CI `39067532732`). ADT **`shim/out/sweet-0057hi.adt`** (QEMU twin `research/q0057-hi.adt`). Boot image **`shim/out/shim-boot-0057u.img`**. Boot args: `debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam -noprogress rd=ufsroot0 unentitled_ios_sim_launch=1 ignition_level=1 wdt_test=no_user_checkin ufsrw=1 rootrw=1 launchd_unsecure_cache=1 wdt=-1`.

**Build a phone image** (kernel K, ADT A): `python3 tools/mkpayload.py $K $A shim/out/payload-X.bin --cmdline "$B" && (cd shim && ./build.sh ../shim/out/payload-X.bin && cp out/shim-boot.img out/shim-boot-X.img)` then check `python3 tools/unpack_bootv2.py shim/out/shim-boot-X.img shim/out/check-X && cmp shim/out/check-X/ramdisk shim/out/payload-X.bin`. QEMU smoke test: `python3 tools/mkpayload.py $K research/q0057-hi.adt $S/csq/payloadX.bin --ramdisk $S/csq/root-fork.img --cmdline "debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam -noprogress rd=md0"` + `PATH=~/swift/usr/bin:$PATH python3 tools/qemu-sweet.py ... --secs 40 --kernel $K --fail-on-panic` (S = scratchpad; root-fork.img lives in the session scratchpad csq/ dir and may be gone in a new session).

**Kernel workflow:** edit `research/bt28/xnu/...` (keep the pre-edit copy in `research/preNNNN/`), syntax check `python3 tools/xnu-cc.py research/run28.log research/bt28 <file>`, make `xnu/patches/NNNN-*.patch` with `diff -u pre bt28 | sed` path rewrite, add new/changed files to `research/check-patch-order.py` list, run it (must say applied + MATCH), commit + push -> GitHub Actions `xnu` builds (~8 min) -> `gh run download <id> -R dipa-studio/ios-sweet -n xnu-kernel -D xnu/out-NNNN`. **Repo is PUBLIC since 2026-10-17** (private macOS runner minutes ran out: "recent account payments have failed"); public = free runners. Commit trailer: only `Co-Authored-By: dipa-studio <183933817+dipa-studio@users.noreply.github.com>`.

**Phone workflow (user does buttons, Claude runs commands):**
- Boot test kernel: phone in fastboot -> `fastboot boot shim/out/shim-boot-X.img`. NEVER `fastboot getvar`.
- **Read logs WITHOUT filming:** after a test the user holds Power+VolDown -> fastboot -> `fastboot boot recovery/recovery.img` (OrangeFox, temp) -> wait for `adb shell true` -> `tools/sweet-log-pull.sh /run/media/dipa/android/ios-sweet-work/logs/<name>.txt` (reads the 4 MiB console ring the kernel keeps in the last 1025 blocks of userdata; patch 0047). Then `adb reboot bootloader` brings the phone back to fastboot without the user.
- **Flash a root image:** `fastboot flash -S 512M userdata <img>.simg` (7 min, 25 chunks). After a big flash the Xiaomi ABL fastboot hangs: next `fastboot boot` stalls at "Sending" -> the USER must re-enter fastboot by hand (Power+VolDown). Do not retry commands against the hung ABL. A flash right after `adb reboot bootloader` once failed on chunk 1 (USB protocol error): just retry. User must NOT unplug during flash (once interrupted at 25/25 -> reflash).
- **Edit the phone root without reflashing (same-length only):** find the file's raw offset in the local image (it is one extent; search the image for its first 4 KiB), compare with `adb exec-out dd if=/dev/block/sda34 ...`, then `adb push` changed 4 KiB blocks and `dd of=/dev/block/sda34 seek=... conv=notrunc,fsync`, read back. Recovery kernel has no hfsplus.
- **Pull the whole phone root** (12 min): `adb exec-out "dd if=/dev/block/sda34 bs=1048576 count=16384" > img`; mount ro with udisksctl or `sudo mount -t hfsplus -o loop,ro`. To write into a pulled image: `sudo fsck.hfsplus -fy` first (volume is never cleanly unmounted -> Linux mounts ro even with -o force), then `sudo mount -t hfsplus -o loop,force`.
- Making images: copy latest img with `cp --sparse=always`, mount rw with force, change, `sync; umount`, `sha256sum`, `img2simg`. Keep only the latest image + one fallback on the SSD (/home is ~98% full; big work files live in `/run/media/dipa/android/ios-sweet-work/`, old kernels/images archived in `.../ios-sweet-work/archive/`).

**Diagnostics built into the kernel (all SWEET-only):** persistent console log (0047, boot-arg sweetlog=0 off; flush every ~1 s); `|name| text` copies of /dev/null writes for processes in `sweetnull` (default backboardd,SpringBoard; 0048); `IOK name:` IOKit lookup/open trace for `sweetiolog` (default backboardd,SpringBoard; 0049/0054, 400 lines max); `SWEET Sandbox: proc op N` (0050); `STR ...` heap text dump on SIGABRT/SIGTRAP for `sweetscan` (default backboardd,SpringBoard; 0051/0053) - this is how NSException/BSAssert reasons were found; `SMP name tN pc .. bt ..` user stack sampler for `sweetsample` (default SpringBoard,backboardd; first at 90 s then every 120 s, 40 samples, 16 frames; 0054/0055); `SWEET FB: N swaps` every 1000 swaps; `CRASH name ...` crash reports (0043/0044). Symbolicate cache addresses with `ipsw dyld a2s research/dsc/dyld_shared_cache_arm64 <addr - slide>`; main-binary addresses: addr - mh + 0x100000000.

**Patches added today (0046-0057, all CI-built):** 0046 IOSurface (IOCoreSurfaceRoot) + IOMobileFramebuffer (AppleCLCD on /arm-io/disp0) + arm-io nubs; 0047 persistent log; 0048 /dev/null tee; 0049 IOKit trace; 0050 permissive "Sandbox" MAC policy; 0051/0053 heap text on crash; 0052 RENAME_SWAP via exchangedata on HFS; 0054/0055 sampler, swap counter, AKS selectors 35 (extended device state = 17) and 101; 0056 panel copy from the vsync timer at 10 Hz (sweetfb_hz) instead of every swap; 0057 no config_ext_resolver (ACL group entries resolve without memberd). ADT (tools/mkadt.py): /arm-io/disp0, /chosen/display-scale 3, /chosen/unique-chip-id (synthetic 0x5357454554000001) + chip-id 0x8015 -> IOPlatformUUID A9683613-3704-53F2-95D0-98A8FB574E78. Image v9-v12: /private/var/containers/{Bundle,Data/System,Shared/SystemGroup,Temp}; launchd.plist StandardOut/ErrorPath renamed to ...PatX (pointing jobs at /dev/console stops them launching: EACCES); v12: LastSystemVersion=20H392 in plain /var/mobile/Library/Preferences/com.apple.migration.plist (stops the 1-hour data migration that ran every boot), VirtualAudio.plugin moved to /Library/Audio/Plug-Ins/HAL.disabled/.

**Codex helper** (`codex exec --skip-git-repo-check -m gpt-6.1-sol -c model_reasoning_effort=high -s workspace-write -C /run/media/dipa/android/ios-sweet-work/codex -o OUT "$(cat task.md)" < /dev/null`, run detached with setsid nohup; config already defaults to gpt-6.1-sol high). Reports in `/run/media/dipa/android/ios-sweet-work/codex/`: mediaserverd-report.md, installcoordinationd-report.md (-> 0057), ufs-performance.md (ranked UFS speed plan), **ufs/0058-sweet-ufs-faster.patch** (READY, not yet applied: ufslogsecs default 10 s log flush batching, optional ufscache=1 directional cache ops, optional ufswait=1 spin-then-sleep; syntax-checked, host-stub verified; see ufs/README.md). Apply it as patch 0058 after review.

**Claude safety-classifier note:** several messages about QuartzCore renderer selection / writing an HFS reader tool were cut off by an automatic classifier (false positives, user agrees). Keep those topics short or let them be; they are not blockers now (rendering already works).

**NEXT STEPS (in order):**
1. **Input** (Setup stuck on Hello): touch + power + volume as IOHIDEventService/IOHIDDevice services backboardd matches (log shows backboardd matching IOHIDDevice with DeviceUsagePairs and IOService with HIDServiceSupport=true). Phone hardware: Goodix/Focaltech touch over I2C/SPI (check live DT `dtb/`), buttons via PMIC (pon) and GPIO keys. Start with a fake HID service (e.g. power button via a timer or boot-arg) to learn the ABI, then real drivers.
2. **Device identity**: MobileGestalt reports iPod + Home button. Add /product node / product-type (iPhone10,3, D22AP), device class iPhone, home-button-less (Face ID) properties in mkadt; find exact MG keys (MGIOMFBSupport.c, `IODeviceTree:/product` lookups seen in backboardd trace).
3. **Battery**: AppleSmartBattery/IOPMPowerSource style service (status bar shows empty red battery).
4. Apply Codex 0058 (UFS speed), consider cpus>1, check whether installcoordinationd/mediaserverd loops are gone, analyse mobileactivationd.
5. Hide kernel console over the GUI when not debugging: boot-arg sweetfb_noconsole=1 (but then panics are not on screen).

- **🎉 MILESTONE: iOS GUI ON THE PHONE - Setup.app "Hello" screen (2026-10-17 ~21:30 UTC, boot 0057u on image v12).** Photo: `/run/media/dipa/android/ios-sweet-work/MILESTONE-setup-hello-2026-10-17.jpg` (animated "dobar d(an)" hello lettering, status bar "iPod" + battery icon, bottom "Pritisnite Home za otvaranje" = "Press Home to open" (locale hr), (i) button). Rendered by iOS 16.7 SpringBoard/Setup through CoreAnimation -> backboardd -> kernel IOSurface (IOCoreSurfaceRoot) -> kernel AppleCLCD swaps -> ABL panel memory. What made it: data migration finally skipped (v12: `LastSystemVersion` 20H392 in the plain `/var/mobile/Library/Preferences/com.apple.migration.plist`; ADT `/chosen/unique-chip-id` + `chip-id` for IOPlatformUUID), 0057 (no ext resolver -> ACL containers work), plus everything before (0046 display/IOSurface, 0050 Sandbox policy, display-scale 3, containers dirs, RENAME_SWAP, AKS 35/101, 10 Hz present).
  **Missing (next work, in rough order):**
  - **Input: no touch, no power button, no volume buttons** (no HID drivers; backboardd looks for IOHIDDevice / HIDServiceSupport services). Setup is stuck on "Hello".
  - **Device identity: it thinks it is an iPod with a Home button** (status bar "iPod", "Press Home to open"): MobileGestalt has no product/model identity (no /product node, product-type, etc.) - give it iPhone10,3 / home-button-less (Face ID class) identity.
  - **No battery detection** (no battery/charger/PMIC service; status bar battery shows empty/red).
  - Locale came up Croatian (hr) - harmless.
  - Performance: cpus=1, polled UFS (Codex UFS patch in progress: `codex/ufs/`), backboardd presents at 60 Hz.
- **README refreshed (2026-10-17):** read the full notes and updated the public overview through patch 0045, v7 hardware observations and prepared v8 diagnostics. Documents real Apple userspace, the missing display/IOSurface GUI work, limited security services, highmem, persistent userdata root, current tooling and build examples. Documentation only; no kernel build, tests, flashing or phone boot performed.

- **v11 still migrated (boot 0056u, 20:32 UTC, `logs/boot-0056u-v11.txt`).** On iOS kCFPreferencesCurrentHost lands in the plain plist: all DMEnvironment setters (setLastBuildVersionPref, setUserDataDispositionPref, ...) use CurrentHost and the phone's `/var/mobile/Library/Preferences/com.apple.migration.plist` holds DMUserDataDisposition; datamigrator's XPC service runs with `_RoleAccount: mobile`. **Image v12** = v11 + `LastSystemVersion` = 20H392 added to that plain `com.apple.migration.plist` (keeps DMUserDataDisposition, 501:501 0600) + `/Library/Audio/Plug-Ins/HAL/VirtualAudio.plugin` moved to `/Library/Audio/Plug-Ins/HAL.disabled/` (Codex: stops the mediaserverd SIGSEGV loop; untested). **installcoordinationd loop explained (Codex `codex/installcoordinationd-report.md`):** os_crash "Failed to create data directory" EACCES for `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.installcoordinationd/Library/InstallCoordination`: `Library`/`Library/Caches` in the container are ACL-only (uid/gid 0xfffffffe, mode 0000, ACE for group GUID ...012B = gid 299 systemusers); with `config_ext_resolver` the kernel asks an identity resolver (memberd/opendirectoryd) that iOS does not run -> EWOULDBLOCK -> ACE skipped -> EACCES. **Patch 0057**: drop config_ext_resolver from FILESYS_BASE (compatibility UID/GID<->GUID mapping is used instead), likely fixes other ACL-protected containers too. Codex task 3: UFS driver performance design (`codex/ufs-performance.md`).
- **mediaserverd SIGSEGV loop explained (Codex report `/run/media/dipa/android/ios-sweet-work/codex/mediaserverd-report.md`):** the fault (FAR 0x390) is in the HAL plug-in `/Library/Audio/Plug-Ins/HAL/VirtualAudio.plugin/VirtualAudio` (ApplyBeamFormerPreference <- VirtualAudio_PlugIn::SetPropertyData <- HALS_AHPPlugIn::ObjectSetPropertyData <- AudioObjectSetPropertyData <- MediaExperience vaemVADSerializationListener): the default virtual audio device ('vdef', VirtualAudioDevice_Default) does not exist (no audio hardware/driver, no /product/audio). Proposed workaround for GUI bring-up: move VirtualAudio.plugin out of /Library/Audio/Plug-Ins/HAL/ in the next root image (untested). v11 reflashed OK after an interrupted flash (USB unplugged at chunk 25/25). Codex task 2: installcoordinationd crash loop.
- **ROOT CAUSE of the endless migration: no IOPlatformUUID (2026-10-17).** datamigrator's `-[DMMigrator isMigrationNeededWithBuildVersion:lastBuildVersion:clientPID:]` gets lastBuildVersion from `-[DMEnvironment lastBuildVersionPref]` = `CFPreferencesCopyValue("LastSystemVersion", "com.apple.migration", kCFPreferencesCurrentUser, kCFPreferencesCurrentHost)` -> a ByHost file. The phone had `/var/mobile/Library/Preferences/com.apple.migration.plist` (only DMUserDataDisposition) and NO `Preferences/ByHost` directory at all. On arm XNU publishes IOPlatformUUID (gethostuuid) only from `/chosen/unique-chip-id` (8 bytes) + `/chosen/chip-id` (4 bytes) (IOPlatformExpertDevice::generatePlatformUUID, called from IOPlatformExpert::start); the SWEET ADT had neither, so every CurrentHost preference write failed. Fix: mkadt adds `unique-chip-id` = 0x5357454554000001 (synthetic) and `chip-id` = 0x8015 -> UUID `A9683613-3704-53F2-95D0-98A8FB574E78` (same SHA1 namespace computation as the kernel). ADT `shim/out/sweet-0057hi.adt`, boot image `shim/out/shim-boot-0056u.img` (0056 kernel + 0057hi ADT, QEMU OK). **Image v11** = v10 + `Preferences/ByHost/com.apple.migration.<UUID upper and lower>.plist` {LastSystemVersion: 20H392} (501:501, dir 0755 files 0600). Flashing v11 2026-10-17 ~20:10 UTC. Codex (gpt-6.1-sol high) analysing the mediaserverd SIGSEGV loop in `/run/media/dipa/android/ios-sweet-work/codex/` (report `mediaserverd-report.md`).
- **v10 did NOT stop the migration (boot 0056n on v10, 19:18 UTC, `logs/boot-0056n-v10.txt`):** datamigrator + migrationpluginwrapper ran again, backboardd drew the progress UI (13000+ swaps in ~5 min). So `com.apple.DataMigration.plist`/LastSystemVersion is not the deciding input. What is known about the decision (datamigrator XPC service `DataMigration.framework/XPCServices/com.apple.datamigrator.xpc/com.apple.datamigrator`, strings): `Migration sentinel present. Migration necessary.` (sentinel `/private/var/datamigrator/migrate`, created and removed by datamigrator itself; absent in v10), `System build version changed from %@ to %@. Migration necessary.` / `...unchanged... not necessary`, `Disposition dictionary with build version %@ is out of date relative to current build version %@`, `SyntheticDidUpgrade`, DMUserDataDispositionManager; previous build source not found yet (not in the binary's plain strings; likely in DataMigration.framework's DMUserDataDispositionManager / preferences domain `com.apple.migration`). backboardd calls `DMPerformMigrationIfNeeded` and holds SpringBoard in `checkInAndWaitForDataMigration` until it returns. NEXT: find where the previous build version / disposition dictionary is stored (disassemble DataMigration.framework DMUserDataDispositionManager + datamigrator's isMigrationNeeded path), write it into the image; or get datamigrator's os_log out (OS_ACTIVITY_DT_MODE needs a launchd env change).
- **Data migration never records completion -> skip it (image v10, 2026-10-17).** Boot 0056n (18:16 UTC, `logs/boot-0056n.txt`, 30 min): 10 Hz panel copies, backboardd still presents at ~60 Hz (107k swaps), SpringBoard still in `BKSSystemShellService _checkIn` at sample 14. Every migration run takes 1+ hour on cpus=1 and repeats each boot. DataMigration decides from `/var/mobile/Library/Preferences/com.apple.DataMigration.plist` key `LastSystemVersion` (vs ProductBuildVersion 20H392); the pulled phone root (21:01 local) had NO such file. **v10** = that pulled phone state + fsck.hfsplus -fy (volume was marked not cleanly unmounted -> Linux mounts it read-only even with -o force; fsck found only hard-link counts + minor volume header, repaired) + `com.apple.DataMigration.plist` {LastSystemVersion: 20H392} (501:501 0600). `/run/media/dipa/android/ios-sweet-ipsw/ios16-root-20H392-v10.img` (+ .sha256, .simg); v8 files deleted, v9 kept as fallback.
- **Repo made PUBLIC (2026-10-17, user request) so GitHub-hosted macOS runners are free:** the 0056 CI run was refused ("recent account payments have failed or your spending limit needs to be increased"). Checked before: no device dumps, serials, IMEI or Apple binaries in the history (.gitignore keeps backup/, dtb/, recovery/, research/ out); commit author emails are public now. 0056 rerun `39056660104` passed -> `xnu/out-0056`, QEMU OK, image `shim/out/shim-boot-0056n.img` booted 18:16 UTC.
- **Boot 0055n (17:16 UTC, ~65 min, `logs/boot-0055n.txt`): migration bar reached 99% in ~30 min (was ~60), then crawled.** Root cause of the slowness: backboardd presents the progress UI at ~58 Hz (**167,000 swaps in ~48 min**) and AppleCLCD copied the full 10 MB frame into the panel on every swap -> ~600 MB/s memcpy on the single CPU (cpus=1), starving everything (polled UFS I/O too). Sampler (16 frames): **SpringBoard waits in `-[BKSSystemShellService _checkIn]`** (synchronous BSXPC call to backboardd, from FBSystemShellInitialize <- SBSystemAppMain) - backboardd holds the system shell check-in until the data migration ends, so the migration is the gate to SpringBoard UI. **Patch 0056**: swap only records the latest swap record; the vsync timer copies it to the panel every 60/sweetfb_hz ticks (default 10 Hz); `SWEET FB: N swaps` every 1000.
- **Boot 0054n (16:53 UTC, ~12 min, `logs/boot-0054n.txt`, patch 0054 sampler):** the data migration runs AGAIN on every boot (it completed once in the 0053s run) - completion is not being recorded. backboardd keeps swapping the progress UI (3700+ swaps in ~10 min, `SWEET FB: N swaps`). Sample during migration: SpringBoard main thread blocked in a synchronous XPC call (`mach_msg2_trap <- dispatch_mach_send_and_wait_for_reply <- xpc_connection_send_message_with_reply_sync <- -[BSXPCServiceConnectionMessage _sendSynchronously:] <- BSXPCServiceConnectionProxy ...`). Unsupported AKS selectors seen: 101 `aks_assert_consume`, 93 `aks_get_internal_info`, 34 `_aks_stash_load` (datamigrator), **35 `aks_get_extended_device_state`** (SpringBoard, chronod, remindd, searchd, symptomsd...). **Patch 0055**: AKS 35 answered like 17 (same DER device state), 101 succeeds; sampler backtraces 16 frames, 40 samples (~80 min).
- **MILESTONE: FIRST iOS PIXELS ON THE PANEL (boot 0053s long run, 15:33 UTC, ~60 min; photos IMG_20261017_183029/183222/183419; log `/run/media/dipa/android/ios-sweet-work/logs/boot-0053s-long.txt`, 407 KB, 1428 flushes).** The iOS data-migration boot screen (Apple logo + progress bar) was shown and the bar advanced to full in ~60 minutes. It is drawn by **backboardd through our kernel display path**: `SWEET SURF: backboardd create id 2/3 1080x2400 fmt 0x42475241 (BGRA) bpe 4 bpr 4352 size 10452992 keys 11`, IOSurface sels 9, 27, 5, 34 and traps 2/3 (lock/unlock), IOMFB SwapBegin (4) / SwapEnd (5, 1132-byte struct) / GetLayerDefaultSurface (3) / 68 / 55, then `SWEET FB: swap N layer 0 surface 2|3 1080x2400 ... a 0,0 1080x2400 b 0,0 1080x2400` alternating (double buffering; only the first 16 swaps are logged). Triggered by `com.apple.datamigrator` (AKS sels 101/93/34 return unsupported) and `com.apple.migrationpluginwrapper`. Probably ProgressUI-style CoreGraphics drawing into IOSurfaces (no GPU used). After the migration: SpringBoard and backboardd stay up (exec once each, no crash), nothing new drawn; crash loops only for mediaserverd, installcoordinationd, mobileactivationd (~108 each in the hour); bluetoothd and fairplayd.H2 relaunch constantly (no hardware). Kernel console text overlays the image (sweetfb_noconsole=1 would hide it).
- **MILESTONE: SpringBoard and backboardd both stay up (boot 0053s on v9, 15:29 UTC, `logs/boot-0053s.txt`).** With /chosen/display-scale = 3: `exec SpringBoard` once, `exec backboardd` once, no CRASH for either; MobileGestaltHelper reads IOMFB size/dot pitch; backboardd opens AppleCLCD (sels 57,15,22,29,33,79,74 as before). No IOSurface creates and no swaps: backboardd keeps polling `IOProviderClass IOAcceleratorES` (-> 0 found) and AGXAccelerator/IOAcceleratorESLegacy - no GPU, so no CoreAnimation renderer yet. Log goes quiet after ~47 s (only 47 flushes): the system idles. NEXT WALL: CoreAnimation rendering without a GPU (CPU path) so the window server produces frames.
- **SpringBoard's invalid mode = scale 0 (boot 0053n, 15:19 UTC, `logs/boot-0053n.txt`, heap scan):** `FBSDisplayMode cannot be configured as requested : <FBSDisplayMode: ...; infxinf@0x (1080x2400/0) 60Hz sRGB SDR>` - pixel size and 60 Hz are fine, scale is 0. libMobileGestalt (MGIOMFBSupport.c, sub_19c560a54) reads `display-scale` (u32, default 0) and `display-rotation` from **IODeviceTree:/chosen**, pixel size via IOMobileFramebufferGetDisplaySize (MobileGestaltHelper sel 8/28 in the log). mkadt now adds `/chosen/display-scale` = 3 (1080x2400 @3x = 360x800 pt). ADT `shim/out/sweet-0054hi.adt` (QEMU `research/q0054-hi.adt`), image `shim/out/shim-boot-0053s.img` = 0053 kernel + 0054hi ADT. Possible catch: MobileGestalt may have cached scale 0 in `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/...`.
- **MILESTONE: backboardd survives and opens the display (boot 0052n on v9, 15:07 UTC, `logs/boot-0052n.txt`).** No `CRASH backboardd`. It walks `IODeviceTree:/arm-io` children, matches IOMobileFramebuffer, `open AppleCLCD type 0 -> 0x0`, calls IOMFB selectors 57, 15, 22, 29, 33, 79 (GetBlock, out 1580/40), 74 (SupportedFrameInfo), 12, 6, 27, 17, 84, 50; opens IOCoreSurfaceRoot (sel 13); looks for AGXAccelerator / IOAcceleratorES / IOAcceleratorESLegacy (none, repeatedly), `IODeviceTree:/product` (none, repeatedly), `/buttons`, aop-smart-cover, IOPMrootDomain. No swaps yet. **SpringBoard now gets past display discovery** and dies (sig 5) in `-[FBSDisplayMode _initWithWidth:height:preferredScale:scaleOverride:refreshRate:gamut:hdr:rotation:virtual:validityCheck:]+580` <- `_initWithCADisplayMode:scale:rotation:` <- `FBSDisplayConfiguration _initWithImmutableDisplay:` <- `FBSDisplaySource initWithDisplay:` <- `FBSDisplayMonitor` (slide 0x14504000): "FBSDisplayMode cannot be configured as requested". Checks: width/height >= 2, preferredScale > 0, scaleOverride >= 0, refreshRate non-zero, valid gamut/HDR/rotation. Suspects: refresh rate 0 (IOMFB timing blocks answered with zeros) and/or scale 0 (MobileGestalt main-screen-scale; no /product node in the ADT). **Patch 0053**: heap text scan also on SIGTRAP and for SpringBoard (default sweetscan list backboardd,SpringBoard) to read the exact mode description.
- **Image v9 (2026-10-17) = v8 + `/private/var/containers/{Bundle,Data/System,Shared/SystemGroup,Temp}` (root:wheel 0755; on iOS these live on the data volume, absent from the rootfs) + launchd.plist with StandardOutPath/StandardErrorPath renamed to ...PatX (the in-place phone fix; daemons' stdout reaches the log via the 0048 /dev/null tee).** `/run/media/dipa/android/ios-sweet-ipsw/ios16-root-20H392-v9.img` SHA256 aa9f9139...6e67, `.simg` 12,145,303,864 bytes; written through `sudo mount -t hfsplus -o loop,force`. **Patch 0052** (`xnu/patches/0052-sweet-hfs-rename-swap.patch`, CI `39042761826` -> `xnu/out-0052`, QEMU OK, image `shim/out/shim-boot-0052n.img`): vn_rename falls back to VNOP_EXCHANGE when VNOP_RENAMEX(RENAME_SWAP) returns ENOTSUP for two regular files on one volume (HFS exchange swaps data and cnode descriptors = swap semantics). Flashing v9 started 2026-10-17 ~15:00 UTC.
- **backboardd EXCEPTION FOUND (boot 0051n, 14:41 UTC, `logs/boot-0051n.txt`, patch 0051 heap scan):** `*** Terminating app due to uncaught exception 'NSInvalidArgumentException', reason: '*** -[NSURL initFileURLWithPath:]: nil string parameter'`. First-throw stack (slide 0x337f0000): `+[NSURL fileURLWithPath:]` <- `-[BSSystemContainerForCurrentProcessPathProvider libraryPath]` <- `cachesPath` <- backboardd main+0x1d858 (StartWindowServer, shader cache path). BaseBoard: libraryPath = `BSSystemSharedResourcesDirectoryForIdentifier` = `BSSystemSharedDirectoryForIdentifier(id)` + "/Library"; that calls `container_system_path_for_identifier` (libsystem_containermanager -> `_container_legacy_lookup` -> containermanagerd XPC), which returned NULL (BaseBoard logs "Error getting shared system container ..."). With 0050 the sandbox denials are gone. containermanagerd.log.0 in the pulled (pre-0050) image: "Did not receive any persona attributes", "Expected to find at least one persona", notify_register_dispatch failed 9; `/private/var/containers` does NOT exist in the root image (on iOS it lives on the data volume). usermanagerd does create kernel personas 99/199/1000, but fails to save `/private/var/keybags/usersession.kb` and `persona.kb`: "Failed to atomically swap writing file: Operation not supported (45)" (HFS has no RENAME_SWAP). NEXT: create `/private/var/containers` (and check what containermanagerd needs for system group containers), fix or emulate RENAME_SWAP on HFS, then re-check backboardd.
- **Disk housekeeping (2026-10-17):** /home was at 4 GiB free. Moved (not deleted) `xnu/out-0010..0044` and old `shim/out/*.img`/`payload-*.bin` (everything before 0046) to `/run/media/dipa/android/ios-sweet-work/archive/{xnu,shim-out}` (6.3 GiB); /home now 8.7 GiB free. Large work files (phone-root.img 16 GiB, logs, tracev3 dumps) live in `/run/media/dipa/android/ios-sweet-work/`. **Patch 0051** (`xnu/patches/0051-sweet-crash-heap-strings.patch`, CI `39041440935`): on SIGABRT of a process in boot-arg `sweetscan` (default backboardd) the crash log prints heap text runs as `STR ...` (to find the NSException reason). Boot 0051n 14:41 UTC.
- **Boot 0049n (14:11 UTC, `logs/boot-0049n.txt`, patch 0049 trace): backboardd's IOKit lookups before it dies** (each run): `IODeviceTree:/arm-io/pearl-sep` -> none, matching ApplePearlSEPDriver -> none, `IOService:/IOResources/AppleKeyStore` open OK, matching IOHIDDevice (DeviceUsagePairs) / `HIDServiceSupport` notifications, `usb-drd,t8027` notification; **never any IOMobileFramebuffer / display lookup** - the exception happens before display detection. launchd (tracev3) shows backboardd's mach lookups denied with `error = 159: Sandbox restriction`: com.apple.mobilegestalt.xpc, com.apple.iohideventsystem, com.apple.system.notification_center, com.apple.logd, containermanagerd, ACCHWComponentAuthService, oscard. libsystem_sandbox uses `__mac_syscall("Sandbox", op, arg)` (ops: 1 init, 2 check, 3 note, 4 container path, 5/6/7/8 extensions, 0x15 check_bulk, ...); with no policy named "Sandbox" every call gets ENOPOLICY. **Patch 0050** (`xnu/patches/0050-sweet-sandbox-policy.patch`): built-in permissive MAC policy "Sandbox" in sweet_amfi.c (mpo_policy_syscall returns 0, container/extension ops ENOENT; logs first use of each op as `SWEET Sandbox: proc op N`).
- **Phone root pulled (16 GiB, 12 min, `adb exec-out dd if=/dev/block/sda34`) to `/run/media/dipa/android/ios-sweet-work/phone-root.img` (loop-mounted ro at /run/media/dipa/iOSRoot).** No .ips crash reports. logd tracev3 (Persist, LZ4 `bv41` blocks, decompressed strings in `ios-sweet-work/tracev3/all.txt`): /private/var/db/uuidtext is EMPTY so only launchd's own messages are readable. Findings: v8 launch failure = `Service could not initialize: posix_spawn(/usr/libexec/backboardd), error 0xd - Permission denied` (xpcproxy exit 78) - /dev/console not openable for the mobile user; backboardd[98] spawned `com.apple.MTLCompilerService` before SIGABRT; **launchd denies many mach lookups with `error = 159: Sandbox restriction`** (mediaserverd -> com.apple.backboard.display.services, remoted, mobiletimerd -> sleepd, identityservicesd -> apsd) and **tccd exits OS_REASON_SANDBOX "profile not found"** - no Sandbox kext/profiles on SWEET; likely cause of many daemon crash loops (next wall after the display). CF's uncaught-exception text never reaches stderr for daemons (no CF handler; libc++abi prints only the type). **Patch 0049** (`xnu/patches/0049-sweet-iokit-trace.patch`): `IOK name: ...` console lines for registry path lookups, child iterators, matching (with result count/class), matching notifications and IOServiceOpen of the processes in boot-arg `sweetiolog` (default backboardd), max 400 lines.
- **CONFIRMED: launchd StandardOut/ErrorPath=/dev/console stops backboardd from launching.** After the in-place rename (boot 0047n-b, log `logs/boot-0047n-b.txt`) backboardd launches again and dies as on v7: sig 6, `___pthread_kill <- abort <- demangling_terminate_handler <- _objc_terminate <- std::terminate <- _dispatch_client_callout <- _dispatch_once_callout <- main+0x9334` (window-server dispatch_once). It never opened AppleCLCD or IOCoreSurfaceRoot (no `SWEET FB/SURF: backboardd` lines) -> throws before/at display detection. **Patch 0048** (`xnu/patches/0048-sweet-devnull-tee.patch`, CI `39037749668` -> `xnu/out-0048`, image `shim/out/shim-boot-0048n.img`): writes to /dev/null by processes named in boot-arg `sweetnull` (default `backboardd,SpringBoard`) are printed as `|name| text`. Boot 0048n (13:48 UTC, log `logs/boot-0048n.txt`): only `|backboardd| libc++abi: terminating due to uncaught exception of type NSException` (CF's reason line goes to os_log, not stderr, despite CFLOG_FORCE_STDERR/OS_ACTIVITY_DT_MODE). Next: pull the whole 16 GiB root from recovery (`adb exec-out dd if=/dev/block/sda34`) to `/run/media/dipa/android/ios-sweet-work/phone-root.img` and read ReportCrash .ips files / logd tracev3 for the exception reason.
- **Persistent log WORKS (boot 0047n on v8, 13:31 UTC; pulled from OrangeFox: 70 KB, 111 flushes, `/run/media/dipa/android/ios-sweet-work/logs/boot-0047n.txt`).** In 3 min **backboardd was never exec'd** (v7 ran it), ~70 bare `exec xpcproxy`, SpringBoard loops on FBSDisplayMonitor (no display), mediaserverd sig 11 loop, locationd, lockdownd sig 5. Suspect the v8 plist (StandardOut/ErrorPath=/dev/console on backboardd). **In-place plist edit from recovery (no reflash):** launchd.plist is one extent at image/partition byte offset 0x1e025f000 (195 blocks; verified bytes identical on phone vs local v8 mount); renamed StandardOutPath->StandardOutPatX and StandardErrorPath->StandardErrorPatX (same length, both jobs) in blocks 68 and 105 via `adb push` + `dd of=/dev/block/sda34 seek=... conv=notrunc,fsync`, read back VERIFIED. Phone now differs from local v8 image in those 2 blocks (files in `/run/media/dipa/android/ios-sweet-work/`). Test boot 0047n 13:38:42 UTC. Recovery kernel has no hfsplus (raw block edits only).
- **Patch 0047: persistent console log (CI `39036478663` -> `xnu/out-0047`, QEMU no panic; phone image `shim/out/shim-boot-0047n.img` = 0047 + sweet-0046hi.adt + 0045n cmdline).** `_cnputs` (all console output: kernel printf + daemons' /dev/console) also appends to a 4 MiB ring in sweet_ufs.c; after the UFS partition is ready and writable (ufsrw=1) a thread writes new ring blocks + header to the LAST 1025 blocks (4 KiB) of userdata every ~1 s and SYNCHRONIZE CACHE (prints `SWEET LOG: console log to the last 4100 KiB ...`). Read: phone to fastboot -> `fastboot boot recovery/recovery.img` (OrangeFox) -> `tools/sweet-log-pull.sh OUT.txt` (adb dd of that area + `tools/sweet-log.py`). Not yet verified on the phone. Panics after the last flush are not in it (screen still shows them). 2x font attempt reverted: XNU's v_scale only scales the progress icon.
- **Boot 0046n on v8 (13:05 UTC, VID_20261017_150522_HSR_120):** phone prints `SWEET SURF: IOCoreSurfaceRoot registered` and `SWEET FB: AppleCLCD 1080x2400 stride 4320 at 0x9c000000, default surface 1` (nubs + match work on hardware). Visible userspace: early boot tasks, launchd_cache_loader, `exec SpringBoard`; no `exec backboardd` / `SWEET FB: backboardd` line seen in the readable frames (video blurry). Frame 00:47: lower half of the screen shows OLDER console text (16:01:12) below newer lines -> unconfirmed hint that a swap copied an old snapshot of the panel (CA reads the default/displayed surface = panel memory). SpringBoard still dies in `-[FBSDisplayMonitor _initWithBookendObserver:transformer:]+1160` (sig 5, slide 0x30960000). **Shim: 2x console font** (`shim/loader.c` Video.v_depth scale field = 1) so phone videos are readable; image `shim/out/shim-boot-0046b.img` = 0046n + 2x font.
- **Patch 0046: built-in IOSurface + IOMobileFramebuffer (2026-10-17, offline, NOT phone-tested).** `xnu/patches/0046-sweet-iosurface-iomfb.patch`: new `iokit/Kernel/arm/SweetSurface.{h,cpp}` (IOCoreSurfaceRoot + IOSurfaceRootUserClient: sel 13/0/4/34/35, traps 0-5, wired buffers mapped into the caller, per-client refs) and `SweetFramebuffer.cpp` (AppleCLCD : IOMobileFramebuffer on /arm-io/disp0: sizes, swap = CPU copy of enabled layers into the ABL panel memory, 60 Hz vsync via sendAsyncResult64WithOptions(CanDrop), panel memory published as the default IOSurface, kernel text console paused on the first swap only with `sweetfb_noconsole=1` (default keeps the console: pausing switches it to serial and would hide panics)); SweetPlatformExpert creates nubs for /arm-io children (not gic) attached to the platform expert (IOPlatformDevice::compareName casts its provider to IOPlatformExpert, so nubs under the arm-io nub never matched - first CI build showed that in QEMU). mkadt: /arm-io/disp0 {device_type display-subsystem, compatible sweet,display, canvas-width 1080, canvas-height 2400}. CI `39021572169` -> `xnu/out-0046`. **QEMU** (`research/q0046-hi.adt`, RAM disk init, msgbuf): `SWEET SURF: IOCoreSurfaceRoot registered`, `SWEET FB: AppleCLCD 1080x2400 stride 4320 at 0x9c000000, default surface 1`, init alive, no panic. Phone image **`shim/out/shim-boot-0046n.img`** (SHA256 9c4d2fe9..., CI `39024108588` with the review fixes: swap bounds check, zeroed 64-bit async ref, port release, 1.5 GiB wired budget, ref leak/race fixes; QEMU re-checked) = 0046 kernel + `shim/out/sweet-0046hi.adt` + the 0045n cmdline; boot it on image v8 (backboardd/SpringBoard log to console) and film. Expected new console lines: `SWEET SURF: <proc> create id ...`, `SWEET FB: backboardd sel N ...`, `SWEET FB: swap ...`. Open question for the next wall: QuartzCore's IOMFB server builds its renderer from Metal first (`CAMetalContextCreate`), GLES only when enabled; how the CPU renderer gets selected on a device without a GPU is not yet established.
- **IOSurface values ABI (offline RE, `/run/media/dipa/android/ios-sweet-work/iosurface-values.md`) - TODO in SweetSurface (0046 only accepts and drops values, so IOSurfaceCopyValue always returns NULL):** sel 9 SetValue in = {u32 id, u32 pad, IOCFSerialize([value, key]) or ([dict] = merge)}, sel 0xb RemoveValue in = {u32 id, u32 pad, key\0} (empty key = remove all); both out 4 bytes = new generation, client accepts only (gen+2)|1. Kernel after each change: gen = (gen+2)|1 (odd, never 0) -> state+0x20, serialized size (>=1) -> state+0x28. sel 0xa in {u32 id, u32 0, u8 0}, out {u32 ?, u32 gen, serialized non-bulk dict}; too small -> 0xe00002db + needed size (client retries x16). sel 0x1b in 0x88: bulk struct 0x70 @0, u64 valid size @0x70, u64 changed mask @0x78, u32 id @0x80 -> copy masked fields into state+0x30 (bit0 32B @0, bit1 16B @0x20, bit2 8B @0x30, bits3-10 1B @0x38..0x3f, bits11-14 24B @0x40/4B @0x58/8B @0x5c/1B @0x64).
- **IOMFB display matching confirmed (offline RE, `/run/media/dipa/android/ios-sweet-work/iomfb-match.md`):** the framework never matches on "AppleCLCD"; any registered IOMobileFramebuffer subclass works. `iomfb_match_callback` reads only `dfr`/`AppleTV`/`external` (CFBoolean, service itself, no parents); internal main display = all absent/false (type 0, name "primary"). Display count = /arm-io children whose device_type starts with "display-subsystem" (count 0 -> CreateDisplayList returns NULL; more nodes than services -> 30 s wait). IOMobileFramebufferOpen fails only on IOServiceOpen failure; canvas-width/height read as 4-byte CFData from the IOService-plane parent (optional). CopyProperty = IORegistryEntrySearchCFProperty on the service only. Patch 0046 (disp0 node, `external`=false, AppleCLCD : IOMobileFramebuffer) fits all of this.
- **IOMobileFramebuffer swap + notification ABI (2026-10-17, offline).** Swap record = fb+0x18, **0x46c bytes**, zeroed by SwapBegin and sent whole by `kern_SwapEnd` = IOConnectCallStructMethod(sel 5, rec, 0x46c, no output). **SwapBegin** = sel 4, no input, 1 scalar out = swap id (stored at rec+0x50). `kern_SwapSetLayer(fb, layer<4, IOSurfaceRef, CGRect a, CGRect b, flags)`: rec+0x54+4*layer = **IOSurface id**; rec+0x104 bit layer = layer enabled (rec+0x108 bit cleared); rect a (int x,y,w,h, scaled) at rec+0x64+16*layer, rect b at rec+0xc4+16*layer; rec+0x114+4*layer = transform from flags&0xf; flag bits 5/31/6/7/8/9 set bytes rec+0x2ca/0x2cc/0x2e3/0x2e5/0x2e6/0x467+layer. A NULL surface only sets the enable bit with zero id. SwapWait = sel 6 scalars [swap id, timeout, 0].
  - **Notifications**: `IOMobileFramebufferScheduleWithDispatchQueue`/`GetRunLoopSource` create an IONotificationPort and `IOConnectSetNotificationPort(conn, type, port, 0)` (kernel `registerNotificationPort`). `kern_EnableNotifications(fb, type, cb, ctx)` = **sel 72 scalars [NotifyCallbackFuncs[type], fb, type, 0]** -> the kernel keeps an async reference {port, func, refcon=fb} per type and fires it with `sendAsyncResult64`. Types: 0 HotPlug, 1 Power, 3 FrameInfo (args[0] = mask of 31-bit keys, args[1] u32, then values), 4 CRC, **5 Vsync**: 6 args, each a 32-bit half in a u64 slot: (ts lo, ts hi), (t2 lo, hi) passed through the time-ingest helper, (t3 lo, hi); the framework then calls the client's vsync callback(fb, ts, t2', t3, ctx). Vsync callbacks are dropped while the notification port has queued messages.

- **IOSurface.framework user-client ABI reversed (2026-10-17, offline, step 2 of the GUI plan).** `ipsw dyld disass research/dsc/dyld_shared_cache_arm64 --image IOSurface` (selector scan script: scratchpad `selscan.py`).
  - Connect (`_iosConnectInitalize`, pthread_once): `IOServiceGetMatchingService(IOServiceNameMatching("IOCoreSurfaceRoot"))`, retried with sleep(1) up to 241 times (a missing service stalls every client ~4 min, no crash); `IOServiceOpen(type 0)`; then **sel 13** (no inputs, struct out 0x18 bytes = `_ioSurfaceLimits`) and requires u16 at out+0x16 == 1 (ABI version); out+0 = offset/plane-base alignment mask, out+4 = bytes-per-row alignment mask (used as (x+m)&~m), +0..+0x14 also copied into IOSurface remote-method init, otherwise logs and closes the connection.
  - **Create = sel 0**: scalar in [parent id or 0], struct in = `IOCFSerialize(props, kIOCFSerializeToBinary)` (OSUnserializeBinary format; keys IOSurfaceWidth/Height/BytesPerRow/BytesPerElement/PixelFormat/AllocSize/PlaneInfo/CacheMode/IsGlobal/...), struct out **0xa68 bytes** ("lock result"). **Lookup = sel 4**: scalar in [id], same struct out. LookupFromMachPort = sel 0x22 (scalar in [port name]); CreateMachPort = sel 0x23 (scalar in [id, options], scalar out [port name]).
  - Lock result (copied to client+0x68, size 0x68 + planes*0x80, min 0xe8): 0x00 u64 base address **mapped in the caller's task**; 0x08 u64 task VA of a per-surface shared state page (+0 u64 registry id, +8/+0xa u16 bound accel ids, +0xc u32 seed, +0x14 u8 tiled, +0x20 u32 value generation, +0x24 YCbCr matrix, +0x28 u32 non-bulk values size, +0x2d u8 displayable, +0x2e u8 sysmem-only, +0x30 0x70 bytes bulk attachments); 0x10 u64 task VA of timestamp page (4 u64 indexed timestamps, +0x20 detach code); 0x18 u32 surface id; 0x1c u32 alloc size; 0x20 width; 0x24 height; 0x28 bytes per row; 0x2c buffer offset; 0x30 pixel format; 0x34 u32 (dcache flush length); 0x38 plane count; 0x40 u16 bytes/element; 0x42 u8 element width; 0x43 u8 element height; 0x44 cache mode; 0x4c u8 subsampling; 0x4d u8 prohibit-use count; 0x50 parent id; 0x54 slice count; 0x58 u64 trace id; 0x60 u64 protection options; planes[n] at 0x68+n*0x80 (+0 width, +4 height, +8 bytes/row, +0xc offset, +0x14 size, +0x18 u16 bpe, +0x1a/+0x1b u8 element w/h, +0x1c u8 component count, +0x1d address format, +0x54 u8 compression type (non-zero -> no CPU base address)).
  - **Traps** (IOConnectTrapN -> `IOUserClient::getTargetAndTrapForIndex`): 0 IncrementUseCount(id, category), 1 DecrementUseCount(id, category), 2 **Lock**(id, options, &seed_out), 3 **Unlock**(id, options, &seed_out), 4 Release(id), 5 Release after a failed create/lookup setup (id).
  - Other selectors: 5 SetYCbCrMatrix, 6 WrapClientImage, 7 WrapClientMemory, 9 SetValue (serialized), 0xa UpdateNonBulkValueCache (struct in 9), 0xb RemoveValue, 0xc BindAccel, 0x11 SetSurfaceNotify (async), 0x12 RemoveSurfaceNotify, 0x13 Log, 0x14 SetPurgeable, 0x15 SetOwnership, 0x16 SetTiled, 0x18 SetTimestamp, 0x19 GetTileFormat, 0x1a CopyDataValueBytes, 0x1b SetBulkAttachments (struct 0x88), 0x1e/0x2e-0x31 (via outlined helpers), 0x1f SetCompressedTileDataRegionMemoryUsed, 0x20 GetGraphicsCommPageAddress, 0x21 SetIndexedTimestamp, 0x24-0x26/0x2d IOSurfaceAccelerator, 0x27-0x29 shared events, 0x2a SignalEvent, 0x2b Set/InitDetachModeCode, 0x2c SetOwnershipIdentity, 0x32-0x34 data properties.
  - => SWEET kernel service: class/name **IOCoreSurfaceRoot** + IOSurfaceRootUserClient; minimum = sel 13, 0, 4, 9/0xa/0xb (values), traps 0-5, 0x22/0x23 later for cross-process surfaces (CA sends surfaces to backboardd by mach port). Memory: IOBufferMemoryDescriptor per surface, mapped into each task with createMappingInTask; ids from a global table.

- **Image v8: daemon logs on the console.** `tools/patch-launchd-plist.py IN OUT LABEL...` rewrites launchd.plist (binary, plistlib): renames every `_PanicOnCrash` to `_PanicOnCrasX` and gives the listed jobs `StandardOutPath`/`StandardErrorPath` `/dev/console` (devfs console is 0622, writable by mobile) plus `OS_ACTIVITY_DT_MODE=YES` (os_log mirrored to stderr) and `CFLOG_FORCE_STDERR=1`. v8 = v7 + that plist for com.apple.backboardd and com.apple.SpringBoard, written through the mount (796310 bytes, root:80 0644), SHA256 in `ios16-root-20H392-v8.img.sha256`, `.simg` ready; boot with `shim/out/shim-boot-0045n.img`. Goal: see backboardd's uncaught exception text and the window server's display probing. ODDITY (unresolved): the v5 raw-image rename at offset 0x1e025f000 is present in the v5-v7 image bytes, but the plist read through a Linux mount of v7 still had the original `_PanicOnCrash` keys; filefrag shows the file as one extent. Never patch file contents through raw offsets again; write through the mount.
- **IOMobileFramebuffer.framework reversed (step 1 of the GUI plan).** `ipsw dyld disass research/dsc/dyld_shared_cache_arm64 --image IOMobileFramebuffer`.
  - Display discovery (`IOMobileFramebufferCreateDisplayList` -> `getDisplayListNumber`): iterates children of `IODeviceTree:/arm-io`, counts nodes whose `device_type` is "display-subsystem" or "ext-display-subsystem" (or `compatible` "paravirtualizedgraphics,gpu"); then `iomfb_populate_display_infos` adds an IOServiceAddMatchingNotification(IOServiceFirstMatch, **IOServiceMatching("IOMobileFramebuffer")**) and runs the run loop up to 30 s until that many services matched. `iomfb_match_callback` reads service properties `dfr`, `AppleTV`, `external` (CFBoolean) and names displays (external ones "%s-%d").
  - `IOMobileFramebufferOpen(service, task, type, &fb)`: `__ioMobileFramebufferAlloc` (CFPreferences com.apple.iokit.IOMobileGraphicsFamily: canvas_width/height, override_display_width/height, override_panel_width/height, benchmark, enable_ktrace), `IOServiceOpen(service, task, type)` (GetMainDisplay passes type 0), `getEDTProperty` reads `canvas-width`/`canvas-height` from the service's IODeviceTree parent, then fills a table of `kern_*` function pointers.
  - User client selectors (`kern_*` -> IOConnectCall*): 3 _kern_GetLayerDefaultSurface[ScalarMethod_stub]; 4 _kern_SwapBegin[ScalarMethod_stub]; 5 _kern_SwapEnd[StructMethod_stub]; 6 _kern_SwapWaitWithTimeout[ScalarMethod_stub] _kern_SwapWait[ScalarMethod_stub]; 7 _kern_GetID[ScalarMethod_stub]; 8 _kern_GetDisplaySize[ScalarMethod_stub]; 10 _kern_SetTVOutMode[ScalarMethod_stub]; 11 _kern_SetWSSInfo[ScalarMethod_stub]; 12 _kern_RequestPowerChange[ScalarMethod_stub]; 13 _kern_EnableStatistics[ScalarMethod_stub]; 14 _kern_SetFlags[ScalarMethod_stub]; 15 _kern_SetDebugFlags[ScalarMethod_stub]; 16 _kern_SetTVOutSignalType[ScalarMethod_stub]; 17 _kern_SetGammaTable[StructMethod_stub]; 18 _IOMobileFramebufferIsMainDisplay[ScalarMethod_stub]; 19 _kern_SetWhiteOnBlackMode[ScalarMethod_stub]; 20 _kern_SwapSignal[ScalarMethod_stub]; 22 _kern_SetDisplayDevice[ScalarMethod_stub]; 23 _kern_SetDigitalOutMode[ScalarMethod_stub]; 24 _kern_GetHDCPDownstreamState[StructMethod_stub]; 25 _kern_GetDigitalOutState[ScalarMethod_stub]; 26 _kern_printDisplayRegs[ScalarMethod_stub]; 27 _kern_GetGammaTable[StructMethod_stub]; 28 _kern_GetDotPitch[ScalarMethod_stub]; 29 _kern_GetDisplayArea[StructMethod_stub]; 30 _kern_EnableDisableDithering[ScalarMethod_stub]; 31 _kern_SetUnderrunColor[ScalarMethod_stub]; 33 _kern_EnableDisableVideoPowerSavings[ScalarMethod_stub]; 34 _kern_SetVideoDACGain[ScalarMethod_stub]; 35 _kern_SetLine21Data[ScalarMethod_stub]; 41 _IOMobileFramebufferEnableMirroring[ScalarMethod_stub]; 42 _IOMobileFrameBufferGetMirroringCapability[StructMethod_stub]; 43 _IOMobileFramebufferSetRenderingAngle[StructMethod_stub]; 44 _IOMobileFramebufferSetMirrorContentRegion[StructMethod_stub]; 47 _kern_HDCPSendRequest[ScalarMethod_stub]; 48 _kern_HDCPGetReply[ScalarMethod_stub]; 49 _kern_SurfaceIsReplaceable[ScalarMethod_stub]; 50 _kern_SetBrightnessCorrection[ScalarMethod_stub]; 51 _kern_SetColorRemapMode[ScalarMethod_stub]; 52 _kern_SwapCancel[ScalarMethod_stub]; 53 _IOMobileFramebufferSetCanvasSize[ScalarMethod_stub]; 54 _IOMobileFramebufferGetMatrix[Method_stub]; 55 _IOMobileFramebufferSetMatrix[Method_stub]; 56 _IOMobileFramebufferKernelTests[StructMethod_stub]; 57 _kern_GetColorRemapMode[ScalarMethod_stub]; 66 _kern_SPLCSetBrightness[ScalarMethod_stub]; 67 _kern_SPLCGetBrightness[ScalarMethod_stub]; 68 _kern_SetParameter[Method_stub]; 69 _kern_SwapSetColorMatrix[StructMethod_stub]; 72 _kern_DisableNotifications[ScalarMethod_stub] _kern_EnableNotifications[ScalarMethod_stub]; 73 _kern_ChangeFrameInfo[ScalarMethod_stub]; 74 _kern_SupportedFrameInfo[Method_stub]; 75 _kern_FactoryPortal[StructMethod_stub]; 77 _kern_GetCurrentAbsoluteTime[ScalarMethod_stub]; 78 _kern_SetBlock[Method_stub]; 79 _kern_GetBlock[Method_stub]; 80 _kern_GetLinkQuality[ScalarMethod_stub]; 81 _kern_SwapCancelAll[ScalarMethod_stub]; 82 _kern_GetProtectionOptions[ScalarMethod_stub]; 83 _kern_CopyLayerDisplayedSurface[ScalarMethod_stub]; 84 _kern_SetContrast[StructMethod_stub]; 85 _kern_GetBufBlock[Method_stub]; 86 _IOMFBGainEncoderFinishEncoding[Method_stub]; UNKNOWN {}
  - => Kernel needs: an `/arm-io` child node with device_type "display-subsystem" (+ canvas-width/height) and an IOService of class **IOMobileFramebuffer** (subclass name match) attached under it, opened with type 0, implementing at least GetDisplaySize(8), IsMainDisplay(18), GetID(7), GetLayerDefaultSurface(3), SwapBegin(4)/SwapEnd(5 struct)/SwapWait(6), Enable/DisableNotifications(72), frame info(73/74), CopyLayerDisplayedSurface(83), plus IOSurface for the swapped buffers. NEXT: CoreAnimation's AppleDisplay/IOMFBDisplay usage of these (constructor, first swap, vsync), then IOSurface.framework's IOSurfaceRoot selectors.
- **GUI PLAN (decided 2026-10-16): CPU rendering + kernel IOMobileFramebuffer.** User: CPU rendering is fine for now (goal = prove the GUI runs), may later research an Apple-style GPU driver for the Adreno 618 -> keep display output and renderer separable. QuartzCore findings (symbols from the cache's .symbols subcache: `ipsw dyld symaddr research/dsc/dyld_shared_cache_arm64 --image QuartzCore`; strings: `ipsw dyld macho ... QuartzCore --strings`):
  - Renderers: `sw_new_context` (CA::OGL::SWContext, full CPU renderer incl. blur, images, IOSurface-backed surfaces, make_buffer_current(WindowServer::Surface)), `gles_new_context`, `metal_new_context`, `new_null_context`. Env knobs include CA_ENABLE_OGL, CA_DISPLAY_TYPE, CA_FORCE_LOCAL_SERVER, CA_FORCE_TIMER, CA_CANVAS_WIDTH/HEIGHT, CA_MAIN_DISPLAY_SCALE/ORIENTATION, CA_DISABLE_RENDER, CA_ALWAYS_RENDER (selection logic not traced yet).
  - `-[CAWindowServer _detectDisplays]` (0x1884e3150) iterates static tables `open_funcs`/`count_funcs` = AppleCLCDDisplay, AppleRGBOutDisplay, AppleWirelessDisplay only; each `count()` = `display_count_of_type(IOMFBDisplayType)` over **`IOMobileFramebufferCreateDisplayList()`**, `open(i)` = `create_display_of_type` -> `CA::WindowServer::AppleDisplay(CFString name, ..., IOMFBDisplayType)` (an IOMFBDisplay driven by IOMFBServer: vsync_callback, frame_info_callback, swaps). `CA::WindowServer::VirtualDisplay` exists but is never auto-detected (explicit API only). => the main display MUST come from an IOMobileFramebuffer kernel service.
  - NEXT: reverse IOMobileFramebuffer.framework: IOMobileFramebufferCreateDisplayList / IOMobileFramebufferOpen (service matching, display type property), the user-client selectors used by IOMFBServer (display size/modes, swap begin/set-layer/end with IOSurface ids, vsync notifications), then the IOSurface kernel side (IOSurfaceRoot user client: create/lookup/lock, memory mapping) that both IOMFB swaps and CA surfaces need. Kernel: SWEET IOMobileFramebuffer service that copies the swapped IOSurface to the 1080x2400 framebuffer at 0x9c000000.
- **logd fixed; backboardd = DISPLAY WALL (boot 0045n on v7, 21:08:57 UTC, frames VID_20261016_230850 00:55-01:28, slide 0x4c3ec000, `research/crash-0045n-v7.txt`).** No `CRASH logd` any more; new daemons run (runningboardd, WirelessRadioManagerd, networkserviceproxy, dasd, cloudpaird, magicswitchd, atc, askpermissiond, ManagedSettingsAgent, containermanagerd uses AKS 0/17). New: locationd sig 11 at CFRunLoopAddSource+132 (NULL source) from its main+0x2af138 in a dispatch_once. **backboardd** sig 6: abort <- std::terminate <- _objc_terminate <- dispatch_once <- main+0x9334 = the "start %{public}@..." wrapper (0x100009264) for **"window server"** (block 0x10000a770 -> dispatch_once body 0x10001d7f0 = StartWindowServer): MTLSetShaderCachePath, `[CAWindowServer serverWithOptions:@{kCAWindowServerDisableUpdatesOnMainDisplay: @YES}]`, `setRendererFlags:`, **`mainDisplay`** -> `displayId` -> `[CADisplay displayWithDisplayId:]`, setWindowServerDisplay:, bounds, pointScale, currentMode, preferredScale, nativeOrientation, touchScales... With no display, mainDisplay is nil and it throws. (HID system and GS start fine before it.) SpringBoard dies on the same missing display (FBSDisplayMonitor). QuartzCore display backends (from the cache's .symbols subcache, `ipsw dyld str`): `CA::WindowServer::AppleCLCDDisplay` (IOMobileFramebuffer hardware) and **`CA::WindowServer::VirtualDisplay`** (open(), new_server, clone_update). `CA_DISPLAY_TYPE` and `CA_FORCE_LOCAL_SERVER` strings exist in QuartzCore but have no direct xref (likely read via a table of CA_* env names). NEXT: find how CA::WindowServer::Server enumerates displays (IOMobileFramebuffer services vs VirtualDisplay / CA_DISPLAY_TYPE) and choose: (a) kernel IOMobileFramebuffer service + IOSurface, or (b) a VirtualDisplay rendered by CA's CPU path (CA::OGL::SW) and copied to the framebuffer.
- **watchdogd + CommCenter + identityservicesd fixed (boot 0045n on v6, 20:41:30 UTC, frames VID_20261016_224133 00:39-01:13, slide 0x20fec000).** `SWEET WDT: watchdogd sel 0 in 0/0 out 1/0 -> ok`, no watchdogd/CommCenter/identityservicesd crashes (CommCenter/identityservicesd now call AKS 0/17/7). usermanagerd boot task runs (UMD_INIT creates primary session uid 501 "mobile", personas 99 System and 199 Default registered with the kernel); `Failed to atomically swap writing file /private/var//keybags/usersession.kb: Operation not supported (45)` (HFS lacks the atomic swap rename; non-fatal so far). Remaining: SpringBoard (FBSDisplayMonitor, no display), backboardd (uncaught exception), mediaserverd, lockdownd (crash inside obfuscated code, main+0x4c1b4?), logd. **logd**: main+0x18160 = `BUG IN LIBTRACE: Failed to migrate directory` from 0x10001801c(dir 0): 0x100016538 requires the dir to exist with uid/gid/mode from the table at 0x10002df14 (0: /private/var/db/diagnostics 272:272 0751, 1: /private/var/db/uuidtext 272:272 0755, 2: /private/var/db/diagnostics/timesync 272:272 0755) plus a `.migrated` file, else XPC "operation 6" to a helper and crash. **Image v7** = v6 + those dirs/markers (also in mkiosroot.sh), SHA256 in `ios16-root-20H392-v7.img.sha256`, `.simg` ready. Boot with `shim/out/shim-boot-0045n.img`.
- **Exit-reason text works (boot 0044n, frames VID_20261016_221726 00:32-00:53, slide 0x22d5c000).** CommCenter/identityservicesd: `couldn't dlopen libobjc-trampolines.dylib: dlopen(/usr/lib/libobjc-trampolines.dylib, 0x0106): tried: '/usr/lib/libobjc-trampolines.dylib' (no such file, not in dyld cache)`: the file only exists in the OS cryptex and dyld does not search cryptexes at ignition_level=1. 19 cryptex files have no root counterpart (OS: DriverKit dyld cache + .symbols, VisualTestKit, libffi-trampolines, libobjc-trampolines, libstdc++ 6.0.9 + 2 symlinks; App: SafariSupport.bundle, AuthenticationServicesAgent, com.apple.Safari.History, passwordbreachd, safarifetcherd, webbookmarksd, webinspectord, webpushd) -> hard-linked (symlinks copied: Linux hfsplus cannot hard-link symlinks); `tools/mkiosroot.sh` does it generically. watchdogd still crashed: the `-wdt_no_pmu` / `/arm-io/wdt no-pmu` check (0x10000a01c) only runs when os_variant_has_internal_diagnostics; otherwise 0x100009b18 looks up IOServiceMatching("IOService") + IOPropertyMatch {IOPMUPrimary: 1} (NSConstantDictionary) and crashes if absent, then IORegistryEntrySetCFProperty(boot stage 0xff) (failure only logged). Patch **0045**: IOWatchdog sets IOPMUPrimary = 1 and accepts setProperties; CI `38961814194` -> `xnu/out-0045`. **Image v6** = v5 + the 19 cryptex links, SHA256 7c610c6a...297a, `ios16-root-20H392-v6.simg` (full flash needed). Boot image `shim/out/shim-boot-0045n.img` (0045 + sweet-0044hi.adt). Still open: SpringBoard (no display), backboardd (uncaught exception, reason none), mediaserverd (Fig NULL dict), logd (main+0x18160), lockdownd (main+0x4c1b4).
- **System survives daemon crashes (boot 0043p, video frames VID_20261016_215006 00:25/00:42/00:54).** With the v5 plist patch no panic: launchd keeps launching (runningboardd, powerd, tccd, healthd, peopled, cryptexd, routined, aksd, mediaremoted, familynotificationd, nanoprefsyncd, navd, cloudpaird, passd, amsaccountsd, accessoryupdaterd, wcd ...). Shared cache slide that boot 0x406b4000 (`research/crash-0043p.txt`). watchdogd still crashed at main+0xb82c from the PMU step: `-wdt_no_pmu` is only honored when os_variant_has_internal_diagnostics; customer builds read `no-pmu` from IODeviceTree:/arm-io/wdt (IORegistryEntrySearchCFProperty) -> mkadt adds /arm-io/wdt {no-pmu}. **cryptexd** sig 6: abort_with_payload <- os_crash_fmt <- `__darwin_arm_secure_boot_chip.cold.7` ("panic: failed to get crypto algorithm") <- `_img4_chip_select_personalized_ap`: reads /chosen use-ddi-secure-boot, allow-ecid-mismatch, crypto-hash-method ("sha1" | "sha2-384"), /chosen/asmb lp-smb0/1 -> mkadt adds crypto-hash-method "sha2-384". **identityservicesd** sig 6 = same `_objc_fatal` in imp_implementationWithBlock as CommCenter (block trampolines; message needed). lockdownd sig 5 at main+0x4c1b4. Patch **0044**: crash report adds `CRASH name reason ns N code X: text` (exit reason description = abort_with_payload text). CI `38959096811` -> `xnu/out-0044`, QEMU OK. Image `shim/out/shim-boot-0044n.img` = 0044 + `shim/out/sweet-0044hi.adt` (wdt no-pmu, crypto-hash-method) + cmdline (wdt=-1, no -wdt_no_pmu).
- **First symbolicated daemon crashes (boot 0043u on journaled v4, 19:38:53 UTC; video frame chat image 36; transcribed in `research/crash-0043u.txt`; shared cache slide 0x40d60000 for every process).** (Gemini's video transcription invented values, use frames only.) `tools/sweet-crash.py research/dsc/dyld_shared_cache_arm64 x research/crash-0043u.txt`:
  - **watchdogd** pc main+0xb82c (`_os_crash` trap helper) from 0x100009bb0 = set PMU boot stage via IORegistry (no PMU) -> fix: boot-args `wdt=-1 -wdt_no_pmu` (Apple's own test mode writes "%s wdt=-1 -wdt_no_pmu"; watchdogd logs "skipping setting PMU boot stage because -wdt_no_pmu found in boot-args or no-pmu found in EDT"). Kernel effect of wdt=-1: sched hygiene debug off, zone_exhausted_timeout -1 (harmless).
  - **SpringBoard** sig 5 in `-[FBSDisplayMonitor _initWithBookendObserver:transformer:]+1160` <- `+[FBDisplayManager sharedInstance]` <- `FBSystemShellInitialize` <- `SBSystemAppMain`: no main display. GUI WALL: display service (IOMobileFramebuffer / CoreAnimation display).
  - **backboardd** sig 6: abort <- std::terminate <- _objc_terminate (uncaught exception; message not shown).
  - **CommCenter** sig 6: `_objc_fatal` in `imp_implementationWithBlock` (from `+[_PFRoutines initialize]`, CoreData): objc block trampolines cannot be allocated -> likely kernel gap (trampoline page remap); will hit many processes.
  - **mediaserverd** sig 11: CFDictionaryGetValue(NULL) in FigNotificationListenerStartNotifications (routing session manager).
  - **logd** sig 5 at its main+0x18160 (bt main+0x9dfc); lockdownd sig 5 (not yet symbolicated).
  - Image v5 = v4 + launchd.plist (`/System/Library/xpc/launchd.plist`, contiguous at image offset 0x1e025f000, 1456980 bytes) with the 7 `_PanicOnCrash` keys renamed `_PanicOnCrasX` in place (raw image patch, no metadata change) -> `diff-v4-v5.simg` = 7 blocks; v5 SHA256 78f96974...185a. Boot image `shim/out/shim-boot-0043p.img` = 0043 + `wdt=-1 -wdt_no_pmu`.
- **0043 console crash reports (QEMU verified); image `shim/out/shim-boot-0043u.img`; NEXT: flash v4 + boot 0043u.** Boot 0042u (video photo IMG_20261016_211646): short exec lines work; watchdogd crashes with NO `SWEET WDT:` line (fails before its first IOWatchdog call: lookup or IOServiceOpen, or elsewhere); lockdownd, SpringBoard, mediaserverd, CommCenter, identityservicesd, backboardd, watchdogd all crash repeatedly ("Too many corpses being created" = corpse limit, no crash reports). AKS callers: lockdownd (0, 7), imagent/sleepd (0, 17, 7), backboardd (0, 17), UserEventAgent (0, 7, 102, 103 -> unsupported). Patch **0043**: `sweet_crash_log` (osfmk/kern/exception.c, called from proc_prepareexit for crash exits on the current proc) prints `CRASH name[pid] sig S code (exc<<32|code) sub X slide SR mh MH`, `CRASH name pc lr sp fp far`, `CRASH name bt` (10 fp frames); AKS sel 103 notify_state_is_set -> 0. CI `38954520419` -> `xnu/out-0043`. QEMU test: init forks, child `brk #1`: `CRASH launchd[2] sig 5 code 0x600000001 sub 0x1000004f0 slide 0x0`, pc correct, parent keeps running (pid 1 crashes panic before proc_prepareexit, so test with a child). `tools/sweet-crash.py CACHE ROOT [report]` symbolicates typed-in CRASH lines (`ipsw dyld a2s` with addr - slide; main binary offsets = addr - mh + 0x100000000).
- **v3 reflashed 18:50-18:55 UTC (`research/flash-userdata-v3b.log`, 24/24 OKAY); 0042u booted 19:01:17 UTC on the clean disk (`research/boot0042u-2.log`), SLOW MO VID pending (watchdogd failure reason).** ABL hangs on the first `fastboot boot` after every big flash; user re-enters fastboot. User gave standing approval to reflash/boot without asking (memory standing-flash-approval). Commits now end with `Co-Authored-By: dipa-studio <183933817+dipa-studio@users.noreply.github.com>` (user request; never a Claude trailer).
  - watchdogd flow: connect_to_kext (0x100005408): IOServiceGetMatchingService("IOWatchdog") fails -> "failed to discover" + _os_crash; IOServiceOpen(type 1) fails -> "IOServiceOpen failed with error : 0x%x" + _os_crash. Then sel 0 (out 1 scalar): 0 -> "userspace monitoring disabled", 0x100009bb0, sleep 2, exit(0); nonzero -> "userspace monitoring enabled", normal operation.
  - **Image v4 (JOURNALED):** `tools/mkiosroot.sh` now does `mkfs.hfsplus -J`, mounts with `-o loop,force`, adds the /System/Library/Caches/com.apple.dyld hard links (44) and /private/var/keybags/systembag.kb (0700/0600 root). Built from the IPSW dmgs (OS 087-86698-044, SystemOS 087-86593-047, AppOS 087-86715-047) -> `/run/media/dipa/android/ios-sweet-ipsw/ios16-root-20H392-v4.img` SHA256 fba4aeae...ec0f9 + `.simg`. Header: attr 0x80002100 (unmounted, journaled), journal info block 129, journal 8 MiB at 532480 flagged need-init. Linux `fsck.hfsplus -n` reports "Volume header needs minor repair" on any fresh journaled volume even after -y (quirk). QEMU: 64 MB journaled test root (`rd=md0 rootrw=1`, 0042 kernel): `hfs: Initializing the journal (joffset 0x3000 sz 0x80000)` -> mounted -> init runs, no panic. NEXT: flash v4 (full), boot 0042u.
- **SPRINGBOARD STARTS (boot 0041u 18:39:53 UTC, photo IMG_20261016_204142).** backboardd, bluetoothd, fairplayd.H2, SpringBoard (pid 111, crashed: "Too many corpses"), xpcproxy run; `SWEET AKS: backboardd sel 0 -> 0`, `sel 17 in 1/0 out 0/4096 -> 0`. Panic: watchdogd[113] exited, namespace 2 subcode 5 (SIGTRAP = its _os_crash): watchdogd crashes on purpose when IOServiceGetMatchingService("IOWatchdog") fails ("connect_to_kext() unexpectedly failed") or IOServiceOpen(type 1) fails ("IOServiceOpen failed with error"); IOWatchdog DOES register (QEMU msgbuf: `SWEET WDT: IOWatchdog registered`), cause not on screen yet -> need video. Note `wdt_test=no_user_checkin` makes watchdogd log "detected testing boot-args to not run, exiting" (path not reached here?). **HFS CORRUPTION:** `hfs_swap_BTNode: offset #0 invalid (0xBC1D) (blockSize 0x2000 numRecords 81)`, `node=19677 fileID=4` (catalog), `hfs_mark_inconsistent` repeated. Likely cause: non-journaled HFS + unclean panics while writing (0038e wrote a 2.7 GB core then panicked; every boot since ends in panic). Plan: reflash v3 (clean), longer term HFS journaling. Patch **0042**: one short `exec NAME` console line instead of the 3-line "Allowing spawn of iOS binary" notice; CI `38949451276` -> `xnu/out-0042`; image `shim/out/shim-boot-0042u.img` (same cmdline as 0041u).
- **LAUNCHD DAEMONS RUN (boot 0039u, 18:29:13 UTC, photo IMG_20261016_203052).** With `launchd_unsecure_cache=1` all boot tasks pass and launchd starts LaunchDaemons (pids > 100: identityservicesd 114 and lockdownd 106 crash, "Too many corpses being created"). Fatal: `watchdogd: ERROR: failed to discover watchdog KEXT service` -> exit (namespace 2 = signal, subcode 5) -> `_PanicOnCrash` panic. watchdogd: IOServiceMatching("IOWatchdog"), IOServiceOpen type 1, IOConnectCallScalarMethod sel 0/1 (check in)/3/4 (disable/enable userspace monitoring)/5, IOConnectCallStructMethod sel 2 (1 KiB in) and 9 (small out); VM path ("detected virtual machine environment and no watchdog KEXT found, exiting...") only when it detects a VM. Console also flooded with `hfs: set hardlink bit on vol=iOSRoot cnid=321318` (Linux-made hard links lack kHFSHasLinkChainBit; repaired only in memory on each lookup). Patches **0040** (`iokit/Kernel/arm/SweetWatchdog.cpp`: IOWatchdog + IOWatchdogUserClient, all selectors succeed with zeroed outputs, each logged once as `SWEET WDT: ...`) and **0041** (sweet_hfs hfs_catalog.c: the three link-repair printfs limited to 8 per boot); CI `38948245372` PASSED -> `xnu/out-0041` (QEMU regression OK). Image `shim/out/shim-boot-0041u.img` (0041 + sweet-0038hi.adt + ufsrw rootrw + launchd_unsecure_cache=1) booted 18:39:53 UTC (`research/boot0041u.log`), photo pending.
- **v3 FLASHED + keybag passes; next wall AMFI (launchd_cache_loader).** User said "flash, nothing to lose": `fastboot -S 512M flash userdata ios16-root-20H392-v3.simg` 17:51:52-17:57:01 UTC, 24/24 chunks OKAY (`research/flash-userdata-v3.log`). userdata = v3 (SHA256 fa84274c...22df) until the next rw boot. ABL fastboot then hung ("Sending" forever, `reboot bootloader` timed out) until the user re-entered fastboot by hand (common Xiaomi ABL crash). Boot 0038e 18:06:15 UTC (`research/boot0038e-3.log`), photos IMG_20261016_200812/200838: keybag OK, then boot tasks tzinit (`Bad zoneinfo link`, resets to system partition, OK), finish-restore, finish-demo-restore, sysstatuscheck, prng_seedctl (`failed to load kernel prng seed`, `failed to load virtual random (-147)`, AllowCrash), auearlyboot, then **launchd_cache_loader: `abort: Unable to find AMFI`** -> 2.7 GB core written to /cores in 91 s -> launchd panic `launchd_cache_loader[22] exited -- exit reason namespace 7 subcode 0x1`. launchd_cache_loader: SecStaticCodeCheckValidity of /System/Library/xpc/launchd.plist with detached .sig, then IOServiceMatching("AppleMobileFileIntegrity") + IOServiceOpen type 0 + IOConnectCallMethod sel 6 (1 scalar = 1, struct in = cdhash) = trust the cdhash, then sends the cache to launchd. Boot-arg `launchd_unsecure_cache=1` skips signature + AMFI ("Using unsecure cache"); the value is parsed with strtoul base 10 (helper 0x100002da8), so a path = 0 = off: boot 0039w (18:17:13 UTC, `=/System/Library/xpc/launchd.plist`, photo IMG_20261016_202008) still aborted `Unable to find AMFI` (core dump now skipped: `Failed to generate core file ... error 14`, so 0039 works). Image `shim/out/shim-boot-0039u.img` uses `launchd_unsecure_cache=1`. Patch **0039**: do_coredump = 0 on SWEET (kern.coredump sysctl still works); CI `38945267341` -> `xnu/out-0039` (_do_coredump now in __common). Image `shim/out/shim-boot-0039w.img` = 0039 + sweet-0038hi.adt + ufsrw rootrw + `launchd_unsecure_cache=/System/Library/xpc/launchd.plist`. TODO later: real AppleMobileFileIntegrity IOService (sel 6 trust cdhash etc.).
- **Image v3 ready, awaiting user "flash".** Boot 0038w 17:38:10 UTC, photo (chat image 30): `SWEET AKS: keybagd sel 0 -> 0x0`, `sel 14 out 1/0 -> 0x0` (x2), `MKB_INIT: mount is with NO CPROTECT ... does not support Data Protection`, `System Keybag loaded`; then keybagd still opens /private/var/keybags/systembag.kb (0x100012d3c, for BackupKeyBagKeys) -> ENOENT, `no-effaceable-storage` not set -> `Can't load the keybag. tears in rain... Time to die` -> `FATAL KEYBAG ERROR: kb_load` -> reboot -> Halt/Restart Timed Out panic. Fix: ADT `/defaults/no-effaceable-storage` (mkadt.py; `shim/out/sweet-0038hi.adt`, `research/q0038-hi.adt`, QEMU OK) + file `/private/var/keybags/systembag.kb` (0600 root, dir 0700; XML plist {KeyBagKeys: data}). **v3 image** `/run/media/dipa/android/ios-sweet-ipsw/ios16-root-20H392-v3.img` = v2 + that file, fsck OK, SHA256 fa84274c...22df; `ios16-root-20H392-v3.simg` (img2simg: zero blocks become FILL chunks, so a full flash overwrites every block the rw boots changed). Flash: `fastboot -S 512M flash userdata ios16-root-20H392-v3.simg`, then boot `shim/out/shim-boot-0038e.img` (0038 + sweet-0038hi.adt + ufsrw=1 rootrw=1).
- **0038 AppleKeyStore (CI 38938744130 PASSED -> `xnu/out-0038`; QEMU msgbuf: `SWEET AKS: AppleKeyStore registered (no passcode, unlocked)`; phone image `shim/out/shim-boot-0038w.img` booted 17:38:10 UTC, `research/boot0038w.log`, photo pending).** QEMU full kernel log trick (fb.txt is only the last screen): `llvm-nm KERNEL | grep _msgbufp` -> `--hmp "x /1gx ADDR"` gives struct msgbuf address (static, 0xfffffe0007b56678 on 0038) -> `--hmp "x /3gx STRUCT"` gives bufc (3rd quad) -> `--hmp "memsave BUFC 0x20000 \"FILE\""` (quote the file name), `tr -d "\0" < FILE`. Same inputs give the same addresses. Boot 0037w 17:08:35 UTC, photo IMG_20261016_191052: bindfs fixed mount; mount-phase-1/2 pass; `cc_fips_test` boot task: all corecrypto FIPS POST tests PASSED in userspace; then keybag boot task `keybagd --init`: `MKB_INIT: FATAL KEYBAG ERROR: failed to load system bag`, `Could not get options entry from the device tree` (x2, IODeviceTree:/options = NVRAM, non-fatal), `REBOOTING INTO RECOVERY MODE` -> reboot -> panic `Halt/Restart Timed Out @IOPlatformExpert.cpp:884` (no restart path on SWEET).
  - keybagd (static libaks): load_devicebag (0x100012c30) calls aks_get_system (sel 14, 0-1 scalar in, 1 out) and loads /private/var/keybags/systembag.kb only if the result is 0xe00002f0 (NotFound); any other error -> fatal; SUCCESS -> skip the file (userspace-reboot path). systembag.kb is a plist {KeyBagKeys}; decrypted with effaceable storage unless IODeviceTree:/defaults has `no-effaceable-storage`. Image has no /private/var/keybags. has_data_protection: statfs of /private/var; no cprotect on our HFS -> device-bag volume mapping skipped.
  - libaks connection: IORegistryEntryFromPath / IOServiceMatching("AppleKeyStore"), IOServiceOpen type 0, then selector 0 (no args) must succeed.
  - **AppleKeyStore selector map (iOS 16.7 AppleKeyStore.framework, via `ipsw dyld disass`):** 0 open, 2 create_bag, 3 save_bag, 4 unload_bag, 5 set_system_with_passcode, 6 load_bag, 7 get_lock_state (1 in, 1 out; bit 2 = unlocked since boot), 9 unlock_device, 10 wrap_key, 11 unwrap_key, 12 unlock_bag/test_stashed_kek, 13 lock_bag, 14 get_system, 15 change_secret_se, 16 internal_state, 17 get_device_state (1 in, struct out <=4K: DER SET of SEQUENCE{UTF8 key, INTEGER}: ss state, sls lock_state (MKBGetDeviceLockState returns it), sb backoff, sbo, sfa failed attempts, sfao, sgs generation, sas assertions, sgpe grace, srcd countdown, sr reserved), 18 recover_with_escrow_bag, 19 obliterate_class_d, 20 drain_backup_keys, 21/22 set/clear_backup_bag, 23 get_bag_uuid, 24 rewrap_key_for_backup, 26/27 assert_hold/drop, 30/31 set/get_configuration, 33-37 stash, 38 auth_token_create, 40 generation, 41 fdr_hmac_data, 42 verify_password, 43 _aks_operation, 44 remote_session, 49/50 signing keys, 51/53/54 stash enable/persist/escrow, 55 unload_session_bags, 57/58 remote peer, 59-62 smartcard, 63 migrate_s_key, 65 set_keybag_for_volume_with_cookie_persona, 66/67 sync bags, 68 copy_volume_cookie_persona, 69-73 se_*, 74-79/84/85/99 fv_* (FileVault/VEK), 80/81 absinthe, 82 make_public_backup_bag, 83 drop_auxiliary_auth, 86 kext get/set options, 87 invalidate_bag, 88-91/94/95/106/107 se_*, 92 lower_iteration_count, 93 get_internal_info, 96-98/117 keybag_persona create/list/delete, 100/101 assert promote/consume, 102/103 notify_state set/is_set, 104 fairplay, 105 change_secret_epilogue, 108 delete_xart_leak, 110-113 backup volume, 114 sealed_hashes_set, 115 prewarm_sps, 118-128 AKSIdentity*/AKSGetLastUser.
  - Patch **0038**: `iokit/Kernel/arm/SweetKeyStore.cpp` (class AppleKeyStore on IOResources, IOUserClientClass AppleKeyStoreUserClient; personality in KernelConfigTables.cpp): 0/4/5/9/12/13/26/27/55/102 success, 14 -> handle 0, 7 -> 0x4, 17 -> DER state (ss 4, sls 0), others kIOReturnUnsupported; logs `SWEET AKS: <proc> sel N arg0 in a/b out c/d -> ret` for every call.
  - Tools: shared cache copied to `research/dsc/` (git-ignored; ipsw needs a writable dir for its .a2s symbol cache); `ipsw dyld disass research/dsc/dyld_shared_cache_arm64 --image AppleKeyStore|MobileKeyBag`; scratchpad `annot2.py BIN DIS FIXUPS` annotates llvm-objdump output with strings and import names (`ipsw macho info --fixups`).
- **0037 bindfs (phone boot 0037w pending photo).** Boot 0036mw 16:57:47 UTC, photo IMG_20261016_190102: WRITABLE ROOT WORKS: `/dev/ufsroot0 on / (hfs, local, noatime)` after mount_hfs update (GetMasterBlock EBUSY harmless), coredump of mount written to /cores (rw). Then `mount: failed to mount /private/preboot/5CBE3601.../usr/standalone/firmware -> ...: Operation not supported by device (19)` -> exit 74 -> launchd panic `mount[2] exited`. Cause: the macOS-derived config had nullfs but no bindfs (ENODEV = unknown fs type). Caller passes env 0 -> bind not required, ENOENT (missing source dir) tolerated. Patch **0037** adds `bindfs` to FILESYS_BASE in MASTER.arm64.sweet; CI `38936550483` -> `xnu/out-0037` (bindfs_vfsops present; QEMU probe regression OK). Image `shim/out/shim-boot-0037w.img` (0037 + sweet-0036hi.adt + ufsrw=1 rootrw=1) booted 17:08:35 UTC (`research/boot0037w.log`). NOTE: userdata has now been modified by rw boots; it no longer equals the v2 image, so sparsediff with v2 as OLD is not safe any more (full reflash or a new baseline needed).
- **0036 phone: launchd boot tasks run; mount -P 1 needs /chosen/boot-manifest-hash.** Boot 0036hr 16:15:32 UTC, photo IMG_20261016_185236: platform check passes; fsck boot task runs (`fsck: not booting main or diagnostic OS. Skipping fsck on OS container`); mount-phase-1: `failed to get filesystem info` x2 (no IODeviceTree:/filesystems/fstab, non-fatal), `mount: data volume missing, but not required in env: 0`, mount_hfs update of /: `GetMasterBlock: Error 16 opening /dev/ufsroot0` (EBUSY, mounted block dev, non-fatal) then mount() EROFS (read-only boot) -> `mount: / failed with 1`; then `failed to get boot-manifest-hash` -> errx exit 66 -> launchd panic `mount[3] exited`. /sbin/mount: fn 0x100005f90 reads IODeviceTree:/chosen boot-manifest-hash (hex), bindfs-mounts /private/preboot/<HEX>/usr/standalone/firmware (ENOENT tolerated unless required). `tools/mkadt.py` now adds `boot-manifest-hash` = SHA-384("sweet boot manifest") (5CBE3601...5205). ADTs `shim/out/sweet-0036hi.adt`, `research/q0036-hi.adt` (QEMU probe OK, csops 0x26000001). Image `shim/out/shim-boot-0036mw.img` (0036 + new ADT + ufsrw=1 rootrw=1), booted 16:57:47 UTC (`research/boot0036mw.log`): FIRST WRITABLE BOOT of userdata (restore source: v2 image on SSD).
- **0036 CS_SIGNED (phone boot 0036hr pending photo).** Phone boot 0035hr 2026-10-16 15:57:02 UTC (`research/boot0035hr.log`, photo IMG_20261016_180249): highmem works on hardware; shared cache maps (trust-cache warnings only), Apple launchd runs (`Darwin Bootstrapper Version 7.0.0`, `entering ondemand mode`), starts boot task fsck, then userspace panic `boot task is not a platform binary (fsck, /sbin/fsck)`. launchd+0x3fea0: `csops(pid, CS_OPS_STATUS)` must have bit 0x04000000. Cause: nothing set CS_SIGNED (AMFI does it in vnode_check_signature), so csproc_get_blob() returns NULL for every process and csops never reports CS_PLATFORM_BINARY (also breaks per-process cdhash/entitlement queries). QEMU probe init (`csops` status printer, scratchpad csq/) on 0035: `0x02000001`; patch **0036** (`*cs_flags |= CS_SIGNED` in the SWEET AMFI hook), CI `38929635791` -> `xnu/out-0036`: `0x26000001`. Images `shim/out/shim-boot-0036hr.img` / `-0036hw.img` (same cmdlines as 0035). 0036hr booted 16:15:32 UTC (`research/boot0036hr.log`). Next launchd boot tasks (embedded __config plist): fsck -qL and mount -P 1/2 (RequireSuccess); no /etc/fstab on the image.
- **0035 ENTITLEMENTS + PLATFORM BINARIES (QEMU verified).** `xnu/patches/0035-sweet-amfi-entitlements-platform-binaries.patch`: new `iokit/Kernel/arm/SweetEntitlements.cpp` (OSObject subclass: OSDictionary from OSUnserializeXML of the signature's XML entitlements + original XML for CS_OPS_ENTITLEMENTS_BLOB); `bsd/kern/sweet_amfi.c` answers queryEntitlementBoolean/String(+WithProc, string also matches array members), copyEntitlementAsOSObject(+WithProc, retained), asdict (retained), get_xml (kalloc_data copy); built-in MAC policy "SWEET AMFI" (registered from bsd_init before vfs/exec) with mpo_vnode_check_signature: every signed binary on the MNT_ROOTFS mount gets CS_PLATFORM_BINARY (stand-in for AMFI's static trust cache: iOS system binaries are ad-hoc, cd_flags 0x2, platform byte 0), and attaches entitlements ONLY for the writable copy (cs_blob != csb_ro_addr; revalidation passes the RO blob). LESSON: first version attached in adjustContextWithoutMonitor -> QEMU `unable to adjust OSEntitlements context without monitor: 53` because ubc_cs_convert_to_multilevel_hash (4K-page signatures on 16K kernel) sets csb_entitlements_blob = NULL; ALL iOS 16 binaries (launchd, backboardd, SpringBoard) use 4K code pages, so this would have broken launchd on the phone. Boot-arg `sweet_amfi_debug=1` logs `SWEET AMFI: <ident>: N entitlements (test: ...)`. `tools/mkinit.py OBJ OUT [ENTS.plist]` adds an XML entitlements blob (special slot -5; default output byte-identical). QEMU `research/q0035-ent` (RAM disk `research/root-hfs-ent.img`, init with 3 test entitlements, highmem): `org.sweet.init: 3 entitlements (test: bool 1 string 1 array 1)` then init PID 1. MAC policies loaded: 0034 = 1, 0035 = 2 (QMP `mac_policy_list`). CI `38909807230` -> `xnu/out-0035`. Phone images: `shim/out/shim-boot-0035hr.img` (highmem, ro), `-0035hw.img` (highmem, +ufsrw=1 rootrw=1), `-0035r.img` (low mem fallback).
- **PHONE TEST ORDER (updated):** 0035hr -> if instant reset, 0035r -> then 0035hw.

- **HIGHMEM: XNU in the upper DDR bank, ~3.95 GiB (was 1.2 GiB).** Live FDT memory = <0x80000000 2G> + <0x1_00000000 0xfcc00000>; all fixed reserved-memory carve-outs are in the low bank (highest: ramdump_fb 0xaf000000, rmtfs ~0xfde01000), dynamic pools have alloc-ranges <= 0xffffffff, UFS node has no `iommus` (Linux DMAs anywhere). `tools/mkadt.py --highmem` sets /chosen dram-base 0x100000000 dram-size 0xfcc00000; `tools/mkpayload.py` now takes phys_base/mem_size from the ADT (default payloads byte-identical, verified); `tools/qemu-sweet.py` sizes -m from the payload (8G for highmem). Patch **0034** (`0034-sweet-ufs-dma-above-4g.patch`): UFS refuses DMA memory above 4G without UFSHCI CAP.64AS (bit 24), logs `DMA at 0x...`. CI `38905889883` success -> `xnu/out-0034`. **QEMU verified** (`research/q0034-hi`, ADT `research/q0034-hi.adt` --qemu --highmem, HFS RAM disk): phys_base 0x100000000, init PID 1 heartbeat, no panic; `max_mem` = `mem_size` = 0xfcc00000 read via QMP (`research/q0034-hi-mem`). Phone images: `shim/out/shim-boot-0034hr.img` (read-only) / `-0034hw.img` (+ufsrw=1 rootrw=1), ADT `shim/out/sweet-0034hi.adt` (asmb SIP + sweet-ufs + highmem). PHONE RISK: unknown runtime TZ/XPU protection in the upper bank would show as an instant reset; fall back to 0033r/w. Watchdog ruled out for the overnight reset: msm-watchdog bark is 20 s (qcom,bark-time 0x4e20) yet panic screens stay up for many minutes.

- **Offline research 2026-10-16 (user away, phone unavailable). Images rebuilt** `shim/out/shim-boot-0033r.img` / `-0033w.img` now also carry `wdt_test=no_user_checkin`. NEXT ON PHONE: boot 0033r (expect past in6_nigroup), then 0033w (first writes: rw root fixes HFS link-chain bits itself and gives /var for launchd sockets /var/run/syslog, /var/run/lockdown.sock).
- **launchd.plist** (`/System/Library/xpc/launchd.plist`, compiled; 532 daemons, 66 RunAtLoad/KeepAlive, list in scratchpad `early-daemons.txt`). `_PanicOnCrash` daemons: containermanagerd/usermanagerd (InternalOnly), lockdownd/remoted/trustd/remotepairingdeviced (AutomationOnly), **watchdogd unconditional** (KeepAlive SuccessfulExit=false). watchdogd needs IOKit `IOWatchdog` kext service; if absent it exits only when `kern.hv_vmm_present` (ADT `/defaults/vmm-present`, hvg_sysctl.c) or with boot-arg `wdt_test=no_user_checkin` ("detected testing boot-args to not run, exiting"; reads kern.bootargs). Using the boot-arg (vmm-present would change many daemons; keep as an option).
- **GUI path research (QuartzCore in the shared cache, `ipsw dyld str CACHE STR`, ~10 s/search):** CA::WindowServer has IOMFBServer/IOMFBDisplay (Apple DCP/IOMobileFramebuffer), AppleCLCDDisplay, AppleRGBOutDisplay, **VirtualServer/VirtualDisplay** and **MemorySurface**, EAGLServer. Renderers: CA::OGL::MetalContext, GLContext and a **CPU software rasterizer CA::OGL::SW** (samplers/blend modes; "image is too large for software renderer"). Env knobs: `CA_ENABLE_OGL`, `CA_DISPLAY_TYPE`, `CA_FORCE_LOCAL_SERVER` (249 CA_* vars). Hypothesis (unverified): backboardd's render server could run a VirtualServer/MemorySurface with the SW renderer and we copy the surface to the ABL framebuffer -> needs disassembly of CA::WindowServer server creation. Expected other GUI walls: IOSurface (closed-source kext; needs a reimplementation), IOMobileFramebuffer user client, IOHID touch events, AppleKeyStore/keybag (SEP) for lock state, MobileGestalt answers (AppleCLCD etc.).

- **0032r RESULT (boot 05:07:50 UTC, `research/boot0032r.log`, photo IMG_20261016_071200): SHARED CACHE MAPPED, LAUNCHD RUNS.** With SIP relaxed (ADT asmb) the `not in trust cache` lines are only warnings for every subcache (.31 ... .42.dyldlinkedit); no SIP rejection; libSystem loads; launchd configures networking (`skip attaching fsw to lo0 using legacy TX model`) -> kernel data abort far 0x28 in `SHA1Init` (symbolized as sha1_init) from `in6_nigroup` (IPv6 on lo0): g_crypto_funcs NULL. Kernel addresses are unslid: `~/swift/usr/bin/llvm-symbolizer --obj=KERNEL ADDR` works directly.
- **0032** BearSSL SHA-1 (`0032-sweet-bearssl-sha1.patch`), **0033** BearSSL SHA-384/512 (`0033-sweet-bearssl-sha384-sha512.patch`, BearSSL ctx stored in SHA512_CTX, static-asserted to fit; ubc_subr.c uses SHA-384 for code directories). `0020-stage-bearssl.sh` now also stages hash/sha1.c, hash/sha2big.c, codec/{dec,enc}{32,64}be.c. CI `38854909053` success (0032-only run `38854802073` superseded). Kernel `xnu/out-0033` (SHA1Init -> _br_sha1_init verified by disassembly; nm symbols have a leading underscore). Images (ADT sweet-0032): `shim/out/shim-boot-0033r.img` (read-only), `shim-boot-0033w.img` (+ufsrw=1 rootrw=1). Still NULL g_crypto_funcs users: des, chacha20poly1305, rsa, aesxts, rand, flow_divert.
- `research/check-patch-order.py` now skips patches touching CI-staged sweet_hfs sources (0031) instead of stopping.

- **0031r RESULT (boot 05:03:52 UTC 2026-10-16, `research/boot0031r.log`, photo IMG_20261016_070508): SHARED CACHE FOUND.** dyld now opens `dyld_shared_cache_arm64` (v2 image hard links), kernel refuses to map it: `shared_region: ... map(...'dyld_shared_cache_arm64'): not in trust cache` -> `vnode is not SIP-protected` (vm_unix.c: macOS arm64 path needs trust cache, else root-owned + SF_RESTRICTED unless CSR_ALLOW_UNRESTRICTED_FS) -> `dyld cache '(null)' not loaded: syscall to map cache into shared region failed` -> libSystem not loaded -> coredump to /cores fails error 30 (EROFS) -> panic initproc failed -> "MACH Reboot" (spins; screen kept). Lots of `hfs: set hardlink bit on vol=iOSRoot cnid=... linkid=...` spam (Linux-made hard links lack the link-chain bit; read-only mount cannot persist the fix). FIX: ADT `/chosen/asmb` with `lp-sip0`=0x6f (u64; incl. CSR_ALLOW_UNRESTRICTED_FS) and `lp-sip1`=1 (unauthenticated root), `tools/mkadt.py` -> `shim/out/sweet-0032.adt`. Images with kernel 0031: `shim/out/shim-boot-0032r.img` (read-only) and `shim-boot-0032w.img` (+ufsrw=1 rootrw=1).

- **2026-10-16 morning:** userdata now = **v2** image (`diff-v1-v2.simg` flashed 21:06:50 UTC 2026-10-15, OKAY, `research/flash-userdata-diff-v2.log`); future diffs use `ios16-root-20H392-v2.img` as OLD. Booted `shim-boot-0029k.img` (ignition_level=1) right after (`research/boot0029k-v2.log`); **no photo** (user asleep). Next morning the phone was in PixelOS recovery = some hardware reset (ABL then booted Android, which cannot use userdata). OBSERVATION: our kernel cannot reset the SoC itself (`PE_halt_restart` is never set; reboot/halt print "MACH Reboot"/"CPU halted" and spin), so the reset came from outside XNU: Qualcomm watchdog or a TZ/XPU violation. Unknown which; re-boot 0029k and watch/video until the reset. Do NOT tap factory reset/format data in recovery (would wipe the iOS image).
- **0030** (`xnu/patches/0030-sweet-ufs-writes.patch`, CI `38852655542`): UFS WRITE(10) + read-modify-write for partial 4 KiB blocks + SYNCHRONIZE CACHE (DKIOCSYNCHRONIZE), only with boot-arg `ufsrw=1`; `ufs_write_blocks` re-checks partition bounds before every write (only place data goes out).
- **0031** (`xnu/patches/0031-sweet-read-write-root.patch`, CI `38852837176`): boot-arg `rootrw=1` clears MNT_RDONLY before the root mount (no data volume on sweet: /private/var is on the root; image has no /etc/fstab); Apple HFS accepts a dirty non-journaled ROOT read-write on SWEET (logs "mounting dirty non-journaled root read-write"). Later: journaled HFS for crash safety. Kernel `xnu/out-0031` (CI `38852837176` success, 5m31s; 0030 run cancelled by the newer push). Boot images (phone ADT `sweet-0028.adt`, ramdisk byte-matched): `shim/out/shim-boot-0031r.img` = 0029k args (read-only, ignition_level=1) and `shim/out/shim-boot-0031w.img` = same + `ufsrw=1 rootrw=1`. PLAN: boot 0031r first and film until the reset (diagnose overnight reset), then 0031w (first ever writes to userdata; v2 image on the SSD is the restore source). `research/check-patch-order.py` cannot check 0031 (staged sweet_hfs files are not in its index); CI stage scripts run first, so CI is the check.

- **ignition_level=1 result** (boot 21:01:39 UTC, `research/boot0029k.log`, photo IMG_20261015_230308): preboot/cryptex stages skipped (need >= 2/3), `dylib_cache: finding shared cache on system volume: ignition level = 1, search root fd = 4, subpath = System/Library/Caches/com.apple.dyld/` -> not found -> `ignition boot failed: 19` -> no shared cache -> libSystem not loaded. FIX IN PROGRESS: image v2 = copy of the flashed image + `/System/Library/Caches/com.apple.dyld/` with HARD LINKS to the 44 cryptex cache files (no extra space; avoids symlink-following doubts), then `tools/sparsediff.py ios16-root-20H392.img ios16-root-20H392-v2.img diff.simg` and flash only the diff. Boot with `ignition_level=1` (shim-boot-0029k.img).
- **ignition_level=0 result** (boot 20:58:07 UTC, `research/boot0029j.log`, photo IMG_20261015_230037): all stages skipped as "ignition level insufficient" (hello/preboot/cryptex1 sniff >= 2, select os cryptex path/graft >= 3, **dyld_cache >= 1**), `ignition boot failed: 89`, "ignition partially disabled", then same `Library not loaded: /usr/lib/libSystem.B.dylib (no such file, no dyld cache)`. => dyld gets the shared cache directory from ignition's dyld_cache stage. Next: `ignition_level=1` (`shim/out/shim-boot-0029k.img`) to skip preboot/cryptex stages but run dyld_cache; its log "finding shared cache on %s ... subpath = %s" will show where it searches. If it searches rootfs /System/Library/Caches/com.apple.dyld, add a symlink there (image rebuild; consider a diff-only sparse flash tool to avoid rewriting 12 GB).
- **APPLE dyld/launchd RUNNING (libignition) with `unentitled_ios_sim_launch=1`** (boot 20:53:24 UTC, `research/boot0029i.log`, photo IMG_20261015_225617): kernel prints "Allowing spawn of iOS binary ... boot-arg set to true"; `shared_region: ... check_np ... vm_shared_region_start_address() failed` (no region yet, normal); dyld's built-in **libignition** (Darwin Ignition Sequence 1.0.0, libignition-51~1974; prints rd=ufsroot0, hardware target sweet, ignition level 0x5, platform 0x2, boot spec local, 7 stages): `hello from launchd.1` -> `preboot: mounting preboot` -> `failed to lookup preboot: 25` (ENOTTY: looks for a separate Preboot volume by role) -> ignition fails -> dyld `Library not loaded: /usr/lib/libSystem.B.dylib ... (no such file, no dyld cache)` -> launchd exit -> panic initproc failed. dyld boot-args found via strings: `ignition_level`, `ignition_force_dylib_root` (forced rootfs/livefs/cryptex fallback), `ignition_halt_after`, `ignition_live_app_graft`; dyld cache search paths include /System/Cryptexes/OS, /System/Volumes/Preboot/Cryptexes/OS/, /private/preboot/Cryptexes/OS/ (present in our image). Next try `ignition_level=0` (`shim/out/shim-boot-0029j.img`).
- **APPLE launchd EXECUTED FROM UFS (2026-10-15).** Flashed iOS image: `img2simg` -> `ios16-root-20H392.simg` (12.1 GB) then `fastboot -S 512M flash userdata ...simg` (24 chunks, 307 s, `research/flash-userdata-ios16.log`; a raw-image flash was killed by earlyoom at 2.6 GB RSS - always flash the sparse image). ABL fastboot hung on getvar after the flash; power+vol-down fixed it. Boot 0029u 20:49:04 UTC (`research/boot0029u-ios16.log`), photo IMG_20261015_225134: `hfs: mounted iOSRoot` -> load_init_program /sbin/launchd -> panic `unexpected SIGKILL of launchd (CS_KILLED) with reason -- namespace 9 code 0xe` = OS_REASON_EXEC / EXEC_EXIT_REASON_WRONG_PLATFORM: our kernel is XNU_TARGET_OS_OSX, iOS-platform binaries are "alien" and refused unless spawn attr platform set or DEVELOPMENT TUNABLE `unentitled_ios_sim_launch`. Next try: same kernel, cmdline + `unentitled_ios_sim_launch=1` (`shim/out/shim-boot-0029i.img`). LONGER TERM: macOS-config kernel marks iOS maps alien (vm_map_mark_alien) and differs from iOS in many policies; an iPhoneOS-config kernel build may eventually be needed.
- **iOS 16 ROOT IMAGE BUILT:** `/run/media/dipa/android/ios-sweet-ipsw/ios16-root-20H392.img` (16 GiB case-sensitive HFS+, label iOSRoot, 12 GB used, fsck OK after `fsck.hfsplus -y` rewrote 32 non-ASCII localized WorkflowKit Shortcut names Linux decomposes differently). Built by `tools/mkiosroot.sh OS.dmg SYSTEMOS.dmg APPOS.dmg OUT.img [SIZE]` (needs sudo; apfs-fuse as root; OS dmg is UDIF -> link must end .dmg). Contents: iPhone X 20H392 OS root + SystemOS cryptex at /private/preboot/Cryptexes/OS (so /System/Cryptexes/OS -> cache, 44 files, dyld_v1 arm64) + AppOS at .../App. /sbin/launchd and /usr/lib/dyld root:wheel 0755. NEXT: (confirm) `fastboot flash userdata ios16-root-20H392.img` (auto-sparse), boot 0029u (rd=ufsroot0) -> Apple launchd attempt.
- **MILESTONE ON HARDWARE: BOOT FROM INTERNAL FLASH.** 0029 CI `38797924912` PASSED, `xnu/out-0029` SHA256 `a68bc847...2a37`. Image `shim/out/shim-boot-0029u.img` (payload-0029u = 0029 kernel + `shim/out/sweet-0028.adt` + `rd=ufsroot0`, NO RAM disk). Boots 20:01:34 and 20:12:37 UTC (`research/boot0029u*.log`), photo IMG_20261015_221403: `SWEET UFS: "userdata" on LUN 0: first block 0x2b8c00, 109643 MiB, read-only` -> `BSD root: ufsroot0, major 1, minor 0` -> `hfs: mounted SweetRoot on device b(1, 0)` -> `SWEET: root volume is not authenticated (error 25); continuing unsealed` -> `load_init_program ... /sbin/launchd` -> `*** SWEET userspace: init running as PID 1 ***` -> heartbeat (ran for minutes unattended). userdata currently holds the 8 MB `research/root-hfs.img`. NEXT: build a multi-GB HFS+ image with the iOS 16 (iPhone X 20H392) userland (OS rootfs + SystemOS cryptex contents incl. dyld shared cache at /System/Library/Caches/com.apple.dyld; preserve modes/owners/symlinks; decompress LZBITMAP via apfs-fuse), flash it to userdata (sparse, needs user OK), then try Apple's dyld/launchd. Driver is read-only (root mounts RDONLY), fine for first launchd attempts.
- **userdata FLASHED with the 8 MB HFS test volume** (user said "flash it", 2026-10-15 19:53:17 UTC, `research/flash-userdata-hfs-test.log`: `fastboot flash userdata research/root-hfs.img` OKAY; pre-checks: one sweet device, partition-size:userdata 0x1AC4BFB000, partition-type f2fs, image fsck OK, SHA256 3626ea69...). Android userdata is now destroyed (expected/approved). Boot 0028u at 19:53:20 (`research/boot0028u-hfs.log`), photo IMG_20261015_215541: `BSD root: ufsroot0` -> **`hfs: mounted SweetRoot on device b(1, 0)` from internal UFS** -> panic `rootvp not authenticated after mounting @bsd_init.c:931` (arm64 macOS-config requires FSIOC_KERNEL_ROOTAUTH sealed root for non-ramdisk roots). Patch **0029** (`dd1c284`): SWEET logs `SWEET: root volume is not authenticated (error N); continuing unsealed` instead of panicking (Apple configs keep the panic; pivot_root still requires auth). CI **`38797924912`** running. Next: download out-0029, phone image with sweet-0028.adt + rd=ufsroot0 (no RAM disk), boot -> expect init from UFS.
- **UFS ROOT DRIVER VERIFIED ON HARDWARE (read-only).** 0028 CI `38796139570` PASSED, `xnu/out-0028` SHA256 `8b981640...9da6`; QEMU HFS RAM-disk regression `research/q0028-hfs` still runs init. Phone boot 2026-10-15 19:50:24 UTC (`research/boot0028u.log`, image `shim/out/shim-boot-0028u.img`, phone ADT `shim/out/sweet-0028.adt` with /sweet-ufs, NO RAM disk, `rd=ufsroot0`), photos IMG_20261015_215151/215220: `SWEET UFS: "userdata" on LUN 0: first block 0x2b8c00, 109643 MiB, read-only` -> `BSD root: ufsroot0, major 1, minor 0` -> `hfs_ValidateHFSPlusVolumeHeader: unknown Volume Signature : f188` (Android-encrypted data, as expected) -> `cannot mount root, errno = 19`, kernel retries mountroot (no panic). Nothing written to flash. NEXT (destructive, needs user confirmation right before): `fastboot flash userdata research/root-hfs.img` (8 MB HFS with test init) then boot rd=ufsroot0 -> expect init from internal flash.
- **PATCH 0028 (`33aceac`): XNU read-only UFS root device**, CI **`38796139570`** running (next artifacts xnu/out-0028, research/bt29, run29.log). `bsd/dev/sweet_ufs.c`: reuses ABL's UFSHCI state (like the shim probe), takes over UTRL at a kmem_alloc_contig region (DMA layout: UTRL 0x0, UCD 0x1000, 1 MiB bounce 0x4000), verifies UTRLBA readback before any doorbell, IE=0 polled, one SCSI cmd at a time on LUN0 (TUR x3, READ(10) via bounce, PRDT 256 KiB chunks), flush_dcache64 by PA around each command (host not dma-coherent per DT), finds GPT partition by name (`ufsroot=` boot-arg, default `userdata`), exposes `/dev/ufsroot0`/`rufsroot0` (512-byte logical sectors, physical 4 KiB, DKIOC* ioctls), refuses writes (EROFS). IOKitBSDInit: `rd=ufsroot0` -> sweet_ufs_rootdev() (lazy init) else panic. ADT: `tools/mkadt.py` adds `/sweet-ufs` reg <0x1d84000 0x3000> for the PHONE only (not --qemu). Local compile OK, imports resolve. Sandbox research/bt28 (pre0028 originals). FIRST PHONE TEST PLAN (non-destructive): boot 0028 with phone ADT + `rd=ufsroot0` and NO RAM disk: expect `SWEET UFS: "userdata" on LUN 0: first block 0x2b8c00, 109643 MiB` + `BSD root: ufsroot0`, then root mount failure (userdata is still Android-encrypted) -> panic. That validates the driver before flashing an HFS image into userdata (needs explicit user confirmation at that time).
- **SUPERSEDES the 64 GiB iosroot GPT plan: user said "u can delete android" (2026-10-15).** Use the existing `userdata` partition (LUN0 sda34, 4K LBA 0x2B8C00, 0x1AC4B MiB ~107 GiB) directly as the iOS root: NO GPT changes. Keep bootloaders, recovery (OrangeFox), modem/persist/fsg/modemst untouched. Write the HFS image later with `fastboot flash userdata` (sparse, auto-split under the 768 MiB limit). Android will no longer boot normally (expected; reinstallable). Order: XNU UFS driver first, read-only against the current GPT; flash only once it can locate userdata. Nothing erased yet.
- **DECIDED (user, 2026-10-15): 64 GiB `iosroot` on LUN0 (sda), taken from userdata (wipes Android user data; Android/super kept).** Planned GPT (4K LBAs): userdata 0x2B8C00..0xD7D6FF (~43 GiB, keep type/unique GUIDs and attributes); iosroot 0xD7D700..0x1D7D6FF (0x1000000 blocks = 64 GiB, 1 MiB aligned); backup GPT area unchanged. Procedure: user backs up phone data -> boot OrangeFox recovery (adb) -> back up GPT (sgdisk --backup + raw dd of LBA 0-5 and last 6 blocks) to research/ -> sgdisk edit -> Format Data -> verify Android boots to setup. NOT EXECUTED YET.
- **INTERNAL UFS WORKS FROM THE SHIM (read-only), user authorized internal-UFS approach incl. flashing (2026-10-15, "i allow everything").** Shim probe `shim/ufs.c` (commit `12ed3ed` + filter): ufshc@1d84000 is UFSHCI 2.1 (ver 0x210, cap 0x1587031F, 32 slots), ABL leaves HCE=1, HCS=0x10F (device present, lists ready, UIC ready); probe takes over UTRL at its own buffer (verifies UTRLBA readback before any doorbell), TEST UNIT READY/READ CAPACITY/READ(10) all succeed. LUN0 = 0x1D7D800 x 4 KiB (~126.6 GB), valid GPT (64 entries at LBA 2). Photos IMG_20261015_212916/213325/213429. Big LUN0 partitions (start in 4K LBAs / MiB): super 0xCA00/0x2200 (8.5 GiB), logdump 0x22CA00/64, minidump 0x230A00/128, rawdump 0x238A00/128, recovery 0x240C00/128, cache 0x248C00/384 ext4, exaid 0x260C00/384, cust 0x278C00/1024 ext4, **userdata 0x2B8C00/0x1AC4B MiB (~107 GiB), fs unreadable = encrypted (metadata encryption)**. cache..cust contiguous = only 1.75 GiB (too small for iOS ~10+ GiB). Plan needing user consent: shrink userdata in GPT (wipes Android data) and add an `iosroot` partition at the end of LUN0. LUNs 1-5 not listed yet (sdb..sdf backed up in backup/lun).
- **fastboot limit measured (2026-10-15, read-only getvar):** `max-download-size: 805306368` (768 MiB); `max-fetch-size` unsupported; `is-userspace: no` (ABL fastboot). A `fastboot boot` image (shim+kernel+RAM disk) must be < 768 MiB, so the 2.5 GiB iOS shared cache cannot ride in the boot RAM disk even if XNU gets all RAM. Real userland needs storage access (UFS driver, or USB host) or a much smaller cache. Unlocking full RAM is still needed later (GUI).
- **iOS 16 USERLAND SOURCE (Claude, 2026-10-15).** Chose **iPhone X (iPhone10,3/10,6, D22/D221AP)** iOS **16.7.16 (20H392)** over iPhone 8: same A11 (no PAC -> plain arm64, runs on Kryo 470/ARMv8.2), last iOS for A11; X userland is home-button-less and tall-screen (1125x2436 vs sweet 1080x2400), better fit for later GUI. Note the X has its OWN SystemOS cryptex (different digest from iPhone 8's). IPSW URL in `research/ipsw-x/URL.txt` (+ BuildManifest). Images on the user's external SSD (NOT in git, do not format that disk: it holds the user's photos): `/run/media/dipa/android/ios-sweet-ipsw/iPhone10,3_16.7.16_20H392/` — `087-86593-047.dmg` = Cryptex1,SystemOS (2,743,074,816 B), `087-86698-044.dmg` = OS rootfs (4,730,814,044 B), both zip CRC-32 verified, plus Firmware/*.root_hash/.trustcache/.mtree. AppOS cryptex is 087-86715-047.dmg (10 MB, same as iPhone 8).
  - Images are raw APFS; files use LZBITMAP (decmpfs type 14). 7z cannot decode. Tools: `ipsw` 3.1.738 (AUR ipsw-bin, user-approved) needs apfs-fuse on Linux; **apfs-fuse** built in user space (system cmake broken: cmake 4.4.4 wants libjsoncpp.so.27, jsoncpp 1.9.6 installed = partial upgrade, NOT fixed) with pip cmake + `-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_CXX_FLAGS="-include cstdint"`, installed to `~/.local/bin/apfs-fuse` (+apfs-dump-quick). Mount via a comma-free symlink (apfs-fuse splits options on ',' in `iPhone10,3`; exFAT has no symlinks -> put link elsewhere): `apfs-fuse LINK/087-86698-044.dmg MNT` -> `MNT/root/...`; unmount `fusermount3 -u MNT`.
  - Verified from headers: `dyld_shared_cache_arm64` magic `dyld_v1   arm64`; `/sbin/launchd`, `/usr/lib/dyld` = cputype 0x100000c subtype 0 (plain arm64). libSystem exists only inside the cache.
  - **BLOCKER for real userland via RAM disk:** shared cache = 3.10 GiB in 44 files (~2.5 GiB without the 592 MB `.symbols`), but the kernel manages only 1.20 GiB (0xb0000000..0xfd000000). Options: (A) give XNU the phone's full ~6 GB (banks 0x80000000+2G and 0x100000000+0xfcc00000, carve-out holes need pmap support) AND check fastboot max-download-size for a multi-GB boot image; (B) storage driver (Qualcomm UFS) to read a root from flash (no flashing allowed: would need a file/partition strategy); (C) run against individual dylibs extracted from the cache (uncertain).
- **MILESTONE ON HARDWARE: HFS+ ROOT FILESYSTEM -> PID 1.** Boot 2026-10-15 18:22:12 UTC (`research/boot0027b.log`, image `shim/out/shim-boot-0027b.img`), photo `IMG_20261015_202334.jpg`: `BSD root: md0` -> `hfs: mounted SweetRoot on device b(1, 0)` -> `load_init_program: attempting to load /sbin/launchd` -> `*** SWEET userspace: init running as PID 1 ***` -> repeated `SWEET init: still alive`, no panic. Kernel 0027 (built-in Apple OSS HFS + BearSSL MD5), init with SP alignment fix. NEXT: real iOS 16 userland on the HFS image (dyld, libSystem/dyld shared cache, launchd). Known gaps: entitlements (none granted), SHA-1/SHA-384/512 providers, no storage driver (RAM disk only), root mounted read-only.
- **PHONE HFS ROOT (0027) + SIGBUS ROOT-CAUSED.** Phone boot 2026-10-15 17:49:06 UTC (`research/boot0027.log`, photo `IMG_20261015_200031.jpg`): `hfs: mounted SweetRoot on device b(1, 0)` (HFS works on hardware), init printed its first line, then `pid 1 exited -- exit reason namespace 2 subcode 0xa` = SIGNAL/SIGBUS -> `initproc failed to start` panic. Diagnostic boot 18:08:13 UTC (`research/boot0027d.log`, image `shim/out/shim-boot-0027d.img`, diag init `research/diag-init` from scratch diag-init.S with [a][b][c] markers, `cs_debug=1`; photo `IMG_20261015_201547.jpg`): output `PID [a][b]` then SIGBUS -> fault at first `strb w21,[sp]`; no code-signing messages. Cause: kernel enters a static binary with sp at argc, not necessarily 16-aligned (depends on arg/apple string lengths, differs mockfs vs HFS); EL0 SP alignment check -> EXC_ARM_SP_ALIGN -> SIGBUS (sleh handle_sp_align). QEMU does not enforce SP alignment. NOT a kernel bug: real binaries start in dyld which aligns. Fix `1a8fc15`: sweet-init aligns sp at entry. Rebuilt `research/root-hfs.img`, QEMU `research/q0027-hfs2` OK. Phone image `shim/out/shim-boot-0027b.img` SHA256 `098ba46c...c5c` (payload-0027b, ramdisk match check-0027b) ready, awaiting FASTBOOT. Lesson: Assembly `;` is a comment in Apple arm64 asm (use .macro, not ;-joined #define).
- **HFS ROOT WORKS (QEMU).** 0027 CI `38779441895` PASSED, `xnu/out-0027` SHA256 `a8643886...5f6a`. QEMU `research/q0027-hfs` (RAM disk = `research/root-hfs.img`, rd=md0): `BSD root: md0` -> `hfs: mounted SweetRoot on device b(1, 0)` -> `load_init_program: attempting to load /sbin/launchd` -> `*** SWEET userspace: init running as PID 1 ***` + heartbeat, no panic. Phone image `shim/out/shim-boot-0027.img` (payload-0027 = 0027 kernel + sweet-0021.adt + root-hfs.img + rd=md0, ramdisk byte-match check-0027) ready; awaiting FASTBOOT for phone test.
- **HFS ROOT WORK (Claude), patches 0026-0027.**
  - 0026 (`f0e990c` + link fix `64c96f4`): Apple OSS **hfs-627.100.6** (commit `31d5ec238dfab485e78a9a30b8b92d13e8914f03`, paired with xnu-8796.141.3 in macos-135 release.json) staged by `xnu/patches/0026-stage-hfs.sh` into `bsd/sweet_hfs` (core + hfs_encodings; AppleKeyStore include/key prototypes guarded by CONFIG_PROTECT; SDK TargetConditionals copied). New config option `sweet_hfs` (MASTER + MASTER.arm64.sweet); 40 `optional sweet_hfs` files; Makefile.template foreach adds `_CFLAGS_ADD = -include sweet_hfs_compat.h -I...` (MUST come after kernel -D flags; compat undefs BSD/XNU_KERNEL_PRIVATE and the CONFIG_* HFS tests so kext-config.h decides: macOS profile, no content protection). `sweet_hfs_iokit.c` replaces hfs_iokit.cpp/hfs_encodings_kext.cpp: `sweet_hfs_register()` called in bsd_init after vfsinit (encodings init, vfs_fsadd VFS_TBLCANMOUNTROOT, zones, sysctls); is_ejectable 0, iterate_media none, serial KERN_NOT_SUPPORTED, OSKextGetCurrentLoadTag -> kOSKextInvalidLoadTag (renamed via compat macro). hfs_encodings' own `hfs_allocated` renamed per object (separate kexts on Apple; first CI `38777325964` failed on that duplicate at link). mockfs now validates Mach-O magic (its TODO) so non-Mach-O roots fall through to HFS (new fs entries come AFTER mockfs in vfsconf). CI `38778133720` PASSED, `xnu/out-0026` SHA256 `0b49170c...701a`, prints `SWEET HFS: hfs-627.100.6 registered`.
  - HFS+ image: `research/root-hfs.img` (8 MB, mkfs.hfsplus from AUR hfsprogs installed with user approval; loop-mounted with sudo; /sbin/launchd = research/sweet-init, /dev; fsck.hfsplus OK). QEMU `research/q0026-hfs`: `BSD root: md0` then data abort in MD5Init from hfs_getvoluuid (mount computes volume UUID).
  - 0027 (`14bf2b7`): 0020 stager also copies BearSSL hash/md5.c + codec/dec32le.c/enc32le.c; `corecrypto_md5.c` SWEET branch converts MD5_CTX <-> br_md5_context around br_md5_* calls; wrappers sweet_md5.c/sweet_dec32le.c/sweet_enc32le.c. Host test 40/40 match md5sum. CI **`38779441895`** running.
  - Local tooling: `tools/xnu-cc.py` has `XNU_CC_POST` (flags after logged ones). Sandbox `research/bt28/xnu` = 0025 CI tree + 0026/0027 edits; originals `research/pre0026`, `research/pre0027`. HFS local objects `research/hfs-objs`. Checker entries updated to bt28.
  - SHA-1 / SHA-384/512 still have no provider.
- **MILESTONE ON HARDWARE: USERSPACE PID 1 RUNS ON THE PHONE.** Boot 2026-10-15 17:16:00 UTC (`research/boot0025.log`: send OKAY0.410s, boot OKAY0.135s), image `shim/out/shim-boot-0025.img` SHA256 `9dbfa0b1...89db0`. Photo `IMG_20261015_191733.jpg`: `BSD root: md0` -> `load_init_program: attempting to load /sbin/launchd` -> `*** SWEET userspace: init running as PID 1 ***` -> repeated `SWEET init: still alive` (5 s heartbeat), no panic. Kernel 0025 + mockfs RAM disk + built-in no-entitlements AMFI. No flashing performed.
- **NEXT (toward real iOS userland):** real root filesystem with real binaries. Options: (a) build Apple OSS `hfs` (macOS 13.5 tag `hfs-627.100.6`) into SWEET like libpthread, then an HFS RAM disk image; (b) iOS 16 dyld + libSystem/dyld shared cache from the IPSW (needs APFS or repacking onto HFS). Expected hurdles: entitlements (sweet_amfi grants none), SHA-1/MD5/SHA-384/512 providers (BearSSL), missing kexts/daemons. Current init is a static test program, not launchd.
- **MILESTONE: USERSPACE RUNS (QEMU).** 0025 CI `38774788048` PASSED, `xnu/out-0025` SHA256 `5496069b...4877`. QEMU `research/q0025-rd` (150 s, no panic): `BSD root: md0` -> `load_init_program: attempting to load /sbin/launchd` -> `*** SWEET userspace: init running as PID 1 ***` -> `SWEET init: still alive` every 5 s. Exec, ad-hoc SHA-256 code signature, syscalls, devfs /dev/console, select timeouts all work. Phone image prepared: `shim/out/shim-boot-0025.img` 16,515,072 bytes SHA256 `9dbfa0b15140c0bd733a16c4f727f6a7df44a8741f98d8e266d5f2fa4f689db0` (payload-0025 = 0025 kernel + sweet-0021.adt + research/sweet-init + rd=md0; ramdisk byte-match check-0025). Waiting for user to put phone in FASTBOOT.
- **0024 CI `38773277811` PASSED**, `xnu/out-0024` SHA256 `a0ba964b...4348`. QEMU `research/q0024-rd` and **PHONE (boot 2026-10-15 17:05:55 UTC, `research/boot0024.log`, image `shim/out/shim-boot-0024.img` SHA256 `cf3dac86...6964`, 16,510,976 bytes, payload `shim/out/payload-0024.bin` = 0024 kernel + `shim/out/sweet-0021.adt` + RAM disk `research/sweet-init` + rd=md0; ramdisk byte-match `check-0024`)** agree: `Added memory device md0`, `BSD root: md0`, `load_init_program: attempting to load /sbin/launchd`, then data abort in accelerate_entitlement_queries (PC 0x...77d2458, FAR 0x1a0) = NULL AMFI interface. Photo `IMG_20261015_190715.jpg`. RAM disk root is physically verified.
- **0025 (`2518c79`)**: new `bsd/kern/sweet_amfi.c` registers a built-in AMFI interface at EARLY_BOOT/MIDDLE: no entitlements (adjustContextWithoutMonitor succeeds without creating a context, queries KERN_DENIED, copies NULL/KERN_NOT_FOUND, get_xml/transmuted false); WithMonitor KERN_NOT_SUPPORTED; OSEntitlements_query and query_context_to_object panic explicitly (CoreEntitlements closed; no kernel caller); TrustCache version 0 (0015 keys on trust_cache_rt==NULL, img4 absent -> still unavailable); CoreEntitlements table zero (PMAP_CS only). Compiles locally; checker updated (bt27 entries). CI **`38774788048`** running. Next artifacts `xnu/out-0025`, `research/bt29`, `research/run29.log`. Real iOS binaries will need real entitlements later (no OSS CoreEntitlements exists).
- **0021-0024 RAM-disk-root iteration (Claude), QEMU only so far, no new phone boot since 0020.** Each kernel tested with `tools/mkpayload.py KERNEL research/q0021.adt OUT --ramdisk research/sweet-init --cmdline "debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam -noprogress rd=md0"` then `tools/qemu-sweet.py OUT DIR --secs 150 --kernel KERNEL --fail-on-panic` (PATH needs ~/swift/usr/bin for llvm-nm). Fresh ADTs: `research/q0021.adt` (QEMU), `shim/out/sweet-0021.adt` (phone).
  - 0021 CI `38769532000` PASSED, `xnu/out-0021` SHA256 `2b7500a1...962e`, `research/bt25`/`run25.log`. QEMU `research/q0021-rd`: md0 root, then assert `iomediaClass` in IOService::publishHiddenMedia.
  - 0022 (`20ece9c`, publishHiddenMedia without IOMedia class) CI `38770666158` PASSED, `xnu/out-0022` SHA256 `a4d0e787...30c5`, `research/bt26`/`run26.log`. QEMU `research/q0022-rd`: data abort in SHA256_Init (NULL g_crypto_funcs) from vm_kernel_addrhash_internal.
  - 0023 (`c8089d1`, libkern SHA256_Init/Update/Final use built-in ccsha256_ltc_di + ccdigest_init/update on SWEET; also serves code-signing SHA-256; SHA-1/MD5/SHA-384/512 still have NO provider - BearSSL from 0020 could supply them later) CI `38771876423` PASSED, `xnu/out-0023` SHA256 `d763fed7...1003`, `research/bt27`/`run27.log`. QEMU `research/q0023-rd`: **mockfs mounted md0, `load_init_program: attempting to load /sbin/launchd`**, then panic `mockfs_fsnode_vnode failed to create fictitious pages ... rvalue = 5` (mockfs.c:351).
  - 0024 (`3293c80`): mockfs used memdev mi_base (4K page number of a VIRTUAL kernel address for IOKit RAMDisk, truncated to 32 bits) << PAGE_SHIFT as a physical address. Now zero-copy pager mapping only when mi_phys (with 4K units); virtual md uses pagein/blockmap/strategy -> memdev bcopy. memdev's own mdPhys path assumes 4K ppnums (unsafe on 16K arm64), so do NOT switch the RAMDisk to physical. CI **`38773277811`** running. Next artifacts `xnu/out-0024`, `research/bt28`, `research/run28.log`.
  - Sandboxes: bt25/bt26/bt27 contain the next patch's edited files; pristine copies in `research/pre0022`..`pre0024`.
- **PATCH 0021 (Claude): RAM disk root via mockfs -> first userspace program.** Commits `9c37771` (initial; CI `38768500280` FAILED: mockfs_fsnode.c kfree_type(mockfs_fsnode_t) typed-alloc static assert; local xnu-cc stubs `__builtin_xnu_types_compatible` so it can't catch this) and `193772f` (fix), CI **`38769532000`** running: https://github.com/dipa-studio/ios-sweet/actions/runs/38769532000. Next artifacts: `xnu/out-0021`, `research/bt25`, `research/run25.log`.
  - Kernel: `config/MASTER.arm64.sweet` FILESYS_BASE += `mockfs` (XNU's built-in FS: root device is itself a Mach-O, served as /sbin/launchd, plus /dev for devfs). Upstream mockfs bit-rot fixed: kalloc_type/kfree_type used the POINTER typedef mockfs_fsnode_t (nodes were 8 bytes) -> `struct mockfs_fsnode`. `IOService::setRootMedia` asserted IOBlockStorageDriver class exists (IOStorageFamily absent): SWEET-only, a missing class means root=NULL (same as IOSetImageBoot); Apple path keeps assert. All 21 patches apply (`research/check-patch-order.py`); 5 TUs compile locally with -DMOCKFS (`research/mockfs-objs`), imports resolve vs 0020 kernel. Sandbox `research/bt24/xnu` now holds 0021 versions of those 3 files; pristine 0020 copies in `research/pre0021`.
  - Tools: `tools/mkpayload.py --ramdisk IMAGE` appends IMAGE as an extra payload segment right after the kernel, moves kernel_end past it (shim unchanged: ADT+boot_args follow it, image stays below topOfKernelData), and adds ADT `/chosen/memory-map` `RAMDisk`=<phys,size>. Boot with `rd=md0`. Without --ramdisk output is byte-identical to existing 0020 QEMU and phone payloads (verified). `tools/sweet-init.S` + `tools/mkinit.py`: PIC static init (open /dev/console, print PID, heartbeat every 5 s via select, never exits) wrapped into a static arm64 Mach-O (__PAGEZERO, __TEXT@0x100000000, LC_UNIXTHREAD, ad-hoc SHA-256 CodeDirectory v0x20400, 4K pages). Build: `~/swift/usr/bin/clang -target arm64-apple-ios16.0 -c tools/sweet-init.S -o X.o && tools/mkinit.py X.o research/sweet-init` (ld64.lld cannot link static iOS). Signature not verified by a real codesign; the kernel will tell.
  - QEMU with 0020 kernel + RAM disk (`research/q0020-rd.bin`, rd=md0, 150 s `research/q0020-rd150`): `Added memory device md0`, **`BSD root: md0, major 1, minor 0`** (plumbing works), then the setRootMedia assert (now fixed in 0021). NOTE: QEMU needs >60 s to reach IOFindBSDRoot (60 s run showed nothing after stf0; likely RTC/inittodr wait), so use --secs 150.
  - NEXT: download 0021, QEMU 150 s with ramdisk; expect mockfs mount then init exec -> `*** SWEET userspace: init running as PID 1 ***`. Then phone boot with same payload (phone ADT shim/out/sweet-0020.adt pattern + --ramdisk + rd=md0).
- **0020 PHONE RESULT (user transcription of screen, 2026-10-15): KERNEL INIT COMPLETE, WAITING FOR ROOT.** After Skywalk self-tests PASSED, kminit, ifnet_attach lo0/gif0/stf0, screen prints `BSD`, then `Waiting on <dict><key>IOProviderClass</key><string>IOMedia</string><key>Content</key><string>Apple_HFS</string></dict>` and `Failed to write boot-picker-bringup-reason to NVRAM.` No panic. This is IOFindBSDRoot waiting for a root device (none exists); NVRAM warning is expected (no NVRAM driver). QEMU `cpu_idle` snapshot is presumably the same wait (not GDB-confirmed; milestone GDB run was cancelled by user since phone answered it). Draft `research/check-milestones20.gdb` (hbreaks inittodr/vfs_mountroot/IOFindBSDRoot/bsd_utaskbootstrap) left uncommitted/ignored.
- **NEXT MILESTONE: root filesystem -> launchd.** Plan: (1) RAM disk: shim places an image in RAM, ADT /chosen/memory-map `RAMDisk` entry, boot-arg `rd=md0` (XNU md driver). (2) HFS is a separate kext on Apple; build Apple OSS `hfs` (tag paired with macOS 13.5 in distribution-macOS macos-135 release.json) into SWEET like libpthread 0019. APFS is closed. (3) Minimal HFS image with iOS 16 launchd (later: dyld/shared cache; AMFI/code-signing absent will be a later hurdle). User's end goal is full iOS GUI.
- **0020 (AES) VERIFIED + PHONE BOOTED (Claude took over after Codex usage limit).** Actions `38765422261` (`ab9e23f`) PASSED; kernel `xnu/out-0020/kernel.development.sweet` checksum OK; buildtree `research/bt24`, log `research/run24.log`. Actual-kernel AES checks PASS (`research/check-aes20.gdb` / `.log`, 12 extra CBC cases match OpenSSL). 45s QEMU `research/q0020`: no panic, zero unknown glyphs, past old TCP/AES panic -> Skywalk self-tests PASSED -> bsd_autoconf kminit -> ifnet_attach lo0/gif0/stf0; final snapshot PC in `cpu_idle` (idle or waiting; NOT yet diagnosed, could be root-device wait). Image `shim/out/shim-boot-0020.img` 16,461,824 bytes SHA256 `775200cb02d95fc750981516b79d91dcdc96184bbe67a38f9d57c59b4a391828`, ramdisk byte-matches `payload-0020.bin` (`check-0020`). **Phone temporarily booted 2026-10-15 16:10:00 UTC**: one FASTBOOT product sweet, send OKAY0.407s, boot OKAY0.134s, total0.549s, exit0 (`research/boot0020.log`). Awaiting user photo; do not reboot the phone before it. NEXT: read photo; diagnose what QEMU waits on after stf0 (GDB backtrace of threads / longer run). Codex's STOP request below is complete.
- User requests STOP after completing the current0020 AES iteration (Actions/QEMU/phone), then leave a precise committed handoff for another AI. User says FASTBOOT ready again after0019 photo. Do not start a new blocker fix after this iteration.
- Goal: iOS16-generation XNU on Redmi Note10Pro sweet/SM7150. Always commit, use gh/Actions for kernel builds, keep this handoff current. Temporary fastboot boot only; preserve Android/backups. No userland/root filesystem boot yet.
- **Patch0020 update:** initial `e71098d` / Actions `38765012466` superseded by scalar-only compile flags. Added -mgeneral-regs-only to all six provider/BearSSL TUs and corecrypto_aes.c; object disassembly now confirms no SIMD. Updated implementation `ab9e23f`, Actions `38765422261` queued/running: https://github.com/dipa-studio/ios-sweet/actions/runs/38765422261. Do not launch another run. portable BearSSL AES CBC and legacy one-block ECB wired directly into SWEET corecrypto_aes.c. Genuine bitslice implementation, no CPU AES/SIMD requirement, heap or fake global crypto table. Source fetched by `0020-stage-bearssl.sh` from official BearSSL git at immutable `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f`; MIT license retained, downloaded source stays out of git. Kernel limits include adapter only. All128/192/256-bit keys, CBC encrypt/decrypt, copied contexts, in-place/out-of-place; zero block count and size overflow handled, invalid keys clear context. Seven TUs compile to arm64 objects (`research/aes-objs`), imports resolve, all20 patches apply and sources match (`research/patch0020-check.log`). Sandbox `research/bt23/xnu`, originals `research/pre0020`. NEXT: Actions then actual-kernel NIST/random CBC/ECB checks and >=45s QEMU before another phone boot. Next artifacts out-0020 / bt24 / run24.log. 0020 updated CI pending. Local sources/checks match the scalar-only patch.
- **Latest built kernel0019**, implementation `256d3f0`, patches0001-0019. Actions `38763072907` PASSED (4m5s): https://github.com/dipa-studio/ios-sweet/actions/runs/38763072907. Kernel `xnu/out-0019/kernel.development.sweet`, SHA256 `a27df7568f03fb541cf0e8024c0a594fa178a85054fcf9eba29158cbd4c5ecc0`; checksum verified. Log/source `research/run23.log` / `research/bt23` (no nested .git). Seven pthread source/build/header files and staged adaptations byte-match local compile inputs.
- **0019 hardware photo received** `IMG_20261015_175306.jpg`: pthread registration visible, passes mbinit and DLIL checksum/scheduling, same AES fault as QEMU: PC`0xfffffe00079174e0` (`aes_encrypt_key128`), LR`0xfffffe000767c3a4` (`tcp_init`), FAR0x78, x8=0. Disassembly proves NULL g_crypto_funcs->ccaes_cbc_encrypt. Photo processed; no more0019 observation pending. General crypto table remains absent, other hash/mode operations may still fault after0020. DO NOT bypass TCP or install fake crypto. XNU already contains SHA256/HMAC implementations; AES source there is a dispatch wrapper. Full future provider interface libkern/libkern/crypto/register_crypto.h. Apple/corecrypto default README describes evaluation-only licensing, so no external corecrypto was fetched or staged; BearSSL selected for this portable AES integration.
- **0019 pthread FIXED in QEMU and observed beyond its init on phone**: 45s QEMU `research/q0019`, zero unknown glyphs, then AES panic. Actual-kernel API checks PASS `research/check-pthread19.gdb` / `.log`, guest `research/q0019-api`: function/callback table identity, actual provider pthread_init returns, locks/global hash/threadcall/typed zones initialized, thread_selfid via syscall shim + buffer bounds, process hash init/delete via shims restores NULL. Monitor quit prints expected remote-disconnect after PASS. All fixture guests stopped.
- **0019 provider**: genuine Apple libpthread-514.100.2 commit `a6c70ca0e544347a0377babf748f831577ec24f9`, exact paired release with xnu8796.141.3 in distribution-macOS/macos-135/release.json (`research/macos-135-release.json`). 0019 shell stage runs before patches (workflow copies *.sh); three SWEET wrapper TUs use kext BSD header view, vm_fault_external, renamed provider-side pthread_kern/current_uthread; register real function table at EARLY_BOOT SECOND, real pthread_init later. Stager applies bounded address casts, zero user addresses, proper panic format. SWEET opaque ksyn storage enlarged48->56 for trailing kwe_uth, checked with provider static assertion. Local pre-CI TargetConditionals fixture was syntax-only; artifact bt23 carries actual SDK header and CI is authoritative.
- **Phone0019 temporarily booted** 2026-10-15 15:51:36 UTC: exactly one FASTBOOT/product sweet verified; send OKAY0.406s, boot OKAY0.134s, total0.546s, exit0 (`research/boot0019.log`). Image `shim/out/shim-boot-0019.img`, 16,457,728 bytes, SHA256 `19429a57e486b856880df9e27327ed488e0139345311fdb0350974e72103a9a1`. Phone ADT/payload `shim/out/sweet-0019.adt` / `payload-0019.bin` timer19, unpacked ramdisk byte-match (`check-0019`). EntryPA0xb146b488, kernelendPA0xb2000000, boot_argsPA0xb2004000/top0xb2008000. Last user FASTBOOT+USB reply preceded this boot; do not assume phone is still in FASTBOOT.
- **CPU0018 physically verified** by `IMG_20261015_173951 (2).jpg`: boot CPU0 registered, real SGI1 verified, initialization complete -> BSD/MAC/mbinit -> old pthread-table panic. SweetCPU uses legacy IOCPU, ml_processor_register/processor_start/initCPU, real SGI1 clears SIGPdisabled before max CPUs completion; no forced flags/skipped waits. CPU APIs and two-CPU rejection passed (`research/check-cpu18.gdb`, `q0018-api`, `q0018-smp`). Single core; SMP/suspend unsupported. CURRENT SWEET has NO USE_APPLEARMSMP.
- QEMU next run: generate fresh `tools/mkadt.py research/q0020.adt --qemu` (timer27), mkpayload with `debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam -noprogress`, then `tools/qemu-sweet.py PAYLOAD OUT --secs 45 --kernel KERNEL --fail-on-panic`. 12s can miss later panics because IORTC waits30s. Runner snapshot only: panic exit2, blank/incomplete exit3; absence of panic does not mean complete boot. Qualcomm XPU/ABL/panel and phone SMC PSCI require hardware checks.
- Local checker `tools/xnu-cc.py research/run23.log research/bt23 FILTER --per-file`, XNU_CC_OBJDIR for objects. For new BearSSL TUs add XNU_CC_EXTRA with -I bt23/xnu/libkern/crypto/sweet_bearssl/{inc,src}. Patch checker `research/check-patch-order.py` uses temporary upstream index; source fixtures/artifacts ignored under research. GDB mask registers to unsigned64, use function-entry manual-call return traps, discard manipulated guests. No QEMU guest intentionally left running.

## Session log and earlier handoffs (superseded by the active summary above)

### Prior 0019 transition notes (superseded)

- Goal: iOS 16 generation XNU on sweet. Always commit completed work, use gh/Actions for kernel builds, keep this handoff current. Temporary fastboot boot only; preserve Android/backups.
- **0019 build PASSED** Actions `38763072907` (4m5s), implementation `256d3f0`. Kernel `xnu/out-0019/kernel.development.sweet`, SHA256 `a27df7568f03fb541cf0e8024c0a594fa178a85054fcf9eba29158cbd4c5ecc0`; checksum verified. Log/source `research/run23.log` / `research/bt23`; all seven patched files and staged provider adaptations match local compile inputs. Prefer bt23 as the next baseline.
- **0019 pthread FIXED in QEMU**: 45s run `research/q0019` registers provider, passes mbinit, DLIL SUM16 checks and DLIL thread scheduling. Actual-kernel GDB checks `research/check-pthread19.gdb` / `.log` PASS: function/callback table identity, real _pthread_init returns, locks/global hash/cleanup threadcall/typed zones non-NULL, thread_selfid via actual syscall shim with output bounds, process hash init/delete through actual shims restores NULL. Guest stopped after tests; no fixture left running. GDB monitor quit prints expected remote disconnect after PASS.
- **Current next blocker:** QEMU0019 panic data abort FAR0x78 at `aes_encrypt_key128` PC`0xfffffe00079174e0`, called by `tcp_init` LR`0xfffffe000767c3a4`. Disassembly confirms `g_crypto_funcs == NULL`, loading ccaes_cbc_encrypt at+0x78. General crypto registration is still absent; DO NOT bypass TCP or supply fake crypto. Next integrate a genuine compatible crypto implementation/provider (AES first needed here, other digest/mode APIs also used). XNU contains SHA256/HMAC but no AES implementation; its corecrypto_aes.c is a dispatch wrapper. Full crypto table is in libkern/libkern/crypto/register_crypto.h.
- **0019 phone image prepared and verified**, user reports FASTBOOT+USB again; exactly one device/product sweet verified. `shim/out/shim-boot-0019.img`, 16,457,728 bytes, SHA256 `19429a57e486b856880df9e27327ed488e0139345311fdb0350974e72103a9a1`; unpacked ramdisk matches phone payload (`shim/out/check-0019`, `payload-0019.bin`, `sweet-0019.adt`, timer19). EntryPA0xb146b488; kernelendPA0xb2000000; boot_argsPA0xb2004000/top0xb2008000. Usual debug cmdline cpus=1/-noprogress. **Temporarily booted 2026-10-15 15:51:36 UTC**: send OKAY0.406s, boot OKAY0.134s, total0.546s, exit0 (`research/boot0019.log`). User asked for photo after45s. Await the photo; DO NOT reboot again before observation. Bootloader acceptance only; no0019 physical progress observed yet.
- **Hardware photo confirms 0018 progress** (`IMG_20261015_173951 (2).jpg`): real phone prints `SWEET CPU: boot CPU 0 registered, SGI1 verified, initialization complete`, enters BSD/MAC, reaches `mbinit: done`, then the same missing-pthread-function-table panic as QEMU at pthread_shims.c:318. CPU completion/interrupt delivery is now physically observed. The photo was received; no further phone boot performed yet.
- **Patch0019 committed/pushed `256d3f0`; Actions `38763072907` queued/running:** https://github.com/dipa-studio/ios-sweet/actions/runs/38763072907. Do not launch a duplicate. genuine Apple OSS libpthread-514.100.2 provider (immutable commit `a6c70ca0e544347a0377babf748f831577ec24f9`), paired with xnu-8796.141.3 by Apple's `distribution-macOS/macos-135/release.json` (`research/macos-135-release.json`). `0019-stage-libpthread.sh` fetches/stages it before patches; workflow now copies shell scripts too. SWEET-only wrappers compile all three real kernel sources, rename provider-side symbols, use kext header view and vm_fault_external, register the real function table at EARLY_BOOT SECOND. Existing pthread_init then runs the actual provider initialization. No pthread wait/syscall is bypassed. Source staging includes bounded explicit address casts/zero user addresses and panic-format fixes. SWEET kernel opaque ksyn storage enlarged from48 to56 bytes to contain this provider's trailing kwe_uth, with a provider size assertion. Local compile of three provider TUs plus pthread_shims/kern_fork passed; imports resolve and provider exports do not collide with existing kernel symbols. All19 patches apply and changed sources match (`research/patch0019-check.log`). Source sandbox `research/bt22/xnu`, originals `research/pre0019`, objects `research/pthread-objs`. Local TargetConditionals fixture only has target macros for syntax; CI stages the real macOS SDK header and is authoritative. Next Actions artifacts: out-0019 / bt23 / run23.log; run QEMU >=45 seconds. 0019 CI is pending; no 0019 QEMU run yet.
- **Latest kernel implementation `e7d9550`, patches0001-0018; CI `38760004398` PASSED (3m56s)**: https://github.com/dipa-studio/ios-sweet/actions/runs/38760004398. No build is pending. Kernel `xnu/out-0018/kernel.development.sweet`, SHA256 `b3c8d59acc88f93a2c836eb2527a05ed4fbaac7c580a2ea8c3b795137f4aadf1`; checksum verified. Source/log `research/bt22` / `research/run22.log` (baseline for patch0019; no nested .git). New driver/config sources match CI exactly.
- **CPU wait FIXED in QEMU**: SweetCPU uses legacy IOCPU, validates single boot CPU, ml_processor_register -> processor_start -> initCPU real SGI1 -> scheduler/IOKit completion -> ml_set_max_cpus. It does NOT force a flag or skip a wait. CPU APIs passed: Running CPU0, processor_array[0] association, SGI signalling enabled, name, unsupported secondary-start error (`research/check-cpu18.gdb` / `.log`, `research/q0018-api`). Single-core only; SMP and suspend unsupported. Two-CPU topology fails explicitly (`research/q0018-smp`).
- **Next blocker reproduced in 45s QEMU** (`research/q0018-long`, zero unknown glyphs): BSD initialization reaches MAC framework, network mcache and `mbinit: done`, then **`pthread kernel extension not loaded (function table is NULL). @pthread_shims.c:318`**. Do not bypass pthread_init: find/integrate the matching open-source libpthread kernel implementation and register its real function table. A 12s run `research/q0018` looked panic-free before the 30s IORTC wait elapsed; use >=45s or GDB checkpoints for the next iteration. No userland/root filesystem boot yet.
- **Phone 0018 TEMPORARILY BOOTED** 2026-10-15 **15:31:15 UTC**: exactly one FASTBOOT device verified product sweet; send OKAY0.400s, boot OKAY0.134s, total0.539s, exit0. Local log `research/boot0018.log`. This confirms bootloader acceptance only. User was asked for a photo; await it, DO NOT reboot the phone again before their observation. No flashing performed.
- Current hardware image `shim/out/shim-boot-0018.img`, **16,437,248 bytes**, SHA256 **`b7a23595d143a76c72c9fe2cfcc5d77a8f16987b5af1a2703bbffdfa6922908c`**. Phone ADT/payload `shim/out/sweet-0018.adt` / `shim/out/payload-0018.bin` (timer19), unpacked ramdisk exactly matches payload (`shim/out/check-0018`). EntryPA0xb146b488; kernelendPA0xb1ffc000; boot_argsPA0xb2000000/top0xb2004000. Command line `debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam -noprogress`.
- QEMU payload/ADT `research/q0018.bin` / `research/q0018.adt` (timer27). Run `python3 tools/qemu-sweet.py research/q0018.bin research/NEW-OUT --secs 45 --kernel xnu/out-0018/kernel.development.sweet --fail-on-panic`; fresh ADT seed for a new payload. Output fb.png/fb.txt/regs.txt/qemu.log/result.json. Visible panic exit2; blank/incomplete decode exit3; no_panic_observed is snapshot-only, not successful boot. -noprogress prevents the graphical indicator corrupting console text. Qualcomm XPU/bootloader/panel and SMC PSCI still need physical validation.
- Patches0014-0017 fixed PRNG registration/direct SHA256, explicit unavailable trust-cache service with rejected loads/no matches, built-in SweetPlatformExpert, and timer PPI from ADT (phone19/default19, QEMU27). All their checks/artifacts are preserved in the history below. CURRENT SWEET has NO USE_APPLEARMSMP; do not assume gCPUIC/gAIC/gPMGR AppleARMSMP globals exist.
- Local single-file checker: tools/xnu-cc.py research/run22.log research/bt22 FILTER --per-file, output via XNU_CC_OBJDIR. Patch checker `research/check-patch-order.py` applies all18 via temporary index, matches sandbox sources. Sandbox for0018 `research/bt21/xnu`, originals `research/pre0018`, objects `research/cpu-objs`. First compiler issues were missing machine/atomic.h and nonexistent getNameSymbol; fixed and both TUs compiled successfully before CI. Fixtures/artifacts under research are local-only/ignored.
- GDB: mask int(register)&((1<<64)-1) for unsigned kernel pointers; use function-entry manual-call return traps, discard manipulated guests. No QEMU fixture is intentionally left running.

### Earlier active handoff snapshot (superseded)


- **0018 milestone:** Actions `38760004398` PASSED (3m56s), checksums passed, new CPU/build files byte-match CI tree. Kernel `xnu/out-0018/kernel.development.sweet`, SHA256 `b3c8d59acc88f93a2c836eb2527a05ed4fbaac7c580a2ea8c3b795137f4aadf1`; log/tree `research/run22.log` / `research/bt22`. QEMU `research/q0018` 12s: boot CPU registered, SGI1 verified, CPU initialization complete, **BSD initialization entered** (copyright, MAC framework, buffer headers), no panic/zero unknown glyphs. Direct CPU API checks PASS (`research/check-cpu18.gdb`, `.log`, `research/q0018-api`): CPU0 Running, processor matches processor_array[0], real SGI enabled, CPU name correct, secondary-start returns KERN_NOT_SUPPORTED. Two-CPU ADT correctly panics before registration (`research/q0018-smp`). Longer 45s run `research/q0018-long` still running; next BSD wait/fault not yet identified.
- **Prepared 0018 phone image:** `shim/out/shim-boot-0018.img`, 16,437,248 bytes, SHA256 `b7a23595d143a76c72c9fe2cfcc5d77a8f16987b5af1a2703bbffdfa6922908c`. Phone ADT/payload `shim/out/sweet-0018.adt` / `shim/out/payload-0018.bin`, usual debug args with cpus=1 and -noprogress. Unpacked ramdisk byte-compared (`shim/out/check-0018`). Entry PA remains 0xb146b488; kernel end PA 0xb1ffc000, boot_args 0xb2000000/top0xb2004000. User reports FASTBOOT+USB ready; read-only check found exactly one product sweet. NEXT: temporary fastboot boot of this verified image, record send/boot results, then await hardware photo without rebooting again.
- Patch 0018 committed/pushed **`e7d9550`**; Actions **`38760004398`** queued/running: https://github.com/dipa-studio/ios-sweet/actions/runs/38760004398. Do not launch a duplicate run.
- Active continuation: patch **0018** implemented in `iokit/Kernel/arm/SweetCPU.cpp` + arm64 source list + exact qcom,kryo470 personality. Keeps legacy IOCPU, accepts ONLY the single boot CPU, fills ml_processor_info from parsed topology with CPU object as cpu_id, calls ml_processor_register and processor_start. initCPU sends SGI1 via ICC_SGI1R_EL1 and waits (1-second deadline) for real cpu_signal_handler to clear SIGPdisabled. Only after successful startup calls ml_cpu_init_completed/cpusRunning and publishes completion/max CPUs. Secondary startup/suspend are explicitly unsupported. Local C++ compile passed for both TUs (`research/cpu-objs`), all imports resolve, object contains dsb ishst / ICC_SGI1R / isb; all18 patches apply in order and match sources. Sandbox `research/bt21/xnu`, originals `research/pre0018`; next CI artifacts should use `xnu/out-0018`, `research/bt22`, `research/run22.log`. User has the phone available; first run QEMU, then prepare/temporarily boot useful hardware progress.
- Goal: iOS 16 generation XNU on Redmi Note 10 Pro / sweet. User wants persistent progress, commits, kernel builds via `gh` Actions, and this handoff kept current across agent switches. Temporary `fastboot boot` only; preserve Android and backups.
- Latest kernel implementation: **`aa3f991`**, patches **0001-0017**. All four new Actions builds PASSED: 0014 `38748543058` (4m0s), 0015 `38749549779` (4m3s), 0016 `38750733996` (4m3s), 0017 **`38751507437` (4m7s)**. Latest: https://github.com/dipa-studio/ios-sweet/actions/runs/38751507437. No build is pending.
- **Current blocker: CPU initialization has no SWEET CPU driver.** QEMU registers SweetPlatformExpert, then kernel_bootstrap_thread waits in **kperf_init_early -> ml_wait_max_cpus**. Confirmed via actual-kernel GDB call stack (`research/locate-cpu-wait2.log` / `.symbols`) and normal-run `max_cpus_initialized == 2` (MAX_CPUS_WAIT). Do not force the flag or remove the wait. Next implement real CPU registration and completion using XNU's CPU/processor interfaces. CURRENT SWEET uses legacy IOCPU (`USE_APPLEARMSMP` is absent); enabling AppleARMSMP is a separate architectural change requiring GIC/PMGR services. No userland/root filesystem boot yet.
- Fixed this session: PC=0 unregistered PRNG callback (0014, built-in HMAC-SHA256 provider + direct entropy/write_random hashing); absent Image4/AMFI trust-cache service (0015, unavailable runtime, loads rejected and queries no-match); missing platform driver (0016, SweetPlatformExpert exact personality); incorrect QEMU timer IRQ (0017, validated ADT PPI property, phone default19/QEMU27).
- **Latest kernel** `xnu/out-0017/kernel.development.sweet`, SHA256 `055a80190ab998b4df9203f1102072dcc78faad1779a537a514e522b682b582f`. Buildtree/log **`research/bt21` / `research/run21.log`**; all nine changed C/C++/header/config files byte-match local checked sources. Checksums passed. Entry PA `0xb146b488`, kernel end PA `0xb1ff4000`. Preferred baseline for patch 0018: `research/bt21/xnu` (no nested .git).
- **QEMU verified**: `research/q0017-noprogress` ran **30 seconds**, no visible panic, **zero unknown glyphs**, IRQ exceptions returned normally (4 IRQs, tickless idle). It still waits for CPU completion, so this is NOT a completed boot. Earlier 15s run `research/q0017` captured 122 IRQs, timer value27, GICR_ISENABLER0 `0x08000002`, and CPU WAIT; graphical progress overlay corrupted 13 glyphs. Add **`-noprogress`** to keep the console readable. New runner classifies incomplete/blank decoding explicitly (exit3 with --fail-on-panic), visible panic exits2. Snapshot-only; use regs/GDB to diagnose stalls.
- Current QEMU payload/ADT: **`research/q0017-noprogress.bin` / `research/q0017.adt`**. Run: `python3 tools/qemu-sweet.py research/q0017-noprogress.bin research/NEW-OUT --secs 30 --kernel xnu/out-0017/kernel.development.sweet --fail-on-panic`. Generate fresh seed with mkadt for a new payload. QEMU virt models generic ARM execution, not Qualcomm XPU/bootloader/panel or the phone's SMC PSCI conduit.
- **Prepared phone image**: **`shim/out/shim-boot-0017.img`**, 16,416,768 bytes, SHA256 `51ff7fe30b4a6668c3452ffe1da922c5ac30cb8de60625c2a652587ecbd0ec92`. Phone ADT/payload `shim/out/sweet-0017.adt` / `shim/out/payload-0017.bin` (timer19). Unpacked ramdisk exactly matches payload (`shim/out/check-0017`). Command line **`debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam -noprogress`**. NOT sent to phone this session: known CPU-driver wait should be addressed in QEMU first. Last actual phone boot remains 0013; user's latest photo `IMG_20261015_160033.jpg` confirmed the old PRNG PC=0 panic.
- Direct QEMU/GDB API checks: PRNG 600-byte chunking, buffer bounds, changing output, zero-length reads/writes, user reseed, contended refresh, generator1 init/output PASS again on latest0017 (`research/check-prng17.gdb` / `.log`, guest `research/q0017-api`). Trust-cache unavailable-service/argument/output cases PASS on0015 (`research/check-trustcache.gdb` / `.log`). Platform registration + target/product normal/truncated/zero/null/bounds PASS on0016 (`research/check-platform.gdb`, `research/check-platform3.log`). Different platform ID correctly retains IOPanicPlatform fallback (`research/q0016-negative`). Timer PPI32 and size2 correctly panic (`research/q0017-badppi`, `research/q0017-badsize`); omitted property selects19 (`research/q0017-default`). These are API/bring-up checks, not crypto certification or SMP scheduling validation.
- Local checker **`research/check-patch-order.py`** verifies all17 patches and changed source equality using a temporary upstream git index. Fixtures/logs/artifacts under research are local-only and ignored. For GDB unsigned kernel pointers, mask `int(register_value) & ((1<<64)-1)`; x30/x29 may be rendered signed. Stop at a function entry for manual-call return traps, and discard each manipulated guest after API tests. All fixture QEMU guests have been stopped.


- User wants persistent progress toward iOS 16, commits for completed changes, builds through `gh` / GitHub Actions.
- Keep this file current at every milestone so another agent can resume immediately, including when usage limits interrupt a session.
- Patch 0017 committed/pushed `aa3f991`, Actions `38751507437` running: https://github.com/dipa-studio/ios-sweet/actions/runs/38751507437. Next artifacts: xnu/out-0017, research/bt21, research/run21.log. Do not duplicate.
- Patch 0016 kernel downloaded/checksum verified: SHA256 `d06336c54baa06e0df6561a8bd7df98a9b9f7502c9381c62d1a44c045cd1ce46`, `xnu/out-0016/kernel.development.sweet`; buildtree/log `research/bt20` / `research/run20.log`. QEMU `research/q0016` (10s) prints platform expert registered, zero unknown glyphs, no panic observed BUT stalls (timer mapping still wrong until 0017). Direct actual-kernel GDB tests passed for registered instance and target/product names, including maxLength=1/0 and NULL, sentinels intact (`research/check-platform.gdb`, `research/check-platform3.log`, `research/q0016-api3`). First two fixture attempts used premature/wrong return breakpoints; discarded, corrected fixture uses start-return observation then a function-entry return trap. No phone boot yet.
- Patch 0016 CI `38750733996` PASSED (4m3s); artifacts not yet downloaded/booted. Patch 0017 prepared to fix QEMU timer fidelity BEFORE interpreting future no-panic/stall runs: actual `qemu-system-aarch64 -M virt,gic-version=3,dumpdtb=research/qemu-virt.dtb ...` timer property has virtual PPI 11 => INTID 27, while phone uses INTID 19. Kernel formerly hardcoded 19. New optional /arm-io/gic virtual-timer-intid property selects the PPI (validate exact u32 and 16..31); missing property retains phone default 19. One RO-late global drives GIC enable and sleh_irq dispatch. tools/mkadt.py emits phone19/QEMU27. Both C TUs compile (`research/timer-objs`), ADT serialize/parse checks confirm values/addresses, all 17 patches apply and match. Sandbox `research/bt19/xnu`, originals `research/pre0017`; initial local sleh compile failed due read-only exported header not updated, fixed export and BOTH recompiled successfully. CI exports normally.
- Architecture correction for next agent: CURRENT SWEET board_config does NOT define USE_APPLEARMSMP; it compiles the legacy IOCPU path, not cpu_boot_thread/IOPMGR AppleARMSMP. Existing roadmap mentions AppleARMSMP as a future approach. Do not look for gCPUIC/gAIC/gPMGR globals in the current kernel: they are absent. Determine the actual CPU-init wait after platform registration before choosing the next driver architecture.
- Patch 0016 committed/pushed as `0dcdf5c`; Actions `38750733996` running: https://github.com/dipa-studio/ios-sweet/actions/runs/38750733996. Next artifacts: `xnu/out-0016`, `research/bt20`, `research/run20.log`.
- Patch 0016 implemented: new `iokit/Kernel/arm/SweetPlatformExpert.cpp`, arm64 source list, built-in personality in KernelConfigTables.cpp guarded by ARM64_BOARD_CONFIG_SWEET. Matches only xiaomi,sweet at score 10000, keeps IOPanicPlatform fallback for other hardware. Uses IODTPlatformExpert base initialization/power domain and createNubs CPU logical-ID annotation; overrides top-level publishing because base requires nonexistent Apple NVRAM /options. Publishes real CPU/top-level nodes, provides bounded target/product names, and registers the platform service. GIC/PMGR and arm-io child-bus drivers remain separate work. Both C++ TUs compile (`research/platform-objs`), all imports resolve against 0015/own objects, all 16 patches apply and sources match. Sandbox `research/bt19/xnu`; originals `research/pre0016`. NEXT: full Actions/QEMU; inspect CPU boot waits after the platform registers, do not equate absence of panic with successful boot.
- Patch 0015 CI `38749549779` PASSED (4m3s), checksum verified. Kernel `xnu/out-0015/kernel.development.sweet`, SHA256 `ca1b424a596c7058550ad1659080a333e7643270f019656401d80bf2b876645f`; buildtree/log `research/bt19` / `research/run19.log`. QEMU `research/q0015` (10s, zero unknown glyphs) passes trust-cache handling and machine lockdown, then panics `Unable to find driver for this platform: "xiaomi,sweet" @IOPlatformExpert.cpp:2319` (IOPanicPlatform fallback). Next concrete work: add a built-in SWEET IODTPlatformExpert personality/class; keep the fallback for mismatched platforms. No phone boot yet.
- Direct trust-cache API checks PASSED in the actual 0015 kernel under QEMU/GDB (`research/check-trustcache.gdb`, `research/check-trustcache.log`, `research/q0015-api`): runtime pointers NULL, hash/UUID queries return NOT_FOUND, typed/untyped/legacy loads return NOT_SUPPORTED, capabilities outputs zero and bounds preserved, invalid-argument cases still reject. Second PRNG check also verifies contended refresh returns immediately (`research/check-prng2.log`, `research/q0014-api2`).
- Patch 0015 committed/pushed `8f851d4`, Actions run `38749549779` running: https://github.com/dipa-studio/ios-sweet/actions/runs/38749549779. Do not duplicate.
- Direct PRNG API checks passed in the REAL 0014 kernel under QEMU/GDB, stopped before trust-cache init (`research/check-prng.gdb`, log `research/check-prng.log`, guest `research/q0014-api`). Invoked read_random for 600 bytes (chunking and buffer sentinel intact), repeated output differed, zero-length read/write succeeded, write_random(64-byte input) succeeded, secondary generator 1 initialized and generated distinct output. QEMU log has no exceptions during these checks; guest was discarded after the tests. This tests API behavior, not a cryptographic certification or SMP scheduling.
- Patch 0015 implemented in `bsd/kern/kern_trustcache.c`: SWEET with missing Image4/AMFI marks both runtime pointers NULL and logs service unavailability. Existing static loader handles NULL. Public load APIs return KERN_NOT_SUPPORTED; hash/UUID queries return KERN_NOT_FOUND; capabilities outputs are zero with KERN_NOT_SUPPORTED. Invalid-input checks remain, and Apple paths/available-provider initialization retain existing behavior. No trust is granted. Local arm64 compile passed (`research/trustcache-objs`), all 15 patches apply and sources match. Sandbox `research/bt18/xnu`, baseline `research/pre0015`. Next: Actions/QEMU and direct unavailable-service API checks using GDB.
- Patch 0014 CI `38748543058` PASSED (4m0s), artifact checksum passed. Kernel `xnu/out-0014/kernel.development.sweet`, SHA256 `741de20c851755d333759d7e668346f3edb4f325efac4cc7c142d80d1f5ff75c`; buildtree/log `research/bt18` / `research/run18.log`. QEMU run `research/q0014` (10s, zero unknown glyphs) prints `SWEET PRNG: HMAC-SHA256 registered`, passes commpage initialization, loads vnguard policy, THEN panics `image4 interface not available @kern_trustcache.c:253`. PC=0 fault FIXED IN QEMU. No new phone boot performed.
- Next work: SWEET currently has neither AppleImage4 nor AMFI. `trust_cache_runtime_init` unconditionally requires both; unlike BCM2837, SWEET enters this startup path. Investigate an explicitly unavailable trust-cache runtime with rejected loads/no query matches while providers are absent; preserve all Apple-platform checks. Merely skipping the startup call would leave later AMFI/IMG4 dereferences unsafe. Existing load_static_trust_cache already handles trust_cache_rt == NULL.
- QEMU runner now supports `--kernel MATCHING_KERNEL --fail-on-panic`: runtime font extraction from the payload produces exact `fb.txt`, plus `result.json`; a visible panic returns 2. Baseline 0013 re-run `research/q0013-text` detects the same NULL callback panic with zero unknown glyphs. Synthetic glyph roundtrip (including literal `?`) and invalid-VA rejection passed. Screen rows remain circular, not a full log; `no_panic_observed` does not prove successful boot. README has the invocation.
- Patch 0014 committed/pushed as `be61f99`; Actions run `38748543058` is running: https://github.com/dipa-studio/ios-sweet/actions/runs/38748543058. Do not start a duplicate build.
- 2026-10-15 active: hardware photo `IMG_20261015_160033.jpg` confirms the same PC=0 instruction-fetch abort as QEMU (LR `0xfffffe0007443fe4` = read_random). Independently reproduced with kernel 0013 in `research/q0013` (8-second run); prior allocator fix works. Latest tooling commit reviewed: `8d66d2d`.
- Patch 0014 implemented: registers a built-in HMAC-SHA256 DRBG provider at EARLY_BOOT/FIRST, before commpage creation. A shared mutex serializes output/reseed across CPUs (correctness first; no per-CPU scaling yet), initgen validates CPU identities, refresh uses try-lock and the existing entropy filter/health tests. SWEET entropy accumulation and write_random now use the built-in SHA256 directly; no incomplete g_crypto_funcs table is registered. The existing bootloader-seed requirement remains enforced.
- Local validation: both PRNG translation units compile to arm64 objects in `research/prng-objs`; no SHA256 wrapper imports remain. All 14 patches apply in CI order and resulting PRNG sources match local inputs. Sandbox `research/bt17/xnu`, originals `research/pre0014`, checker `research/check-patch-order.py`. NEXT: Actions kernel build, download to `xnu/out-0014`, run the QEMU payload before requesting another phone boot. Baseline QEMU ADT/payload are `research/q0013.adt` / `research/q0013.bin`.
- 2026-10-15 08:15 QEMU EMULATION WORKS (`tools/qemu-sweet.py`, see "QEMU emulation" below). Patch 0013 VERIFIED in QEMU: boot passes kmem_crypto_init and ulock_initialize. NEXT BLOCKER (reproduced in QEMU, expected on hardware too): `pmap_create_commpages -> random() -> RandomULong -> read_random -> prng_funcs.refresh == NULL` (instruction fetch abort at pc 0, lr read_random+0x34). Nobody calls `register_and_init_prng` (closed corecrypto kext does it on Apple). Fix = patch 0014: SWEET-registered cckprng_funcs provider (osfmk/prng/prng_random.c); note random_cpu_init also panics while !prng_ready. The 07:26 hardware boot of 0013 will most likely show this same panic.
- Previous hardware boot: patch 0013 (`a3a46e2`) CI `38686345689` PASSED (3m44s), image `shim/out/shim-boot-0013.img` was temporarily booted on 2026-10-15 at 05:26 UTC: send OKAY (0.407s), boot OKAY (0.134s), total 0.546s. Superseded by the hardware/QEMU PC=0 observation and patch 0014 work above.
- Latest kernel implementation commit: `8f851d4`. Latest successful kernel CI: `38749549779` (patch 0015), https://github.com/dipa-studio/ios-sweet/actions/runs/38749549779.
- CURRENT image: `shim/out/shim-boot-0013.img`, 16,412,672 bytes, SHA256 `110d1c46aee4b60253db24b6535e9781c4cf0fd25ca2a70e9016cf81378cea25`. Kernel `xnu/out-0013/kernel.development.sweet`, SHA256 `f0b1d375995316c550ce7014ff234d8271e9b9ac2857795ceff41b76ba2cd740`, plain arm64. CI log confirms 0013 applied; checksums passed. Entry PA `0xb146b488`, kernel end PA `0xb1ff4000`.
- Current log/buildtree: `research/run17.log`, `research/bt17` (extracted, no nested .git; preferred baseline for patch 0014). Payload/ADT: `shim/out/payload-0013.bin`, `shim/out/sweet-0013.adt` (includes /defaults). Unpacked ramdisk byte-compared with payload in `shim/out/check-0013`.
- Patch-0012 original image: `shim/out/shim-boot-0012.img`, 16,412,672 bytes, SHA256 `cf4b8ec4a65a51888d71c17d09cd0831d6b761b90e2531fdb8e575c32f4fd24a`. Kernel `xnu/out-0012/kernel.development.sweet`, SHA256 `69b78f49f6459cc63a0af44e7cf73c1779ef72130ef72b12ae86c88183ffc742`; checksums passed and sweet_early_relocate symbol present. Entry PA remains `0xb146b488`, kernel end PA `0xb1ff4000`.
- Patch-0012 log/tree: `research/run16.log`, `research/bt16` (extracted, no nested .git; preferred baseline for next patch). CI log confirms 0012 applied. Payload `shim/out/payload-0012.bin`, ADT `shim/out/sweet-0012.adt`; packed ramdisk byte-compared with payload in `shim/out/check-0012`.
- Active payload command line: `debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam`.
- Latest observed photo: `/home/dipa/Downloads/IMG_20261015_071346.jpg` (local only). Stages 9 (kernel framebuffer VA), 10 (TTBR0 off/TLB flush), 11 (physmap table pointers) and 12 (calling pmap_bootstrap) all visible. Persistent diagnostics are VERIFIED ON HARDWARE.
- pmap.c:1987 is the assert after SecureDTLookupEntry(NULL, "/defaults", &entry). The pmap-max-asids property itself is optional; an empty /defaults uses XNU's MAX_ASIDS. Do not bypass the assertion or guess an ASID limit.
- Previous payload-only fix image: `shim/out/shim-boot-0012-defaults.img`, SHA256 `3ff61a268853c6ea7cbf284833f1346a1d791980ca366b6e1a215a86e040512b` (16,412,672 bytes). Same kernel/CI as 0012; ADT 2516 bytes (`shim/out/sweet-0012-defaults.adt`), root /defaults present with no ASID override. Payload `shim/out/payload-0012-defaults.bin`; unpacked ramdisk exactly matches payload (`shim/out/check-0012-defaults`). This boot reached the allocator crypto NULL-pointer fault below.
- Latest hardware photo: `/home/dipa/Downloads/IMG_20261015_071608.jpg` (local only). Normal serial framebuffer console works. VM bootstrap/zone initialization, logging, scheduler, IPC, KDP and ulock_initialize print before the kmem_crypto_init data abort. gPanicBase warnings are expected because PLATFORM_PANIC_LOG_DISABLED is configured, and are not the faulting call.
- Faulting instruction: `ldr x0, [x8, #0x150]` in crypto_random_kmem_ctx_size; x8 = NULL g_crypto_funcs. Source: libkern/crypto/corecrypto_rand.c and osfmk/vm/vm_kern.c:2448. rand.h explicitly permits NON-cryptographic kmem RNGs, but requires no locking in generation and context size <=256. Do not substitute read_random here: the global PRNG provider is also unregistered and kmem generation must remain lock-free. early_random may seed contexts during single-CPU bootstrap; it uses the built-in HMAC-SHA256 DRBG with the host-generated ADT seed.
- Patch 0013 keeps the replacement entirely private to vm_kern.c: SplitMix64 state is 8 bytes per CPU/sizeclass, initialized using early_random. Uniform selection uses rejection sampling to avoid modulo bias. Other platforms retain the original corecrypto calls; SWEET's generic crypto APIs/registration remain untouched. Reference: https://prng.di.unimi.it/splitmix64.c (Sebastiano Vigna, public domain).
- Validation: vm_kern.c compiles to arm64 (`research/kmem-rng-objs`, using `research/run16.log` + `research/bt16`). Undefined symbols include early_random and NO crypto_random_* references. All 13 patches apply in CI order and match the checked source. Original saved as `research/vm_kern.pre0013.c`.
- RNG host checks: extracted actual new helper in `research/kmem-rng-check.c`; 16,384 outputs match the author's downloaded reference (`research/splitmix64-reference.c`), 147,456 bounded outputs satisfy their limits (including 1 and UINT64_MAX), and a forced rejection advances correctly. Full kernel crypto services and the registered kernel PRNG provider remain future work; this patch only supplies the allocator RNG contract.
- Patch-0011 artifacts: kernel `xnu/out-0011/kernel.development.sweet`, log `research/run15.log`, extracted buildtree `research/bt15` (no nested .git). CI log confirms patch 0011 applied; artifact checksums passed. Kernel is plain arm64, entry VA `0xfffffe000746b488` -> PA `0xb146b488`, kernel end PA still `0xb1ff4000`.
- Patch-0011 image: 16,412,672 bytes, SHA256 `29ad5cbfc752473de4af2c471a24a8b34f92da4bff5afec65c614b90cd3ad53a`. Kernel SHA256 `8ac3a956894b09f7bd0d890de8c5de38c65513287feb1e1bcd12db8ca772ee5c`. Payload/ADT in `shim/out/payload-0011.bin`, `shim/out/sweet-0011.adt`. Header unpacked/checked in `shim/out/check-0011`.
- First patch-0011 attempt timed out waiting for FASTBOOT; superseded by the successful send/boot recorded above. Do not repeat the boot before the user reports the current screen.
- Patch-0011 photo: `/home/dipa/Downloads/IMG_20261015_070218.jpg` (local only). Visible stages 1-8 and old red shim text; entry PA B146B488, boot args PA B1FF8000 / top B1FFC000. No evidence yet locating execution after stage 8.
- Patch-0012 sandbox: `research/bt15/xnu` (NO nested .git). Proposed permanent debug VA: VM_MIN_KERNEL_ADDRESS + ARM_TT_L2_SIZE, in the reserved gap below gVirtBase and above low globals; map the same PA framebuffer as Normal-NC in the final TTBR1 before arm_vm_physmap_init changes phystokv(). Keep the early panic sink until normal kprintf startup.
- Patch 0012 validation: all 4 changed C translation units compiled to arm64 objects in `research/post-ttbr0-objs`; internal header export added to osfmk/arm64/Makefile and recreated locally in EXPORT_HDRS for pe_serial.c. All 12 patches apply in CI order and match all 6 edited files. Baselines are saved under `research/pre0012/`.
- Actual mapping-helper host model (`research/early-map-check.c`, barrier stubbed only for host compilation) confirms: VA `0xfffffe0002000000`, L1 index 2016, L2 index 1; descriptor `0x006000009c000605` = framebuffer PA, Normal-NC, outer-shareable, EL1 RW, PXN+UXN. All other L2 entries preserved. The gap is excluded by ARM_LARGE_MEMORY's pmap_virtual_region(0).
- Next boot command line MUST add `-enable_kprintf_spam`: DEVELOPMENT disables kprintf_output by default even when DB_KPRT is set (`pexpert/arm/pe_kprintf.c`). Planned command line: `debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam`.

### Patch 0012 screen legend (after original stages 1-8)
- 9: kernel framebuffer VA live; 10: TTBR0 off / TLB flushed; 11: physmap pointers rebound.
- 12: calling pmap_bootstrap; 13: pmap_bootstrap returned; 14: early I/O page tables ready; 15: arm_vm_init returned.
- 16: calling serial_init; 17: fbcon config read / mapping; 18: fbcon mapping returned; 19: serial_init returned; 20: kprintf startup complete.
- Normal serial initialization clears the screen, so earlier stages may disappear before 19. If serial exists, early console disables after 20; otherwise early panic output stays enabled.
- Local source sandbox: `research/bt13/xnu` (git baseline `623b060`, patches 0001-0008 already in baseline; uncommitted export edits correspond to patch 0009). Preserve those edits when producing patch 0010.
- Previous compile log/tree: `research/run13.log`, `research/bt13`; previous kernel: `xnu/out/kernel.development.sweet`. New successful log/tree: `research/run14.log`, `research/bt14`; new kernel: `xnu/out-0010/kernel.development.sweet`.
- Current device access: patch-0012 image was temporarily started from FASTBOOT; no adb connection is expected. Never flash partitions for bring-up; use `fastboot boot` with the shim image.
- Patch `0010` lives in `xnu/patches/0010-sweet-early-framebuffer-debug.patch`. Its exact compiled sources are under `research/bt13/xnu`; generated objects are in `research/early-objs`.
- Local checks passed: all 5 changed/new translation units compiled to arm64 Mach-O objects; new console only imports `_doprnt` and `iso_font` (both exist in the previous kernel). All 10 patches applied to a temporary upstream git index in CI order, and all 7 resulting changed source files matched the local compile inputs.
- Reproduce changed-file compilation: `XNU_CC_OBJDIR="$PWD/research/early-objs" python3 tools/xnu-cc.py research/run13.log research/bt13 arm_init.c arm_vm_init.c kern/debug.c arm64/start.s osfmk/arm64/sweet_early.c --per-file` (create the output directory first). The helper now accepts explicit new source paths absent from the old artifact's Makefiles and rejects empty selections.
- Device command result: `adb reboot bootloader`, then `timeout 30s fastboot boot shim/out/shim-boot-0010.img`: send OKAY (16028 KB), boot OKAY, total 0.541s. This confirms bootloader acceptance only, not XNU progress.
- The successful boot above was on 2026-10-14. On 2026-10-15, `timeout 45s fastboot boot ...` timed out waiting for a device; no image was sent. Boot image SHA256 rechecked and unchanged. No new build is needed to repeat the trial.
- Earlier retry: `timeout 90s fastboot boot shim/out/shim-boot-0010.img` timed out (exit 124). This is superseded by the successful 2026-10-15 repeat boot recorded above; do not repeat it until the user reports the screen.
- User observation confirms MMU-on C entry, platform expert, CPU topology/bootstrap, startup bootstrap and cpu_init all complete. Failure is within arm_vm_physmap_init (non-XNU_MONITOR branch), before stage 8 / TTBR0 teardown. Old red shim text remains behind the early console; this is expected because only written rows are cleared.
- New edit/compile sandbox is `research/bt14/xnu` (extracted artifact, NO nested .git; `git diff` there would act on the parent project). Use a saved baseline file / generated unified diff, or explicitly initialize a local baseline before editing. `research/bt13/xnu` does have its own baseline git repo.
- Exact user-reported panic: `arm_vm_init.c:1606 Assertion failed: (temp_ptov_table[ptov_index - 1].va + temp_ptov_table[ptov_index - 1].len) <= physmap_end`.
- Root cause: MacOSX build sets `ARM_LARGE_MEMORY=1`; `XNU_MONITOR` is off. Block alignment in arm_vm_physmap_slide can add gaps, but the non-PPL large-memory physmap_end omitted the padding already present in the small-memory branch. Patch 0011 reserves PTOV_TABLE_SIZE*ARM_TT_TWIG_SIZE (8*32MB) in both the aperture bound and its L1 allocation; monitor/PPL builds retain zero padding. The assertion is preserved.
- Validation: `arm_vm_init.c` compiled to an arm64 object using `research/run14.log` + `research/bt14` (object in `research/physmap-objs`). All 11 patches apply in CI order and produce exactly that source. Host harness `research/physmap-check.c` extracts the real XNU slide function with page-table-write stubs: all 65,536 page-aligned slides within 1GB checked against the current kernel memory layout; old bound fails 65,504 cases, padded bound fails zero; worst overrun 0x1ffc000 bytes. Baseline source saved as `research/arm_vm_init.pre0011.c`.
- CI: https://github.com/dipa-studio/ios-sweet/actions/runs/38638702083 (success; artifacts and full log downloaded).
- New image: `shim/out/shim-boot-0010.img` (16,412,672 bytes, SHA256 `ed2c270e0081bad5ff517be415f9bfe8805463aea7866732203fa97ac737e64e`). Previous image preserved as `shim/out/shim-boot-pre0010.img`.
- New kernel SHA256: `3ee05270cc291c49589a101678f904b1b69cb2f2575e05398bce8a4e052f409a`. Artifact checksums passed; arm64 (not arm64e), early-console symbols present. Payload entry VA `0xfffffe000746a488` -> PA `0xb146a488`; kernel end PA `0xb1ff4000`. Command line remains `debug=0xc serial=3 cpus=1 keepsyms=1`.

### Patch 0010 screen legend
- Bottom-left white 64x32 tile: assembly entered `start_first_cpu`, before page tables/MMU.
- Text `SWEET EARLY 1`: entered `arm_init` with MMU on; 2: platform expert done; 3: CPU topology done; 4: CPU bootstrap done; 5: startup bootstrap done; 6: CPU init done; 7: entering `arm_vm_init`; 8: leaving bootstrap TTBR0.
- `SWEET EARLY PANIC:` prints a copy of panic arguments before normal panic handling needs per-CPU/thread state.
- In patches 0010/0011 the console disabled before TTBR0 invalidation; patch 0012 replaces that with a persistent kernel VA alias and diagnostics through normal serial/kprintf startup (see its legend above).
- Screen contents require a physical observation from the user: adb cannot capture a framebuffer after Android has been replaced by a bare-metal kernel.

## QEMU emulation (2026-10-15)
- `tools/mkadt.py OUT.adt --qemu` = same ADT with QEMU virt GICD 0x08000000 / GICR 0x080a0000 / CNTFRQ 62.5 MHz.
- `tools/qemu-sweet.py PAYLOAD OUTDIR [--secs N] [--hmp "x /8gx ADDR"] [--gdb]`: host-side copy of shim/loader.c
  (segments + ADT + boot_args at their PAs, 6-instruction stub sets x0 and jumps), `-M virt,gic-version=3 -cpu cortex-a76`
  (same ID_AA64MMFR0 as Kryo 470), 4G RAM so 0x9c000000 fb and 0xb0000000 kernel are plain RAM.
  Outputs `fb.png` (the screen), `regs.txt`, `qemu.log` (exceptions with ESR/FAR/ELR). `--gdb` halts with a stub on :1234
  (system `gdb` + `set architecture aarch64`, `hbreak *VA` works with the MMU on).
- Not emulated: Qualcomm XPUs, ABL, real panel, PSCI conduit (QEMU virt uses hvc). Hardware still decides those.
- Example: `python3 tools/mkadt.py /tmp/q.adt --qemu && python3 tools/mkpayload.py xnu/out-0013/kernel.development.sweet /tmp/q.adt /tmp/pq.bin --cmdline 'debug=0xc serial=3 cpus=1 keepsyms=1 -enable_kprintf_spam' && python3 tools/qemu-sweet.py /tmp/pq.bin /tmp/q`

## Layout
- `backup/`  partition dumps + full sdb..sdf LUNs, `SHA256SUMS` (all verified on-device == local)
- `dtb/`     live FDT (from OrangeFox), PixelOS boot.img dtb, dtbo, dts versions
- `shim/`    bare-metal boot shim (`./build.sh` -> `out/shim-boot.img`)
- `research/` mainline sm7150 dts, XNU pe_fiq.c etc, PocketDarwin patches
- `tools/unpack_bootv2.py`

## Device access
- No root in PixelOS 17 (user build, adb root disabled). Root = `fastboot boot recovery/recovery.img` (OrangeFox R12.0_2, temp boot, not flashed).
- `fastboot boot` works for stock boot.img, OrangeFox, and our shim.
- Shim resets itself via PSCI SYSTEM_RESET; IMEM restart_reason 0x77665500 is seen
  (bootreason=bootloader) but ABL still boots Android, so it does not stop in fastboot.

## Hardware facts (live DT + shim measurements)
- Framebuffer (ABL cont splash): 0x9c000000, 1080x2400, stride 4320, a8r8g8b8, panel is DSC *video* mode (no kick needed).
- RAM: 0x80000000+2G, 0x100000000+0xfcc00000. Live reserved-memory = PixelOS base dtb + sweet dtbo fixups.
- GICv3: GICD 0x17a00000, GICR 0x17a60000 (stride 0x20000, 8 PEs). GICD_TYPER 0x007B041D: SecurityExtn=1 (DS=0).
  ABL leaves GICD_CTLR = 0x10 (ARE_NS on, groups off). Writing 0x13 reads back 0x12: EnableGrp1A (bit1) is the one that matters.
- GIC Group 1 VERIFIED (shim 2c): vtimer INTID 19 = 30 IRQs/300ms, ptimer INTID 18 = 30, SGI 1 to self = 10/10.
  ICC_SRE=1 already, ICC_CTLR 0x8440, priority/enable writes stick. GICR_IGROUPR0 and GICD_IGROUPRn read 0 from NS
  even though Group 1 delivery works (RAZ in NS view) - do not use them as a health check.
  INTID 28 shows pending constantly (unknown PPI 12).
- Timer 19.2 MHz. Qualcomm PPI numbering: secure-phys/phys/virt/hyp = PPI 1/2/3/0 -> vtimer INTID 19, ptimer 18 (NOT 27/30).
- PSCI 1.1 via SMC, SMCCC 1.1. CPU_ON ok; SYSTEM_SUSPEND and SYSTEM_RESET2 unsupported.
- SMP: CPU_ON works for all 7 secondaries (MPIDR 0x81000n00).
- Entry EL1, MMU off, x0 = DTB (magic ok). ID_AA64MMFR0 = ...101122: 16K granule YES, 4K YES.
- No serial console: debug UART SE is in SPI mode on sweet. Screen is the only debug channel.

## XNU implications
- XNU GICv3 path (pexpert/arm/pe_fiq.c, VMAPPLE) puts the timer (PPI 27) in Group 0 = FIQ. With SecurityExtn=1,
  Group 0 is secure -> impossible from NS EL1. Need: Group 1 IRQ, ICC_IGRPEN1, INTID 19, and the timer handled in the IRQ path.
- XNU VMAPPLE PSCI uses `hvc`; sweet needs `smc`.
- PocketDarwin NonAppleGenericCpu.patch only swaps -mcpu=apple-h7 for -march=armv8-a.

## Milestone 3 (2026-10-14): 16K MMU verified
- ABL loads the Image at 0x80080000 (base 0x80000000 + 0x80000) regardless of text_offset=0.
- 16K granule, T0SZ=28 (L2 start, 32MB blocks), MAIR 0x44ff00, TCR 0x1409CB51C, PARange=2 (40-bit PA).
- Only own image pages WB (Qualcomm XPUs: never map carve-outs cacheable); fb Normal-NC; rest Device.
- AT S1E1R checks all as expected; unmapped -> translation fault L2.
- Fill fb: 110 ms (MMU off) -> 3.5 ms (NC). Memory loop 70 ms -> 0.7 ms. vtimer + SGI IRQs still fine with MMU on.

## XNU loader design notes (xnu-8796)
- Entry: `_start` -> `start_first_cpu`, x0 = boot_args (PA), MMU off, EL1. boot_args: Revision/Version 2,
  virtBase/physBase/memSize/topOfKernelData, Boot_Video (fb 0x9c000000, rowBytes 4320, 1080x2400, depth 32),
  deviceTreeP/Length (ADT), CommandLine[608], bootFlags, memSizeActual.
- start.s maps [kernel mach header .. physBase+memSize) with cacheable BLOCKS. On Qualcomm every XPU carve-out
  must therefore lie below the kernel: use physBase = 0xb0000000 (above ramdump_fb 0xaf000000+16M,
  cdsp_sec, qseecom), end before rmtfs 0xfde01000 -> memSize ~0x4d000000 for bring-up.
- Base ADT: iPhone 8 d20ap DeviceTree from iOS 16.7.16 IPSW (tools/remotezip.py + tools/adt.py; LZFSE payload).
  Template values are empty: the loader must fill chosen/*, memory-map, cpu*/reg etc. like iBoot.
- XNU build: GitHub Actions (dipa-studio/ios-sweet, xnu.yml) via blacktop/darwin-xnu-build, MACOS_VERSION=13.5.
  New-clang fixes in xnu/patches; Xcode 16 iig is incompatible (IORPC.kernelContent) -> macos-14 runner, oldest Xcode.

## Kernel architecture plan (SWEET machine config)
- First stock build (VMAPPLE) is arm64e (PAC). Kryo 470 = ARMv8.2, no PAC -> SWEET must build plain arm64
  (HAS_APPLE_PAC is only defined for __arm64e__, so arm64 drops PAC automatically).
- Template: VMAPPLE (16K pages, GICv3 code in pe_fiq.c) minus APPLEVIRTUALPLATFORM hypercalls/paravirt PAC,
  plus BCM2837 (generic ARM: no APPLE_ARM64_ARCH_FAMILY Apple sysregs). Do not link the KDK lib<cfg>.os.*.a.
- Timer: XNU expects it on FIQ (sleh_fiq -> rtclock_intr). SWEET: GIC Group 1, so sleh_irq must ack ICC_IAR1,
  route INTID 19 to the same timer path, SGIs to cpu_signal_handler, EOI via ICC_EOIR1.
- SMP/interrupts: open-source AppleARMSMP (USE_APPLEARMSMP) needs an IOInterruptController (AIC role) and an
  IOPMGR (CPU power -> PSCI CPU_ON via SMC). Plan: built-in IOKit classes (SweetGIC, SweetPMGR, platform
  expert) compiled into the kernel and matched via iokit/KernelConfigTables.cpp -> no closed kexts needed.
- Debug: xnu patch 0003 sweet-fbcon = kprintf drawn on the framebuffer (ADT node "sweet-fbcon").
- ADT /arm-io ranges must not map to parent 0 (pe_arm_get_soc_base_phys()==0 disables serial): use parent 0x1000000.

## Status 2026-10-14 late: first XNU boot attempt
- SWEET kernel builds (CI run 38635343732, patches 0001-0009). Verified offline: arm64, no PAC, no >v8.2 code,
  70300 classic relocs all in range (slide 0 = no loader work), entry = __start.
- Boot: shim loader worked (initrd 0x846F0000-0x855FE3E0, BOOTARG 0xB1FF8000, JUMP 0xB146A488) but screen stayed
  red -> xnu died/hung before serial_init (fbcon). kprintf is a no-op before STARTUP_SUB_KPRINTF.
- Historical next-step plan (patch 0010, now implemented and built; see active handoff above): early fb debug channel
  1. start.s start_first_cpu (after mov x20,x0 / mov x21,#0): PA marker band (MMU off, direct store to 0x9c000000).
  2. start.s after both create_bootstrap_mapping calls: add ONE block entry to the existing V=P L2 table
     (x25 + 2*PGBYTES; do NOT call create_bootstrap_mapping again: fb and RAM share L1 entry 0, it would replace
     the L2 table). Entry = TYPE_BLOCK|VALID|SH(OUTER)|ATTRINDX(CACHE_ATTRINDX_WRITECOMB=1)|AF|PNX|NX|0x9c000000,
     index = (va & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT.
  3. new osfmk/arm64/sweet_early.c (+files.arm64 entry): sweet_early_mark(n) colored bands at screen bottom and
     sweet_early_putc using iso_font via VA=PA while the bootstrap TTBR0 is live; disable before
     arm_vm_init's set_mmu_ttb(invalid_ttep) (arm_vm_init.c:2148).
  4. markers in arm_init after PE_init_platform, ml_parse_cpu_topology, cpu_bootstrap, kernel_startup_bootstrap,
     cpu_init, before arm_vm_init.
  5. panic hook at top of panic_trap_to_debugger: va_copy + _doprnt(fmt, &copy, sweet_early_putc, 16).
  Verify with tools/xnu-cc.py (compile+symbols) and patch-order simulation before the single CI run.
