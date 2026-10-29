# Polaris20H392 GPU integration

0105 adds a **default-off wall-time diagnostic**, without changing rendering,
GPU submission/completion, surface ownership or performance requests. Exact
`touch_lat=2` retains the full frame trace and measures library tail, logging,
observer callbacks and pre-first-draw GL API work; `touch_lat=3` keeps the same
accounting but omits the per-frame `tl: g` write for a separate comparison.
The existing `touch_lat=1` path remains available as the original control.

Each per-process/per-context window closes64 consecutive frame intervals at
the next actual frame begin. Six short records carry one matching identity;
the host rejects missing parts, broken time partitions or discontinuous
windows. Full-trace mode independently matches every original frame timestamp.
Output cost belongs to the next closed interval and is never subtracted.
Idle intervals remain in totals; the separately reported active subset uses
an explicit100ms period bound. The final unclosed interval is not measured.
Wall times include preemption: pre-frame API time is not pure CPU busy, and
the remaining outside interval also includes caller work and scheduling.
These counters establish neither physical scanout frequency nor60FPS.

The physical0105 trial matched1664 pairs against the full trace, passed GPU
pixels and lock/home/Settings/scroll/home checks, then completed native shutdown
and independently verified FASTBOOT. In its measured832-pair window, average
library tail was73.266us (logging63.819us), and pre-frame GL API work119.191us.
Subtracting both per-window maxima from each exact gap still leaves a median
2095us lower bound outside those paths. The separate <=25ms-period cohort has
570 pairs and a1872us median lower bound; all longer input pauses remain in
the full population. These are bounds, not individual scheduler-wait samples.
Reducing logging alone therefore cannot account for the observed interframe gap.
CPU-policy fallback and compositor/frame-clock timing remain separate concerns.

0106 adds a default-off, scoped clock experiment. Exact `ca_vbl=0` observes
the normal CoreAnimation decision; exact `ca_vbl=1` sets `CA_FORCE_TIMER=1`
before executing the pixel-tested desktop process. No launchd-wide environment,
GPU performance request, panel register or native VSYNC deadline changes.
Duplicate settings, inherited clock variables and failed environment changes
refuse the experimental exec. The existing no-token path stays unchanged.

The injected observer checks the actual20H392 QuartzCore UUID, readable
segment bounds, code signature and fixed `CADeviceUseVBL` state/once addresses.
It reads them only after the existing >=1s performance callback. An uncompleted
once token is explicitly uninitialized, not a zero-valued decision. The logged
`window_frames` count belongs to that performance window, not a cumulative
frame sequence. A selected CA path is neither physical refresh rate nor proof
of60FPS; actual control/treatment UI, frame/copy timings and native shutdown
must still pass before accepting this experiment.

0054 has **physical native command/fence/4096-pixel/idle/halt proof, forced
GMEM framebuffer-fetch/restore/pixel acceptance, and sustained real desktop
GPU submissions**. The human confirmed submission counts rise with scrolling;
photos show desktop C739, C1605 and C1663 with T6/E0/D0/R1. Home-screen bitmap
icons are still missing, so rendering correctness and measured FPS remain
unfinished. Metal application support is a separate layer.

0055 additionally passes actual caller-memory EAGL BGRA/ABGR alpha and live
pixel-update tests before T6. A later photo shows794 desktop submissions,
T6/E0/D0/R1 and no renderer error; residual stutter remains. CPU1 still
performs the final panel copy (one photographed copy10.636ms wall time).

0056 separates60Hz notification deadlines from budgeted copy deadlines;
copy cost still reserves half the interval for other CPU work, with a1ms
minimum timer yield. Early copy wakes do not send extra VSYNC notifications.
A synthetic10636us-copy timeline reproduces the old30copies/s quantization
and permits46–48copies/s with independent deadlines. This is a scheduling
regression test, **not a measurement of physical phone FPS**.

The normal panel now has six necessary rows rather than29 boot snapshots:
USB summary, GA, FD, GLR, PF(or first GLX error), and GLT. First runtime GPU
fault and first process crash add their saved details only when present,
at most eleven rows. Detailed hardware initialization stays in the RAM log.
No display callback reads GPU registers or gathers host CPU statistics.

`FD` uses decimal values: `P` is actual copied frames per second x10 over
the latest elapsed>=1s window, `C` average panel-copy wall microseconds,
`J` largest within-window interval between successful copied frames,
`D` the previous diagnostic repaint's wall microseconds. Idle lowers P;
measure while continuously scrolling. `PF` reports the latest renderer
window's average wall microseconds: `F` from first draw through frame end,
`W` final completion/copy-submission wait, `R` copying render targets back,
`U` uploading IOSurface pixels, `H` checking wrapped-image contents.
Stages can overlap; do not add them as a partition of F or treat W as GPU
utilisation. CPU `B` is aggregate host busy in basis points(9900=99%),
`N` online cores; B10001/N0 means unknown. CPU counters are sampled at
most once a second outside the rendering timer. PF retains the last active
window when idle. First renderer errors always override PF. Diagnostic
reports never establish readiness/completion or allow another GPU writer.

The A630 hardware bootstrap follows this phone's DT, original MiCode sources
and original firmware. `polarisgpu=9` retains that baseline. An additional
`polarisgpuclient=1` allocates resident CB0 page tables before bootstrap and
publishes `PolarisGPU` only after the entire native proof passes. CB1/GMU,
foreign/HYP contexts, firmware authentication and the tested SQE order remain
owned by the original bootstrap. Runtime submission does not reset or power
cycle the GPU.

The initial MSM1.7 implementation supports **one verified writer**, synchronous
IB submission, CPU cache maintenance and imported SweetSurfaces. It is a
development window-server backend, not isolated GPU address spaces for every
application. The20H392 window server runs as `mobile`; admission verifies its
actual root-owned executable vnode and checks the owner task on every method
and mapping. The separate acceptance executable is the other admitted image.
An unknown DMA completion retains the client, mappings, backing descriptors,
firmware/power and tables until reboot. No forced teardown/recovery is claimed.

`SweetSurface` pixel memory starts at offset **zero**, unlike the reference's
MiniIOSurface layout. Imported surfaces stay retained. All referenced BOs are
cleaned before submission; success requires the render flush fence, consumed
ring, idle core and halted SQE. Cache invalidation precedes a successful reply.
The display skips a busy surface and never reads GPU registers from its timer.

The `polarisgl=1` test image carries a SHA256-checked fixed-six-file bundle in a
reserved payload segment. The kernel accepts it only with the verified file
root and512MiB volatile RAM COW. It creates new files with `O_EXCL`; it does not
write a partition or overwrite the Apple bootstrap. A small PID1 program then
renames the original backboardd and activates the wrapper using POSIX rename,
with rollback on failure, and immediately execs Apple's `/sbin/launchd`.
Reboot discards the entire overlay. The existing Android/Windows installation,
root-image file, GPT, bootloaders and backups remain unchanged.

The wrapper launches a separate-task acceptance program before genuine
backboardd. That program rejects a software renderer, compiles GLSL, imports a
64x64 BGRA IOSurface, renders into it, waits, and compares all4096 pixels through
the CPU mapping. Only an exit status0 enables the EAGL bridge. A failed test
or180-second timeout retains the existing CPU interface. The test and normal
backboardd never compete for the exclusive connection.

`GA` replaces one completed native status row without increasing panel height:
`O` is an open client, `S` completed submissions, `I` surface imports, `T` the
acceptance phase(1connection/2context/3shader/4surface/5draw/6pixels), `E` the
test error, `D` runtime quarantine and `R` backend readiness. `S`/`I` are hex.
On runtime quarantine, three completed native rows show the first error and
expected/actual values, CP/IRQ/protection status, and the exact64-bit fault
address/syndrome. Capture is seven fixed read-only accesses within the existing
deadline; an expired deadline is never renewed and the valid mask says which
words were actually read. Rendering only formats the immutable snapshot.
T6/E0 with increasing S during real interface use is distinct from the earlier
native proof. Full original diagnostics remain in RAM.

0049 fixes the injector's program-name gate: the original executable is now
`/usr/libexec/polaris-bbd-real`, while dyld derives the program name from the
kernel's executable path, even when the wrapper rewrites argv[0]. The bridge
checks `_NSGetExecutablePath` against that exact path and the successful-test
environment; kernel admission still verifies the actual executable vnode.
See Apple's [dyld1042.1 ProcessConfig](https://github.com/apple-oss-distributions/dyld/blob/dyld-1042.1/dyld/DyldProcessConfig.cpp).
The existing AMFI request ABI and all7 required EAGL methods were independently
checked against the actual20H392 cache. All7 methods are preflighted before
any replacement; an installation failure restores the original implementations.

The injector opens one task-owned GPU connection and passes that same port to
Mesa through its existing `POLARIS_GPU_CONNECTION` adapter. It never borrows
the child selftest's port. Opening the connection alone does not prove drawing.
Cached fields appended to the existing GA row keep the selftest T/E intact:
L1 means scoped dyld policy answered, L2 injector admitted, L3 bridge loading,
L4 all methods installed, L5 CA requested a context, L6 context created.
X is the loading error (1environment,2dlopen,3missing status exports,
4method installation,5API/allocation,6Mesa context); at L1 it is policy errno.
M is the7-bit method mask, required0x7f. The trusted-server-only12-byte selector
0x7b changes diagnostics only, never native readiness/submission/import counts.
Context reports happen on first request/success and failures, not every frame.
Neither L6 nor O1 alone proves desktop acceleration: S and I must increase
beyond the single selftest submission/import during real interface use.

The0048 bootstrap keeps the0047 hardware/submission path intact. Bundle files
are installed in at most128KiB synchronous VFS writes, with the volatile-root
guard rechecked before each request. `GLB` records the last completed-byte
count and the call being entered: S1native wait, S2bundle validation, S3open,
S4write, S5size check, S6close, S7all staged, S8activation-helper exec,
S9helper-exec failure. F is the file index0..5; B is done/total, E is errno,
and ms is elapsed milliseconds at the last update. All GLB numbers are hex.
An individual VFS call can still block; this is not an asynchronous timeout
or proof that a stalled HFS call can be cancelled. Important first hardware
snapshots and new faults stay in RAM; periodic diagnostics avoid reprinting
unchanged full hardware snapshots and instead print compact GLB/GA progress.
The optional AMFI hook returns the original absent-policy result ENOPOLICY
for every non-target and refuses PID1 before any executable-vnode lookup.

Sources and licensing:

- Kernel/userland interfaces are informed by the local HackiOS references in
  `REFERENCE_REPOS.md`; their MIT license is preserved in `LICENSE.hackios`.
- All457 EAGL slot offsets and the two optional QuartzCore vtable targets were
  checked against the actual20H392 cache before building. No Apple code or
  binaries are stored here.
- Mesa25.0.7 uses the pinned official archive SHA256
  `592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6`
  and the two existing Darwin/ES profile patches. Mesa retains its own license.
- `tools/build-polaris-mesa.py` builds in a new local directory from a supplied
  archive and iOS SDK. `tools/build-polaris-graphics.py` builds/signs the six
  artifacts and manifest in a new local output directory. These tools never
  change a phone or mounted root. Keep SDKs and built files outside Git.


0050 follows the0049 physical failure: human reports only logs/Applelogo,
ObjC PIDs370->380, and S a->b / I13->15. The wrapper reruns the shader test
on each launch, so those totals are not desktop evidence. A new GA C counter
counts only successful submissions by the genuine window-server client.

The actual20H392 `-[EAGLContext sharegroup]` at0x1d3f5188c loads the private
pointer at object+8, then pointer+8. Our custom context never initializes that
Apple structure. The reference already guards this CoreImage access;0050
adds the truthful nil answer (no resource sharing), after checking the actual
CoreImage caller explicitly accepts nil. All8 methods now preflight/rollback
as one transaction; required M is0xff. The observed0049 crash PC is unknown,
so this is a confirmed compatibility defect, not a claimed physical cause.

The context observer replays the latest cached stage when attached late;
it no longer overwrites an already-created context with L4. Successful CB0
access announcements stop after native publication; first-bootstrap records
and actual failures remain. No MMIO, polling, cache or submission order changes.

Only one desktop GPU opening is admitted per boot. After it, the registry's
PolarisDesktopAttempted property makes the wrapper skip another child test and
start the genuine server without injection. The kernel also enforces the
one-attempt limit. This is a CPU escape after a failed trial, not GPU recovery;
unknown DMA ownership still retains all resources until reboot.

A fatal SIGSEGV/BUS/ABRT/ILL/TRAP submits one fixed40-byte record through the
thin AMFI0x5b syscall, scoped to the same verified executable. The first record
survives process restarts and replaces three completed diagnostic rows with
GLF, GLPC/LR and GLADDR; panel height remains29rows. No allocation, stdio,
loader lookup, stack walk or GPU lock runs in the signal handler. PC image
0 means raw address,1 shared-cache preferred address,2 injector offset,
3 bridge offset,4 Mesa offset. SIGKILL/external watchdog termination cannot
be captured by a signal handler. Neither a fatal report nor fallback changes
GPU completion/readiness proof. Full Metal applications remain unsupported.

0051 addresses a captured IOSurface shared-state fault in the desktop trial.
The real framework's WrapClientImage/WrapClientMemory methods (selectors6/7)
consume a full mapped lock result. Returning success with zeros creates a
client whose bulk-attachments getter dereferences a null state page. The
Polaris surface profile now pins the caller's original memory, maps a separate
read-only state page through the existing result path, preserves unaligned
ranges and exact allocation size, and unwinds pins/charges on failure or final
release. Read-only input gets a read-only mapping. Unknown methods asking for
another full lock result return unsupported instead of fabricating a client.

Selector27 updates the selected bulk metadata fields in that shared page,
checking the caller's surface reference, input length, field bounds and mask
before any write. The native GPU importer still accepts only its original
wired buffer surfaces; external task memory uses the existing EAGL texture
upload path. No DMA, MMU, firmware, clock or HID event changes are made here.

The separate-task acceptance program now calls the actual iOS wrapper and
bulk getter APIs, verifies live aliases, metadata, cached Mach-port lookup and
release, before its GPU GLSL/all4096-pixel test. A passed test still does not
prove actual desktop rendering: require growing genuine-desktop C counts,
no new fatal record, stable UI and working input on the real phone.

0052 refines the image range using the actual CA::Render::Image vtable's
`data_size` method: bytesPerRow*(height-1)+width*bytesPerElement. The final
row's padding is outside that declared range and is neither required nor
pinned/read. The framework selftest deliberately wraps13x8 BGRA pixels with
row64 and length500, plus an unaligned raw-memory range, so a check that
incorrectly demands512 bytes is caught before desktop admission. The0051
image passed its build/CPU tests but was superseded before any phone action.

0053 keeps the hardware, surface fix and GPU completion gate unchanged.
The0052 phone reachedT2/E0 with zero submissions and no method installation:
the new surface contract and A630 renderer check passed, but the shader test
ended before its compile/link checkpoint. The old wrapper had a30-second
whole-process limit and did not retain its exit/signal/timeout reason, so a
cold-load timeout is plausible, not established as the cause.

The wrapper now uses a180-second monotonic wall-clock limit, still requiring
normal exit0 after all pixel checks. A single saved GLT row replaces an already
completed bootstrap row, without increasing panel height. R1 means begun,
R2 exited (V is exit code), R3 signalled (V is signal), R4 timed out, R5 spawn
error, R6 wait/clock error. MS is elapsed time at the last checkpoint or the
terminal result; it is not a heartbeat. The first terminal result survives
server restarts. Child progress P10/11 brackets the IOSurface checks, P20/21
context/renderer, P22..25 vertex create/source/compile/status, P26..29 fragment,
P31/32 shader return, P33/34 link, P35 surface setup, P40 drawing, P41 readback,
P42 completed pixel check. Read T/E and C separately; GLT cannot establish
hardware completion or permit another writer.

Diagnostic AMFI5c admits only the actual root-owned activated wrapper vnode
or the verified shader-test vnode, with disjoint event types. GPU caller_kind
and all GPU methods/mappings retain their previous two-image gate. AMFI5a
still allows dyld flags only for the genuine real window server; PID1 and
other callers retain ENOPOLICY without executable lookup. The shader test
may also submit its first fatal PC/LR through5b. Image2 then denotes its own
executable offset; for a desktop fault image2 remains the injector offset.
A fatal record takes priority over GLT on the panel. No DMA cleanup/reset or
synthetic-success recovery is introduced.


Polaris 0054 corrects `MSM_PARAM_GMEM_BASE` to `0x100000`, matching this
phone's native UCHE window `0x100000..0x1fffff`. The reference A642L reports
zero, which does not match this A630 setup. Mesa 25.0.7 uses that parameter
for GMEM framebuffer-fetch textures and 2D resolves. The 0053 phone completed
18 desktop submissions before an address-zero translation fault and a later
NULL shader BO crash; stable acceleration was not established.

The acceptance child now checks the reported base and requests GMEM rendering
only in its own process. After the existing solid shader/shared-surface check,
it requires `GL_EXT_shader_framebuffer_fetch`, executes four full-surface
colour inversions in separate passes, and verifies every one of the 4096
pixels after each pass. Stage T6 requires all checks to pass. This exercises
GMEM restore, texture read and resolve, which the earlier small solid shader
could miss. Host tests are not physical GPU evidence. Runtime quiescence keeps
its original stop/fault/ownership predicates, and now records which predicate
failed; faults still quarantine all DMA resources without acknowledging or
resuming them. USB host observation remains paused by user request.


0055 addresses a confirmed missing IOSurfaceCreate contract: an
`IOSurfaceAddress` property describes existing pixels in the owning task.
It must pin those exact bytes, not create a zero-filled replacement. The
current20H392 `IOSurfaceClientCreateChild` serializes the dictionary to
selector0 and explicitly handles that property; CoreAnimation also has a
Create dictionary branch alongside its selector6 image wrapper. Flat images
retain the tight final row bound. Invalid/overflowing addresses, short ranges,
unsupported scattered ranges and wiring failures return errors; a failed pin
never silently substitutes empty pixels. External task descriptors remain
excluded from direct GPU import and use the existing EAGL upload route.

The separate acceptance task additionally loads the actual EAGL bridge and
checks coloured, partially transparent BGRA and untyped ABGR pictures from
caller memory. It samples all4096 pixels after the original upload and a live
update of the same pixels. T6 still requires every earlier shader, shared
surface and GMEM test. Actual icon recovery awaits the physical run.

The next display request is60Hz, admitted only while an open, ready desktop
has completed genuine GPU work. CPU fallback retains its20Hz/legacy measured
copy budget. GPU presentation leaves half the measured copy interval for
other work, caps outlier backoff, accounts for work already spent in the
vsync callback and always yields at least1ms. Diagnostic text is repainted
at5Hz independently. This is a requested limit, not a measured60FPS claim.

Diagnostic-only selector0x7a accepts a32-byte rendering notice from the
verified desktop client only. Two existing rows, GLR and GLX, show frames,
GL errors, shader/image failures, missing calls and the first failure's kind,
argument and slot. Hardware first-fault rows take priority. Reports never
establish DMA completion or modify GPU admission/readiness; all values are
cached RAM and the display never reads hardware to show them.
