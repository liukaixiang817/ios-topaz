# Polaris20H392 GPU integration

0046 has **physical native command/fence/4096-pixel/idle/halt proof**. Its
desktop uses CoreAnimation's CPU renderer. This integration adds the missing
resident submission and Mesa/EAGL path; application/desktop acceleration must
still pass the new physical acceptance test. Metal application support is a
separate layer and is not implemented here.

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
or30-second timeout retains the existing CPU interface. The test and normal
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
