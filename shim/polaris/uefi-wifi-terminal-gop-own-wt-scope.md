# Exact observed GOP write-through attribute (0178)

Actual0177 returned a normal admission refusal before any Wi-Fi phase. Its
complete126096B record retained the successful NS read/write translation of
page9d465000, exact PAR restoration, and PAR valueba0000009d465b80. The original
display classifier accepted onlyFF/44, so the new diagnostic could not arm.
This identifies that new display-admission refusal, not any earlier opaque
power/CPU/database failure.

The primary [Arm PAR_EL1 table4-65](https://documentation-service.arm.com/static/5e906b3d8259fe2368e2aa8a)
(DDI0488D, printed4-85/4-86) defines high nibbleB as Normal outer write-through
with read/write allocation and low nibbleA as Normal inner write-through with
read allocation. UnlikeBB, BA does not request inner write allocation. This
uses the architectural PAR encoding, not a claim that the phone is an A57.
The [GOP interface](https://uefi.org/specs/UEFI/2.10/12_Protocols_Console_Support.html)
provides direct access to its current linear framebuffer; a cache attribute
or a Reserved descriptor by itself never grants that ownership.

New default-OFF --wifi-power-terminal-gop-own-wt requires the explicit terminal
GOP diagnostic. It adds only literalBA to pixel-page attributes. Protocol,
mode and info headers still requireFF. The complete actualGOP provenance,
self/native binding, descriptor version/map validation, current architecture,
nativeCPU-not-issued, NS read/write samePA, exact PAR restoration, all-page
preflight and immediate per-page check, unchanged405-page bound/576x384 ROI,
cache-line/page bounds, terminal50ms and sticky partial/reentry rules remain.
Each current page must also match its own newly captured normal admission;
the old0177 raw record is never a current framebuffer or radio lease.

No MAIR, TTBR, page table, permission, memory type or cache policy is written.
No generic Normal-memory attribute, Device page, RSC/ARC/SMEM/radio address or
firmware header is newly accepted. Cache cleaning and barriers stay inside
the same checked GOP pages. The old FF/44 behavior remains when the new flag
is OFF. Existing private200ms, READ50ms/25ms reserves, full source/CPU/namespace
retirement and all UNKNOWN gates are unchanged. Terminal success/failure still
ends in the original all-DAIF/G1 nonreturning hold, with no GOP method, console,
USB, SMC, Stall, cleanup, response or reset.

This grants no READ/vote/MSS/NV or Wi-Fi permission and proves no physical
drawing success. A new source/profile/checks/two serial wholeEFI-XNU models,
original whole codec, independent freeze/once helper and actual Polaris
FASTBOOT admission are required. The controlled0177 receipt/actualFASTBOOT
preserves its fresh strictRO qualification for the next necessary candidate;
do not repeat the root/NV audit solely for inventory.
