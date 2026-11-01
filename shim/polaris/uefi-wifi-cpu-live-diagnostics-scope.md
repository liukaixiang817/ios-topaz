# Original CPU live failure evidence (default OFF)

NEW0181 addresses the actual0180 photograph: access outstanding0x20001,
CPU error3/ARCH, body7/access, held1/restored0. That photograph does not
identify the failed predicate or establish a timeout, register change or fault.

`--wifi-power-cpu-live-diagnostics` requires the explicit normal-to-masked
database scope and terminal GOP diagnostics. It adds48 resident bytes to the
CPU record (10096 bytes) and full parent (1969104 bytes). Its independent label
is `WIFI_CURRENT_PRIVATE_CPU_LIVE_DIAGNOSTIC_RAW_V1`. The complete original
records,10MiB firmware/14MiB+128 host capacity and all checks remain present.

Only the FIRST failed original ARCH predicate records reason/call/masked,
original opening ticks, original CPU-normal ticks and that original returned
sample's ticks. An arch callback that returns false records reason1,
arch_callback_ok0/failed_ticks0; partial callback bytes are not a valid clock.
A nonreturning arch callback cannot be classified by this post-return capture.
There is no extra clock/register/owner read, retry or post-hold classification.
Original short-circuit order is preserved, including DS/owner read order.
No later predicate is evaluated once an earlier predicate fails.

Reasons (decimal; display is hexadecimal):1 callback returned false;2 EL;
3 local MPIDR;4 frequency;5 EL changed;6 MPIDR changed;7 TTBR0;8 TTBR1;
9 TCR;10 SCTLR;11 MAIR;12 SRE;13 DAIF;14 G1;15 CPACR;16 before normal;
17 age since normal;18 before opening;19 age since opening;20 TPL;
21 boot pointer;22 config pointer;23 config count;24 DS;25 cached owner/config.
These identify the first failed original comparison, not a hardware root cause.
Reason0 means no ARCH failure was captured, not success or zero hardware work.

The V2 numeric layout retains the same16 rows/576x384 ROI/405 target pages,
same50ms terminal limit, header/pixel NS/RW/PA/PAR checks, cache operations
and original append-RAM/allDAIF+G1-mask/nonreturnWFE. It displays body/CPU errors,
reason/call, masked/arch-callback-ok, full64-bit opening/normal/failed ticks,
literal original limit, access marker, both full DB byte/hash prefixes,
held/restored and the unexecuted engine attempt fields. Terminal rendering
does not take another CPU observation or alter the private ticket.

Original200ms/all68 samples/READ50+25ms reserves, fresh source/namespace/owner/
AT/FP/CPU, complete retirement and sticky UNKNOWN remain unchanged. No masked
RSC reader/store/engine/vote/MSS/NV/scan is introduced. Diagnostic capture is
not a permission grant, cleanup, retirement, exception handler or safe exit.
No old image/payload/record/frozen-controller reuse. New exact host profile,
affected checks/two SERIAL whole-parent models, original codec, independent
freeze/ONE helper and fresh full strictRO qualification are required before
any new physical session. A software fixture does not identify0180's cause.
