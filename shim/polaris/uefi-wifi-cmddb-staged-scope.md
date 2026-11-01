# Staged complete CmdDb RO preparation

`--wifi-power-cmddb-staged-ro` is default OFF. It selects a distinct parent
branch before any private client and before Clock allocations/final GCD. The
existing private-client/power compile flags supply types and original source
bindings; their Create/Delete, Query, CPU-critical, PSCI and RSC bodies are not
called by this branch. The old full, first-node and work-admission modes remain
separate; neither old policy nor spent boot record is modified or reused.

Four resident phases capture64KiB each: two halves per128KiB database, twice.
Each phase opens its own genuinely new Core record/context and spent-once ticket,
with the original200ms deadline. It must finish before the next starts. This
is completion of separate read operations, never renewal/rebasing of a held
private or final Clock/GCD interval. The native CPU_ON flag is the actual main
literal `&wln_cpu_on_issued`, checked in the loaded self image, not a host boolean.

Each phase retains both complete original memory maps/Core source snapshots,
FP/architectural guards on its original LocateProtocol and GetMemoryMap calls,
the registered CmdDb owner, five normalized source hashes, full relocated72B
protocol table and72B globals. The exact cached/platform pointers must agree
on85fe0000/128KiB. No Init, original CmdDb Query or original descriptor getter
runs. LoadedImage headers are read from retained enumeration addresses afresh;
the freed enumeration handle array is never dereferenced. Read-only heap
classification excludes self/Core/all loaded images and admits no writer lease.

The existing bounded Core namespace reader performs two full traversals per
phase, including source, template, head, released-lock, node links, bounds,
current loaded-image exclusion, exact NS/WB AT and actual PAR restoration.
Every target page receives both the preliminary descriptor/AT admission and
an immediate complete source/head/lock/node/target guard before its4096B copy.
A final guard follows the last foreign service. CmdDb source/table/globals,
all LoadedImage headers, original maps, architectural context and actual native
flag must close consistently before phase3 retirement. All raw partials,
UNKNOWN, late/regressing counters and failed restoration stay sticky.

Across completed phases the full namespace, maps/keys, loaded headers and
CmdDb source/table/globals must match. This compares observations at separate
read intervals; it is not continuous exclusivity over interrupts, firmware,
DRV2, EE/EL3, VMID/MPU, rails or DMA. Four complete pieces form two resident
128KiB databases; all bytes must match before the unchanged ARC/raw384 decoder
can parse both. Missing/currently unsupported descriptors or an unsupported
stable database can produce a known RO refusal only after complete retirement.
A later source/namespace change cannot hide behind that classification.

The complete1660544B STAGED_RO_RAW_V1 is emitted with its own labels and log
capacity assertion. It is not an old ZERO_VOTE client/path report. The existing
8MiB firmware log and12MiB+128 host capacity suffice without stripping raw.
Unsafe preparation reaches the explicit parent gate: append RAM, local mask,
nonreturn WFE; no Console/USB/Stall/PON/native/receipt/reset/cleanup/ACK. A
known clean refusal never falls back to another scope or starts a client.

This preparation does not vote, start MSS, serve NV or perform radio scan,
join or data. A successful software fixture or whole EFI model is not a
physical namespace/database read or phone timing proof. Current cache/TCS,
independent ownership, real power completion/restore, MSS and transport
integration remain subsequent work.
