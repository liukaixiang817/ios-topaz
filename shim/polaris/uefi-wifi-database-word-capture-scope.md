# Full masked CmdDb Normal RAM word capture (default OFF)

The human's 0181 V2 photo records the first failed original opening-age
comparison: 3,907,820 ticks against the unchanged 3,840,000-tick limit.
DB0 has a 128KiB byte prefix, DB1 has 48KiB. This identifies the guard that
stopped that session; it does not isolate the cost of a particular operation.

`--wifi-power-db-word-capture` requires the explicit CPU live diagnostics and
all their normal-to-masked DB, work, source, namespace, CPU and terminal GOP
dependencies. It changes only the prepared masked DB page's data loads from
eight volatile byte reads to one aligned 64-bit Normal RAM `LDR`. It never
widens a Device/MMIO load, store, translation permission or radio grant.

Both complete fresh 128KiB snapshots, all source hashes, current owner and
namespace checks, all 64 per-page NS/WB/same-PA AT/PAR observations, original
200ms opening, all 68 work samples and READ50ms+reserve25ms remain. CPU,
FP/DAIF/G1 restoration, source/cache/Device rechecks and known Delete still
precede a normal return and USB export. No opening timestamp is rebased.

The retained preparation baseline keeps its original byte-wide loads. All
eight retained baseline bytes are compared together with the delivered word;
an equal block is stored to aligned own Normal RAM and advances the full byte
prefix once. A mismatch uses those same retained samples to preserve the
first differing byte, without re-reading the baseline after failure.

Each 56-byte resident word record preserves issued/returned counts, pending
load address, last complete delivered word/address, byte comparison prefix
and first mismatching byte. A failed byte comparison retains the remaining
bytes of that delivered word in `last_word`; they are not counted as copied
or compared. Full closure checks both word records against their complete
raw tails and counts. Native nonreturn is not intercepted or classified by
the hosted failure peer. The original UNKNOWN/held-mask nonreturn path stays.

The new complete parent record is 1,969,216 bytes with label
`WIFI_CURRENT_PRIVATE_DB_WORD_CAPTURE_RAW_V1`. The same bounded GOP area uses
`V3 HOLD`: rows 12/13 show DB0/DB1 word issued/returned counts. The original
WHY/CALL, captured ticks, unchanged limit, byte prefixes and held/restored
rows retain their exact meaning. No register or clock is re-read for display.
The default OFF ABI/behavior
stays unchanged. Software tests or fewer source loads cannot establish a
physical speedup, successful masked retirement, READ or network operation.

0182 is not admitted for a phone until affected checks, two SERIAL whole
EFI-XNU models, exact host profile, original whole codec, fresh strict RO
root/NV audit, independent freeze and one offline helper have passed.
Never reuse 0181's consumed image, payload attempt, context or boot record.
