# Same private masked database observation (0176)

This new default-OFF diagnostic stops before the first masked RSC/MMIO read.
It does not retry the opaque0175 full access path or repeat the completed0172
CPU-only checkpoint. It tests the still-unobserved transition from the same
fresh private client/namespace/cache/normal Device input and exact CPU-local
mask to two complete current128KiB CmdDb RAM captures and64 immediate NS/WB
translations. Source, owner, table, globals, every byte and exact PAR restore
are checked through the existing implementation and decoder.

`pwra_prepare_checked` is the unchanged argument/owner/current-state prefix of
the existing acquisition, followed by its first full database capture. The
ordinary acquisition still takes the same prefix, performs the full checked
geometry snapshot, and only then publishes acquired/local-held. This scope
instead wires NULL masked RSC read/translation callbacks and a deny-only store
callback. It captures the second full database and validates both using the
same validation routine as the complete observer. No RSC access lifetime is
opened: acquired, local-held and retired remain ZERO. No engine result, READ
completion or hardware lease is fabricated.

The enclosing path then captures full provider RAM, checks original source,
restores CPU state exactly, obtains its second normal Device observation and
closes current namespace/source before known Delete. The planned body reason
is15 and its own full retirement proves only this narrower RAM observation.
The distinct RAW label is CURRENT_PRIVATE_MASKED_DB_OBSERVATION_RAW_V1; the
existing1943840B C ABI remains unchanged, as do complete preparation/client
raw, log capacity, original200ms deadline, all68 samples, READ50ms and25ms
work reserves. Partial/late/changed/held/UNKNOWN still prevents foreign USB,
Console, Stall, reset, receipt or cleanup; full RAM evidence is retained before
the terminal local mask/WFE hold. No old context or ticket is renewed.

This is a failure-isolation scope, not a fix for an identified0175 predicate.
It grants no later READ/vote/MSS/NV/radio permission. Every future full access
or READ phase needs its own fresh current owner/source/cache/Device/CPU checks
and complete retirement. Old CPU OFF, maps, AT, RET locks and callback returns
do not confer an EE/EL3/VMID/MPU lease.
