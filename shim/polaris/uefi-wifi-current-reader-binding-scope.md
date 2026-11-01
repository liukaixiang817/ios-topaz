# Same private caller reader arguments (0175)

This default-OFF current read-observation path binds the command namespace,
Device reader and checked-access reader to the exact `client.reader.memory`
object passed by `pwrcl_run_body`. The original command reader's five memory
members must match that object. These checks precede prepared CmdDb capture
and every CPU transition. Mismatches retain ARGUMENT/UNKNOWN and the known
client; they cannot trigger Delete, mask, SMC, MMIO or a cleanup fallback.

The physical constructor uses `client.reader` and its embedded memory address
consistently. Equal outer-copy contents alone do not satisfy pointer binding.
This is argument admission, not a boolean hardware lease, an EE/EL3 grant or
permission to use an old context. The same interval still revalidates current
source/namespace/CmdDb/RAM/Device/CPU and retires fully before USB export.

The existing observer performs both full128KiB current CmdDb captures,64 RAM
translations and70 checked geometry loads. Its literal store callback still
rejects; READ/WRITE engines remain entirely zero. No engine request, trigger,
IRQ ACK, resource vote, MSS start, NV serving or radio operation is enabled.
The original200ms deadline, all68 slowest-sample work admission, full READ50ms
and25ms reserve, raw ABI/capacity, exact CPU restore and known Delete remain.

The real outer-copy composition regression rejects three wrong reader
pointers, five mismatched original memory members and a wrong access context
before prepared/CPU work. The correct composition completes the existing full
SOFTWARE observer and retirement. These cases do not prove actual hardware
execution or diagnose old0173. Actual0174 stopped during payload transfer;
the source binding fix has not yet been physically tested.
