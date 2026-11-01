# 0167: completed ACTIVE launch latches and three bounded RAW READs

Actual0166 passed stride48 exclusion, three original GCD getters and35
NS Device R/W AT guarded register loads, then refused before CPU admission.
Its first complete hardware control pass has IRQ enable1/status0, TCS0
CONTROL01010000/STATUS1/CMD_ENABLE1, and original TCS RAM state0/requestNULL.
The remaining active slots have no enabled IRQ. These observations alone do
not authorize clearing the control word or selecting a disabled slot.

The exact original b718efb6/61440B RPMh image supplies the missing lifecycle
correspondence. Bank2 HAL7704..7734 reads CONTROL, retains AMC bit16, stores
that value (trigger low), reads it back, then sets bit24 and stores the new
trigger. It does not wait for trigger to auto-clear. HAL7874..7898 returns
STATUS bit0. Submission67c4..6860 programs wait/command enable and command
descriptors before that explicit trigger routine. Completion63f8..64d4 clears
the IRQ via809c, publishes the result and writes TCS RAM state0/requestNULL at
6490/6498. The direct CONTROL/CMD_ENABLE reset calls89a0/8a88 occur in4050's
all-TCS initialization loop. They are not the normal completion body.
The free-slot search5ff0..6028 tests TCS RAM state at+4 for zero. No original
routine is invoked, patched or entered internally by our new engine.

The new capture-only reader therefore admits the completed single-command
shape only with the same source-bound FREE/no-request original RAM record,
idle STATUS1 and no IRQ, plus all existing source/namespace/Device/CPU gates.
Unknown control bits, trigger-without-AMC, non-single command enable and RAM
pending requests still refuse. Ordinary untriggered empty slots remain valid.
This conditional APPS DRV2 interval is not an EE/EL3/VMID/MPU grant.

Before each new READ the finite engine deasserts the previous trigger and
reads it back before changing command registers. One command is staged, then
one new rising edge starts it. New IRQ, all issued/completed status, raw
response and idle precede ACK. No IRQ enable/type or CMD_DATA write occurs.
There are exactly three new launches. Each completion disables the command;
if the saved trigger was high, the completed new latch stays high. Restoration
never writes a high trigger. After the final ACK the old MSGID/address/wait
and enabled-command value are restored without another trigger transition.
Every touched RW value, complete snapshot and final IRQ state are read back.
An unexpected replay IRQ or changing state is UNKNOWN, never acknowledged or
cleaned up as a retry. The full independent prefix audit verifies deassertion
before staging and rejects a forged high-trigger restoration event.

All original private200ms, READ50ms/256steps/1024events, source/fullDB/RAM,
seven-peer admission, exact CPU restore and final namespace/Delete gates
remain. No ticket is reset or rebased. The parent still retains all partial
raw and enters local-mask/nonreturn WFE on UNKNOWN without Console/USB/Stall/
reset/cleanup/ACK. Resource WRITE remains compiled out; RAW ARC words are not
qualified saved votes, and MSS/NV serving/radio/scan/join/data remain disabled.
The new RAW_V2 label distinguishes this lifecycle from the old V1 prefixes;
binary extents stay complete and are decoded with the actual frozen C ABI.
