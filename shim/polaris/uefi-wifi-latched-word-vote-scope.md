# Same fresh READ TCS with a completed high launch latch

The separate default-OFF `--wifi-power-current-word-vote-latched` requires the
complete explicit fresh READ-derived vote scope. It addresses the photographed
0186 writer eligibility refusal, rather than changing timeout or IRQ policy.

The actual V7 photograph shows READ phase8, WRITE phase0, WRITE error6 (BUSY),
zero WRITE triggers/completions and last returned read at TCS0 CMD2_RESP_DATA.
The exact caller therefore returned from the finite read-only writer initial
scan without selecting an eligible idle/untriggered IRQ-enabled TCS. The
photograph is not a full binary record or a completed access/CPU retirement.
An additional exact frozen C-ABI decode of historical0185 data shows active
mask15 but IRQ enable1 and READ TCS0 CONTROL01010000/ENABLE1. Those historical
values are not a new session's admission. The earlier software success peers
enabled four IRQ slots; that simulated availability did not describe the phone.

Own HAL7704..7734 and the already physically retired READ protocol establish
low/readback before a new rising edge, and retention of the final completed
edge instead of writing a saved high trigger during restoration. This explicit
WRITE path follows that protocol for exactly two launches. The writer accepts
only the precise idle STATUS1/CONTROL01010000/ENABLE1 completed shape. Before
its first actual store, the checked adapter requires the same TCS, IRQ enable,
active mask and complete saved snapshot as the same fresh fully retired READ's
final snapshot. No generic high latch, historical snapshot, permission boolean
or changed IRQ enable/type qualifies a writer.

Each launch lowers/readbacks TRIGGER before changing commands, stages the
three bounded ARC commands, then issues one new edge. After new IRQ, all three
DONE statuses and idle, the writer disables commands and reads the retained
high control value before ACK. The second ACK leaves its own completed edge
high. All touched command RW values, wait and saved command enable are restored
with no subsequent high control store. Final IRQ must be clear and full saved
RW/snapshots/prefixes must match. Any extra IRQ, partial transfer, status bit,
source/AT/time mismatch or failed restoration remains sticky UNKNOWN and held.

The pure transaction verifier reconstructs both edges, each low readback,
pending control samples, full initial/final snapshots and status/response/IRQ
summaries. The checked parent binds the same fresh READ snapshot throughout,
then repeats complete engine/access checks after the second full database and
geometry capture, before CPU restoration and known client Delete. No earlier
READ values or context are reused between sessions. The existing 200ms opening,
all68 timing samples, combined READ+WRITE50ms/256steps/1024events, READ50+25ms
estimate, IRQ type, FP/DAIF/G1 and full source/namespace closure remain unchanged.

`CURRENT_PRIVATE_WORD_LATCHED_ARC_VOTE_RAW_V1` retains the 1969216-byte ABI.
V8's existing 16 resident rows additionally project writer TCS/IRQ enable;
there is no post-failure clock/register sampling. Previous flags, raw labels
and behavior remain unchanged with this flag OFF. Software peers and models
do not demonstrate physical power voting, modem/MPU ownership or WiFi traffic.
