# 0168: retire a returned pre-mask CPU refusal without granting READ

The0167 startup ACK and subsequent UEFI state were unavailable. Physical
recovery and an independent product query confirmed FASTBOOT07:20. There is
no new CPU/RSC raw, so the failing predicate, mask state and write count are
unknown. The following static finding is not a diagnosis of that attempt.

`pwrpc_begin` already distinguishes a completed normal-IRQ PSCI refusal from
an unknown call or held mask. After a fully returned non-OFF observation it
can return errorPSCI, unknown0, retired1, no mask and no outstanding call.
The parent previously converted every CPU admission failure into UNKNOWN,
even this completed read-only refusal. That prevented all normal reporting.

The new capture-only READ parent accepts ONLY retirement of recognized
ON0 or ON_PENDING2 results. Every issued normal guard must have entered,
returned, left, restored FP and preserved observed TPL4. All prior queried
peers must be OFF1, and the contiguous issued/returned masks must agree.
The original source sample must be complete; the original context must still
be fresh. CPU mask/restore records and all READ/WRITE/access records must be
entirely untouched. Unsupported or unrecognized results, unknown/partial
calls, corrupted guards, source errors and any held mask still quarantine.

This helper authorizes no READ, CPU mask, rail, DMA, MMIO store or lease.
The parent continues to refuse the power operation. It must close the full
current CmdDb/namespace, revalidate source and two complete pool snapshots,
check the exact known client/empty queues and then use known Delete. A changed
or expired final check remains UNKNOWN. No ticket is reset/rebased, no raw is
discarded, and a later fresh admission cannot borrow this refusal as authority.

The change is conditional on the distinct default-OFF capture-only READ
scope. The old WRITE path retains its existing handling. If all peers are OFF,
the existing fresh masked seven-peer checks and entire READ/completion/full
restore path remain mandatory. The parent UNKNOWN/native/PON/receipt gates
are unchanged for uncertain or held work. This does not retroactively classify
0167 or prove that any CPU is currently ON. Wi-Fi remains unimplemented.
