# 0174: bind the access observer to the private caller's actual memory object

The physical preboot constructs a pwrcl_io whose reader embeds a COPY of the
incoming paic_io. pwrcl_run_body passes &ops->reader.memory to pwrpt_body.
0173 instead constructed pwra_observation_io with the outer incoming pointer.
Its unchanged strict gate rejects access.memory != body memory, even when
all five paic_io members are equal. Its original software fixture constructed
pwrpt_io inside the callback, so it did not reproduce the outer-copy boundary.

The physical preboot now binds &client.reader.memory. The pointer check, exact
access context and deny-only store callback remain. No other production branch,
record layout, time/source/owner/UNKNOWN condition or retirement is changed.
A new regression constructs IO OUTSIDE pwrcl_run_body, uses the real embedded
reader copy and callback argument, and substitutes only hardware leaves with
software peers. It reproduces the old PWRPT_ARGUMENT/UNKNOWN before CPU and
verifies the corrected composition closes the full existing observation,
CPU restoration, namespace and known Delete without any engine or store.
Actual whole-parent preprocessing checks the literal production binding.

This is a proven source wiring defect.0173 exported no raw, so this does not
prove its actual execution point or sole physical failure cause. The existing
full128KiB current CmdDb/32AT twice,70 checked RSC geometry loads, exact CPU/
RAM/source/namespace retirement and original200ms/full READ reserves remain.
The observer still cannot issue READ requests, TCS stores or IRQ ACK, and its
records do not grant an EE/EL3/VMID/MPU lease. Later actual READ must have a new
fresh private lifetime and all current admission and restoration checks.

The next candidate needs a new exact source profile, affected parent checks,
two serial terminal models, original whole codec and independent freeze.0173
UNKNOWN/physical reset requires NEW full strictRO root/currentNV qualification
at that already-needed conversion. The user's persistent authorization covers
the same immutable63cb payload only for each fully reviewed, independently
frozen NEW temporary RAM session once, never replaying consumed0173 or writing
partitions. Wi-Fi scan/join/data and four Wi-Fi VRM/MSS/GLINK/WLFW/ath10k remain
unfinished; no native/kernel, capability or UI change is included here.
