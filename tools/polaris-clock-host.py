#!/usr/bin/env python3
"""Host UTC calibration inside an already image-bound serial runtime session.

No USB discovery/open/boot/reset, command-line device action or background loop.
`synchronize(protocol)` accepts only an existing verified kernel-entered client.
All times in this protocol are calendar metadata; no monotonic clock is written.
"""
from dataclasses import dataclass, asdict
import struct
import time

FREQUENCY = 19_200_000
MIN_UTC_US, MAX_UTC_US = 1_577_836_800_000_000, 4_102_444_800_000_000
MAX_RTT_NS, MAX_HOST_STEP_NS, MAX_UNCERTAINTY_US = 250_000_000, 2_000_000, 150_000
READY, APPLIED, REJECTED, SEALED = 1, 2, 3, 4


class ClockError(RuntimeError):
    pass


class DeliveryUnknown(ClockError):
    """SET may have reached firmware/native; query status, never resend it."""
    def __init__(self, cookie, sequence, reason):
        self.cookie, self.sequence = cookie, sequence
        super().__init__(f"UTC delivery unknown for sequence {sequence}; status-only recovery: {reason}")


@dataclass(frozen=True)
class Status:
    cookie: int
    sequence: int
    status: int
    error: int
    frequency: int
    actual_utc_us: int
    actual_ticks: int
    uncertainty_us: int
    applied_count: int


def decode_status(raw):
    if len(raw) != 60:
        raise ClockError("UTC status length")
    magic, *fields = struct.unpack("<8sQIIIIQQQI", raw)
    result = Status(*fields)
    if (magic != b"PCLSTA01" or not result.cookie or result.frequency != FREQUENCY
            or result.status not in (READY, APPLIED, REJECTED, SEALED) or result.error > 7
            or result.applied_count > result.sequence):
        raise ClockError("UTC status identity or range")
    if result.status == APPLIED and (result.error or not MIN_UTC_US <= result.actual_utc_us < MAX_UTC_US
            or not result.actual_ticks or not 0 < result.uncertainty_us <= MAX_UNCERTAINTY_US
            or not result.sequence or not result.applied_count):
        raise ClockError("UTC applied status lacks bounded calendar readback")
    return result


def _request(protocol, command):
    if not getattr(protocol, "verified", False) or len(command) > 64:
        raise ClockError("UTC requires the existing verified runtime session")
    protocol.transport.write(command)
    reply = protocol.transport.read(64)
    if not reply.startswith(b"OKAY"):
        # Do not expose arbitrary device text or identifiers in host logs.
        raise ClockError("clock-only command refused or response unavailable")
    return reply[4:]


def status(protocol):
    """Read clock metadata only, including after an uncertain SET acknowledgement."""
    return decode_status(_request(protocol, b"oem utc-status"))


def _pair(realtime_ns, monotonic_ns):
    first = monotonic_ns()
    realtime = realtime_ns()
    last = monotonic_ns()
    if last < first or last - first > MAX_HOST_STEP_NS:
        raise ClockError("host UTC/monotonic pairing delayed or reversed")
    return realtime, first + (last - first) // 2, last - first


def synchronize(protocol, *, realtime_ns=time.time_ns, monotonic_ns=time.monotonic_ns,
                sleep=time.sleep, max_status_reads=30):
    """One fresh probe, at most one SET, then bounded independent native status.

    Reconnect calibration is another fresh call after the prior sequence has
    completed. Firmware rejects probes while a request remains outstanding.
    Host wallclock is the stated source, not NTP or a physical RTC guarantee.
    """
    if type(max_status_reads) is not int or not 1 <= max_status_reads <= 50:
        raise ValueError("bounded native status reads required")
    if not getattr(protocol, "verified", False) or protocol.state() != "kernel-entered":
        raise ClockError("UTC requires an admitted running native kernel")
    prior = status(protocol)
    if prior.status == SEALED or prior.sequence >= 0xFFFFFFFF:
        raise ClockError("UTC session is sealed or sequence exhausted")
    seq = prior.sequence + 1
    first_utc, first_mono, first_span = _pair(realtime_ns, monotonic_ns)
    raw = _request(protocol, f"oem utc-probe:{seq:08x}".encode("ascii"))
    last_utc, last_mono, last_span = _pair(realtime_ns, monotonic_ns)
    if len(raw) != 60:
        raise ClockError("UTC probe length")
    magic, cookie, returned, frequency, rx, tx, consumed, phase, error, reserved = struct.unpack(
        "<8sQIIQQIIIQ", raw)
    if (magic != b"PCLPRO01" or cookie != prior.cookie or returned != seq or frequency != FREQUENCY
            or consumed != prior.sequence or phase != prior.status or error != prior.error or reserved
            or not rx or tx < rx):
        raise ClockError("UTC probe cookie/sequence/source-counter binding")
    rtt = last_mono - first_mono
    if not 0 < rtt <= MAX_RTT_NS or abs((last_utc - first_utc) - rtt) > MAX_HOST_STEP_NS:
        raise ClockError("host wallclock stepped or RTT exceeds UTC admission")
    processing_ns = (tx - rx) * 1_000_000_000 // frequency
    if processing_ns > rtt + MAX_HOST_STEP_NS:
        raise ClockError("device counter elapsed exceeds measured host round trip")
    # Midpoints estimate the shared epoch. The complete RTT/2 is retained as
    # an uncertainty bound; do not assume symmetric USB/firmware scheduling.
    uncertainty = (rtt // 2 + MAX_HOST_STEP_NS + max(first_span, last_span) + 999) // 1000 + 1
    utc = (first_utc + last_utc) // 2000
    anchor = rx + (tx - rx) // 2
    if not MIN_UTC_US <= utc < MAX_UTC_US or not 0 < uncertainty <= MAX_UNCERTAINTY_US:
        raise ClockError("host UTC epoch/uncertainty outside declared source range")
    # Check the realtime source again immediately before SET. A jump after the
    # probe must not seed the device with a stale or fabricated association.
    before_set_utc, before_set_mono, _ = _pair(realtime_ns, monotonic_ns)
    if (before_set_mono < last_mono or before_set_mono - last_mono > 1_000_000_000
            or abs((before_set_utc - last_utc) - (before_set_mono - last_mono)) > MAX_HOST_STEP_NS):
        raise ClockError("host source changed or calibration was delayed before SET")
    command = f"oem utc-set:{seq:08x}:{utc:016x}:{anchor:016x}:{uncertainty:08x}".encode("ascii")
    if len(command) != 63:
        raise ClockError("fixed UTC SET shape")
    try:
        accepted = _request(protocol, command)
        if accepted:
            raise ClockError("UTC SET acknowledgement has unexpected metadata")
    except Exception as exc:
        raise DeliveryUnknown(cookie, seq, type(exc).__name__) from exc
    # OKAY means the fixed metadata was published; only native APPLIED with an
    # actual calendar/counter readback proves that the kernel consumed it.
    for attempt in range(max_status_reads):
        try:
            current = status(protocol)
        except Exception as exc:
            raise DeliveryUnknown(cookie, seq, type(exc).__name__) from exc
        if current.cookie != cookie or current.sequence > seq:
            raise DeliveryUnknown(cookie, seq, "native clock identity changed")
        if current.sequence == seq:
            if current.status != APPLIED or current.error:
                raise ClockError(f"native calendar rejected sequence {seq}, status {current.status}, error {current.error}")
            if current.actual_ticks < anchor or current.actual_ticks - anchor > FREQUENCY * 10:
                raise ClockError("native calendar readback counter age")
            expected = utc + (current.actual_ticks - anchor) * 1_000_000 // frequency
            if abs(current.actual_utc_us - expected) > 10_000:
                raise ClockError("native calendar readback does not match host association")
            result = asdict(current)
            result.update(source="host-UTC", host_rtt_ns=rtt, anchor_ticks=anchor,
                          anchor_utc_us=utc, monotonic_clock_modified=False,
                          rtc_or_nvram_written=False, network_time_verified=False)
            return result
        if current.status == SEALED:
            raise ClockError("native clock sealed during calibration")
        if attempt + 1 < max_status_reads:
            sleep(0.1)
    raise DeliveryUnknown(cookie, seq, "native calendar acknowledgement not yet observed")
