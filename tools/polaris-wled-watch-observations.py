"""Read-only WLED fault timeline; no health, retry or writer permission."""
import re


def parse(text):
    if (any(s in text for s in ('WLED_MOCK_BACKEND=', 'WLED_POWER_',
                                 'Darwin Kernel Version', 'KERNEL_PSCI_STATUS=')) or
            len(re.findall(r'(?m)^WH_WATCH_HOLD: READ_ONLY NO_WRITER_PERMISSION\r?\n', text)) != 1 or
            not re.search(r'(?m)^WLED_KERNEL_AP_STAGE=0x0000000000000000\r?$', text)):
        raise ValueError('not a physical, no-OS, no-writer fault timeline')
    fields = {}
    for line in text.splitlines():
        if not line.startswith('WH_') or line.startswith('WH_WATCH_HOLD:'):
            continue
        match = re.fullmatch(r'(WH_[A-Z0-9_]+)=0x([0-9a-f]{16})', line)
        if not match or match[1] in fields:
            raise ValueError('truncated, interleaved or duplicated watch record')
        fields[match[1]] = int(match[2], 16)
    required = {'WH_VERSION', 'WH_SOURCE_REFUSAL', 'WH_SAMPLES', 'WH_ERROR', 'WH_COMPLETE',
                'WH_FAULT_OR', 'WH_RT_OR', 'WH_ENABLE_XOR', 'WH_READS',
                'WH_PARTIAL_VALID', 'WH_PARTIAL_WORD'}
    if not required <= fields.keys() or fields['WH_VERSION'] != 1:
        raise ValueError('incomplete watch header')
    count, error, complete = (fields[k] for k in ('WH_SAMPLES', 'WH_ERROR', 'WH_COMPLETE'))
    if (count > 32 or error > 7 or complete != int(count == 32 and error == 0) or
            (not complete and not error) or (complete and fields['WH_SOURCE_REFUSAL'] not in (0,7)) or
            fields['WH_SOURCE_REFUSAL'] not in range(8)):
        raise ValueError('inconsistent watch completion or refusal')
    samples = []
    fault_or = rt_or = enable_xor = 0
    for n in range(count):
        at, word = f'WH_S{n:02d}_AT', f'WH_S{n:02d}_WORD'
        required.update((at, word))
        if at not in fields or word not in fields or fields[word] >= 1 << 32:
            raise ValueError('missing sample or invalid word width')
        began, ended = fields[at] >> 32, fields[at] & 0xffffffff
        first, after, rt, enable = ((fields[word] >> k) & 255 for k in (0, 8, 16, 24))
        if (began > ended or ended > 2000000 or
                n and began - samples[-1]['ended_us'] < 10000):
            raise ValueError('reversed, unbounded or too-early observation')
        fault_or |= first | after
        rt_or |= rt
        if n:
            enable_xor |= enable ^ samples[0]['enable']
        samples.append(dict(began_us=began, ended_us=ended, first=first, after=after, rt=rt, enable=enable))
    mask, partial = fields['WH_PARTIAL_VALID'], fields['WH_PARTIAL_WORD']
    # Prefixes follow the actual alternating observer read order.
    allowed = (0, 1, 5, 7, 15) if count & 1 else (0, 1, 3, 7, 15)
    if complete:
        allowed = (15,)
    if mask not in allowed or partial >= 1 << 32:
        raise ValueError('invalid partial observation')
    for bit, shift in ((1, 0), (8, 8), (2, 16), (4, 24)):
        if not mask & bit and (partial >> shift) & 255:
            raise ValueError('unread partial word published as data')
    fault_or |= (partial & 255) | ((partial >> 8) & 255)
    rt_or |= (partial >> 16) & 255
    if (set(fields) != required or fields['WH_FAULT_OR'] != fault_or or
            fields['WH_RT_OR'] != rt_or or fields['WH_ENABLE_XOR'] != enable_xor or
            fields['WH_READS'] < 4 * count or fields['WH_READS'] > 4 * count + (0 if complete else 4)):
        raise ValueError('lost fault witness, unexplained read or unknown record')
    if complete and (fields['WH_READS'] != 128 or
                     samples[-1]['ended_us'] - samples[0]['began_us'] < 310000):
        raise ValueError('missing actual bounded observation span')
    return dict(diagnostic_complete=bool(complete), error=error,
                source_refusal_preserved=fields['WH_SOURCE_REFUSAL'],
                observed_fault_or=fault_or, observed_rt_or=rt_or,
                disappearing_fault_pairs=sum(bool(s['first'] & ~s['after']) for s in samples),
                samples=samples, partial=dict(valid=mask, word=partial),
                health_proven=False, permits_writer=False, permits_retry=False,
                physical_darkness_proven=False, simultaneous_snapshot=False)
