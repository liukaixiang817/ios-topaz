#!/usr/bin/env python3
"""Audit native raw-word witnesses; diagnostic observations never admit clocks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tsens_raw', ROOT / 'polaris-thermal-observations.py')
raw_parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(raw_parser)
IO = re.compile(r'us=(\d+) begin=(\d+) end=(\d+) reads=(\d+) logical=(\d+) valid_retry=([0-9a-f]+) disagree=([0-9a-f]+) repaired=([0-9a-f]+); bounded72 physical reads')
WORD = re.compile(r'us=(\d+) id=(\d+) count=(\d+) selected=(\d+)/(\d+) values=([0-9a-f]+(?:/[0-9a-f]+){3}); hottest observed VALID word retained')
FAIL = re.compile(r'us=(\d+) begin=(\d+) end=(\d+) error=(\d+) id=(\d+) count=(\d+) reads=(\d+) raw=([0-9a-f]+(?:/[0-9a-f]+){3}) last=([0-9a-f]+); no partial admission')


def choose(values):
    peak = values.index(max(values))
    for i in range(len(values) - 1, -1, -1):
        if i != peak and values[peak] - values[i] <= 2000:
            return sorted((i, peak))
    return None


def analyze(text):
    ordinary = raw_parser.analyze(text)
    samples = {p['us']: p for p in ordinary['samples']}
    errors = {p['us']: p for p in ordinary['error_observations']}
    ios, words, failures = {}, {}, []
    for line in text.splitlines():
        for prefix, pattern, kind in [('POLARIS TSENS PAIR IO: ', IO, 'io'),
                                      ('POLARIS TSENS WITNESS: ', WORD, 'word'),
                                      ('POLARIS TSENS PAIR FAIL: ', FAIL, 'fail')]:
            if not line.startswith(prefix):
                continue
            m = pattern.fullmatch(line[len(prefix):])
            if not m:
                raise ValueError('malformed/truncated/interleaved native witness record')
            if kind == 'io':
                stamp, began, ended, reads, logical = map(int, m.groups()[:5])
                retry, disagree, repaired = (int(v, 16) for v in m.groups()[5:])
                if (stamp in ios or not 0 < began <= ended == stamp < 2**64 or ended - began > 1000 or
                    not 12 <= logical <= 24 or not logical <= reads <= logical * 3 or
                    retry >> logical or disagree != repaired or repaired >= 64 or
                    not (retry or repaired)):
                    raise ValueError('invalid native witness IO bounds or identity')
                bits = retry.bit_count()
                if not logical + bits <= reads <= logical + 2 * bits:
                    raise ValueError('physical reads inconsistent with bounded VALID retry mask')
                ios[stamp] = dict(us=stamp, begin_us=began, ended_us=ended, reads=reads,
                                  logical=logical, retry_mask=retry, repaired_mask=repaired)
            elif kind == 'word':
                stamp, sensor, count, a, b = map(int, m.groups()[:5])
                raw = [int(v, 16) for v in m[6].split('/')]
                if not 7 <= sensor <= 12 or not 3 <= count <= 4 or not 0 <= a < b < count or any(raw[count:]):
                    raise ValueError('invalid native witness sensor/count/selection')
                values = [raw_parser.decode(v) for v in raw[:count]]
                if choose(values[:2]) is not None or choose(values) != [a, b] or (count == 4 and choose(values[:3]) is not None):
                    raise ValueError('witness drops hottest data or was read after a conclusive pair')
                key = (stamp, sensor)
                if key in words:
                    raise ValueError('duplicate native raw witness')
                if stamp in samples:
                    sample = samples[stamp]
                    if [sample['raw_passes'][i][sensor - 7] for i in (0, 1)] != [raw[a], raw[b]]:
                        raise ValueError('native summary differs from selected authentic witness words')
                words[key] = dict(us=stamp, sensor=sensor, count=count, selected=[a, b], raw=raw,
                                  hottest_mC=max(values), hot_experiment_limit_reached=max(values) >= (75000 if sensor < 11 else 60000))
            else:
                stamp, began, ended, error, sensor, count, reads = map(int, m.groups()[:7])
                raw = [int(v, 16) for v in m[8].split('/')]
                if (not 1 <= error <= 7 or not 7 <= sensor <= 12 or not 0 <= count <= 4 or
                    not 0 <= reads <= 72 or stamp not in errors or errors[stamp]['error'] != error or
                    errors[stamp]['offset'] != 0xa0 + sensor * 4 or any(raw[count:])):
                    raise ValueError('failure witness must match the retained native refusal')
                for word in raw[:count]:
                    raw_parser.decode(word)
                failures.append(dict(us=stamp, began_us=began, ended_us=ended, error=error,
                                     sensor=sensor, count=count, reads=reads, raw=raw,
                                     last_raw=int(m[9], 16), performance_admission=False))
    repairs = []
    for stamp, io in sorted(ios.items()):
        matching = [words[stamp, n] for n in range(7, 13) if (stamp, n) in words]
        if sum(1 << (p['sensor'] - 7) for p in matching) != io['repaired_mask']:
            raise ValueError('missing native witness for a repaired sensor')
        if io['logical'] != 12 + sum(p['count'] - 2 for p in matching):
            raise ValueError('logical-read count differs from actual raw-word evidence')
        repairs.append(dict(io, sensors=matching))
    if any(stamp not in ios for stamp, _ in words):
        raise ValueError('orphan raw witness without complete native IO record')
    return dict(witness_observations=repairs, failed_observations=failures,
                ordinary_temperature_observations=ordinary['valid_observations'],
                sensor_freshness_proven=False, continuous_performance_admitted=False,
                hardware_scanout_Hz_proven=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    raw = a.log.read_bytes()
    result = dict(analyze(raw.decode(errors='replace')), source_sha256=hashlib.sha256(raw).hexdigest())
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')


if __name__ == '__main__':
    main()
