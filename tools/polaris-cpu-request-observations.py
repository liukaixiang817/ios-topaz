#!/usr/bin/env python3
"""Associate frames with bracketed native CPU request observations, not Hz.

The interval between consecutive readbacks is not a continuous hardware
frequency measurement. Exclude frames overlapping either policy tick. Never
extrapolate past the final observation or infer causation from these groups.
"""
import argparse
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('frame_stats', Path(__file__).with_name('polaris-frame-latency.py'))
fm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fm)
REQUEST = re.compile(r'begin_us=(\d+) end_us=(\d+) index=(\d+) transitions=(\d+) error=(\d+); request not measured Hz')
INVENTORY = re.compile(r'physical0x([4-7]00) raw_index=(0x[0-9a-f]+|0) effective_index=(0x[0-9a-f]+|0) requested_Hz=(\d+); request is not measured Hz')


def analyze(text, start, end):
    if not 0 <= start < end:
        raise ValueError('bounded monotonic frame window required')
    records, inventory = [], []
    for line in text.splitlines():
        prefix = 'POLARIS OSM REQUEST: '
        if not line.startswith(prefix):
            continue
        initial = INVENTORY.fullmatch(line[len(prefix):])
        if initial:
            physical, raw, effective, nominal = initial.groups()
            row = dict(physical=int(physical, 16), raw_index=int(raw, 0),
                       effective_index=int(effective, 0), nominal_request_Hz=int(nominal))
            if row['raw_index'] >= 27 or row['effective_index'] >= 27 or row['nominal_request_Hz'] >= 2**64:
                raise ValueError('invalid untimed initial CPU inventory')
            inventory.append(row)
            continue  # This older, untimed inventory is never a live-frame observation.
        m = REQUEST.fullmatch(line[len(prefix):])
        if not m:
            raise ValueError('truncated/interleaved CPU request observation')
        begin, finish, index, transitions, error = map(int, m.groups())
        if not 0 < begin <= finish < 2**64 or index not in (0, 22) or transitions >= 2**64:
            raise ValueError('invalid native request observation')
        row = dict(begin_us=begin, end_us=finish, index=index, transitions=transitions, error=error)
        if records:
            prev = records[-1]
            if begin < prev['end_us'] or transitions < prev['transitions']:
                raise ValueError('request observation clock or counter reversed')
        records.append(row)
    if len(records) < 2:
        raise ValueError('two complete native observations required')
    all_records = len(records)
    # The bounded measurement needs its immediately preceding/following
    # observations, not an unrelated incomplete startup interval. A missing
    # transition inside those bounds still refuses the entire association.
    first = max(0, bisect.bisect_right([p['end_us'] for p in records], start) - 1)
    last = min(len(records), bisect.bisect_left([p['begin_us'] for p in records], end) + 1)
    records = records[first:last]
    for prev, row in zip(records, records[1:]):
        if row['transitions'] > prev['transitions'] + 1:
            raise ValueError('request transition records missing inside bounded association')
        if row['transitions'] == prev['transitions'] and row['index'] != prev['index']:
            raise ValueError('request changed without a matching policy transition')
    selected = []
    for m in fm.FRAME.finditer(text):
        seq, began, ended, _ = map(int, m.groups())
        if start <= began and ended <= end:
            if ended < began:
                raise ValueError('frame clock reversed')
            selected.append((seq, began, ended))
    for a, b in zip(selected, selected[1:]):
        if b[0] != a[0] + 1 or b[1] < a[2]:
            raise ValueError('frame trace is not one complete context')
    ends = [p['end_us'] for p in records]
    groups = {0: [], 22: []}
    gap_groups, period_groups = {0: [], 22: []}, {0: [], 22: []}
    previous = None
    excluded = 0
    for _, began, ended in selected:
        i = bisect.bisect_right(ends, began) - 1
        if i < 0 or i + 1 >= len(records) or ended > records[i + 1]['begin_us'] or records[i]['error'] or records[i + 1]['error']:
            excluded += 1
            previous = None
            continue
        groups[records[i]['index']].append(ended - began)
        if previous is not None and previous[0] == i:
            gap_groups[records[i]['index']].append(began - previous[2])
            period_groups[records[i]['index']].append(began - previous[1])
        previous = (i, began, ended)
    return dict(request_observations=records, untimed_inventory_excluded=inventory,
                out_of_window_request_records_excluded=all_records-len(records),
                selected_frames=len(selected), excluded_frames=excluded,
                frame_duration_by_last_observed_request={str(k): fm.stats(v) for k, v in groups.items()},
                interframe_gap_by_same_request_interval={str(k): fm.stats(v) for k, v in gap_groups.items()},
                frame_begin_period_by_same_request_interval={str(k): fm.stats(v) for k, v in period_groups.items()},
                request_tick_wall_us=fm.stats([p['end_us'] - p['begin_us'] for p in records]),
                continuous_hardware_frequency_proven=False, CPU_busy_proven=False,
                correlation_is_not_isolated_causation=True, hardware_scanout_Hz_proven=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('--start-us', type=int, required=True)
    p.add_argument('--end-us', type=int, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    raw = a.log.read_bytes()
    result = dict(analyze(raw.decode(errors='replace'), a.start_us, a.end_us), source_sha256=hashlib.sha256(raw).hexdigest())
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')


if __name__ == '__main__':
    main()
