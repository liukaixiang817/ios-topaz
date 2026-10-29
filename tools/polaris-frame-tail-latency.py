#!/usr/bin/env python3
"""Audit six-part EAGL tail windows; these wall times are not hardware Hz."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('frame_latency', Path(__file__).with_name('polaris-frame-latency.py'))
fm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fm)
KEYS = {
    'HEAD': ('id', 'q', 'end_us', 'from_us', 'n', 'first', 'last', 'mode'),
    'TOTAL': ('id', 'q', 'end_us', 'gap', 'tail', 'outside', 'render', 'maxgap'),
    'WORK': ('id', 'q', 'end_us', 'log', 'obs', 'report', 'maxtail', 'maxobs'),
    'ACTIVE': ('id', 'q', 'end_us', 'n', 'idle', 'gap', 'tail', 'outside', 'render', 'over'),
    'ACTIVEWORK': ('id', 'q', 'end_us', 'log', 'obs', 'report'),
    'API': ('id', 'q', 'end_us', 'api', 'active', 'calls', 'activecalls', 'maxapi'),
}
RECORD = re.compile(r'POLARIS GL TAIL (HEAD|TOTAL|WORK|ACTIVE|ACTIVEWORK|API): (.*)')


def analyze(text, start, end, mode=2):
    if not 0 <= start < end < 2**64 or mode not in (2, 3):
        raise ValueError('explicit bounded diagnostic mode/window required')
    parts = {}
    for line in text.splitlines():
        if line.startswith('POLARIS GL TAIL FAULT:'):
            raise ValueError('native tail accounting failed; do not infer missing time')
        if not line.startswith('POLARIS GL TAIL ') or line.startswith('POLARIS GL TAIL MODE:'):
            continue
        m = RECORD.fullmatch(line)
        if not m:
            raise ValueError('malformed or truncated tail diagnostic')
        kind, body = m.groups()
        tokens = body.split()
        if len(tokens) != len(KEYS[kind]):
            raise ValueError('tail part missing or extra fields')
        row = {}
        for token, name in zip(tokens, KEYS[kind]):
            pattern = name + r'=([0-9a-f]+)' if name == 'id' else name + r'=(\d+)'
            match = re.fullmatch(pattern, token)
            if not match:
                raise ValueError('tail part has reordered, duplicate or invalid fields')
            row[name] = int(match[1], 16 if name == 'id' else 10)
            if row[name] >= 2**64:
                raise ValueError('tail field exceeds native integer width')
        key = row['id'], row['q'], row['end_us']
        if not row['id'] >> 32 or not row['id'] & 0xffffffff or not 0 < row['q'] < 2**32:
            raise ValueError('invalid process/context/window identity')
        group = parts.setdefault(key, {})
        if kind in group:
            raise ValueError('duplicate tail part')
        group[kind] = row
    selected, contexts, residuals = [], {}, []
    all_frames = [tuple(map(int, m.groups())) for m in fm.FRAME.finditer(text)]
    for key, group in sorted(parts.items(), key=lambda pair: pair[0][2]):
        head = group.get('HEAD')
        if head is None:
            if start <= key[2] <= end:
                raise ValueError('orphan tail part in measurement interval')
            continue
        if head['from_us'] < start or head['end_us'] > end:
            continue  # Do not use partially overlapping aggregate windows.
        if set(group) != set(KEYS):
            raise ValueError('all six native tail parts required')
        total, work, active, aw = [group[k] for k in ('TOTAL', 'WORK', 'ACTIVE', 'ACTIVEWORK')]
        api = group['API']
        n = head['n']
        if (n != 64 or head['mode'] != mode or not 0 < head['first'] <= head['last'] < 2**32
                or head['last'] - head['first'] != n - 1 or not 0 < head['from_us'] < head['end_us']
                or total['tail'] + total['outside'] != total['gap']
                or total['render'] + total['gap'] != head['end_us'] - head['from_us']
                or work['log'] + work['obs'] > total['tail'] or work['report'] > work['log']
                or total['maxgap'] * n < total['gap'] or total['maxgap'] > total['gap']
                or work['maxtail'] * n < total['tail'] or work['maxtail'] > total['tail']
                or work['maxobs'] * n < work['obs'] or work['maxobs'] > work['obs']
                or active['n'] + active['idle'] != n or active['over'] > active['n']
                or active['tail'] + active['outside'] != active['gap']
                or aw['log'] + aw['obs'] > active['tail'] or aw['report'] > aw['log']
                or api['api'] > total['outside'] or api['active'] > active['outside']
                or api['active'] > api['api'] or api['activecalls'] > api['calls']
                or api['maxapi'] * n < api['api'] or api['maxapi'] > api['api']):
            raise ValueError('native wall-time partition, identity or bound violated')
        for name in ('render', 'gap', 'tail', 'outside'):
            if active[name] > total[name] or (not active['n'] and active[name]):
                raise ValueError('active window exceeds the retained total')
        for name in ('log', 'obs', 'report'):
            if aw[name] > work[name] or (not active['n'] and aw[name]):
                raise ValueError('active work exceeds the retained total')
        prior = contexts.get(head['id'])
        if prior and (head['q'] != prior['q'] + 1 or head['first'] != prior['last'] + 1
                      or head['from_us'] != prior['end_us']):
            raise ValueError('selected context windows are not complete and contiguous')
        contexts[head['id']] = head
        if mode == 2:
            frames = [v for v in all_frames if head['from_us'] <= v[1] < head['end_us']]
            successor = [v for v in all_frames if v[0] == head['last'] + 1 and v[1] == head['end_us']]
            if (len(frames) != n or len(successor) != 1 or frames[0][0] != head['first']
                    or frames[0][1] != head['from_us'] or frames[-1][0] != head['last']):
                raise ValueError('aggregate does not match the actual full-frame trace')
            following = frames[1:] + successor
            for a, b in zip(frames, following):
                if b[0] != a[0] + 1 or not a[1] <= a[2] <= b[1]:
                    raise ValueError('frame trace is missing, overlapping or interleaved')
            renders = [v[2] - v[1] for v in frames]
            gaps = [b[1] - a[2] for a, b in zip(frames, following)]
            real_active = [i for i, (a, b) in enumerate(zip(frames, following)) if b[1] - a[1] <= 100000]
            if (sum(renders) != total['render'] or sum(gaps) != total['gap'] or max(gaps) != total['maxgap']
                    or len(real_active) != active['n'] or sum(renders[i] for i in real_active) != active['render']
                    or sum(gaps[i] for i in real_active) != active['gap']
                    or sum(renders[i] + gaps[i] > 16667 for i in real_active) != active['over']):
                raise ValueError('aggregate frame accounting differs from exact native-time trace')
            # A window supplies maxima, not individual tail/API samples. Even
            # subtracting BOTH maxima from EVERY pair leaves this much outside
            # those measured paths. This is a lower bound, not scheduler time.
            for a, b, render, gap in zip(frames, following, renders, gaps):
                residuals.append(dict(context=head['id'], window=head['q'], frame=a[0],
                                      begin_us=a[1], next_begin_us=b[1],
                                      render_us=render, gap_us=gap,
                                      tail_upper_us=work['maxtail'], api_upper_us=api['maxapi'],
                                      outside_tail_and_API_lower_us=max(0, gap - work['maxtail'] - api['maxapi'])))
        selected.append(dict(head=head, total=total, work=work, active=active, active_work=aw, api=api,
                             full_trace_independently_matched=mode == 2))
    if not selected:
        raise ValueError('no complete bounded tail windows')
    totals = {k: sum(v['total'][k] for v in selected) for k in ('gap', 'tail', 'outside', 'render')}
    works = {k: sum(v['work'][k] for v in selected) for k in ('log', 'obs', 'report')}
    active = {k: sum(v['active'][k] for v in selected) for k in ('n', 'idle', 'over', 'gap', 'tail', 'outside', 'render')}
    active_work = {k: sum(v['active_work'][k] for v in selected) for k in ('log', 'obs', 'report')}
    n = 64 * len(selected)
    api_total = sum(v['api']['api'] for v in selected)
    api_active = sum(v['api']['active'] for v in selected)
    # Contact pauses remain in the full population. The separately named
    # <=25ms-period cohort excludes long waits without claiming steady FPS.
    short = [v for v in residuals if v['next_begin_us'] - v['begin_us'] <= 25000]
    def bounds(rows):
        return dict(pairs=len(rows), gap_us=fm.stats([v['gap_us'] for v in rows]),
                    outside_tail_and_API_lower_us=fm.stats([v['outside_tail_and_API_lower_us'] for v in rows]))
    return dict(passed=True, mode=mode, complete_windows=selected, complete_pairs=n,
                mean_wall_us_per_pair={k: v / n for k, v in dict(totals, **works).items()},
                active_totals=active, active_work_totals=active_work,
                active_mean_wall_us={k: v / active['n'] for k, v in dict(
                    {k: active[k] for k in ('gap', 'tail', 'outside', 'render')}, **active_work).items()} if active['n'] else None,
                hardware_scanout_Hz_proven=False, CPU_busy_proven=False,
                outside_is_pure_scheduler_wait=False, own_report_cost_is_retained=True,
                mean_pre_frame_API_wall_us=api_total / n,
                active_mean_pre_frame_API_wall_us=api_active / active['n'] if active['n'] else None,
                pre_frame_API_includes_preemption=True,
                full_trace_residual_bounds=dict(all_pairs=bounds(residuals),
                    period_le_25000_us=bounds(short), rows=residuals,
                    individual_tail_or_API_time_proven=False, scheduler_wait_proven=False) if mode == 2 else None,
                final_unclosed_tail_measured=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('--start-us', type=int, required=True)
    p.add_argument('--end-us', type=int, required=True)
    p.add_argument('--mode', type=int, choices=(2, 3), required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); raw = a.log.read_bytes()
    result = dict(analyze(raw.decode(errors='replace'), a.start_us, a.end_us, a.mode),
                  source_sha256=hashlib.sha256(raw).hexdigest())
    with a.output.open('x') as f:
        json.dump(result, f, indent=2); f.write('\n')


if __name__ == '__main__':
    main()
