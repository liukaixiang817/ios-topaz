#!/usr/bin/env python3
"""Validate scoped CA clock-choice observations; not physical refresh rate."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ENV = re.compile(r'POLARIS CA CLOCK ENV: request=(-?\d+) status=(-?\d+); no refresh-rate claim')
TARGET = re.compile(r'POLARIS CA CLOCK TARGET: status=(-?\d+) mode=(\d+); exact20H392 read-only')
SAMPLE = re.compile(r'POLARIS CA CLOCK: us=(\d+) mode=(\d+) ready=(\d+) choice=(\d+) window_frames=(\d+); choice not hardware Hz')


def analyze(text, start, end, mode):
    if not 0 <= start < end < 2**64 or mode not in (1, 2):
        raise ValueError('explicit bounded clock experiment required')
    env, targets, samples = [], [], []
    for line in text.splitlines():
        if not line.startswith('POLARIS CA CLOCK'):
            continue
        if m := ENV.fullmatch(line):
            env.append(tuple(map(int, m.groups())))
        elif m := TARGET.fullmatch(line):
            targets.append(tuple(map(int, m.groups())))
        elif m := SAMPLE.fullmatch(line):
            us, observed_mode, ready, choice, frames = map(int, m.groups())
            if (not 0 < us < 2**64 or observed_mode != mode or ready not in (0, 1)
                    or not 0 <= choice <= 255 or (ready and choice > 1)
                    or not 0 < frames < 2**32 or (samples and us <= samples[-1]['us'])):
                raise ValueError('invalid/nonmonotonic clock observation')
            samples.append(dict(us=us, mode=observed_mode, ready=ready, choice=choice, window_frames=frames))
        else:
            raise ValueError('malformed/truncated clock observation')
    if env != [(mode, mode)] or targets != [(1, mode)]:
        raise ValueError('successful unique scoped environment/target binding required')
    selected = [s for s in samples if start <= s['us'] <= end]
    if not selected or any(not s['ready'] for s in selected):
        raise ValueError('no complete initialized CA choice in the selected interval')
    choices = sorted({s['choice'] for s in selected})
    if mode == 1 and choices != [1]:
        raise ValueError('explicit VBL request did not select the audited CA path')
    return dict(passed=True, mode=mode, selected=selected, observed_choices=choices,
                runtime_CA_choice_observed=True, hardware_refresh_Hz_proven=False,
                sixty_FPS_proven=False, window_frames_is_cumulative_sequence=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('--start-us', type=int, required=True)
    p.add_argument('--end-us', type=int, required=True)
    p.add_argument('--mode', type=int, required=True, choices=(1, 2))
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); raw = a.log.read_bytes()
    result = dict(analyze(raw.decode(errors='replace'), a.start_us, a.end_us, a.mode),
                  source_sha256=hashlib.sha256(raw).hexdigest())
    with a.output.open('x') as f:
        json.dump(result, f, indent=2); f.write('\n')
