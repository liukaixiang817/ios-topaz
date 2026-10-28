#!/usr/bin/env python3
"""Measure native publication->panel-copy delay, not hardware scanout FPS.

Records contain the native publication identity, lock-protected ready time,
workloop callback time, actual copy begin/end and the original notify deadline.
A timer callback can begin before a concurrent publication: ready>tick is legal.
"""
import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path

FIELDS={'q','s','r','t','b','e','n','w','v','c','d'}


def fields(line, expected):
    tokens=line.strip().split()
    matches=[re.fullmatch(r'(\w+)=(\d+)',token) for token in tokens]
    if any(m is None for m in matches):
        raise ValueError('interleaved or malformed publication record')
    pairs=[(m[1],m[2]) for m in matches]
    if len(pairs)!=len(expected) or {k for k,_ in pairs}!=expected:
        raise ValueError('missing/duplicate/malformed publication field')
    result={k:int(v) for k,v in pairs}
    if any(x>2**64-1 for x in result.values()):
        raise ValueError('publication integer outside native range')
    return result


def stats(values):
    if not values:return None
    s=sorted(values)
    return dict(count=len(s),min=s[0],median=statistics.median(s),
                mean=statistics.mean(s),p95=s[min(len(s)-1,(len(s)*95+99)//100-1)],max=s[-1])


def analyze(text,start,end):
    if not 0<=start<end:raise ValueError('bounded monotonic window required')
    if 'POLARIS PFB ERROR:' in text:raise ValueError('native publication identity failed')
    records=[];all_records=[];panels=[];previous=None
    for line in text.splitlines():
        if 'POLARIS PFB: q=' in line:
            row=fields(line.split('POLARIS PFB: ',1)[1],FIELDS)
            if not row['q'] or not row['r'] or not row['t'] or row['s']>2**32-1:
                raise ValueError('invalid native publication identity')
            if not row['r']<=row['b']<=row['e'] or row['t']>row['b']:
                raise ValueError('publication/copy clock order violated')
            if any(row[k]>1 for k in ['w','v','c']):
                raise ValueError('invalid native publication flag')
            if row['v'] and row['n'] and row['t']<row['n']:
                raise ValueError('early VSYNC notification')
            if previous and (row['q']<=previous['q'] or row['d']<previous['d'] or
                             row['b']<previous['e']):
                raise ValueError('repeated/out-of-order publication or overlapping panel copies')
            previous=row
            all_records.append(row)
            if start<=row['r'] and row['e']<=end:records.append(row)
        if 'POLARIS PANEL PERF:' in line:
            row=fields(line.split('POLARIS PANEL PERF:',1)[1],
                       {'end_us','span_us','copies','fps10','copy_mean_us','maxgap_us','cadence_us'})
            if not row['span_us'] or row['span_us']>row['end_us']:
                raise ValueError('invalid panel window')
            if row['end_us']-row['span_us']>=start and row['end_us']<=end:panels.append(row)
    if not records:raise ValueError('no actual native publication records in window')
    windows=[]
    for p in panels:
        lo=p['end_us']-p['span_us'];hi=p['end_us']
        # A publication can predate a window and still be copied inside it.
        # Only claim a complete window when its native count matches records.
        copies=[r for r in all_records if r['c'] and lo<=r['e']<=hi]
        if len(copies)!=p['copies']:
            raise ValueError('panel count differs from complete native publication records')
        windows.append(dict(start_us=lo,end_us=hi,copies=len(copies)))
    copied=[r for r in records if r['c']]
    return dict(native_records=len(records),actual_completed_panel_copies=len(copied),
        complete_panel_windows=windows,
        ready_to_copy_begin_us=stats([r['b']-r['r'] for r in copied]),
        actual_copy_us=stats([r['e']-r['b'] for r in copied]),
        ready_to_copy_end_us=stats([r['e']-r['r'] for r in copied]),
        notify_lateness_us=stats([r['t']-r['n'] for r in records if r['v'] and r['n']]),
        publication_begin_period_us=stats([b['b']-a['b'] for a,b in zip(copied,copied[1:])]),
        wake_callback_copies=sum(r['w'] for r in copied),
        timer_callback_copies=sum(not r['w'] for r in copied),
        first_publication=records[0]['q'],last_publication=records[-1]['q'],
        records=records,hardware_scanout_FPS_proven=False,sixty_FPS_proven=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('log',type=Path);p.add_argument('--start-us',type=int,required=True)
    p.add_argument('--end-us',type=int,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();raw=a.log.read_bytes();result=analyze(raw.decode(errors='replace'),a.start_us,a.end_us)
    result.update(source_sha256=hashlib.sha256(raw).hexdigest(),start_us=a.start_us,end_us=a.end_us)
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')


if __name__=='__main__':main()
