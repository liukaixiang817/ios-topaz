#!/usr/bin/env python3
"""Validate paired native readonly TSENS observations, never admit clock policy."""
import argparse,hashlib,json,re
from pathlib import Path

HEAD=re.compile(r'us=(\d+) begin=(\d+) span=(\d+) gold=(-?\d+)/(-?\d+)/(-?\d+)/(-?\d+) gpu=(-?\d+)/(-?\d+); mC observations, not sensor freshness')
RAW=re.compile(r'us=(\d+) pass=([01]) values=([0-9a-f]+(?:/[0-9a-f]+){5})')
ERROR=re.compile(r'us=(\d+) error=([1-9]\d*) last_offset=([0-9a-f]+) raw=([0-9a-f]+); no temperature or policy admission')

def decode(word):
    if not 0<=word<=0xffffffff or not word&(1<<21) or word&(1<<19):
        raise ValueError('invalid/critical native sensor word')
    code=word&0xfff
    if code&0x800:code-=4096
    value=code*100
    if not -40000<=value<=150000:raise ValueError('implausible native sensor word')
    return value

def analyze(text):
    heads={};raws={};errors=[];order=[]
    for line in text.splitlines():
        if 'POLARIS TSENS RO: us=' in line:
            body=line.split('POLARIS TSENS RO: ',1)[1]
            error=ERROR.fullmatch(body)
            if error:
                stamp,code,offset,word=error.groups()
                errors.append(dict(us=int(stamp),error=int(code),offset=int(offset,16),raw=int(word,16)))
                continue
            match=HEAD.fullmatch(body)
            if not match:raise ValueError('malformed/truncated/interleaved TSENS observation')
            stamp,began,span,*temps=map(int,match.groups())
            if stamp in heads or not 0<began<=stamp<2**64 or stamp-began!=span or span>1000:
                raise ValueError('TSENS identity or observation-clock bounds violated')
            if order and stamp<=order[-1]:raise ValueError('TSENS clock/order reversed')
            heads[stamp]=dict(us=stamp,begin_us=began,span_us=span,temperatures_mC=temps);order.append(stamp)
        elif 'POLARIS TSENS RAW:' in line:
            match=RAW.fullmatch(line.split('POLARIS TSENS RAW: ',1)[1])
            if not match:raise ValueError('malformed native raw sensor record')
            stamp,which,words=match.groups();key=(int(stamp),int(which))
            if key in raws:raise ValueError('duplicate native sensor pass')
            raws[key]=[int(word,16) for word in words.split('/')]
    if not heads:raise ValueError('no complete native temperature observations')
    expected={(stamp,p) for stamp in heads for p in (0,1)}
    if set(raws)!=expected:raise ValueError('missing or orphan native raw sensor passes')
    samples=[]
    for stamp in order:
        first=list(map(decode,raws[stamp,0]));second=list(map(decode,raws[stamp,1]))
        if any(abs(a-b)>2000 for a,b in zip(first,second)):
            raise ValueError('successive native sensor values disagree')
        if heads[stamp]['temperatures_mC']!=list(map(max,first,second)):
            raise ValueError('native temperatures do not match their raw sensor words')
        samples.append(dict(heads[stamp],raw_passes=[raws[stamp,0],raws[stamp,1]]))
    sensors=[]
    for n in range(6):
        values=[sample['temperatures_mC'][n] for sample in samples]
        sensors.append(dict(id=7+n,role='gold' if n<4 else 'GPU',minimum_mC=min(values),maximum_mC=max(values),distinct_values=len(set(values))))
    return dict(valid_observations=len(samples),first_us=order[0],last_us=order[-1],
                max_observation_gap_us=max((b-a for a,b in zip(order,order[1:])),default=0),
                sensors=sensors,error_observations=errors,samples=samples,
                sensor_freshness_proven=False,continuous_performance_admitted=False,
                hardware_scanout_Hz_proven=False)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    raw=a.log.read_bytes();result=analyze(raw.decode(errors='replace'))
    result['source_sha256']=hashlib.sha256(raw).hexdigest()
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')

if __name__=='__main__':main()
