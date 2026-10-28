#!/usr/bin/env python3
"""Decode fixed RO A630/SDM845v2 GPUCC snapshots from native diagnostics.

Formula follows pinned MiCode c7cb50c1 gpucc-sdm845.c, clk-alpha-pll.c and
clk-rcg2.c. It is a REFERENCE clock graph, not a validated GMU firmware clock
graph. Even an admitted reference estimate is NOT physical configured or
instantaneous frequency, utilization, or proof a vote was executed. Do not fit
an unexplained divider to make a physical snapshot match its requested rate.
"""
import argparse,hashlib,json,re
from pathlib import Path
PINNED_COMMIT='c7cb50c18f812629b9620b2b8fa684bc40d82080'
FACTORY_HZ=(180000000,257000000,342000000,414000000,520000000,596000000,675000000,710000000)
CLOCK_KEYS=('CMD','CFG','MODE','L','FRAC','USER','OP')
RO_KEYS=('ok','valid','ACK','PERF','BW','RETURN')
RECORD=re.compile(r'POLARIS GPU CLOCK (RO|A|B): (.*)')
def parse_fields(raw,expected):
 pairs=re.findall(r'(\w+)=([^\s]+)',raw);out={}
 for key,value in pairs:
  if key in out:raise ValueError('duplicate clock field')
  if key not in ('end_us',*expected):raise ValueError('unknown clock field')
  if not re.fullmatch('[0-9]+' if key in ('end_us','ok') else '[0-9a-fA-F]+',value):raise ValueError('invalid clock number')
  out[key]=int(value,10 if key in ('end_us','ok') else 16)
 if set(out)!=set(('end_us',*expected)):raise ValueError('missing clock field')
 if out['end_us']>=2**64 or any(out[k]>=2**32 for k in expected):raise ValueError('clock integer overflow')
 return out

def decode(ro,first,second):
 # Same-end and full read mask, then two-pass stability, before any arithmetic.
 if not (ro.get('end_us')==first.get('end_us')==second.get('end_us')):raise ValueError('clock timestamp mismatch')
 if ro['ok']!=1 or ro['valid']!=0x3ffff:raise ValueError('partial native clock reads')
 if any(first[k]!=second[k] for k in CLOCK_KEYS):raise ValueError('PLL/RCG changed during read-only snapshot')
 if ro['ACK'] or ro['RETURN']:raise ValueError('unconfirmed GMU request state')
 if ro['PERF']&0xffffff00!=0x30000000 or not 1<=ro['PERF']&255<=7 or not 1<=ro['BW']<=12:
  raise ValueError('unknown GMU request encoding')
 c=first
 if c['CMD']&1:raise ValueError('RCG update in flight')
 if (c['CFG']>>8)&7!=1 or c['CFG']&0x3000:raise ValueError('unsupported graphics clock parent/mode')
 if not c['MODE']&(1<<31) or c['OP']!=1:raise ValueError('Fabia PLL is not locked/running')
 if not 0<c['L']<256 or c['FRAC']>=65536:raise ValueError('unsupported Fabia L/fraction')
 divider={0:1,1:2,3:4,7:8}.get((c['USER']>>8)&15)
 if divider is None:raise ValueError('unknown PLL even post-divider')
 # Preserve original vendor integer rounding order: PLL, postdiv, then HID.
 pll=19200000*c['L']+((19200000*c['FRAC'])>>16)
 parent=pll//divider;hid=c['CFG']&31
 rate=parent*2//(hid+1) if hid else parent
 nearest=min(FACTORY_HZ,key=lambda f:abs(f-rate))
 if abs(nearest-rate)>500:raise ValueError('configured rate is outside original factory table tolerance')
 return dict(admitted=True,end_us=ro['end_us'],requested_index=ro['PERF']&255,
  requested_floor_Hz=FACTORY_HZ[ro['PERF']&255],bandwidth_index=ro['BW'],
  reference_graph_rate_Hz=rate,nearest_reference_factory_clock_Hz=nearest,
  request_floor_met_by_register_configuration=rate+500>=FACTORY_HZ[ro['PERF']&255],
  parent='GPU_PLL0_even / CRC_div1',PLL_Hz=pll,PLL_post_divider=divider,
  RCG_HID=hid,primary_commit=PINNED_COMMIT,
  physical_clock_graph_verified=False,physical_configured_clock_Hz=None,
  instantaneous_frequency_proven=False,GPU_busy_or_scanout_FPS_proven=False)

def analyze(text):
 groups={}
 for line in text.splitlines():
  match=RECORD.search(line)
  if not match:continue
  tag=match[1];row=parse_fields(match[2],RO_KEYS if tag=='RO' else CLOCK_KEYS)
  group=groups.setdefault(row['end_us'],{})
  if tag in group:raise ValueError('duplicate native clock record')
  group[tag]=row
 if not groups:raise ValueError('no actual native clock snapshots')
 result=[]
 for end,group in sorted(groups.items()):
  if set(group)!=set(('RO','A','B')):raise ValueError('incomplete native clock record group')
  try:item=decode(group['RO'],group['A'],group['B'])
  except ValueError as error:item=dict(admitted=False,end_us=end,reason=str(error))
  item['raw']=group;result.append(item)
 return result

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('log',type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
 raw=a.log.read_bytes();records=analyze(raw.decode(errors='replace'))
 result=dict(source=str(a.log),source_sha256=hashlib.sha256(raw).hexdigest(),
  algorithm_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  records=records,admitted_count=sum(r['admitted'] for r in records),
  rejected_count=sum(not r['admitted'] for r in records),reference_graph_only=True,
  physical_clock_graph_verified=False,physical_configured_clock_Hz=None,
  instantaneous_frequency_proven=False)
 with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps({k:result[k] for k in ('admitted_count','rejected_count','instantaneous_frequency_proven')}))
if __name__=='__main__':main()
