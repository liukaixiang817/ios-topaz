#!/usr/bin/env python3
"""Correlate opt-in EAGL frame times with completed native/panel time windows.
Uses the shared mach_absolute_time timebase. Does not equate a framebuffer
copy, EAGL completion or a CPU clock request with hardware scanout FPS.
"""
import argparse,hashlib,json,re,statistics
from pathlib import Path
FRAME=re.compile(r'tl: g (\d+) began (\d+) ended (\d+) (\d+)')
PANEL=re.compile(r'POLARIS PANEL PERF: (.*)')
METHOD=re.compile(r'POLARIS GPU METHOD PERF: (.*)')
PHASE=re.compile(r'POLARIS GPU STAGE PERF: (.*)')
PHASE_PART=re.compile(r'POLARIS GPU STAGE (WORK|EXEC|DONE|BYTES): (.*)')
METHOD_PART=re.compile(r'POLARIS GPU METHOD (AUTH|WORK): (.*)')
DETAIL=re.compile(r'redwood-gl: frame (\d+): .*; (\d+) us \((\d+) handing on, (\d+) waiting, (\d+) copying out\), (\d+) before it')
def fields(text):
 result={}
 for k,v in re.findall(r'(\w+)=([^\s]+)',text):
  if k in result:raise ValueError('interleaved diagnostic record has duplicate field: '+k)
  result[k]=int(v) if v.isdecimal() else v
 return result
def stats(values):
 if not values:return None
 order=sorted(values)
 return dict(count=len(order),min=order[0],median=statistics.median(order),p95=order[min(len(order)-1,(95*len(order)+99)//100-1)],max=order[-1],mean=statistics.mean(order))
def join_records(parents,parts,identity,expected,required,start,end):
 """Require every short console part with its original timestamp/identity.
 Legacy complete records remain supported. Never infer a missing value as0.
 """
 def key(row):
  if any(k not in row for k in identity):raise ValueError('diagnostic identity missing')
  return tuple(row[k] for k in identity)
 known={key(p) for p in parents};group={}
 for tag,row in parts:
  if not isinstance(row.get('end_us'),int):raise ValueError('invalid diagnostic part timestamp')
  k=key(row);group.setdefault(k,{}).setdefault(tag,[]).append(row)
  if k not in known and start<=row['end_us']<=end:
   raise ValueError('orphan diagnostic part without timestamp-matching parent')
 result=[];seen=set()
 for parent in parents:
  last=parent.get('end_us');span=parent.get('window_us')
  if not isinstance(last,int) or not isinstance(span,int) or span<=0:
   raise ValueError('invalid native diagnostic window')
  if last-span<start or last>end:continue
  k=key(parent);extra=group.get(k,{})
  if k in seen:raise ValueError('duplicate diagnostic parent')
  seen.add(k)
  if all(isinstance(parent.get(n),int) for n in required):
   if extra:raise ValueError('mixed complete and split diagnostic records')
   result.append(parent);continue
  if not extra:raise ValueError('truncated or malformed native stage record; no complete decomposition claim')
  merged=dict(parent)
  for tag in expected:
   rows=extra.get(tag,[])
   if len(rows)!=1:raise ValueError('missing or duplicate diagnostic part: '+tag)
   for name,value in rows[0].items():
    if name in identity:continue
    if name in merged:raise ValueError('overlapping diagnostic part field: '+name)
    merged[name]=value
  if any(not isinstance(merged.get(n),int) for n in required):
   raise ValueError('truncated or malformed native stage record; no complete decomposition claim')
  result.append(merged)
 return result
def contact_bounds(text,first,last):
 if not 0<first<last:raise ValueError('ordered actual input sequences required')
 lines=text.splitlines()
 def locate(seq,down):
  indices=[i for i,l in enumerate(lines) if re.search(r'POLARIS UEFI INPUT: seq='+str(seq)+r' down='+str(down)+r' ',l)]
  if len(indices)!=1:raise ValueError('contact boundary absent or ambiguous')
  return indices[0]
 a,b=locate(first,1),locate(last,0)
 if a>=b:raise ValueError('contact markers reversed')
 full=[]
 for line in lines[a+1:b]:
  m=FRAME.search(line)
  if m:full.append(tuple(map(int,m.groups())))
 if len(full)<4:raise ValueError('insufficient completions inside actual contacts')
 # The first completion may have BEGUN before the first contact. Exclude it;
 # the next non-overlapping frame begins after that known post-contact end.
 return full[1][1],full[-1][2],dict(first_sequence=first,last_sequence=last,
  first_post_contact_completion_excluded=full[0][0],last_pre_release_completion=full[-1][0],
  boundary='actual native input log ordering, not stale pre-capture or host UTC')
def analyze(text,start,end):
 if not 0<=start<end:raise ValueError('a bounded monotonic window is required')
 frames=[];panels=[];methods=[];details=[];phases=[];method_parts=[];phase_parts=[]
 for line in text.splitlines():
  m=DETAIL.search(line)
  if m:details.append(tuple(map(int,m.groups())))
  m=FRAME.search(line)
  if m:
   seq,began,ended,draws=map(int,m.groups())
   if ended<began:raise ValueError('negative EAGL duration')
   if began>=start and ended<=end:frames.append(dict(frame=seq,began_us=began,ended_us=ended,draws=draws))
  for regex,result in [(METHOD_PART,method_parts),(PHASE_PART,phase_parts)]:
   m=regex.search(line)
   if m:result.append((m[1],fields(m[2])))
  for regex,result,key in [(PANEL,panels,'span_us'),(METHOD,methods,'window_us'),(PHASE,phases,'window_us')]:
   m=regex.search(line)
   if m:
    item=fields(m.group(1));last=item.get('end_us');span=item.get(key)
    if regex!=PANEL or (isinstance(last,int) and isinstance(span,int) and span>0 and last-span>=start and last<=end):result.append(item)
 methods=join_records(methods,method_parts,('end_us','kind'),('AUTH','WORK'),
  ('calls','errors','auth_us','dispatch_us','lock_us','body_us','total_us','max_us'),start,end)
 phases=join_records(phases,phase_parts,('end_us',),('WORK','EXEC','DONE','BYTES'),
  ('submits','rejected','core_missing','validation_us','cache_pre_us','submit_us','cache_post_us',
   'prior_us','ring_us','execute_idle_us','visibility_us','halt_us','postcheck_us','prebytes','postbytes','WCpre','WCpost'),start,end)
 if len(frames)<3:raise ValueError('at least3 actual full-frame timestamp records are required')
 gaps=[];periods=[]
 for a,b in zip(frames,frames[1:]):
  if b['frame']!=a['frame']+1 or b['began_us']<a['ended_us']:
   raise ValueError('multiple contexts, missing frames or overlapping trace; cannot claim a single-frame pipeline')
  gaps.append(b['began_us']-a['ended_us']);periods.append(b['began_us']-a['began_us'])
 durations=[x['ended_us']-x['began_us'] for x in frames]
 span=frames[-1]['ended_us']-frames[0]['began_us'];rendered=len(frames)*1000000/span if span else None
 panel_span=sum(x['span_us'] for x in panels);copies=sum(x['copies'] for x in panels)
 selected={f['frame']:f for f in frames};paired=[]
 for seq,total,flush,finish,copy,attach in details:
  if seq in selected:
   f=selected[seq]
   if total!=f['ended_us']-f['began_us'] or flush+finish+copy>total:
    raise ValueError('detailed frame does not match its full timestamp record')
   paired.append(dict(frame=seq,total_us=total,command_handoff_us=flush,frame_end_blit_flush_wait_us=finish,CPU_readback_us=copy,other_inside_frame_us=total-flush-finish-copy,surface_prepare_us=attach))
 phase_stats={k:stats([f[k] for f in paired]) for k in ['total_us','command_handoff_us','frame_end_blit_flush_wait_us','CPU_readback_us','other_inside_frame_us','surface_prepare_us']}
 by_method={}
 for m in methods:
  b=by_method.setdefault(m['kind'],dict(calls=0,errors=0,auth_us=0,lock_us=0,body_us=0,total_us=0,windows=0))
  for key in b:
   if key!='windows':b[key]+=m[key]
  b['windows']+=1
 for b in by_method.values():
  if b['calls']:
   for k in ['auth_us','lock_us','body_us','total_us']:b['mean_'+k]=b[k]/b['calls']
 phase_totals={};phase_frame_completions=0
 core_keys=['prior_us','ring_us','execute_idle_us','visibility_us','halt_us','postcheck_us']
 for phase in phases:
  required=['submits','rejected','core_missing','validation_us','cache_pre_us',
   'submit_us','cache_post_us','prebytes','postbytes','WCpre','WCpost',*core_keys]
  if any(not isinstance(phase.get(k),int) for k in required):
   raise ValueError('truncated or malformed native stage record; no complete decomposition claim')
  matched=[m for m in methods if m['kind']=='submit' and m['end_us']==phase['end_us']]
  if len(matched)!=1 or phase['submits']!=matched[0]['calls']-matched[0]['errors']:
   raise ValueError('full-stage and native method successful submission counts differ')
  if phase['rejected'] or phase['core_missing']:raise ValueError('incomplete phase timings; no full decomposition claim')
  if sum(phase[k] for k in core_keys)>phase['submit_us']:
   raise ValueError('core sub-stages exceed containing submit walltime')
  for k,v in phase.items():
   if k not in ('end_us','window_us'):phase_totals[k]=phase_totals.get(k,0)+v
  a,b=phase['end_us']-phase['window_us'],phase['end_us']
  phase_frame_completions+=sum(a<f['ended_us']<=b for f in frames)
 phase_per_frame={k:v/phase_frame_completions for k,v in phase_totals.items() if k.endswith('_us')} if phase_frame_completions else {}
 return dict(passed=True,bounded_window_us=[start,end],shared_timebase='mach_absolute_time, microseconds',
  full_frame_trace_count=len(frames),first_frame=frames[0],last_frame=frames[-1],
  logical_EAGL_completion_rate_per_second=rendered,frame_duration_us=stats(durations),
  frame_begin_period_us=stats(periods),after_frame_until_next_begin_us=stats(gaps),
  detailed_frame_pairs=paired,detailed_phase_us=phase_stats,
  frame_over_16_667_us=sum(x>16667 for x in durations),
  complete_panel_windows=len(panels),completed_panel_copies=copies,
  completed_panel_copy_window_us=panel_span,panel_copy_rate_per_second=copies*1000000/panel_span if panel_span else None,
  per_window_panel_copy_mean_us=stats([p['copy_mean_us'] for p in panels]),
  per_window_panel_cadence_us=stats([p['cadence_us'] for p in panels]),
  complete_native_method_windows=by_method,complete_all_submit_phase_windows=len(phases),
  all_submit_phase_totals=phase_totals,phase_window_EAGL_completions=phase_frame_completions,
  phase_us_per_completion_window_ratio=phase_per_frame,core_phases_are_subset_of_submit_us=True,
  hardware_scanout_FPS_proven=False,CPU_busy_proven=False,
  limitations=['EAGL completion is not distinct scanout; panel copy is not hardware VSYNC.',
   'Native wall-time includes preemption; sums across stages/windows must not be added into one frame.',
   'The frame idle gap does not by itself distinguish scheduler delay from CoreAnimation pacing.',
   'No clock request or frequency inference is made.'])
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('log',type=Path)
 ap.add_argument('--start-us',type=int);ap.add_argument('--end-us',type=int)
 ap.add_argument('--contact-start-sequence',type=int);ap.add_argument('--contact-end-sequence',type=int)
 ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 raw=a.log.read_bytes();text=raw.decode(errors='replace');bounds=None
 if a.contact_start_sequence is not None or a.contact_end_sequence is not None:
  if a.start_us is not None or a.end_us is not None or a.contact_start_sequence is None or a.contact_end_sequence is None:ap.error('choose complete native contact pair OR explicit time pair')
  start,end,bounds=contact_bounds(text,a.contact_start_sequence,a.contact_end_sequence)
 else:
  if a.start_us is None or a.end_us is None:ap.error('complete native contact pair OR explicit time pair required')
  start,end=a.start_us,a.end_us
 result=analyze(text,start,end);result.update(source=str(a.log),source_sha256=hashlib.sha256(raw).hexdigest(),actual_contact_bracket=bounds);
 with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps({k:result[k] for k in ['full_frame_trace_count','frame_duration_us','frame_begin_period_us','after_frame_until_next_begin_us','logical_EAGL_completion_rate_per_second','panel_copy_rate_per_second']}))
if __name__=='__main__':main()
