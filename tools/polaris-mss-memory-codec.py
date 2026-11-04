#!/usr/bin/env python3
"""Decode MSS_MEMORY_RAW_V1 independently; successful allocation is not Wi-Fi.

Requires its original early allocation record. Optional post-payload evidence
checks continued EFI ownership without inventing target AT/cache/VMID grants.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('early_codec', Path(__file__).with_name('polaris-wifi-early-codec.py'))
early = importlib.util.module_from_spec(spec)
spec.loader.exec_module(early)
Layout, fields = early.Layout, early.fields
RANGE = Layout(fields(8, 'base bytes'))
INPUT = Layout([('owner', early.INPUT, 1), ('metadata_bytes', 8, 1), ('retained', RANGE, 2)])
MEMORY = Layout([('input', INPUT, 1), ('command', early.COMMAND, 1)] +
                fields(4, 'started unknown error pending calls complete') +
                [('claim', early.CLAIM, 3), ('map', early.MAP, 4)])
NATIVE = Layout([('memory', MEMORY, 1)] + fields(8, 'early digest') +
                [('early_digest', 1, 32), ('call', early.CALL, 7), ('final', early.ARCH, 1)] +
                fields(4, 'attempted unknown error complete'))
LAYOUTS = dict(pwmc_range=RANGE, pmme_input=INPUT, pmme_memory=MEMORY, pmmn_native=NATIVE)
RESERVED = [(0x85700000,0x600000),(0x85d00000,0x200000),(0x85fc0000,0x4940000),
            (0x8ab00000,0x1400000),(0x8bf00000,0x500000),(0x8c400000,0x10000),
            (0x8c410000,0x5000),(0x8c415000,0x2000),(0x8c500000,0x1e00000),
            (0x8e300000,0x100000),(0x8e400000,0x7800000),(0x95c00000,0x500000),
            (0x96100000,0x800000),(0x96900000,0x200000),(0x96b00000,0x1400000),
            (0x97f00000,0x100000),(0x9d400000,0x2400000),(0xb0000000,0x400000),
            (0xaf000000,0x1000000),(0x86000000,0x200000)]


def disjoint(a, n, b, m):
    return n > 0 and m > 0 and a+n < 1 << 64 and b+m < 1 << 64 and (a+n <= b or b+m <= a)


def admitted(a):
    c = a['cpu']
    return (c['el'] == 4 and c['mpidr'] & 0xffffff == 0 and c['frequency'] == 19200000 and
            c['ticks'] > 0 and c['sre'] & 1 and c['sctlr'] & 1 and c['mair'] == 0xffbb4400 and
            c['daif'] == 0 and c['group1'] == 1 and (a['cpacr'] >> 20) & 3 == 3)


def stable(a, b, limit=38400000):
    return (admitted(a) and admitted(b) and a['cpacr'] == b['cpacr'] and
            all(a['cpu'][k] == b['cpu'][k] for k in a['cpu'] if k != 'ticks') and
            0 <= b['cpu']['ticks']-a['cpu']['ticks'] <= limit)


def decode(raw, early_raw, retained_raw=None):
    if len(raw) != NATIVE.size:
        raise ValueError(f'MSS_MEMORY_RAW_V1 needs exactly {NATIVE.size} bytes')
    r = NATIVE.decode(raw)
    e = early.decode(early_raw)
    issues = []
    def require(ok, label):
        if not ok: issues.append(label)
    require(e['local_completion_consistent'], 'early completion')
    e = e['record']
    m = r['memory']; i = m['input']; owner = i['owner']
    require(r['early_digest'] == hashlib.sha256(early_raw).hexdigest(), 'early digest')
    require(r['early'] > 0 and r['digest'] > 0, 'resident input addresses')
    require(tuple(r[k] for k in ('attempted','unknown','error','complete')) == (1,0,0,1), 'native completion')
    require(tuple(m[k] for k in ('started','unknown','error','pending','calls','complete')) == (1,0,0,0,7,1), 'memory completion')
    require(owner == e['memory']['input'], 'actual early owner')
    require(0 < i['metadata_bytes'] <= 65536, 'metadata bounds')
    retained = [(q['requested'],q['bytes']) for q in e['memory']['claim']]
    require([(q['base'],q['bytes']) for q in i['retained']] == retained, 'actual early retained claims')
    exclusions = RESERVED + [(owner['image'],owner['image_bytes']),(owner['bank'],owner['bank_bytes'])] + retained
    for n, q in enumerate(m['claim']):
        size = (0x7800000,0x100000,(i['metadata_bytes']+4095)//4096*4096)[n]
        base = q['requested']
        require(tuple(q[k] for k in ('bytes','pages','status','issued','returned','retained','reserved')) ==
                (size,size//4096,0,1,1,1,0), f'claim {n} completion')
        require(0x80000000 <= base <= 0x100000000-size and base % (0x100000 if n == 0 else 4096) == 0 and
                q['returned_address'] == q['exposed'] == base and q['exposed_bytes'] == (i['metadata_bytes'] if n == 2 else size),
                f'claim {n} geometry')
        require(all(disjoint(base,size,b,s) for b,s in exclusions), f'claim {n} exclusions')
        exclusions.append((base,size))
    require(m['command'] == dict(address=0,pages=0,sequence=7,operation=1,index=3,reserved=0), 'terminal command')
    for n, item in enumerate(m['map']):
        h = item['map']
        require(tuple(h[k] for k in ('status','version','issued','returned','valid')) == (0,1,1,1,1) and h['key'] > 0,
                f'map {n} completion')
    try:
        maps = [early.descriptors(item) for item in m['map']]
        require(all(early.owned(ds,owner['bank'],owner['bank_bytes'],2) and
                    all(early.owned(ds,b,s,2) for b,s in retained) for ds in maps), 'early retained ownership')
        for n,q in enumerate(m['claim']):
            a,b = m['map'][n]['map'],m['map'][n+1]['map']
            require(a['key'] != b['key'] and a['stride'] == b['stride'] and
                    early.allocation_delta(maps[n],maps[n+1],q['requested'],q['bytes']), f'claim {n} whole delta')
            require(all(early.owned(ds,q['requested'],q['bytes'],2) for ds in maps[n+1:]), f'claim {n} retained')
    except ValueError as error: issues.append(str(error))
    opening = r['call'][0]['before']
    for n,c in enumerate(r['call']):
        require(tuple(c[k] for k in ('issued','returned','unknown','complete','native_before','native_after')) == (1,1,0,1,0,0),
                f'call {n} completion')
        require(stable(opening,c['before']) and stable(c['before'],c['after'],3840000) and
                (n == 0 or c['before']['cpu']['ticks'] >= r['call'][n-1]['after']['cpu']['ticks']), f'call {n} CPU/time')
        require(c['fp']['saved'] == c['fp']['restored'] == 1 and c['fp']['cpacr_before'] == c['before']['cpacr'], f'call {n} FP')
        for phase,s in enumerate(c['source']):
            require((s['pages'],s['hash_count'],s['hash_failed'],s['complete'],s['TPL'],s['smm']) == (57,5,0,1,4,0), f'call {n} source {phase}')
            require(s['hashes'] == e['call'][4]['source'][1]['hashes'], f'call {n} source hashes {phase}')
            require(all(a['page'] == e['core']+4096*k and a['raw'] == (0xff00000000000b80|a['page']) and
                        a['issued'] == a['returned'] == 1 for k,a in enumerate(s['AT'])), f'call {n} source AT {phase}')
    require(stable(opening,r['final']) and r['final']['cpu']['ticks'] >= r['call'][6]['after']['cpu']['ticks'], 'final CPU/time')
    if retained_raw is not None:
        h = early.decode_retained(retained_raw,early_raw)
        require(h['local_completion_consistent'], 'post-payload producer completion')
        h = h['record']
        require(h['input']['early'] == r['early'] and h['input']['digest'] == r['digest'], 'post-payload early binding')
        require(h['before']['cpu']['ticks'] >= r['final']['cpu']['ticks'], 'post-payload ordering')
        try:
            ds = early.descriptors(h['map'])
            for n,q in enumerate(m['claim']):
                require(early.owned(ds,q['requested'],q['bytes'],2) and
                        disjoint(q['requested'],q['bytes'],h['payload'],h['payload_bytes']) and
                        disjoint(q['requested'],q['bytes'],h['log'],h['input']['log_bytes']), f'post-payload claim {n}')
        except ValueError as error: issues.append(str(error))
    return dict(format='MSS_MEMORY_RAW_V1',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                local_completion_consistent=not issues,issues=issues,physical_wifi_proven=False,
                secure_ownership_proven=False,target_mapping_proven=False,record=r)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('raw',type=Path);p.add_argument('--early',type=Path,required=True)
    p.add_argument('--retained',type=Path);p.add_argument('--ram-log',action='store_true')
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    raw=a.raw.read_bytes()
    if a.ram_log:raw=early.extract(raw,b'MSS_MEMORY_RAW_V1')
    result=decode(raw,a.early.read_bytes(),a.retained.read_bytes() if a.retained else None)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='record'}))


if __name__ == '__main__':main()
