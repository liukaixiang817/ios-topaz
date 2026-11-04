#!/usr/bin/env python3
"""Independent little-endian decoder for EARLY_WIFI_MEMORY_RAW_V1.

The raw file remains authoritative, including incomplete calls and map tails.
A consistent completed record only describes local UEFI claims. It never grants
secure ownership, proves firmware callback absence, or admits remote startup.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


class Layout:
    def __init__(self, fields, alignment=1):
        self.fields = {}
        end = 0
        for name, kind, count in fields:
            size, align = (kind.size, kind.align) if isinstance(kind, Layout) else (kind, kind)
            end = (end + align - 1) // align * align
            self.fields[name] = (end, kind, count)
            end += size * count
            alignment = max(alignment, align)
        self.align = alignment
        self.size = (end + alignment - 1) // alignment * alignment

    def decode(self, data, base=0):
        result = {}
        for name, (offset, kind, count) in self.fields.items():
            at = base + offset
            if isinstance(kind, Layout):
                values = [kind.decode(data, at + n * kind.size) for n in range(count)]
            elif kind == 1 and count > 1:
                result[name] = data[at:at + count].hex()
                continue
            else:
                values = list(struct.unpack_from('<' + {1:'B',4:'I',8:'Q'}[kind] * count, data, at))
            result[name] = values[0] if count == 1 else values
        return result


def fields(kind, names):
    return [(n, kind, 1) for n in names.split()]


INPUT = Layout(fields(8, 'image image_bytes bank bank_bytes'))
COMMAND = Layout(fields(8, 'address pages') + fields(4, 'sequence operation index reserved'))
MAP_HEADER = Layout(fields(8, 'status bytes key stride') + fields(4, 'version issued returned valid'))
MAP = Layout([('map', MAP_HEADER, 1), ('data', 1, 8192)])
CLAIM = Layout(fields(8, 'requested bytes pages status returned_address exposed exposed_bytes') +
               fields(4, 'issued returned retained reserved'))
MEMORY = Layout([('input', INPUT, 1), ('command', COMMAND, 1)] +
                fields(4, 'started unknown error pending calls complete') +
                [('claim', CLAIM, 2), ('map', MAP, 3)])
CPU = Layout(fields(8, 'el mpidr ttbr0 ttbr1 tcr sctlr mair daif sre group1 frequency ticks'))
ARCH = Layout([('cpu', CPU, 1), ('cpacr', 8, 1)])
FP = Layout(fields(8, 'cpacr_before cpacr_after fpcr fpsr') + [('q8_q15', 8, 16)] +
            fields(4, 'saved restored'), alignment=16)
CORE_AT = Layout(fields(8, 'page raw') + fields(4, 'issued returned'))
CORE = Layout([('AT', CORE_AT, 57), ('hashes', 1, 160)] +
              fields(4, 'pages hash_count hash_failed complete') + fields(8, 'TPL smm'))
CALL = Layout([('before', ARCH, 1), ('after', ARCH, 1), ('fp', FP, 1), ('source', CORE, 2)] +
              fields(4, 'issued returned unknown complete native_before native_after'))
IMAGE = Layout(fields(4, 'revision pad') + fields(8, 'parent system device file_path reserved') +
               fields(4, 'options_bytes pad2') + fields(8, 'options base bytes') +
               fields(4, 'code_type data_type') + fields(8, 'unload'))
TRANSLATION = Layout(fields(8, 'page saved read_par write_par restored') +
                     fields(4, 'read_issued read_returned write_issued write_returned'))
NATIVE = Layout([('memory', MEMORY, 1), ('image', IMAGE, 1)] +
                fields(8, 'system image_address native_address boot core') +
                [('BS', 1, 376), ('call', CALL, 5), ('AT', TRANSLATION, 1028), ('final', ARCH, 1),
                 ('translated', 4, 2)] + fields(4, 'attempted complete error unknown'))
LAYOUTS = dict(pwea_input=INPUT, pwea_command=COMMAND, pgcd_map=MAP_HEADER, pwea_map=MAP,
               pwea_claim=CLAIM, pwea_memory=MEMORY, pwfc_arch=CPU, pgcd_arch=ARCH,
               pgcd_fp_guard=FP, pwmc_irq_AT=CORE_AT, pwea_core=CORE,
               pwea_native_call=CALL, efi_loaded=IMAGE, pwmc_translation=TRANSLATION,
               pwea_native=NATIVE)


def descriptors(item):
    m = item['map']
    if not (40 <= m['stride'] <= 8192 and m['stride'] % 8 == 0 and
            0 < m['bytes'] <= 8192 and m['bytes'] % m['stride'] == 0):
        raise ValueError('map dimensions')
    data = bytes.fromhex(item['data'])
    result = []
    for offset in range(0,m['bytes'],m['stride']):
        raw = data[offset:offset+m['stride']]
        kind,pad,base,virtual,pages,attributes = struct.unpack_from('<IIQQQQ',raw)
        if base % 4096 or not pages or base+pages*4096 >= 1<<64:
            raise ValueError('map extent')
        result.append((base,base+pages*4096,kind,attributes,raw))
    result.sort()
    if any(a[1] > b[0] for a,b in zip(result,result[1:])):
        raise ValueError('map overlap')
    return result


def owned(items, base, size, kind):
    cursor = base
    for start,end,owner,attributes,_ in items:
        if start <= cursor < end:
            if owner != kind or attributes >> 63: return False
            cursor = min(end,base+size)
            if cursor == base+size:return True
    return False


def allocation_delta(before, after, base, size):
    # Independent interval partition comparison handles both descriptor split
    # and coalescence. Padding, virtual address, attributes and extensions must
    # remain identical everywhere; only this claim's type7->2 may change.
    if not owned(before,base,size,7) or not owned(after,base,size,2):return False
    boundaries = sorted({base,base+size,*[x for d in before+after for x in d[:2]]})
    for start,end in zip(boundaries,boundaries[1:]):
        a = next((d for d in before if d[0] <= start < d[1]),None)
        b = next((d for d in after if d[0] <= start < d[1]),None)
        if a is None or b is None:
            if a != b:return False
            continue
        if base <= start < base+size:
            if (a[2],b[2]) != (7,2):return False
        elif a[2] != b[2]:return False
        if a[4][4:8]+a[4][16:24]+a[4][32:] != b[4][4:8]+b[4][16:24]+b[4][32:]:return False
    return True


def decode(raw):
    if len(raw) != NATIVE.size:
        raise ValueError(f'RAW_V1 needs exactly {NATIVE.size} bytes, received {len(raw)}')
    record = NATIVE.decode(raw)
    issues = []
    def require(ok, label):
        if not ok: issues.append(label)
    memory = record['memory']
    require((record['attempted'],record['complete'],record['error'],record['unknown']) == (1,1,0,0), 'native completion')
    require(tuple(memory[k] for k in ('started','unknown','error','pending','calls','complete')) == (1,0,0,0,5,1), 'memory completion')
    for n, claim in enumerate(memory['claim']):
        size = (0x200000,0x202000)[n]
        require(tuple(claim[k] for k in ('bytes','pages','status','issued','returned','retained','reserved')) ==
                (size,size//4096,0,1,1,1,0), f'claim {n} completion')
        base = claim['requested']
        require(0x80000000 <= base <= 0x100000000-size and base % (0x200000 if n == 0 else 4096) == 0 and
                claim['returned_address'] == base and claim['exposed'] == base + (4096 if n else 0) and
                claim['exposed_bytes'] == (0x200000 if n else 0x100000), f'claim {n} extent')
        require(record['translated'][n] == size//4096, f'claim {n} translated count')
        for k in range(size//4096):
            at = record['AT'][514*n+k]
            page = base + 4096*k
            require(at['page'] == page and at['read_par'] == at['write_par'] == (0xff00000000000b80 | page) and
                    at['saved'] == at['restored'] and all(at[x] == 1 for x in
                    ('read_issued','read_returned','write_issued','write_returned')), f'claim {n} translation {k}')
    a,b = memory['claim']
    require(a['requested']+a['bytes'] <= b['requested'] or b['requested']+b['bytes'] <= a['requested'], 'claim overlap')
    for n, item in enumerate(memory['map']):
        m = item['map']
        require(tuple(m[k] for k in ('status','version','issued','returned','valid')) == (0,1,1,1,1) and
                m['key'] and 40 <= m['stride'] <= 8192 and 0 < m['bytes'] <= 8192 and m['bytes'] % m['stride'] == 0,
                f'map {n} completion')
    try:
        maps = [descriptors(item) for item in memory['map']]
        bank = memory['input']
        require(all(owned(m,bank['bank'],bank['bank_bytes'],2) for m in maps),'bank ownership')
        for n, claim in enumerate(memory['claim']):
            before,after = memory['map'][n]['map'],memory['map'][n+1]['map']
            require(before['stride'] == after['stride'] and before['key'] != after['key'] and
                    allocation_delta(maps[n],maps[n+1],claim['requested'],claim['bytes']), f'claim {n} full map delta')
            require(owned(maps[2],claim['requested'],claim['bytes'],2), f'claim {n} retained map')
    except ValueError as error:
        issues.append(str(error))
    for n, call in enumerate(record['call']):
        require(tuple(call[k] for k in ('issued','returned','unknown','complete','native_before','native_after')) == (1,1,0,1,0,0), f'call {n} completion')
        require(call['fp']['saved'] == call['fp']['restored'] == 1, f'call {n} FP')
        for phase in range(2):
            q = call['source'][phase]
            if n == 0 and phase == 0:
                require(q == CORE.decode(bytes(CORE.size)), 'first source must be unobserved')
            else:
                require((q['pages'],q['hash_count'],q['complete'],q['TPL'],q['smm']) == (57,5,1,4,0), f'call {n} source {phase}')
    return dict(format='EARLY_WIFI_MEMORY_RAW_V1', bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                local_completion_consistent=not issues,issues=issues,secure_ownership_proven=False,
                source_identity_reverified=False,physical_wifi_proven=False,record=record)


def extract(text):
    begin=b'EARLY_WIFI_MEMORY_RAW_V1_BEGIN\r\n'
    end=b'EARLY_WIFI_MEMORY_RAW_V1_END\r\n'
    if text.count(begin)!=1 or text.count(end)!=1:
        raise ValueError('requires one complete early RAW record')
    body=text.split(begin,1)[1].split(end,1)[0]
    if not re.fullmatch(rb'(?:[0-9a-f]{2})+(?:\r\n(?:[0-9a-f]{2})+)*\r\n',body):
        raise ValueError('malformed or partial RAW hex')
    return bytes.fromhex(body.decode())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--ram-log',action='store_true')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    raw=args.input.read_bytes()
    if args.ram_log:raw=extract(raw)
    result=decode(raw)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='record'}))


if __name__=='__main__':main()
