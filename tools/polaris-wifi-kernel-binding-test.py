#!/usr/bin/env python3
"""Reject wrong/ambiguous backing before firmware can touch a kernel page."""
import importlib.util
import struct
from pathlib import Path

spec = importlib.util.spec_from_file_location('binding', Path(__file__).with_name('polaris-wifi-kernel-binding.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
BASE = 0xfffffe0007004000
PAGE = module.BYTES
checks = 0


def kernel():
    raw = bytearray(2*PAGE+128)
    struct.pack_into('<8I', raw, 0, 0xfeedfacf, 0x100000c, 0, 2, 2, 176, 0, 0)
    struct.pack_into('<II16s4Q4I', raw, 32, 0x19, 152, b'__DATA', BASE, PAGE, PAGE, PAGE, 3, 3, 1, 0)
    struct.pack_into('<16s16sQQ8I', raw, 104, b'__data', b'__DATA', BASE, PAGE, PAGE, 14, 0, 0, 0, 0, 0, 0)
    struct.pack_into('<6I', raw, 184, 2, 24, 2*PAGE, 1, 2*PAGE+32, len(module.NAME)+2)
    struct.pack_into('<IBBHQ', raw, 2*PAGE, 1, 0xf, 1, 0, BASE)
    raw[2*PAGE+32:2*PAGE+34+len(module.NAME)] = b'\0'+module.NAME+b'\0'
    raw[PAGE:2*PAGE] = module.INITIAL
    return raw


def reject(raw, **kwargs):
    global checks
    try:
        module.binding(raw, kwargs.get('base', BASE), kwargs.get('span', PAGE), kwargs.get('other_spans', ()))
    except ValueError:
        checks += 1
    else:
        raise AssertionError('accepted malformed kernel')


good = kernel()
answer = module.binding(good, BASE, PAGE)
assert answer['file_offset'] == PAGE and answer['offset'] == 0 and not answer['BSS'] and not answer['boot_admission']
checks += 1
for n in (0, 4, 31, 32, 39, 183, 207, PAGE, 2*PAGE, len(good)-100):
    reject(good[:n])
for at, fmt, value in ((0, 'I', 0), (4, 'I', 7), (12, 'I', 1), (16, 'I', 0),
        (16, 'I', 4097), (20, 'I', 177), (20, 'I', 0xffffffff), (36, 'I', 151),
        (36, 'I', 8), (80, 'Q', PAGE+1), (88, 'I', 1), (92, 'I', 7),
        (96, 'I', 2), (136, 'Q', BASE+1), (144, 'Q', PAGE-1), (152, 'I', PAGE+1),
        (168, 'I', 1), (188, 'I', 16), (192, 'I', 0xffffffff),
        (196, 'I', 0xffffffff), (200, 'I', 0xffffffff), (204, 'I', 0xffffffff),
        (2*PAGE, 'I', 0xffffffff), (2*PAGE+4, 'B', 1), (2*PAGE+4, 'B', 0xe),
        (2*PAGE+5, 'B', 0), (2*PAGE+5, 'B', 2), (2*PAGE+8, 'Q', BASE+1)):
    bad = bytearray(good)
    struct.pack_into('<'+fmt, bad, at, value)
    reject(bad)
for at in (40, 104, 120, PAGE, PAGE+1, PAGE+2, 2*PAGE-1):
    bad = bytearray(good)
    bad[at] ^= 1
    reject(bad)
bad = bytearray(good)
bad[2*PAGE+33+len(module.NAME)] = 65
reject(bad)
bad = bytearray(good)
bad[2*PAGE+16:2*PAGE+32] = bad[2*PAGE:2*PAGE+16]
struct.pack_into('<I', bad, 196, 2)
reject(bad)
reject(good, base=BASE+1)
reject(good, span=PAGE-1)
reject(good, base=(1 << 64)-PAGE+1)
reject(good, other_spans=((0, 128),))
reject(good, other_spans=((-1, 128),))
reject(good, other_spans=((PAGE, 128),))
assert module.binding(good, BASE, 2*PAGE, ((PAGE, 128),))['offset'] == 0
checks += 1
# A second section aliases the chosen symbol even though n_sect selects one.
bad = bytearray(good)
bad[264:288] = bad[184:208]
bad[184:264] = bad[104:184]
struct.pack_into('<I', bad, 20, 256)
struct.pack_into('<I', bad, 36, 232)
struct.pack_into('<I', bad, 96, 2)
reject(bad)
# A second overlapping segment must not reinterpret this physical destination.
bad = bytearray(good)
bad[256:280] = bad[184:208]
struct.pack_into('<II16s4Q4I', bad, 184, 0x19, 72, b'__OTHER', BASE, PAGE, PAGE, PAGE, 3, 3, 0, 0)
struct.pack_into('<II', bad, 16, 3, 248)
reject(bad)
# Real XNU keeps file-only CTF metadata with vmsize0. That is allowed away
# from the target; the mailbox's DATA segment must still be fully backed.
real_shape = bytearray(good)
real_shape[256:280] = real_shape[184:208]
struct.pack_into('<II16s4Q4I', real_shape, 184, 0x19, 72, b'__TEXT', BASE-PAGE, PAGE, 0, PAGE, 1, 1, 0, 0)
struct.pack_into('<II16s4Q4I', real_shape, 280, 0x19, 72, b'__CTF', BASE+PAGE, 0, 0, 32, 1, 1, 0, 0)
struct.pack_into('<II', real_shape, 16, 4, 320)
assert module.layout(real_shape) == (BASE-PAGE, 2*PAGE)
assert module.binding(real_shape, *module.layout(real_shape))['offset'] == PAGE
checks += 2
print(f'PASS {checks} kernel mailbox backing checks; synthetic Mach-O, no boot admission')
