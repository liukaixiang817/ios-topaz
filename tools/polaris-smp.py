#!/usr/bin/env python3
"""Opt in to the first two Polaris A55s in an existing private phone ADT.

Requires the existing Polaris PSCI/SGI kernel and matching cpus=2 argument.
Only adds CPU1 (MPIDR0x100), leaving the proven CPU0 and all other nodes
unchanged. No A75, clock/voltage programming, GPU or partition operation.
"""
import argparse
import copy
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt


def props(node):
    return {k: v for k, _, v in node.props}


def child(node, name):
    return next(c for c in node.children if props(c).get('name') == name.encode() + b'\0')


def setprop(node, key, value):
    node.props = [(k, f, v) for k, f, v in node.props if k != key] + [(key, 0, value)]


def nodes(node):
    yield node
    for c in node.children:
        yield from nodes(c)


def build(original, cpu_count=1):
    if type(cpu_count) is not int or cpu_count not in (1, 2):
        raise ValueError('only one CPU or the first two A55s are supported')
    root, _ = adt.parse(original)
    if adt.serialize(root) != original:
        raise ValueError('input ADT must be canonical')
    if b'xiaomi,polaris' not in props(root).get('compatible', b'').split(b'\0'):
        raise ValueError('not a Polaris ADT')
    chosen = props(child(root, 'chosen'))
    if (chosen.get('dram-base') != struct.pack('<Q', 0x180000000) or
            chosen.get('dram-size') != struct.pack('<Q', 0xfc8a0000)):
        raise ValueError('not the observed Polaris upper RAM bank')
    if props(child(child(root, 'arm-io'), 'gic')).get('reg') != struct.pack(
            '<4Q', 0x16a00000, 0x10000, 0x16a60000, 0x100000):
        raise ValueError('requires the physical Polaris GIC, not the stock QEMU topology')
    cpus = child(root, 'cpus')
    if len(cpus.children) != 1:
        raise ValueError('expected the proven one-CPU input tree')
    cpu0 = child(cpus, 'cpu0')
    p = props(cpu0)
    if (p.get('reg') != struct.pack('<I', 0) or p.get('state') != b'running\0' or
            b'qcom,kryo385' not in p.get('compatible', b'').split(b'\0') or
            p.get('timebase-frequency') != struct.pack('<I', 19200000)):
        raise ValueError('unexpected boot CPU identity/state/timebase')
    if cpu_count == 1:
        return original
    handles = [struct.unpack('<I', v)[0] for n in nodes(root)
               for k, _, v in n.props if k == 'AAPL,phandle' and len(v) == 4]
    if len(handles) != len(set(handles)) or not handles or max(handles) == 0xffffffff:
        raise ValueError('invalid phandle namespace')
    cpu1 = copy.deepcopy(cpu0)
    for k, v in [('name', b'cpu1\0'), ('reg', struct.pack('<I', 0x100)),
                 ('cpu-id', struct.pack('<I', 1)), ('cluster-core-id', struct.pack('<I', 1)),
                 ('l2-cache-id', struct.pack('<I', 1)), ('state', b'stopped\0'),
                 ('AAPL,phandle', struct.pack('<I', max(handles) + 1))]:
        setprop(cpu1, k, v)
    # Both first A55s have private128KiB L2 and the same2MiB L3 per liveDT.
    # Keep CPU0's proven properties intact; distinctL2 IDs avoidfalse sharing.
    cpus.children.append(cpu1)
    result = adt.serialize(root)
    cpus.children.remove(cpu1)
    if adt.serialize(root) != original:
        raise ValueError('unrelated ADT mutation')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input_adt', type=Path)
    p.add_argument('output_adt', type=Path)
    p.add_argument('--cpus', type=int, choices=(1, 2), default=1)
    a = p.parse_args()
    data = build(a.input_adt.read_bytes(), a.cpus)
    with a.output_adt.open('xb') as f:
        a.output_adt.chmod(0o600)
        f.write(data)
    print('Prepared private Polaris ADT for ' + str(a.cpus) + ' A55 CPU(s); no phone access')


if __name__ == '__main__':
    main()
