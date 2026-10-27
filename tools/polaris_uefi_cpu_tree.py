"""Select resident XNU CPU1, CPU7, or a CPU7+CPU6 pair in a Polaris RAM tree.

CPU0 remains firmware-owned. No clocks, voltage, RAM or peripherals change.
The two-core experiment additionally requires explicit cpus=2 kernel opt-in.
The declared clock-frequency is a compatibility value, not a measurement.
"""
import argparse
import copy
from pathlib import Path
import struct

import adt


def props(node):
    return {key: value for key, _, value in node.props}


def child(node, name):
    matches = [n for n in node.children if n.name == name]
    if len(matches) != 1:
        raise ValueError('missing or duplicate ' + name)
    return matches[0]


def owner_metadata(node, name):
    p = props(node)
    if (len(p) != len(node.props) or set(p) != {
            'name', 'version', 'layout', 'protected-blocks', 'owner-packet', 'protected-map'} or
            p['name'] != (name+'\0').encode() or p['version'] != struct.pack('<I', 1) or
            len(p['layout']) != 24 or len(p['protected-blocks']) != 8):
        raise ValueError('noncanonical owned-file fixture metadata')
    packet = p['owner-packet']
    if len(packet) < 384 or packet[:8] != b'PROWN001':
        raise ValueError('truncated owned-file packet')
    nodes, maps = struct.unpack_from('<II', packet, 72)
    if (nodes > 64 or not 0 < maps <= 4096 or
            struct.unpack_from('<II', packet, 8) != (384, len(packet)) or
            len(packet) != 384 + nodes * 4104 + maps * 24 or
            p['layout'] != packet[16:40]):
        raise ValueError('owned-file packet/layout mismatch')
    start, blocks, file_blocks = struct.unpack('<QQQ', p['layout'])
    if not 256 <= start <= 0xffffffff or not 0 < blocks <= 2**32-start or not 0 < file_blocks <= blocks:
        raise ValueError('owned-file partition bounds')
    if not p['protected-map'] or len(p['protected-map']) % 24 or len(p['protected-map']) > 4096*24:
        raise ValueError('protected base map required')
    logical = 0
    for at in range(0, len(p['protected-map']), 24):
        offset, physical, length = struct.unpack_from('<QQQ', p['protected-map'], at)
        if offset != logical or not start <= physical < start+blocks or not 0 < length <= start+blocks-physical:
            raise ValueError('protected base must be a complete canonical bounded map')
        logical += length
    if struct.unpack('<Q', p['protected-blocks'])[0] != logical:
        raise ValueError('protected base coverage mismatch')
    return p


def validate(raw, core=1, qemu=False, count=1):
    if (type(core) is not int or core not in (1, 7) or type(qemu) is not bool or
            type(count) is not int or count not in (1, 2) or count == 2 and core != 7):
        raise ValueError('only firmware-reserved CPU1 or CPU7 trials are supported')
    tree, used = adt.parse(raw)
    if used != len(raw) or adt.serialize(tree) != raw:
        raise ValueError('canonical complete tree required')
    if b'xiaomi,polaris' not in props(tree).get('compatible', b'').split(b'\0'):
        raise ValueError('not the Polaris compatibility tree')
    chosen = props(child(tree, 'chosen'))
    base = 0x130000000 if qemu else 0x180000000
    gic = (0x7000000, 0x10000, 0x70a0000, 0x100000 if core == 7 else 0x40000) if qemu else (
        0x16a00000, 0x10000, 0x16a60000, 0x100000)
    if (chosen.get('dram-base') != struct.pack('<Q', base) or
            chosen.get('dram-size') != struct.pack('<Q', 0xfc8a0000) or
            props(child(child(tree, 'arm-io'), 'gic')).get('reg') != struct.pack('<4Q', *gic)):
        raise ValueError('RAM/GIC does not match the selected platform')
    cpus = child(tree, 'cpus')
    if len(cpus.children) != count:
        raise ValueError('wrong declared XNU CPU count; firmware CPU0 is reserved')
    target = core if qemu else core << 8
    for logical, cpu in enumerate(cpus.children):
        p = props(cpu)
        physical = target - logical * (1 if qemu else 0x100)
        if (p.get('reg') != struct.pack('<I', physical) or
                p.get('cpu-id') != struct.pack('<I', logical) or
                p.get('state') != (b'running\0' if logical == 0 else b'stopped\0')):
            raise ValueError('logical CPU does not match the selected physical core/state')
    owned = [n for n in tree.children if n.name == 'polaris-qemu-owned-file']
    virtual_ufs = [n for n in tree.children if n.name == 'polaris-qemu-ufs']
    if owned:
        if not qemu or core != 7 or count != 2 or len(owned) != 1 or len(virtual_ufs) != 1:
            raise ValueError('owned virtual fixture must never reach a phone tree')
        owner_metadata(owned[0], 'polaris-qemu-owned-file')
    if virtual_ufs:
        if not qemu or core != 7 or count != 2 or len(virtual_ufs) != 1:
            raise ValueError('isolated virtual UFS must never reach a phone tree')
        p = props(virtual_ufs[0])
        expected = {'name': b'polaris-qemu-ufs\0',
                    'compatible': b'qemu,isolated-owned-ufs\0' if owned else b'qemu,isolated-readonly-ufs\0',
                    'version': struct.pack('<I', 1),
                    'reg': struct.pack('<QQ', 0x10100000, 0x2000),
                    'ecam': struct.pack('<QQ', 0x4010000000, 0x100000)}
        if (len(p) != len(virtual_ufs[0].props) or set(p) != set(expected) | {'head-crc32'} or
                any(p.get(k) != v for k, v in expected.items()) or len(p.get('head-crc32', b'')) != 4):
            raise ValueError('noncanonical isolated virtual UFS metadata')
    marker = [n for n in tree.children if n.name == 'polaris-owned-marker']
    if marker:
        if qemu or core != 7 or count != 2 or len(marker) != 1 or owned or virtual_ufs:
            raise ValueError('physical marker must never reach a virtual or foreign CPU tree')
        p = owner_metadata(marker[0], 'polaris-owned-marker')
        base_file = props(child(tree, 'polaris-file-root'))
        layout = base_file.get('layout', b'')
        if (len(layout) != 24 or base_file.get('reg') != struct.pack('<QQ', 0x1d84000, 0x2500) or
                base_file.get('version') != struct.pack('<I', 1) or
                p['layout'][:16] != layout[:16] or struct.unpack_from('<Q',p['layout'],16)[0] != 2048 or
                p['protected-map'] != base_file.get('extents') or p['protected-blocks'] != layout[16:24] or
                struct.unpack_from('<Q',layout,16)[0] != 4194304):
            raise ValueError('physical marker must bind the complete actual original16GiB root map')
        packet=p['owner-packet'];nodes,maps=struct.unpack_from('<II',packet,72)
        start,blocks,file_blocks=struct.unpack('<QQQ',p['layout']);next_block=0;seen=[]
        protected=[struct.unpack_from('<QQQ',p['protected-map'],at)
                   for at in range(0,len(p['protected-map']),24)]
        for n in range(maps):
            logical,physical,length=struct.unpack_from('<QQQ',packet,384+nodes*4104+n*24)
            if (logical!=next_block or not 0<length<=file_blocks-next_block or
                    not 0<physical<blocks or length>blocks-physical):
                raise ValueError('marker map must completely cover the new small file')
            absolute=start+physical
            if any(absolute<a+b and a<absolute+length for a,b in seen) or any(
                    absolute<a+b and a<absolute+length for _,a,b in protected):
                raise ValueError('marker aliases itself or the original root')
            seen.append((absolute,length));next_block+=length
        if next_block!=file_blocks:raise ValueError('marker map incomplete')
    return tree


def select(raw, core=1, qemu=False, count=1):
    if (type(core) is not int or core not in (1, 7) or type(count) is not int or
            count not in (1, 2) or count == 2 and core != 7):
        raise ValueError('only firmware-reserved CPU1 or CPU7 trials are supported')
    tree = validate(raw, 1, qemu)
    cpu = child(tree, 'cpus').children[0]
    old = 1 if qemu else 0x100
    if core == 1:
        return raw
    target = core if qemu else core << 8
    cpu.props = [(key, flags, struct.pack('<I', target) if key == 'reg' else value)
                 for key, flags, value in cpu.props]
    gic_node = child(child(tree, 'arm-io'), 'gic')
    old_gic = props(gic_node)['reg']
    if qemu:
        # Eight emulated affinities need all eight redistributors mapped.
        # Physical Polaris already maps its complete one-MiB GICR region.
        expanded = struct.pack('<4Q', 0x7000000, 0x10000, 0x70a0000, 0x100000)
        gic_node.props = [(key, flags, expanded if key == 'reg' else value)
                          for key, flags, value in gic_node.props]
    peer = None
    if count == 2:
        def walk(node):
            yield node
            for sub in node.children:
                yield from walk(sub)
        handles = [struct.unpack('<I', value)[0] for node in walk(tree)
                   for key, _, value in node.props if key == 'AAPL,phandle' and len(value) == 4]
        if not handles or len(handles) != len(set(handles)) or max(handles) == 0xffffffff:
            raise ValueError('invalid phandle namespace')
        peer = copy.deepcopy(cpu)
        updates = {'name': b'cpu1\0', 'cpu-id': struct.pack('<I', 1),
                   'reg': struct.pack('<I', target - (1 if qemu else 0x100)),
                   'cluster-core-id': struct.pack('<I', 1), 'l2-cache-id': struct.pack('<I', 1),
                   'state': b'stopped\0', 'AAPL,phandle': struct.pack('<I', max(handles) + 1)}
        peer.props = [(key, flags, updates.get(key, value)) for key, flags, value in peer.props]
        child(tree, 'cpus').children.append(peer)
    result = adt.serialize(tree)
    validate(result, core, qemu, count)
    if peer is not None:
        child(tree, 'cpus').children.remove(peer)
    gic_node.props = [(key, flags, old_gic if key == 'reg' else value)
                      for key, flags, value in gic_node.props]
    cpu.props = [(key, flags, struct.pack('<I', old) if key == 'reg' else value)
                 for key, flags, value in cpu.props]
    if adt.serialize(tree) != raw:
        raise ValueError('unrelated tree mutation')
    return result


def isolated_qemu_ufs(raw, head_crc32):
    """Add a read-only native-controller fixture to an already validated VM.

    The ECAM/window are from the actual virt FDT and the isolated UFS device
    is bus0/slot3. The kernel also checks actual MPIDR and CNTFRQ before MMIO.
    """
    if type(head_crc32) is not int or not 0 <= head_crc32 <= 0xffffffff:
        raise ValueError('exact CRC32 required')
    root = validate(raw, 7, True, 2)
    if any(n.name == 'polaris-qemu-ufs' for n in root.children):
        raise ValueError('virtual UFS is already present')
    node = adt.Node()
    node.props = [(k, 0, v) for k, v in {
        'name': b'polaris-qemu-ufs\0', 'compatible': b'qemu,isolated-readonly-ufs\0',
        'version': struct.pack('<I', 1), 'reg': struct.pack('<QQ', 0x10100000, 0x2000),
        'ecam': struct.pack('<QQ', 0x4010000000, 0x100000),
        'head-crc32': struct.pack('<I', head_crc32)}.items()]
    root.children.append(node)
    result = adt.serialize(root)
    validate(result, 7, True, 2)
    return result


def isolated_qemu_owned(raw, head_crc32, packet, protected_map, protected_blocks):
    """Bind a synthetic owner export; the native driver must reread all metadata."""
    tree, _ = adt.parse(isolated_qemu_ufs(raw, head_crc32))
    controller = child(tree, 'polaris-qemu-ufs')
    controller.props = [(k, f, b'qemu,isolated-owned-ufs\0' if k == 'compatible' else v)
                        for k, f, v in controller.props]
    node = adt.Node()
    node.props = [(k, 0, v) for k, v in {
        'name': b'polaris-qemu-owned-file\0', 'version': struct.pack('<I', 1),
        'layout': packet[16:40], 'owner-packet': packet, 'protected-map': protected_map,
        'protected-blocks': struct.pack('<Q', protected_blocks)}.items()]
    tree.children.append(node)
    result = adt.serialize(tree)
    validate(result, 7, True, 2)
    return result


def physical_marker(raw, packet):
    """Add a small owned-file export while preserving the complete original root."""
    tree = validate(raw, 7, False, 2)
    if any(n.name == 'polaris-owned-marker' for n in tree.children):
        raise ValueError('physical marker already present')
    base = props(child(tree, 'polaris-file-root'))
    node = adt.Node()
    node.props = [(k, 0, v) for k,v in {
        'name': b'polaris-owned-marker\0', 'version': struct.pack('<I',1),
        'layout': packet[16:40], 'owner-packet': packet,
        'protected-map': base['extents'], 'protected-blocks': base['layout'][16:24]}.items()]
    tree.children.append(node)
    result = adt.serialize(tree)
    validate(result,7,False,2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--core', type=int, choices=(1, 7), default=1)
    parser.add_argument('--qemu', action='store_true')
    parser.add_argument('--cpus', type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    result = select(args.input.read_bytes(), args.core, args.qemu, args.cpus)
    with args.output.open('xb') as out:
        out.write(result)
    print('Selected one resident XNU core; clocks and storage unchanged')


if __name__ == '__main__':
    main()
