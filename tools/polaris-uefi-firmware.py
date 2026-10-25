#!/usr/bin/env python3
"""Offline RAM-trial packaging for an extracted Mindows Android-v1 UEFI image.

No device access or installation. Preserve BootShim, DTB, ramdisk, every DXE
file and the original SimpleInit executable. Add one hold-only inventory DXE
driver, triggered at ReadyToBoot before any OS application starts. The supplied driver's
build manifest must explicitly forbid XNU handoff and storage/NVRAM writes.
This is a compatibility probe, not an iOS boot manager or an installer.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import uuid
import zlib
import lzma

SIMPLE_INIT = uuid.UUID('6d77b2bb-69eb-42ab-becf-4f40c89568c3')
PROBE_DXE_GUID = uuid.UUID('ca04f676-e2c3-47d5-aebd-ac7f13a7e957')
LZMA_GUID = uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf')
LIMIT = 64 * 1024 * 1024


def require(ok, why):
    if not ok:
        raise ValueError(why)


def align(n, a):
    return (n + a - 1) // a * a


def sha(b):
    return hashlib.sha256(b).hexdigest()


def decode_edk2_lzma(encoded):
    require(len(encoded) >= 13, 'short EDK2 LZMA header')
    declared = struct.unpack_from('<Q', encoded, 5)[0]
    # EDK II GetInfo reads this field directly; FORMAT_ALONE's unknown-size
    # sentinel is not accepted. A host streaming decoder alone misses this.
    require(0 < declared <= LIMIT, 'EDK2 LZMA needs a bounded explicit decoded size')
    z = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    try:
        decoded = z.decompress(encoded, max_length=LIMIT + 1)
    except lzma.LZMAError:
        # liblzma's Alone wrapper rejects a known-size stream with an end
        # marker. The EDK2 SDK decoder accepts it; validate the raw stream
        # and its end marker, then independently enforce the explicit size.
        prop = encoded[0]
        require(prop < 9 * 5 * 5, 'invalid LZMA properties')
        filters = [dict(id=lzma.FILTER_LZMA1, dict_size=struct.unpack_from('<I', encoded, 1)[0],
                        lc=prop % 9, lp=prop // 9 % 5, pb=prop // 45)]
        z = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        decoded = z.decompress(encoded[13:], max_length=LIMIT + 1)
    require(z.eof and not z.unused_data and len(decoded) == declared, 'invalid EDK2 LZMA data/size')
    return decoded


def encode_edk2_lzma(data, dictionary):
    require(4096 <= dictionary <= LIMIT and dictionary & (dictionary - 1) == 0,
            'unsupported original LZMA dictionary')
    require(0 < len(data) <= LIMIT, 'inner FV exceeds decoded bound')
    b = lzma.compress(data, format=lzma.FORMAT_ALONE,
                      filters=[dict(id=lzma.FILTER_LZMA1, dict_size=dictionary)])
    b = b[:5] + struct.pack('<Q', len(data)) + b[13:]
    require(decode_edk2_lzma(b) == data, 'EDK2 LZMA round trip failed')
    return b


def sections(b):
    at = 0
    while at < len(b):
        require(at + 4 <= len(b), 'truncated section header')
        n = int.from_bytes(b[at:at + 3], 'little')
        kind, hs = b[at + 3], 4
        if n == 0xffffff:
            require(at + 8 <= len(b), 'truncated extended section')
            n, hs = struct.unpack_from('<I', b, at + 4)[0], 8
        require(hs <= n <= len(b) - at, 'section size out of bounds')
        yield kind, b[at + hs:at + n], b[at:at + n]
        at = align(at + n, 4)
    require(at <= len(b) + 3, 'invalid section padding')


def section(kind, data):
    n = len(data) + 4
    if n >= 0xffffff:
        require(len(data) + 8 <= 0xffffffff, 'section exceeds extended size field')
        return b'\xff\xff\xff' + bytes([kind]) + struct.pack('<I', len(data) + 8) + data
    return n.to_bytes(3, 'little') + bytes([kind]) + data


def files(fv):
    require(len(fv) >= 72 and fv[40:44] == b'_FVH', 'not an FV')
    length = struct.unpack_from('<Q', fv, 32)[0]
    header = struct.unpack_from('<H', fv, 48)[0]
    require(length == len(fv) and header >= 72 and header % 8 == 0 and header <= length,
            'invalid FV length/header')
    require(sum(struct.unpack('<' + 'H' * (header // 2), fv[:header])) & 65535 == 0,
            'FV checksum mismatch')
    require(struct.unpack_from('<I', fv, 44)[0] & 0x800, 'only erased-FF volumes supported')
    # Keep the existing single block-map entry and its block size.
    count, block, end1, end2 = struct.unpack_from('<IIII', fv, 56)
    require(count and block and count * block == length and not end1 and not end2,
            'unsupported FV block map')
    result, at, names = [], header, set()
    while at + 24 <= length:
        if fv[at:at + 24] == b'\xff' * 24:
            break
        h = fv[at:at + 24]
        size, hs = int.from_bytes(h[20:23], 'little'), 24
        if size == 0xffffff:
            require(at + 32 <= length and h[19] & 1, 'bad large FFS header')
            size, hs = struct.unpack_from('<Q', fv, at + 24)[0], 32
        require(hs <= size <= length - at, 'FFS size out of bounds')
        raw = fv[at:at + size]
        check = bytearray(raw[:hs]); check[17] = check[23] = 0
        require(sum(check) & 255 == 0, 'FFS header checksum mismatch')
        require((sum(raw[hs:]) + raw[17]) & 255 == 0 if h[19] & 0x40 else raw[17] == 0xaa,
                'FFS data checksum mismatch')
        name = uuid.UUID(bytes_le=h[:16])
        require(name not in names, 'duplicate FFS GUID')
        names.add(name)
        # Current files are DATA_VALID with erase polarity inverted.
        require(h[23] == 0xf8, 'non-live FFS state unsupported')
        result.append((name, raw))
        at = align(at + size, 8)
    require(all(x == 0xff for x in fv[at:]), 'unparsed FV tail')
    return header, block, result


def ffs(name, body, template):
    require(len(template) >= 24 and not template[19] & 0x39,
            'large or aligned FFS rewrite unsupported')
    require(len(body) + 24 < 0xffffff, 'large FFS rewrite unsupported')
    h = bytearray(template[:24]); h[:16] = name.bytes_le
    h[16] = 0; h[20:23] = (len(body) + 24).to_bytes(3, 'little')
    h[17] = (-sum(body)) & 255 if h[19] & 0x40 else 0xaa
    h[16] = (-(sum(h) - h[17] - h[23])) & 255
    return bytes(h) + body


def volume(original, new_files, fixed):
    header, block, _ = files(original)
    b = bytearray(original[:header])
    for _, raw in new_files:
        b.extend(b'\xff' * (align(len(b), 8) - len(b))); b.extend(raw)
    length = len(original) if fixed else align(len(b), block)
    require(len(b) <= length, 'replacement does not fit original outer FV')
    b.extend(b'\xff' * (length - len(b)))
    struct.pack_into('<Q', b, 32, length)
    struct.pack_into('<I', b, 56, length // block)
    struct.pack_into('<H', b, 50, 0)
    checksum = (-sum(struct.unpack('<' + 'H' * (header // 2), b[:header]))) & 65535
    struct.pack_into('<H', b, 50, checksum)
    files(bytes(b))  # Independently re-parse checksums, bounds and GUID uniqueness.
    return bytes(b)


def unpack_android(b):
    require(2048 <= len(b) <= LIMIT and b[:8] == b'ANDROID!', 'not an Android image')
    kn, rn, sn, pg, version = [struct.unpack_from('<I', b, o)[0] for o in [8, 16, 24, 36, 40]]
    require(pg == 2048 and version == 1 and rn == 1 and not sn and
            struct.unpack_from('<I', b, 1632)[0] == 0 and
            struct.unpack_from('<I', b, 1644)[0] == 1648, 'unsupported original boot layout')
    ram_at = pg + align(kn, pg)
    require(len(b) == ram_at + align(rn, pg), 'unexpected boot image footer/data')
    kernel, ram = b[pg:pg + kn], b[ram_at:ram_at + rn]
    require(len(kernel) == kn and ram == b'\n', 'invalid original boot components')
    digest = hashlib.sha1(kernel + struct.pack('<I', kn) + ram + struct.pack('<I', rn) +
                          struct.pack('<II', 0, 0)).digest()
    require(b[576:608] == digest + b'\0' * 12, 'Android v1 component digest mismatch')
    dec = zlib.decompressobj(31)
    decoded = dec.decompress(kernel, LIMIT + 1)
    require(dec.eof and len(decoded) <= LIMIT and not dec.unconsumed_tail, 'invalid gzip kernel')
    tail = dec.unused_data
    require(len(tail) >= 40 and tail[:4] == b'\xd0\x0d\xfe\xed' and
            struct.unpack_from('>I', tail, 4)[0] == len(tail), 'invalid appended board DTB')
    return b[:pg], decoded, tail, ram


def package(original, app):
    header, decoded, tail, ram = unpack_android(original)
    require(decoded[56:60] == b'ARMd' and decoded[0x8028:0x802c] == b'_FVH',
            'unexpected original BootShim/FV layout')
    outer = decoded[0x8000:]
    _, _, outer_files = files(outer)
    compressed = []
    for name, raw in outer_files:
        if raw[18] == 0x0b:
            ss = list(sections(raw[24:])); require(len(ss) == 1, 'unexpected FV file sections')
            kind, data, whole = ss[0]
            require(kind == 2 and uuid.UUID(bytes_le=data[:16]) == LZMA_GUID,
                    'unsupported FV compression')
            off, attrs = struct.unpack_from('<HH', data, 16)
            require(off == 24 and attrs == 1, 'unexpected GUID section encoding')
            encoded = whole[off:]
            require(encoded[0] == 0x5d, 'unexpected original LZMA properties')
            dictionary = struct.unpack_from('<I', encoded, 1)[0]
            inner_stream = decode_edk2_lzma(encoded)
            nested = list(sections(inner_stream))
            require(len(nested) == 1 and nested[0][0] == 0x17, 'unexpected inner FV topology')
            compressed.append((name, raw, nested[0][1], dictionary))
    require(len(compressed) == 1, 'expected one compressed inner FV')
    name, old_compressed, inner, dictionary = compressed[0]
    _, _, inner_files = files(inner)
    selected = [raw for guid, raw in inner_files if guid == SIMPLE_INIT]
    require(len(selected) == 1 and all(guid != PROBE_DXE_GUID for guid, _ in inner_files),
            'missing SimpleInit or already modified firmware')
    old_init = selected[0]; require(old_init[18] == 9, 'SimpleInit is not an application')
    originals = dict(inner_files)
    new_files = inner_files.copy()
    body = section(0x10, app)
    body += b'\0' * (align(len(body), 4) - len(body))
    body += section(0x13, b'\x06\x08')  # EFI_DEP_TRUE, EFI_DEP_END.
    body += b'\0' * (align(len(body), 4) - len(body))
    body += section(0x15, 'Polaris RAM compatibility probe\0'.encode('utf-16le'))
    driver_template = bytearray(old_init[:24]); driver_template[18] = 7
    new_files.append((PROBE_DXE_GUID, ffs(PROBE_DXE_GUID, body, driver_template)))
    changed_inner = volume(inner, new_files, fixed=False)
    _, _, verified = files(changed_inner); checked = dict(verified)
    require(all(checked[g] == raw for g, raw in inner_files),
            'unrelated original firmware file changed')
    encoded = encode_edk2_lzma(section(0x17, changed_inner), dictionary)
    new_comp = ffs(name, section(2, LZMA_GUID.bytes_le + struct.pack('<HH', 24, 1) + encoded),
                   old_compressed)
    new_outer = volume(outer, [(g, new_comp if g == name else raw) for g, raw in outer_files], fixed=True)
    new_decoded = decoded[:0x8000] + new_outer
    require(new_decoded[:0x8000] == decoded[:0x8000] and len(new_decoded) == len(decoded),
            'BootShim code or mapped firmware size changed')
    kernel = gzip.compress(new_decoded, mtime=0) + tail
    h = bytearray(header); struct.pack_into('<I', h, 8, len(kernel))
    digest = hashlib.sha1(kernel + struct.pack('<I', len(kernel)) + ram + struct.pack('<I', len(ram)) +
                          struct.pack('<II', 0, 0)).digest()
    h[576:608] = digest + b'\0' * 12
    result = bytes(h) + kernel + b'\0' * (align(len(kernel), 2048) - len(kernel)) + ram
    result += b'\0' * (align(len(ram), 2048) - len(ram))
    _, check_decoded, check_tail, check_ram = unpack_android(result)
    require(check_decoded == new_decoded and check_tail == tail and check_ram == ram,
            'final container verification failed')
    require(len(result) <= LIMIT, 'RAM image exceeds limit')
    return result, dict(original_inner_files=len(originals),
                        unchanged_inner_files=len(originals),
                        original_SimpleInit_preserved=True,
                        probe_DXE_GUID=str(PROBE_DXE_GUID),
                        holds_before_OS_start=True,
                        original_BootShim_preserved=True, board_DTB_sha256=sha(tail),
                        board_DTB_preserved=True, ramdisk_preserved=True,
                        LZMA_dictionary_bytes=dictionary,
                        LZMA_explicit_decoded_bytes=struct.unpack_from('<Q', encoded, 5)[0],
                        kernel_handoff=False, installer=False, phone_writes=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--original', required=True, type=Path)
    ap.add_argument('--expected-sha256', required=True)
    ap.add_argument('--probe-manifest', required=True, type=Path)
    ap.add_argument('--qemu-el1', required=True, type=Path)
    ap.add_argument('--qemu-el2', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    a = ap.parse_args()
    require(not a.output.exists(), 'refusing to overwrite output directory')
    original = a.original.read_bytes()
    require(sha(original) == a.expected_sha256, 'original firmware hash mismatch')
    m = json.loads(a.probe_manifest.read_text()); app_path = a.probe_manifest.parent / m['artifact']
    require(app_path.parent.resolve() == a.probe_manifest.parent.resolve(), 'invalid app path')
    app = app_path.read_bytes()
    require(m.get('probe_only') is True and m.get('holds_before_OS_start') is True and
            m.get('ready_to_boot_driver') is True and
            m.get('kernel_handoff') is False and m.get('storage_write_api') is False and
            m.get('NVRAM_write_api') is False and sha(app) == m['sha256'], 'not a verified hold-only probe')
    for path, mode in [(a.qemu_el1, 'off'), (a.qemu_el2, 'on')]:
        test = json.loads(path.read_text())
        require(test.get('passed') is True and test.get('inventory_hold') is True and
                test.get('image_sha256') == m.get('harness_sha256') and test.get('virtualization') == mode and
                test.get('checks', {}).get('probe_completed_before_hold') is True,
                'same probe has not passed both generic EFI emulation cases')
    pe = struct.unpack_from('<I', app, 60)[0] if len(app) >= 64 else 0
    require(pe >= 64 and pe + 94 <= len(app) and app[:2] == b'MZ' and
            app[pe:pe + 4] == b'PE\0\0' and struct.unpack_from('<H', app, pe + 4)[0] == 0xaa64 and
            struct.unpack_from('<H', app, pe + 24 + 68)[0] == 11, 'not an AArch64 EFI boot-service driver')
    harness = a.probe_manifest.parent / m.get('harness_artifact', '')
    require(harness.parent.resolve() == a.probe_manifest.parent.resolve() and harness.is_file() and
            sha(harness.read_bytes()) == m.get('harness_sha256'), 'emulated driver harness changed')
    result, record = package(original, app)
    require(sha(a.original.read_bytes()) == a.expected_sha256, 'source changed during packaging')
    a.output.mkdir(parents=True)
    target = a.output / 'polaris-original-uefi-probe.img'; target.write_bytes(result)
    record.update(artifact=target.name, bytes=len(result), sha256=sha(result),
                  original_sha256=sha(original), app_sha256=sha(app),
                  probe_manifest_sha256=sha(a.probe_manifest.read_bytes()))
    (a.output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
