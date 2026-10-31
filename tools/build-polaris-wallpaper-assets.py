#!/usr/bin/env python3
"""Prepare exact original iOS16 wallpaper PNG/CAML assets for later RAMCOW use.

Host-only. Reads an existing root, compiles the adjacent ImageIO helper, and
writes only to a new ignored research directory. Never installs to a phone.
ImageIO needs access to the host decoding service; an unavailable pixel
provider is an error, never a successful blank-image conversion.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import plistlib
import re
import struct
import subprocess
import sys
from urllib.parse import unquote, quote
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[1]
BASE = Path('Library/Wallpaper/Collections/iOS_16~iphone.wallpaperCollection')
WALLPAPER = BASE / 'Wallpapers/7400.WWDC_2022-375w-812h@3x~iphone.wallpaper'
EXPECTED = {'Body.HEIC', 'Arm.HEIC', 'Leg.HEIC', 'Head.HEIC', 'Head Mask.HEIC'}
CAP = 32 * 1024 * 1024
REF = re.compile(rb'(<contents\s+type="CGImage"\s+src=")([^"<>]+)("\s*/>)')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_info(path):
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': digest(data), 'mode': path.stat().st_mode & 0o777}


def within(path, root):
    return path == root or root in path.parents


def binary_array(name, data):
    lines = [f'static const unsigned char {name}[] __attribute__((aligned(16))) = {{\n']
    lines.extend('    ' + ','.join('0x%02x' % x for x in data[i:i+24]) + ',\n'
                 for i in range(0, len(data), 24))
    lines.append('};\n')
    return ''.join(lines)


def hash_array(hex_value):
    return '{' + ','.join('0x' + hex_value[i:i+2] for i in range(0, 64, 2)) + '}'


def structure(data):
    """Comparison only; never reserialize the original XML into runtime files."""
    root = ET.fromstring(data)
    def node(e):
        return [e.tag, sorted(e.attrib.items()), (e.text or '').strip(),
                [(child.tail or '').strip() for child in e], [node(c) for c in e]]
    return node(root)


def macho_alloc_bytes(data):
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('Expected little-endian ARM64 Mach-O object')
    ncmds = struct.unpack_from('<I', data, 16)[0]
    at, total, sections = 32, 0, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > len(data):
            raise ValueError('Malformed object command')
        if cmd == 0x19:
            count = struct.unpack_from('<I', data, at + 64)[0]
            for i in range(count):
                s = at + 72 + i * 80
                if s + 80 > at + size:
                    raise ValueError('Malformed object section')
                name = data[s:s+16].split(b'\0')[0].decode()
                segment = data[s+16:s+32].split(b'\0')[0].decode()
                length = struct.unpack_from('<Q', data, s + 40)[0]
                align = struct.unpack_from('<I', data, s + 52)[0]
                if align > 20:
                    raise ValueError('Unexpected section alignment')
                total = (total + (1 << align) - 1) & ~((1 << align) - 1)
                total += length
                sections.append({'segment': segment, 'section': name, 'bytes': length, 'align_power': align})
        at += size
    return total, sections


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--graphics-bytes', type=int, default=15475776)
    args = parser.parse_args()
    root, out = args.root.resolve(strict=True), args.out.resolve()
    ignored = (REPO / 'research').resolve()
    if not within(out, ignored) or within(out, root) or within(root, out) or out.exists():
        parser.error('Output must be a NEW directory under ignored research, separate from the source root')
    if not 0 < args.graphics_bytes <= CAP:
        parser.error('Invalid existing graphics byte count')
    subprocess.run(['git', 'check-ignore', '--quiet', str(out)], cwd=REPO, check=True)
    source = root / WALLPAPER
    original = {str(p.relative_to(root)): file_info(p) for p in sorted(source.rglob('*')) if p.is_file()}
    if not original or any(p.is_symlink() for p in source.rglob('*')):
        parser.error('Missing default wallpaper or unexpected symbolic link')
    scenes = sorted(source.glob('*.ca/main.caml'))
    images = sorted(source.rglob('*.HEIC'))
    if len(scenes) != 3 or len(images) != 5 or {p.name for p in images} != EXPECTED:
        parser.error('Expected exact original375w812h three scenes and five images')
    wallpaper_plist = plistlib.loads((source / 'Wallpaper.plist').read_bytes())
    if wallpaper_plist.get('identifier') != 7400 or wallpaper_plist.get('logicalScreenClass') != '375w-812h@3x~iphone':
        parser.error('Wallpaper identity mismatch')
    out.mkdir(parents=True)
    helper = out / 'wallpaper-imageio'
    helper_source = REPO / 'tools/polaris-wallpaper-imageio.c'
    build = ['/usr/bin/clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(helper_source),
             '-framework', 'CoreFoundation', '-framework', 'CoreGraphics', '-framework', 'ImageIO', '-o', str(helper)]
    subprocess.run(build, check=True, capture_output=True)
    evidence = out / 'decode-evidence'
    evidence.mkdir()
    payload = out / 'payload'
    payload.mkdir()
    manifest = {'schema': 'polaris.wallpaper.ramcow-assets.v1', 'ready': False,
                'ios_build': '20F66', 'wallpaper_identifier': 7400,
                'logical_screen_class': '375w-812h@3x~iphone', 'source_root': str(root),
                'runtime_destination': '512MiB RAMCOW only; immutable UFS original unchanged',
                'host_only': True, 'physical_wallpaper_fixed': False,
                'helper_source_sha256': digest(helper_source.read_bytes()),
                'helper_sha256': digest(helper.read_bytes()), 'helper_compile_command': build,
                'original_files': original, 'images': [], 'files': [], 'scenes': []}
    manifest_path = out / 'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    save()
    image_paths = {}
    for index, image in enumerate(images):
        rel = image.relative_to(root)
        target = rel.with_suffix('.PNG')
        png = payload / target
        png.parent.mkdir(parents=True, exist_ok=True)
        ev = evidence / f'image-{index:02d}'
        ev.mkdir()
        command = [str(helper), 'convert', str(image), str(png), str(ev/'source.rgba8'),
                   str(ev/'png.rgba8'), str(ev/'source-properties.plist')]
        run = subprocess.run(command, capture_output=True, text=True)
        (ev / 'helper.stdout').write_text(run.stdout)
        (ev / 'helper.stderr').write_text(run.stderr)
        record = {'source_path': '/' + str(rel), 'target_path': '/' + str(target),
                  'source': original[str(rel)], 'helper_exit': run.returncode,
                  'evidence': str(ev.relative_to(out))}
        manifest['images'].append(record)
        if run.returncode:
            manifest['failure'] = 'ImageIO actual pixel decode/encode/roundtrip failed; no runtime asset set is READY'
            save()
            raise RuntimeError(manifest['failure'] + ': ' + run.stderr.strip())
        stats = json.loads(run.stdout)
        source_rgba, png_rgba = (ev/'source.rgba8').read_bytes(), (ev/'png.rgba8').read_bytes()
        props = plistlib.loads((ev/'source-properties.plist').read_bytes())
        if not stats['whole_rgba8_equal'] or source_rgba != png_rgba or not any(source_rgba) or \
                not stats['alpha_max'] or props.get('Orientation', 1) != 1 or \
                props.get('Depth') != 8 or props.get('ColorModel') != 'RGB' or \
                stats['width'] != props.get('PixelWidth') or stats['height'] != props.get('PixelHeight') or \
                stats['nonopaque_pixels'] != stats['png_nonopaque_pixels']:
            manifest['failure'] = 'Invalid/blank pixels or changed geometry/alpha/metadata'
            save()
            raise RuntimeError(manifest['failure'])
        record.update(stats, source_rgba8_sha256=digest(source_rgba), png_rgba8_sha256=digest(png_rgba),
                      png=file_info(png), source_properties=props,
                      source_properties_sha256=digest((ev/'source-properties.plist').read_bytes()))
        image_paths[rel] = target
        manifest['files'].append({'path': '/' + str(target), 'source_path': '/' + str(rel),
                                  'source_sha256': original[str(rel)]['sha256'],
                                  'operation': 'create_png_or_accept_exact_existing',
                                  **file_info(png), 'mode': original[str(rel)]['mode']})
        save()
    refs_seen = set()
    for scene in scenes:
        rel = scene.relative_to(root)
        before = scene.read_bytes()
        changes = []
        def replace(match):
            old = match.group(2).decode('utf-8')
            decoded = unquote(old)
            old_path = Path(decoded)
            if old_path.is_absolute() or '..' in old_path.parts:
                raise ValueError('Unexpected external CAML image URL')
            old_rel = rel.parent / old_path
            if old_rel not in image_paths:
                raise ValueError('CAML references a non-default or unverified image')
            new_path = image_paths[old_rel].relative_to(rel.parent)
            new = quote(str(new_path), safe='/._-')
            refs_seen.add(old_rel)
            changes.append({'before': old, 'after': new, 'source_path': '/' + str(old_rel),
                            'target_path': '/' + str(image_paths[old_rel])})
            return match.group(1) + new.encode() + match.group(3)
        after = REF.sub(replace, before)
        if not changes:
            raise ValueError('No exact contents/CGImage URL in expected scene')
        reverse = after
        for c in changes:
            reverse = reverse.replace(('src="' + c['after'] + '"').encode(), ('src="' + c['before'] + '"').encode())
        if reverse != before or structure(reverse) != structure(before):
            raise ValueError('Change outside exact CAML contents src URL')
        target = payload / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(after)
        manifest['scenes'].append({'path': '/' + str(rel), 'changes': changes,
                                   'before_sha256': digest(before), 'after_sha256': digest(after),
                                   'original_restored_whole_bytes_equal': True,
                                   'layer_graph_animations_and_names_unchanged': True,
                                   'original_structure_sha256': digest(json.dumps(structure(before), separators=(',', ':')).encode())})
        manifest['files'].append({'path': '/' + str(rel), 'source_path': '/' + str(rel),
                                  'source_sha256': digest(before),
                                  'operation': 'replace_caml_only_if_original_source_hash_matches',
                                  **file_info(target), 'mode': original[str(rel)]['mode']})
    if refs_seen != set(image_paths):
        raise ValueError('Not all five images were referenced exactly')
    after_original = {str(p.relative_to(root)): file_info(p) for p in sorted(source.rglob('*')) if p.is_file()}
    if after_original != original:
        raise ValueError('Source root changed while preparing resources')
    manifest['original_root_files_unchanged'] = True
    # Apple-derived bytes/header stay ONLY under the ignored output directory.
    header = out / 'polaris-wallpaper-assets-embedded.h'
    with header.open('w') as f:
        f.write('/* PRIVATE Apple-derived assets; generated for RAMCOW only. Never commit. */\n'
                '#ifndef POLARIS_WALLPAPER_ASSETS_EMBEDDED_H\n#define POLARIS_WALLPAPER_ASSETS_EMBEDDED_H\n'
                '#include <stdint.h>\n#include <stddef.h>\n'
                'struct polaris_wallpaper_embedded_asset {\n'
                ' const char *path,*source_path; const unsigned char *data; uint64_t bytes;\n'
                ' uint32_t mode,operation; unsigned char sha256[32],source_sha256[32];\n};\n'
                '/* operation1: create PNG, or accept only exact same existing bytes.\n'
                ' * operation2: replace CAML after exact original source hash check.\n'
                ' * Verify ALL current source hashes + immutableRO/RAMCOW before ANY change.\n'
                ' * A source match is not authorization to write physical UFS. */\n')
        for i, item in enumerate(manifest['files']):
            f.write(binary_array(f'polaris_wallpaper_data_{i}', (payload / item['path'].lstrip('/')).read_bytes()))
        f.write('static const struct polaris_wallpaper_embedded_asset polaris_wallpaper_assets[] = {\n')
        for i, item in enumerate(manifest['files']):
            operation = 1 if item['operation'].startswith('create_') else 2
            f.write(' {' + ','.join([json.dumps(item['path']), json.dumps(item['source_path']),
                f'polaris_wallpaper_data_{i}', str(item['bytes']), str(item['mode']), str(operation),
                hash_array(item['sha256']), hash_array(item['source_sha256'])]) + '},\n')
        f.write('};\n#define POLARIS_WALLPAPER_ASSET_COUNT '
                '(sizeof(polaris_wallpaper_assets)/sizeof(polaris_wallpaper_assets[0]))\n#endif\n')
    stub = out / 'embedded-check.c'
    stub.write_text('#include "polaris-wallpaper-assets-embedded.h"\n'
                    'const struct polaris_wallpaper_embedded_asset *polaris_wallpaper_embedded_check(void) '
                    '{return polaris_wallpaper_assets;}\n')
    obj = out / 'embedded-check.o'
    compile_command = ['/usr/bin/clang', '-target', 'arm64-apple-ios16.5', '-isysroot', '/', '-ffreestanding', '-O2',
                       '-Wall', '-Wextra', '-Werror', '-c', str(stub), '-o', str(obj)]
    native = subprocess.run(compile_command, capture_output=True, text=True)
    (out / 'embedded-build.log').write_text(native.stdout + native.stderr)
    if native.returncode:
        raise RuntimeError('Cannot compile embedded header')
    allocated, sections = macho_alloc_bytes(obj.read_bytes())
    total_payload = sum(i['bytes'] for i in manifest['files'])
    # Existing bundle + complete generated resource object + explicit4KiB link
    # allowance. Does not raise the existing32MiB admission cap.
    budget_total = args.graphics_bytes + allocated + 4096
    manifest['budget'] = {'graphics_existing_bytes': args.graphics_bytes, 'cap_bytes': CAP,
                          'raw_png_and_caml_bytes': total_payload, 'arm64_object_file_bytes': obj.stat().st_size,
                          'arm64_allocated_sections_bytes': allocated, 'link_allowance_bytes': 4096,
                          'combined_bound_bytes': budget_total, 'remaining_bound_bytes': CAP-budget_total,
                          'sections': sections, 'within_original_cap': budget_total <= CAP}
    manifest['embedded'] = {'header': header.name, 'header_bytes': header.stat().st_size,
                            'header_sha256': digest(header.read_bytes()), 'object': obj.name,
                            'object_sha256': digest(obj.read_bytes()), 'compile_command': compile_command,
                            'table_symbol': 'polaris_wallpaper_assets', 'format_version': 1,
                            'count': len(manifest['files']),
                            'operation1': 'new PNG; source_path=original HEIC; require whole source SHA256',
                            'operation2': 'existing CAML; source_path=path; require whole original SHA256'}
    manifest['ready'] = budget_total <= CAP
    manifest['runtime_install_implemented'] = False
    manifest['build_script_sha256'] = digest(Path(__file__).read_bytes())
    save()
    print(json.dumps({'ready': manifest['ready'], 'images': len(images), 'scenes': len(scenes),
                      'payload_bytes': total_payload, 'combined_bound_bytes': budget_total,
                      'cap_bytes': CAP, 'physical_wallpaper_fixed': False}))
    return 0 if manifest['ready'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
