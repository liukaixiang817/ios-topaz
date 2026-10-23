#!/usr/bin/env python3
"""Build a new local HFSX iOS root from verified, read-only Apple mounts.

Default is a reviewable plan. --execute requires root for numeric ownership.
Only a new image below this repository's ignored research/ is created. There
are no phone commands, partition edits, physical-disk formatting or overwrites.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'research/ipsw-x'


def digest(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def run(args, capture=False):
    print('+', ' '.join(map(str, args)), flush=True)
    p = subprocess.run(list(map(str, args)), check=True,
                       stdout=subprocess.PIPE if capture else None)
    return p.stdout if capture else None


def inside(base, relative):
    """Reject paths that would traverse an absolute iOS symlink on the host."""
    path = base / relative
    if not path.parent.resolve().is_relative_to(base.resolve()):
        raise ValueError('destination parent escapes image: ' + relative)
    return path


def mkdir_owned(base, relative, uid=0, gid=0, mode=0o755):
    path = inside(base, relative)
    if path.is_symlink():
        raise ValueError('refusing directory symlink: ' + relative)
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    return path


def raw_hfs_length(path):
    with path.open('rb') as f:
        f.seek(1024)
        header = f.read(512)
        f.seek(-512, 2)
        footer = f.read(512)
    if header[:4] != b'HX\x00\x05':
        raise ValueError('not a case-sensitive HFSX filesystem at byte zero')
    block, count = struct.unpack_from('>II', header, 40)
    if block < 512 or block & (block - 1) or not count:
        raise ValueError('invalid HFS block geometry')
    length = block * count
    if path.stat().st_size == length:
        return length
    if footer[:4] != b'koly':
        raise ValueError('unrecognized non-filesystem image tail')
    offset, size = struct.unpack_from('>QQ', footer, 24)
    if offset != 0 or size != length or path.stat().st_size < length + 512:
        raise ValueError('UDIF is not a contiguous raw data fork')
    return length


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--execute', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=ROOT / 'research/polaris/ios16-root-20H392-macos-v1.img')
    ap.add_argument('--size-gib', type=int, default=16)
    args = ap.parse_args()
    output = args.output.absolute()
    research = (ROOT / 'research').resolve()
    if not output.parent.resolve().is_relative_to(research) or output.is_symlink():
        ap.error('output must be a new file under repository research/')
    if not 12 <= args.size_gib <= 64:
        ap.error('size must be between 12 and 64 GiB')
    work = output.with_suffix('.build')
    if output.exists() or work.exists() or output.with_suffix('.json').exists():
        ap.error('refusing existing output or build directory; choose a new output name')
    records = json.loads((SOURCES / 'verified-images.json').read_text())
    info = plistlib.loads(run(['hdiutil', 'info', '-plist'], capture=True))
    mounts = {}
    for record in records:
        src = (SOURCES / record['path']).resolve()
        if not src.is_relative_to(SOURCES.resolve()) or src.stat().st_size != record['bytes']:
            raise ValueError('source size/path mismatch')
        images = [i for i in info.get('images', []) if Path(i.get('image-path', '')).resolve() == src]
        if len(images) != 1 or images[0].get('writeable') is not False:
            raise ValueError('source must have exactly one read-only attachment: ' + str(src))
        points = [Path(e['mount-point']) for e in images[0]['system-entities'] if 'mount-point' in e]
        if len(points) != 1 or not points[0].resolve().is_relative_to(SOURCES.resolve()):
            raise ValueError('unexpected source mount')
        mounts[record['component']] = points[0]
        if args.execute:
            print('Verifying SHA384:', src.name, flush=True)
            if digest(src, 'sha384') != record['sha384']:
                raise ValueError('Apple source SHA384 mismatch')
    plan = dict(output=str(output), size_gib=args.size_gib,
                sources={k: str(v) for k, v in mounts.items()},
                copy='rsync -aH --numeric-ids; no xattr/ACL/decmpfs copy',
                changes='merge cryptexes, seed log/keybag paths, apply sweet-root-tweaks.py',
                verification='critical hashes/uid/gid/modes, HFS geometry, fsck_hfs, raw image SHA256',
                phone_access=False)
    print(json.dumps(plan, indent=2), flush=True)
    if not args.execute:
        return
    if sys.platform != 'darwin' or os.geteuid() != 0:
        ap.error('--execute requires macOS root to preserve iOS file ownership')
    work.mkdir(mode=0o750)
    os.chown(work, 0, int(os.environ.get('SUDO_GID', '0')))
    partial = work / 'root.partial.dmg'
    mount = work / 'mount'
    mount.mkdir()
    device = None
    completed = False
    verification = {}
    try:
        run(['hdiutil', 'create', '-size', f'{args.size_gib}g', '-fs',
             'Case-sensitive Journaled HFS+', '-layout', 'NONE', '-volname',
             'iOSRoot', '-nospotlight', '-format', 'UDRW', partial])
        attached = plistlib.loads(run(['hdiutil', 'attach', '-nobrowse', '-noautoopen',
                     '-owners', 'on', '-mountpoint', mount, '-plist', partial], capture=True))
        (work / 'attachment.plist').write_bytes(plistlib.dumps(attached))
        entities = attached['system-entities']
        device = entities[0]['dev-entry']
        actual = [e for e in entities if e.get('mount-point') == str(mount)]
        if len(actual) != 1:
            raise ValueError('new image did not mount at the requested private path')
        # Write only this newly created filesystem. Never copy through /var,
        # /etc, or other absolute iOS symlinks from the host namespace.
        targets = [('OS', ''), ('Cryptex1,SystemOS', 'private/preboot/Cryptexes/OS'),
                   ('Cryptex1,AppOS', 'private/preboot/Cryptexes/App')]
        for key, relative in targets:
            dst = mkdir_owned(mount, relative) if relative else mount
            run(['/usr/bin/rsync', '-aH', '--numeric-ids', str(mounts[key]) + '/', str(dst) + '/'])
        critical = ['sbin/launchd', 'usr/lib/dyld', 'System/Library/CoreServices/SystemVersion.plist']
        for name in critical:
            src, dst = mounts['OS'] / name, inside(mount, name)
            a, b = src.stat(), dst.stat()
            if (a.st_uid, a.st_gid, stat.S_IMODE(a.st_mode)) != (b.st_uid, b.st_gid, stat.S_IMODE(b.st_mode)):
                raise ValueError('ownership/mode mismatch: ' + name)
            sha = digest(src)
            if digest(dst) != sha:
                raise ValueError('content mismatch: ' + name)
            verification[name] = dict(sha256=sha, uid=b.st_uid, gid=b.st_gid, mode=oct(stat.S_IMODE(b.st_mode)))
        # Populate missing root paths with hard links to the copied cryptexes.
        for kind in ['OS', 'App']:
            tree = mount / 'private/preboot/Cryptexes' / kind
            for parent, dirs, files in os.walk(tree, followlinks=False):
                links = [d for d in dirs if (Path(parent) / d).is_symlink()]
                dirs[:] = [d for d in dirs if d not in links]
                for name in files + links:
                    src = Path(parent) / name
                    relative = str(src.relative_to(tree))
                    dst = inside(mount, relative)
                    if os.path.lexists(dst):
                        continue
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if src.is_symlink():
                        os.symlink(os.readlink(src), dst)
                        st = src.lstat()
                        os.lchown(dst, st.st_uid, st.st_gid)
                    else:
                        os.link(src, dst)
        for relative, mode in [('diagnostics', 0o751), ('uuidtext', 0o755), ('diagnostics/timesync', 0o755)]:
            path = mkdir_owned(mount, 'private/var/db/' + relative, 272, 272, mode)
            marker = path / '.migrated'
            if marker.is_symlink(): raise ValueError('unexpected migration symlink')
            marker.touch(); os.chown(marker, 272, 272); os.chmod(marker, 0o644)
        keybags = mkdir_owned(mount, 'private/var/keybags', mode=0o700)
        keybag = keybags / 'systembag.kb'
        if keybag.is_symlink(): raise ValueError('unexpected keybag symlink')
        keybag.write_bytes(plistlib.dumps({'KeyBagKeys': b'SWEET'}, fmt=plistlib.FMT_XML))
        os.chown(keybag, 0, 0); os.chmod(keybag, 0o600)
        mkdir_owned(mount, 'private/var/mobile/Library/Preferences', 501, 501)
        run([sys.executable, ROOT / 'tools/sweet-root-tweaks.py', mount])
        run(['/bin/sync'])
        run(['hdiutil', 'detach', device]); device = None
        length = raw_hfs_length(partial)
        if length != args.size_gib * 1024**3:
            raise ValueError('filesystem capacity differs from requested image size')
        if partial.stat().st_size != length:
            with partial.open('r+b') as f: f.truncate(length)
        run(['/sbin/fsck_hfs', '-fn', partial])
        sha = digest(partial)
        partial.rename(output)
        completed = True
        manifest = dict(plan, complete=True, bytes=length, sha256=sha, critical_files=verification)
        manifest_path = output.with_suffix('.json')
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
        uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
        for path in (output, manifest_path):
            os.chown(path, uid, gid); os.chmod(path, 0o600)
        print('VERIFIED LOCAL ROOT IMAGE:', output, sha, flush=True)
    finally:
        if device:
            # Detach only the device returned for our new image; never force.
            subprocess.run(['hdiutil', 'detach', device], check=False)
        if not completed:
            print('Build incomplete; partial files retained for diagnosis:', work, file=sys.stderr)


if __name__ == '__main__':
    main()
