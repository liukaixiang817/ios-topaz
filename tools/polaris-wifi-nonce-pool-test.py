#!/usr/bin/env python3
"""Host freshness/one-use checks, with a private temporary consumption ledger."""
from pathlib import Path
import concurrent.futures
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location('nonce_pool', Path(__file__).with_name('polaris-wifi-nonce-pool.py'))
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)
checks = 0


def check(value):
    global checks
    assert value
    checks += 1


def refuses(call):
    try:
        call()
    except (OSError, ValueError):
        check(True)
    else:
        raise AssertionError('expected refusal')


with tempfile.TemporaryDirectory(prefix='polaris-nonce-') as temporary:
    root = Path(temporary)
    pool.LEDGER = root / 'ledger'
    first = pool.create(root / 'first')
    second = pool.create(root / 'second')
    header, metadata = pool.binding(root / 'first')
    check(metadata['sha256'] == first['sha256'] and '_Alignas(64)' in header and 'polaris_wifi_image_nonces[2128]' in header)
    data = (root / 'first/nonce-pool.bin').read_bytes()
    check(first['sha256'] != second['sha256'] and len(data) == pool.SIZE)
    check((root / 'first/nonce-pool.bin').stat().st_mode & 0o777 == 0o600)
    refuses(lambda: pool.create(root / 'first'))
    refuses(lambda: pool.consume(root / 'first', '0' * 64))
    check(not (root / 'first/nonce-pool.used').exists())
    shutil.copytree(root / 'first', root / 'copy')

    def consume_once(name):
        script = """import importlib.util,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('pool',sys.argv[1]);p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
p.LEDGER=Path(sys.argv[4])
try:p.consume(Path(sys.argv[2]),sys.argv[3])
except FileExistsError:sys.exit(2)
"""
        result = subprocess.run([sys.executable, '-c', script, str(Path(pool.__file__).resolve()), str(root / name), first['sha256'], str(pool.LEDGER)], capture_output=True, text=True)
        assert result.returncode in (0, 2), result.stderr
        return result.returncode == 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(consume_once, ['first', 'copy']))
    check(sum(outcomes) == 1)
    refuses(lambda: pool.consume(root / 'first', first['sha256']))
    refuses(lambda: pool.consume(root / 'copy', first['sha256']))
    check(len(list(pool.LEDGER.glob('*.used'))) == 1)
    refuses(lambda: pool.binding(root / 'copy'))
    check(pool.consume(root / 'second', second['sha256']) == (root / 'second/nonce-pool.bin').read_bytes())
    check(len(list(pool.LEDGER.glob('*.used'))) == 2)
    for at in [0, 8, 12, 16, 20, 40, 72, 80, len(data) - 1]:
        bad = bytearray(data)
        bad[at] ^= 1
        refuses(lambda: pool.validate(bytes(bad)))
    for duplicate in [False, True]:
        bad = bytearray(data)
        bad[80:112] = data[112:144] if duplicate else bytes(32)
        bad[40:72] = hashlib.sha256(bad[80:]).digest()
        refuses(lambda: pool.validate(bytes(bad)))
    (root / 'symlink').symlink_to(root / 'first', target_is_directory=True)
    refuses(lambda: pool.consume(root / 'symlink', first['sha256']))
print(json.dumps(dict(checks=checks, scope='SOFTWARE host CSPRNG pool format and digest-wide atomic one-use; no phone boot')))
