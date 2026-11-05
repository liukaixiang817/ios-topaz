#!/usr/bin/env python3
"""Frozen input/burn boundary checks; synthetic bytes are not a bootable PE."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('polaris-wifi-nonce-candidate.py'))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
sha = lambda data: hashlib.sha256(data).hexdigest()
checks = 0


def refuses(call):
    global checks
    try:
        call()
    except (ValueError, OSError):
        checks += 1
    else:
        raise AssertionError('expected refusal')


with tempfile.TemporaryDirectory(prefix='polaris-nonce-candidate-') as temporary:
    root = Path(temporary)
    candidate.pool.LEDGER = root / 'ledger'
    candidate.pool.create(root / 'wifi-nonce')
    header, metadata = candidate.pool.binding(root / 'wifi-nonce')
    data = (root / 'wifi-nonce/nonce-pool.bin').read_bytes()
    image = b'SOFTWARE ONLY: synthetic linked input\0' + data + bytes.fromhex(metadata['sha256'])
    artifact = root / 'test.efi'
    artifact.write_bytes(image)
    (root / 'uefi-wifi-image-nonce-pool.h').write_text(header)
    manifest = dict(artifact=artifact.name, bytes=len(image), sha256=sha(image),
                    wifi_host_nonce_pool=metadata, wifi_host_nonce_header_sha256=sha(header.encode()))
    path = root / 'manifest.json'
    raw = json.dumps(manifest).encode()
    path.write_bytes(raw)
    frozen = sha(raw)
    result = candidate.verify(path, frozen)
    assert result['sha256'] == metadata['sha256']
    checks += 1
    refuses(lambda: candidate.consume(path, '0' * 64))
    artifact.write_bytes(image[:-1])
    refuses(lambda: candidate.consume(path, frozen))
    artifact.write_bytes(image)
    (root / 'uefi-wifi-image-nonce-pool.h').write_text(header + 'altered')
    refuses(lambda: candidate.consume(path, frozen))
    (root / 'uefi-wifi-image-nonce-pool.h').write_text(header)
    manifest['artifact'] = '../test.efi'
    path.write_text(json.dumps(manifest))
    refuses(lambda: candidate.consume(path, sha(path.read_bytes())))
    path.write_bytes(raw)
    artifact.rename(root / 'real.efi')
    artifact.symlink_to(root / 'real.efi')
    refuses(lambda: candidate.consume(path, frozen))
    artifact.unlink()
    (root / 'real.efi').rename(artifact)
    assert not candidate.pool.LEDGER.exists()
    checks += 1
    burned = candidate.consume(path, frozen)
    assert burned['consumed'] and not burned['boot_admission'] and not burned['device_command_executed']
    checks += 1
    refuses(lambda: candidate.consume(path, frozen))
print(json.dumps(dict(checks=checks, scope='SOFTWARE frozen driver/nonce binding and burn; no boot command')))
