#!/usr/bin/env python3
"""Read RAM logs or a stable BGRA panel snapshot over Polaris USB ECM.

Requires admitted USB ECM plus polarisdebug=1. This is not a remote shell.
--plan only inspects the matching ECM NIC. --configure temporarily adds its
private host address, as polaris-usb-log.py does. Output is new and mode0600.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import time
import zlib

REQUEST = struct.Struct('<4sHHQII')
REPLY = struct.Struct('<4sHHQIIIIHHI')
CHUNK, FRAME_BYTES = 1400, 4320 * 2160
HOST, PHONE, PORT = '192.168.7.1', '192.168.7.2', 5141


def decode(packet, token):
    if len(packet) < REPLY.size:
        raise ValueError('truncated debug reply')
    magic, version, status, session, kind, offset, total, size, width, height, crc = REPLY.unpack_from(packet)
    if magic != b'PDBR' or version != 1 or session != token or status > 4:
        raise ValueError('foreign debug reply')
    payload = packet[REPLY.size:]
    if status:
        if any((kind, offset, total, size, width, height, crc)) or payload:
            raise ValueError('invalid error reply')
        raise RuntimeError('device debug status ' + str(status))
    if (kind == 1 and total <= 4 * 1024 * 1024 and not width and not height):
        pass
    elif kind == 2 and total == FRAME_BYTES and (width, height) == (1080, 2160):
        pass
    else:
        raise ValueError('unsupported snapshot bounds/geometry')
    if size > CHUNK or size != len(payload) or offset > total or size > total - offset:
        raise ValueError('invalid snapshot chunk bounds')
    if zlib.crc32(payload) != crc:
        raise ValueError('snapshot CRC mismatch')
    return (kind, total, width, height), offset, payload


def fetch(sock, kind, timeout=0.5, retries=6, token=None):
    token = token or secrets.randbits(64) or 1
    metadata = None
    for _ in range(retries):
        sock.send(REQUEST.pack(b'PDBG', 1, kind, token, 0, 0))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            sock.settimeout(max(0.001, end - time.monotonic()))
            try:
                packet = sock.recv(2048)
            except socket.timeout:
                break
            try:
                row, offset, data = decode(packet, token)
            except ValueError:
                continue
            if row[0] == kind and not offset and not data:
                metadata = row
                break
        if metadata:
            break
    if metadata is None:
        raise TimeoutError('no USB snapshot response')
    out = bytearray(metadata[1])
    for base in range(0, len(out), 16 * CHUNK):
        pending = {offset: min(CHUNK, len(out) - offset)
                   for offset in range(base, min(base + 16 * CHUNK, len(out)), CHUNK)}
        for _ in range(retries):
            for offset, size in pending.items():
                sock.send(REQUEST.pack(b'PDBG', 1, 3, token, offset, size))
            end = time.monotonic() + timeout
            while pending and time.monotonic() < end:
                sock.settimeout(max(0.001, end - time.monotonic()))
                try:
                    packet = sock.recv(2048)
                except socket.timeout:
                    break
                try:
                    row, offset, data = decode(packet, token)
                except ValueError:
                    continue
                if row != metadata or offset not in pending or len(data) != pending[offset]:
                    continue
                out[offset:offset + len(data)] = data
                del pending[offset]
            if not pending:
                break
        if pending:
            raise TimeoutError('USB snapshot chunk retries exhausted')
    return bytes(out), metadata


def panel_png(raw, width=1080, height=2160):
    if (width, height) != (1080, 2160) or len(raw) != FRAME_BYTES:
        raise ValueError('unsupported panel snapshot')
    rows = []
    for y in range(height):
        line = raw[y * width * 4:(y + 1) * width * 4]
        rgb = bytearray(width * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        rows.append(b'\0' + rgb)
    def chunk(name, body):
        return struct.pack('>I', len(body)) + name + body + struct.pack('>I', zlib.crc32(name + body))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(b''.join(rows), 6)) + chunk(b'IEND', b''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('log', 'screenshot'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--configure', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('this interface setup helper is for macOS')
    if args.output.exists() or args.output.is_symlink():
        parser.error('refusing existing output')
    spec = importlib.util.spec_from_file_location('usb_log', Path(__file__).with_name('polaris-usb-log.py'))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    nics = helper.inspect()
    matches = [n for n, d in nics.items() if d['mac'] == helper.HOST_MAC]
    if len(matches) != 1:
        print('USB ECM interface absent' if not matches else 'USB ECM interface ambiguous')
        return 2
    nic = matches[0]
    if any(ip.startswith('192.168.7.') for n, d in nics.items() if n != nic for ip in d['ipv4']):
        raise RuntimeError('debug subnet belongs to another interface')
    has_address = HOST in nics[nic]['ipv4']
    if args.plan:
        print('USB ECM ' + nic + '; host address ' + ('present' if has_address else 'needed') +
              '; snapshot service still needs a successful request')
        return 0
    if not has_address and (not args.configure or os.geteuid() != 0):
        raise RuntimeError('use --configure with root to add only the private ECM alias')
    added = False
    try:
        if not has_address:
            subprocess.run(['/sbin/ifconfig', nic, 'inet', HOST, 'netmask', '255.255.255.0', 'alias'],
                           check=True, capture_output=True)
            added = True
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((HOST, 0))
            sock.connect((PHONE, PORT))
            raw, metadata = fetch(sock, 1 if args.operation == 'log' else 2)
        output = panel_png(raw, *metadata[2:]) if args.operation == 'screenshot' else raw
        fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(output)
        print('Saved ' + args.operation + ' (' + str(len(output)) + ' bytes) to ' + str(args.output))
    finally:
        if added:
            cleanup = subprocess.run(['/sbin/ifconfig', nic, 'inet', HOST, '-alias'], capture_output=True)
            if cleanup.returncode:
                raise RuntimeError('snapshot finished but removal of the added ECM alias failed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
