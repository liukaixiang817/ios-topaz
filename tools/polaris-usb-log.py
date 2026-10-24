#!/usr/bin/env python3
"""Receive Polaris RAM console over USB ECM on macOS.

Run after a polarisusb=2 temporary boot. --configure adds only the private
192.168.7.1/24 alias to the ECM NIC, identified by its descriptor's fixed
host MAC; it never changes the default route or another interface. Requires
root for that alias. The alias is removed on exit unless --keep-address.
No shell/remote command service is exposed. Raw logs remain local mode0600.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

HOST_MAC = '02:00:5e:77:ee:01'  # ECM descriptor, not factory Wi-Fi identity.
HOST_IP, PHONE_IP, PORT = '192.168.7.1', '192.168.7.2', 5140


def interfaces(text):
    found = {}
    name = None
    for line in text.splitlines():
        match = re.match(r'^([A-Za-z0-9]+): ', line)
        if match:
            name = match[1]
            found[name] = {'mac': None, 'ipv4': []}
        if name is None:
            continue
        match = re.match(r'\s+ether ([0-9a-fA-F:]{17})\b', line)
        if match:
            found[name]['mac'] = match[1].lower()
        match = re.match(r'\s+inet ([0-9.]+)\b', line)
        if match:
            found[name]['ipv4'].append(match[1])
    return found


def inspect():
    return interfaces(subprocess.check_output(['/sbin/ifconfig', '-a'], text=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new private raw log file')
    parser.add_argument('--interface', help='optional NIC name; descriptor MAC must still match')
    parser.add_argument('--configure', action='store_true')
    parser.add_argument('--keep-address', action='store_true')
    parser.add_argument('--wait', type=float, default=30, help='seconds to wait for ECM NIC')
    parser.add_argument('--seconds', type=float, default=600, help='bounded capture duration')
    parser.add_argument('--plan', action='store_true', help='read-only interface/command plan')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('this host helper is for macOS')
    if not 0 <= args.wait <= 600 or not 1 <= args.seconds <= 86400:
        parser.error('wait must be0..600 and capture1..86400 seconds')
    output = args.output.absolute()
    status_path = output.with_suffix(output.suffix + '.json')
    if output.exists() or status_path.exists():
        parser.error('refusing existing log or status; choose a new filename')
    start = time.monotonic()
    while True:
        all_nics = inspect()
        matching = [n for n, d in all_nics.items() if d['mac'] == HOST_MAC]
        if args.interface:
            matching = [n for n in matching if n == args.interface]
        if len(matching) == 1:
            nic = matching[0]
            break
        if len(matching) > 1:
            raise RuntimeError('multiple ECM interfaces; specify --interface')
        if args.plan or time.monotonic() - start >= args.wait:
            print(json.dumps({'state': 'ECM interface absent', 'network_changed': False}))
            return 2
        time.sleep(0.5)
    if any(ip.startswith('192.168.7.') for n, d in all_nics.items()
           if n != nic for ip in d['ipv4']):
        raise RuntimeError('private debug subnet already belongs to another interface')
    configure = ['/sbin/ifconfig', nic, 'inet', HOST_IP, 'netmask', '255.255.255.0', 'alias']
    remove = ['/sbin/ifconfig', nic, 'inet', HOST_IP, '-alias']
    has_address = HOST_IP in all_nics[nic]['ipv4']
    plan = {'interface': nic, 'already_configured': has_address,
            'add_only_if_needed': configure, 'remove_added_alias': remove,
            'receiver': HOST_IP + ':' + str(PORT), 'accepted_peer': PHONE_IP,
            'raw_log': str(output), 'default_route_change': False}
    if args.plan:
        print(json.dumps(plan, indent=2))
        return 0
    if not has_address and not args.configure:
        raise RuntimeError('ECM needs its private alias; use --configure or configure it manually')
    if not has_address and os.geteuid() != 0:
        raise RuntimeError('--configure requires root to add the ECM-only address')
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    added = False
    state = dict(plan, state='starting', packets=0, bytes=0, rejected_packets=0,
                 udp_loss_measured=False, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())

    def save():
        # Never print raw console bytes; they may contain private device data.
        status_path.write_text(json.dumps(state, indent=2) + '\n')
        status_path.chmod(0o600)

    try:
        if not has_address:
            subprocess.run(configure, check=True, capture_output=True)
            added = True
        with os.fdopen(fd, 'wb', buffering=0) as stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((HOST_IP, PORT))
            sock.settimeout(1)
            state['state'] = 'listening'
            save()
            print('Listening on ' + nic + '; raw console saved privately', flush=True)
            end, update = time.monotonic() + args.seconds, time.monotonic() + 10
            while time.monotonic() < end:
                try:
                    packet, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                if peer[0] != PHONE_IP:
                    state['rejected_packets'] += 1
                    continue
                stream.write(packet)
                state['packets'] += 1
                state['bytes'] += len(packet)
                state['last_packet_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                if time.monotonic() >= update:
                    save()
                    print('USB console: ' + str(state['packets']) + ' packets, ' + str(state['bytes']) + ' bytes', flush=True)
                    update = time.monotonic() + 10
            state['state'] = 'capture_complete'
    except KeyboardInterrupt:
        state['state'] = 'capture_interrupted'
    except Exception as error:
        state.update(state='stopped', error_type=type(error).__name__)
        raise
    finally:
        if added and not args.keep_address:
            cleanup = subprocess.run(remove, capture_output=True)
            state['added_alias_removed'] = cleanup.returncode == 0
        state['address_added_by_this_run'] = added
        save()
    print(json.dumps({'state': state['state'], 'packets': state['packets'], 'bytes': state['bytes']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
