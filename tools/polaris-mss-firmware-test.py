#!/usr/bin/env python3
"""Validate own MDT parser refusals without executing or modifying firmware."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mdt',type=Path);a=p.parse_args()
    spec=importlib.util.spec_from_file_location('firmware',Path(__file__).with_name('polaris-mss-firmware.py'))
    f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
    raw=a.mdt.read_bytes();layout=f.parse_mdt(raw);assert len(layout['segments'])==28
    assert sum(s['filesz']==0 for s in layout['segments'])==3
    changes=[(0,'I',0),(16,'H',3),(18,'H',183),(20,'I',0),(24,'I',0),(28,'I',0),(40,'H',0),(42,'H',0),(44,'H',29)]
    for n in range(2,30):
        at=52+32*n
        changes += [(at+24,'I',0x6),(at+16,'I',0xffffffff),(at+20,'I',0),(at+28,'I',3)]
    changes += [(52+3*32+12,'I',0x8e400000),(52+29*32+20,'I',0xffffffff)]
    checks=2
    for at,kind,value in changes:
        changed=bytearray(raw);struct.pack_into('<'+kind,changed,at,value)
        try:f.parse_mdt(changed)
        except ValueError:checks+=1
        else:raise AssertionError((at,kind,value))
    for changed in (b'',raw[:-1],raw+b'\0'):
        try:f.parse_mdt(changed)
        except ValueError:checks+=1
        else:raise AssertionError('length')
    # The tail is outside the ADT and must have an exact extent and identity.
    bundle=bytes(range(256))*16;payload=bytearray(4096)+bundle
    payload[:8]=b'SWEETXNU';struct.pack_into('<I',payload,8,1)
    struct.pack_into('<QQ',payload,32,0x2a8,8)
    manifest=dict(bytes=len(bundle),sha256=hashlib.sha256(bundle).hexdigest())
    transport=f.payload_transport(payload,manifest)
    assert transport['offset']==4096 and transport['payload_bytes']==8192;checks+=1
    mutations=[(0,'Q',0),(8,'I',2),(32,'Q',0),(32,'Q',1<<63),
               (40,'Q',7),(40,'Q',0x100001),(4095,'B',1),(8191,'B',0)]
    for at,kind,value in mutations:
        changed=bytearray(payload);struct.pack_into('<'+kind,changed,at,value)
        try:f.payload_transport(changed,manifest)
        except ValueError:checks+=1
        else:raise AssertionError(('payload',at))
    for changed in (b'',payload[:-1],payload+b'\0'):
        try:f.payload_transport(changed,manifest)
        except ValueError:checks+=1
        else:raise AssertionError('payload length')
    print(json.dumps(dict(passed=True,checks=checks,firmware_executed=False)))


if __name__=='__main__':main()
