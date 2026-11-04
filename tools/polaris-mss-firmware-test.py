#!/usr/bin/env python3
"""Validate own MDT parser refusals without executing or modifying firmware."""
import argparse
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
    print(json.dumps(dict(passed=True,checks=checks,firmware_executed=False)))


if __name__=='__main__':main()
