#!/usr/bin/env python3
"""One targeted read-only capture from the Polaris UEFI RAM diagnostic service.

Does not start a continuous USB observer or send boot/flash/download commands.
Only accesses the synthetic polaris-uefi endpoint after checking its product.
The map is the admission snapshot taken before USB buffer allocations.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import time


def map_summary(data):
    if len(data)<32 or data[:8]!=b'PEFIMAP1':raise ValueError('not a Polaris EFI map')
    size,stride,version=struct.unpack_from('<QQQ',data,8)
    if (not size or size>65536 or stride<40 or stride>4096 or stride%8 or
        size%stride or size//stride>4096 or len(data)!=32+size or version!=1):
        raise ValueError('invalid EFI map bounds/version')
    entries=[];free=live=mapped=0
    for at in range(32,len(data),stride):
        kind,pad,base,virtual,pages,attrs=struct.unpack_from('<IIQQQQ',data,at)
        if base%4096 or not pages or pages>((1<<64)-1-base)//4096:raise ValueError('invalid EFI range')
        end=base+pages*4096
        if any(base<e['end'] and e['base']<end for e in entries):raise ValueError('overlapping EFI ranges')
        entries.append(dict(type=kind,base=base,end=end,pages=pages,attributes=attrs))
        n=max(0,min(end,0x27c8a0000)-max(base,0x180000000))//4096;mapped+=n
        runtime=bool(attrs&(1<<63))
        if kind==7 and not runtime:free+=n
        if runtime or (kind not in [1,2,3,4,7]):live+=n
    return dict(snapshot='admission before USB initialization; requery before kernel handoff',
                descriptors=len(entries),upper_free_pages=free,upper_retained_pages=live,
                upper_unmapped_pages=0xfc8a0-mapped,ranges=entries)


def ppm_info(data):
    match=re.match(rb'P6\n([1-9][0-9]{0,3}) ([1-9][0-9]{0,3})\n255\n',data)
    if not match:raise ValueError('invalid PPM header')
    w,h=map(int,match.groups())
    if w>4096 or h>4096 or len(data)>16*1024*1024 or len(data)!=match.end()+w*h*3:
        raise ValueError('invalid PPM dimensions/data length')
    return w,h,match.end()


def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def diagnostic_product(text):
    values=re.findall(r'(?m)^(?:\(bootloader\)\s*)?product:\s*(\S+)[ \t]*\r?$',text)
    return values==['polaris-uefi-diag']


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fastboot',required=True,type=Path)
    ap.add_argument('--boot-record',required=True,type=Path)
    ap.add_argument('--image-manifest',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--wait-seconds',type=int,default=60)
    ap.add_argument('--libusb',type=Path,help='Use direct libusb transport instead of fastboot discovery')
    a=ap.parse_args()
    if not 0<=a.wait_seconds<=600:ap.error('wait must be between zero and 600 seconds')
    native=None
    try:
        if a.libusb:
            from polaris_uefi_usb_transport import LibusbTransport
            native=LibusbTransport(a.libusb)
        return capture(a,native)
    finally:
        if native:native.close()


def capture(a,native=None):
    boot=json.loads(a.boot_record.read_text());image=json.loads(a.image_manifest.read_text())
    if (boot.get('state')!='temporary_UEFI_probe_boot_command_succeeded' or
        boot.get('image_sha256')!=image.get('sha256') or not image.get('RAM_only_USB_diagnostics')):
        raise ValueError('capture is not bound to a sent USB diagnostic RAM image')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    base=[str(a.fastboot.resolve()),'-s','polaris-uefi']
    record=dict(started_utc=now(),sent_utc=boot['sent_utc'],image_sha256=image['sha256'],
                targeted_capture=True,continuous_observer=False,phone_write_commands=False,
                commands=[],captures={},errors=[])
    record['transport']='libusb' if native else 'stock fastboot'
    record['host_reader_sha256']=digest(Path(__file__))
    if native:
        from polaris_uefi_usb_transport import ReadOnlyProtocol
        protocol=ReadOnlyProtocol(native)
        record['libusb_library_sha256']=digest(native.library)
        record['host_transport_sha256']=digest(Path(__file__).with_name('polaris_uefi_usb_transport.py'))
    def save():
        (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    def command(args):
        if native:
            try:
                if args==['getvar','product']:message='product: '+protocol.product()+'\n'
                elif len(args)==2 and args[0]=='oem' and args[1] in protocol.limits:
                    protocol.stage(args[1]);message='OKAY\n'
                elif len(args)==2 and args[0]=='get_staged':
                    data=protocol.upload();Path(args[1]).write_bytes(data);message=f'Uploaded {len(data)} bytes\n'
                else:raise ValueError('command outside read-only host capture')
            except Exception as error:
                record['commands'].append(dict(args=args,exit=1,output=str(error)));save();raise
            record['commands'].append(dict(args=args,exit=0,output=message));save();return message
        run=subprocess.run(base+args,capture_output=True,timeout=45)
        message=(run.stdout+run.stderr).decode(errors='replace')
        record['commands'].append(dict(args=args,exit=run.returncode,output=message[-2048:]))
        save()
        if run.returncode:raise RuntimeError('diagnostic command failed: '+' '.join(args))
        return message
    save();began=time.monotonic();present=False
    while True:
        try:
            if native:present=native.open_target()
            else:
                run=subprocess.run([str(a.fastboot.resolve()),'devices'],capture_output=True,timeout=8)
                present=run.returncode==0 and sum(line.split()[:1]==[b'polaris-uefi'] for line in run.stdout.splitlines())==1
        except Exception as error:
            record['errors'].append('target admission: '+str(error));save();print(str(error));return 1
        if present or time.monotonic()-began>=a.wait_seconds:break
        time.sleep(1)
    record.update(target_discovered=present,discovery_seconds=time.monotonic()-began);save()
    if not present:
        record['errors'].append('diagnostic endpoint not found during targeted wait');save()
        print('Targeted diagnostic endpoint not found; no commands sent.');return 1
    try:
        product=command(['getvar','product'])
        if not diagnostic_product(product):raise ValueError('wrong product; no OEM commands sent')
    except Exception as e:
        record['errors'].append(str(e));save();print(str(e));return 1
    for kind,name in [('logs','uefi.log'),('memmap','memory-map.bin'),('screenshot','screen.ppm')]:
        try:
            target=out/name;command(['oem',kind]);command(['get_staged',str(target)]);target.chmod(0o600)
            info=dict(bytes=target.stat().st_size,sha256=digest(target))
            if kind=='memmap':
                summary=map_summary(target.read_bytes());(out/'memory-map.json').write_text(json.dumps(summary,indent=2)+'\n')
                info['summary_file']='memory-map.json'
            if kind=='screenshot':
                raw=target.read_bytes();w,h,offset=ppm_info(raw);info.update(width=w,height=h)
                try:
                    from PIL import Image
                    picture=Image.frombytes('RGB',(w,h),raw[offset:]);picture.save(out/'screen.png')
                    with Image.open(out/'screen.png') as check:
                        if check.convert('RGB').tobytes()!=raw[offset:]:raise ValueError('PNG pixels differ from capture')
                    (out/'screen.png').chmod(0o600);info['PNG']='screen.png'
                except ImportError:info['PNG']='Pillow unavailable; original PPM preserved'
            record['captures'][kind]=info;print('Captured '+kind,flush=True)
        except Exception as e:record['errors'].append(kind+': '+str(e))
        save()
    record.update(completed_utc=now(),passed=len(record['captures'])==3 and not record['errors']);save()
    print('Read-only diagnostic capture '+('passed' if record['passed'] else 'incomplete'))
    return 0 if record['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
