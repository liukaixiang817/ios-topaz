#!/usr/bin/env python3
"""Build a RAM-only resident EFI/XNU driver, never install or boot it.

QEMU mode is explicitly separate: virt has different RAM/CPU affinities and
cannot validate the Qualcomm peripheral implementation or physical DDR map.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zlib


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def symbols(raw):
    if len(raw)<32 or raw[:4]!=b'\xcf\xfa\xed\xfe':raise ValueError('requires kernel Mach-O')
    count,commands=struct.unpack_from('<II',raw,16)
    if count>4096 or commands>len(raw)-32:raise ValueError('invalid Mach-O commands')
    at=32;wanted={}
    for _ in range(count):
        kind,size=struct.unpack_from('<II',raw,at)
        if size<8 or size>32+commands-at:raise ValueError('invalid Mach-O command size')
        if kind==2:
            off,n,strings,bytes_=struct.unpack_from('<4I',raw,at+8)
            if n>(len(raw)-off)//16 or strings>len(raw) or bytes_>len(raw)-strings:raise ValueError('invalid symbol table')
            for i in range(n):
                name,typ,section,desc,value=struct.unpack_from('<IBBHQ',raw,off+16*i)
                if name>=bytes_ or typ&0xe0:continue
                end=raw.find(b'\0',strings+name,strings+bytes_)
                if end<0:raise ValueError('unterminated kernel symbol')
                text=raw[strings+name:end]
                if text in (b'_sweet_log_ring',b'_sweet_log_total',b'_polaris_uefi_input'):
                    if text.decode() in wanted:raise ValueError('duplicate log symbol')
                    wanted[text.decode()]=value
        at+=size
    if not {'_sweet_log_ring','_sweet_log_total'}<=set(wanted):raise ValueError('kernel RAM console symbols absent')
    return wanted


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--zig',required=True,type=Path)
    ap.add_argument('--kernel',required=True,type=Path)
    ap.add_argument('--payload',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--test-qemu',action='store_true')
    a=ap.parse_args();r=Path(__file__).resolve().parents[1]
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    raw=a.payload.read_bytes();k=a.kernel.read_bytes()
    sys.path.insert(0,str(r/'tools'));import mkpayload
    kernel=bytearray(k);m=mkpayload.parse_macho(kernel);mkpayload.apply_chained_fixups(kernel,m)
    va=struct.unpack_from('<Q',raw,16)[0]
    if va!=m['segs'][0]['vmaddr']&~0x1ffffff:raise ValueError('payload virtual base mismatch')
    n=struct.unpack_from('<I',raw,12)[0]
    if n>64 or len(raw)<0x2a8+32*n:raise ValueError('invalid payload segment table')
    segs=[struct.unpack_from('<4Q',raw,0x2a8+32*i) for i in range(n)]
    for s in m['segs']:
        if not s['vmsize']:continue
        matches=[row for row in segs if row[:2]==(s['vmaddr'],s['vmsize'])]
        if len(matches)!=1:raise ValueError('payload kernel segment mismatch')
        _,_,off,size=matches[0]
        if off>len(raw) or size>len(raw)-off or size!=s['filesize'] or raw[off:off+size]!=kernel[s['fileoff']:s['fileoff']+size]:
            raise ValueError('payload does not contain this rebased kernel')
    syms=symbols(k);log=syms['_sweet_log_ring']-va;total=syms['_sweet_log_total']-va
    end=struct.unpack_from('<Q',raw,48)[0]-va
    if not 0<=log<=end-(4<<20) or not 0<=total<=end-8:raise ValueError('log symbols outside kernel ownership')
    input_offset=syms.get('_polaris_uefi_input',va)-va;input_present='_polaris_uefi_input' in syms
    if input_present and (input_offset%128 or not 0<=input_offset<=end-256):raise ValueError('invalid input mailbox address')
    if not a.test_qemu and not input_present:raise ValueError('physical trial requires the bounded input kernel')
    # Run the exact C copy-plan admission function before emitting an EFI image.
    lib=out/'payload-validator.dylib';flags=['-DPOLARIS_EFI_TEST_QEMU=1'] if a.test_qemu else []
    subprocess.run(['/usr/bin/clang','-shared','-fPIC',*flags,str(r/'shim/polaris/payload.c'),'-o',str(lib)],check=True)
    class Plan(ctypes.Structure):_fields_=[(x,ctypes.c_uint64) for x in ['adt','args','top','entry']]
    fn=ctypes.CDLL(str(lib)).polaris_payload_check
    fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint64,ctypes.POINTER(Plan)];fn.restype=ctypes.c_char_p
    buf=ctypes.create_string_buffer(raw);plan=Plan();error=fn(buf,len(raw),0x100000000,ctypes.byref(plan))
    if error:raise ValueError(error.decode())
    config=out/'uefi-xnu-config.h'
    config.write_text(f'''#define EFI_XNU_PAYLOAD_BYTES {len(raw)}u
#define EFI_XNU_PAYLOAD_CRC32 0x{zlib.crc32(raw):08x}u
#define EFI_XNU_LOG_OFFSET 0x{log:x}ULL
#define EFI_XNU_LOG_TOTAL_OFFSET 0x{total:x}ULL
#define EFI_XNU_LOG_SIZE (4u*1024u*1024u)
#define EFI_XNU_INPUT_AVAILABLE {int(input_present)}
#define EFI_XNU_INPUT_OFFSET 0x{input_offset:x}ULL
#define EFI_XNU_CPU {1 if a.test_qemu else 256}u
#define EFI_XNU_BOOT_CPU_TOKEN "polarisbootcpu={1 if a.test_qemu else 256}"
''')
    sources=['uefi-xnu.c','uefi-xnu-ap.S','uefi-xnu-crc.c','payload.c','uefi-usb.c','uefi-usb-command.c','uefi-usb-control.c']
    inputs=['shim/polaris/'+n for n in sources]+['shim/polaris/uefi.h','shim/polaris/uefi-xnu.h','shim/polaris/uefi-usb.h','shim/polaris/uefi-memory.h','shim/polaris/uefi-reset.h','shim/polaris/payload.h','tools/build-polaris-uefi-xnu.py','tools/polaris-uefi-input.h']
    objects=[]
    for source in sources:
        obj=out/(Path(source).stem+'.obj');objects.append(str(obj))
        cmd=['/usr/bin/clang','--target=aarch64-unknown-windows','-ffreestanding','-fno-builtin','-fno-stack-protector','-fshort-wchar','-mgeneral-regs-only','-O2','-Wall','-Wextra','-Werror',*flags,'-I'+str(out),'-c',str(r/'shim/polaris'/source),'-o',str(obj)]
        p=subprocess.run(cmd,capture_output=True);(out/(source+'.log')).write_bytes(p.stdout+p.stderr)
        if p.returncode:raise RuntimeError('EFI module compile failed: '+source)
    image=out/('PolarisXnuTest.efi' if a.test_qemu else 'PolarisXnuDxe.efi')
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    p=subprocess.run([str(a.zig.resolve()),'build-exe',*objects,'-target','aarch64-uefi','--subsystem','efi_application' if a.test_qemu else 'efi_boot_service_driver','-O','ReleaseSmall','-femit-bin='+str(image)],env=env,capture_output=True)
    (out/'link.log').write_bytes(p.stdout+p.stderr)
    if p.returncode:raise RuntimeError('EFI link failed')
    manifest=dict(artifact=image.name,sha256=sha(image),bytes=image.stat().st_size,
                  kernel_sha256=sha(a.kernel),payload_sha256=sha(a.payload),payload_bytes=len(raw),
                  payload_crc32=zlib.crc32(raw),payload_C_admission=True,rebased_kernel_bytes_match=True,
                  RAM_only_XNU_loader=True,kernel_handoff=True,storage_write_api=False,NVRAM_write_api=False,
                  reset_commands=True,reset_commands_hardware_tested=False,ready_to_boot_driver=not a.test_qemu,
                  bounded_input=input_present,input_offset=input_offset,
                  QEMU_variant=a.test_qemu,phone_compatible=not a.test_qemu,
                  kernel_CPU_affinity=1 if a.test_qemu else 256,
                  RAM_base=0x130000000 if a.test_qemu else 0x180000000,RAM_bytes=0xfc8a0000,
                  firmware_core_reserved=0,firmware_services_exited=False,
                  device_execution_tested=False,inputs={p:sha(r/p) for p in inputs})
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ['artifact','sha256','bytes','QEMU_variant','device_execution_tested']}))


if __name__=='__main__':main()
