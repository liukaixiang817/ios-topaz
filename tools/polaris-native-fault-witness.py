"""Bind a read-only remnant probe to one already-spent native diagnostic."""
import hashlib
import json
from pathlib import Path
import struct


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root, descriptor, output):
    root = root.resolve();descriptor = descriptor.resolve()
    if not descriptor.is_relative_to(root/'research') or descriptor.stat().st_size>65536:
        raise ValueError('private bounded witness descriptor required')
    d = json.loads(descriptor.read_text())
    if (d.get('scope')!='one_spent_native_fault_record_readonly' or
        d.get('maximum_record_read_bytes')!=272 or d.get('record_bytes')!=272 or
        d.get('arbitrary_memory_read_API') is not False or d.get('old_RAM_write_API') is not False):
        raise ValueError('not the fixed fault-record observation scope')
    bound = {str(descriptor.relative_to(root)): sha(descriptor)}
    for name, digest in d['inputs'].items():
        p = (root/name).resolve()
        if not p.is_relative_to(root) or not p.is_file() or sha(p)!=digest:
            raise ValueError('witness input changed: '+name)
        bound[name] = digest
    case = (root/d['prior_case']).resolve()
    if not case.is_relative_to(root/'research'):
        raise ValueError('invalid previous diagnostic case')
    driver = json.loads((case/'driver-0001/manifest.json').read_text())
    boot = json.loads((case/'phone-native-0001/boot.json').read_text())
    outcome = json.loads((case/'physical-outcome-0001.json').read_text())
    pe_path = case/'driver-0001'/driver['artifact']
    if (driver.get('wifi_native_fault_hold') is not True or
        driver.get('wifi_firmware_diagnostic_only') is not True or
        driver.get('kernel_handoff') is not False or
        boot.get('native_command_ACK') is not True or outcome.get('image_and_nonce_spent') is not True or
        boot['image_sha256']!=d['prior_image_sha256'] or driver['sha256']!=d['driver_sha256'] or
        sha(pe_path)!=d['driver_sha256'] or
        d['native_source_sha256']!=driver['inputs']['shim/polaris/uefi-xnu.c']):
        raise ValueError('witness does not identify the spent firmware-only fault diagnostic')
    for p in (pe_path,case/'driver-0001/manifest.json',case/'phone-native-0001/boot.json',
              case/'physical-outcome-0001.json'):
        if str(p.relative_to(root)) not in bound:
            raise ValueError('missing witness artifact binding')
    layout = d['expected_layout']
    if (len(layout)!=12 or any(type(v) is not int or not 0<v<(1<<64) for v in layout) or
        layout[0]!=d['image_base'] or layout[1]!=d['image_bytes'] or
        layout[8]!=d['record_address'] or layout[9]!=272 or layout[7]!=16384 or
        layout[3]!=layout[2]+2048 or not 2048<layout[4]-layout[2]<=4096 or
        layout[2]%2048 or layout[6]%4096 or layout[8]%16 or layout[10]%8 or
        not 0<layout[1]<=128<<20 or not 0<layout[11]<=262144):
        raise ValueError('invalid old record layout')
    spans = [(layout[2],layout[4]-layout[2]),(layout[6],layout[7]),
             (layout[8],layout[9]),(layout[10],layout[11]),(d['nonce_address'],d['nonce_bytes'])]
    for i,(at,count) in enumerate(spans):
        if (type(at) is not int or type(count) is not int or not count or
            at<layout[0] or at+count>layout[0]+layout[1] or
            any(at<a+n and a<at+count for a,n in spans[:i])):
            raise ValueError('witness ranges are not disjoint inside the old image')
    if not 0<d['nonce_bytes']<=4096:
        raise ValueError('bounded nonce required')
    pe = pe_path.read_bytes();header = struct.unpack_from('<I',pe,60)[0]
    if pe[:2]!=b'MZ' or pe[header:header+4]!=b'PE\0\0' or struct.unpack_from('<H',pe,header+4)[0]!=0xaa64:
        raise ValueError('old AArch64 PE required')
    if struct.unpack_from('<I',pe,header+24+56)[0]!=layout[1]:
        raise ValueError('old image span changed')
    table = header+24+struct.unpack_from('<H',pe,header+20)[0]
    nonce = None;rva = d['nonce_address']-layout[0]
    for n in range(struct.unpack_from('<H',pe,header+6)[0]):
        at = table+n*40;_,start,size,where = struct.unpack_from('<IIII',pe,at+8)
        if start<=rva and rva+d['nonce_bytes']<=start+size:
            nonce = pe[where+rva-start:where+rva-start+d['nonce_bytes']]
    if nonce is None or hashlib.sha256(nonce).hexdigest()!=d['nonce_sha256']:
        raise ValueError('expected nonce is not the actual linked image bytes')
    digest = bytes.fromhex(d['nonce_sha256'])
    if len(digest)!=32:
        raise ValueError('nonce digest size')
    text = '/* Private, one spent image; generated addresses/digest, never commit. */\n'
    text += 'static const struct pnfw_config pnfw_configuration={\n {'
    text += ','.join('UINT64_C(0x%x)'%v for v in layout)+'},\n'
    text += ' UINT64_C(0x%x),UINT64_C(%d),{'%(d['nonce_address'],d['nonce_bytes'])
    text += ','.join('0x%02x'%b for b in digest)+'}};\n'
    (output/'native-fault-witness-config.h').write_text(text)
    return dict(enabled=True,scope=d['scope'],prior_image_sha256=d['prior_image_sha256'],
                prior_driver_sha256=d['driver_sha256'],record_bytes=272,nonce_bytes=d['nonce_bytes'],
                descriptor_sha256=sha(descriptor),old_RAM_writes=False,
                arbitrary_memory_read_API=False,inputs=bound)
