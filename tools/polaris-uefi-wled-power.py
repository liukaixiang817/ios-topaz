#!/usr/bin/env python3
"""Bound pre-XNU WLED power cycle; no OS, touch or arbitrary PMIC commands."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re

from polaris_uefi_usb_transport import KernelProtocol, LibusbTransport


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def binding(boot, image, driver):
    if (boot.get('state') != 'temporary_WLED_power_cycle_boot_command_succeeded' or
            boot.get('image_sha256') != image.get('sha256') or not boot.get('sent_utc') or
            image.get('driver_sha256') != driver.get('sha256')):
        raise ValueError('not the source-bound physical WLED cycle session')
    for m in (image,driver):
        for key,value in dict(WLED_power_cycle_only=True,WLED_readonly_inventory_only=False,
                              PMIC_write_api=True,kernel_CPU_ON_compiled_out=True,kernel_handoff=False,
                              storage_write_api=False,NVRAM_write_api=False).items():
            if type(m.get(key)) is not type(value) or m[key] != value:
                raise ValueError('not the isolated WLED power cycle: '+key)
    if driver.get('QEMU_variant') is not False:
        raise ValueError('software PMIC fixture is not a phone image')


def parse(text):
    if ('WLED_POWER_MOCK_BACKEND=' in text or 'Darwin Kernel Version' in text or
            'KERNEL_PSCI_STATUS=' in text):
        raise ValueError('mock or OS-running log is not physical pre-XNU evidence')
    pairs = re.findall(r'(?m)^(WLED_[A-Z_0-9]+)=0x([0-9a-f]{16})\r?$',text)
    fields = {}
    for k,v in pairs:
        if k in fields:
            raise ValueError('duplicate WLED cycle field: '+k)
        fields[k] = int(v,16)
    expected = dict(WLED_POWER_PREPARE_ERROR=0,WLED_KERNEL_AP_STAGE=0,
                    WLED_POWER_INITIAL_VERSION=0x50000000,WLED_POWER_INITIAL_CTRL_MAP=0x0103d800,
                    WLED_POWER_INITIAL_SINK_MAP=0x0103d900,WLED_POWER_INITIAL_CTRL_APID_OWNER=253<<32,
                    WLED_POWER_INITIAL_SINK_APID_OWNER=254<<32,WLED_POWER_INITIAL_PSM=0x8480,
                    WLED_POWER_OFF_MODULE=0,WLED_POWER_OFF_IRQ=0,WLED_POWER_RESTORED_MODULE=0x80,
                    WLED_POWER_RESTORED_IRQ=2,WLED_POWER_WRITES_ISSUED=4,WLED_POWER_WRITES_COMPLETED=4,
                    WLED_POWER_CYCLE_ERROR=0)
    if any(fields.get(k) != v for k,v in expected.items()):
        raise ValueError('cycle readback incomplete, refused or inconsistent')
    if (not fields.get('WLED_POWER_OFF_US') or not fields.get('WLED_POWER_RESTORED_US') or
            fields['WLED_POWER_RESTORED_US']-fields['WLED_POWER_OFF_US']<2000000 or
            fields.get('WLED_POWER_SOFTSTART_US',0)<10000 or
            not fields.get('WLED_AP_STAGE_ADDRESS') or
            len(re.findall(r'(?m)^WLED_POWER_CYCLE_HOLD: NO_CPU_ON SAVED_STATE_RESTORED\r?\n',text)) != 1):
        raise ValueError('missing cooperative timing or verified final hold')
    return dict(electrical_module_off_and_restore_readbacks=True,physical_darkness_proven=False,
                OS_started=False,fields=fields)


def prestart_refusal(text):
    """Only recover a failed preparation that never armed a writer.

    The current image independently gates reset on its actual issued count.
    This is not a bypass for a cycle failure, uncertain command or running OS.
    """
    pairs = re.findall(r'(?m)^(WLED_[A-Z_0-9]+)=0x([0-9a-f]{16})\r?$',text)
    f = {}
    for k,v in pairs:
        if k in f:
            raise ValueError('duplicate preparation record')
        f[k] = int(v,16)
    initial_refusal = (f.get('WLED_POWER_PREPARE_ERROR') in (1,2,3,4,5,6,7,32,33) and
                       'WLED_POWER_CYCLE_ERROR' not in f)
    zero_write_refusal = (f.get('WLED_POWER_PREPARE_ERROR') == 0 and
                          f.get('WLED_POWER_CYCLE_ERROR') in (1,2,3,4,5,6,7,32,33,34,35,36,37,38) and
                          f.get('WLED_POWER_WRITES_ISSUED') == 0 and
                          f.get('WLED_POWER_WRITES_COMPLETED') == 0 and
                          f.get('WLED_POWER_UNCERTAIN') == 0)
    if (not (initial_refusal or zero_write_refusal) or
            f.get('WLED_KERNEL_AP_STAGE') != 0 or not f.get('WLED_AP_STAGE_ADDRESS') or
            'WLED_POWER_CYCLE_ARMED: NO_CPU_ON' not in text or
            any(x in text for x in ('WLED_POWER_OFF_US=',
                                    'WLED_POWER_MOCK_BACKEND=','Darwin Kernel Version','KERNEL_PSCI_STATUS='))):
        raise ValueError('not a proven no-writer pre-XNU preparation refusal')
    if f.get('WLED_POWER_WRITES_ISSUED',0) != 0 or f.get('WLED_POWER_PREPARE_WRITES_ISSUED',0) != 0:
        raise ValueError('a PMIC command was issued; refusal recovery forbidden')
    return dict(preparation_refused_before_writer=True,firmware_reset_gate_still_required=True,
                electrical_module_off_and_restore_readbacks=False,physical_darkness_proven=False,fields=f)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action',choices=('state','cycle','capture','reboot-fastboot','recover-prestart-fastboot'))
    for name in ('libusb','boot-record','image-manifest','driver-manifest','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--payload',type=Path)
    a = ap.parse_args()
    b,i,d = (json.loads(p.read_text()) for p in (a.boot_record,a.image_manifest,a.driver_manifest))
    binding(b,i,d)
    raw = a.payload.read_bytes() if a.payload else None
    if (a.action=='cycle') != (raw is not None) or (raw is not None and
            (len(raw)!=d['payload_bytes'] or hashlib.sha256(raw).hexdigest()!=d['payload_sha256'])):
        raise ValueError('cycle requires its exact fixed no-CPU payload')
    a.output.mkdir(parents=True,exist_ok=False)
    record = dict(action=a.action,started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  sent_utc=b['sent_utc'],image_sha256=i['sha256'],driver_sha256=d['sha256'],
                  reader_sha256=sha(Path(__file__)),PMIC_power_cycle_permitted=True,
                  storage_writes=False,NVRAM_writes=False,kernel_CPU_ON_compiled_out=True,errors=[])
    native = None
    try:
        native = LibusbTransport(a.libusb)
        if not native.open_target():
            raise RuntimeError('bound UEFI endpoint unavailable')
        protocol = KernelProtocol(native)
        record['product'] = protocol.product();record['state_before'] = protocol.state()
        if a.action=='cycle':
            if record['state_before']!='waiting-payload':
                raise ValueError('cycle may only be started once from waiting-payload')
            protocol.stage_payload(raw,d);protocol.boot()
            record['cycle_request_acknowledged'] = True
        if a.action in ('capture','reboot-fastboot','recover-prestart-fastboot'):
            protocol.stage('logs');data = protocol.upload();p = a.output/'firmware.log'
            p.write_bytes(data);p.chmod(0o600);record['firmware_log_sha256'] = sha(p)
            reader = prestart_refusal if a.action=='recover-prestart-fastboot' else parse
            record['cycle'] = reader(data.decode(errors='replace'))
            if protocol.state()!='prepared':
                raise ValueError('cycle did not stay in pre-XNU hold')
        if a.action in ('reboot-fastboot','recover-prestart-fastboot'):
            protocol.reboot(True);record['reset_command_acknowledged'] = True
            record['actual_FASTBOOT_verified'] = False
        else:
            record['state_after'] = protocol.state()
        record['passed'] = True
    except Exception as e:
        record['passed'] = False;record['errors'].append(str(e))
    finally:
        if native:
            native.close()
        record['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        p = a.output/'result.json';p.write_text(json.dumps(record,indent=2)+'\n');p.chmod(0o600)
    print(json.dumps({k:record[k] for k in ('action','passed','errors')}))
    return not record['passed']


if __name__=='__main__':
    raise SystemExit(main())
