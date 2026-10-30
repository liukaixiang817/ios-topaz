#!/usr/bin/env python3
"""Manifest-bound OEM WLED RAM cycle client; no OS/storage/raw-reset command."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
from polaris_uefi_usb_transport import LibusbTransport
from polaris_wled_journal import WledOemProtocol
from polaris_wled_oem_admission import exact_scope


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def binding(boot,image,driver):
    exact_scope(driver);exact_scope(image)
    if (boot.get('state')!='temporary_WLED_OEM_power_cycle_boot_command_succeeded' or
        boot.get('image_sha256')!=image.get('sha256') or not boot.get('sent_utc') or
        boot.get('driver_manifest_sha256')!=image.get('driver_manifest_sha256') or
        image.get('driver_sha256')!=driver.get('sha256') or image.get('final_reset_receipt_required') is not True or
        image.get('root_access_permitted') is not False or image.get('installer') is not False):
        raise ValueError('not the bound independent OEM WLED RAM session')


def cycle_readbacks(text):
    if any(x in text for x in ('WLED_POWER_MOCK_BACKEND=','Darwin Kernel Version','KERNEL_PSCI_STATUS=')):
        raise ValueError('mock or OS-running evidence is not a physical WLED cycle')
    fields={}
    for key,value in re.findall(r'(?m)^(WLED_[A-Z_0-9]+)=0x([0-9a-f]{16})\r?$',text):
        if key in fields:raise ValueError('duplicate WLED physical observation')
        fields[key]=int(value,16)
    required=dict(WLED_POWER_OEM_STATUS_POLICY=1,WLED_KERNEL_AP_STAGE=0,WLED_POWER_PREPARE_ERROR=0,
        WLED_POWER_INITIAL_VERSION=0x50000000,WLED_POWER_INITIAL_CTRL_MAP=0x0103d800,
        WLED_POWER_INITIAL_SINK_MAP=0x0103d900,WLED_POWER_INITIAL_CTRL_APID_OWNER=253<<32,
        WLED_POWER_INITIAL_SINK_APID_OWNER=254<<32,WLED_POWER_INITIAL_PSM=0x8480,
        WLED_POWER_OFF_MODULE=0,WLED_POWER_OFF_IRQ=0,WLED_POWER_RESTORED_MODULE=0x80,
        WLED_POWER_RESTORED_IRQ=2,WLED_POWER_WRITES_ISSUED=4,WLED_POWER_WRITES_COMPLETED=4,
        WLED_POWER_CYCLE_ERROR=0,WLED_POWER_SOURCE_STATUS_VALID=3)
    if any(fields.get(k)!=v for k,v in required.items()) or not fields.get('WLED_AP_STAGE_ADDRESS'):
        raise ValueError('incomplete actual physical OFF/restore readbacks')
    if (fields.get('WLED_POWER_RESTORED_US',0)-fields.get('WLED_POWER_OFF_US',0)<2000000 or
        fields.get('WLED_POWER_SOFTSTART_US',0)<10000 or
        fields.get('WLED_POWER_SOURCE_STATUS',0)&~0x0101 or
        'WLED_POWER_CYCLE_HOLD: NO_CPU_ON SAVED_STATE_RESTORED' not in text):
        raise ValueError('invalid physical hold/softstart/source status')
    return dict(electrical_module_off_and_restored_readbacks=True,physical_darkness_proven=False,fields=fields)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action',choices=('state','cycle','capture','reboot-fastboot','recover-prestart-fastboot'))
    for name in ('libusb','boot-record','image-manifest','driver-manifest','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--payload',type=Path)
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    b,i,d=(json.loads(p.read_text()) for p in (a.boot_record,a.image_manifest,a.driver_manifest));binding(b,i,d)
    if (b.get('image_manifest_sha256')!=sha(a.image_manifest) or i.get('controller_sha256')!=sha(Path(__file__)) or
        i.get('wire_parser_sha256')!=sha(root/'tools/polaris_wled_journal.py') or
        i.get('transport_sha256')!=sha(root/'tools/polaris_uefi_usb_transport.py')):
        raise ValueError('frozen controller/manifest/wire parser changed')
    image=a.image_manifest.parent/i['artifact'];app=a.driver_manifest.parent/d['artifact']
    if (image.resolve().parent!=a.image_manifest.parent.resolve() or sha(image)!=i['sha256'] or
        app.resolve().parent!=a.driver_manifest.parent.resolve() or sha(app)!=d['sha256'] or
        sha(a.driver_manifest)!=i['driver_manifest_sha256']):raise ValueError('bound image/driver changed')
    for name,digest in d['inputs'].items():
        path=(root/name).resolve()
        if root not in path.parents or sha(path)!=digest:raise ValueError('OEM source changed: '+name)
    raw=a.payload.read_bytes() if a.payload else None
    if ((a.action=='cycle')!=(raw is not None) or
        raw is not None and (len(raw)!=d['payload_bytes'] or hashlib.sha256(raw).hexdigest()!=d['payload_sha256'])):
        raise ValueError('cycle requires the exact fixed no-CPU RAM payload')
    a.output.mkdir(parents=True,exist_ok=False);native=None;protocol=None
    record=dict(action=a.action,started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        sent_utc=b['sent_utc'],image_sha256=i['sha256'],driver_sha256=d['sha256'],reader_sha256=sha(Path(__file__)),
        storage_writes=False,NVRAM_writes=False,kernel_CPU_ON_compiled_out=True,OS_started=False,
        physical_darkness_proven=False,actual_FASTBOOT_verified=False,errors=[])
    try:
        native=LibusbTransport(a.libusb)
        if not native.open_target():raise RuntimeError('bound OEM UEFI endpoint unavailable')
        protocol=WledOemProtocol(native);record['product']=protocol.product();record['state_before']=protocol.state()
        if a.action=='cycle':
            if record['state_before']!='waiting-payload':raise ValueError('do not start a second WLED cycle')
            protocol.stage_payload(raw,d);protocol.boot();record['cycle_request_acknowledged']=True
        if a.action in ('capture','reboot-fastboot','recover-prestart-fastboot'):
            if record['state_before']=='prepared':
                packet,parsed=protocol.capture_journal();p=a.output/'journal.bin';p.write_bytes(packet);p.chmod(0o600)
                record['journal']=parsed
            elif a.action!='recover-prestart-fastboot':raise ValueError('not an actual pre-XNU WLED hold')
            protocol.stage('logs');log=protocol.upload();p=a.output/'firmware.log';p.write_bytes(log);p.chmod(0o600)
            record['firmware_log_sha256']=sha(p)
            if record.get('journal',{}).get('cycle_restored_readbacks'):
                record['cycle']=cycle_readbacks(log.decode(errors='replace'))
            if a.action=='reboot-fastboot':record['reset_receipt']=protocol.reboot_restored()
            if a.action=='recover-prestart-fastboot':record['zero_write_reset_receipt']=protocol.recover_unstarted_fastboot()
        if a.action not in ('reboot-fastboot','recover-prestart-fastboot'):record['state_after']=protocol.state()
        record['passed']=True
    except Exception as e:
        record['passed']=False;record['errors'].append(str(e))
    finally:
        if protocol and protocol.last_reset_response is not None:
            p=a.output/'reset-response.bin';p.write_bytes(protocol.last_reset_response);p.chmod(0o600)
            record['reset_response_sha256']=sha(p)
        if native:native.close()
        record['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        p=a.output/'result.json';p.write_text(json.dumps(record,indent=2)+'\n');p.chmod(0o600)
    print(json.dumps({k:record[k] for k in ('action','passed','errors')}))
    return not record['passed']


if __name__=='__main__':raise SystemExit(main())
