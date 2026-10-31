#!/usr/bin/env python3
"""One manifest-bound native WLED RO/RAMCOW RAM session; no generic reset/flash."""
import argparse,datetime,hashlib,importlib.util,json,sys,time
from pathlib import Path
from polaris_uefi_usb_transport import LibusbTransport
from polaris_wled_runtime_control import WledRuntimeProtocol
from polaris_wled_runtime_admission import exact_scope


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()


def binding(boot,image,driver):
    build=image.get('userland_build','20H392')
    exact_scope(driver,build);exact_scope(image,build)
    if (boot.get('state')!='temporary_native_WLED_runtime_RAM_boot_succeeded' or not boot.get('sent_utc') or
        boot.get('image_sha256')!=image.get('sha256') or boot.get('driver_manifest_sha256')!=image.get('driver_manifest_sha256') or
        image.get('driver_sha256')!=driver.get('sha256') or image.get('scope')!='independent_native_WLED_RO_RAMCOW_runtime' or
        image.get('atomic_exit_required') is not True or image.get('installer') is not False or
        image.get('immutable_root_RAMCOW_only') is not True or image.get('may_write_userdata') is not False):
        raise ValueError('not the independent bound native-WLED RAM boot')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action',choices=('state','boot','capture','tap','swipe','shutdown-fastboot','exit-drained','recover-exit','recover-prestart','utc-sync','utc-status'))
    ap.add_argument('--host-utc-sync',action='store_true',help='explicit one-shot host UTC calendar calibration; no RTC/monotonic writes')
    for n in ('libusb','boot-record','image-manifest','driver-manifest','output'):ap.add_argument('--'+n,type=Path,required=True)
    ap.add_argument('--payload',type=Path);ap.add_argument('--wait-seconds',type=int,default=8)
    ap.add_argument('--shutdown-seconds',type=int,default=180)
    ap.add_argument('--x',type=int);ap.add_argument('--y',type=int);ap.add_argument('--to-x',type=int);ap.add_argument('--to-y',type=int)
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    if not 0<=a.wait_seconds<=30 or not 1<=a.shutdown_seconds<=240:raise ValueError('bounded control deadlines required')
    b,i,d=(json.loads(p.read_text()) for p in (a.boot_record,a.image_manifest,a.driver_manifest));binding(b,i,d)
    if sha(a.image_manifest)!=b.get('image_manifest_sha256') or sha(a.driver_manifest)!=i['driver_manifest_sha256'] or sha(Path(__file__))!=i['controller_sha256']:
        raise ValueError('frozen native runtime controller binding changed')
    image=a.image_manifest.parent/i['artifact'];driver=a.driver_manifest.parent/d['artifact']
    if image.resolve().parent!=a.image_manifest.parent.resolve() or driver.resolve().parent!=a.driver_manifest.parent.resolve() or sha(image)!=i['sha256'] or sha(driver)!=d['sha256']:
        raise ValueError('frozen actual image changed')
    for name,digest in i['evidence_sha256'].items():
        p=(root/name).resolve()
        if root not in p.parents or sha(p)!=digest:raise ValueError('bound evidence/source changed '+name)
    if (a.action=='boot')!=(a.payload is not None):raise ValueError('only boot accepts the exact payload')
    if (a.action=='utc-sync')!=a.host_utc_sync:raise ValueError('only utc-sync requires the explicit --host-utc-sync intent')
    clock=None
    if a.action in ('utc-sync','utc-status'):
        mailbox=d.get('host_UTC_mailbox')
        if d.get('host_UTC_sync') is not True or not isinstance(mailbox,dict) or mailbox.get('BSS') is not False or mailbox.get('bytes')!=256:
            raise ValueError('this frozen driver has no admitted host UTC metadata bridge')
        for name in ('tools/polaris-clock-host.py','tools/polaris-clock-sync.h','tools/polaris-clock-uefi.h','tools/polaris-clock-native.h'):
            if d.get('inputs',{}).get(name)!=sha(root/name):raise ValueError('frozen clock implementation binding changed')
        spec=importlib.util.spec_from_file_location('polaris_clock_host',root/'tools/polaris-clock-host.py')
        clock=importlib.util.module_from_spec(spec);sys.modules[spec.name]=clock;spec.loader.exec_module(clock)
    if a.payload and (sha(a.payload)!=d['payload_sha256'] or a.payload.stat().st_size!=d['payload_bytes']):raise ValueError('exact payload required')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    record=dict(action=a.action,started_utc=now(),sent_utc=b['sent_utc'],image_sha256=i['sha256'],
                phone_partition_writes=False,NVRAM_writes=False,actual_FASTBOOT_verified=False,errors=[])
    def save():(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    def history(p,label):
        pages,j=p.capture_history()
        for n,raw in enumerate(pages):(out/f'{label}-{n:03d}.bin').write_bytes(raw)
        (out/(label+'.json')).write_text(json.dumps(j,indent=2)+'\n');return j
    transport=None;p=None;save()
    try:
        transport=LibusbTransport(a.libusb);start=time.monotonic()
        while not transport.open_target():
            if time.monotonic()-start>=a.wait_seconds:raise RuntimeError('bound UEFI service not connected')
            time.sleep(.2)
        p=WledRuntimeProtocol(transport);record['product']=p.product();record['state_before']=p.state();save()
        if a.action=='state':pass
        elif a.action in ('utc-sync','utc-status'):
            if record['state_before']!='kernel-entered':raise ValueError('calendar metadata requires the actual native running phase')
            if a.action=='utc-status':
                record['host_UTC_status']=clock.asdict(clock.status(p))
            else:
                record['host_UTC_SET_may_be_attempted']=True;save()
                try:record['host_UTC_sync']=clock.synchronize(p)
                except clock.DeliveryUnknown as error:
                    record['host_UTC_delivery_unknown']=dict(cookie=error.cookie,sequence=error.sequence,recovery='utc-status only; never resend SET')
                    save();raise
        elif a.action=='boot':
            record['kernel_command_attempted']=True;save();p.stage_payload(a.payload.read_bytes(),d);p.boot();record['kernel_command_ACK']=True
        elif a.action=='recover-prestart':
            record['zero_write_receipt']=p.recover_prestart();record['reset_ACK_received']=True
        elif a.action=='capture':
            for kind in ('logs','screenshot'):
                p.stage(kind);raw=p.upload();(out/('native.log' if kind=='logs' else 'screenshot.ppm')).write_bytes(raw)
            record['history']=history(p,'history')
        elif a.action in ('tap','swipe'):
            if a.action=='tap':p.tap(a.x,a.y)
            else:p.swipe(a.x,a.y,a.to_x,a.to_y)
            record['contact_ACK']=True
        else:
            if a.action=='shutdown-fastboot':
                record['native_request_attempted']=True;save();token=p.request_shutdown(True);record['native_token']=list(token);save()
            else:
                # Fresh actual status after an unknown earlier host ACK. No
                # shutdown/PMIC request is replayed; only native-drained exit.
                s=p.shutdown_status()
                if (not s['cookie'] or (s['sequence'],s['mode'],s['phase'],s['error'],s['write_epoch'],s['flushed_epoch'],s['capabilities'])!=(1,2,3,0,0,0,0x80000003)):
                    raise ValueError('actual native RAM drain not independently observed')
                p.shutdown_token=(s['cookie'],1,2);record['native_token']=list(p.shutdown_token)
            start=time.monotonic();record['native_samples']=[];save()
            while True:
                s=p.shutdown_status()
                if not record['native_samples'] or record['native_samples'][-1]!=s:record['native_samples'].append(s);save()
                if s['error'] or s['phase']==6:raise RuntimeError('actual native drain refused; no reset sent')
                if (s['cookie'],s['sequence'],s['mode'])==p.shutdown_token and s['phase']==3 and s['capabilities']==0x80000003:break
                if time.monotonic()-start>a.shutdown_seconds:raise RuntimeError('native drain incomplete; no reset sent')
                time.sleep(.1)
            p.stage('logs');(out/'native-drain.log').write_bytes(p.upload())
            while True:
                prefix=history(p,'terminal-prefix')
                if prefix['failed']:raise RuntimeError('WLED failure retained; no reset sent')
                if prefix['flags'] in (11,27) and prefix['module']==128 and prefix['irq']==2 and prefix['request']==prefix['ack'] and prefix['issued']==prefix['completed']:break
                if time.monotonic()-start>a.shutdown_seconds:raise RuntimeError('WLED restoration not completed; no reset sent')
                time.sleep(.1)
            record['exit_command_attempted']=True;save()
            record['final_actual_history']=p.atomic_exit(prefix,recover=a.action=='recover-exit')
            record['reset_ACK_received']=True
        record['completed_utc']=now();record['passed']=True
    except Exception as e:
        record['passed']=False;record['errors'].append(type(e).__name__+': '+str(e));raise
    finally:
        if p:
            if p.actual_footer:(out/'actual-exit-footer.bin').write_bytes(p.actual_footer)
            if p.actual_reply:(out/'actual-reset-response.bin').write_bytes(p.actual_reply)
        # Preserve the validated transaction before any host-only cleanup.
        # This program exits immediately afterward; no context is reused.
        defer_context=(sys.platform=='darwin' and record.get('passed') is True and
                       record.get('reset_ACK_received') is True)
        if defer_context:record['host_context_cleanup']='immediate_process_exit_after_validated_receipt'
        save()
        if transport:
            if defer_context:transport.close(process_exit_after_disconnect=True)
            else:transport.close()
        save()
    if a.action in ('utc-sync','utc-status'):print('Calendar metadata action completed; no reset requested')
    else:print('Native WLED action completed; actual FASTBOOT requires a separate readonly query')


if __name__=='__main__':main()
