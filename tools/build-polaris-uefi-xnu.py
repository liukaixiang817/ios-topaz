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
import uuid
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
                if text in (b'_sweet_log_ring',b'_sweet_log_total',b'_polaris_uefi_input',b'_polaris_uefi_shutdown',b'_polaris_uefi_buttons',
                            b'_polaris_uefi_wled',b'_PolarisWledNativeProbe'):
                    if text in (b'_polaris_uefi_wled',b'_PolarisWledNativeProbe') and \
                        ((typ&0x0e)!=0x0e or not section or not value):
                        raise ValueError('native WLED symbol must be actually defined')
                    if text.decode() in wanted:raise ValueError('duplicate log symbol')
                    wanted[text.decode()]=value
        at+=size
    if not {'_sweet_log_ring','_sweet_log_total'}<=set(wanted):raise ValueError('kernel RAM console symbols absent')
    return wanted


def readonly_osm_intent(tokens,expected,core,count,qemu,drain,bridge,ufs,marker,performance=False):
    actual=[t for t in tokens if t.startswith(b'polarisosm=')]
    if (expected and performance) or actual!=([b'polarisosm=2'] if performance else [b'polarisosm=1'] if expected else []) or ((expected or performance) and
        (core!=7 or count!=4 or ufs or marker or
         not (drain in ('success','stale-cookie','peer-refused') if qemu else bridge))):
        raise ValueError('OSM mode requires the explicit four-big RAM native-drain trial and intact unique token')
    return expected

def gpu_stock_intent(tokens,mode,core,count,qemu,drain,bridge,ufs,marker):
    actual=[t for t in tokens if t.startswith(b'polarisgpup=')]
    if type(mode) is not int or mode not in (0,1,2,3) or actual!=([f'polarisgpup={mode}'.encode()] if mode else []):
        raise ValueError('GPU stock request needs its exact explicit unique experiment mode')
    if mode:
        if core!=7 or count!=4 or ufs or marker or not (drain in ('success','stale-cookie','peer-refused') if qemu else bridge):
            raise ValueError('GPU stock experiment requires four-big RAM-only native drain')
        for key,value in [('polarisramcow','1'),('ufsrw','0'),('polarisquiesce','1')]:
            if [t for t in tokens if t.startswith((key+'=').encode())]!=[(key+'='+value).encode()]:
                raise ValueError('GPU stock experiment must preserve RAM COW, write protection and native drain')
    return mode


def framebuffer_wake_intent(tokens,enabled,core,count,qemu,drain,bridge,ufs,marker):
    actual=[t for t in tokens if t.startswith(b'polarisfbwake=')]
    if type(enabled) is not bool or actual!=([b'polarisfbwake=1'] if enabled else []):
        raise ValueError('framebuffer wake must match its unique explicit firmware intent')
    if enabled:
        if (core!=7 or count not in (2,4) or ufs or marker or
            not (drain in ('success','stale-cookie','peer-refused') if qemu else bridge)):
            raise ValueError('framebuffer wake trial requires native multi-core RAM drain')
        for key,value in [('polarisramcow','1'),('ufsrw','0'),('polarisquiesce','1')]:
            if [t for t in tokens if t.startswith((key+'=').encode())]!=[(key+'='+value).encode()]:
                raise ValueError('framebuffer wake must preserve RAM-only native shutdown')
    return enabled


def physical_buttons_intent(tokens,enabled,core,count,qemu,drain,bridge,ufs,marker):
    actual=[t for t in tokens if t.startswith(b'polarisbuttons=')]
    if type(enabled) is not bool or actual!=([b'polarisbuttons=1'] if enabled else []):
        raise ValueError('physical keys require their unique explicit three-key intent')
    if enabled and (core!=7 or count not in (2,4) or ufs or marker or
                    not (drain in ('success','stale-cookie','peer-refused') if qemu else bridge)):
        raise ValueError('physical keys require the native multi-core RAM shutdown bridge')
    if enabled:
        for expected in (b'polarisinput=1',b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1'):
            key=expected.split(b'=',1)[0]+b'='
            if [t for t in tokens if t.startswith(key)]!=[expected]:
                raise ValueError('physical keys must preserve touch, RAM COW and native shutdown')
    return enabled

def tsens_readonly_intent(tokens,enabled,core,count,qemu,drain,bridge,ufs,marker,osm,
                          lease=False,gpu_mode=0,osm_stock=False,extended=False):
    actual=[t for t in tokens if t.startswith(b'polaristsens=')]
    if type(extended) is not bool or (extended and not lease):
        raise ValueError('TSENS extended duration requires explicit thermal lease')
    if type(lease) is not bool or (lease and (not enabled or gpu_mode!=3 or not osm_stock)):
        raise ValueError('TSENS thermal lease requires explicit readonly/stock CPU and GPU mode3')
    expected=b'polaristsens=3' if extended else b'polaristsens=2' if lease else b'polaristsens=1'
    if type(enabled) is not bool or actual!=([expected] if enabled else []):
        raise ValueError('TSENS readonly intent must match one explicit token')
    if enabled:
        if core!=7 or count!=4 or ufs or marker or not osm or not (
            drain in ('success','stale-cookie','peer-refused') if qemu else bridge):
            raise ValueError('TSENS readonly requires four-big RAM native drain and platform inventory')
        for expected in (b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1'):
            if [t for t in tokens if t.startswith(expected.split(b'=')[0]+b'=')]!=[expected]:
                raise ValueError('TSENS readonly must preserve RAM/write-protection/drain guards')
    return enabled


def tsens_pair_witness_intent(tokens,enabled,readonly,lease,extended):
    actual=[t for t in tokens if t.startswith(b'polarispts=')]
    if type(enabled) is not bool or actual!=([b'polarispts=1'] if enabled else []):
        raise ValueError('TSENS pair witness requires one separate explicit intent')
    if enabled:
        if any(type(v) is not bool or not v for v in (readonly,lease,extended)):
            raise ValueError('TSENS pair witness requires the extended thermal experiment')
        for token in (b'polaristsens=3',b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1'):
            if [t for t in tokens if t.startswith(token.split(b'=')[0]+b'=')]!=[token]:
                raise ValueError('TSENS pair witness must preserve native RAM/thermal guards')
    return ({'max_physical_reads':72,'max_words_per_sensor':4,'max_span_us':1000,
             'max_pair_delta_mC':2000,'hottest_word_required':1,'actual_words_only':1}
            if enabled else None)


def wled_native_intent(tokens,physical,test):
    if physical and test:raise ValueError('physical and SOFTWARE WLED scopes are exclusive')
    for key,enabled in ((b'polariswled=',physical or test),(b'polariswledvm=',test)):
        if [t for t in tokens if t.startswith(key)]!=([key+b'1'] if enabled else []):
            raise ValueError('native WLED arguments require exact independent physical/SOFTWARE intent')
    if physical:
        for expected in (b'ufsrw=0',b'rootrw=1',b'polarisramcow=1',b'polarisrammb=512',
                         b'polarisquiesce=1',b'ca_vbl=1'):
            key=expected.split(b'=')[0]+b'='
            if [t for t in tokens if t.startswith(key)]!=[expected]:
                raise ValueError('physical WLED must retain original RO/RAMCOW/drain/display guards')
        if any(t.startswith((b'polarisownedmarker=',b'polarisperf=')) for t in tokens):
            raise ValueError('physical runtime requires the explicit diagnostic-token substitution, no owned writes')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--zig',required=True,type=Path)
    ap.add_argument('--kernel',required=True,type=Path)
    ap.add_argument('--payload',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--test-qemu',action='store_true')
    ap.add_argument('--test-qemu-ufs',action='store_true',
                    help='isolated read-only native virtual UFS; never a physical admission proof')
    ap.add_argument('--test-qemu-owned',action='store_true',
                    help='write only a newly copied synthetic owned-file UFS fixture; never phone admission')
    ap.add_argument('--test-owned-response-short',action='store_true',
                    help='QEMU-only software response-residual injection after real WRITE completion')
    ap.add_argument('--physical-owned-marker',action='store_true',
                    help='separately admitted physical8MiB marker; original root stays RAM COW')
    ap.add_argument('--test-omit-durable-guard',action='store_true',
                    help='QEMU-only old-loader mismatch: native owned writes must be refused before MMIO')
    ap.add_argument('--cpu-osm-stock-performance',action='store_true',help='bounded stock4-core OSM request; not overclocking or all7-core admission')
    ap.add_argument('--gpu-stock-request',type=int,choices=(1,2,3),default=0,help='bounded original HFI request:1 bandwidth only,2 core only,3 both; no physical MHz claim')
    ap.add_argument('--gpu-stock-inventory',type=Path,help='actual original-device read-only request baseline before this experiment')
    ap.add_argument('--framebuffer-arrival-wake',action='store_true',help='explicit coalesced display workloop wake; native probe required before phone admission')
    ap.add_argument('--physical-buttons',action='store_true',help='three original PM8998 keys on firmware CPU0; QEMU tests only the native consumer without Qualcomm MMIO')
    ap.add_argument('--tsens-readonly',action='store_true',help='original six CPU/GPU thermal status registers only')
    ap.add_argument('--gpu-thermal-lease',action='store_true',help='explicit default-OFF bounded GPU-only thermal experiment; requires readonly TSENS and stock mode3')
    ap.add_argument('--gpu-thermal-extended',action='store_true',help='separate default-OFF 600s GPU duration experiment; all thermal/idle/10s low guards retained')
    ap.add_argument('--tsens-pair-witness',action='store_true',help='separate default-OFF bounded VALID-word witness, retaining hottest observed temperature')
    ap.add_argument('--wled-inventory-only',action='store_true',help='short original WLED observer inventory then hold; CPU_ON compiled out, no PMIC writes')
    ap.add_argument('--wled-fault-watch',action='store_true',help='readonly inventory plus bounded FAULT/RT/enable timeline, never health or writer admission')
    ap.add_argument('--test-wled-fault-pulse',action='store_true',help='QEMU-only explicit nonzero/disappearing FAULT words for readonly watch')
    ap.add_argument('--wled-power-cycle-only',action='store_true',help='isolated pre-XNU WLED OFF/two-second hold/ON; no OS or storage writes')
    ap.add_argument('--wled-oem-status',action='store_true',help='QEMU-only explicit OEM volatile-status policy; no physical image admission yet')
    ap.add_argument('--wled-oem-physical-cycle',action='store_true',help='separate pre-XNU physical OEM cycle; requires independent OEM image admission')
    ap.add_argument('--wled-native-runtime',action='store_true',help='independent physical PMIC native runtime scope; needs its own image/admission/controller')
    ap.add_argument('--wled-native-runtime-test',action='store_true',help='independent QEMU-only actual native/FW mailbox test with SOFTWARE PMIC; never a phone image')
    ap.add_argument('--test-wled-native-start-refusal',choices=('owner','configuration','before-runtime'),help='QEMU runtime-only pre-CPU/zero-WRITE recovery test')
    ap.add_argument('--test-wled-native-fault',choices=('timeout','fault-ovp','fault-sc','fault-unknown','rt-ovp','rt-sc','rt-unknown','clock-regression'),help='independent SOFTWARE PMIC error after first runtime WRITE; QEMU only')
    ap.add_argument('--test-wled-native-lifecycle',choices=('capacity','stale-ack','receipt-age','lease'),help='independent QEMU runtime lifecycle fixture; never physical admission')
    ap.add_argument('--test-wled-prepare-refusal',nargs='?',const='owner',choices=('owner','configuration','before-cycle'),help='QEMU OEM-only zero-write owner/configuration/pre-WLED refusal')
    ap.add_argument('--test-wled-status-after-issue',type=lambda s:int(s,0),default=0,help='QEMU-only packed FAULT/RT severe bits after first issued command')
    ap.add_argument('--test-wled-write-timeout',action='store_true',help='isolated QEMU uncertain WLED command; no reset or retry')
    ap.add_argument('--test-wled-read-failure',action='store_true',help='QEMU-only explicit observer refusal in the inventory hold')
    ap.add_argument('--cpu-stock-inventory',type=Path,help='required physical read-only OSM evidence for the first performance trial')
    ap.add_argument('--cpu-osm-readonly',action='store_true',
                    help='explicit four-big-core stock OSM read-only inventory intent')
    ap.add_argument('--kernel-core',type=int,choices=(1,7),default=1,
                    help='boot XNU core: existing small CPU1 or opt-in big CPU7; firmware retains CPU0')
    ap.add_argument('--kernel-cpus',type=int,choices=(1,2,4),default=1,
                    help='one core, CPU7+CPU6 pair, or CPU7..CPU4 group; firmware CPU0 stays reserved')
    ap.add_argument('--test-ram-drain',choices=['success','stale-cookie','peer-refused'],
                    help='QEMU-only real BSD RAM drain experiment; never UFS durability proof')
    ap.add_argument('--ram-shutdown-bridge',action='store_true',
                    help='expose native RAM-only shutdown mailbox over resident USB')
    ap.add_argument('--efi-application',action='store_true',help='selected application, never ReadyToBoot interception')
    ap.add_argument('--disk-guid',type=uuid.UUID,help='exact GPT partition UUID for read-only disk payload')
    ap.add_argument('--disk-start-lba',type=int)
    ap.add_argument('--disk-blocks',type=int)
    ap.add_argument('--disk-version',default='V0061')
    ap.add_argument('--chain-app-manifest',type=Path,help='RAM test wrapper for the exact already-built selected disk app')
    a=ap.parse_args();r=Path(__file__).resolve().parents[1]
    if a.test_wled_native_start_refusal and (not a.wled_native_runtime_test or not a.test_qemu or
        a.test_ram_drain!='success' or a.test_wled_native_fault or a.test_wled_native_lifecycle or
        a.test_wled_prepare_refusal or a.test_wled_status_after_issue or a.test_wled_write_timeout or
        a.test_wled_read_failure or a.test_wled_fault_pulse):
        ap.error('native WLED prestart refusal requires only the independent QEMU runtime scope')
    if a.test_wled_native_lifecycle and (not a.wled_native_runtime_test or not a.test_qemu or
        a.test_ram_drain!='success' or a.test_wled_native_fault or a.test_wled_prepare_refusal or
        a.test_wled_status_after_issue or a.test_wled_write_timeout or a.test_wled_read_failure or a.test_wled_fault_pulse):
        ap.error('native WLED lifecycle requires only the independent QEMU runtime success-drain fixture')
    if a.test_wled_native_fault and (not a.wled_native_runtime_test or not a.test_qemu or
        a.test_ram_drain!='success' or a.test_wled_prepare_refusal or a.test_wled_status_after_issue or
        a.test_wled_write_timeout or a.test_wled_read_failure or a.test_wled_fault_pulse):
        ap.error('native WLED fault requires only the independent QEMU runtime success-drain fixture')
    if a.wled_native_runtime_test and (not a.test_qemu or a.kernel_core!=7 or a.kernel_cpus!=4 or
        a.test_ram_drain not in ('success','stale-cookie','peer-refused') or not a.physical_buttons or
        not a.framebuffer_arrival_wake or a.wled_power_cycle_only or a.wled_inventory_only or
        a.wled_oem_status or a.wled_oem_physical_cycle or a.test_qemu_ufs or a.test_qemu_owned or
        a.physical_owned_marker or a.disk_guid or a.chain_app_manifest or a.efi_application):
        ap.error('native WLED is an independent QEMU four-core RAM-drain/keys/workloop test only')
    if a.wled_native_runtime and (a.test_qemu or a.wled_native_runtime_test or
        a.kernel_core!=7 or a.kernel_cpus!=4 or not a.ram_shutdown_bridge or
        not a.physical_buttons or not a.framebuffer_arrival_wake or not a.tsens_readonly or
        not a.cpu_osm_stock_performance or a.gpu_stock_request!=3 or not a.gpu_thermal_extended or
        not a.gpu_thermal_lease or not a.tsens_pair_witness or a.wled_inventory_only or
        a.wled_power_cycle_only or a.wled_oem_status or a.wled_oem_physical_cycle or
        a.test_qemu_ufs or a.test_qemu_owned or a.physical_owned_marker or a.disk_guid or
        a.chain_app_manifest or a.efi_application or a.test_ram_drain or a.cpu_osm_readonly or
        a.test_wled_prepare_refusal or a.test_wled_native_fault or a.test_wled_native_lifecycle or
        a.test_wled_read_failure or a.test_wled_status_after_issue or a.test_wled_write_timeout or
        a.test_wled_fault_pulse or a.test_omit_durable_guard or a.test_wled_native_start_refusal):
        ap.error('physical native WLED requires its independent guarded four-big RO/RAMCOW scope')
    native_runtime=a.wled_native_runtime or a.wled_native_runtime_test
    target=a.kernel_core if a.test_qemu else a.kernel_core<<8
    if a.tsens_pair_witness and not a.gpu_thermal_extended:
        ap.error('TSENS pair witness requires the explicit extended thermal experiment')
    if a.gpu_thermal_extended and not a.gpu_thermal_lease:
        ap.error('TSENS extended duration requires explicit thermal lease')
    if a.gpu_thermal_lease and (not a.tsens_readonly or not a.cpu_osm_stock_performance or a.gpu_stock_request!=3):
        ap.error('TSENS thermal lease requires readonly TSENS, stock CPU and GPU request3')
    if a.tsens_readonly and (a.kernel_core!=7 or a.kernel_cpus!=4 or
        a.test_qemu_ufs or a.test_qemu_owned or a.physical_owned_marker or a.disk_guid or
        a.chain_app_manifest or a.efi_application or a.wled_inventory_only or a.wled_power_cycle_only or
        not (a.cpu_osm_readonly or a.cpu_osm_stock_performance) or
        not (a.test_ram_drain in ('success','stale-cookie','peer-refused') if a.test_qemu else a.ram_shutdown_bridge)):
        ap.error('TSENS readonly is only an explicit four-big RAM native-drain inventory')
    if a.wled_inventory_only and a.wled_power_cycle_only:
        ap.error('read-only WLED inventory and PMIC power cycle are different scopes')
    if a.wled_oem_status and not (a.test_qemu and a.wled_power_cycle_only):
        ap.error('OEM status policy is currently isolated QEMU power-cycle only')
    if a.wled_oem_physical_cycle and (a.test_qemu or a.wled_oem_status or not a.wled_power_cycle_only or
        a.test_wled_prepare_refusal or a.test_wled_status_after_issue or a.test_wled_write_timeout or a.test_wled_read_failure):
        ap.error('physical OEM cycle is a separate no-injection pre-XNU scope')
    if a.test_wled_prepare_refusal and (not a.test_qemu or not a.wled_oem_status or
        a.test_wled_status_after_issue or a.test_wled_write_timeout):
        ap.error('zero-write preparation refusal requires an independent QEMU OEM cycle')
    oem_status=a.wled_oem_status or a.wled_oem_physical_cycle
    if a.test_wled_status_after_issue and (not a.wled_oem_status or
        not 0<a.test_wled_status_after_issue<=0xffff or
        not (a.test_wled_status_after_issue&0xfefe) or a.test_wled_write_timeout):
        ap.error('status fault injection requires separate QEMU OEM cycle without timeout injection')
    if a.wled_fault_watch and not a.wled_inventory_only:
        ap.error('WLED fault watch requires the no-writer pre-XNU inventory scope')
    if a.test_wled_fault_pulse and not (a.test_qemu and a.wled_fault_watch):
        ap.error('synthetic WLED fault words are QEMU readonly watch only')
    wled_hold=a.wled_inventory_only or a.wled_power_cycle_only
    if wled_hold and (not a.physical_buttons or a.kernel_core!=7 or a.kernel_cpus!=4 or
        a.test_qemu_ufs or a.test_qemu_owned or a.physical_owned_marker or a.disk_guid or
        a.chain_app_manifest or a.efi_application or not (a.test_ram_drain=='success' if a.test_qemu else a.ram_shutdown_bridge)):
        ap.error('WLED inventory is only a four-big RAM pre-XNU hold with original key observer and no disk/owned/chain mode')
    if a.test_wled_read_failure and not (a.test_qemu and a.wled_inventory_only):
        ap.error('WLED read refusal injection is isolated QEMU inventory only')
    if a.test_wled_write_timeout and not (a.test_qemu and a.wled_power_cycle_only):
        ap.error('WLED write timeout is only an isolated QEMU power-cycle refusal')
    if a.physical_owned_marker and (a.test_qemu or a.kernel_core!=7 or a.kernel_cpus!=2 or
                                    not a.ram_shutdown_bridge or a.chain_app_manifest):
        ap.error('physical marker requires physical CPU7+6 and its selected native shutdown bridge')
    if a.test_qemu_ufs and (not a.test_qemu or a.kernel_core!=7 or a.kernel_cpus!=2):
        ap.error('isolated virtual UFS requires explicit QEMU CPU7+6')
    if a.test_qemu_owned and (not a.test_qemu_ufs or a.test_ram_drain not in ('success','stale-cookie') or
                              a.disk_guid or a.chain_app_manifest or a.efi_application):
        ap.error('owned virtual fixture requires isolated QEMU UFS and native drain without disk/chain mode')
    if a.test_owned_response_short and not a.test_qemu_owned:
        ap.error('controlled response injection requires isolated owned-file mode')
    if a.test_omit_durable_guard and (not a.test_qemu_owned or a.test_owned_response_short):
        ap.error('guard-omission injection requires the isolated owned QEMU test alone')
    if a.kernel_cpus>1 and a.kernel_core!=7:ap.error('multi-core trial requires CPU7 with descending declared peers')
    if a.test_ram_drain=='peer-refused' and a.kernel_cpus not in (2,4):
        ap.error('peer refusal injection requires the explicit two-core QEMU test')
    if a.test_ram_drain and (not a.test_qemu or a.chain_app_manifest):
        ap.error('RAM drain experiment requires QEMU without a chain wrapper')
    if a.ram_shutdown_bridge and a.chain_app_manifest:
        ap.error('RAM shutdown bridge belongs to the selected loader, not its chain wrapper')
    if a.disk_guid is not None:
        if (a.disk_start_lba is None or a.disk_blocks is None or not 0<a.disk_start_lba<2**64 or
            not 0<a.disk_blocks<2**64-a.disk_start_lba):ap.error('disk identity requires valid start and block count')
        if len(a.disk_version)!=5 or a.disk_version[0]!='V' or not a.disk_version[1:].isascii() or not a.disk_version[1:].isdigit():
            ap.error('disk version must be V plus four ASCII digits')
    elif a.efi_application or a.disk_start_lba is not None or a.disk_blocks is not None:
        ap.error('selected application requires a complete disk identity')
    if a.chain_app_manifest and (not a.disk_guid or a.efi_application):ap.error('chain wrapper requires disk identity and no --efi-application')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    raw=a.payload.read_bytes();k=a.kernel.read_bytes()
    sys.path.insert(0,str(r/'tools'));import mkpayload
    tokens=raw[0x48:0x2a8].split(b'\0',1)[0].split()
    if any(t.startswith(b'polarisdurableguard=') for t in tokens):
        raise ValueError('durable guard must be produced by live resident firmware')
    if (a.physical_owned_marker or a.test_qemu_owned) and len(raw[0x48:0x2a8].split(b'\0',1)[0])+32>=608:
        raise ValueError('reserve space for runtime durable guard in final boot args')
    if [t for t in tokens if t.startswith(b'polarisownedmarker=')]!=([b'polarisownedmarker=1'] if a.physical_owned_marker else []):
        raise ValueError('physical marker must be uniquely bound to explicit firmware durable mode')
    if a.physical_owned_marker:
        for key,value in [('polarisfileroot','1'),('rootrw','1'),('polarisramcow','1'),('polarisrammb','512'),('ufsrw','0')]:
            if [t for t in tokens if t.startswith((key+'=').encode())]!=[(key+'='+value).encode()]:
                raise ValueError('physical marker requires unchanged512MiB RAM COW root and closed generic write gate')
    ufs_tokens=[t for t in tokens if t.startswith(b'polarisqemuufs=')]
    if ufs_tokens!=([b'polarisqemuufs=1'] if a.test_qemu_ufs else []):
        raise ValueError('virtual UFS must be explicitly and uniquely bound to a QEMU-only test')
    for key,enabled in [('polarisqemuowned',a.test_qemu_owned),('polarisownedfault',a.test_owned_response_short)]:
        if [t for t in tokens if t.startswith((key+'=').encode())]!=([(key+'=1').encode()] if enabled else []):
            raise ValueError('owned-file opt-in/injection must be uniquely bound to its isolated QEMU test')
    off_tokens=[t for t in tokens if t.startswith(b'polarisofftest=')]
    if off_tokens!=([b'polarisofftest=1'] if a.test_ram_drain=='peer-refused' else []):
        raise ValueError('peer refusal injection must be uniquely bound to its QEMU-only test')
    readonly_osm_intent(tokens,a.cpu_osm_readonly,a.kernel_core,a.kernel_cpus,
        a.test_qemu,a.test_ram_drain,a.ram_shutdown_bridge,a.test_qemu_ufs,a.physical_owned_marker,a.cpu_osm_stock_performance)
    gpu_stock_intent(tokens,a.gpu_stock_request,a.kernel_core,a.kernel_cpus,
        a.test_qemu,a.test_ram_drain,a.ram_shutdown_bridge,a.test_qemu_ufs,a.physical_owned_marker)
    framebuffer_wake_intent(tokens,a.framebuffer_arrival_wake,a.kernel_core,a.kernel_cpus,
        a.test_qemu,a.test_ram_drain,a.ram_shutdown_bridge,a.test_qemu_ufs,a.physical_owned_marker)
    tsens_readonly_intent(tokens,a.tsens_readonly,a.kernel_core,a.kernel_cpus,
        a.test_qemu,a.test_ram_drain,a.ram_shutdown_bridge,a.test_qemu_ufs,
        a.physical_owned_marker,a.cpu_osm_readonly or a.cpu_osm_stock_performance,
        a.gpu_thermal_lease,a.gpu_stock_request,a.cpu_osm_stock_performance,a.gpu_thermal_extended)
    pair_policy=tsens_pair_witness_intent(tokens,a.tsens_pair_witness,a.tsens_readonly,
        a.gpu_thermal_lease,a.gpu_thermal_extended)
    gpu_inventory=None
    if a.gpu_stock_request and not a.test_qemu:
        if not a.gpu_stock_inventory:raise ValueError('GPU stock request requires actual physical read-only baseline')
        evidence=json.loads(a.gpu_stock_inventory.read_text())
        log=(r/evidence['actual_log']).resolve(strict=True)
        if r not in log.parents:raise ValueError('GPU baseline log must belong to this workspace')
        if (evidence.get('passed') is not True or evidence.get('phone_trial_ended') is not True or
            evidence.get('actual_RO_clock_count')!=53 or evidence.get('GMU_request')!=dict(performance_index=1,bandwidth_index=4,return_code=0) or
            evidence.get('GPU_frequency_or_bandwidth_writes_added') is not False or evidence.get('storage_writes') is not False or
            sha(log)!=evidence.get('actual_log_sha256')):
            raise ValueError('original-device GPU request baseline/hash mismatch')
        gpu_inventory=dict(passed=True,sha256=sha(a.gpu_stock_inventory),actual_log_sha256=sha(log),baseline_PERF=1,baseline_BW=4)
    elif a.gpu_stock_inventory:raise ValueError('GPU baseline belongs only to its physical experiment')
    stock_inventory=None
    if a.cpu_osm_stock_performance and not a.test_qemu:
        if not a.cpu_stock_inventory:raise ValueError('stock performance requires actual physical read-only inventory')
        evidence=json.loads(a.cpu_stock_inventory.read_text());case=Path(evidence['case'])
        if not case.is_absolute():case=r/case
        log=case/'capture-0001-OSM/kernel.log'
        if (evidence.get('passed') is not True or evidence.get('clock_voltage_writes') is not False or
            evidence.get('storage_writes') is not False or evidence.get('enabled')!=3 or
            evidence.get('core_control')!=0 or evidence.get('rows')!=27 or
            evidence.get('current_requested_index')!=0 or evidence.get('normal_four_core_max_index')!=22 or
            evidence.get('normal_four_core_max_requested_Hz')!=2649600000 or
            sha(log)!=evidence.get('actual_native_log_sha256') or
            sha(case/'boot.json')!=evidence.get('boot_sha256')):
            raise ValueError('physical stock OSM evidence/hash mismatch')
        stock_inventory=dict(passed=True,sha256=sha(a.cpu_stock_inventory),
            actual_native_log_sha256=evidence['actual_native_log_sha256'],target_index=22,
            target_requested_Hz=2649600000,shared_cluster=True,clock_voltage_writes=False)
    elif a.cpu_stock_inventory:raise ValueError('physical stock inventory belongs only to its physical performance trial')
    cpu_tokens=[t for t in tokens if t.startswith(b'polarisbootcpu=')]
    if cpu_tokens!=[f'polarisbootcpu={target}'.encode()]:
        raise ValueError('payload must uniquely declare the exact selected kernel core')
    if [t for t in tokens if t.startswith(b'cpus=')]!=[f'cpus={a.kernel_cpus}'.encode()]:
        raise ValueError('payload must uniquely declare the selected kernel CPU count')
    # Bind firmware PSCI target to the kernel's actual tree, not just a token.
    import polaris_uefi_cpu_tree
    if len(raw)<72:raise ValueError('payload header truncated')
    tree_at,tree_bytes=struct.unpack_from('<QQ',raw,32)
    if tree_at>len(raw) or not 8<=tree_bytes<=len(raw)-tree_at:
        raise ValueError('CPU tree source outside payload')
    tree=polaris_uefi_cpu_tree.validate(raw[tree_at:tree_at+tree_bytes],a.kernel_core,a.test_qemu,a.kernel_cpus)
    if any(n.name=='polaris-qemu-ufs' for n in tree.children)!=a.test_qemu_ufs:
        raise ValueError('virtual UFS opt-in does not match the actual tree')
    if any(n.name=='polaris-qemu-owned-file' for n in tree.children)!=a.test_qemu_owned:
        raise ValueError('owned-file opt-in does not match the actual tree')
    if any(n.name=='polaris-owned-marker' for n in tree.children)!=a.physical_owned_marker:
        raise ValueError('physical marker opt-in does not match the actual tree')
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
    shutdown_offset=syms.get('_polaris_uefi_shutdown',va)-va
    shutdown_bridge=a.ram_shutdown_bridge or bool(a.test_ram_drain)
    physical_buttons_intent(raw[0x48:0x2a8].split(b'\0',1)[0].split(),a.physical_buttons,
                            a.kernel_core,a.kernel_cpus,a.test_qemu,a.test_ram_drain,
                            a.ram_shutdown_bridge,a.test_qemu_ufs,a.physical_owned_marker)
    buttons_offset=syms.get('_polaris_uefi_buttons',va)-va
    wled_offset=syms.get('_polaris_uefi_wled',va)-va
    wled_tokens=raw[0x48:0x2a8].split(b'\0',1)[0].split()
    wled_native_intent(wled_tokens,a.wled_native_runtime,a.wled_native_runtime_test)
    if native_runtime:
        if ('_PolarisWledNativeProbe' not in syms or '_polaris_uefi_wled' not in syms or wled_offset%128 or
            not 0<=wled_offset<=end-256 or not input_present or
            any(abs(wled_offset-other)<256 for other in (input_offset,buttons_offset,shutdown_offset))):
            raise ValueError('native WLED mailbox must be independent/aligned/kernel-owned')
        probe=syms['_PolarisWledNativeProbe']
        if (probe&3) or not any(s['vmaddr']<=probe<s['vmaddr']+s['vmsize'] and
                               s['name']=='__TEXT_EXEC' for s in m['segs']):
            raise ValueError('native WLED probe must be in actual kernel executable text')
    if a.physical_buttons:
        if ('_polaris_uefi_buttons' not in syms or buttons_offset%128 or
            not 0<=buttons_offset<=end-256 or not input_present or
            abs(buttons_offset-input_offset)<256 or abs(buttons_offset-shutdown_offset)<256):
            raise ValueError('physical key mailbox must be independent, aligned and kernel-owned')
    if shutdown_bridge:
        tokens=raw[0x48:0x2a8].split(b'\0',1)[0].split()
        if tokens.count(b'polarisquiesce=1')!=1 or any(
                t.startswith(b'polarisquiesce=') and t!=b'polarisquiesce=1' for t in tokens):
            raise ValueError('RAM drain experiment requires explicit unique kernel opt-in')
        if ('_polaris_uefi_shutdown' not in syms or shutdown_offset%128 or
                not 0<=shutdown_offset<=end-256 or not input_present or
                abs(shutdown_offset-input_offset)<256):
            raise ValueError('invalid independent shutdown mailbox symbol')
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
#define EFI_XNU_BUTTONS_AVAILABLE {int(a.physical_buttons)}
#define EFI_XNU_BUTTONS_OFFSET 0x{buttons_offset:x}ULL
#define EFI_XNU_WLED_OFFSET 0x{wled_offset:x}ULL
#define EFI_XNU_CPU {target}u
#define EFI_XNU_BOOT_CPU_TOKEN "polarisbootcpu={target}"
#define EFI_XNU_CPUS_TOKEN "cpus={a.kernel_cpus}"
''')
    if shutdown_bridge:
        with config.open('a') as f:
            f.write('#define EFI_XNU_SHUTDOWN_BRIDGE 1\n')
            f.write(f'#define EFI_XNU_SHUTDOWN_OFFSET 0x{shutdown_offset:x}ULL\n')
            if a.test_ram_drain:
                mode={'success':1,'stale-cookie':2,'peer-refused':3}[a.test_ram_drain]
                f.write(f'#define EFI_XNU_RAM_DRAIN_TEST {mode}\n')
            if a.test_qemu_owned:f.write('#define EFI_XNU_OWNED_TEST 1\n')
            if a.test_omit_durable_guard:f.write('#define EFI_XNU_TEST_OMIT_OWNED_GUARD 1\n')
            if a.physical_owned_marker:f.write('#define EFI_XNU_PHYSICAL_MARKER 1\n')
    disk_path=None
    if a.disk_guid:
        disk_path='\\EFI\\Polaris\\'+a.disk_version+'\\PAYLOAD.BIN'
        with config.open('a') as f:
            f.write('#define EFI_XNU_DISK_GUID {'+','.join(str(b) for b in a.disk_guid.bytes_le)+'}\n')
            f.write(f'#define EFI_XNU_DISK_START {a.disk_start_lba}ULL\n#define EFI_XNU_DISK_BLOCKS {a.disk_blocks}ULL\n')
            f.write('#define EFI_XNU_DISK_PATH {'+','.join(str(ord(c)) for c in disk_path)+',0}\n')
    chain=None
    if a.chain_app_manifest:
        child=json.loads(a.chain_app_manifest.read_text());child_file=a.chain_app_manifest.parent/child['artifact']
        if (child.get('selected_application') is not True or child.get('QEMU_variant')!=a.test_qemu or
            child.get('disk_guid')!=str(a.disk_guid) or child.get('disk_start_lba')!=a.disk_start_lba or
            child.get('disk_blocks')!=a.disk_blocks or child.get('disk_payload_path')!=disk_path or
            child.get('kernel_CPU_affinity')!=target or child.get('kernel_CPU_count',1)!=a.kernel_cpus or
            child.get('kernel_sha256')!=sha(a.kernel) or child.get('payload_sha256')!=sha(a.payload) or
            child.get('sha256')!=sha(child_file) or not 0<child_file.stat().st_size<2<<20):
            raise ValueError('chain requires matching selected application and exact disk/payload/kernel')
        image_bytes=child_file.read_bytes();pe=struct.unpack_from('<I',image_bytes,60)[0]
        if image_bytes[pe:pe+6]!=b'PE\0\0\x64\xaa' or struct.unpack_from('<H',image_bytes,pe+24+68)[0]!=10:
            raise ValueError('chain target must be AArch64 EFI_APPLICATION')
        chain=dict(manifest_sha256=sha(a.chain_app_manifest),artifact_path=str(child_file.resolve()),
                   sha256=sha(child_file),bytes=len(image_bytes),historical_inputs=child['inputs'])
        name='\\EFI\\Polaris\\'+a.disk_version+'\\PolarisIos.efi'
        with config.open('a') as f:
            f.write(f'#define EFI_XNU_CHAIN_BYTES {len(image_bytes)}u\n#define EFI_XNU_CHAIN_CRC32 0x{zlib.crc32(image_bytes):08x}u\n')
            f.write('#define EFI_XNU_CHAIN_PATH {'+','.join(str(ord(c)) for c in name)+',0}\n')
        flags.append('-DPOLARIS_EFI_CHAIN_APP=1')
    if a.efi_application:flags.append('-DPOLARIS_EFI_APPLICATION=1')
    if a.wled_inventory_only:flags.append('-DEFI_XNU_WLED_INVENTORY_ONLY=1')
    if a.wled_fault_watch:flags.append('-DEFI_XNU_WLED_FAULT_WATCH=1')
    if a.test_wled_fault_pulse:flags.append('-DEFI_XNU_TEST_WLED_FAULT_PULSE=1')
    if a.wled_power_cycle_only:flags.append('-DEFI_XNU_WLED_POWER_CYCLE_ONLY=1')
    if oem_status:flags.append('-DEFI_XNU_WLED_OEM_STATUS=1')
    if a.wled_oem_physical_cycle:flags.append('-DEFI_XNU_WLED_OEM_PHYSICAL_CYCLE=1')
    if a.wled_native_runtime_test:flags.append('-DEFI_XNU_WLED_NATIVE_RUNTIME_TEST=1')
    if a.wled_native_runtime:flags.append('-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1')
    if a.test_wled_native_start_refusal:
        flags.append('-DEFI_XNU_WLED_NATIVE_START_REFUSAL='+str(('owner','configuration','before-runtime').index(a.test_wled_native_start_refusal)+1))
    if a.test_wled_native_fault:
        flags.append('-DEFI_XNU_WLED_NATIVE_FAULT='+str(('timeout','fault-ovp','fault-sc','fault-unknown','rt-ovp','rt-sc','rt-unknown','clock-regression').index(a.test_wled_native_fault)+1))
    if a.test_wled_native_lifecycle:
        flags.append('-DEFI_XNU_WLED_NATIVE_LIFECYCLE='+str(('capacity','stale-ack','receipt-age','lease').index(a.test_wled_native_lifecycle)+1))
    if a.test_wled_prepare_refusal:flags.append('-DEFI_XNU_TEST_WLED_PREPARE_REFUSAL='+str({'owner':1,'configuration':2,'before-cycle':3}[a.test_wled_prepare_refusal]))
    if a.test_wled_status_after_issue:flags.append('-DEFI_XNU_TEST_WLED_STATUS_AFTER_ISSUE='+str(a.test_wled_status_after_issue))
    if a.test_wled_write_timeout:flags.append('-DEFI_XNU_TEST_WLED_WRITE_TIMEOUT=1')
    if a.test_wled_read_failure:flags.append('-DEFI_XNU_TEST_WLED_READ_FAILURE=1')
    sources=['uefi-xnu.c','uefi-xnu-ap.S','uefi-xnu-crc.c','payload.c','uefi-usb.c','uefi-usb-command.c','uefi-usb-control.c']
    inputs=['shim/polaris/'+n for n in sources]+['shim/polaris/uefi.h','shim/polaris/uefi-xnu.h','shim/polaris/uefi-usb.h','shim/polaris/uefi-memory.h','shim/polaris/uefi-reset.h','shim/polaris/uefi-file.h','shim/polaris/uefi-boot-options.h','shim/polaris/uefi-ram-lease.h','shim/polaris/payload.h','tools/build-polaris-uefi-xnu.py','tools/polaris-uefi-input.h']
    inputs+=['tools/polaris_uefi_cpu_tree.py','tools/adt.py','tools/mkpayload.py']
    inputs.append('shim/polaris/runtime-marker.h')
    if a.physical_buttons:
        inputs+=['shim/polaris/uefi-buttons.h','shim/polaris/uefi-buttons-spmi.h',
                 'tools/polaris-buttons.h','tools/polaris-uefi-buttons.h']
    if a.wled_inventory_only:inputs+=['shim/polaris/uefi-wled-inventory.h','shim/polaris/uefi-wled-readonly.h']
    if a.wled_fault_watch:inputs+=['shim/polaris/uefi-wled-fault-watch.h']
    if a.wled_power_cycle_only:inputs+=['shim/polaris/uefi-wled-cycle.h','shim/polaris/uefi-wled-power.h','shim/polaris/uefi-wled-readonly.h','shim/polaris/uefi-wled-status.h']
    if oem_status:inputs+=['shim/polaris/uefi-wled-journal.h']
    if native_runtime:
        inputs+=['shim/polaris/uefi-wled-native.h','shim/polaris/uefi-wled-runtime.h',
                 'shim/polaris/uefi-wled-power.h','shim/polaris/uefi-wled-readonly.h',
                 'shim/polaris/uefi-wled-status.h','shim/polaris/uefi-wled-journal.h',
                 'tools/polaris-wled-mailbox.h']
    if shutdown_bridge:inputs.append('shim/polaris/runtime-quiesce.h')
    objects=[]
    for source in sources:
        obj=out/(Path(source).stem+'.obj');objects.append(str(obj))
        cmd=['/usr/bin/clang','--target=aarch64-unknown-windows','-ffreestanding','-fno-builtin','-fno-stack-protector','-fshort-wchar','-mgeneral-regs-only','-O2','-Wall','-Wextra','-Werror',*flags,'-I'+str(out),'-c',str(r/'shim/polaris'/source),'-o',str(obj)]
        p=subprocess.run(cmd,capture_output=True);(out/(source+'.log')).write_bytes(p.stdout+p.stderr)
        if p.returncode:raise RuntimeError('EFI module compile failed: '+source)
    application=a.test_qemu or a.efi_application
    image=out/('PolarisXnuTest.efi' if a.test_qemu else 'PolarisIos.efi' if application else 'PolarisChainDxe.efi' if chain else 'PolarisXnuDxe.efi')
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    p=subprocess.run([str(a.zig.resolve()),'build-exe',*objects,'-target','aarch64-uefi','--subsystem','efi_application' if application else 'efi_boot_service_driver','-O','ReleaseSmall','-femit-bin='+str(image)],env=env,capture_output=True)
    (out/'link.log').write_bytes(p.stdout+p.stderr)
    if p.returncode:raise RuntimeError('EFI link failed')
    manifest=dict(artifact=image.name,sha256=sha(image),bytes=image.stat().st_size,
                  kernel_sha256=sha(a.kernel),payload_sha256=sha(a.payload),payload_bytes=len(raw),
                  payload_crc32=zlib.crc32(raw),payload_C_admission=True,rebased_kernel_bytes_match=True,
                  RAM_only_XNU_loader=not a.physical_owned_marker,kernel_handoff=not wled_hold,storage_write_api=False,NVRAM_write_api=False,
                  WLED_readonly_inventory_only=a.wled_inventory_only,controlled_WLED_read_refusal=a.test_wled_read_failure,
                  WLED_readonly_fault_watch=a.wled_fault_watch,controlled_WLED_fault_pulse=a.test_wled_fault_pulse,
                  WLED_power_cycle_only=a.wled_power_cycle_only,controlled_WLED_write_timeout=a.test_wled_write_timeout,
                  WLED_OEM_status_policy=oem_status,WLED_OEM_physical_cycle=a.wled_oem_physical_cycle,
                  WLED_native_runtime_test=a.wled_native_runtime_test,
                  WLED_native_runtime_physical=a.wled_native_runtime,
                  controlled_WLED_native_start_refusal=a.test_wled_native_start_refusal,
                  controlled_WLED_native_fault=a.test_wled_native_fault,
                  controlled_WLED_native_lifecycle=a.test_wled_native_lifecycle,
                  WLED_native_SOFTWARE_PMIC=a.wled_native_runtime_test,
                  WLED_runtime_journal_version=3 if native_runtime else None,
                  WLED_runtime_archive_capacity=(64 if a.test_wled_native_lifecycle=='capacity' else 8192) if native_runtime else None,
                  WLED_runtime_archive_storage_capacity=8192 if native_runtime else None,
                  raw_reset_requires_native_and_WLED_restore=native_runtime,
                  WLED_native_zero_write_receipt_bytes=40 if native_runtime else None,
                  controlled_WLED_prepare_refusal=bool(a.test_wled_prepare_refusal),controlled_WLED_prepare_kind=a.test_wled_prepare_refusal,
                  controlled_WLED_status_after_issue=a.test_wled_status_after_issue,
                  WLED_journal_version=2 if oem_status else None,
                  WLED_journal_bytes_max=1348 if oem_status else None,
                  WLED_final_reset_receipt_bytes=56 if oem_status else None,
                  WLED_zero_write_receipt_bytes=16 if oem_status else None,
                  PMIC_write_api=a.wled_power_cycle_only or native_runtime,kernel_CPU_ON_compiled_out=wled_hold,
                  probe_only=wled_hold,holds_before_OS_start=wled_hold,
                  original_root_writes_volatile=True,physical_small_file_write_test=a.physical_owned_marker,
                  reset_commands=True,reset_commands_hardware_tested=False,ready_to_boot_driver=not application,
                  RAM_host_idle_recovery_seconds=None if (a.test_qemu_owned or a.physical_owned_marker) else 1800,
                  selected_application=a.efi_application,disk_payload_read_only=bool(a.disk_guid),
                  disk_guid=str(a.disk_guid) if a.disk_guid else None,disk_start_lba=a.disk_start_lba,
                  disk_blocks=a.disk_blocks,disk_payload_path=disk_path,
                  chain_app=chain,
                  bounded_input=input_present,input_offset=input_offset,
                  physical_buttons=a.physical_buttons,buttons_offset=buttons_offset if a.physical_buttons else None,
                  TSENS_readonly_inventory=a.tsens_readonly,thermal_configuration_write_api=False,
                  GPU_thermal_lease_trial=a.gpu_thermal_lease,
                  GPU_thermal_extended_trial=a.gpu_thermal_extended,
                  TSENS_pair_witness_trial=a.tsens_pair_witness,TSENS_pair_policy=pair_policy,
                  GPU_thermal_policy=({'experimental_limits_mC':[75000,70000,60000,55000],
                    'max_observation_age_us':500000,'hard_high_ns':600000000000 if a.gpu_thermal_extended else 120000000000,
                    'confirmed_low_ns':10000000000,'idle_ns':250000000} if a.gpu_thermal_lease else None),
                  RAM_native_drain_test=a.test_ram_drain,RAM_native_shutdown_bridge=shutdown_bridge,
                  shutdown_offset=shutdown_offset if shutdown_bridge else None,
                  persistent_root_or_UFS_durability_proven=False,
                  QEMU_variant=a.test_qemu,phone_compatible=not a.test_qemu,
                  isolated_QEMU_readonly_UFS_test=a.test_qemu_ufs and not a.test_qemu_owned,
                  isolated_QEMU_owned_UFS_test=a.test_qemu_owned,
                  controlled_owned_response_short_injection=a.test_owned_response_short,
                  raw_reset_requires_durable_SAFE=a.test_qemu_owned or a.physical_owned_marker,
                  physical_owned_marker_test=a.physical_owned_marker,
                  controlled_durable_guard_omitted=a.test_omit_durable_guard,
                  durable_guard_generated_after_reset_disabled=a.test_qemu_owned or a.physical_owned_marker,
                  kernel_CPU_affinity=target,
                  kernel_CPU_count=a.kernel_cpus,
                  CPU_OSM_readonly_inventory=a.cpu_osm_readonly,
                  CPU_OSM_stock_performance=a.cpu_osm_stock_performance,CPU_OSM_stock_inventory=stock_inventory,
                  GPU_stock_request=a.gpu_stock_request,GPU_stock_inventory=gpu_inventory,
                  framebuffer_arrival_wake=a.framebuffer_arrival_wake,
                  RAM_base=0x130000000 if a.test_qemu else 0x180000000,RAM_bytes=0xfc8a0000,
                  firmware_core_reserved=0,firmware_services_exited=False,
                  device_execution_tested=False,inputs={p:sha(r/p) for p in inputs})
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ['artifact','sha256','bytes','QEMU_variant','device_execution_tested']}))


if __name__=='__main__':main()
