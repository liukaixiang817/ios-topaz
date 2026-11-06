#!/usr/bin/env python3
"""Build a RAM-only resident EFI/XNU driver, never install or boot it.

QEMU mode is explicitly separate: virt has different RAM/CPU affinities and
cannot validate the Qualcomm peripheral implementation or physical DDR map.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import shlex
from pathlib import Path
import struct
import subprocess
import sys
import uuid
import zlib


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def mss_zero_storage(image):
    """Require linker-emitted virtual BSS; never rewrite the linked PE."""
    raw=image.read_bytes();pe=struct.unpack_from('<I',raw,60)[0]
    machine,count=struct.unpack_from('<HH',raw,pe+4)
    optional=pe+24;size=struct.unpack_from('<H',raw,pe+20)[0]
    image_bytes=struct.unpack_from('<I',raw,optional+56)[0]
    if raw[pe:pe+4]!=b'PE\0\0' or machine!=0xaa64 or size!=240 or count>32:
        raise ValueError('MSS PE geometry')
    matches=[]
    for n in range(count):
        at=optional+size+40*n
        if raw[at:at+8]!=b'.mssbss\0':continue
        virtual,rva,file_bytes,file_offset=struct.unpack_from('<IIII',raw,at+8)
        flags=struct.unpack_from('<I',raw,at+36)[0]
        if not (virtual>=13631488 and rva%4096==0 and rva+virtual<=image_bytes and
                file_bytes==file_offset==0 and flags==0xc0000080):
            raise ValueError('MSS storage must be writable non-executable virtual BSS')
        matches.append(dict(section='.mssbss',rva=rva,virtual_bytes=virtual,file_bytes=0,image_bytes=image_bytes))
    if len(matches)!=1:raise ValueError('one MSS virtual BSS section required')
    return matches[0]


def gcd_clock_metadata(enabled,qemu,core_binding,core_pe):
    # Explicit NEW scope; the previous Device/BSmap-only policy is unchanged.
    e=bool(enabled);physical=bool(e and not qemu)
    fields=dict(original_GCD_query=e,original_GCD_default_OFF=True,
        original_GCD_physical_body=physical,original_GCD_physical_compiled_out=bool(e and qemu),
        original_GCD_original_PE=core_pe,
        original_GCD_original_PE_whole_SHA256=core_binding['whole_SHA256'] if core_binding else None,
        original_GCD_binding_SHA256=core_binding['binding_sha256'] if core_binding else None,
        original_GCD_registered_DS_GUID='05ad34ba-6f02-4214-952e-4da0398e2bb9' if e else None,
        original_GCD_immutable_hashes=5 if e else None,original_GCD_exact_descriptor_bytes=56 if e else None,
        original_GCD_fixed_pages=[0x10b000,0x117000,0x152000,0x18a000] if e else None,
        original_GCD_original_getter_calls_max=8 if e else None,original_GCD_BS_GetMap_calls_max=2 if e else None,
        original_GCD_original_TPL_lock_and_event_dispatch=physical,
        original_GCD_getter_RO_may_write_original_TPL_lock_RAM=physical,
        original_GCD_raw_bytes=30224 if e else None,original_GCD_raw_format='RAW_V1' if e else None,
        original_GCD_full_partial_raw_preserved=True if e else None,
        original_GCD_bootstrap_authority='incoming UEFI BS contract' if e else None,
        original_GCD_bootstrap_TPL_UNOBSERVED=True if e else None,
        original_GCD_FP_CPACR_before_Q_instructions=True if e else None,
        original_GCD_FP_q8_q15_full128_FPCR_FPSR_preserved=True if e else None,
        original_GCD_CPACR_write=False,original_GCD_original_call_unknown_blocks_native_and_reset=True if e else None,
        original_GCD_final_prestart_checkpoints=2 if e else None,original_GCD_final_checkpoint_RAM_appended=True if e else None,
        original_GCD_classification_is_not_MPU_or_exclusive_permission=True,
        original_GCD_GetMap_unlisted_alone_grants_MMIO=False,
        original_GCD_type_required=3 if e else None,original_GCD_UC_capability_required=True if e else None,
        original_GCD_Attributes_allowed=[0,1] if e else None,original_GCD_Attributes_zero_is_UC=False,
        original_GCD_no_BS_RAM_reserved_unknown_overlap=True if e else None,
        original_GCD_each_Clock_call_actual_Device_NS_identity=True if e else None,
        original_GCD_indirect_GCC_MMIO_read_body=physical,original_GCD_MMIO_writes=False,
        original_GCD_MMIO_writes_field_scope='direct getter/provider body only',
        original_GCD_indirect_event_hardware_side_effects_proven_absent=False,
        original_GCD_actual_observations_proven=False,original_GCD_SMEM_or_radio=False,
        original_GCD_external_SError_recoverable=False,original_GCD_nonreturning_walltime_bound_proven=False,
        audio_Clock_GCD_query=e,audio_Clock_GCD_raw_format='RAW_V2' if e else None,
        audio_Clock_GCD_raw_bytes=43504 if e else None,audio_Clock_GCD_original_query_calls_max=16 if e else None,
        audio_Clock_GCD_CapUC_Attributes0_or_UC=True if e else None,audio_Clock_GCD_CAMCC_NOT_ISSUED=True,
        audio_Clock_GCD_combined_I2C_Clock_RAM_report_bytes=98076 if e else None,
        original_GCD_new_scope_RAM_log_capacity=262144 if e else None,
        original_GCD_snapshot_allocation_matches_log_capacity=True if e else None)
    if e:
        # NEW0144 qualifies only the original latched ConfigurationTable RAM.
        # The previous core/self/DS/guard and GCC MMIO rules are unchanged.
        fields.update(
            original_GCD_config_RAM_types=[3,4,6],
            original_GCD_config_BS3_4_nonruntime_required=True,
            original_GCD_config_RuntimeData_attributes=0x800000000000000f,
            original_GCD_config_span_limit=dict(entries=128,entry_bytes=24,bytes=3072,boundary_pages=2),
            original_GCD_config_latched_pointer_count_only=True,
            original_GCD_config_single_complete_descriptor_no_alias=True,
            original_GCD_config_no_overlap_current_image_or_core=True,
            original_GCD_config_full_page_AT_required=True,
            original_GCD_config_RuntimeData_PAR_base=0xff00000000000b80,
            original_GCD_config_readonly_no_general_runtime_permission=True,
            original_GCD_config_raw_span=dict(offset=30000,bytes=112,count=2))
    return fields


def resource_clock_metadata(enabled,qemu,clock_binding,clock_pe):
    """Explicit observations; neither a memory descriptor nor a clock bit grants ownership."""
    pfr=dict(readonly=enabled,default_OFF=True,physical_map_PSCI_body=bool(enabled and not qemu),
        actual_observations_proven=False,GetMemoryMap_calls_max=2 if enabled else None,
        map_buffer_count=2 if enabled else None,map_buffer_capacity=8192 if enabled else None,
        descriptor_version=1 if enabled else None,full_raw_buffers_preserved=True if enabled else None,
        partial_GetMemoryMap_output_extent_unknown=True if enabled else None,
        PSCI_function=0xc4000004 if enabled else None,PSCI_calls_max=7 if enabled else None,
        PSCI_uses_SMC=True if enabled else None,
        PSCI_target_MPIDRs=[0x100,0x200,0x300,0x400,0x500,0x600,0x700] if enabled else None,
        all_OFF_is_instantaneous_not_exclusive=True if enabled else None,prepare_stage=2 if enabled else None,
        after_NC_before_console_and_PON=True if enabled else None,before_CPU_ON=True if enabled else None,
        exact_cache_witness_required=True if enabled else None,cache_after_fresh_limit_ticks=3840000 if enabled else None,
        frequency=19200000 if enabled else None,single_boot_ticket=True if enabled else None,
        raw_report_format='RAW_V1' if enabled else None,raw_report_endianness='little' if enabled else None,
        raw_report_bytes=17416 if enabled else None,raw_maps_offset=1032 if enabled else None,
        raw_report_RAM_only=True if enabled else None,firmware_RAM_log_capacity=131072 if enabled else None,
        firmware_RAM_log_overflow_sticky=True if enabled else None,
        resource_ranges=[[0x8e400000,0x7800000],[0x96900000,0x200000],[0x8e300000,0x100000],
            [0x8bf00000,0x500000],[0x8c415000,0x2000],[0x8c500000,0x1e00000]] if enabled else None,
        Reserved_is_free_or_owned=False,RMTFS_address_assigned=False,MSA_address_assigned=False,
        SMEM_reads=0,SFPB_writes=False,resource_allocation=False,resource_writes=False,
        MSS_PIL_or_SCM_initialization=False,hardware_MPU_or_VMID_query=False,native_permission=False,
        radio_or_transmit=False,no_runtime_or_USB_command=True,
        external_SError_recoverable=False,nonreturning_service_wall_time_bound_proven=False,
        physical_map_PSCI_compiled_out=bool(enabled and qemu))
    clock=dict(readonly=enabled,default_OFF=True,physical_original_query_body=bool(enabled and not qemu),
        actual_observations_proven=False,original_PE=clock_pe,
        original_PE_whole_SHA256=clock_binding['source_whole_sha256'] if clock_binding else None,
        binding_SHA256=clock_binding['binding_sha256'] if clock_binding else None,
        original_image_bytes=266240 if enabled else None,immutable_hashes=6 if enabled else None,
        methods=['IsEnabled','IsOn'] if enabled else None,query_calls_max=16 if enabled else None,
        descriptor_targets=15 if enabled else None,possible_GCC_baseline_targets=8 if enabled else None,
        blocked_CAMCC_targets=7 if enabled else None,CAMCC_queries_NOT_ISSUED=True if enabled else None,
        parent_clock_ON_does_not_qualify_CAMCC=True if enabled else None,
        actual_Device_identity_and_EFI_MMIO_required=True if enabled else None,
        camera_descriptor_targets=9 if enabled else None,audio_readonly_targets=3 if enabled else None,
        MSS_GCC_readonly_targets=3 if enabled else None,uses_original_descriptor_not_cross_version_DT_ID=True if enabled else None,
        indirect_GCC_MMIO_read_body=bool(enabled and not qemu),CAMCC_indirect_MMIO_read_body=False,
        exact_I2C_cache_required=True if enabled else None,prepare_stage=2 if enabled else None,
        after_complete_WiFi_diagnostics=True if enabled else None,before_CPU_ON_PON_and_mask=True if enabled else None,
        independent_clock_fresh_limit_ticks=3840000 if enabled else None,frequency=19200000 if enabled else None,
        raw_report_format='RAW_V1' if enabled else None,raw_report_endianness='little' if enabled else None,
        raw_report_bytes=13000 if enabled else None,raw_report_max_append_chars=126 if enabled else None,
        combined_I2C_Clock_RAM_report_bytes=37001 if enabled else None,
        raw_report_RAM_only=True if enabled else None,outer_status_may_drop_inner_DAL_status=True if enabled else None,
        diagnostic_error_zero_is_not_complete_baseline=True if enabled else None,
        booleans_are_not_raw_CSR=True if enabled else None,clock_or_pin_ownership_proven=False,
        GetFreq_Enable_Disable_Open=False,clock_reset_voltage_or_PLL_writes=False,I2C_CCI_or_TAS_methods=False,
        MMIO_writes=False,SE5_or_camera_bus_lease=False,PCM_or_camera_completion=False,native_permission=False,
        no_runtime_or_USB_command=True,external_SError_recoverable=False,
        physical_original_query_compiled_out=bool(enabled and qemu))
    return dict({('wifi_CPU0_resources_'+k):v for k,v in pfr.items()},
                **{('audio_Clock_query_'+k):v for k,v in clock.items()})


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
                            b'_polaris_uefi_wled',b'_PolarisWledNativeProbe',b'_polaris_uefi_clock',b'_polaris_uefi_battery'):
                    if text in (b'_polaris_uefi_wled',b'_PolarisWledNativeProbe',b'_polaris_uefi_clock',b'_polaris_uefi_battery') and \
                        ((typ&0x0e)!=0x0e or not section or not value):
                        raise ValueError('native WLED symbol must be actually defined')
                    if text.decode() in wanted:raise ValueError('duplicate log symbol')
                    wanted[text.decode()]=value
        at+=size
    if not {'_sweet_log_ring','_sweet_log_total'}<=set(wanted):raise ValueError('kernel RAM console symbols absent')
    return wanted


def clock_mailbox_binding(kernel,syms,va,end,other_spans):
    """Actual defined symbol, writable/file-backed DATA, exact initial ABI.

    Firmware seeds the slot after segment copy/zero and before CPU_ON. BSS or
    common storage would lose that seed during native initialization.
    """
    address=syms.get('_polaris_uefi_clock',0);offset=address-va
    if not address or offset%128 or not 0<=offset<=end-256:
        raise ValueError('UTC mailbox must be aligned and entirely kernel-owned')
    if any(offset<start+bytes_ and start<offset+256 for start,bytes_ in other_spans):
        raise ValueError('UTC mailbox overlaps another kernel-owned channel')
    count,command_bytes=struct.unpack_from('<II',kernel,16);at=32;matches=[]
    if count>4096 or command_bytes>len(kernel)-32:raise ValueError('UTC Mach-O command bounds')
    for _ in range(count):
        kind,size=struct.unpack_from('<II',kernel,at)
        if size<8 or size>32+command_bytes-at:raise ValueError('UTC Mach-O command size')
        if kind==0x19:
            if size<72:raise ValueError('UTC truncated segment')
            segname=kernel[at+8:at+24].split(b'\0',1)[0]
            vm,vmsize,fileoff,filesize=struct.unpack_from('<4Q',kernel,at+24)
            _,prot,nsects,_=struct.unpack_from('<4I',kernel,at+56)
            if nsects>(size-72)//80:raise ValueError('UTC section table bounds')
            for n in range(nsects):
                sec=at+72+n*80;name=kernel[sec:sec+16].split(b'\0',1)[0]
                owner=kernel[sec+16:sec+32].split(b'\0',1)[0]
                start,bytes_,source=struct.unpack_from('<QQI',kernel,sec+32)
                flags=struct.unpack_from('<I',kernel,sec+64)[0]
                if start<=address and 256<=bytes_ and address-start<=bytes_-256:
                    if (segname!=b'__DATA' or owner!=b'__DATA' or name!=b'__data' or flags&0xff or
                        not prot&2 or prot&4 or vm>start or start-vm>vmsize or bytes_>vmsize-(start-vm) or
                        start-vm>filesize or bytes_>filesize-(start-vm) or source!=fileoff+start-vm):
                        raise ValueError('UTC mailbox must be writable file-backed __DATA,__data, never BSS')
                    source+=address-start
                    if source>len(kernel) or 256>len(kernel)-source:
                        raise ValueError('UTC mailbox initial bytes outside kernel file')
                    initial=bytes(kernel[source:source+256])
                    if initial!=struct.pack('<Q',0x50434c4f434b3031)+bytes(248):
                        raise ValueError('UTC mailbox exact native ABI initializer changed')
                    matches.append(dict(symbol='_polaris_uefi_clock',offset=offset,bytes=256,alignment=128,
                        segment='__DATA',section='__data',file_offset=source,
                        initial_sha256=hashlib.sha256(initial).hexdigest(),BSS=False))
        at+=size
    if len(matches)!=1:raise ValueError('UTC requires one actual file-backed native mailbox')
    return matches[0]


def battery_mailbox_binding(kernel,syms,va,end,other_spans):
    """Bound the actual native zero-fill span; publish only after native BSS init."""
    address=syms.get('_polaris_uefi_battery',0);offset=address-va
    if not address or offset%128 or not 0<=offset<=end-256:
        raise ValueError('battery mailbox must be aligned and entirely kernel-owned')
    if any(offset<start+bytes_ and start<offset+256 for start,bytes_ in other_spans):
        raise ValueError('battery mailbox overlaps another kernel-owned channel')
    count,command_bytes=struct.unpack_from('<II',kernel,16);at=32;matches=[]
    if count>4096 or command_bytes>len(kernel)-32:raise ValueError('battery Mach-O command bounds')
    for _ in range(count):
        kind,size=struct.unpack_from('<II',kernel,at)
        if size<8 or size>32+command_bytes-at:raise ValueError('battery Mach-O command size')
        if kind==0x19:
            if size<72:raise ValueError('battery truncated segment')
            segname=kernel[at+8:at+24].split(b'\0',1)[0]
            vm,vmsize,fileoff,filesize=struct.unpack_from('<4Q',kernel,at+24)
            _,prot,nsects,_=struct.unpack_from('<4I',kernel,at+56)
            if nsects>(size-72)//80:raise ValueError('battery section table bounds')
            for n in range(nsects):
                sec=at+72+n*80;name=kernel[sec:sec+16].split(b'\0',1)[0]
                owner=kernel[sec+16:sec+32].split(b'\0',1)[0]
                start,bytes_,source=struct.unpack_from('<QQI',kernel,sec+32)
                flags=struct.unpack_from('<I',kernel,sec+64)[0]
                if start<=address and 256<=bytes_ and address-start<=bytes_-256:
                    if (segname!=b'__DATA' or owner!=b'__DATA' or name not in (b'__bss',b'__common') or
                        flags&0xff!=1 or not prot&2 or prot&4 or vm>start or start-vm>vmsize or
                        bytes_>vmsize-(start-vm) or source):
                        raise ValueError('battery mailbox must be writable native __DATA zero-fill')
                    matches.append(dict(symbol='_polaris_uefi_battery',offset=offset,bytes=256,alignment=128,
                        segment='__DATA',section=name.decode(),BSS=True,pre_CPU_ON_publish=False))
        at+=size
    if len(matches)!=1:raise ValueError('battery requires one actual native zero-fill mailbox')
    return matches[0]


def runtime_services_intent(tree,battery,wifi):
    """Exact payload DT opt-ins; boot argument bytes are not edited here."""
    if type(battery) is not bool or type(wifi) is not bool:
        raise ValueError('runtime service intent must be explicit boolean flags')
    nodes=[n for n in tree.children if n.name=='polaris-runtime-services']
    if not nodes and not (battery or wifi):return None
    if len(nodes)!=1:raise ValueError('runtime services require one explicit payload DT node')
    node=nodes[0];props={name:value for name,_,value in node.props}
    expected={'name':b'polaris-runtime-services\0','version':struct.pack('<I',1),
        'battery-readonly':struct.pack('<I',int(battery)),'wifi-readonly':struct.pack('<I',int(wifi))}
    if (len(props)!=len(node.props) or props!=expected or node.children or
        any(flags for _,flags,_ in node.props)):
        raise ValueError('runtime service flags must exactly match canonical payload DT opt-ins')
    return dict(version=1,battery_readonly=battery,wifi_readonly=wifi,
        path='/polaris-runtime-services',boot_argument_tokens_changed=False)


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
    ap.add_argument('--test-wled-native-exit',choices=('delayed-footer','lost-receipt-recovery'),help='QEMU-only actual native-drain/terminal USB-response fixture; never physical USB emulation')
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
    ap.add_argument('--host-utc-sync',action='store_true',
                    help='default-OFF fixed host UTC metadata bridge; calendar RAM only, no RTC/CNT writes')
    ap.add_argument('--battery-readonly',action='store_true',
                    help='default-OFF real battery telemetry; exact native BSS and payload DT opt-in')
    ap.add_argument('--wifi-readonly',action='store_true',
                    help='default-OFF native Wi-Fi readonly diagnostic opt-in; no EFI SMEM or transmit API')
    ap.add_argument('--wifi-firmware-cache-pe',type=Path,
                    help='explicit exact own original SmemDxe PE for cache-only CPU0 image-RAM inspection; requires --wifi-readonly')
    ap.add_argument('--wifi-cpu0-firstread',action='store_true',
                    help='default-OFF one preboot CPU0 36B x2 SMEM read; exact original cache witness required; external SError is not recoverable')
    ap.add_argument('--wifi-cpu0-firstread-normal-nc',action='store_true',
                    help='default-OFF separate exactNormalNC44/NS/OuterShareable CPU0 read;18architecturalLDR max, not a buscap; original cache and guarded native runtime required')
    ap.add_argument('--audio-i2c-cache-pe',type=Path,
                    help='default-OFF exact original I2CDxe image-RAM cache witness; no I2C/DAL/MMIO/pointer follow; after completeWiFi diagnostics andbeforePON')
    ap.add_argument('--wifi-resources-readonly',action='store_true',
                    help='default-OFF exact combined pre-CPU_ON resource observation: two full maps and seven AFFINITY_INFO queries; no free/owner grant')
    ap.add_argument('--audio-clock-query-pe',type=Path,
                    help='default-OFF exact original ClockDxe readonly IsEnabled/IsOn queries; requires the combined resource/I2C/NC scope')
    ap.add_argument('--audio-clock-query-camera-readonly',action='store_true',
                    help='explicit two GCC camera-parent readonly targets plus seven blocked CAMCC descriptors; no CAMCC query, CCI or rail writer')
    ap.add_argument('--audio-clock-query-mss-readonly',action='store_true',
                    help='explicit three exact original MSS GCC branch readonly baselines; no cold-MSS MMIO, PLL, vote, reset or PIL write')
    ap.add_argument('--efi-application',action='store_true',help='selected application, never ReadyToBoot interception')
    ap.add_argument('--disk-guid',type=uuid.UUID,help='exact GPT partition UUID for read-only disk payload')
    ap.add_argument('--disk-start-lba',type=int)
    ap.add_argument('--disk-blocks',type=int)
    ap.add_argument('--disk-version',default='V0061')
    ap.add_argument('--chain-app-manifest',type=Path,help='RAM test wrapper for the exact already-built selected disk app')
    ap.add_argument('--original-gcd-query-pe',type=Path,help='default-OFF exact registered original DxeCore GCD getter; TPL/FP guarded')
    ap.add_argument('--audio-clock-gcd-query',action='store_true',help='default-OFF new GCD namespace plus actual DeviceNS AT Clock readonly scope')
    ap.add_argument('--wifi-npa-readonly-pe',type=Path,help='default-OFF original NpaDxe source-bound RAM namespace only; no NPA API/vote; requires whole GCD/Clock scope')
    ap.add_argument('--wifi-rpmh-readonly-pe',type=Path,help='default-OFF exact original RPMh init/DRV/TCS RAM baseline; NO provider API/client/MMIO/vote')
    ap.add_argument('--wifi-rpmh-private-client',action='store_true',help='default-OFF distinct pre-Clock original RPMh zero-vote private RAM client create/verify/retire; no commandset/MSS')
    ap.add_argument('--wifi-power-transaction-pe',type=Path,help='default-OFF NEW bounded private ARC path with exact original CmdDb source; offline link only until independent hardware ownership and NEW host admission')
    ap.add_argument('--wifi-power-cmddb-capture-only',action='store_true',help='default-OFF focused CmdDb namespace diagnostic; planned retirement before Query API, CPU critical admission or RSC access')
    ap.add_argument('--wifi-power-cmddb-bounded-gcd',action='store_true',help='default-OFF capture-only diagnostic using finite source-bound original Core RAM namespace; no original GCD query fallback')
    ap.add_argument('--wifi-power-cmddb-first-node-stop',action='store_true',help='default-OFF failure-isolation cutpoint: validate and retain first Core namespace node, then planned known-client retirement; NO database target load or full-namespace claim')
    ap.add_argument('--wifi-power-cmddb-budget-admission',action='store_true',help='default-OFF complete bounded capture with independent completed RO timing admission BEFORE private Create; estimate only, unchanged private/final 200ms and ownership gates')
    ap.add_argument('--wifi-power-cmddb-staged-ro',action='store_true',help='default-OFF four independent completed RO phases capture64KiB each before ANY private client; full two-pass namespaces/immediate source+AT guards and original200ms per ticket retained')
    ap.add_argument('--wifi-power-prepared-transaction',action='store_true',help='default-OFF distinct full staged RO then SAME current known-client/bounded RSC/completion/restore; new hardware/source admission still required')
    ap.add_argument('--wifi-power-current-arc-read',action='store_true',help='default-OFF same qualified private/CPU/Device interval: three bounded single-command READs and full restoration; RAW responses only, resource WRITE compiled unreachable in this scope')
    ap.add_argument('--wifi-cpu-ro-admission',action='store_true',help='default-OFF independent normal-IRQ seven-peer AFFINITY_INFO64 raw capture and full source/map retirement; NO private client, mask, TCS or READ')
    ap.add_argument('--wifi-cpu-masked-ro-admission',action='store_true',help='default-OFF fresh normal and masked seven-peer CPU-local observations, exact DAIF/G1/FP/source restoration and full independent RO retirement; NO private client/TCS/READ/vote or hardware grant')
    ap.add_argument('--wifi-power-current-arc-read-work-admission',action='store_true',help='default-OFF same complete private READ path; before mask compare all68 retired-RO timing samples, counted tail, full50ms READ and25ms reserve against remaining ORIGINAL200ms; estimate-only, no lease/deadline renewal')
    ap.add_argument('--wifi-power-private-cpu-checkpoint',action='store_true',help='default-OFF source-bound failure isolation: same real private/current namespace/fullRAM/Device/normal+masked CPU/complete restore/Delete before ANY RSC access/TCS store; no writer callback or fake engine retirement')
    ap.add_argument('--wifi-power-read-access-checkpoint',action='store_true',help='default-OFF same private CPU path plus full current masked CmdDb and checked RSC geometry reads/complete observation retirement; deny-only store callback, no engine or READ request')
    ap.add_argument('--wifi-power-read-database-checkpoint',action='store_true',help='default-OFF two full current masked CmdDb RAM captures and complete CPU/private retirement BEFORE first masked RSC MMIO read; no access acquisition or engine state')
    ap.add_argument('--wifi-power-terminal-gop-diagnostics',action='store_true',help='default-OFF bounded numeric UNKNOWN evidence in the current GOP framebuffer, no firmware/GOP method or USB/reset/cleanup on the terminal path; requires the explicit masked database diagnostic')
    ap.add_argument('--wifi-power-terminal-gop-own-wt',action='store_true',help='default-OFF exact own GOP PAR attribute0xBA Normal WT admission; original literal framebuffer/header/NS/RW/PA/PAR/CPU/hold gates unchanged, no mapping or radio permission change')
    ap.add_argument('--wifi-power-pre-mask-arguments',action='store_true',help='default-OFF normal-IRQ exact future access object ranges and full page AT/PAR evidence, complete current namespace/source/pool/client close and known Delete BEFORE CPU/masked access; no lease or subsequent READ permission')
    ap.add_argument('--wifi-power-normal-to-masked-database',action='store_true',help='default-OFF NEW same-private normal argument evidence then fresh original masked CPU/full CmdDb checks and complete retirement; normal evidence grants no masked access, original deadline/reserves unchanged, no masked RSC reader or engine')
    ap.add_argument('--wifi-power-cpu-live-diagnostics',action='store_true',help='default-OFF first failing original CPU live predicate and already returned tick sample; same fresh normal-to-masked DB scope and terminal GOP, no extra hardware reader, deadline or permission change')
    ap.add_argument('--wifi-power-db-word-capture',action='store_true',help='default-OFF aligned64-bit capture of the same two complete freshly NS/WB/PA/AT qualified Normal RAM databases; preserve every compared byte, delivered word and pending prefix, original200ms and full retirement; no Device/MMIO widening')
    ap.add_argument('--wifi-power-current-word-read',action='store_true',help='default-OFF separate fresh current private capture-only three bounded READs with normal argument admission, two complete masked word DBs, original CPU/time/IRQ/full restore and known Delete; RAW is not a qualified vote')
    ap.add_argument('--wifi-power-current-word-vote',action='store_true',help='default-OFF explicit fresh READ-derived HLOS/DRV2 ARC max(saved,target) raise and reverse saved restore, one combined READ+WRITE50ms interval, full touched-RW/CPU/source/namespace/Delete retirement; no MSS/NVserve/radio')
    ap.add_argument('--wifi-power-current-word-vote-latched',action='store_true',help='default-OFF same-fresh-retired-READ TCS completed high-latch ARC WRITE; low/readback before each of two new edges, retain final edge rather than write a third, preserve original IRQ enable/type and exact full retirement')
    ap.add_argument('--wifi-power-four-vrm-roundtrip',action='store_true',help='default-OFF independent fresh sixteen-field own WiFi VRM READ, ordered voltage/enable raise and reverse exact saved restore; one original combined interval and full CPU/source/private retirement, no ARC transaction or MSS/radio')
    ap.add_argument('--wifi-early-memory',action='store_true',help='default-OFF incoming UEFI independent retained MSA/RMTFS claims; original Core checks, no late remote-memory path, secure assignment or radio startup')
    ap.add_argument('--mss-memory',action='store_true',help='default-OFF independent modem120MiB, MBA1MiB and own metadata12KiB allocations after early MSA/RMTFS; retains all claims, no target access or remote startup')
    ap.add_argument('--mss-firmware-directory',type=Path,help='default-OFF embed already extracted verified own firmware and stage MBA/metadata into actual independent allocations; no secure assignment or remote start')
    ap.add_argument('--mss-firmware-in-payload',action='store_true',help='source verified own firmware from the exact appended RAM payload tail instead of embedding its bytes in EFI')
    ap.add_argument('--mss-mba-share',action='store_true',help='default-OFF native HLOS3 to MSS15 RW assignment of the actual staged MBA1MiB, retained descriptor/continuations and CPU restoration; no reset, power, free or remote start')
    ap.add_argument('--wifi-host-nonce-pool',action='store_true',help='generate a fresh private host-CSPRNG nonce input for this new temporary-boot candidate; requires digest-wide consumption before send; does not enable native WLAN')
    ap.add_argument('--wifi-native-auth-metadata-checkpoint',nargs='?',const='assigned',choices=['assigned','returned','copied','copy-ready','first-copy','first-rmb'],help='default-OFF terminal hold at an explicit metadata/copy/first-RMB boundary; never resume or call CPU_ON')
    ap.add_argument('--wifi-native-first-rmb-events',type=int,choices=range(1,7),help='first-rmb checkpoint only: terminal hold after exactly1..6 completed initial RMB operations; no retry/resume')
    ap.add_argument('--wifi-firmware-diagnostic-only',action='store_true',help='separate default-OFF RAM firmware diagnostic with mandatory authentication checkpoint and unconditional terminal hold before XNU/CPU_ON; USB payload only')
    ap.add_argument('--wifi-native-runtime',action='store_true',help='build the complete native radio/runtime and retained terminal path; does not grant physical boot admission')
    ap.add_argument('--wifi-nv-backup-directory',type=Path,help='private own GPT backup used only to generate expected identities; current NV is reread on each boot')
    ap.add_argument('--wifi-country',choices=['AU'],help='explicit country for the currently implemented native radio profile')
    ap.add_argument('--wifi-irq-provider-directory',type=Path,help='exact original Timer/GIC/CPU PEs for the explicit early-memory profile; inert binding input')
    a=ap.parse_args();r=Path(__file__).resolve().parents[1]
    if a.wifi_native_auth_metadata_checkpoint and not (a.wifi_native_runtime and a.wifi_power_terminal_gop_diagnostics):
        ap.error('auth metadata checkpoint requires native runtime and terminal GOP evidence')
    if (a.wifi_native_auth_metadata_checkpoint=='first-rmb')!=(a.wifi_native_first_rmb_events is not None):
        ap.error('first-rmb checkpoint and explicit1..6 first RMB events must be selected together')
    if a.wifi_firmware_diagnostic_only and (not a.wifi_native_auth_metadata_checkpoint or
        not a.wifi_native_runtime or not a.wifi_power_terminal_gop_diagnostics or a.disk_guid):
        ap.error('firmware-only diagnostic requires native runtime, authentication checkpoint, terminal GOP and USB RAM payload')
    if bool(a.wifi_nv_backup_directory)!=a.wifi_native_runtime or bool(a.wifi_country)!=a.wifi_native_runtime:
        ap.error('native runtime, own GPT backup and explicit country must be selected together')
    if a.wifi_native_runtime and (a.test_qemu or a.chain_app_manifest or a.physical_owned_marker or
        a.kernel_core!=7 or a.kernel_cpus!=4 or not all((a.mss_mba_share,a.mss_firmware_in_payload,a.wifi_host_nonce_pool,
            a.ram_shutdown_bridge,a.wled_native_runtime,a.physical_buttons,a.wifi_readonly))):
        ap.error('native Wi-Fi requires the complete physical RAM-only CPU700/MSS/nonce/shutdown/display/input profile')
    if a.mss_firmware_in_payload and not a.mss_firmware_directory:
        ap.error('--mss-firmware-in-payload requires verified own firmware directory')
    if a.mss_memory and not a.wifi_early_memory:
        ap.error('MSS memory requires the physical --wifi-early-memory parent')
    if a.mss_firmware_directory and not a.mss_memory:
        ap.error('MSS firmware staging requires --mss-memory')
    if a.mss_mba_share and not a.mss_firmware_directory:
        ap.error('MBA secure assignment requires the actual verified own firmware staging parent')
    if a.wifi_host_nonce_pool and not a.mss_mba_share:
        ap.error('Wi-Fi nonce input requires the actual independent MBA staging/assignment parent')
    if bool(a.wifi_irq_provider_directory)!=a.wifi_early_memory or (a.wifi_early_memory and
        (not a.wifi_power_four_vrm_roundtrip or a.test_qemu)):
        ap.error('early memory requires the full physical four-VRM scope and exact original IRQ-provider directory; no QEMU substitution')
    early_irq_header=None;early_irq_metadata=None;early_irq_inputs=[]
    if a.wifi_early_memory:
        try:
            directory=a.wifi_irq_provider_directory.resolve(strict=True)
            directory.relative_to(r)
            spec=importlib.util.spec_from_file_location('polaris_irq_identity',r/'tools/polaris-uefi-irq-provider-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            early_irq_header,early_irq_metadata=module.binding(directory)
            early_irq_inputs=[str((directory/item['file']).relative_to(r)) for item in early_irq_metadata]
        except (OSError,ValueError) as error:
            ap.error('early memory needs exact project-local original providers: '+str(error))
    if a.wifi_power_four_vrm_roundtrip and (not a.wifi_power_current_word_read or a.wifi_power_current_word_vote or a.wifi_power_current_word_vote_latched):
        ap.error('four VRM roundtrip requires the complete fresh current word/argument/CPU/DB/work scope and forbids the independent ARC vote scopes')
    if a.wifi_power_current_word_vote and not a.wifi_power_current_word_read:
        ap.error('current word ARC vote requires the explicit complete current word READ dependencies')
    if a.wifi_power_current_word_vote_latched and not a.wifi_power_current_word_vote:
        ap.error('completed-latch ARC vote requires the explicit fresh READ-derived vote scope')
    if a.wifi_power_read_access_checkpoint and not a.wifi_power_private_cpu_checkpoint:
        ap.error('read access checkpoint requires the complete same-private CPU checkpoint dependencies')
    if a.wifi_power_read_database_checkpoint and not a.wifi_power_read_access_checkpoint:
        ap.error('database checkpoint requires the complete same-private read observation dependencies')
    if a.wifi_power_terminal_gop_diagnostics and not (a.wifi_power_read_database_checkpoint or a.wifi_power_current_word_read):
        ap.error('terminal GOP evidence requires the explicit current masked database diagnostic scope')
    if a.wifi_power_terminal_gop_own_wt and not a.wifi_power_terminal_gop_diagnostics:
        ap.error('own GOP WT admission requires explicit terminal GOP diagnostics')
    if a.wifi_power_pre_mask_arguments and not (a.wifi_power_read_database_checkpoint or a.wifi_power_current_word_read):
        ap.error('pre-mask argument observation requires complete current private database dependencies')
    if a.wifi_power_normal_to_masked_database and not a.wifi_power_pre_mask_arguments:
        ap.error('normal-to-masked database observation requires fresh normal arguments and complete database dependencies')
    if a.wifi_power_cpu_live_diagnostics and not ((a.wifi_power_normal_to_masked_database or a.wifi_power_current_word_read) and a.wifi_power_terminal_gop_diagnostics):
        ap.error('CPU live diagnostics require the explicit normal-to-masked database scope and terminal GOP diagnostics')
    if a.wifi_power_db_word_capture and not a.wifi_power_cpu_live_diagnostics:
        ap.error('database word capture requires original CPU live diagnostics and the complete fresh normal-to-masked database scope')
    if a.wifi_power_current_word_read and (not (a.wifi_power_current_arc_read and a.wifi_power_current_arc_read_work_admission and
        a.wifi_power_pre_mask_arguments and a.wifi_power_cpu_live_diagnostics and a.wifi_power_db_word_capture and
        a.wifi_power_terminal_gop_diagnostics) or a.wifi_power_private_cpu_checkpoint or a.wifi_power_read_access_checkpoint or
        a.wifi_power_read_database_checkpoint or a.wifi_power_normal_to_masked_database or a.wifi_cpu_ro_admission or a.wifi_cpu_masked_ro_admission):
        ap.error('current word READ requires its explicit complete capture-only normal/CPU/DB/work/GOP dependencies and forbids checkpoint or independent CPU-RO scopes')
    if a.wifi_power_private_cpu_checkpoint and not a.wifi_power_current_arc_read_work_admission:
        ap.error('private CPU checkpoint requires the full prepared/current source and unchanged READ work admission dependencies')
    if a.wifi_power_current_arc_read_work_admission and not a.wifi_power_current_arc_read:
        ap.error('READ work admission requires the same full prepared/current capture-only READ scope')
    if a.wifi_cpu_masked_ro_admission and not a.wifi_cpu_ro_admission:
        ap.error('masked CPU RO requires the distinct independent CPU RO scope')
    if a.wifi_power_current_arc_read and not a.wifi_power_prepared_transaction:
        ap.error('current ARC READ requires the complete prepared/current private path')
    if a.test_wled_native_exit and (not a.wled_native_runtime_test or not a.test_qemu or
        a.test_ram_drain!='success' or a.test_wled_native_fault or a.test_wled_native_lifecycle or
        a.test_wled_native_start_refusal or a.test_wled_prepare_refusal or a.test_wled_status_after_issue or
        a.test_wled_write_timeout or a.test_wled_read_failure or a.test_wled_fault_pulse):
        ap.error('native WLED atomic exit requires only its independent QEMU runtime scope')
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
        a.test_wled_fault_pulse or a.test_omit_durable_guard or a.test_wled_native_start_refusal or a.test_wled_native_exit):
        ap.error('physical native WLED requires its independent guarded four-big RO/RAMCOW scope')
    native_runtime=a.wled_native_runtime or a.wled_native_runtime_test
    if a.wifi_cpu0_firstread and a.wifi_cpu0_firstread_normal_nc:
        ap.error('Device-only and exactNormalNC firstread flags are mutually exclusive')
    if a.wifi_cpu0_firstread_normal_nc and (not a.wifi_firmware_cache_pe or not a.wifi_readonly or not native_runtime):
        ap.error('NormalNC CPU0 first-read requires exact --wifi-firmware-cache-pe, --wifi-readonly and guarded native runtime')
    if a.wifi_cpu0_firstread and (not a.wifi_firmware_cache_pe or not a.wifi_readonly or not native_runtime):
        ap.error('CPU0 first-read requires exact --wifi-firmware-cache-pe, --wifi-readonly and guarded native runtime')
    combined_resources=bool(a.wifi_resources_readonly or a.audio_clock_query_pe or a.audio_clock_query_camera_readonly or a.audio_clock_query_mss_readonly)
    if combined_resources and (not a.wifi_resources_readonly or not a.audio_clock_query_pe or
        not a.audio_clock_query_camera_readonly or not a.audio_clock_query_mss_readonly or not a.audio_i2c_cache_pe or
        not a.wifi_cpu0_firstread_normal_nc or not a.wifi_firmware_cache_pe or not a.wifi_readonly or not native_runtime):
        ap.error('resource/Clock queries require the explicit combined exact NC, SmemDxe, I2CDxe, ClockDxe and GCC readonly scope')
    gcd_enabled=bool(a.original_gcd_query_pe or a.audio_clock_gcd_query)
    if gcd_enabled and (not a.original_gcd_query_pe or not a.audio_clock_gcd_query or not combined_resources):
        ap.error('NEW GCD/Clock requires both explicit flags and the complete original-resource/NC/I2C/Clock scope')
    if a.wifi_cpu_ro_admission and (not gcd_enabled or a.wifi_npa_readonly_pe or a.wifi_rpmh_readonly_pe or
        a.wifi_rpmh_private_client or a.wifi_power_transaction_pe or a.wifi_power_current_arc_read or
        a.wifi_power_prepared_transaction or a.wifi_power_cmddb_capture_only or a.wifi_power_cmddb_bounded_gcd or
        a.wifi_power_cmddb_staged_ro or a.wifi_power_cmddb_budget_admission or a.wifi_power_cmddb_first_node_stop):
        ap.error('CPU RO qualification requires its independent GCD/Clock scope, never a private/READ/NPA/RPMh inventory scope')
    gcd_header=None;gcd_binding=None;gcd_pe_relative=None
    if gcd_enabled:
        try:
            gcd_pe=a.original_gcd_query_pe.resolve(strict=True);gcd_pe_relative=str(gcd_pe.relative_to(r))
            spec=importlib.util.spec_from_file_location('polaris_gcd_identity',r/'tools/polaris-uefi-gcd-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            gcd_header,gcd_binding=module.binding(gcd_pe)
            gcd_binding['binding_sha256']=hashlib.sha256(gcd_header.encode()).hexdigest()
        except (OSError,ValueError) as error:
            ap.error('GCD query PE must be the exact original project-local image: '+str(error))
    if a.wifi_rpmh_private_client and not (gcd_enabled and a.wifi_rpmh_readonly_pe and a.wifi_npa_readonly_pe):
        ap.error('private RAM client requires complete source-bound original GCD/Clock/NPA/RPMh scope')
    cmddb_header=None;cmddb_binding=None;cmddb_pe_relative=None
    namespace_header=None;namespace_binding=None
    if a.wifi_power_cmddb_first_node_stop and not a.wifi_power_cmddb_bounded_gcd:
        ap.error('first-node planned stop requires the explicit bounded capture-only scope')
    if a.wifi_power_prepared_transaction and (not a.wifi_power_cmddb_staged_ro or a.wifi_power_cmddb_capture_only):
        ap.error('prepared transaction requires full staged RO and its distinct writer scope, not a capture-only label')
    if a.wifi_power_cmddb_staged_ro and (not a.wifi_power_cmddb_bounded_gcd or a.wifi_power_cmddb_first_node_stop or a.wifi_power_cmddb_budget_admission):
        ap.error('staged RO preparation requires its distinct full bounded capture, never an old first-node or budget scope')
    if a.wifi_power_cmddb_budget_admission and (not a.wifi_power_cmddb_bounded_gcd or a.wifi_power_cmddb_first_node_stop):
        ap.error('work admission requires the distinct full bounded capture, never first-node mode')
    if a.wifi_power_cmddb_bounded_gcd:
        if (not a.wifi_power_cmddb_capture_only and not a.wifi_power_prepared_transaction) or not gcd_binding:
            ap.error('bounded GCD namespace requires explicit capture-only and exact original Core binding')
        spec=importlib.util.spec_from_file_location('polaris_wifi_gcd_namespace_identity',r/'tools/polaris-wifi-gcd-namespace-identity.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        namespace_header,namespace_binding=module.binding(gcd_pe)
        namespace_binding['binding_SHA256']=hashlib.sha256(namespace_header.encode()).hexdigest()
    if a.wifi_power_cmddb_capture_only and not a.wifi_power_transaction_pe:
        ap.error('CmdDb capture-only requires the separately bound original power-parent scope')
    if a.wifi_power_transaction_pe:
        if not a.wifi_rpmh_private_client:ap.error('NEW power path requires the explicit original private-client scope')
        try:
            cmddb_pe=a.wifi_power_transaction_pe.resolve(strict=True);cmddb_pe_relative=str(cmddb_pe.relative_to(r))
            spec=importlib.util.spec_from_file_location('polaris_wifi_cmddb_identity',r/'tools/polaris-wifi-cmddb-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            cmddb_header,cmddb_binding=module.binding(cmddb_pe)
            cmddb_binding['binding_sha256']=hashlib.sha256(cmddb_header.encode()).hexdigest()
        except (OSError,ValueError) as error:
            ap.error('CmdDb must be the exact own original project-local PE: '+str(error))
    rpmh_header=None;rpmh_binding=None;rpmh_pe_relative=None
    if a.wifi_rpmh_readonly_pe:
        if not gcd_enabled:ap.error('RPMh baseline requires complete original GCD/Clock scope')
        try:
            rpmh_pe=a.wifi_rpmh_readonly_pe.resolve(strict=True);rpmh_pe_relative=str(rpmh_pe.relative_to(r))
            spec=importlib.util.spec_from_file_location('polaris_wifi_rpmh_identity',r/'tools/polaris-wifi-rpmh-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            rpmh_header,rpmh_binding=module.binding(rpmh_pe)
            rpmh_binding['binding_sha256']=hashlib.sha256(rpmh_header.encode()).hexdigest()
        except (ValueError,OSError) as error:
            ap.error('RPMh source must be exact project-local original PE: '+str(error))
    npa_header=None;npa_binding=None;npa_pe_relative=None
    if a.wifi_npa_readonly_pe:
        if not gcd_enabled:ap.error('NPA RAM namespace requires the complete original GCD/Clock scope')
        try:
            npa_pe=a.wifi_npa_readonly_pe.resolve(strict=True);npa_pe_relative=str(npa_pe.relative_to(r))
            spec=importlib.util.spec_from_file_location('polaris_wifi_npa_identity',r/'tools/polaris-wifi-npa-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            npa_header,npa_binding=module.binding(npa_pe)
            npa_binding['binding_sha256']=hashlib.sha256(npa_header.encode()).hexdigest()
        except (OSError,ValueError) as error:
            ap.error('NPA RAM source must be the exact original project-local PE: '+str(error))
    audio_clock_header=None;audio_clock_binding=None;audio_clock_pe_relative=None
    if a.audio_clock_query_pe:
        try:
            clock_pe=a.audio_clock_query_pe.resolve(strict=True)
            audio_clock_pe_relative=str(clock_pe.relative_to(r))
            spec=importlib.util.spec_from_file_location('polaris_audio_clock_identity',r/'tools/polaris-audio-clock-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            audio_clock_header,audio_clock_binding=module.binding(clock_pe)
            audio_clock_binding['binding_sha256']=hashlib.sha256(audio_clock_header.encode()).hexdigest()
        except (OSError,ValueError) as error:
            ap.error('Clock query PE must be the exact original project-local image: '+str(error))
    audio_header=None;audio_binding=None;audio_pe_relative=None
    if a.audio_i2c_cache_pe:
        if not native_runtime or not a.wifi_readonly or not a.wifi_firmware_cache_pe:
            ap.error('audio I2C cache requires guarded native runtime and exact WiFi cache diagnostics ordering')
        try:
            audio_pe=a.audio_i2c_cache_pe.resolve(strict=True)
            audio_pe_relative=str(audio_pe.relative_to(r))
            spec=importlib.util.spec_from_file_location('polaris_audio_i2c_firmware_identity',r/'tools/polaris-audio-i2c-firmware-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            audio_header,audio_binding=module.binding(audio_pe)
            audio_binding['binding_sha256']=hashlib.sha256(audio_header.encode()).hexdigest()
        except (OSError,ValueError) as error:
            ap.error('audio I2C cache PE must be the exact original project-local image: '+str(error))
    cache_header=None;cache_binding=None;cache_pe_relative=None
    if a.wifi_firmware_cache_pe:
        if not a.wifi_readonly or not native_runtime:
            ap.error('firmware cache inspection requires --wifi-readonly and its guarded native runtime scope')
        try:
            cache_pe=a.wifi_firmware_cache_pe.resolve(strict=True)
            cache_pe_relative=str(cache_pe.relative_to(r))
            spec=importlib.util.spec_from_file_location('polaris_wifi_firmware_identity',r/'tools/polaris-wifi-firmware-identity.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            cache_header,cache_binding=module.binding(cache_pe)
            cache_binding['binding_sha256']=hashlib.sha256(cache_header.encode()).hexdigest()
        except (OSError,ValueError) as error:
            ap.error('firmware cache PE must be the exact original project-local image: '+str(error))
    if a.host_utc_sync and (not native_runtime or not a.physical_buttons or
        not (a.test_ram_drain if a.test_qemu else a.ram_shutdown_bridge) or
        a.test_qemu_owned or a.physical_owned_marker or a.disk_guid or a.chain_app_manifest or a.efi_application):
        ap.error('host UTC metadata requires its guarded native WLED RO/RAMCOW session and native drain')
    if (a.battery_readonly or a.wifi_readonly) and (not native_runtime or not a.physical_buttons or
        not (a.test_ram_drain if a.test_qemu else a.ram_shutdown_bridge) or
        a.test_qemu_ufs or a.test_qemu_owned or a.physical_owned_marker or a.disk_guid or
        a.chain_app_manifest or a.efi_application):
        ap.error('runtime service opt-ins require the guarded native WLED RO/RAMCOW session and drain')
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
    wifi_runtime_header=None;wifi_runtime_metadata=None;wifi_runtime_inputs=[]
    if a.wifi_native_runtime:
        backup=a.wifi_nv_backup_directory.resolve(strict=True)
        backup.relative_to(r)
        spec=importlib.util.spec_from_file_location('polaris_nv_plan',r/'tools/polaris-nv-plan.py')
        nv_packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(nv_packager)
        nv_packager.build(backup,out/'wifi-nv')
        wifi_runtime_inputs=['tools/polaris-nv-plan.py','tools/polaris-wifi-runtime-config.py',
            'tools/polaris-wifi-kernel-binding.py']
        wifi_runtime_inputs += [str((backup/name).relative_to(r)) for name in
            ('layout.json','manifest.json','sde.head.bin','sde.tail.bin','sdf.head.bin','sdf.tail.bin')]
    wifi_nonce_metadata=None
    if a.wifi_host_nonce_pool:
        spec=importlib.util.spec_from_file_location('polaris_wifi_nonce',r/'tools/polaris-wifi-nonce-pool.py')
        nonce_packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(nonce_packager)
        nonce_packager.create(out/'wifi-nonce')
        nonce_header,wifi_nonce_metadata=nonce_packager.binding(out/'wifi-nonce')
        nonce_packager.write_exclusive(out/'uefi-wifi-image-nonce-pool.h',nonce_header.encode())
    mss_firmware=None;mss_inputs=[]
    if a.mss_firmware_directory:
        spec=importlib.util.spec_from_file_location('polaris_mss_firmware',r/'tools/polaris-mss-firmware.py')
        mss_packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(mss_packager)
        mss_firmware=mss_packager.package(a.mss_firmware_directory,out/'mss-firmware')
        mss_inputs=['tools/polaris-mss-firmware.py','tools/polaris-mss-memory-codec.py','tools/polaris-mss-stage-codec.py',
                    str((a.mss_firmware_directory.resolve()/'proof.json').relative_to(r))]
        mss_inputs += [str((a.mss_firmware_directory.resolve()/name).relative_to(r)) for name in mss_firmware['source_files']]
    if early_irq_header:
        (out/'uefi-wifi-irq-source-binding.h').write_text(early_irq_header)
        (out/'wifi-irq-provider-binding.json').write_text(json.dumps(early_irq_metadata,indent=2)+'\n')
    if cache_binding:
        (out/'uefi-wifi-cache-binding.h').write_text(cache_header)
        (out/'wifi-firmware-cache-binding.json').write_text(json.dumps(cache_binding,indent=2)+'\n')
    if audio_binding:
        (out/'uefi-audio-i2c-cache-binding.h').write_text(audio_header)
        (out/'audio-i2c-cache-binding.json').write_text(json.dumps(audio_binding,indent=2)+'\n')
    if audio_clock_binding:
        (out/'uefi-audio-clock-binding.h').write_text(audio_clock_header)
        (out/'audio-clock-query-binding.json').write_text(json.dumps(audio_clock_binding,indent=2)+'\n')
    if gcd_binding:
        (out/'uefi-gcd-core-binding.h').write_text(gcd_header)
        (out/'original-gcd-query-binding.json').write_text(json.dumps(gcd_binding,indent=2)+'\n')
    if rpmh_binding:
        (out/'uefi-wifi-rpmh-binding.h').write_text(rpmh_header)
        (out/'wifi-rpmh-binding.json').write_text(json.dumps(rpmh_binding,indent=2)+'\n')
    if npa_binding:
        (out/'uefi-wifi-npa-binding.h').write_text(npa_header)
        (out/'wifi-npa-binding.json').write_text(json.dumps(npa_binding,indent=2)+'\n')
    if cmddb_binding:
        (out/'uefi-wifi-cmddb-binding.h').write_text(cmddb_header)
        (out/'wifi-cmddb-binding.json').write_text(json.dumps(cmddb_binding,indent=2)+'\n')
    if namespace_binding:
        (out/'uefi-wifi-gcd-namespace-binding.h').write_text(namespace_header)
        (out/'wifi-gcd-namespace-binding.json').write_text(json.dumps(namespace_binding,indent=2)+'\n')
    raw=a.payload.read_bytes();k=a.kernel.read_bytes()
    mss_payload_transport=None
    if a.mss_firmware_in_payload:
        mss_payload_transport=mss_packager.payload_transport(raw,mss_firmware)
        mss_firmware['payload_transport']=mss_payload_transport
        (out/'mss-firmware/manifest.json').write_text(json.dumps(mss_firmware,indent=2)+'\n')
    sys.path.insert(0,str(r/'tools'));import mkpayload
    tokens=raw[0x48:0x2a8].split(b'\0',1)[0].split()
    if [t for t in tokens if t.startswith(b'polariswifi=')]!=([b'polariswifi=1'] if a.wifi_native_runtime else []):
        raise ValueError('native Wi-Fi boot token must match the explicit complete runtime build')
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
    runtime_services=runtime_services_intent(tree,a.battery_readonly,a.wifi_readonly)
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
    clock_binding=None
    reserved=[(input_offset,256),(shutdown_offset,256),(buttons_offset,256),(wled_offset,256),
        (log,4<<20),(total,8)]
    battery_span=[(syms['_polaris_uefi_battery']-va,256)] if '_polaris_uefi_battery' in syms else []
    if a.host_utc_sync:
        clock_binding=clock_mailbox_binding(k,syms,va,end,reserved+battery_span)
    battery_binding=None
    if a.battery_readonly:
        clock_span=[(syms['_polaris_uefi_clock']-va,256)] if '_polaris_uefi_clock' in syms else []
        battery_binding=battery_mailbox_binding(k,syms,va,end,reserved+clock_span)
    if a.wifi_native_runtime:
        spec=importlib.util.spec_from_file_location('polaris_wifi_runtime_config',r/'tools/polaris-wifi-runtime-config.py')
        wifi_runtime_packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(wifi_runtime_packager)
        runtime_reserved=[(input_offset,256),(buttons_offset,256),(wled_offset,256),(log,4<<20),(total,8)]
        runtime_reserved += [(syms[name]-va,256) for name in ('_polaris_uefi_clock','_polaris_uefi_battery') if name in syms]
        wifi_runtime_header,wifi_runtime_metadata=wifi_runtime_packager.binding(k,va,end,runtime_reserved,a.wifi_country)
        if wifi_runtime_metadata['shutdown']['offset']!=shutdown_offset:
            raise ValueError('native terminal binding differs from the actual shutdown symbol')
        (out/'uefi-wifi-native-runtime-config.h').write_text(wifi_runtime_header)
        (out/'wifi-native-runtime-binding.json').write_text(json.dumps(wifi_runtime_metadata,indent=2)+'\n')
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
#define EFI_XNU_HOST_UTC_AVAILABLE {int(a.host_utc_sync)}
#define EFI_XNU_HOST_UTC_OFFSET 0x{clock_binding['offset'] if clock_binding else 0:x}ULL
#define EFI_XNU_BATTERY_AVAILABLE {int(a.battery_readonly)}
#define EFI_XNU_BATTERY_OFFSET 0x{battery_binding['offset'] if battery_binding else 0:x}ULL
#define EFI_XNU_BATTERY_SPAN_LIMIT_US 500000u
#define EFI_XNU_WIFI_CACHE_AVAILABLE {int(cache_binding is not None)}
#define EFI_XNU_WIFI_FIRSTREAD_AVAILABLE {int(a.wifi_cpu0_firstread)}
#define EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE {int(a.wifi_cpu0_firstread_normal_nc)}
#define EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE {int(audio_binding is not None)}
#define EFI_XNU_WIFI_RESOURCES_AVAILABLE {int(a.wifi_resources_readonly)}
#define EFI_XNU_GCD_MMIO_QUERY_AVAILABLE {int(gcd_enabled)}
#define EFI_XNU_WIFI_NPA_READONLY_AVAILABLE {int(npa_binding is not None)}
#define EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE {int(rpmh_binding is not None)}
#define EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE {int(a.wifi_rpmh_private_client)}
#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE {int(cmddb_binding is not None)}
#define EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY {int(a.wifi_power_cmddb_capture_only)}
#define EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE {int(a.wifi_power_cmddb_bounded_gcd)}
#define EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP {int(a.wifi_power_cmddb_first_node_stop)}
#define EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION {int(a.wifi_power_cmddb_budget_admission)}
#define EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE {int(a.wifi_power_cmddb_staged_ro)}
#define EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE {int(a.wifi_power_prepared_transaction)}
#define EFI_XNU_WIFI_ARC_READ_AVAILABLE {int(a.wifi_power_current_arc_read)}
#define EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY {1-int(a.wifi_power_current_word_vote)}
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION {int(a.wifi_power_current_arc_read_work_admission)}
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT {int(a.wifi_power_private_cpu_checkpoint)}
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT {int(a.wifi_power_read_access_checkpoint)}
#define EFI_XNU_WIFI_READ_DB_CHECKPOINT {int(a.wifi_power_read_database_checkpoint)}
#define EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS {int(a.wifi_power_terminal_gop_diagnostics)}
#define EFI_XNU_WIFI_TERMINAL_GOP_OWN_WT {int(a.wifi_power_terminal_gop_own_wt)}
#define EFI_XNU_WIFI_PRE_MASK_ARGUMENTS {int(a.wifi_power_pre_mask_arguments)}
#define EFI_XNU_WIFI_NORMAL_TO_MASKED_DB {int(a.wifi_power_normal_to_masked_database)}
#define EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS {int(a.wifi_power_cpu_live_diagnostics)}
#define EFI_XNU_WIFI_DB_WORD_CAPTURE {int(a.wifi_power_db_word_capture)}
#define EFI_XNU_WIFI_CURRENT_WORD_READ {int(a.wifi_power_current_word_read)}
#define EFI_XNU_WIFI_CURRENT_WORD_VOTE {int(a.wifi_power_current_word_vote)}
#define EFI_XNU_WIFI_CURRENT_WORD_VOTE_LATCHED {int(a.wifi_power_current_word_vote_latched)}
#define EFI_XNU_WIFI_FOUR_VRM_AVAILABLE {int(a.wifi_power_four_vrm_roundtrip)}
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 0
#define EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE {int(a.wifi_early_memory)}
#define EFI_XNU_MSS_MEMORY_AVAILABLE {int(a.mss_memory)}
#define EFI_XNU_MSS_STAGING_AVAILABLE {int(bool(a.mss_firmware_directory))}
#define EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE {int(a.mss_firmware_in_payload)}
#define EFI_XNU_MSS_FIRMWARE_OFFSET {mss_payload_transport['offset'] if mss_payload_transport else 0}u
#define EFI_XNU_MSS_PAYLOAD_FW_BYTES {mss_firmware['bytes'] if mss_payload_transport else 0}u
#define EFI_XNU_MSS_MBA_SHARE_AVAILABLE {int(a.mss_mba_share)}
#define EFI_XNU_WIFI_NONCE_POOL_AVAILABLE {int(a.wifi_host_nonce_pool)}
#define EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE {int(a.mss_mba_share)}
#define EFI_XNU_MSS_METADATA_BYTES 8412u
#define EFI_XNU_WIFI_CPU_RO_ADMISSION {int(a.wifi_cpu_ro_admission)}
#define EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION {int(a.wifi_cpu_masked_ro_admission)}
#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE {int(cmddb_binding is not None)}
#define EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE {int(gcd_enabled)}
#define EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE {int(audio_clock_binding is not None)}
#define EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY {int(a.audio_clock_query_camera_readonly)}
#define EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY {int(a.audio_clock_query_mss_readonly)}
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
    if a.wifi_native_auth_metadata_checkpoint:
        auth_checkpoint_mode={'assigned':1,'returned':2,'copied':3,'copy-ready':4,'first-copy':5,'first-rmb':6}[a.wifi_native_auth_metadata_checkpoint]
        with config.open('a') as f:f.write(f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {auth_checkpoint_mode}\n')
    if a.wifi_native_first_rmb_events is not None:
        with config.open('a') as f:f.write(f'#define EFI_XNU_WIFI_FIRST_RMB_EVENTS {a.wifi_native_first_rmb_events}\n')
    if a.wifi_firmware_diagnostic_only:
        with config.open('a') as f:f.write('#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1\n')
    if a.wifi_native_runtime:
        with config.open('a') as f:f.write('#include "uefi-wifi-native-runtime-config.h"\n')
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
    if a.test_wled_native_exit:
        flags.append('-DEFI_XNU_WLED_NATIVE_EXIT_TEST='+str(('delayed-footer','lost-receipt-recovery').index(a.test_wled_native_exit)+1))
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
    if a.wifi_power_terminal_gop_diagnostics:inputs.append('shim/polaris/uefi-wifi-terminal-gop.h')
    if a.wifi_power_pre_mask_arguments:
        inputs+=['shim/polaris/uefi-wifi-pre-mask-arguments.h','shim/polaris/uefi-wifi-cpu-readonly.h']
    if a.wifi_power_cpu_live_diagnostics:inputs.append('shim/polaris/uefi-wifi-cpu-live-diagnostics.h')
    if cache_binding:
        inputs+=['shim/polaris/uefi-wifi-cache-readonly.h','tools/polaris-wifi-firmware-identity.py',
                 'tools/polaris-wifi-firmware-identity.h',cache_pe_relative]
    if a.wifi_cpu0_firstread:inputs.append('shim/polaris/uefi-wifi-firstread.h')
    if a.wifi_cpu0_firstread_normal_nc:inputs.append('shim/polaris/uefi-wifi-firstread-normal-nc.h')
    if a.wifi_resources_readonly:inputs.append('shim/polaris/uefi-wifi-resources-readonly.h')
    if audio_binding:
        inputs+=['shim/polaris/uefi-audio-i2c-cache.h','tools/polaris-audio-i2c-firmware-identity.py',
                 'tools/polaris-audio-i2c-firmware-identity.h',audio_pe_relative]
    if audio_clock_binding:
        inputs+=[('shim/polaris/uefi-audio-clock-gcd-query.h' if gcd_binding else 'shim/polaris/uefi-audio-clock-query.h'),'tools/polaris-audio-clock-identity.py',
                 'tools/polaris-audio-clock-identity.h',audio_clock_pe_relative]
    if a.wifi_rpmh_private_client:inputs+=['shim/polaris/uefi-wifi-rpmh-client.h']
    if cmddb_binding:
        inputs+=['shim/polaris/uefi-wifi-power-path.h','shim/polaris/uefi-wifi-rsc-access.h',
                 'shim/polaris/uefi-wifi-power-critical.h','shim/polaris/uefi-wifi-rsc-baseline.h',
                 'shim/polaris/uefi-wifi-rsc-device.h','shim/polaris/uefi-wifi-cmddb-query.h',
                 'tools/polaris-wifi-rsc-transaction.h','tools/polaris-wifi-cmddb-identity.h',
                 'tools/polaris-wifi-cmddb-identity.py',cmddb_pe_relative]
    if namespace_binding:
        inputs+=['shim/polaris/uefi-wifi-gcd-namespace.h','tools/polaris-wifi-gcd-namespace-identity.py']
    if cmddb_binding:inputs+=['shim/polaris/uefi-wifi-cmddb-budget.h','shim/polaris/uefi-wifi-cmddb-staged.h','shim/polaris/uefi-wifi-cmddb-prepared.h']
    if a.wifi_power_cmddb_staged_ro:inputs+=['shim/polaris/uefi-wifi-gcd-ro-owner.h']
    if a.wifi_cpu_ro_admission:inputs+=['shim/polaris/uefi-wifi-cpu-readonly.h','shim/polaris/uefi-wifi-psci-affinity.h']
    if cmddb_binding:inputs+=['shim/polaris/uefi-wifi-psci-affinity.h','shim/polaris/uefi-wifi-cpu-local-mask.h']
    if a.wifi_cpu_masked_ro_admission:inputs+=['shim/polaris/uefi-wifi-cpu-local-mask.h']
    if a.wifi_power_current_arc_read:inputs+=['shim/polaris/uefi-wifi-rsc-read-plan.h','tools/polaris-wifi-rsc-read.h']
    if a.wifi_power_four_vrm_roundtrip:
        inputs+=['shim/polaris/uefi-wifi-vrm-domain.h','shim/polaris/uefi-wifi-vrm-access.h',
                 'tools/polaris-wifi-vrm-read.h','tools/polaris-wifi-vrm-transaction.h']
    if rpmh_binding:
        inputs+=['shim/polaris/uefi-wifi-rpmh-readonly.h','tools/polaris-wifi-rpmh-identity.py',
                 'tools/polaris-wifi-rpmh-identity.h',rpmh_pe_relative]
    if npa_binding:
        inputs+=['shim/polaris/uefi-wifi-npa-readonly.h','tools/polaris-wifi-npa-identity.py',
                 'tools/polaris-wifi-npa-identity.h',npa_pe_relative]
    if gcd_binding:
        inputs+=['shim/polaris/uefi-gcd-mmio-readonly.h','shim/polaris/gcd-core-identity.h',
                 'tools/polaris-uefi-gcd-identity.py',gcd_pe_relative]
    if a.host_utc_sync:
        inputs+=['tools/polaris-clock-sync.h','tools/polaris-clock-uefi.h',
                 'tools/polaris-clock-native.h','tools/polaris-clock-host.py']
    if a.battery_readonly:
        inputs+=['shim/polaris/uefi-battery-native.h','tools/polaris-battery-shared.h',
                 'tools/polaris-battery-readonly.h','tools/polaris-battery-producer.h',
                 'tools/polaris-battery-native.cpp']
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
    if a.mss_memory:inputs+=['tools/polaris-mss-memory-codec.py']
    if a.mss_mba_share:inputs+=['tools/polaris-mss-mba-share-codec.py']
    if a.wifi_host_nonce_pool:inputs+=['tools/polaris-wifi-nonce-pool.py']
    if a.wifi_native_runtime:
        inputs+=wifi_runtime_inputs
        flags+=['-DPOLARIS_WIFI_GLINK_FREESTANDING=1','-I'+str(out/'wifi-nv'),
            '-I'+str(r/'tools'),'-I'+str(r/'shim/polaris')]
    if mss_firmware:
        inputs+=mss_inputs
        flags+=['-I'+str(out/'mss-firmware'),'-I'+str(r/'shim/polaris')]
    if a.wifi_early_memory:
        inputs+=['tools/polaris-uefi-irq-provider-identity.py','tools/polaris-wifi-early-codec.py',*early_irq_inputs]
    for source in sources:
        obj=out/(Path(source).stem+'.obj');objects.append(str(obj))
        cmd=['/usr/bin/clang','--target=aarch64-unknown-windows','-ffreestanding','-fno-builtin','-fno-stack-protector','-fshort-wchar','-mgeneral-regs-only','-O2','-Wall','-Wextra','-Werror',*flags,'-I'+str(out),'-c',str(r/'shim/polaris'/source),'-o',str(obj)]
        if a.wifi_early_memory:cmd+=['-Wframe-larger-than=1024','-MMD','-MF',str(obj.with_suffix('.d'))]
        p=subprocess.run(cmd,capture_output=True);(out/(source+'.log')).write_bytes(p.stdout+p.stderr)
        if p.returncode:raise RuntimeError('EFI module compile failed: '+source)
        if a.wifi_early_memory:
            dependencies=obj.with_suffix('.d').read_text().replace('\\\n',' ')
            for name in shlex.split(dependencies.split(':',1)[1]):
                path=Path(name).resolve()
                if path.is_relative_to(out):continue # generated bindings recorded separately
                if not path.is_relative_to(r):raise ValueError('untracked external early-profile source: '+str(path))
                inputs.append(str(path.relative_to(r)))
    if a.wifi_native_runtime:
        for name in wifi_runtime_packager.SOURCES:
            source=r/'tools'/name;obj=out/(source.stem+'.obj');objects.append(str(obj));inputs.append(str(source.relative_to(r)))
            cmd=['/usr/bin/clang','--target=aarch64-unknown-windows','-ffreestanding','-fno-builtin',
                '-fno-stack-protector','-fshort-wchar','-mgeneral-regs-only','-O2','-Wall','-Wextra','-Werror',
                '-Wframe-larger-than=1024',*flags,'-I'+str(out),'-MMD','-MF',str(obj.with_suffix('.d')),
                '-c',str(source),'-o',str(obj)]
            p=subprocess.run(cmd,capture_output=True);(out/(name+'.log')).write_bytes(p.stdout+p.stderr)
            if p.returncode:raise RuntimeError('native Wi-Fi module compile failed: '+name)
            dependencies=obj.with_suffix('.d').read_text().replace('\\\n',' ')
            for dependency in shlex.split(dependencies.split(':',1)[1]):
                path=Path(dependency).resolve()
                if path.is_relative_to(out):continue
                if not path.is_relative_to(r):raise ValueError('untracked external Wi-Fi source: '+str(path))
                inputs.append(str(path.relative_to(r)))
    if mss_firmware and not a.mss_firmware_in_payload:
        obj=out/'mss-firmware.obj'
        p=subprocess.run(['/usr/bin/clang','--target=aarch64-unknown-windows','-c',str(out/'mss-firmware/mss-firmware.S'),'-o',str(obj)],capture_output=True)
        (out/'mss-firmware-compile.log').write_bytes(p.stdout+p.stderr)
        if p.returncode:raise RuntimeError('own firmware data object compile failed')
        objects.append(str(obj))
    application=a.test_qemu or a.efi_application
    image=out/('PolarisXnuTest.efi' if a.test_qemu else 'PolarisIos.efi' if application else 'PolarisChainDxe.efi' if chain else 'PolarisXnuDxe.efi')
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    p=subprocess.run([str(a.zig.resolve()),'build-exe',*objects,'-target','aarch64-uefi','--subsystem','efi_application' if application else 'efi_boot_service_driver','-O','ReleaseSmall','-femit-bin='+str(image)],env=env,capture_output=True)
    (out/'link.log').write_bytes(p.stdout+p.stderr)
    if p.returncode:raise RuntimeError('EFI link failed')
    mss_bss=mss_zero_storage(image) if a.mss_firmware_in_payload else None
    manifest=dict(artifact=image.name,sha256=sha(image),bytes=image.stat().st_size,
                  kernel_sha256=sha(a.kernel),payload_sha256=sha(a.payload),payload_bytes=len(raw),
                  payload_crc32=zlib.crc32(raw),payload_C_admission=True,rebased_kernel_bytes_match=True,
                  RAM_only_XNU_loader=not a.physical_owned_marker,kernel_handoff=not (wled_hold or a.wifi_firmware_diagnostic_only),storage_write_api=False,NVRAM_write_api=False,
                  WLED_readonly_inventory_only=a.wled_inventory_only,controlled_WLED_read_refusal=a.test_wled_read_failure,
                  WLED_readonly_fault_watch=a.wled_fault_watch,controlled_WLED_fault_pulse=a.test_wled_fault_pulse,
                  WLED_power_cycle_only=a.wled_power_cycle_only,controlled_WLED_write_timeout=a.test_wled_write_timeout,
                  WLED_OEM_status_policy=oem_status,WLED_OEM_physical_cycle=a.wled_oem_physical_cycle,
                  WLED_native_runtime_test=a.wled_native_runtime_test,
                  WLED_native_runtime_physical=a.wled_native_runtime,
                  controlled_WLED_native_exit=a.test_wled_native_exit,
                  WLED_reset_prepared_before_terminal_reads=native_runtime,
                  WLED_reset_arm_SOFTWARE_delay_us=250000 if a.wled_native_runtime_test else 0,
                  WLED_atomic_exit_footer_max=212 if native_runtime else None,
                  WLED_atomic_exit_receipt_bytes=60 if native_runtime else None,
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
                  host_UTC_sync=a.host_utc_sync,host_UTC_mailbox=clock_binding,
                  host_UTC_source='host-realtime-plus-monotonic-RTT' if a.host_utc_sync else None,
                  calendar_RAM_only=True if a.host_utc_sync else None,
                  RTC_write_api=False,monotonic_counter_write_api=False,
                  battery_readonly=a.battery_readonly,battery_mailbox=battery_binding,
                  battery_UI_span_limit_us=500000 if a.battery_readonly else None,
                  battery_physical_PMIC_reads_compiled_out=a.test_qemu if a.battery_readonly else None,
                  battery_PMIC_write_api=False,wifi_readonly=a.wifi_readonly,
                  wifi_EFI_SMEM_read_api=False,wifi_EFI_transmit_api=False,
                  wifi_firmware_cache_readonly=cache_binding is not None,
                  wifi_firmware_cache_original_PE=cache_pe_relative,
                  wifi_firmware_cache_original_PE_whole_SHA256=cache_binding['source_whole_sha256'] if cache_binding else None,
                  wifi_firmware_cache_binding_SHA256=cache_binding['binding_sha256'] if cache_binding else None,
                  wifi_firmware_cache_before_mask=True if cache_binding else None,
                  wifi_firmware_cache_bytes_per_snapshot=632 if cache_binding else None,
                  wifi_firmware_cache_snapshot_count=2 if cache_binding else None,
                  wifi_firmware_cache_calls_original_code=False,
                  wifi_firmware_cache_new_SMEM_reads=False,
                  wifi_firmware_cache_native_permission=False,wifi_firmware_cache_transmit=False,
                  wifi_firmware_cache_physical_inspection_compiled_out=bool(cache_binding and a.test_qemu),
                  wifi_CPU0_firstread_readonly=a.wifi_cpu0_firstread,
                  wifi_CPU0_firstread_default_OFF=True,
                  wifi_CPU0_firstread_new_SMEM_read_body=bool(a.wifi_cpu0_firstread and not a.test_qemu),
                  wifi_CPU0_firstread_compiled_target_LDR32_max=18 if a.wifi_cpu0_firstread and not a.test_qemu else 0,
                  wifi_CPU0_firstread_actual_target_reads_observed=False,
                  wifi_CPU0_firstread_bytes_each=36 if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_passes_max=2 if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_target_LDR32_max=18 if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_addresses=[0x8600005c,0x860000c0,0x861ff000,0x861ff004,
                    0x861ff008,0x860b9000,0x860b9008,0x860b900c,0x860b9010] if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_fresh_limit_ticks=3840000 if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_frequency=19200000 if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_before_CPU_ON=True if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_before_console_and_PON=True if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_no_runtime_or_USB_command=True,
                  wifi_CPU0_firstread_retrospective_constructor_admission=True if a.wifi_cpu0_firstread else None,
                  wifi_CPU0_firstread_hardware_MPU_or_VMID_query=False,
                  wifi_CPU0_firstread_external_SError_recoverable=False,
                  wifi_CPU0_firstread_native_permission=False,wifi_CPU0_firstread_FIFO_or_TX=False,
                  wifi_CPU0_firstread_physical_SMEM_reads_compiled_out=bool(a.wifi_cpu0_firstread and a.test_qemu),
                  wifi_CPU0_normal_nc_firstread_readonly=a.wifi_cpu0_firstread_normal_nc,
                  wifi_CPU0_normal_nc_firstread_default_OFF=True,
                  wifi_CPU0_normal_nc_firstread_new_SMEM_read_body=bool(a.wifi_cpu0_firstread_normal_nc and not a.test_qemu),
                  wifi_CPU0_normal_nc_firstread_compiled_architectural_target_LDR32_max=18 if a.wifi_cpu0_firstread_normal_nc and not a.test_qemu else 0,
                  wifi_CPU0_normal_nc_firstread_actual_architectural_target_reads_observed=False,
                  wifi_CPU0_normal_nc_firstread_architectural_bytes_each=36 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_passes_max=2 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_architectural_target_LDR32_max=18 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_addresses=[2248147036, 2248147136, 2250240000, 2250240004, 2250240008, 2248904704, 2248904712, 2248904716, 2248904720] if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_translation_pages=[2248146944, 2248904704, 2250240000] if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_PAR_attributes=68 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_PAR_shareability=2 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_PAR_nonsecure=True if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_PAR_exact_low12=2816 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_MAIR_expected=4290462720 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_whole_raw_PAR_stable=True if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_all3pages_required_before_target_LDR=True if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_fresh_limit_ticks=3840000 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_frequency=19200000 if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_before_CPU_ON=True if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_before_console_and_PON=True if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_no_runtime_or_USB_command=True,
                  wifi_CPU0_normal_nc_firstread_retrospective_constructor_admission=True if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_hardware_MPU_or_VMID_query=False,
                  wifi_CPU0_normal_nc_firstread_external_SError_recoverable=False,
                  wifi_CPU0_normal_nc_firstread_native_permission=False,
                  wifi_CPU0_normal_nc_firstread_FIFO_or_TX=False,
                  wifi_CPU0_normal_nc_firstread_physical_SMEM_reads_compiled_out=bool(a.wifi_cpu0_firstread_normal_nc and a.test_qemu),
                  wifi_CPU0_normal_nc_firstread_normal_speculative_repeated_coalesced_bus_reads_possible=True if a.wifi_cpu0_firstread_normal_nc else None,
                  wifi_CPU0_normal_nc_firstread_physical_bus_transaction_cap=False,
                  wifi_CPU0_normal_nc_firstread_original_Device_policy_unchanged=True,
                  wifi_CPU0_normal_nc_firstread_mutually_exclusive_with_Device_firstread=True,
                  wifi_CPU0_normal_nc_firstread_policy_version='exact-NormalNC44-NS-OuterShareable-v1' if a.wifi_cpu0_firstread_normal_nc else None,
                  audio_I2C_cache_readonly=audio_binding is not None,
                  audio_I2C_cache_default_OFF=True,
                  audio_I2C_cache_new_original_image_RAM_read_body=bool(audio_binding and not a.test_qemu),
                  audio_I2C_cache_actual_cache_observed=False,
                  audio_I2C_cache_original_PE=audio_pe_relative,
                  audio_I2C_cache_original_PE_whole_SHA256=audio_binding['source_whole_sha256'] if audio_binding else None,
                  audio_I2C_cache_binding_SHA256=audio_binding['binding_sha256'] if audio_binding else None,
                  audio_I2C_cache_image_bytes=32768 if audio_binding else None,
                  audio_I2C_cache_cache_RVA=28000 if audio_binding else None,
                  audio_I2C_cache_bytes_per_snapshot=120 if audio_binding else None,
                  audio_I2C_cache_snapshot_count=2 if audio_binding else None,
                  audio_I2C_cache_immutable_hashes=4 if audio_binding else None,
                  audio_I2C_cache_DIR64_relocations=43 if audio_binding else None,
                  audio_I2C_cache_map_calls_max=3 if audio_binding else None,
                  audio_I2C_cache_map_keys_before_FreePool_only=True if audio_binding else None,
                  audio_I2C_cache_prepare_stage=2 if audio_binding else None,
                  audio_I2C_cache_after_complete_WiFi_collect_read_report=True if audio_binding else None,
                  audio_I2C_cache_before_PON_and_mask=True if audio_binding else None,
                  audio_I2C_cache_no_runtime_or_USB_command=True,
                  audio_I2C_cache_calls_original_firmware=False,
                  audio_I2C_cache_calls_I2C_DAL_methods=False,
                  audio_I2C_cache_MMIO_reads=False,
                  audio_I2C_cache_cached_pointer_follow=False,
                  audio_I2C_cache_SE5_owner_proven=False,
                  audio_I2C_cache_TAS_identity_proven=False,
                  audio_I2C_cache_PCM_completion_proven=False,
                  audio_I2C_cache_native_permission=False,
                  audio_I2C_cache_physical_image_inspection_compiled_out=bool(audio_binding and a.test_qemu),
                  audio_I2C_cache_raw_report_format='RAW_V1' if audio_binding else None,
                  audio_I2C_cache_raw_report_endianness='little' if audio_binding else None,
                  audio_I2C_cache_raw_report_bytes=5096 if audio_binding else None,
                  audio_I2C_cache_raw_report_lines=8 if audio_binding else None,
                  audio_I2C_cache_raw_report_max_text_units=126 if audio_binding else None,
                  runtime_services_DT=runtime_services,
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
    manifest.update(resource_clock_metadata(a.wifi_resources_readonly,a.test_qemu,audio_clock_binding,audio_clock_pe_relative))
    manifest.update(gcd_clock_metadata(gcd_enabled,a.test_qemu,gcd_binding,gcd_pe_relative))
    if gcd_enabled:
        # Old raw/gate fields remain present, with explicit NEW values. No strip/retry policy.
        manifest['wifi_CPU0_resources_firmware_RAM_log_capacity']=262144
        manifest['audio_Clock_query_actual_Device_identity_and_EFI_MMIO_required']=False
        manifest['audio_Clock_query_raw_report_format']='RAW_V2'
        manifest['audio_Clock_query_raw_report_bytes']=43504
        manifest['audio_Clock_query_combined_I2C_Clock_RAM_report_bytes']=98076
    if rpmh_binding:
        manifest.update(wifi_CPU0_RPMh_RAM_readonly=True,wifi_CPU0_RPMh_default_OFF=True,
            wifi_CPU0_RPMh_physical_body=not a.test_qemu,wifi_CPU0_RPMh_physical_compiled_out=a.test_qemu,
            wifi_CPU0_RPMh_source_PE=rpmh_pe_relative,wifi_CPU0_RPMh_source_SHA256=rpmh_binding['source_whole_sha256'],
            wifi_CPU0_RPMh_binding_SHA256=rpmh_binding['binding_sha256'],wifi_CPU0_RPMh_immutable_hashes=5,
            wifi_CPU0_RPMh_raw_format='RAW_V1',wifi_CPU0_RPMh_raw_bytes=19264,
            wifi_CPU0_RPMh_DRV_max=4,wifi_CPU0_RPMh_TCS_max=16,wifi_CPU0_RPMh_modes_max=4,
            wifi_CPU0_RPMh_full_raw_two_passes=True,wifi_CPU0_RPMh_new_BS_LocateProtocol_calls_max=2,
            wifi_CPU0_RPMh_new_BS_GetMap_calls_max=2,wifi_CPU0_RPMh_original_service_FP_arch_TPL_guard=True,
            wifi_CPU0_RPMh_unknown_blocks_native_and_reset=True,wifi_CPU0_RPMh_provider_API_calls=0,
            wifi_CPU0_RPMh_client_or_vote=False,wifi_CPU0_RPMh_MMIO_or_SMC=False,
            wifi_CPU0_RPMh_RAM_baseline_not_TCS_owner_or_rail_permission=True)
    if npa_binding:
        manifest.update(wifi_CPU0_NPA_RAM_readonly=True,wifi_CPU0_NPA_default_OFF=True,
            wifi_CPU0_NPA_physical_body=not a.test_qemu,wifi_CPU0_NPA_physical_compiled_out=a.test_qemu,
            wifi_CPU0_NPA_source_PE=npa_pe_relative,wifi_CPU0_NPA_source_SHA256=npa_binding['source_whole_sha256'],
            wifi_CPU0_NPA_binding_SHA256=npa_binding['binding_sha256'],wifi_CPU0_NPA_immutable_hashes=5,
            wifi_CPU0_NPA_list_nodes_max=512,wifi_CPU0_NPA_full_raw_two_passes=True,
            wifi_CPU0_NPA_raw_format='RAW_V2',wifi_CPU0_NPA_raw_bytes=470496,
            wifi_CPU0_NPA_reuses_current_loaded_image_enumeration=True,
            wifi_CPU0_NPA_new_BS_LocateProtocol_calls_max=2,wifi_CPU0_NPA_new_BS_GetMap_calls_max=2,
            wifi_CPU0_NPA_original_service_FP_arch_TPL_guard=True,wifi_CPU0_NPA_unknown_blocks_native_and_reset=True,
            wifi_CPU0_NPA_api_calls=0,wifi_CPU0_NPA_query_plugins=False,wifi_CPU0_NPA_client_or_vote=False,
            wifi_CPU0_NPA_RAM_namespace_not_owner_or_write_permission=True,
            original_GCD_new_scope_RAM_log_capacity=1572864,wifi_CPU0_resources_firmware_RAM_log_capacity=1572864)
    if a.wifi_rpmh_private_client:
        # This NEW total RPMh scope writes private provider RAM. Do not retain
        # misleading whole-scope readonly/no-client/no-API flags from0148.
        manifest.update(wifi_CPU0_RPMh_RAM_readonly=False,wifi_CPU0_RPMh_client_or_vote=True,
            wifi_CPU0_RPMh_provider_API_calls=2,wifi_CPU0_RPMh_private_client=True,
            wifi_CPU0_RPMh_private_default_OFF=True,wifi_CPU0_RPMh_private_physical_body=not a.test_qemu,
            wifi_CPU0_RPMh_private_physical_compiled_out=a.test_qemu,
            wifi_CPU0_RPMh_private_raw_format='RAW_V1',wifi_CPU0_RPMh_private_raw_bytes=227104,
            wifi_CPU0_RPMh_private_DRV=2,wifi_CPU0_RPMh_private_API_This_argument=False,
            wifi_CPU0_RPMh_private_Create_slot=48,wifi_CPU0_RPMh_private_Delete_slot=72,
            wifi_CPU0_RPMh_private_Create_flag=0,wifi_CPU0_RPMh_private_pool_nodes_max=128,
            wifi_CPU0_RPMh_private_two_reads_each_of_three_pool_stages=True,
            wifi_CPU0_RPMh_private_original_FP_arch_TPL_guard=True,
            wifi_CPU0_RPMh_private_independent_bootstrap_ticket=True,
            wifi_CPU0_RPMh_private_retired_before_Clock_and_final_GCD=True,
            wifi_CPU0_RPMh_private_never_reset_or_reopen_final_GCD_ticket=True,
            wifi_CPU0_RPMh_private_BS_LocateProtocol_calls_max=2,
            wifi_CPU0_RPMh_private_BS_GetMap_calls_max=5,
            wifi_CPU0_RPMh_private_API_calls_max=2,
            wifi_CPU0_RPMh_private_partial_and_UNKNOWN_retained=True,
            wifi_CPU0_RPMh_private_held_or_UNKNOWN_blocks_native_PON_receipt=True,
            wifi_CPU0_RPMh_private_no_NULL_unknown_or_failed_cleanup=True,
            wifi_CPU0_RPMh_private_vote_commandset_MMIO_SMC_MSS_NVserve_calls=0,
            wifi_CPU0_RPMh_private_direct_provider_RAM_body_only=True,
            wifi_CPU0_RPMh_private_indirect_event_hardware_side_effects_proven_absent=False,
            wifi_CPU0_RPMh_private_free_pool_rotation_or_new_retired_slot_recorded=True,
            wifi_CPU0_RPMh_private_not_bitwise_heap_or_hardware_restore_claim=True,
            wifi_CPU0_RPMh_private_no_runtime_USB_control=True,
            original_GCD_new_scope_RAM_log_capacity=2097152,
            wifi_CPU0_resources_firmware_RAM_log_capacity=2097152)
    if cmddb_binding:
        # New total scope: never advertise the old RAM-only/zero-vote label.
        manifest.update(wifi_CPU0_RPMh_MMIO_or_SMC=True,
            wifi_CPU0_RPMh_private_vote_commandset_MMIO_SMC_MSS_NVserve_calls=None,
            wifi_CPU0_RPMh_private_direct_provider_RAM_body_only=False,
            wifi_CPU0_power_transaction=True,wifi_CPU0_power_default_OFF=True,
            wifi_CPU0_power_physical_body=not a.test_qemu,wifi_CPU0_power_physical_compiled_out=a.test_qemu,
            wifi_CPU0_power_source_PE=cmddb_pe_relative,wifi_CPU0_power_source_SHA256=cmddb_binding['source_whole_sha256'],
            wifi_CPU0_power_binding_SHA256=cmddb_binding['binding_sha256'],
            wifi_CPU0_power_CmdDb_RO_base=0x85fe0000,wifi_CPU0_power_CmdDb_RO_bytes=131072,
            wifi_CPU0_power_CmdDb_RO_not_SMEM_writer=True,
            wifi_CPU0_power_raw_format='RAW_V1',wifi_CPU0_power_raw_bytes=1235200,
            wifi_CPU0_power_client_raw_bytes=227104,wifi_CPU0_power_access_raw_bytes=399240,
            wifi_CPU0_power_CPU_raw_bytes=10048,wifi_CPU0_power_guarded_PSCI_calls_max=14,
            wifi_CPU0_power_no_original_submit_or_churn=True,wifi_CPU0_power_no_SMC_during_active_RSC=True,
            wifi_CPU0_power_steps_max=256,wifi_CPU0_power_transaction_events_max=1024,
            wifi_CPU0_power_unknown_blocks_native_PON_receipt=True,
            wifi_CPU0_power_UNKNOWN_no_USB_Console_Stall_or_firmware_return=True,
            wifi_CPU0_power_exact_local_restore_before_known_Delete=True,
            wifi_CPU0_power_local_NS_evidence_not_secure_hardware_grant=True,
            wifi_CPU0_power_hardware_ownership_independently_qualified=False,
            wifi_CPU0_power_new_host_admission_required=True,wifi_CPU0_power_candidate_ready=False,
            wifi_CPU0_power_MSS_or_NVserve_or_radio=False,
            original_GCD_new_scope_RAM_log_capacity=8388608,
            wifi_CPU0_resources_firmware_RAM_log_capacity=8388608)
        if a.wifi_power_cmddb_capture_only:
            manifest.update(wifi_CPU0_power_CmdDb_capture_only=True,
                wifi_CPU0_power_CmdDb_original_Query_calls_max=0,
                wifi_CPU0_power_CmdDb_planned_stop_error=13,
                wifi_CPU0_power_CPUcritical_and_RSC_reachable=False,
                wifi_CPU0_power_guarded_PSCI_calls_max=0,
                wifi_CPU0_power_steps_max=0,wifi_CPU0_power_transaction_events_max=0,
                wifi_CPU0_RPMh_private_vote_commandset_MMIO_SMC_MSS_NVserve_calls=0)
        if namespace_binding:
            manifest.update(wifi_CPU0_power_CmdDb_bounded_GCD=True,
                wifi_CPU0_power_CmdDb_GCD_namespace_source_SHA256=namespace_binding['source_whole_SHA256'],
                wifi_CPU0_power_CmdDb_GCD_namespace_binding_SHA256=namespace_binding['binding_SHA256'],
                wifi_CPU0_power_CmdDb_GCD_namespace_template_SHA256=namespace_binding['template_SHA256'],
                wifi_CPU0_power_CmdDb_GCD_namespace_max_nodes=512,
                wifi_CPU0_power_CmdDb_original_GCD_API_calls_max=0,
                wifi_CPU0_power_CmdDb_GCD_namespace_lock_or_TPL_calls_max=0,
                wifi_CPU0_power_CmdDb_GCD_namespace_raw_bytes=183064,
                wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_count=66,
                wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_bytes=832,
                wifi_CPU0_power_CmdDb_GCD_namespace_no_EFI_status_fabrication=True,
                wifi_CPU0_power_CmdDb_GCD_namespace_no_API_fallback=True,
                wifi_CPU0_power_raw_format='RAW_V2',wifi_CPU0_power_raw_bytes=1656240)
            if a.wifi_power_cmddb_first_node_stop:
                manifest.update(wifi_CPU0_power_CmdDb_first_node_stop=True,
                    wifi_CPU0_power_CmdDb_first_node_default_OFF=True,
                    wifi_CPU0_power_CmdDb_effective_node_budget=1,
                    wifi_CPU0_power_CmdDb_namespace_complete_possible=False,
                    wifi_CPU0_power_CmdDb_database_target_bytes_max=0,
                    wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_count=0,
                    wifi_CPU0_power_CmdDb_planned_stop_error=14,
                    wifi_CPU0_power_CmdDb_first_node_requires_both_source_checkpoints=True,
                    wifi_CPU0_power_CmdDb_first_node_no_UNKNOWN_clearing=True)
            if a.wifi_power_cmddb_budget_admission:
                manifest.update(wifi_CPU0_power_CmdDb_work_admission=True,
                    wifi_CPU0_power_CmdDb_work_admission_default_OFF=True,
                    wifi_CPU0_power_CmdDb_work_admission_samples=3,
                    wifi_CPU0_power_CmdDb_work_admission_checkpoints=80,
                    wifi_CPU0_power_CmdDb_work_admission_reserve_ticks=480000,
                    wifi_CPU0_power_CmdDb_work_admission_plan_ticks=2400000,
                    wifi_CPU0_power_CmdDb_work_admission_independent_RO_ticket=True,
                    wifi_CPU0_power_CmdDb_work_admission_before_private_Create=True,
                    wifi_CPU0_power_CmdDb_work_admission_no_deadline_renewal=True,
                    wifi_CPU0_power_CmdDb_work_admission_estimate_not_hardware_authority=True,
                    wifi_CPU0_power_CmdDb_work_admission_original_GetMap_calls_max=2,
                    wifi_CPU0_power_CmdDb_work_admission_original_GCD_Query_calls=0,
                    wifi_CPU0_power_CmdDb_work_admission_Core_hash_checkpoints=5,
                    wifi_CPU0_power_CmdDb_work_admission_original_fresh_ticks=3840000,
                    wifi_CPU0_power_CmdDb_work_admission_raw_bytes=31552)
            if a.wifi_power_cmddb_staged_ro:
                # The private-client/power flags are link dependencies only.
                # Its actual parent selects this RO caller exclusively. Do
                # not advertise inactive private/critical/writer effects.
                manifest.update(wifi_CPU0_RPMh_RAM_readonly=True,
                    wifi_CPU0_RPMh_client_or_vote=False,wifi_CPU0_RPMh_MMIO_or_SMC=False,
                    wifi_CPU0_RPMh_provider_API_calls=0,wifi_CPU0_RPMh_private_client=False,
                    wifi_CPU0_RPMh_private_compiled_dependency_only=True,
                    wifi_CPU0_RPMh_private_physical_body=False,
                    wifi_CPU0_RPMh_private_raw_bytes=0,wifi_CPU0_RPMh_private_API_calls_max=0,
                    wifi_CPU0_RPMh_private_BS_LocateProtocol_calls_max=0,
                    wifi_CPU0_RPMh_private_BS_GetMap_calls_max=0,
                    wifi_CPU0_RPMh_private_direct_provider_RAM_body_only=False,
                    wifi_CPU0_power_execution_kind='STAGED_CMDDB_RO_PREPARATION',
                    wifi_CPU0_power_raw_format='STAGED_RO_RAW_V1',wifi_CPU0_power_raw_bytes=1660544,
                    wifi_CPU0_power_client_raw_bytes=0,wifi_CPU0_power_access_raw_bytes=0,
                    wifi_CPU0_power_CPU_raw_bytes=0,wifi_CPU0_power_guarded_PSCI_calls_max=0,
                    wifi_CPU0_power_exact_local_restore_before_known_Delete=False,
                    wifi_CPU0_power_CmdDb_planned_stop_error=None,
                    wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_count=68,
                    wifi_CPU0_power_CmdDb_staged_RO_prepare=True,
                    wifi_CPU0_power_CmdDb_staged_RO_default_OFF=True,
                    wifi_CPU0_power_CmdDb_staged_RO_phases=4,
                    wifi_CPU0_power_CmdDb_staged_RO_bytes_per_phase=65536,
                    wifi_CPU0_power_CmdDb_staged_RO_phase_raw_bytes=349456,
                    wifi_CPU0_power_CmdDb_staged_RO_original_fresh_ticks=3840000,
                    wifi_CPU0_power_CmdDb_staged_RO_independent_resident_spent_once_tickets=True,
                    wifi_CPU0_power_CmdDb_staged_RO_original_GetMap_calls_max=8,
                    wifi_CPU0_power_CmdDb_staged_RO_original_LocateProtocol_calls_max=4,
                    wifi_CPU0_power_CmdDb_staged_RO_full_namespace_passes=8,
                    wifi_CPU0_power_CmdDb_staged_RO_full_database_copies=2,
                    wifi_CPU0_power_CmdDb_staged_RO_before_any_private_client=True,
                    wifi_CPU0_power_CmdDb_staged_RO_NO_deadline_reset_or_rebase=True,
                    wifi_CPU0_power_CmdDb_staged_RO_final_native_flag_source_literal=True,
                    wifi_CPU0_power_CmdDb_staged_RO_no_continuous_hardware_lease_claim=True,
                    wifi_CPU0_power_CmdDb_staged_RO_all_loaded_headers_before_after=True,
                    wifi_CPU0_power_CmdDb_staged_RO_cross_phase_namespace_map_source_equal=True,
                    wifi_CPU0_power_CmdDb_staged_RO_original_ARC_decoder_reused=True)
    if a.wifi_power_prepared_transaction:
        # Whole combined scope, with every previously captured raw byte plus
        # real private/current/critical/RSC records. No capture-only disguise.
        manifest.update(wifi_CPU0_RPMh_RAM_readonly=False,wifi_CPU0_RPMh_client_or_vote=True,
            wifi_CPU0_RPMh_MMIO_or_SMC=True,wifi_CPU0_RPMh_provider_API_calls=2,
            wifi_CPU0_RPMh_private_client=True,wifi_CPU0_RPMh_private_compiled_dependency_only=False,
            wifi_CPU0_RPMh_private_physical_body=not a.test_qemu,wifi_CPU0_RPMh_private_raw_bytes=227104,
            wifi_CPU0_RPMh_private_API_calls_max=2,wifi_CPU0_RPMh_private_BS_LocateProtocol_calls_max=2,
            wifi_CPU0_RPMh_private_BS_GetMap_calls_max=5,
            wifi_CPU0_RPMh_private_vote_commandset_MMIO_SMC_MSS_NVserve_calls=None,
            wifi_CPU0_power_execution_kind='STAGED_RO_THEN_CURRENT_PRIVATE_BOUNDED_POWER',
            wifi_CPU0_power_prepared_transaction=True,wifi_CPU0_power_prepared_default_OFF=True,
            wifi_CPU0_power_CmdDb_capture_only=False,wifi_CPU0_power_CPUcritical_and_RSC_reachable=True,
            wifi_CPU0_power_raw_format='PREPARED_POWER_RAW_V1',wifi_CPU0_power_raw_bytes=1892336,
            wifi_CPU0_power_staged_RO_raw_bytes=1660544,wifi_CPU0_power_client_raw_bytes=227104,
            wifi_CPU0_power_prepared_binding_raw_bytes=233520,wifi_CPU0_power_access_raw_bytes=401800,
            wifi_CPU0_power_CPU_raw_bytes=10048,wifi_CPU0_power_guarded_PSCI_calls_max=14,
            wifi_CPU0_power_steps_max=256,wifi_CPU0_power_transaction_events_max=1024,
            wifi_CPU0_power_exact_local_restore_before_known_Delete=True,
            wifi_CPU0_power_CmdDb_original_Query_calls_max=0,
            wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_count=120,
            wifi_CPU0_power_prepared_staged_target_guards=68,
            wifi_CPU0_power_prepared_private_target_guards_max=52,
            wifi_CPU0_power_prepared_binding_admission_and_close_arch_retained_separately=True,
            wifi_CPU0_power_prepared_current_header_entry_aux_ranges=7,
            wifi_CPU0_power_prepared_current_selected_byte_passes=3,
            wifi_CPU0_power_prepared_current_complete_namespace_passes=2,
            wifi_CPU0_power_prepared_current_original_Query_calls=0,
            wifi_CPU0_power_prepared_masked_FULL_DB_bytes_per_snapshot=131072,
            wifi_CPU0_power_prepared_masked_FULL_DB_snapshots=2,
            wifi_CPU0_power_prepared_masked_fresh_NS_WB_PAR_restore_each_page=True,
            wifi_CPU0_power_prepared_NO_fake_API_observation_or_client=True,
            wifi_CPU0_power_prepared_no_old_RO_ticket_reuse=True,
            wifi_CPU0_power_prepared_original_private_deadline_ticks=3840000,
            wifi_CPU0_power_prepared_final_ticket_unopened_before_Clock=True,
            wifi_CPU0_power_prepared_both_raw_scopes_exported_complete=True,
            wifi_CPU0_power_runtime_HAL_count_static_RVA=0xd238,
            wifi_CPU0_power_runtime_HAL_count_offset=4,
            wifi_CPU0_power_static_logical_DRV_RVA=0xd228,
            wifi_CPU0_power_HAL_count_and_logical_DRV_checked_separately=True,
            original_GCD_new_scope_RAM_log_capacity=10485760,
            wifi_CPU0_resources_firmware_RAM_log_capacity=10485760)
    if a.wifi_power_current_arc_read:
        manifest.update(
            wifi_CPU0_power_execution_kind='STAGED_RO_CURRENT_PRIVATE_THREE_READ_RESTORE_NO_RESOURCE_WRITE',
            wifi_CPU0_power_raw_format='CURRENT_ARC_READ_RAW_V2',
            wifi_CPU0_power_raw_bytes=1941984,wifi_CPU0_power_access_raw_bytes=401936,
            wifi_CPU0_power_current_ARC_read=True,wifi_CPU0_power_current_ARC_read_default_OFF=True,
            wifi_CPU0_power_current_ARC_read_capture_only=True,
            wifi_CPU0_power_current_ARC_resource_WRITE_reachable=False,
            wifi_CPU0_power_current_ARC_resource_WRITE_commands_max=0,
            wifi_CPU0_power_current_ARC_original_Read_API_calls=0,
            wifi_CPU0_power_current_ARC_read_raw_bytes=49488,
            wifi_CPU0_power_current_ARC_read_requests_max=3,
            wifi_CPU0_power_current_ARC_commands_per_read=1,
            wifi_CPU0_power_current_ARC_read_single_outstanding=True,
            wifi_CPU0_power_current_ARC_read_MSGID=0x108,
            wifi_CPU0_power_current_ARC_read_CMD_DATA_writes=False,
            wifi_CPU0_power_current_ARC_read_RAW_not_qualified_vote=True,
            wifi_CPU0_power_current_ARC_read_full_RW_prefix_before_CPU_restore=True,
            wifi_CPU0_power_current_ARC_read_checked_IO_prefix_crossbound=True,
            wifi_CPU0_power_current_ARC_read_same_source_client_200ms=True,
            wifi_CPU0_power_current_ARC_read_entire_partial_raw_preserved=True,
            wifi_CPU0_power_current_ARC_read_shared_event_limit=1024,
            wifi_CPU0_power_current_ARC_read_shared_step_limit=256,
            wifi_CPU0_power_current_ARC_read_shared_deadline_ticks=960000,
            wifi_CPU0_power_current_ARC_read_qualified_response_semantics_proven=False,
            wifi_CPU0_power_current_ARC_retired_single_command_latch=True,
            wifi_CPU0_power_current_ARC_original_FREE_and_request_NULL_required=True,
            wifi_CPU0_power_current_ARC_trigger_low_readback_before_staging=True,
            wifi_CPU0_power_current_ARC_high_trigger_restore_stores_max=0,
            wifi_CPU0_power_current_ARC_three_new_rising_edges=True,
            wifi_CPU0_power_current_ARC_restore_enable_after_final_ACK=True,
            wifi_CPU0_power_current_ARC_normal_ON_pending_known_refusal=True,
            wifi_CPU0_power_current_ARC_CPU_refusal_requires_all_guard_returns_and_full_close=True,
            wifi_CPU0_power_current_ARC_CPU_refusal_never_masks_or_stores=True,
            wifi_CPU0_power_current_ARC_unsupported_or_unknown_CPU_state_quarantines=True)
    if a.wifi_power_current_arc_read_work_admission:
        manifest.update(wifi_CPU0_power_raw_format='CURRENT_ARC_READ_RAW_V3',wifi_CPU0_power_raw_bytes=1943840,
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_ARC_READ_RAW_V3',
            wifi_CPU0_power_current_ARC_path_raw_bytes=1943840,
            wifi_CPU0_power_current_ARC_work_admission=True,wifi_CPU0_power_current_ARC_work_default_OFF=True,
            wifi_CPU0_power_current_ARC_work_before_any_CPU_mask_or_RSC_store=True,
            wifi_CPU0_power_current_ARC_work_reuses_only_completed_RO_sample_evidence=True,
            wifi_CPU0_power_current_ARC_work_all_samples_including_slowest=68,
            wifi_CPU0_power_current_ARC_work_Core_count_tail='4+selected_pages',
            wifi_CPU0_power_current_ARC_work_RPMh_count_tail=4,wifi_CPU0_power_current_ARC_work_CmdDb_count_tail=3,
            wifi_CPU0_power_current_ARC_work_generic_verifier_Core_units_each=2,
            wifi_CPU0_power_current_ARC_work_total_source_units='18+selected_pages',
            wifi_CPU0_power_current_ARC_work_full_READ_reserve_ticks=960000,
            wifi_CPU0_power_current_ARC_work_nonhash_reserve_ticks=480000,
            wifi_CPU0_power_current_ARC_work_original_remaining_200ms_unchanged=True,
            wifi_CPU0_power_current_ARC_work_no_new_or_rebased_ticket=True,
            wifi_CPU0_power_current_ARC_work_decline_requires_full_namespace_pool_client_Delete_close=True,
            wifi_CPU0_power_current_ARC_work_unknown_blocks_parent_native_PON_receipt=True,
            wifi_CPU0_power_current_ARC_work_estimate_not_walltime_or_hardware_grant=True)
    if a.wifi_power_private_cpu_checkpoint:
        manifest.update(
            wifi_CPU0_power_execution_kind='SAME_KNOWN_PRIVATE_CURRENT_RAM_DEVICE_MASKED_CPU_EXACT_RESTORE_DELETE_BEFORE_RSC_ACCESS',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_CPU_CHECKPOINT_RAW_V1',wifi_CPU0_power_raw_bytes=1943840,
            wifi_CPU0_power_CPUcritical_and_RSC_reachable=False,wifi_CPU0_power_CPUcritical_reachable=True,
            wifi_CPU0_power_RSC_reachable=False,wifi_CPU0_power_steps_max=0,wifi_CPU0_power_transaction_events_max=0,
            wifi_CPU0_power_current_ARC_read=False,wifi_CPU0_power_current_ARC_compiled_dependency_only=True,
            wifi_CPU0_power_current_ARC_read_requests_max=0,wifi_CPU0_power_current_ARC_commands_per_read=0,
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_CPU_CHECKPOINT_RAW_V1',
            wifi_CPU0_power_prepared_masked_FULL_DB_snapshots=0,
            wifi_CPU0_power_private_CPU_checkpoint=True,wifi_CPU0_power_private_CPU_checkpoint_default_OFF=True,
            wifi_CPU0_power_private_CPU_checkpoint_before_first_TCS_store=True,
            wifi_CPU0_power_private_CPU_checkpoint_no_access_READ_ACK_or_writer_callback=True,
            wifi_CPU0_power_private_CPU_checkpoint_unused_engines_entirely_zero=True,
            wifi_CPU0_power_private_CPU_checkpoint_no_forged_engine_retirement=True,
            wifi_CPU0_power_private_CPU_checkpoint_actual_Create_current_namespace_Device_CPU_restore_Delete=True,
            wifi_CPU0_power_private_CPU_checkpoint_masked_normal_full_RAM_equal=True,
            wifi_CPU0_power_private_CPU_checkpoint_all_Device_control_status_IRQ_bytes_unchanged=True,
            wifi_CPU0_power_private_CPU_checkpoint_work_FULL_READ_reserve_retained=True,
            wifi_CPU0_power_private_CPU_checkpoint_original_200ms_unchanged=True,
            wifi_CPU0_power_private_CPU_checkpoint_held_UNKNOWN_blocks_USB_native_PON_receipt=True,
            wifi_CPU0_power_private_CPU_checkpoint_complete_retire_before_USB_export=True,
            wifi_CPU0_power_private_CPU_checkpoint_not_lease_or_later_READ_permission=True)
    if a.wifi_power_read_access_checkpoint:
        manifest.update(
            wifi_CPU0_power_execution_kind='SAME_PRIVATE_FULL_CURRENT_MASKED_CMDDB_CHECKED_RSC_GEOMETRY_READS_RETIRE_CPU_RESTORE_DELETE_NO_ENGINE_OR_TCS_STORE',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_ACCESS_OBSERVATION_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_ACCESS_OBSERVATION_RAW_V1',
            wifi_CPU0_power_prepared_masked_FULL_DB_snapshots=2,
            wifi_CPU0_power_private_CPU_checkpoint_no_access_READ_ACK_or_writer_callback=False,
            wifi_CPU0_power_private_access_checkpoint=True,wifi_CPU0_power_private_access_checkpoint_default_OFF=True,
            wifi_CPU0_power_private_access_checkpoint_same_fresh_private_CPU_lifetime=True,
            wifi_CPU0_power_private_access_checkpoint_full_current_masked_CmdDb_bytes_each=131072,
            wifi_CPU0_power_private_access_checkpoint_RAM_AT_per_capture=32,
            wifi_CPU0_power_private_access_checkpoint_checked_geometry_reads=70,
            wifi_CPU0_power_private_access_checkpoint_exact_embedded_reader_bindings=3,
            wifi_CPU0_power_private_access_checkpoint_original_memory_members_matched=5,
            wifi_CPU0_power_private_access_checkpoint_arguments_checked_before_prepared_and_CPU=True,
            wifi_CPU0_power_private_access_checkpoint_physical_store_callback_wired=False,
            wifi_CPU0_power_private_access_checkpoint_store_attempt_sticky_refusal=True,
            wifi_CPU0_power_private_access_checkpoint_engines_entirely_zero=True,
            wifi_CPU0_power_private_access_checkpoint_no_forged_engine_completion=True,
            wifi_CPU0_power_private_access_checkpoint_complete_retire_before_CPU_restore_USB=True,
            wifi_CPU0_power_private_access_checkpoint_original_full_READ_work_reserves_retained=True,
            wifi_CPU0_power_private_access_checkpoint_not_READ_request_or_hardware_grant=True)
    if a.wifi_power_read_database_checkpoint:
        manifest.update(
            wifi_CPU0_power_execution_kind='SAME_PRIVATE_TWO_FULL_MASKED_CMDDB_RAM_CAPTURES_CLOSE_CPU_SOURCE_NAMESPACE_DELETE_BEFORE_FIRST_MASKED_RSC_MMIO_READ',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_MASKED_DB_OBSERVATION_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_MASKED_DB_OBSERVATION_RAW_V1',
            wifi_CPU0_power_private_access_checkpoint_checked_geometry_reads=0,
            wifi_CPU0_power_private_database_checkpoint=True,
            wifi_CPU0_power_private_database_checkpoint_default_OFF=True,
            wifi_CPU0_power_private_database_checkpoint_planned_stop_error=15,
            wifi_CPU0_power_private_database_checkpoint_no_masked_RSC_callbacks_wired=True,
            wifi_CPU0_power_private_database_checkpoint_access_acquired_held_retired_published=False,
            wifi_CPU0_power_private_database_checkpoint_full_current_masked_CmdDb_bytes_each=131072,
            wifi_CPU0_power_private_database_checkpoint_RAM_AT_per_capture=32,
            wifi_CPU0_power_private_database_checkpoint_same_original_200ms_and_READ_reserves=True,
            wifi_CPU0_power_private_database_checkpoint_complete_CPU_source_namespace_Delete_before_USB=True)
    if a.wifi_power_terminal_gop_diagnostics:
        manifest.update(wifi_CPU0_power_terminal_GOP_diagnostics=True,
            wifi_CPU0_power_terminal_GOP_default_OFF=True,
            wifi_CPU0_power_terminal_GOP_physical_body=not a.test_qemu,
            wifi_CPU0_power_terminal_GOP_physical_compiled_out=a.test_qemu,
            wifi_CPU0_power_terminal_GOP_scope='NUMERIC_TERMINAL_EVIDENCE_ONLY_NO_FOREIGN_METHOD_NO_EXIT_OR_RF_GRANT',
            wifi_CPU0_power_terminal_GOP_base=0x9d400000,
            wifi_CPU0_power_terminal_GOP_native_CPU_must_not_be_issued=True,
            wifi_CPU0_power_terminal_GOP_fresh_RW_AT_and_PAR_restore_per_page=True,
            wifi_CPU0_power_terminal_GOP_complete_mapping_check_before_first_pixel=True,
            wifi_CPU0_power_terminal_GOP_rect=[48,96,576,384],
            wifi_CPU0_power_terminal_GOP_terminal_deadline_ticks=960000,
            wifi_CPU0_power_terminal_GOP_private_ticket_or_UNKNOWN_changed=False,
            wifi_CPU0_power_terminal_GOP_original_hold_still_nonreturning=True)
    if a.wifi_power_terminal_gop_own_wt:
        manifest.update(wifi_CPU0_power_terminal_GOP_own_WT=True,
            wifi_CPU0_power_terminal_GOP_own_WT_default_OFF=True,
            wifi_CPU0_power_terminal_GOP_framebuffer_attr_bytes=[0xff,0x44,0xba],
            wifi_CPU0_power_terminal_GOP_header_attr_bytes=[0xff],
            wifi_CPU0_power_terminal_GOP_own_WT_observed_PAR=0xba0000009d465b80,
            wifi_CPU0_power_terminal_GOP_no_MAIR_TTBR_or_mapping_change=True)
    if a.wifi_power_pre_mask_arguments and not (a.wifi_power_normal_to_masked_database or a.wifi_power_current_word_read):
        manifest.update(
            wifi_CPU0_power_execution_kind='SAME_PRIVATE_NORMAL_ARGUMENT_RANGES_FULL_AT_CLOSE_NAMESPACE_SOURCE_POOLS_DELETE_BEFORE_CPU_MASKED_ACCESS',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_PRE_MASK_ARGUMENT_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_PRE_MASK_ARGUMENT_RAW_V1',
            wifi_CPU0_power_raw_bytes=1969056,
            wifi_CPU0_power_CPUcritical_reachable=False,
            wifi_CPU0_power_guarded_PSCI_calls_max=0,
            wifi_CPU0_power_prepared_masked_FULL_DB_bytes_per_snapshot=0,
            wifi_CPU0_power_prepared_masked_FULL_DB_snapshots=0,
            wifi_CPU0_power_prepared_masked_fresh_NS_WB_PAR_restore_each_page=False,
            wifi_CPU0_power_private_CPU_checkpoint_actual_Create_current_namespace_Device_CPU_restore_Delete=False,
            wifi_CPU0_power_private_CPU_checkpoint_masked_normal_full_RAM_equal=False,
            wifi_CPU0_power_private_CPU_checkpoint_all_Device_control_status_IRQ_bytes_unchanged=False,
            wifi_CPU0_power_private_access_checkpoint_same_fresh_private_CPU_lifetime=False,
            wifi_CPU0_power_private_access_checkpoint_full_current_masked_CmdDb_bytes_each=0,
            wifi_CPU0_power_private_access_checkpoint_RAM_AT_per_capture=0,
            wifi_CPU0_power_private_access_checkpoint_complete_retire_before_CPU_restore_USB=False,
            wifi_CPU0_power_private_database_checkpoint_full_current_masked_CmdDb_bytes_each=0,
            wifi_CPU0_power_private_database_checkpoint_RAM_AT_per_capture=0,
            wifi_CPU0_power_private_database_checkpoint_complete_CPU_source_namespace_Delete_before_USB=False,
            wifi_CPU0_power_pre_mask_arguments=True,
            wifi_CPU0_power_pre_mask_arguments_default_OFF=True,
            wifi_CPU0_power_pre_mask_arguments_objects=10,
            wifi_CPU0_power_pre_mask_arguments_pages_max=512,
            wifi_CPU0_power_pre_mask_arguments_CPU_callbacks_wired=False,
            wifi_CPU0_power_pre_mask_arguments_normal_Device_captures=1,
            wifi_CPU0_power_pre_mask_arguments_normal_Device_reads=70,
            wifi_CPU0_power_pre_mask_arguments_normal_full_RAM_captures=1,
            wifi_CPU0_power_pre_mask_arguments_raw_bytes=25216,
            wifi_CPU0_power_pre_mask_arguments_planned_stop_error=16,
            wifi_CPU0_power_pre_mask_arguments_full_returned_AT_PAR_prefix=True,
            wifi_CPU0_power_pre_mask_arguments_CPU_access_engines_UNOBSERVED=True,
            wifi_CPU0_power_pre_mask_arguments_known_returned_refusal_full_closure=True,
            wifi_CPU0_power_pre_mask_arguments_partial_source_time_UNKNOWN_sticky=True,
            wifi_CPU0_power_pre_mask_arguments_no_ticket_reset_or_later_lease=True,
            wifi_CPU0_power_pre_mask_arguments_complete_namespace_source_pool_Delete_before_USB=True)
    if a.wifi_power_normal_to_masked_database:
        manifest.update(
            wifi_CPU0_power_execution_kind='SAME_FRESH_PRIVATE_NORMAL_TYPED_ARGUMENTS_THEN_FRESH_MASKED_CPU_FULL_CMDDB_SOURCE_NAMESPACE_DELETE_NO_MASKED_RSC_IO',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_NORMAL_TO_MASKED_DB_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_NORMAL_TO_MASKED_DB_RAW_V1',
            wifi_CPU0_power_raw_bytes=1969056,
            wifi_CPU0_power_pre_mask_arguments=True,
            wifi_CPU0_power_pre_mask_arguments_default_OFF=True,
            wifi_CPU0_power_pre_mask_arguments_objects=10,
            wifi_CPU0_power_pre_mask_arguments_pages_max=512,
            wifi_CPU0_power_pre_mask_arguments_CPU_callbacks_wired=True,
            wifi_CPU0_power_pre_mask_arguments_normal_Device_captures=2,
            wifi_CPU0_power_pre_mask_arguments_normal_Device_reads=140,
            wifi_CPU0_power_pre_mask_arguments_normal_full_RAM_captures=1,
            wifi_CPU0_power_pre_mask_arguments_raw_bytes=25216,
            wifi_CPU0_power_pre_mask_arguments_planned_stop_error=16,
            wifi_CPU0_power_pre_mask_arguments_full_returned_AT_PAR_prefix=True,
            wifi_CPU0_power_pre_mask_arguments_CPU_access_engines_UNOBSERVED=False,
            wifi_CPU0_power_pre_mask_arguments_known_returned_refusal_full_closure=True,
            wifi_CPU0_power_pre_mask_arguments_partial_source_time_UNKNOWN_sticky=True,
            wifi_CPU0_power_pre_mask_arguments_no_ticket_reset_or_later_lease=True,
            wifi_CPU0_power_pre_mask_arguments_complete_namespace_source_pool_Delete_before_USB=True,
            wifi_CPU0_power_normal_to_masked_database=True,
            wifi_CPU0_power_normal_to_masked_database_default_OFF=True,
            wifi_CPU0_power_normal_to_masked_database_planned_stop_error=15,
            wifi_CPU0_power_normal_to_masked_database_normal_decline_error=16,
            wifi_CPU0_power_normal_to_masked_database_post_normal_work_decline_error=12,
            wifi_CPU0_power_normal_to_masked_database_post_normal_work_original_remaining_rechecked=True,
            wifi_CPU0_power_normal_to_masked_database_original_work_68_samples_and_decision_preserved=True,
            wifi_CPU0_power_normal_to_masked_database_normal_prefix_rechecked_before_mask_after_DB_before_Delete=True,
            wifi_CPU0_power_normal_to_masked_database_original_ticket_deadline_reserves_unchanged=True,
            wifi_CPU0_power_normal_to_masked_database_all_masked_checks_fresh=True,
            wifi_CPU0_power_normal_to_masked_database_normal_observation_not_masked_grant=True,
            wifi_CPU0_power_normal_to_masked_database_no_masked_RSC_callbacks_access_lifetime_or_engine=True)
    if a.wifi_power_cpu_live_diagnostics:
        manifest.update(wifi_CPU0_power_execution_kind='SAME_FRESH_PRIVATE_NORMAL_MASKED_DATABASE_FIRST_ORIGINAL_CPU_LIVE_PREDICATE_NO_NEW_READERS',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_CPU_LIVE_DIAGNOSTIC_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_CPU_LIVE_DIAGNOSTIC_RAW_V1',
            wifi_CPU0_power_raw_bytes=1969104,wifi_CPU0_power_current_ARC_path_raw_bytes=1969104,
            wifi_CPU0_power_CPU_raw_bytes=10096,
            wifi_CPU0_power_CPU_live_diagnostics=True,
            wifi_CPU0_power_CPU_live_diagnostics_default_OFF=True,
            wifi_CPU0_power_CPU_live_diagnostic_bytes=48,
            wifi_CPU0_power_CPU_live_diagnostic_reasons=25,
            wifi_CPU0_power_CPU_live_original_short_circuit_order_preserved=True,
            wifi_CPU0_power_CPU_live_first_failure_only=True,
            wifi_CPU0_power_CPU_live_failed_ticks_are_original_sample=True,
            wifi_CPU0_power_CPU_live_extra_clock_register_owner_reads=False,
            wifi_CPU0_power_CPU_live_original_200ms_and_UNKNOWN_unchanged=True,
            wifi_CPU0_power_CPU_live_GOP_numeric_layout_version=2)
    if a.wifi_power_db_word_capture:
        manifest.update(wifi_CPU0_power_execution_kind='SAME_FRESH_PRIVATE_NORMAL_MASKED_FULL_DB_ALIGNED_WORD_CAPTURE_NO_DEVICE_WIDENING',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_DB_WORD_CAPTURE_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_DB_WORD_CAPTURE_RAW_V1',
            wifi_CPU0_power_raw_bytes=1969216,wifi_CPU0_power_current_ARC_path_raw_bytes=1969216,
            wifi_CPU0_power_access_raw_bytes=402048,
            wifi_CPU0_power_DB_word_capture=True,wifi_CPU0_power_DB_word_capture_default_OFF=True,
            wifi_CPU0_power_DB_word_record_bytes=56,wifi_CPU0_power_DB_word_snapshot_records=2,
            wifi_CPU0_power_DB_word_bytes=8,wifi_CPU0_power_DB_words_per_snapshot=16384,
            wifi_CPU0_power_DB_word_full_byte_comparison_and_pending_retained=True,
            wifi_CPU0_power_DB_word_Normal_NSWB_same_PA_per_page_AT_only=True,
            wifi_CPU0_power_DB_word_Device_MMIO_unchanged=True,
            wifi_CPU0_power_DB_word_original_200ms_all68_READ50_reserve25_unchanged=True,
            wifi_CPU0_power_CPU_live_GOP_numeric_layout_version=3)
    if a.wifi_power_current_word_read:
        manifest.update(wifi_CPU0_power_execution_kind='SAME_FRESH_PRIVATE_NORMAL_ARGUMENTS_MASKED_WORD_DATABASE_THREE_BOUNDED_READ_FULL_RETIRE',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_WORD_READ_RAW_V3',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_WORD_READ_RAW_V3',
            wifi_CPU0_power_raw_bytes=1969216,wifi_CPU0_power_current_ARC_path_raw_bytes=1969216,
            wifi_CPU0_power_current_word_READ=True,wifi_CPU0_power_current_word_READ_default_OFF=True,
            wifi_CPU0_power_pre_mask_arguments=True,wifi_CPU0_power_pre_mask_arguments_default_OFF=True,
            wifi_CPU0_power_pre_mask_arguments_objects=10,wifi_CPU0_power_pre_mask_arguments_pages_max=512,
            wifi_CPU0_power_pre_mask_arguments_CPU_callbacks_wired=True,
            wifi_CPU0_power_pre_mask_arguments_normal_Device_captures=2,
            wifi_CPU0_power_pre_mask_arguments_normal_Device_reads=140,
            wifi_CPU0_power_pre_mask_arguments_normal_full_RAM_captures=1,
            wifi_CPU0_power_pre_mask_arguments_raw_bytes=25216,wifi_CPU0_power_pre_mask_arguments_planned_stop_error=16,
            wifi_CPU0_power_pre_mask_arguments_full_returned_AT_PAR_prefix=True,
            wifi_CPU0_power_pre_mask_arguments_CPU_access_engines_UNOBSERVED=False,
            wifi_CPU0_power_pre_mask_arguments_known_returned_refusal_full_closure=True,
            wifi_CPU0_power_pre_mask_arguments_partial_source_time_UNKNOWN_sticky=True,
            wifi_CPU0_power_pre_mask_arguments_no_ticket_reset_or_later_lease=True,
            wifi_CPU0_power_pre_mask_arguments_complete_namespace_source_pool_Delete_before_USB=True,
            wifi_CPU0_power_current_word_READ_three_single_requests_max=3,
            wifi_CPU0_power_current_word_READ_resource_WRITE_reachable=False,
            wifi_CPU0_power_current_word_READ_fresh_full_masked_DB_bytes=262144,
            wifi_CPU0_power_current_word_READ_fresh_masked_DB_AT=64,
            wifi_CPU0_power_current_word_READ_normal_prefix_before_mask_before_READ_after_READ_before_Delete=True,
            wifi_CPU0_power_current_word_READ_original_200ms_all68_READ50_reserve25_unchanged=True,
            wifi_CPU0_power_current_word_READ_new_IRQ_all_DONE_idle_full_touched_RW_restore=True,
            wifi_CPU0_power_current_word_READ_RAW_not_qualified_per_DRV_vote=True,
            wifi_CPU0_power_current_word_READ_EE_EL3_VMID_MPU_grant_claim=False,
            wifi_CPU0_power_current_word_READ_no_MSS_NVserve_scan_join_data=True,
            wifi_CPU0_power_current_word_READ_saved_and_final_status_RAW=True,
            wifi_CPU0_power_current_word_READ_status_RAW_snapshot_phases=[0,7],
            wifi_CPU0_power_current_word_READ_status_snapshot_not_completion_or_grant=True,
            wifi_CPU0_power_current_word_READ_own_pending_status_mask=0x10101,
            wifi_CPU0_power_current_word_READ_own_pending_required_DONE_mask=0x10100,
            wifi_CPU0_power_current_word_READ_own_pending_TRIGGERED_bit=0x1,
            wifi_CPU0_power_current_word_READ_pending_status_OR_matches_pending_journal=True,
            wifi_CPU0_power_current_word_READ_own_pending_status_CMD0_only=True,
            wifi_CPU0_power_current_word_READ_full_status_OR_matches_entire_journal=True,
            wifi_CPU0_power_current_word_READ_no_RAW_bit_masking_or_UNKNOWN_clearing=True,
            wifi_CPU0_power_CPU_live_GOP_numeric_layout_version=6)
    if a.wifi_power_current_word_vote:
        manifest.update(wifi_CPU0_power_execution_kind='SAME_FRESH_PRIVATE_WORD_READ_DERIVED_DRV2_ARC_RAISE_REVERSE_SAVED_RESTORE_FULL_RETIRE',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_WORD_ARC_VOTE_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_WORD_ARC_VOTE_RAW_V1',
            wifi_CPU0_power_current_word_VOTE=True,wifi_CPU0_power_current_word_VOTE_default_OFF=True,
            wifi_CPU0_power_current_word_READ_resource_WRITE_reachable=True,
            wifi_CPU0_power_current_ARC_read_capture_only=False,
            wifi_CPU0_power_current_ARC_resource_WRITE_reachable=True,
            wifi_CPU0_power_current_ARC_resource_WRITE_commands_max=6,
            wifi_CPU0_power_current_ARC_read_RAW_not_qualified_vote=False,
            wifi_CPU0_power_current_ARC_read_qualified_response_semantics_proven=True,
            wifi_CPU0_power_current_word_READ_RAW_not_qualified_per_DRV_vote=False,
            wifi_CPU0_power_current_word_VOTE_semantics_primary='https://lkml.iu.edu/hypermail/linux/kernel/2510.2/06910.html',
            wifi_CPU0_power_current_word_VOTE_READ_HLOS_DRV2_not_aggregate=True,
            wifi_CPU0_power_current_word_VOTE_saved_values_from_same_fresh_READ=True,
            wifi_CPU0_power_current_word_VOTE_raise_order=['CX','MX','MSS'],
            wifi_CPU0_power_current_word_VOTE_restore_order=['MSS','MX','CX'],
            wifi_CPU0_power_current_word_VOTE_raise_max_saved_target=True,
            wifi_CPU0_power_current_word_VOTE_combined_READ_WRITE_ticks_max=960000,
            wifi_CPU0_power_current_word_VOTE_combined_steps_max=256,
            wifi_CPU0_power_current_word_VOTE_initial_final_full_prefix_status_response_IRQ_OR=True,
            wifi_CPU0_power_current_word_VOTE_dynamic_idle_untriggered_TCS=True,
            wifi_CPU0_power_current_word_VOTE_no_irq_enable_type_CMD_status_write=True,
            wifi_CPU0_power_current_word_VOTE_no_VRM_MSS_NVserve_radio=True,
            wifi_CPU0_power_CPU_live_GOP_numeric_layout_version=7)
    if a.wifi_power_current_word_vote_latched:
        manifest.update(wifi_CPU0_power_execution_kind='SAME_FRESH_READ_TCS_COMPLETED_LATCH_ARC_RAISE_REVERSE_SAVED_RESTORE_FULL_RETIRE',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_WORD_LATCHED_ARC_VOTE_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_WORD_LATCHED_ARC_VOTE_RAW_V1',
            wifi_CPU0_power_current_word_VOTE_latched=True,
            wifi_CPU0_power_current_word_VOTE_latched_default_OFF=True,
            wifi_CPU0_power_current_word_VOTE_latched_same_fresh_retired_READ_TCS_full_snapshot=True,
            wifi_CPU0_power_current_word_VOTE_latched_low_readback_before_commands=True,
            wifi_CPU0_power_current_word_VOTE_latched_new_edges_exact=2,
            wifi_CPU0_power_current_word_VOTE_latched_final_high_from_last_edge_no_restore_high_write=True,
            wifi_CPU0_power_current_word_VOTE_latched_original_IRQ_enable_type_unchanged=True,
            wifi_CPU0_power_current_word_VOTE_dynamic_idle_untriggered_TCS=False,
            wifi_CPU0_power_current_word_VOTE_dynamic_idle_TCS_fresh_READ_latch_binding=True,
            wifi_CPU0_power_CPU_live_GOP_numeric_layout_version=8)
    if a.wifi_power_four_vrm_roundtrip:
        manifest.update(wifi_CPU0_power_execution_kind='SAME_FRESH_PRIVATE_SIXTEEN_VRM_READ_FOUR_ORDERED_RAISE_REVERSE_SAVED_RESTORE_FULL_RETIRE',
            wifi_CPU0_power_raw_format='CURRENT_PRIVATE_FOUR_VRM_RAW_V1',
            wifi_CPU0_power_current_ARC_raw_format='CURRENT_PRIVATE_FOUR_VRM_RAW_V1',
            wifi_CPU0_power_raw_bytes=2072064,wifi_CPU0_power_current_ARC_path_raw_bytes=2072064,
            wifi_CPU0_power_four_VRM_roundtrip=True,wifi_CPU0_power_four_VRM_default_OFF=True,
            wifi_CPU0_power_four_VRM_bases=[0x40f00,0x41300,0x40c00,0x42000],
            wifi_CPU0_power_four_VRM_fields=['voltage_mV','enable','raw_PMIC_mode','headroom_mV'],
            wifi_CPU0_power_four_VRM_READ_requests=16,wifi_CPU0_power_four_VRM_WRITE_edges=8,
            wifi_CPU0_power_four_VRM_WRITE_commands=16,
            wifi_CPU0_power_four_VRM_min_mV=[800,1800,1304,3104],
            wifi_CPU0_power_four_VRM_max_mV=[800,1800,1304,3312],
            wifi_CPU0_power_four_VRM_raise_order=['ldoa5','ldoa7','ldoa17','ldoa25'],
            wifi_CPU0_power_four_VRM_restore_order=['ldoa25','ldoa17','ldoa7','ldoa5'],
            wifi_CPU0_power_four_VRM_fresh_current_CmdDb_entries=4,
            wifi_CPU0_power_four_VRM_fresh_normal_selected_ranges=11,
            wifi_CPU0_power_four_VRM_prepared_raw_bytes=236032,
            wifi_CPU0_power_four_VRM_same_fresh_READ_full_snapshot_before_first_WRITE=True,
            wifi_CPU0_power_four_VRM_voltage_before_enable_reverse_saved_enable_before_voltage=True,
            wifi_CPU0_power_four_VRM_raise_max_saved_target=True,
            wifi_CPU0_power_four_VRM_mode_headroom_IRQ_enable_type_stores=False,
            wifi_CPU0_power_four_VRM_combined_READ_WRITE_ticks_max=960000,
            wifi_CPU0_power_four_VRM_combined_steps_max=256,
            wifi_CPU0_power_four_VRM_combined_events_max=1024,
            wifi_CPU0_power_four_VRM_no_deadline_renewal_or_old_context=True,
            wifi_CPU0_power_four_VRM_original_200ms_all68_READ50_reserve25_unchanged=True,
            wifi_CPU0_power_four_VRM_full_CPU_namespace_source_pools_known_Delete=True,
            wifi_CPU0_power_four_VRM_inherited_ARC_records_UNOBSERVED=True,
            wifi_CPU0_power_four_VRM_no_MSS_NVserve_radio=True,
            wifi_CPU0_power_four_VRM_EE_EL3_VMID_MPU_grant_claim=False,
            wifi_CPU0_power_current_word_READ=False,
            wifi_CPU0_power_current_word_READ_three_single_requests_max=0,
            wifi_CPU0_power_current_word_READ_status_RAW_snapshot_phases=[0,33],
            wifi_CPU0_power_current_ARC_read=False,
            wifi_CPU0_power_current_ARC_resource_WRITE_reachable=False,
            wifi_CPU0_power_current_ARC_resource_WRITE_commands_max=0,
            original_GCD_new_scope_RAM_log_capacity=10747904,
            wifi_CPU0_resources_firmware_RAM_log_capacity=10747904,
            wifi_CPU0_power_CPU_live_GOP_numeric_layout_version=9)
    if a.wifi_cpu_ro_admission:
        manifest.update(wifi_CPU0_power_transaction=False,
            wifi_CPU0_power_CPU_RO_admission=True,wifi_CPU0_power_CPU_RO_default_OFF=True,
            wifi_CPU0_power_CPU_RO_execution_kind='INDEPENDENT_NORMAL_IRQ_SEVEN_AFFINITY_INFO64_CAPTURE_FULL_RETIRE_ONLY',
            wifi_CPU0_power_CPU_RO_physical_body=not a.test_qemu,
            wifi_CPU0_power_CPU_RO_physical_compiled_out=a.test_qemu,
            wifi_CPU0_power_CPU_RO_raw_format='CPU_RO_ADMISSION_RAW_V1',wifi_CPU0_power_CPU_RO_raw_bytes=39344,
            wifi_CPU0_power_CPU_RO_function_ID=0xc4000004,wifi_CPU0_power_CPU_RO_affinity_level=0,
            wifi_CPU0_power_CPU_RO_targets=[0x100,0x200,0x300,0x400,0x500,0x600,0x700],
            wifi_CPU0_power_CPU_RO_calls_max=7,wifi_CPU0_power_CPU_RO_original_GetMap_calls_max=2,
            wifi_CPU0_power_CPU_RO_Core_checkpoints=16,wifi_CPU0_power_CPU_RO_hashes_per_checkpoint=5,
            wifi_CPU0_power_CPU_RO_native_flag_reads_max=16,wifi_CPU0_power_CPU_RO_deadline_ticks=3840000,
            wifi_CPU0_power_CPU_RO_final_ticket_never_opened_or_changed=True,
            wifi_CPU0_power_CPU_RO_normal_IRQ_FP_arch_TPL_source_guards=True,
            wifi_CPU0_power_CPU_RO_entire_raw_and_unknown_preserved=True,
            wifi_CPU0_power_CPU_RO_all_states_raw_not_hardware_grant=True,
            wifi_CPU0_power_CPU_RO_no_private_Create_Delete=True,wifi_CPU0_power_CPU_RO_no_mask_TCS_READ_or_vote=True,
            wifi_CPU0_power_CPU_RO_nonreturning_SMC_walltime_bound_proven=False,
            wifi_CPU0_power_CPU_RO_unknown_blocks_Clock_native_PON_receipt=True,
            wifi_CPU0_power_CPU_RO_unknown_RAM_only_nonreturn_hold=True,
            wifi_CPU0_power_CPU_RO_all_OFF_does_not_continue_private=True,
            original_GCD_new_scope_RAM_log_capacity=1048576,
            wifi_CPU0_resources_firmware_RAM_log_capacity=1048576)
    if a.wifi_cpu_masked_ro_admission:
        manifest.update(
            wifi_CPU0_power_CPU_RO_execution_kind='INDEPENDENT_NORMAL_AND_MASKED_SEVEN_PEER_EXACT_LOCAL_RESTORE_FULL_RO_RETIRE_ONLY',
            wifi_CPU0_power_CPU_RO_raw_format='CPU_MASKED_RO_ADMISSION_RAW_V1',wifi_CPU0_power_CPU_RO_raw_bytes=50800,
            wifi_CPU0_power_CPU_RO_calls_max=14,wifi_CPU0_power_CPU_RO_Core_checkpoints=32,
            wifi_CPU0_power_CPU_RO_native_flag_reads_max=64,wifi_CPU0_power_CPU_RO_no_mask_TCS_READ_or_vote=False,
            wifi_CPU0_power_CPU_MASKED_RO_admission=True,wifi_CPU0_power_CPU_MASKED_RO_default_OFF=True,
            wifi_CPU0_power_CPU_MASKED_RO_normal_and_masked_calls_each=7,
            wifi_CPU0_power_CPU_MASKED_RO_original_services_while_held=0,
            wifi_CPU0_power_CPU_MASKED_RO_no_private_TCS_READ_or_vote=True,
            wifi_CPU0_power_CPU_MASKED_RO_mask_DAIF=192,wifi_CPU0_power_CPU_MASKED_RO_mask_Group1=0,
            wifi_CPU0_power_CPU_MASKED_RO_restore_DAIF=0,wifi_CPU0_power_CPU_MASKED_RO_restore_Group1=1,
            wifi_CPU0_power_CPU_MASKED_RO_transition_raw_bytes=72,
            wifi_CPU0_power_CPU_MASKED_RO_exact_mask_and_restore_readbacks=True,
            wifi_CPU0_power_CPU_MASKED_RO_full_source_before_after_each_masked_SMC=True,
            wifi_CPU0_power_CPU_MASKED_RO_full_source_before_IRQ_restore=True,
            wifi_CPU0_power_CPU_MASKED_RO_masked_nonOFF_or_uncertainty_terminal=True,
            wifi_CPU0_power_CPU_MASKED_RO_partial_restore_never_cleanup_or_service=True,
            wifi_CPU0_power_CPU_MASKED_RO_no_IRQ_contract_relaxation=True,
            wifi_CPU0_power_CPU_MASKED_RO_no_DRV_EE_EL3_VMID_MPU_grant=True,
            wifi_CPU0_power_CPU_MASKED_RO_same_fresh_spentonce_200ms_not_rebased=True)
    if a.wifi_early_memory:
        manifest.update(wifi_early_memory=True,wifi_early_memory_default_OFF=True,
            wifi_early_memory_original_calls=['GetMemoryMap','AllocateAddress MSA','GetMemoryMap','AllocateAddress RMTFS','GetMemoryMap'],
            wifi_early_memory_bootstrap_authority='incoming UEFI Boot Services contract; first call has no retrospective qualification',
            wifi_early_memory_backing_bytes=[0x200000,0x202000],
            wifi_early_memory_exposed_bytes=[0x100000,0x200000],
            wifi_early_memory_raw_format='EARLY_WIFI_MEMORY_RAW_V1',
            wifi_early_memory_raw_bytes=100848,
            wifi_early_memory_retained_no_free=True,wifi_early_memory_secure_assignment=False,
            wifi_early_memory_remote_start=False,wifi_early_memory_physical_candidate_ready=False,
            wifi_early_memory_independent_GOP_before_first_call=True,
            wifi_early_memory_UNKNOWN_display_no_firmware_call=True,
            wifi_retained_memory_preboot_GetMap_calls=1,
            wifi_retained_memory_preboot_claim_AT_pages=1026,
            wifi_retained_memory_raw_format='RETAINED_WIFI_MEMORY_RAW_V1',
            wifi_retained_memory_raw_bytes=69584,
            wifi_early_memory_IRQ_bindings=early_irq_metadata,
            wifi_early_memory_generated_inputs={p.name:sha(p) for p in out.glob('*.h')},
            wifi_current_parent_sources=False,wifi_current_parent_source_scope_default_OFF=True,
            original_GCD_new_scope_RAM_log_capacity=11534336,
            wifi_CPU0_resources_firmware_RAM_log_capacity=11534336)
    if a.mss_memory:
        manifest.update(mss_memory=True,mss_memory_default_OFF=True,
            mss_memory_backing_bytes=[0x7800000,0x100000,0x3000],mss_metadata_bytes=8412,
            mss_memory_raw_format='MSS_MEMORY_RAW_V1',mss_memory_raw_bytes=58240,mss_memory_retained_no_free=True,
            mss_memory_preboot_current_map_revalidation=True,mss_memory_target_access=False,
            mss_memory_secure_assignment=False,mss_memory_remote_start=False,
            mss_memory_physical_candidate_ready=False,
            original_GCD_new_scope_RAM_log_capacity=12582912,
            wifi_CPU0_resources_firmware_RAM_log_capacity=12582912)
    if mss_firmware:
        manifest.update(mss_staging=True,mss_staging_default_OFF=True,mss_firmware=mss_firmware,
            mss_firmware_in_payload=a.mss_firmware_in_payload,mss_firmware_embedded=not a.mss_firmware_in_payload,
            mss_virtual_zero_storage=mss_bss,
            mss_firmware_generated_inputs={p.name:sha(p) for p in (out/'mss-firmware').iterdir()},
            mss_stage_assets=['MBA','metadata'],mss_stage_target_pages=259,
            mss_stage_raw_format='MSS_STAGE_RAW_V1',mss_stage_raw_bytes=91656,
            mss_stage_source_AT_hash_before_target_write=True,mss_stage_per_page_AT_readback_CIVAC=True,
            mss_stage_secure_assignment=False,mss_stage_modem_segments_loaded=False,mss_stage_remote_start=False,
            mss_memory_target_access=True,mss_stage_physical_candidate_ready=False,
            original_GCD_new_scope_RAM_log_capacity=13631488,
            wifi_CPU0_resources_firmware_RAM_log_capacity=13631488)
    if a.mss_mba_share:
        manifest.update(mss_MBA_share=True,mss_MBA_share_default_OFF=True,mss_MBA_share_bytes=0x100000,
            mss_MBA_share_source_VMIDs=[3],mss_MBA_share_destination_VMIDs=[15],mss_MBA_share_permissions=6,
            mss_MBA_share_raw_format='MSS_MBA_SHARE_RAW_V1',mss_MBA_share_raw_bytes=12288,mss_MBA_share_raw_excludes_descriptor_page=True,
            mss_MBA_share_max_secure_rounds=4,mss_MBA_share_descriptor_retained=True,
            mss_MBA_share_target_never_read_after_assignment=True,mss_MBA_share_remote_start=False,
            mss_MBA_share_physical_candidate_ready=False)
    if wifi_nonce_metadata:
        manifest.update(wifi_host_nonce_pool=wifi_nonce_metadata,
            wifi_host_nonce_header_sha256=sha(out/'uefi-wifi-image-nonce-pool.h'),
            wifi_host_nonce_native_enabled=False,wifi_host_nonce_physical_candidate_ready=False)
    if a.wifi_native_runtime:
        manifest.update(wifi_native_runtime_enabled=True,wifi_native_runtime_default_OFF=True,
            wifi_native_auth_metadata_checkpoint=bool(a.wifi_native_auth_metadata_checkpoint),
            wifi_native_auth_metadata_checkpoint_phase=a.wifi_native_auth_metadata_checkpoint,
            wifi_native_first_rmb_events=a.wifi_native_first_rmb_events,
            wifi_native_runtime_binding=wifi_runtime_metadata,
            wifi_native_runtime_header_sha256=sha(out/'uefi-wifi-native-runtime-config.h'),
            wifi_native_NV_generated_inputs={p.name:sha(p) for p in (out/'wifi-nv').iterdir()},
            wifi_native_extra_sources=list(wifi_runtime_packager.SOURCES),
            wifi_host_nonce_native_enabled=True,wifi_native_display_input_integrated=True,
            wifi_native_display_input_qualification=wifi_runtime_metadata["display_input_qualification"],
            wifi_native_physical_candidate_ready=False,wifi_native_boot_admission=False)
    if a.wifi_firmware_diagnostic_only:
        manifest.update(wifi_firmware_diagnostic_only=True,XNU_execution_forbidden=True,
            firmware_diagnostic_terminal='unconditional hold before kernel runtime handoff',
            userdata_access_api=False)
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ['artifact','sha256','bytes','QEMU_variant','device_execution_tested']}))


if __name__=='__main__':main()
