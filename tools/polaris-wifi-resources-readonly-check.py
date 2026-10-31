"""SOFTWARE negative services + actual AArch64 object compilation; no device IO."""
from pathlib import Path
import argparse,datetime,hashlib,json,subprocess
R=Path(__file__).resolve().parents[1];W=R/'shim/polaris'
a=argparse.ArgumentParser(description=__doc__);a.add_argument('--out-dir',type=Path,required=True);a.add_argument('--cache-binding-dir',type=Path,required=True);a.add_argument('--cache-snapshot',type=Path,required=True);opt=a.parse_args();O=opt.out_dir;O.mkdir(exist_ok=False)
B=opt.cache_binding_dir;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();runs=[]
def run(name,cmd):
 p=subprocess.run([str(x) for x in cmd],capture_output=True);(O/(name+'.log')).write_bytes(p.stdout+p.stderr);runs.append(dict(name=name,command=[str(x) for x in cmd],exit=p.returncode));assert p.returncode==0,name;return p.stdout.decode()
common=['-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(B),'-I'+str(R/'shim/polaris'),'-I'+str(R/'tools'),'-I'+str(W)]
fixture=O/'host-ASAN-UBSAN';run('host-compile',['clang',*common,'-g','-fsanitize=address,undefined',R/'tools/polaris-wifi-resources-readonly-test.c','-o',fixture]);tests=json.loads(run('host-fixture',[fixture,opt.cache_snapshot]));assert tests['checks']==32
src=O/'actual-CPU0-entry.c';src.write_text('''#include <stdint.h>
void text(const char *);void report(const char *,uint64_t);
#include "uefi-wifi-resources-readonly.h"
_Static_assert(sizeof(struct pfr_result)==17416,"actual wire size");
_Static_assert(offsetof(struct pfr_result,maps)==1032,"actual raw maps offset");
int actual_preCPU_ON_resource_entry(struct efi_system *system,const struct efi_loaded *self,const struct pwfc_result *cache){
 (void)pfr_bind_resident(self);return pfr_prepare(system,cache,2);
}
''')
base=['-ffreestanding','-fno-builtin','-fno-stack-protector','-fshort-wchar','-mgeneral-regs-only'];variants=[]
for name,flags in [('ON',['-DEFI_XNU_WIFI_CACHE_AVAILABLE=1','-DEFI_XNU_WIFI_RESOURCES_AVAILABLE=1']),('DEFAULT_OFF',[]),('SOFTWARE',['-DEFI_XNU_WIFI_CACHE_AVAILABLE=1','-DEFI_XNU_WIFI_RESOURCES_AVAILABLE=1','-DPOLARIS_EFI_TEST_QEMU=1'])]:
 for target,suffix in [('aarch64-unknown-windows','obj'),('arm64-apple-macos14','o')]:run(name+'-'+suffix,['clang','--target='+target,*base,*common,*flags,'-c',src,'-o',O/(name+'.'+suffix)])
 dis=run(name+'-disassembly',['otool','-tvV',O/(name+'.o')]).lower();pre=run(name+'-CPP',['clang','--target=aarch64-unknown-windows',*base,*common,*flags,'-E','-P',src]);(O/(name+'.i')).write_text(pre)
 assert not any('\thvc\t' in x or ('\tmsr\t' in x) for x in dis.splitlines())
 if name=='ON':
  assert sum('\tsmc\t' in x for x in dis.splitlines())>=1 and '\tdsb\tsy' in dis and 'cntvct_el0' in dis
  for at,line in enumerate(dis.splitlines()):
   if '\tsmc\t' in line: assert '#0xc400, lsl #16' in '\n'.join(dis.splitlines()[max(0,at-8):at])
  assert 'static struct pfr_result pfr_record;' in pre and 'static struct pfr_lifetime pfr_ticket;' in pre
 else:
  assert '\tsmc\t' not in dis and 'cntvct_el0' not in dis
  assert 'pfr_actual_affinity(' not in pre and 'static struct pfr_result pfr_record;' not in pre and 'static struct pfr_lifetime pfr_ticket;' not in pre
 variants.append(dict(name=name,physical_provider_present=name=='ON',COFF_sha256=sha(O/(name+'.obj')),MachO_sha256=sha(O/(name+'.o')),preprocessor_sha256=sha(O/(name+'.i'))))
# An enabled physical resource scope cannot be silently used without cache.
p=subprocess.run(['clang','--target=aarch64-unknown-windows',*base,*common,'-DEFI_XNU_WIFI_RESOURCES_AVAILABLE=1','-c',str(src),'-o',str(O/'invalid-no-cache.obj')],capture_output=True);(O/'invalid-no-cache.log').write_bytes(p.stdout+p.stderr);assert p.returncode and b'Resource observations require the original cache witness' in p.stderr
proof=dict(passed=True,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),synthetic_tests=tests,variants=variants,wire_schema=dict(version=1,endian='little',bytes=17416,maps_offset=1032,map_buffer_bytes=8192,map_buffers=2,partial_GetMemoryMap_output_extent_unknown=True),lifetime=dict(single_static_ticket=True,prior_cache_exact_witness=True,cache_after_to_end_max_ticks=3840000,frequency=19200000,peer_vector_is_instantaneous_observation_not_exclusive_lifetime=True),scope=dict(GetMemoryMap_max_calls=2,PSCI_AFFINITY_INFO_max_calls=7,PSCI_function='0xc4000004',PSCI_target_MPIDR=['0x100','0x200','0x300','0x400','0x500','0x600','0x700'],PSCI_CPU_ON=False,SMEM_reads=0,SFPB_MMIO=0,PIL_or_SCM_init=False,resource_allocation=False,resource_writes=False,reserved_is_free=False,MPU_or_VMID_permission=False,RMTFS_address_assigned=False,MSA_address_assigned=False,physical_executed=False,phone_candidate_integrated=False,whole_EFI_or_native_CI=False,nonreturning_service_bounded_in_wall_time=False),runs=runs,inputs={str(p.resolve().relative_to(R)):sha(p) for p in (W/'uefi-wifi-resources-readonly.h',R/'tools/polaris-wifi-resources-readonly-test.c',Path(__file__).resolve(),opt.cache_snapshot,R/'shim/polaris/uefi-wifi-firstread-normal-nc.h',R/'shim/polaris/uefi-wifi-cache-readonly.h',R/'shim/polaris/uefi-memory.h',R/'shim/polaris/uefi.h',B/'uefi-wifi-cache-binding.h')})
p=O/'proof.json';p.write_text(json.dumps(proof,indent=2)+'\n');print('Resource32 syntheticchecks/AArch64COFF+MachO/ON-OFF-SOFTWARE PASS',sha(p))
