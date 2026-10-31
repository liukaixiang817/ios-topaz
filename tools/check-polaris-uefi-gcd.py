#!/usr/bin/env python3
"""Focused NEW provider checks; no USB, original firmware or radio execution."""
from pathlib import Path
import subprocess,json,hashlib,re,sys
import argparse,importlib.util
R=Path(__file__).resolve().parents[1];W=R/'shim/polaris'
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
def binding_module(name):
 spec=importlib.util.spec_from_file_location(name,R/'tools'/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h,_=binding_module('polaris-uefi-gcd-identity').binding(R/'research/polaris/uefi-integration-0057/firmware-files/d6a2cb7f-6a18-4e2f-b43b-9920a733700a.efi');(out/'uefi-gcd-core-binding.h').write_text(h)
h,_=binding_module('polaris-wifi-firmware-identity').binding(R/'research/polaris/uefi-integration-0057/firmware-files/f541d663-4a48-40aa-aabf-ff158ccae34c.efi');(out/'uefi-wifi-cache-binding.h').write_text(h)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inc=['-I',str(W),'-I',str(R/'shim/polaris'),'-I',str(out)]
commands=[]
def run(cmd,name):
 p=subprocess.run(cmd,cwd=R,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);commands.append(dict(command=cmd,exit=p.returncode,log=name));(out/name).write_text(p.stdout)
 if p.returncode:raise RuntimeError(p.stdout)
 return p.stdout
run(['clang','-std=c11','-D_POSIX_C_SOURCE=200112L','-O1','-g','-fsanitize=address,undefined','-Wall','-Wextra','-Werror','-Wno-unused-function',*inc,str(R/'tools/polaris-uefi-gcd-config-runtime-test.c'),'-o',str(out/'host-test')],'host-build.log')
fixture=R/'research/polaris/uefi-integration-0057/firmware-files/d6a2cb7f-6a18-4e2f-b43b-9920a733700a.efi'
host_lines=[json.loads(line) for line in run([str(out/'host-test'),str(fixture)],'host-result.log').splitlines()]
assert host_lines[0]['checks']==36 and host_lines[1]['NEW_exactspan_tests']==15
host=dict(checks=51,affected_legacy_cases=36,new_exactspan_cases=15,record_bytes=30224,original_code_executed=False,MMIO=0,SMEM=0,details=host_lines)
s='#include <stdint.h>\nvoid text(const char *);void report(const char *,uint64_t);\n#include "uefi-gcd-mmio-readonly.h"\nvoid actual_prepare(struct efi_system *system,const struct efi_loaded *self){\n#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)\n (void)pgcd_bind_resident(self);struct pgcd_context *c=pgcd_prepare(system,2);const struct pgcd_observation *o=0;\n for(unsigned k=0;k<4;k++)(void)pgcd_query_page(c,pgcd_pages[k],&o);\n (void)pgcd_finish(c);(void)pgcd_prestart_check(c);\n#else\n (void)system;(void)self;\n#endif\n}\n'.replace('void actual_prepare','_Static_assert(sizeof(struct pgcd_result)==30224,"actual GCD result ABI");\n_Static_assert(sizeof(struct pgcd_service_guard)==464,"actual guard ABI");\n_Static_assert(sizeof(struct pgcd_observation)==576,"actual observation ABI");\nvoid actual_prepare')
(out/'actual.c').write_text(s)
base=['clang','-O2','-ffreestanding','-fno-stack-protector','-mgeneral-regs-only','-Wall','-Wextra','-Werror','-Wno-unused-function',*inc,'-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1']
for target,ext in [('aarch64-pc-windows-msvc','obj'),('arm64-apple-macos11','o')]:
 run([*base,'--target='+target,'-c',str(out/'actual.c'),'-o',str(out/('actual.'+ext))],ext+'-build.log')
 dis=run(['/usr/bin/objdump','-d',str(out/('actual.'+ext))],ext+'-disassembly.txt')
 def body(name):
  m=re.search(r'<_?'+name+r'>:(.*?)(?=\n[0-9a-f]+ <|\Z)',dis,re.S);assert m,name;return m.group(1)
 for name,restore in [('pgcd_actual_fp_save',False),('pgcd_actual_fp_restore',True)]:
  b=body(name);cp=b.index('CPACR_EL1');q=re.search(r'\b(?:stp|ldp)\s+q8, q9',b);assert q and cp<q.start() and re.search(r'\bb\.(?:ne|eq)\b',b[cp:q.start()]);assert not re.search(r'\bmsr\s+CPACR',dis)
  firstfp=min(x for x in [b.find('FPCR'),b.find('FPSR'),q.start()] if x>=0);assert cp<firstfp
  (out/(name+'.'+ext+'.txt')).write_text(b)
# Physical body included only by the NEW actual main branch. These unit OFF
# stubs do not establish whole-main QEMU compilation; that separate check is
# required when parent applies the integration patch.
proof=dict(PASS=True,host=host,actual_cross_compiled_targets=['AArch64 COFF','AArch64 MachO'],compiler_general_regs_only=True,
 assembler_only_fp_feature_does_not_write_CPACR=True,FP_first_instruction_after_actual_CPACR_FPEN3=True,
 original_PE_as_data_only=True,firmware_executed=False,MMIO_or_SMEM_executed=False,
 first_GetMap_authority='incoming UEFI BootServices contract; bootstrap TPL not read before owned-map proof',
 first_GetMap_TPL_sentinel='UINT64_MAX=NOT_OBSERVED, not proven current TPL',
 final_prestart_not_a_renewed_read_permission=True,architecture_external_SError_recoverable=False,
 indirect_original_event_dispatch_possible=True,nonreturning_original_service_has_no_proven_walltime_bound=True,
 source_sha256={str(p.relative_to(R)):sha(p) for p in [W/'uefi-gcd-mmio-readonly.h',W/'gcd-core-identity.h',R/'tools/polaris-uefi-gcd-identity.py',R/'tools/polaris-uefi-gcd-test.c',R/'tools/polaris-uefi-gcd-config-runtime-test.c',Path(__file__).resolve()]},
 commands=commands)
(out/'proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(dict(proof=str(out/'proof.json'),sha256=sha(out/'proof.json'),checks=host['checks'])))
