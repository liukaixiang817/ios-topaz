#!/usr/bin/env python3
"""Check source-RAM/CPU-critical/RSC admission with software peers, never a phone."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bindings', type=Path, required=True)
    p.add_argument('--original-pe', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    bindings, out = a.bindings.resolve(), a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('own_cmddb', ROOT/'tools/polaris-wifi-cmddb-identity.py')
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    header, binding = identity.binding(a.original_pe.resolve())
    (out/'uefi-wifi-cmddb-binding.h').write_text(header)
    old = json.loads((bindings/'manifest.json').read_text())
    originals = [ROOT/old[k] for k in ['original_GCD_original_PE', 'wifi_CPU0_NPA_source_PE', 'wifi_CPU0_RPMh_source_PE']]
    inc = ['-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-I'+str(bindings), '-I'+str(out)]
    common = ['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    records, peers, dependencies = [], {}, set()

    def run(name, cmd):
        result = subprocess.run([str(x) for x in cmd], cwd=ROOT, capture_output=True, text=True, timeout=60)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        records.append(dict(name=name, exit=result.returncode, command=[str(x) for x in cmd]))
        if result.returncode:
            raise RuntimeError(f'{name}: inspect {out/(name+".log")}')
        return result.stdout

    def dependency_file(path):
        for word in path.read_text().replace('\\\n', ' ').split()[1:]:
            candidate = Path(word)
            if candidate.is_file() and candidate.is_relative_to(ROOT):
                dependencies.add(str(candidate.relative_to(ROOT)))

    wrapper = out/'caller-components.c'
    wrapper.write_text('''#include <stdint.h>
void text(const char *);void report(const char *,uint64_t);
#include "uefi-xnu-config.h"
#define EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE 1
#define EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE 1
#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 1
#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE 1
#include "uefi-wifi-power-critical.h"
#include "uefi-wifi-rsc-device.h"
_Static_assert(sizeof(struct pwrpb_baseline)==117392,"complete current RAM V1");
_Static_assert(sizeof(struct pwrpc_result)==10048,"CPU-local interval V2");
_Static_assert(sizeof(struct pwrmd_result)==12256,"read admission V1");
int RAM_component(const struct paic_io *m,struct pwrcl_result *p,const struct pwrph_work *w,
 const struct pwrcl_pool *pool,const struct paic_arch *arch,struct pwrpb_baseline *r)
{return pwrpb_capture(m,p,w,pool,arch,r);}
int CPU_enter(struct pwrpc_io *io,const struct paic_io *m,struct pwrcl_result *p,
 const struct pwrph_work *w,struct pgcd_context *g,uint64_t cpu_on,struct pwrpc_result *r)
{io->affinity=pwrpc_actual_affinity;io->mask=pwrpc_actual_mask;io->restore=pwrpc_actual_restore;
 return pwrpc_begin(io,m,p,w,g,cpu_on,r);}
int CPU_retire(const struct pwrpc_io *io,const struct paic_io *m,struct pwrcl_result *p,
 const struct pwrph_work *w,struct pgcd_context *g,const struct pwrsc_transaction *tx,
 const struct pwrpb_baseline *before,const struct pwrpb_baseline *after,struct pwrpc_result *r)
{return pwrpc_end(io,m,p,w,g,tx,before,after,r);}
int device_component(struct pwrmd_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
 struct pgcd_context *g,const struct pwrpb_baseline *b,struct pwrmd_result *r)
{io->translate=pwrmd_actual_translate;io->read=pwrmd_actual_read;return pwrmd_collect(io,p,w,g,b,r);}
int ARC_component(const struct pwrsc_io *io,struct pwrsc_transaction *r,unsigned mask,
 const uint32_t *saved,const uint32_t *desired)
{return pwrsc_begin(io,r,mask,saved,desired);}
int ARC_step(const struct pwrsc_io *io,struct pwrsc_transaction *r){return pwrsc_step(io,r);}
''')
    with tempfile.TemporaryDirectory(prefix='polaris-power-caller-') as temporary:
        temporary = Path(temporary)
        cases = [('RSC', 'rsc-transaction', 43), ('RAM', 'rsc-baseline', 31),
                 ('CPU', 'power-critical', 26), ('device', 'rsc-device', 26), ('pipeline', 'power-integration', 1)]
        for label, name, count in cases:
            source, binary = ROOT/('tools/polaris-wifi-'+name+'-test.c'), temporary/label
            dep = out/(label+'.d')
            run(label+'-ASAN-UBSAN-build', [*common, '-D_POSIX_C_SOURCE=200112L', '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1',
                '-O1', '-g', '-fsanitize=address,undefined', '-MD', '-MF', dep, *inc, source, '-o', binary])
            dependency_file(dep)
            args = [] if label == 'RSC' else [originals[0], a.original_pe.resolve()] if label == 'pipeline' else originals
            peers[label] = json.loads(run(label+'-software-run', [binary, *args]))
            assert peers[label]['checks'] == count
        assert peers['RSC']['hardware_MMIO_executed'] is False and peers['device']['write_callback_exposed'] is False
        assert peers['CPU']['DRV2_EL3_TCS_lease_granted'] is False
        for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
            dep = out/('components-'+suffix+'.d')
            run('actual-AArch64-components-'+suffix, [*common, '--target='+target, '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1',
                '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only',
                '-Wframe-larger-than=1024', '-MD', '-MF', dep, *inc, '-c', wrapper, '-o', out/('components.'+suffix)])
            dependency_file(dep)
        for label, defines in [('default-OFF', ''), ('QEMU-compiledout', '#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE 1\n#define POLARIS_EFI_TEST_QEMU 1\n')]:
            source = temporary/(label+'.c')
            source.write_text(defines+'#include "uefi-wifi-power-critical.h"\n#include "uefi-wifi-rsc-device.h"\nint offline(void){return 0;}\n')
            run(label, [*common, '--target=aarch64-unknown-windows', '-ffreestanding', *inc, '-c', source, '-o', out/(label+'.obj')])
    # Preserve complete input identity, including the real source bindings and
    # affected test fixtures. Generated records/original proprietary bytes stay
    # private; only repository-authored code is a candidate for Git.
    dependencies.add('tools/polaris-wifi-power-caller-check.py')
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    sources = {name: sha(ROOT/name) for name in sorted(dependencies)}
    proof = dict(passed=True, scope='RAM cache/pool/runtime-HAL + CPU-local exclusion + source-bound RSC read admission and prefix-gated restoration components; all external execution is software',
        checks=records, peers=peers, software_cases=sum(v['checks'] for v in peers.values()), source_inputs=sources,
        CmdDb_source_whole_sha256=binding['source_whole_sha256'], original_bindings_unchanged=True,
        missing_active_state_not_zero=True, original_driver_free_queue_not_pending=True,
        actual_AArch64_AT_S1E1R_S1E1W_PAR_restore_and_CPU_mask_bodies_compiled=True,
        CPU_local_exclusion_not_DRV2_EL3_lease=True, read_adapter_exposes_no_writer=True,
        Core_RPMh_immutable_hashes_owner_protocol_and_TPL_checked_before_IRQ_restore=True,
        parent_200ms_not_reset_or_rebased=True, unknown_mask_or_transaction_never_cleanup=True,
        physical_cache_or_HAL_captured=False, physical_GCD_AT_or_MMIO_executed=False,
        physical_lease_established=False, parent_registered=False, full_EFI_linked=False, new_host_profile=False,
        phone_USB=False, old_manifest_or_frozen_controller_modified=False, native_change_or_CI=False,
        may_vote=False, may_start_MSS=False, may_serve_NV_to_remote=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, software_cases=proof['software_cases'], checks=len(records),
        source_inputs=len(sources), proof_sha256=sha(out/'proof.json'), physical_lease=False, phone_USB=False)))


if __name__ == '__main__':
    main()
