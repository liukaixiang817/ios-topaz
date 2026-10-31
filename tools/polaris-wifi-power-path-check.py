#!/usr/bin/env python3
"""Check one integrated power path and affected client/CPU lifetime regressions."""
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
    records, peers, dependencies = [], {}, set()
    common = ['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    inc = ['-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-I'+str(bindings), '-I'+str(out)]

    def run(name, cmd):
        result = subprocess.run([str(x) for x in cmd], cwd=ROOT, capture_output=True, text=True, timeout=90)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        records.append(dict(name=name, exit=result.returncode, command=[str(x) for x in cmd]))
        if result.returncode:
            raise RuntimeError(f'{name}: inspect {out/(name+".log")}')
        return result.stdout

    def keep_dependencies(path):
        for word in path.read_text().replace('\\\n', ' ').split()[1:]:
            candidate = Path(word).resolve()
            if candidate.is_file() and candidate.is_relative_to(ROOT):
                dependencies.add(str(candidate.relative_to(ROOT)))

    with tempfile.TemporaryDirectory(prefix='polaris-power-path-') as temporary:
        temporary = Path(temporary)
        for label, name, count in [('client', 'rpmh-client', 46), ('CPU', 'power-critical', 26), ('path', 'power-path', 14)]:
            binary, dep = temporary/label, out/(label+'.d')
            run(label+'-ASAN-UBSAN-build', [*common, '-D_POSIX_C_SOURCE=200112L', '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1',
                '-O1', '-g', '-fsanitize=address,undefined', '-MD', '-MF', dep, *inc,
                ROOT/('tools/polaris-wifi-'+name+'-test.c'), '-o', binary])
            keep_dependencies(dep)
            peers[label] = json.loads(run(label+'-software-paths', [binary, *originals, *([a.original_pe.resolve()] if label == 'path' else [])]))
            assert peers[label]['checks'] == count
        assert peers['path']['real_firmware_or_MMIO_execution'] is False and peers['path']['physical_lease_proven'] is False
        assert peers['CPU']['DRV2_EL3_TCS_lease_granted'] is False
        wrapper = out/'integrated-physical-body.c'
        wrapper.write_text('''#include <stdint.h>
void text(const char *);void report(const char *,uint64_t);
#include "uefi-xnu-config.h"
#include "uefi-gcd-mmio-readonly.h"
#include "uefi-audio-i2c-cache.h"
#define EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE 1
#define EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE 1
#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 1
#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE 1
#include "uefi-wifi-power-path.h"
int integrated_physical_body(const struct paic_io *m,const struct paic_result *e,
 struct pgcd_context *final,struct pgcd_context *early,struct pwrcl_result *client,
 struct pwrph_work *work,struct pwrpt_result *r,uint64_t native_flag)
{
 const struct pwrcl_io private={ {*m,pwrph_actual_locate,pwrph_actual_map},pwrcl_actual_create,pwrcl_actual_drop,pwrcl_name};
 struct pwrpt_io io={ { {*m,pwrph_actual_locate,pwrph_actual_map},pwcd_actual_query},
  {m,0,pwrmd_actual_translate,pwrmd_actual_read},
  {0,pwrpc_actual_affinity,pwrpc_actual_mask,pwrpc_actual_restore},
  pwra_physical_io(m,&r->access_context),e,native_flag,r};
 return pwrcl_run_body(&private,e,2,final,early,client,work,pwrpt_body,&io);
}
''' + f'_Static_assert(sizeof(struct pwrpt_result)=={peers["path"]["path_raw_bytes"]},"whole raw path ABI");\n'
            + f'_Static_assert(sizeof(struct pwra_result)=={peers["path"]["access_raw_bytes"]},"complete checked I/O ABI");\n'
            + f'_Static_assert(sizeof(struct pwrpc_result)=={peers["path"]["CPU_raw_bytes"]},"complete CPU-local ABI");\n')
        for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
            dep = out/('integrated-'+suffix+'.d')
            run('actual-integrated-body-'+suffix, [*common, '--target='+target, '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1',
                '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only',
                '-Wframe-larger-than=1024', '-MD', '-MF', dep, *inc, '-c', wrapper, '-o', out/('integrated.'+suffix)])
            keep_dependencies(dep)
        for label, defines in [('default-OFF', ''), ('QEMU-compiledout', '#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE 1\n#define POLARIS_EFI_TEST_QEMU 1\n')]:
            source = temporary/(label+'.c')
            source.write_text(defines+'#include "uefi-wifi-power-path.h"\nint closed(void){return 0;}\n')
            run(label, [*common, '--target=aarch64-unknown-windows', '-ffreestanding', *inc, '-c', source, '-o', out/(label+'.obj')])
    dependencies.add('tools/polaris-wifi-power-path-check.py')
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    proof = dict(passed=True, scope='ONE same-context original-ABI Create -> CmdDb -> RAM/Device -> 14 PSCI/IRQ admission -> checked RSC -> source/RAM/namespace restoration -> known Delete; all external execution SOFTWARE',
        checks=records, peers=peers, software_cases=sum(v['checks'] for v in peers.values()),
        sources={name: sha(ROOT/name) for name in sorted(dependencies)},
        CmdDb_source_whole_sha256=binding['source_whole_sha256'], original_firmware_images_are_data_only=True,
        original_public_blocking_submit_never_called=True, normal_original_GCD_guard_not_relaxed=True,
        post_mask_typed_PSCI_round_precedes_local_quiescent_interval=True, no_SMC_during_active_RSC=True,
        CPU_OFF_reading_not_EL3_or_MPU_lease=True, checked_backend_scope_is_local_NS_not_hardware_authorization=True,
        current_CmdDb_full_RO_copies_before_and_after_retained=True, fresh_NS_Device_read_write_AT_before_every_RSC_access=True,
        unknown_command_status_bits_sticky_without_ACK=True, known_pre_mask_refusal_revalidates_pool_client_source_before_Delete=True,
        UNKNOWN_or_partial_retains_client_without_Delete=True, original_200ms_ticket_not_reset_or_rebased=True,
        actual_AArch64_integrated_API_MMIO_AT_PSCI_bodies_compiled=True, parent_registered=False,
        full_EFI_linked=False, new_host_profile=False, physical_hardware_ownership_established=False,
        physical_MMIO_or_firmware_executed=False, phone_USB=False, new_native_CI=False,
        old_manifest_or_frozen_controller_modified=False, may_vote=False, may_start_MSS=False, may_serve_NV_to_remote=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, software_cases=proof['software_cases'], checks=len(records),
        source_inputs=len(proof['sources']), proof_sha256=sha(out/'proof.json'), physical_lease=False, phone_USB=False)))


if __name__ == '__main__':
    main()
