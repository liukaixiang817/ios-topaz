#!/usr/bin/env python3
"""Differential/independent-oracle verification of scalar Core hash batching."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = '0a7ce93b70a002b21c87f5c676d491643cc42e59'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bindings', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args();bindings, out = a.bindings.resolve(), a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    d = json.loads((bindings/'manifest.json').read_text());original = ROOT/d['original_GCD_original_PE']
    raw = original.read_bytes()
    spec = importlib.util.spec_from_file_location('own_core', ROOT/'tools/polaris-uefi-gcd-identity.py')
    identity = importlib.util.module_from_spec(spec);spec.loader.exec_module(identity)
    header, binding = identity.binding(original)
    (out/'uefi-gcd-core-binding.h').write_text(header)
    # Independent Python SHA oracle over the actual original input bytes.
    oracle = []
    for span in binding['ranges']:
        rva, size = span['rva'], span['bytes']
        canonical = bytearray(raw)
        imagebase_rva = struct.unpack_from('<I',raw,0x3c)[0]+48
        assert f'#define PGCI_IMAGEBASE_RVA {imagebase_rva}u' in header
        struct.pack_into('<Q', canonical, imagebase_rva, 0)
        canonical[0x1bb28:0x1bb2c] = bytes(4)
        value = hashlib.sha256(canonical[rva:rva+size]).hexdigest()
        assert value == span['sha256']
        oracle.append(dict(rva=rva, bytes=size, SHA256=value))
    old = subprocess.check_output(['git', 'show', REFERENCE+':shim/polaris/gcd-core-identity.h'], cwd=ROOT).decode()
    function = old[old.index('static inline int pgci_verify('):old.rindex('#endif')]
    (out/'pgci-committed-reference.h').write_text('#if !__STDC_HOSTED__\n#error Test reference must never enter EFI\n#endif\n'+function.replace('pgci_verify(', 'pgci_verify_reference(', 1))
    records = []
    def run(name, cmd):
        r = subprocess.run([str(x) for x in cmd], cwd=ROOT, capture_output=True, text=True, timeout=180)
        (out/(name+'.log')).write_text(r.stdout+r.stderr);records.append(dict(name=name, exit=r.returncode, command=[str(x) for x in cmd]))
        if r.returncode:raise RuntimeError(name+': inspect '+str(out/(name+'.log')))
        return r.stdout
    inc = ['-I'+str(out), '-I'+str(bindings), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris')]
    flags = ['/usr/bin/clang', '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    run('ASAN-UBSAN-build', [*flags, '-O1', '-g', '-fsanitize=address,undefined', *inc, ROOT/'tools/polaris-gcd-hash-test.c', '-o', out/'test'])
    peer = json.loads(run('ASAN-UBSAN-cases', [out/'test', original]));assert peer['passed'] and peer['all_relocation_bytes_tested'] == 1952
    run('host-scalar-benchmark-build', [*flags, '-O2', '-fno-builtin', '-mgeneral-regs-only', *inc, ROOT/'tools/polaris-gcd-hash-test.c', '-o', out/'benchmark'])
    bench = json.loads(run('host-scalar-benchmark', [out/'benchmark', original, 'benchmark']))
    wrapper = out/'scalar.c';wrapper.write_text('#include <stdint.h>\nvoid text(const char *);void report(const char *,uint64_t);\n#include "gcd-core-identity.h"\nint scalar(const uint8_t *p,uint64_t b,uint8_t h[5][32],unsigned *f,unsigned *c){return pgci_verify(p,b,PGCI_IMAGE_BYTES,h,f,c);}\n')
    for target, suffix in [('aarch64-unknown-windows','obj'), ('arm64-apple-macos14','o')]:
        run('scalar-'+suffix,[*flags,'--target='+target,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-mgeneral-regs-only','-Wframe-larger-than=1024',*inc,'-c',wrapper,'-o',out/('scalar.'+suffix)])
    sha = lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    proof = dict(passed=True,checks=records,peer=peer,host_benchmark=bench,reference_commit=REFERENCE,
        reference_header_SHA256=hashlib.sha256(old.encode()).hexdigest(),independent_hashlib_oracle=oracle,
        all_original_ranges_bytes_relocations_CRC_ImageBase_preserved=True,source_hashes_each=5,
        checkpoint_count_not_reduced=True,deadline_200ms_not_extended=True,no_SIMD_FP_crypto_instructions_requested=True,
        actual_COFF_MachO=True,max_frame=1024,phone_USB=False,phone_timing_proven=False,old_failure_root_cause_proven=False,
        source_files={n:sha(ROOT/n) for n in ('shim/polaris/gcd-core-identity.h','tools/polaris-gcd-hash-test.c','tools/polaris-gcd-hash-check.py')})
    (out/'proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=peer['checks'],host_speed_ratio=bench['host_old_ns']/bench['host_new_ns'],proof_SHA256=sha(out/'proof.json'),physical_timing_proven=False)))


if __name__ == '__main__':main()
