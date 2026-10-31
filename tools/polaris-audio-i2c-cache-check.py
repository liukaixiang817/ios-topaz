#!/usr/bin/env python3
"""Compile the independent original-I2CDxe RAM witness and its finite fixtures.

Never touches USB, executes original code, calls an I2C/DAL method or reads
hardware. No main driver or image builder is changed. Output is private build
evidence, including a digest-only original-firmware binding.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-i2c-pe", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    original, out = args.original_i2c_pe.resolve(), args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("audio_binding", root / "tools/polaris-audio-i2c-firmware-identity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    header, source = module.binding(original)
    binding = out / "uefi-audio-i2c-cache-binding.h"
    if binding.exists() and binding.read_text() != header:
        raise ValueError("refuse changing frozen binding")
    binding.write_text(header)
    runs = []

    def run(name, command):
        proc = subprocess.run([str(x) for x in command], cwd=root, capture_output=True)
        (out / (name + ".log")).write_bytes(proc.stdout + proc.stderr)
        runs.append(dict(name=name, command=[str(x) for x in command], exit=proc.returncode))
        if proc.returncode:
            raise RuntimeError(f"{name} failed; see {out / (name + '.log')}")
        return proc.stdout.decode()

    fixture = out / "audio-cache-fixture"
    run("host-ASAN-UBSAN-compile", ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-O2", "-g", "-fsanitize=address,undefined", "-DEFI_XNU_AUDIO_I2C_CACHE_AVAILABLE=1",
        "-I" + str(out), root / "tools/polaris-audio-i2c-cache-test.c", "-o", fixture])
    fixture_result = json.loads(run("host-ASAN-UBSAN-fixture", [fixture, original]))
    wrapper = out / "actual-audio-cache-entry.c"
    wrapper.write_text('#include <stdint.h>\nvoid text(const char *);\nvoid report(const char *,uint64_t);\n'
        '#include "' + str(root / "shim/polaris/uefi-audio-i2c-cache.h") + '"\n'
        'void audio_cache_actual_entry(struct efi_system *system){paic_prepare(system,2);}\n')
    common = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fshort-wchar",
              "-mgeneral-regs-only", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(out)]
    actual = ["-DEFI_XNU_AUDIO_I2C_CACHE_AVAILABLE=1"]
    run("actual-AArch64-COFF", ["/usr/bin/clang", "--target=aarch64-unknown-windows", *common, *actual,
        "-c", wrapper, "-o", out / "actual-audio-cache-entry.obj"])
    run("actual-AppleClang-MachO", ["/usr/bin/clang", "--target=arm64-apple-macos14", *common, *actual,
        "-c", wrapper, "-o", out / "actual-audio-cache-entry.o"])
    disassembly = run("actual-AppleClang-instructions", ["/usr/bin/otool", "-tvV", out / "actual-audio-cache-entry.o"])
    low = disassembly.lower()
    required = ["s1e1r", "par_el1", "cntvct_el0", "cntfrq_el0", "ttbr0_el1", "ttbr1_el1",
                "sctlr_el1", "mair_el1", "icc_sre_el1", "icc_igrpen1_el1", "dsb\tsy"]
    if any(value not in low for value in required):
        raise RuntimeError("actual RAM collector architectural instructions missing")
    if re.search(r"\b(smc|hvc|eret)\b|\b(msr|mrs)\b[^\n]*(?:_el2|_el3)", low):
        raise RuntimeError("unexpected privilege/SMC/HVC instruction")
    msr = [line for line in low.splitlines() if re.search(r"\bmsr\b", line)]
    if not msr or any("par_el1" not in line for line in msr):
        raise RuntimeError("only saved PAR_EL1 restoration may use MSR")
    chains, lines = [], low.splitlines()
    for index, line in enumerate(lines):
        if "s1e1r" in line:
            chain = lines[max(0, index-2):index+5]
            if not any("mrs" in value and "par_el1" in value for value in chain[:2]) or not any(
                    "msr" in value and "par_el1" in value for value in chain[2:]):
                raise RuntimeError("actual ordered PAR save/AT/ISB/read/restore absent")
            chains.append(chain)

    disabled = []
    for name, defines in [("defaultOFF", []), ("SOFTWARE", [*actual, "-DPOLARIS_EFI_TEST_QEMU=1"])]:
        obj = out / (name + "-audio-cache-entry.o")
        run(name + "-AppleClang", ["/usr/bin/clang", "--target=arm64-apple-macos14", *common, *defines,
            "-c", wrapper, "-o", obj])
        decoded = run(name + "-instructions", ["/usr/bin/otool", "-tvV", obj]).lower()
        if re.search(r"\b(mrs|msr|at|blr|smc|hvc|dsb)\b", decoded):
            raise RuntimeError(name + " must contain no architecture read, indirect BS call or hardware instruction")
        disabled.append(dict(variant=name, no_arch_reads_or_indirect_BS_calls=True))

    raw = original.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3c)[0]
    debug = pe + 24 + 112 + 6*8
    display = bytearray(raw)
    display[debug:debug+8] = bytes(8)
    mutated = bytearray(raw)
    mutated[0x1100] ^= 1
    negatives = []
    with tempfile.TemporaryDirectory(prefix="polaris-audio-identity-", dir="/private/tmp") as temporary:
        for name, data in [("truncated", raw[:-1]), ("disassembly-only-debug-patched", display),
                           ("code-byte-mutated", mutated)]:
            path = Path(temporary) / (name + ".efi")
            path.write_bytes(data)
            try:
                module.binding(path)
            except ValueError as error:
                negatives.append(dict(name=name, rejected=True, reason=str(error), sha256=hashlib.sha256(data).hexdigest()))
            else:
                raise RuntimeError("exact original binding accepted " + name)

    files = ["shim/polaris/uefi-audio-i2c-cache.h", "tools/polaris-audio-i2c-firmware-identity.h",
             "tools/polaris-audio-i2c-firmware-identity.py", "tools/polaris-audio-i2c-cache-test.c",
             "tools/polaris-audio-i2c-cache-check.py"]
    result = dict(passed=True, fixture=fixture_result, source_binding=source,
                  generated_binding_sha256=hashlib.sha256(header.encode()).hexdigest(),
                  actual_instruction_chains=chains, required_actual_instructions=required,
                  only_MSR_saved_PAR_restore=msr, disabled_variants=disabled,
                  original_image_negative_checks=negatives, runs=runs,
                  inputs={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files},
                  shared_source_modified=False, integrated_in_phone_image=False,
                  original_code_executed=False, device_actions=False, MMIO_reads=0,
                  I2C_DAL_methods_called=0, cached_pointer_followed=False,
                  SE5_owner_proved=False, TAS_identity_proved=False, PCM_completed=False,
                  new_native_CI_needed=False)
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(passed=True, fixture_checks=fixture_result["checks"],
                         actual_AArch64_compiles=2, disabled_variants=2,
                         identity_negative_checks=len(negatives), device_actions=False)))


if __name__ == "__main__":
    main()
