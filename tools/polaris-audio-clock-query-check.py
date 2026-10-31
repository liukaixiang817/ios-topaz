#!/usr/bin/env python3
"""Focused original-Clock readonly baseline checks; no firmware/USB execution.

The original PE is relocated AS DATA for a SOFTWARE BootServices/API peer.
Actual AArch64 objects compile the production original-method/AT adapters.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-clock-pe", type=Path, required=True)
    parser.add_argument("--actual-cache-decoded", type=Path, required=True)
    parser.add_argument("--i2c-binding-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = root / "tools/polaris-audio-clock-identity.py"
    spec = importlib.util.spec_from_file_location("clock_identity", source)
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    pe = args.original_clock_pe.resolve()
    header, binding = identity.binding(pe)
    (out / "uefi-audio-clock-binding.h").write_text(header)
    (out / "binding.json").write_text(json.dumps(binding, indent=2) + "\n")
    decoded = json.loads(args.actual_cache_decoded.read_text())
    if not decoded["complete"] or not decoded["diagnostic_consistent"] or decoded["fields"]["error"]:
        raise ValueError("requires complete reviewed original-I2C RAM witness")
    raw = out / "actual-cache-DATA-ONLY.raw"
    raw.write_bytes(bytes.fromhex(decoded["raw_hex"]))
    runs = []

    def run(name, command):
        command = [str(x) for x in command]
        proc = subprocess.run(command, cwd=root, capture_output=True)
        (out / (name + ".log")).write_bytes(proc.stdout + proc.stderr)
        runs.append(dict(name=name, exit=proc.returncode, command=command))
        if proc.returncode:
            raise RuntimeError(name + " failed; retained exact log in " + str(out))
        return proc.stdout.decode()

    includes = ["-I" + str(args.i2c_binding_dir.resolve()), "-I" + str(out)]
    enabled = ["-DEFI_XNU_AUDIO_I2C_CACHE_AVAILABLE=1", "-DEFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE=1"]
    combined = ["-DEFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY=1", "-DEFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY=1"]
    host_results = {}
    for name, scope in [("combined15", combined), ("audio3", [])]:
        binary = out / (name + "-SOFTWARE-peer")
        run(name + "-ASAN-UBSAN-compile", ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-g",
            "-fsanitize=address,undefined", *enabled, *scope, "-DPACQ_SOFTWARE_PEER_ONLY=1", *includes,
            root / "tools/polaris-audio-clock-query-test.c", "-o", binary])
        log = out / (name + "-RAM-only.log")
        result = json.loads(run(name + "-SOFTWARE-ASAN-UBSAN", [binary, raw, pe, log]))
        full = log.read_bytes()
        for marker, expected in [(b"AUDIO_I2C_CACHE", 5096), (b"AUDIO_CLOCK_QUERY", result["wire_schema"]["bytes"])]:
            match = re.search(marker + rb"_RAW_V1_BEGIN\r\n([0-9a-f]+)\r\n" + marker + rb"_RAW_V1_END", full)
            if not match or len(bytes.fromhex(match[1].decode())) != expected:
                raise RuntimeError("complete RAM-only raw record roundtrip failed")
        if result["RAM_max_chunk"] != 126 or result["original_code_executed"] or result["actual_MMIO"]:
            raise RuntimeError("SOFTWARE data-only/compact reporting scope")
        host_results[name] = result

    schema = host_results["combined15"]["wire_schema"]
    wrapper = out / "actual-clock-entry.c"
    assertions = [f'_Static_assert(sizeof(struct pacq_result)=={schema["bytes"]},"raw result ABI");']
    for field, (offset, size) in schema["members"].items():
        assertions += [f'_Static_assert(offsetof(struct pacq_result,{field})=={offset},"{field} offset");',
                       f'_Static_assert(sizeof(((struct pacq_result*)0)->{field})=={size},"{field} bytes");']
    assertions += [f'_Static_assert(sizeof(struct pacq_query)=={schema["query_bytes"]},"query ABI");',
                   f'_Static_assert(offsetof(struct pacq_query,value)=={schema["query_value_offset"]},"query Boolean byte");']
    wrapper.write_text('#include <stdint.h>\nvoid text(const char*);\nvoid report(const char*,uint64_t);\nvoid ram_text(const char*);\n'
        '#include "' + str(root / "shim/polaris/uefi-audio-clock-query.h") + '"\n'
        '#if EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)\n' + "\n".join(assertions) + '\n#endif\n'
        'void actual_entry(struct efi_system *system,uint32_t stage)'
        '{pacq_collect_preboot(system,stage);pacq_report_preboot(ram_text);}\n')
    common = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fshort-wchar", "-mgeneral-regs-only",
              "-O2", "-Wall", "-Wextra", "-Werror", *includes]
    physical = [*enabled, *combined]
    run("actual-AArch64-COFF", ["/usr/bin/clang", "--target=aarch64-unknown-windows", *common, *physical,
        "-c", wrapper, "-o", out / "actual-clock-entry.obj"])
    run("actual-AppleClang-MachO", ["/usr/bin/clang", "--target=arm64-apple-macos14", *common, *physical,
        "-c", wrapper, "-o", out / "actual-clock-entry.o"])
    instructions = run("actual-instructions", ["/usr/bin/otool", "-tvV", out / "actual-clock-entry.o"]).lower()
    if not re.search(r"\bdsb\s+sy\b", instructions) or not re.search(r"\bat\s+s1e1r\b", instructions) or "par_el1" not in instructions:
        raise RuntimeError("requires actual DSB/AT/PAR adapters, not a SOFTWARE replacement")
    if re.search(r"\b(smc|hvc)\b", instructions) or any("par_el1" not in line for line in instructions.splitlines() if re.search(r"\bmsr\b", line)):
        raise RuntimeError("no SMC/HVC/register-write method; MSR only restores saved PAR_EL1")
    disabled = []
    for name, flags in [("defaultOFF", []), ("SOFTWARE_QEMU", [*physical, "-DPOLARIS_EFI_TEST_QEMU=1"])]:
        obj = out / (name + ".o")
        run(name + "-compile", ["/usr/bin/clang", "--target=arm64-apple-macos14", *common, *flags, "-c", wrapper, "-o", obj])
        inactive = run(name + "-instructions", ["/usr/bin/otool", "-tvV", obj]).lower()
        symbols = run(name + "-symbols", ["/usr/bin/nm", obj])
        if re.search(r"\b(blr|dsb|at|mrs|msr|smc|hvc)\b", inactive) or re.search(r"pacq_(preboot|ticket|targets)|pacqi_transform", symbols):
            raise RuntimeError(name + " must remove all original protocol/physical body and resident records")
        disabled.append(name)

    negatives = []
    original = pe.read_bytes()
    for name, bad in [("truncated", original[:-1]), ("wrong-immutable-byte", original[:0x1100] + bytes([original[0x1100]^1]) + original[0x1101:]),
                      ("display-only-debug-patch", original[:0x138] + bytes([original[0x138]^1]) + original[0x139:])]:
        path = out / (name + ".DATA-ONLY.bin")
        path.write_bytes(bad)
        try:
            identity.binding(path)
        except ValueError:
            negatives.append(name)
        else:
            raise RuntimeError("identity negative accepted " + name)

    files = ["shim/polaris/uefi-audio-clock-query.h", "tools/polaris-audio-clock-identity.h",
             "tools/polaris-audio-clock-identity.py", "tools/polaris-audio-clock-query-test.c", "tools/polaris-audio-clock-query-check.py"]
    proof = dict(passed=True, software_peer=host_results, actual_AArch64_compiles=2, actual_DSB_AT_saved_PAR=True,
        original_query_and_BootServices_UNKNOWN_outstanding_before_entry=True, whole_boot_single_ticket=True,
        combined_descriptor_targets=15, combined_possible_GCC_baselines=8, combined_max_original_query_calls=16,
        CAMCC_NOT_ISSUED=7, CAMCC_never_promoted_by_parent_ON_or_AT=True, diagnostic_success_separate_from_baseline_complete=True,
        readonly_gate="EFI_TYPE11_UC_NONRUNTIME_FULL48B_DESCRIPTOR_PLUS_ACTUAL_NS_DEVICE00_OR04_IDENTITY_AT",
        complete_raw_schema=schema, RAM_only_combined_bytes=host_results["combined15"]["RAM_only_log_bytes"],
        disabled_variants=disabled, identity_negatives=negatives, runs=runs,
        sources={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in files},
        original_PE_sha256=identity.EXPECTED, actual_I2C_cache_input_sha256=hashlib.sha256(args.actual_cache_decoded.read_bytes()).hexdigest(),
        original_firmware_executed=False, actual_MMIO_actions=0, physical_TAS_ID=False, PCM=False,
        physical_owner_lease=False, native_kernel_CI=False, USB=False, Git=False, frozen_0141_changed=False)
    (out / "result.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(dict(passed=True, combined_checks=host_results["combined15"]["checks"],
        audio_only_checks=host_results["audio3"]["checks"], raw_bytes=schema["bytes"],
        actual_AArch64_compiles=2, disabled=disabled, actual_firmware_executed=False)))


if __name__ == "__main__":
    main()
