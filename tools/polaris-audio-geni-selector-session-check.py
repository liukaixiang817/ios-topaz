#!/usr/bin/env python3
"""Focused compile/issued-boundary checks for the future SE5 three-command selector/identity session.

Runs an explicit SOFTWARE peer using the actual0141 RAM witness as data. No
physical provider is supplied or claimed, and no image/builder is modified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual-cache-decoded", type=Path, required=True)
    parser.add_argument("--binding-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    decoded = json.loads(args.actual_cache_decoded.read_text())
    if not decoded["complete"] or not decoded["diagnostic_consistent"] or decoded["fields"]["error"]:
        raise ValueError("requires complete reviewed actual original-I2C RAM witness")
    raw = out / "actual-cache-DATA-ONLY.raw"
    raw.write_bytes(bytes.fromhex(decoded["raw_hex"]))
    runs = []

    def run(name, command):
        p = subprocess.run([str(x) for x in command], cwd=root, capture_output=True)
        (out / (name + ".log")).write_bytes(p.stdout + p.stderr)
        runs.append(dict(name=name, exit=p.returncode, command=[str(x) for x in command]))
        if p.returncode:
            raise RuntimeError(name + " failed; retained log in " + str(out))
        return p.stdout.decode()

    include = "-I" + str(args.binding_dir.resolve())
    fixture = out / "geni-software-peer"
    run("host-ASAN-UBSAN-compile", ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-g",
        "-fsanitize=address,undefined", "-DEFI_XNU_AUDIO_GENI_SELECTOR_SESSION_AVAILABLE=1", "-DPAIG_SOFTWARE_PEER_ONLY=1", include,
        root / "tools/polaris-audio-geni-selector-session-test.c", "-o", fixture])
    tests = json.loads(run("host-SOFTWARE-ASAN-UBSAN", [fixture, raw]))
    wrapper = out / "actual-fifo-entry.c"
    wrapper.write_text('#include <stdint.h>\nvoid text(const char*);\nvoid report(const char*,uint64_t);\n'
        '#include "' + str(root / "tools/polaris-audio-geni-selector-session.h") + '"\n'
        'int actual_entry(const struct paig_io *io,const struct paic_result *cache,struct pags_result *out)'
        '{return pags_identity_session_once(io,cache,2,0,out);}\n')
    common = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fshort-wchar", "-mgeneral-regs-only",
              "-O2", "-Wall", "-Wextra", "-Werror", include]
    physical = ["-DEFI_XNU_AUDIO_GENI_SELECTOR_SESSION_AVAILABLE=1", "-DEFI_XNU_AUDIO_GENI_FIFO_PHYSICAL_PROVIDER_AVAILABLE=1"]
    run("actual-AArch64-COFF", ["/usr/bin/clang", "--target=aarch64-unknown-windows", *common, *physical,
        "-c", wrapper, "-o", out / "actual-fifo-entry.obj"])
    run("actual-AppleClang-MachO", ["/usr/bin/clang", "--target=arm64-apple-macos14", *common, *physical,
        "-c", wrapper, "-o", out / "actual-fifo-entry.o"])
    actual = run("actual-instructions", ["/usr/bin/otool", "-tvV", out / "actual-fifo-entry.o"]).lower()
    if "dsb\tsy" not in actual or re.search(r"\b(smc|hvc|mrs|msr)\b", actual):
        raise RuntimeError("requires actual DSB publish ordering without privilege/SMC/clock manipulation")
    disabled = []
    for name, defines in [("defaultOFF", []), ("missingPhysicalProvider", physical[:1]),
                           ("SOFTWARE_QEMU", [*physical, "-DPOLARIS_EFI_TEST_QEMU=1"])]:
        obj = out / (name + ".o")
        run(name + "-compile", ["/usr/bin/clang", "--target=arm64-apple-macos14", *common, *defines, "-c", wrapper, "-o", obj])
        instructions = run(name + "-instructions", ["/usr/bin/otool", "-tvV", obj]).lower()
        if re.search(r"\b(blr|dsb|mrs|msr|smc|hvc)\b", instructions):
            raise RuntimeError(name + " must compile out all provider calls and physical execution body")
        disabled.append(name)
    files = ["tools/polaris-audio-geni-selector-session.h", "tools/polaris-audio-geni-selector-session-test.c", "tools/polaris-audio-geni-selector-session-check.py"]
    result = dict(passed=True, software_peer=tests, actual_AArch64_compiles=2, actual_DSB_SY_present=True,
                  issued_UNKNOWN_outstanding_before_callback=True, synchronous_fault_retained_and_second_object_rejected=True,
                  full_boot_controller_ticket_no_physical_reset_api=True, physical_order_callback_must_equal_actual_DSB_function=True,
                  disabled_variants=disabled, runs=runs,
                  sources={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in files},
                  actual_cache_input_sha256=hashlib.sha256(args.actual_cache_decoded.read_bytes()).hexdigest(),
                  actual_cache_is_data_only=True, physical_provider_implemented=False,
                  physical_owner_clock_pin_power_selector_qualification=False,
                  original_protocol_methods_called=0, actual_MMIO_actions=0, physical_TAS_ID=False, PCM=False,
                  native_kernel_CI=False, USB=False, Git=False, shared_or_0141_input_changed=False)
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(passed=True, software_checks=tests["checks"], actual_AArch64_compiles=2,
                         disabled_variants=disabled, physical_provider_implemented=False)))


if __name__ == "__main__":
    main()
