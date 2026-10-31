#!/usr/bin/env python3
"""Verify the actual EFI cache-only collector without executing firmware.

No USB, SMC, original entry/Get/Alloc or hardware reads. Optional whole-driver
check uses a private source copy and existing compatible EFI objects only.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-smem-pe", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--whole-driver-config", type=Path)
    parser.add_argument("--zig", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    original = args.original_smem_pe.resolve()
    spec = importlib.util.spec_from_file_location("own_binding", root / "tools/polaris-wifi-firmware-identity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    header, source = mod.binding(original)
    binding = out / "uefi-wifi-cache-binding.h"
    if binding.exists() and binding.read_text() != header:
        raise ValueError("refuse changing frozen binding")
    binding.write_text(header)
    runs = []

    def run(name, command, env=None):
        proc = subprocess.run([str(x) for x in command], cwd=root, env=env, capture_output=True)
        (out / (name + ".log")).write_bytes(proc.stdout + proc.stderr)
        runs.append(dict(name=name, command=[str(x) for x in command], exit=proc.returncode))
        if proc.returncode:
            raise RuntimeError(f"{name} failed; see {out / (name + '.log')}")
        return proc.stdout.decode()

    fixture = out / "cache-only-fixture"
    run("host-ASAN-UBSAN-compile", ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-O2", "-g", "-fsanitize=address,undefined", "-I" + str(out),
        root / "tools/polaris-wifi-firmware-cache-test.c", "-o", fixture])
    fixture_result = json.loads(run("host-ASAN-UBSAN-fixture", [fixture, original]))
    wrapper = out / "actual-cache-entry.c"
    wrapper.write_text('#include <stdint.h>\nvoid text(const char *);\nvoid report(const char *,uint64_t);\n'
        '#include "' + str(root / "shim/polaris/uefi-wifi-cache-readonly.h") + '"\n'
        'void cache_only_actual_entry(struct efi_system *system){pwfc_prepare(system,2);}\n')
    common = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fshort-wchar",
              "-mgeneral-regs-only", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(out)]
    run("actual-AArch64-COFF", ["/usr/bin/clang", "--target=aarch64-unknown-windows", *common,
        "-c", wrapper, "-o", out / "actual-cache-entry.obj"])
    run("actual-AppleClang-MachO", ["/usr/bin/clang", "--target=arm64-apple-macos14", *common,
        "-c", wrapper, "-o", out / "actual-cache-entry.o"])
    disassembly = run("actual-AppleClang-instructions", ["/usr/bin/otool", "-tvV", out / "actual-cache-entry.o"])
    low = disassembly.lower()
    required = ["s1e1r", "par_el1", "cntvct_el0", "cntfrq_el0", "ttbr0_el1", "ttbr1_el1",
                "sctlr_el1", "mair_el1", "icc_sre_el1", "icc_igrpen1_el1"]
    if any(x not in low for x in required) or "smc\t" in low or "smc " in low:
        raise RuntimeError("actual cache-only instructions missing or unexpected SMC")
    # Preserve the exact ordered AT+ISB+MRS+restored-PAR instruction body.
    lines = low.splitlines()
    chains = []
    for n, line in enumerate(lines):
        if "s1e1r" in line:
            chain = lines[max(0, n-2):n+5]
            if not any("mrs" in x and "par_el1" in x for x in chain[:2]) or not any(
                    "msr" in x and "par_el1" in x for x in chain[2:]):
                raise RuntimeError("PAR save/restore sequence absent")
            chains.append(chain)
    whole = None
    if args.whole_driver_config:
        cfg = args.whole_driver_config.resolve()
        with tempfile.TemporaryDirectory(prefix="polaris-cache-EFI-", dir="/private/tmp") as temporary:
            private = Path(temporary)
            shutil.copytree(root / "shim/polaris", private / "shim/polaris")
            (private / "tools").symlink_to(root / "tools", target_is_directory=True)
            current = private / "shim/polaris/uefi-xnu.c"
            content = current.read_text()
            at = 'static int prepare_boot(void *context)\n'
            if content.count(at) != 1:
                raise ValueError("exact private prepare_boot hook anchor")
            content = content.replace(at, '#include "uefi-wifi-cache-readonly.h"\n' + at, 1)
            before = '(void)context;if(load_state!=2)return 0;\n'
            start = content.index(at)
            if content[start:].count(before) != 1:
                raise ValueError("exact private before-mask stage hook")
            content = content[:start] + content[start:].replace(before, before + '    pwfc_prepare(system_table,load_state);\n', 1)
            current.write_text(content)
            obj = out / "whole-uefi-xnu-with-cache.obj"
            run("whole-current-EFI-AArch64", ["/usr/bin/clang", "--target=aarch64-unknown-windows", *common,
                "-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1", "-I" + str(cfg.parent), "-c", current, "-o", obj])
            whole = dict(compiled=True, private_hook_only=True, shared_source_modified=False,
                         config_sha256=hashlib.sha256(cfg.read_bytes()).hexdigest())
            if args.zig:
                names = ["uefi-xnu-ap", "uefi-xnu-crc", "payload", "uefi-usb", "uefi-usb-command", "uefi-usb-control"]
                objects = [cfg.parent / (n + ".obj") for n in names]
                if any(not p.is_file() for p in objects):
                    raise ValueError("existing whole EFI objects unavailable")
                env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / "zig-global"), ZIG_LOCAL_CACHE_DIR=str(out / "zig-local"))
                image = out / "cache-only-COMPILE-ONLY.efi"
                run("whole-current-EFI-link", [args.zig.resolve(), "build-exe", obj, *objects, "-target", "aarch64-uefi",
                    "--subsystem", "efi_boot_service_driver", "-O", "ReleaseSmall", "-femit-bin=" + str(image)], env)
                whole.update(linked=True, artifact_sha256=hashlib.sha256(image.read_bytes()).hexdigest(), bytes=image.stat().st_size)
    files = ["shim/polaris/uefi-wifi-cache-readonly.h", "tools/polaris-wifi-firmware-identity.h",
             "tools/polaris-wifi-firmware-identity.py", "tools/polaris-wifi-firmware-cache-test.c",
             "tools/polaris-wifi-firmware-cache-check.py"]
    result = dict(passed=True, fixture=fixture_result, source_binding=source,
                  generated_binding_sha256=hashlib.sha256(header.encode()).hexdigest(),
                  actual_instruction_chains=chains, required_actual_instructions=required,
                  whole_EFI=whole, runs=runs,
                  inputs={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files},
                  original_code_executed=False, device_actions=False, SMEM_reads=0, radio=False,
                  current_native_gate_changed=False, may_transmit=False)
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(passed=True, checks=fixture_result["checks"], whole_EFI=whole,
                         SMEM_reads=0, original_code_executed=False)))


if __name__ == "__main__":
    main()
