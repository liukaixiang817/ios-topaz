#!/usr/bin/env python3
"""Host and actual-codegen checks for the default-OFF CPU0 9-word candidate.

No device/SMC/BootServices/physical SMEM operations. The host reader is a fake;
the AArch64 instructions are compiled/disassembled, never executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--captured-cache", type=Path, required=True)
    p.add_argument("--binding-dir", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--whole-driver-config", type=Path)
    a = p.parse_args()
    r = Path(__file__).resolve().parents[1]
    out = a.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    runs = []

    def run(name, command):
        q = subprocess.run(list(map(str, command)), capture_output=True)
        (out / (name + ".log")).write_bytes(q.stdout + q.stderr)
        runs.append(dict(name=name, exit=q.returncode, command=list(map(str, command))))
        if q.returncode:
            raise RuntimeError(name + " failed; see its log")
        return q.stdout.decode()

    binding_dir = a.binding_dir.resolve()
    fixture = out / "fake-reader-ASAN-UBSAN"
    run("host-compile", ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-g",
        "-fsanitize=address,undefined", "-I" + str(binding_dir), r / "tools/polaris-wifi-firstread-test.c", "-o", fixture])
    checks = json.loads(run("host-fixture", [fixture, a.captured_cache.resolve()]))
    wrapper = out / "actual-firstread-entry.c"
    wrapper.write_text('#include <stdint.h>\nvoid text(const char *);\nvoid report(const char *,uint64_t);\n'
        '#include "' + str(r / "shim/polaris/uefi-wifi-firstread.h") + '"\n'
        'void actual_firstread_entry(const struct efi_loaded *self){\n'
        'pwfr_bind_resident(self);pwfr_prepare(&pwfc_record,2);}\n'
        '#if EFI_XNU_WIFI_FIRSTREAD_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)\n'
        'int actual_ordinary_load32(uint64_t a,uint32_t *v){return pwfr_actual_load32(0,a,v);}\n'
        '#endif\n')
    common = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fshort-wchar",
              "-mgeneral-regs-only", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(binding_dir)]
    actual = {}
    actual_load_words = []
    actual_PAR_chains = []
    for name, flags in [("ON", ["-DEFI_XNU_WIFI_FIRSTREAD_AVAILABLE=1"]), ("DEFAULT_OFF", []),
                        ("SOFTWARE_DISABLED", ["-DEFI_XNU_WIFI_FIRSTREAD_AVAILABLE=1", "-DPOLARIS_EFI_TEST_QEMU=1"])]:
        run(name + "-COFF", ["clang", "--target=aarch64-unknown-windows", *common, *flags,
            "-c", wrapper, "-o", out / (name + ".obj")])
        run(name + "-MachO", ["clang", "--target=arm64-apple-macos14", *common, *flags,
            "-c", wrapper, "-o", out / (name + ".o")])
        dis = run(name + "-instructions", ["otool", "-tvV", out / (name + ".o")]).lower()
        lines = dis.splitlines()
        forbidden = [x for x in lines if "\tsmc\t" in x or "\thvc\t" in x or "el2" in x or "el3" in x or
                     ("\tmsr\t" in x and "par_el1" not in x)]
        if forbidden:
            raise RuntimeError("unexpected secure/EL2/EL3/permission/IRQ instruction")
        if name == "ON":
            for instruction in ["s1e1r", "cntvct_el0", "cntfrq_el0", "par_el1", "ttbr0_el1", "ttbr1_el1", "dsb\tsy"]:
                if instruction not in dis:
                    raise RuntimeError("actual instruction absent: " + instruction)
            load = dis.split("_actual_ordinary_load32:", 1)[1].split("\n_", 1)[0]
            if "ldr\tw" not in load or "ldp\t" in load or "ldrb\t" in load or "ldrh\t" in load:
                raise RuntimeError("requires exact ordinary32-bit load body")
            for n, line in enumerate(lines):
                if "s1e1r" in line:
                    chain = lines[n-1:n+4]
                    if len(chain)!=5 or "mrs" not in chain[0] or "par_el1" not in chain[0] or \
                            "isb" not in chain[2] or "mrs" not in chain[3] or "par_el1" not in chain[3] or \
                            "msr" not in chain[4] or "par_el1" not in chain[4]:
                        raise RuntimeError("actual PAR save/AT/ISB/read/restore chain missing")
                    actual_PAR_chains.append(chain)
            # Extract the actual ordinary-load fixture machine words from its
            # MachO symbol/section location, independently of assembly text.
            raw = (out/(name+".o")).read_bytes()
            commands=struct.unpack_from('<I',raw,16)[0];at=32;text_section=None;symbols=None
            for _ in range(commands):
                kind,size=struct.unpack_from('<II',raw,at)
                if kind==0x19:
                    sections=struct.unpack_from('<I',raw,at+64)[0]
                    for s in range(sections):
                        sec=at+72+80*s
                        if raw[sec:sec+16].rstrip(b'\0')==b'__text':
                            text_section=struct.unpack_from('<QQI',raw,sec+32)
                if kind==2:symbols=struct.unpack_from('<IIII',raw,at+8)
                at+=size
            if not text_section or not symbols:raise RuntimeError('actual MachO text/symbol metadata missing')
            symoff,count,strings,strings_bytes=symbols;found=[]
            for n in range(count):
                nameoff,typ,sec,desc,value=struct.unpack_from('<IBBHQ',raw,symoff+16*n)
                end=raw.find(b'\0',strings+nameoff,strings+strings_bytes)
                if nameoff<strings_bytes and raw[strings+nameoff:end]==b'_actual_ordinary_load32':found.append(value)
            if len(found)!=1:raise RuntimeError('ordinary load fixture symbol not unique')
            va,bytes_,fileoff=text_section;offset=fileoff+found[0]-va
            actual_load_words=list(struct.unpack_from('<4I',raw,offset))
            if sum((w&0xffc00000)==0xb9400000 for w in actual_load_words)!=1:
                raise RuntimeError('actual ordinary load must contain exactly one LDR32')
        elif "s1e1r" in dis or "cntvct_el0" in dis:
            raise RuntimeError("defaultOFF/software entry retained physical operations")
        actual[name] = dict(compile=True, no_secure_or_IRQ_writes=True, physical_operations_compiled_out=name != "ON")
    whole = None
    if a.whole_driver_config:
        config = a.whole_driver_config.resolve()
        with tempfile.TemporaryDirectory(prefix="polaris-firstread-EFI-", dir="/private/tmp") as td:
            private = Path(td)
            shutil.copytree(r / "shim/polaris", private / "shim/polaris")
            (private / "tools").symlink_to(r / "tools", target_is_directory=True)
            main_c = private / "shim/polaris/uefi-xnu.c"
            source = main_c.read_text()
            if source.count('int cache_ok=pwfc_collect_preboot(system_table,load_state);') != 1 or \
                    source.count('if(cache_ok)pwfr_prepare(&pwfc_record,load_state);') != 1:
                raise ValueError("actual integration/order changed")
            variants = {}
            for name, enabled, software in [("ON", 1, False), ("DEFAULT_OFF", 0, False),
                                            ("SOFTWARE_DISABLED", 1, True)]:
                variant = private / name
                variant.mkdir()
                # Preserve actual current payload/offset config. Only this
                # explicit new flag and the SOFTWARE scope differ per compile.
                variant_config = config.read_text() + \
                    '\n#undef EFI_XNU_WIFI_FIRSTREAD_AVAILABLE\n#define EFI_XNU_WIFI_FIRSTREAD_AVAILABLE ' + str(enabled) + '\n'
                (variant / config.name).write_text(variant_config)
                # Quoted include lookup starts beside the actual source. Put
                # the config there so an earlier binding -I cannot shadow it.
                (main_c.parent / config.name).write_text(variant_config)
                scope = ["-DPOLARIS_EFI_TEST_QEMU=1", "-DEFI_XNU_WLED_NATIVE_RUNTIME_TEST=1"] if software else \
                    ["-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1"]
                options = ["clang", "--target=aarch64-unknown-windows", *common, *scope,
                           "-I" + str(variant), "-I" + str(config.parent)]
                run("whole-" + name + "-TU", [*options, "-c", main_c, "-o", out / ("whole-" + name + ".obj")])
                pre = run("whole-" + name + "-preprocess", [*options, "-E", "-P", main_c])
                (out / ("whole-" + name + ".i")).write_text(pre)
                firstread_present = "pwfr_collect(" in pre
                if firstread_present != (enabled == 1 and not software):
                    raise RuntimeError("physical firstread must be absent in defaultOFF/SOFTWARE")
                if software and "WIFI_FIRSTREAD_SOFTWARE_PHYSICAL_SMEM_READ_COMPILED_OUT=" not in pre:
                    raise RuntimeError("SOFTWARE compiled-out marker missing")
                variants[name] = dict(actual_TU_compile=True, physical_firstread_compiled_out=not firstread_present)
            whole = dict(actual_TU_compile=True, actual_integrated_source=True, no_private_hook_rewrite=True,
                         variants=variants, config_sha256=hashlib.sha256(config.read_bytes()).hexdigest())
    files = ["shim/polaris/uefi-wifi-firstread.h", "tools/polaris-wifi-firstread-test.c", "tools/polaris-wifi-firstread-check.py"]
    if a.whole_driver_config:
        files += ["shim/polaris/uefi-xnu.c", "shim/polaris/uefi-wifi-cache-readonly.h",
                  "tools/build-polaris-uefi-xnu.py"]
    result = dict(passed=True, host=checks, actual_codegen=actual, whole_EFI=whole, runs=runs,
                  actual_ordinary_load_words=[hex(w) for w in actual_load_words],actual_PAR_chains=actual_PAR_chains,
                  inputs={f:hashlib.sha256((r/f).read_bytes()).hexdigest() for f in files},
                  captured_input_sha256=hashlib.sha256(a.captured_cache.read_bytes()).hexdigest(),
                  source_only_candidate=True, hardware_executed=False, device_actions=False,
                  external_SError_recoverable=False, hardware_MPU_or_VMID_query=False,
                  native_CPU7_permission=False, may_transmit=False)
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(passed=True, host_checks=checks["checks"], actual_codegen=actual, whole_EFI=whole,
                         hardware_executed=False, external_SError_recoverable=False)))


if __name__ == "__main__":
    main()
