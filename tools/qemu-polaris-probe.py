#!/usr/bin/env python3
"""Exercise the actual polaris probe in QEMU RAM, including its board guard.

This checks CPU-only execution, framebuffer text and rejection of another
board. It cannot verify ABL image acceptance or the phone's actual scanout.
No phone tools or disk devices are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import time


def decode(raw, font):
    rows = re.findall(r"\{([^{}]+)\}", font)
    glyphs = {bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", row)): chr(32 + i)
              for i, row in enumerate(rows)}
    lines = []
    for row in range((2160 - 24) // 48):
        line = ""
        for col in range((1080 - 48) // 24):
            glyph = []
            for y in range(16):
                bits = 0
                for x in range(8):
                    off = ((24 + row * 48 + y * 3) * 1080 + 24 + col * 24 + x * 3) * 4
                    if raw[off:off + 4] == b"\xff" * 4:
                        bits |= 1 << (7 - x)
                glyph.append(bits)
            line += glyphs.get(bytes(glyph), "?")
        if line.strip():
            lines.append(line.rstrip())
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--dtb", type=Path, required=True)
    parser.add_argument("--image", type=Path, help="alternate diagnostic Image")
    parser.add_argument("--outdir", type=Path, help="keep variant evidence separately")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    image = args.image.resolve() if args.image else root / "shim/out/polaris-probe-0001/Image"
    out = args.outdir.resolve() if args.outdir else root / "research/polaris/qemu-probe"
    out.mkdir(parents=True, exist_ok=True)
    stub = out / "entry.bin"
    stub.write_bytes(struct.pack("<4I2Q", 0x58000080, 0x580000b0, 0xd61f0200,
                                0xd503201f, 0x90000000, 0x80080000))
    tree = args.dtb.read_bytes()
    results = []
    for name, blob in [("matching", tree), ("wrong-board", tree.replace(b"Polaris", b"NotThis"))]:
        if name == "wrong-board" and blob == tree:
            raise ValueError("input tree has no Polaris model")
        path = out / name
        path.mkdir(exist_ok=True)
        dtb = path / "input.dtb"
        dtb.write_bytes(blob)
        error_log = (path / "stderr.log").open("wb")
        proc = subprocess.Popen([args.qemu, "-M", "virt,gic-version=3", "-cpu", "cortex-a76",
                                 "-m", "4G", "-smp", "1", "-display", "none", "-serial", "none",
                                 "-monitor", "none", "-qmp", "stdio", "-S", "-no-reboot",
                                 "-d", "int,guest_errors", "-D", str(path / "exceptions.log"),
                                 "-device", f"loader,file={stub},addr=0x80000000,cpu-num=0",
                                 "-device", f"loader,file={image},addr=0x80080000",
                                 "-device", f"loader,file={dtb},addr=0x90000000"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log)
        try:
            greeting = json.loads(proc.stdout.readline())
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")

            def qmp(command, arguments=None):
                request = {"execute": command}
                if arguments:
                    request["arguments"] = arguments
                proc.stdin.write(json.dumps(request).encode() + b"\n")
                proc.stdin.flush()
                while True:
                    response = json.loads(proc.stdout.readline())
                    if "event" not in response:
                        if "error" in response:
                            raise RuntimeError(response)
                        return response["return"]

            qmp("qmp_capabilities")
            qmp("cont")
            time.sleep(3)
            qmp("stop")
            registers = qmp("human-monitor-command", {"command-line": "info registers"})
            (path / "registers.txt").write_text(registers)
            qmp("pmemsave", dict(val=0x9d400000, size=1080 * 2160 * 4, filename=str(path / "fb.raw")))
            qmp("quit")
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            error_log.close()
        raw = (path / "fb.raw").read_bytes()
        if (path / "exceptions.log").stat().st_size:
            raise RuntimeError(f"{name}: guest exception or invalid memory access")
        if name == "matching":
            text = decode(raw, (root / "shim/font.h").read_text())
            (path / "fb.txt").write_text(text)
            for expected in ("MIX 2S boot diagnostic 0001", "no disk driver linked", "parked"):
                if expected not in text:
                    raise RuntimeError(f"expected screen text missing: {expected}\n{text}")
            rgb = bytearray(1080 * 2160 * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = raw[2::4], raw[1::4], raw[0::4]
            (path / "fb.ppm").write_bytes(b"P6\n1080 2160\n255\n" + rgb)
            print(text)
        elif any(raw):
            raise RuntimeError("wrong-board: framebuffer was modified")
        results.append(dict(case=name, passed=True))
    record = dict(image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(), cases=results,
                  scope="QEMU CPU/RAM only; no hardware boot or storage validation")
    (out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
