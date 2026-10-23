#!/usr/bin/env python3
"""Read an UNMOUNTED polaris OS partition into a verified host gzip backup.

No phone writes, mounts, unmounts, reboots, or restoration operations. Android
userdata is refused while mounted. Keep the phone in the same OS until done.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import gzip
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("partition", choices=["mindowswin", "userdata"])
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--jobs", type=int, choices=range(1, 5), default=4)
    parser.add_argument("--su", choices=["/debug_ramdisk/su", "/system/bin/su", "/sbin/su", "none"],
                        default="/debug_ramdisk/su")
    args = parser.parse_args()
    adb = [args.adb, "-d"]

    def command(script):
        script = "stty raw -echo 2>/dev/null; " + script
        return script if args.su == "none" else f"{args.su} -c {shlex.quote(script)}"

    def remote(script, timeout=60):
        return subprocess.run(adb + ["exec-out", command(script)], check=True,
                              capture_output=True, timeout=timeout).stdout

    if remote("getprop ro.product.device").strip() != b"polaris":
        raise SystemExit("Refusing: not a polaris device")
    if not remote("id").startswith(b"uid=0(root)"):
        raise SystemExit("Root access is required")
    source = "/dev/block/bootdevice/by-name/" + args.partition
    node = remote(f"readlink -f {source}").decode().strip().rsplit("/", 1)[-1]
    if not node.startswith("sd") or not node.isalnum():
        raise SystemExit("Unexpected block device")
    device = remote(f"cat /sys/class/block/{node}/dev").decode().strip()

    def check_unmounted():
        # mountinfo uses decimal major:minor, just like sysfs /dev.
        for line in remote("cat /proc/self/mountinfo").decode().splitlines():
            if line.split()[2] == device:
                raise SystemExit(f"Refusing: {args.partition} is mounted; use offline recovery")

    check_unmounted()
    expected = int(remote(f"blockdev --getsize64 {source}"))
    out = Path(__file__).resolve().parents[1] / "backup" / (
        f"polaris-full-{args.partition}-" + time.strftime("%Y%m%d-%H%M%S"))
    out.mkdir(parents=True, mode=0o700)
    chunk_bytes = 4 * 1024**3
    pieces = (expected + chunk_bytes - 1) // chunk_bytes
    started = time.monotonic()
    processes = set()
    lock = threading.Lock()
    stopped = threading.Event()
    record = dict(partition=args.partition, device=node, raw_bytes=expected,
                  verified=False, state="receiving", chunk_bytes=chunk_bytes)
    (out / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"Backing up {args.partition}: {expected} raw bytes in {pieces} chunks to {out}", flush=True)

    def receive(index):
        partial = out / f"part-{index:04d}.img.gz.partial"
        remaining = min(chunk_bytes, expected - index * chunk_bytes)
        # dd only opens an input block device. Last chunk ends at its EOF.
        count = (remaining + 4194303) // 4194304
        script = f"dd if={source} bs=4194304 skip={index * 1024} count={count} 2>/dev/null | gzip -1 -c"
        process = subprocess.Popen(adb + ["exec-out", command(script)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with lock:
            processes.add(process)
        try:
            with partial.open("xb") as stream:
                partial.chmod(0o600)
                while chunk := process.stdout.read(1024 * 1024):
                    if stopped.is_set():
                        raise RuntimeError("Backup interrupted")
                    if shutil.disk_usage(out).free < 8 * 1024**3:
                        raise RuntimeError("Less than 8 GiB immediate free space; partial files retained")
                    stream.write(chunk)
            _, stderr = process.communicate(timeout=60)
            if process.returncode:
                raise RuntimeError(stderr.decode(errors="replace"))
            digest, size = hashlib.sha256(), 0
            with gzip.open(partial, "rb") as stream:
                while chunk := stream.read(4 * 1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            if size != remaining:
                raise RuntimeError(f"Chunk {index}: short read {size} != {remaining}")
            print(f"Chunk {index + 1}/{pieces}: {size / 1024**3:.2f} GiB read, "
                  f"{partial.stat().st_size / 1024**2:.0f} MiB compressed, gzip checked", flush=True)
            return dict(index=index, raw_bytes=size, compressed_bytes=partial.stat().st_size,
                        raw_sha256=digest.hexdigest(), file=partial.name)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
            with lock:
                processes.discard(process)

    pool = ThreadPoolExecutor(max_workers=args.jobs)
    try:
        futures = [pool.submit(receive, i) for i in range(pieces)]
        chunks = []
        for future in as_completed(futures):
            chunks.append(future.result())
            record["chunks"] = sorted(chunks, key=lambda item: item["index"])
            (out / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
        check_unmounted()
        record["state"] = "verifying"
        (out / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
        digest, size = hashlib.sha256(), 0
        print("Checking concatenated raw length and SHA-256", flush=True)
        for chunk in record["chunks"]:
            with gzip.open(out / chunk["file"], "rb") as stream:
                while data := stream.read(4 * 1024 * 1024):
                    digest.update(data)
                    size += len(data)
        if size != expected:
            raise RuntimeError("Concatenated raw size mismatch")
        print("Computing source SHA-256 on the phone", flush=True)
        source_hash = remote(f"sha256sum {source}", timeout=1800).decode().split()[0]
        check_unmounted()
        if source_hash != digest.hexdigest():
            raise RuntimeError("Source SHA-256 mismatch; partial backup retained")
        for chunk in record["chunks"]:
            path = out / chunk["file"]
            path.rename(path.with_suffix(""))
            chunk["file"] = path.with_suffix("").name
        record.update(compressed_bytes=sum(c["compressed_bytes"] for c in record["chunks"]),
                      raw_sha256=source_hash, verified=True, state="verified",
                      elapsed_seconds=round(time.monotonic() - started))
        (out / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
        print(f"VERIFIED: {out}", flush=True)
    finally:
        stopped.set()
        with lock:
            for process in processes:
                if process.poll() is None:
                    process.kill()
        pool.shutdown(wait=True, cancel_futures=True)


if __name__ == "__main__":
    main()
