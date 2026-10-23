#!/usr/bin/env python3
"""Stage one hardware patch profile without mixing topaz and polaris drivers."""
import argparse
from pathlib import Path
import shutil


def selected_patches(root, platform):
    common = root / "xnu/patches"
    if platform == "topaz":
        return sorted(common.glob("*.patch")) + sorted(common.glob("*.sh"))
    if platform != "polaris":
        raise ValueError("unknown platform")
    # Sweet's 0001..0079 form the original ARMv8.2 baseline. Topaz's 0080+
    # contain another SoC's MMIO, CPU topology, GPU and firmware interfaces.
    patches = [p for p in sorted(common.glob("*.patch")) if int(p.name[:4]) <= 79]
    patches += sorted(common.glob("*.sh"))
    overlay = sorted((root / "xnu/profiles/polaris").glob("*.patch"))
    if not overlay:
        raise ValueError("polaris overlay missing")
    return patches + overlay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["topaz", "polaris"], required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    selected = selected_patches(root, args.platform)
    names = {p.name for p in selected}
    owned = {p.name for p in (root / "xnu").rglob("*.patch")}
    args.destination.mkdir(parents=True, exist_ok=True)
    stale = {p.name for p in args.destination.glob("*.patch")} & (owned - names)
    if stale:
        raise SystemExit("Refusing mixed profiles; use a clean build patches directory: " + ", ".join(sorted(stale)))
    for path in selected:
        shutil.copy2(path, args.destination / path.name)
    print(f"Staged {len(selected)} files for {args.platform}")


if __name__ == "__main__":
    main()
