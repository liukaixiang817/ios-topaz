import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("stage", ROOT / "tools/stage-kernel-patches.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class ProfileTests(unittest.TestCase):
    def test_topaz_keeps_full_existing_series(self):
        selected = stage.selected_patches(ROOT, "topaz")
        self.assertEqual({p.name for p in selected},
                         {p.name for p in (ROOT / "xnu/patches").iterdir()
                          if p.suffix in (".patch", ".sh")})

    def test_polaris_excludes_other_soc_drivers(self):
        selected = stage.selected_patches(ROOT, "polaris")
        base = [p for p in selected if p.parent.name == "patches" and p.suffix == ".patch"]
        self.assertTrue(base)
        self.assertTrue(all(int(p.name[:4]) <= 79 for p in base))
        self.assertTrue(any(p.name.startswith("0800-polaris") for p in selected))
        self.assertTrue(any(p.name == "0026-stage-hfs.sh" for p in selected))
        self.assertFalse(any("topaz" in p.name for p in selected))

    def test_framebuffer_block_offset_fits(self):
        block, base, width, height, stride = 0x9c000000, 0x9d400000, 1080, 2160, 4320
        self.assertEqual(block % (32 * 1024**2), 0)
        self.assertEqual(base - block, 0x1400000)
        self.assertLessEqual(base + stride * height, block + 32 * 1024**2)
        self.assertEqual(stride, width * 4)


if __name__ == "__main__":
    unittest.main()
