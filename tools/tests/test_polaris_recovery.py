"""Check archive preservation and the offline backup init policy on the host."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "recovery", Path(__file__).resolve().parents[1] / "build-polaris-backup-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def entry(name, mode, data=b""):
    return [name, [1, mode, 0, 0, 1, 123, len(data), 0, 0, 0, 0, len(name) + 1, 0], data]


class RecoveryTests(unittest.TestCase):
    def archive(self):
        return recovery.pack_newc([entry("init.rc", 0o100644, b"example\n"),
                                   entry("sbin/sh", 0o120777, b"busybox"),
                                   entry("TRAILER!!!", 0)])

    def test_metadata_and_symlink_preserved(self):
        entries = recovery.unpack_newc(self.archive())
        self.assertEqual(entries[0][2], b"example\n")
        self.assertEqual(entries[0][1][1], 0o100644)
        self.assertEqual(entries[0][1][5], 123)
        self.assertEqual(entries[1][1][1], 0o120777)
        self.assertEqual(entries[1][2], b"busybox")
        self.assertEqual(recovery.pack_newc(entries), self.archive())

    def test_truncated_archive_refused(self):
        blob = self.archive()
        for size in range(len(blob) - 3):
            with self.assertRaises(ValueError):
                recovery.unpack_newc(blob[:size])

    def test_crc_corruption_refused(self):
        blob = b"070702" + self.archive()[6:]
        with self.assertRaisesRegex(ValueError, "checksum"):
            recovery.unpack_newc(blob)

    def test_only_root_adb_and_ueventd_services(self):
        text = recovery.init_rc("/sbin/adbd", "/sbin/ueventd").decode()
        for forbidden in ("mount_all", "factoryreset", "wipe", "fsck", "import ", "service recovery"):
            self.assertNotIn(forbidden, text)
        services = [line.split()[1:] for line in text.splitlines() if line.startswith("service ")]
        self.assertEqual([item[0] for item in services], ["ueventd", "adbd"])
        self.assertIn("--root_seclabel=u:r:su:s0", services[1])
        mounts = [line.split()[1] for line in text.splitlines() if line.strip().startswith("mount ")]
        self.assertEqual(mounts, ["configfs", "functionfs"])


if __name__ == "__main__":
    unittest.main()
