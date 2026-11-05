"""Execute the real init plist transaction on a temporary host root only."""
from pathlib import Path
import copy
import plistlib
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
POSTER = '/System/Library/LaunchAngels/com.apple.PosterBoard.plist'
MEDIA = '/System/Library/LaunchDaemons/com.apple.mediaserverd.plist'
WIFI = '/Library/LaunchDaemons/local.polaris.wifi-probe.plist'


class WifiLaunch(unittest.TestCase):
    def test_actual_plist_write_and_conflict_preserve_other_jobs(self):
        jobs = {
            POSTER: dict(Label='com.apple.PosterBoard', ProgramArguments=['/Applications/PosterBoard.app/PosterBoard']),
            MEDIA: dict(Label='com.apple.mediaserverd', ProgramArguments=['/usr/sbin/mediaserverd']),
            'unrelated': dict(Label='unchanged', MachServices={'original': True}),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'init-test'
            subprocess.run(['clang', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                            '-fsanitize=address,undefined', '-DPGPU_USERLAND_20F66=1',
                            '-DPOLARIS_WIFI_BOOT_PROBE=1', '-DPOLARIS_POSTER_STDIO_TEST=1',
                            str(ROOT / 'userland/gpu/polaris-init.c'), '-framework', 'CoreFoundation',
                            '-o', str(target)], check=True)
            path = root / 'System/Library/xpc/launchd.plist'
            path.parent.mkdir(parents=True)
            for conflict in (False, True):
                original = dict(LaunchDaemons=copy.deepcopy(jobs), Other='untouched')
                if conflict:
                    original['LaunchDaemons'][WIFI] = dict(Label='already present')
                raw = plistlib.dumps(original)
                path.write_bytes(raw)
                p = subprocess.run([str(target), str(root)], capture_output=True, text=True)
                if conflict:
                    self.assertNotEqual(p.returncode, 0)
                    self.assertEqual(path.read_bytes(), raw)
                else:
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                    after = plistlib.loads(path.read_bytes())
                    self.assertEqual(after['Other'], 'untouched')
                    self.assertEqual(after['LaunchDaemons']['unrelated'], jobs['unrelated'])
                    wifi = after['LaunchDaemons'][WIFI]
                    self.assertEqual(wifi['ProgramArguments'], ['/usr/libexec/polaris-init', '--wifi-probe'])
                    self.assertEqual(wifi['UserName'], 'root')
                    self.assertTrue(wifi['RunAtLoad'])
                    self.assertFalse(wifi['KeepAlive'])
                self.assertFalse((path.parent / '.polaris-poster-stdio.plist').exists())


if __name__ == '__main__':
    unittest.main()
