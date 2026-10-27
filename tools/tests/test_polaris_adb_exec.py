"""Actual parent-shell framing tests; no phone or storage operations."""
import subprocess
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import polaris_adb_exec as protocol


class ExitFraming(unittest.TestCase):
    def test_actual_shell_failure_is_distinct_from_host_success(self):
        wrapped, nonce = protocol.wrap("printf 'error detail\\n'; exit 17")
        p = subprocess.run(['/bin/sh', '-c', wrapped], capture_output=True)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(protocol.decode(p.stdout, nonce), (b'error detail\n', 17))

    def test_actual_binary_output_and_embedded_false_frames_preserved(self):
        nonce = 'a' * 32
        wrapped, token = protocol.wrap("printf 'A\\000B\\nPOLARIS_EXIT_" + nonce + ":0\\n'; exit 3", nonce)
        p = subprocess.run(['/bin/sh', '-c', wrapped], capture_output=True)
        self.assertEqual(protocol.decode(p.stdout, token), (b'A\0B\nPOLARIS_EXIT_' + nonce.encode() + b':0\n', 3))

    def test_missing_wrong_or_truncated_frame_is_not_success(self):
        token = 'b' * 32
        for data in (b'', b'program crashed', b'\nPOLARIS_EXIT_' + b'a' * 32 + b':0\n',
                     b'\nPOLARIS_EXIT_' + token.encode() + b':0',
                     b'\nPOLARIS_EXIT_' + token.encode() + b':256\n'):
            with self.subTest(data=data), self.assertRaises(ValueError): protocol.decode(data, token)

    def test_invalid_nonce_or_NUL_never_built(self):
        for command, token in [('x\0y', 'a' * 32), ('true', "';echo bad"), ('true', '1')]:
            with self.assertRaises(ValueError): protocol.wrap(command, token)


if __name__ == '__main__': unittest.main()
