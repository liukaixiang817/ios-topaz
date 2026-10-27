"""Exit-status framing for legacy recovery's raw ADB exec service.

The local adb process can exit0 even when the remote program exits1. Always
keep a parent shell to emit a nonce-bound status after a subshell. Returned
binary bytes exclude only that final frame; missing/truncated frames fail.
No device operation or retry is implemented by this module.
"""
import re
import secrets


def wrap(command, nonce=None):
    nonce = nonce or secrets.token_hex(16)
    if not isinstance(command, str) or '\0' in command or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('ordinary command text and 128-bit hex nonce required')
    frame = '\\nPOLARIS_EXIT_' + nonce + ':%d\\n'
    return '(\n' + command + '\n); polaris_rc=$?; printf \'' + frame + '\' "$polaris_rc"', nonce


def decode(data, nonce):
    if not re.fullmatch('[0-9a-f]{32}', nonce): raise ValueError('invalid exit nonce')
    pattern = rb'\nPOLARIS_EXIT_' + nonce.encode() + rb':([0-9]{1,3})\n\Z'
    match = re.search(pattern, data)
    if not match or int(match[1]) > 255: raise ValueError('missing or invalid remote exit frame')
    return data[:match.start()], int(match[1])
