#!/usr/bin/env python3
"""Keep the Polaris-only kernel patch identical to its tested source files."""
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/profiles/polaris/0914-polaris-fixed-resident-wifi-mailbox.patch'
FILES = {
    'bsd/dev/polaris_wifi_mailbox.c': 'tools/polaris-wifi-kernel-mailbox.c',
    'bsd/dev/polaris-wifi-kernel-mailbox.h': 'tools/polaris-wifi-kernel-mailbox.h',
    'bsd/dev/polaris-wifi-mailbox.h': 'tools/polaris-wifi-mailbox.h',
    'bsd/dev/polaris-wifi-mailbox-transport.h': 'tools/polaris-wifi-mailbox-transport.h',
}


def expected():
    result = ['Polaris resident Wi-Fi mailbox storage and kernel transport only.\n',
              'No ifnet/station registration, native firmware runtime or radio enable is implied.\n\n',
              'diff --git a/bsd/conf/files b/bsd/conf/files\n',
              '--- a/bsd/conf/files\n+++ b/bsd/conf/files\n',
              '@@ -1,2 +1,3 @@\n',
              ' bsd/dev/polaris_wifi_native_ro.c\t\tstandard\n',
              ' bsd/dev/polaris_wifi_scm_info.c\t\tstandard\n',
              '+bsd/dev/polaris_wifi_mailbox.c\t\tstandard\n']
    for destination, source in FILES.items():
        lines = (ROOT / source).read_text().splitlines(keepends=True)
        if not lines or not lines[-1].endswith('\n'):
            raise ValueError('source must end with newline: ' + source)
        result += [f'diff --git a/{destination} b/{destination}\n',
                   'new file mode 100644\n', '--- /dev/null\n', f'+++ b/{destination}\n',
                   f'@@ -0,0 +1,{len(lines)} @@\n']
        result += ['+' + line for line in lines]
    return ''.join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    content = expected()
    if args.write:
        PATCH.write_text(content)
    elif PATCH.read_text() != content:
        raise SystemExit('kernel mailbox patch is stale; regenerate from tested sources')
    print('Polaris kernel mailbox patch matches four tested sources')


if __name__ == '__main__':
    main()
