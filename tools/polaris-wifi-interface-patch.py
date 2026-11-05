#!/usr/bin/env python3
"""Bind the Polaris BSD frontend and actual startup/drain hooks to tested code."""
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT/'xnu/profiles/polaris/0915-polaris-resident-wifi-bsd-interface.patch'


def expected():
    text = ['Polaris opt-in BSD interface over the resident Wi-Fi mailbox.\n',
            'Native CPU0 radio/runtime remains a separate required implementation.\n\n',
            '--- a/bsd/conf/files\n+++ b/bsd/conf/files\n',
            '@@ -112,3 +112,4 @@\n',
            ' bsd/dev/polaris_wifi_scm_info.c\t\tstandard\n',
            ' bsd/dev/polaris_wifi_mailbox.c\t\tstandard\n',
            '+bsd/dev/polaris_wifi_interface.c\t\tstandard\n',
            ' bsd/dev/sweet_sample.c\t\t\tstandard\n']
    text.append((ROOT/'tools/polaris-wifi-interface-hooks.patch').read_text())
    for source, destination in [('polaris-wifi-interface.c','polaris_wifi_interface.c'),
                                ('polaris-wifi-interface.h','polaris-wifi-interface.h')]:
        lines = (ROOT/'tools'/source).read_text().splitlines(True)
        if not lines or not lines[-1].endswith('\n'):
            raise ValueError('source requires a final newline')
        text += [f'--- /dev/null\n+++ b/bsd/dev/{destination}\n', f'@@ -0,0 +1,{len(lines)} @@\n']
        text += ['+'+line for line in lines]
    return ''.join(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    content = expected()
    if args.write:
        PATCH.write_text(content)
    elif PATCH.read_text() != content:
        raise SystemExit('kernel interface patch differs from tested sources/hooks')
    print('Polaris interface patch matches tested sources and startup/drain hooks')
