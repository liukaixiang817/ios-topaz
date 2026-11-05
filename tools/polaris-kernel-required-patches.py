#!/usr/bin/env python3
"""Make mandatory Polaris patch failure fatal in the pinned upstream builder."""
import argparse
from pathlib import Path

WARNING = '                warning "Skipping patch ${PATCH} (already upstream, previously applied, or malformed): ${APPLY_CHECK}"'
GUARD = '''                if [[ "${TARGET_PLATFORM:-}" == polaris && "${PATCH##*/}" == 0[89][0-9][0-9]-*.patch ]]; then
                    echo "Mandatory Polaris patch failed: ${PATCH##*/}: ${APPLY_CHECK}" >&2
                    exit 1
                fi
'''


def require_polaris(text):
    if text.count(WARNING) != 1 or GUARD in text:
        raise ValueError('pinned patch-loop shape changed or guard already installed')
    return text.replace(WARNING, GUARD+WARNING)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('script', type=Path)
    args = parser.parse_args()
    args.script.write_text(require_polaris(args.script.read_text()))
    print('All mandatory Polaris overlay patches now fail closed')
