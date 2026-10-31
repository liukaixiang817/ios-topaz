"""Exact expected-product validation; no USB, device selection or command API."""
import re


def expected_polaris_fastboot(returncode, output):
    if type(returncode) is not int or returncode != 0 or type(output) is not str:
        return False
    products = []
    for line in output.splitlines():
        match = re.fullmatch(r'\s*(?:\(bootloader\)\s*)?product:\s*([A-Za-z0-9._-]+)\s*', line)
        if match:
            products.append(match.group(1))
        elif re.match(r'\s*(?:\(bootloader\)\s*)?product:', line):
            return False
    return products == ['polaris']
