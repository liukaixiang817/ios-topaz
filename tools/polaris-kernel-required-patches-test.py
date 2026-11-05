#!/usr/bin/env python3
import importlib.util
import subprocess
from pathlib import Path

spec = importlib.util.spec_from_file_location('required', Path(__file__).with_name('polaris-kernel-required-patches.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
script = 'warning(){ echo warning; }\nTARGET_PLATFORM=$1\nPATCH=$2\nAPPLY_CHECK=failed\n'+module.WARNING+'\necho continued\n'
guarded = module.require_polaris(script)
checks = 0
for platform, patch, failed in [('polaris','/tmp/0800-test.patch',True),('polaris','/tmp/0914-test.patch',True),
        ('polaris','/tmp/0915-test.patch',True),('polaris','/tmp/0001-test.patch',False),
        ('topaz','/tmp/0915-test.patch',False)]:
    result = subprocess.run(['bash','-c',guarded,'test',platform,patch],capture_output=True,text=True)
    assert (result.returncode == 1) == failed
    assert ('continued' not in result.stdout) == failed
    checks += 1
for text in ('', script+module.WARNING, guarded):
    try:
        module.require_polaris(text)
    except ValueError:
        checks += 1
    else:
        raise AssertionError('accepted changed/already guarded builder')
print(f'PASS {checks} required-profile shell checks')
