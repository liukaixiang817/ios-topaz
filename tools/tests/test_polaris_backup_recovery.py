"""Bounded RAM-only audit watchdog; no phone or host reboot command executes."""
import ast
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('backup_builder',ROOT/'tools/build-polaris-backup-recovery.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


class ReadonlyWatchdog(unittest.TestCase):
    def test_default_init_is_byte_identical_to_previous_builder(self):
        source=subprocess.check_output(['git','show','65f063e:tools/build-polaris-backup-recovery.py'],cwd=ROOT,text=True)
        node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='init_rc')
        scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),'previous_init','exec'),scope)
        self.assertEqual(builder.init_rc('/sbin/adbd','/sbin/ueventd'),scope['init_rc']('/sbin/adbd','/sbin/ueventd'))

    def test_actual_shell_calls_only_one_bootloader_property_after_bound_or_sleep_failure(self):
        script=builder.watchdog_script(300).decode()
        subprocess.run(['/bin/sh','-n'],input=script,text=True,check=True)
        for failure,expected in [(0,60),(2,2)]:
            prefix=f'''ticks=0; calls=0
sleep() {{ [ "$#" = 1 ] && [ "$1" = 5 ] || exit 71; ticks=$((ticks+1)); [ "$ticks" != {failure} ]; }}
setprop() {{ [ "$#" = 2 ] && [ "$1" = sys.powerctl ] && [ "$2" = reboot,bootloader ] || exit 72; calls=$((calls+1)); }}
'''
            p=subprocess.run(['/bin/sh','-c',prefix+script+f'\n[ "$ticks" = {expected} ] && [ "$calls" = 1 ]'],capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr)

    def test_explicit_scope_has_no_storage_or_recovery_jobs(self):
        init=builder.init_rc('/sbin/adbd','/sbin/ueventd',300).decode()
        self.assertIn('start polaris-audit-watchdog',init)
        self.assertIn('service polaris-audit-watchdog /sbin/sh /sbin/polaris-audit-watchdog.sh',init)
        self.assertIn('    oneshot\n',init)
        for bad in ('import ','fsck','mount_all','start recovery','/dev/block/sda','format '):
            self.assertNotIn(bad,init)
        for seconds in (0,True,299,301):
            with self.assertRaises(ValueError):builder.watchdog_script(seconds)


if __name__=='__main__':unittest.main()
