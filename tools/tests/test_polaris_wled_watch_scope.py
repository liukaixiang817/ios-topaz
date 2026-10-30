"""A complete diagnostic preserves a fault and never grants writer admission."""
from pathlib import Path
import copy
import importlib.util
import subprocess
import unittest
from .test_polaris_wled_physical_scope import fixture
from .test_polaris_wled_power_scope import load

ROOT = Path(__file__).resolve().parents[2]
image = load('polaris-uefi-wled-image')
observer = load('polaris-wled-watch-observations')
host = load('polaris-uefi-wled')


def log():
    f = dict(WH_VERSION=1, WH_SOURCE_REFUSAL=7, WH_SAMPLES=32, WH_ERROR=0,
             WH_COMPLETE=1, WH_FAULT_OR=1, WH_RT_OR=2, WH_ENABLE_XOR=0,
             WH_READS=128, WH_PARTIAL_VALID=15, WH_PARTIAL_WORD=0x80020001)
    for n in range(32):
        f[f'WH_S{n:02d}_AT'] = (n*10010 << 32) | (n*10010 + 5)
        f[f'WH_S{n:02d}_WORD'] = 0x80020001
    return ('WLED_KERNEL_AP_STAGE=0x0000000000000000\r\n' +
            ''.join(f'{k}=0x{v:016x}\r\n' for k,v in f.items()) +
            'WH_WATCH_HOLD: READ_ONLY NO_WRITER_PERMISSION\r\n')


class WatchScope(unittest.TestCase):
    def test_positive_means_complete_observer_with_nonzero_fault_not_health(self):
        text = log();r = observer.parse(text)
        self.assertTrue(r['diagnostic_complete'])
        self.assertEqual((r['observed_fault_or'],r['source_refusal_preserved'],r['disappearing_fault_pairs']),(1,7,32))
        for k in ('health_proven','permits_writer','permits_retry','physical_darkness_proven','simultaneous_snapshot'):
            self.assertFalse(r[k])
        for n in range(len(text)):
            with self.assertRaises(ValueError):observer.parse(text[:n])
        for before,after in [('WH_FAULT_OR=0x0000000000000001','WH_FAULT_OR=0x0000000000000000'),
                             ('WH_SOURCE_REFUSAL=0x0000000000000007','WH_SOURCE_REFUSAL=0x0000000000000006'),
                             ('WH_READS=0x0000000000000080','WH_READS=0x000000000000007f'),
                             ('WH_S31_AT=','WH_S32_AT='),('WH_S01_AT=0x0000271a','WH_S01_AT=0x00000001')]:
            with self.subTest(before=before),self.assertRaises(ValueError):observer.parse(text.replace(before,after))
        for extra in ('WH_FAULT_OR=0x0000000000000001\n','WLED_MOCK_BACKEND=1\n',
                      'WLED_POWER_CYCLE_ERROR=0\n','Darwin Kernel Version','KERNEL_PSCI_STATUS=0'):
            with self.assertRaises(ValueError):observer.parse(text+extra)

    def test_explicit_watch_model_scope_cannot_be_substituted(self):
        d,m = fixture();d['WLED_readonly_fault_watch']=True
        for x in m:
            refused = x['controlled_read_refusal']
            x.update(WLED_readonly_fault_watch=True,controlled_fault_pulse=True)
            x['checks'].update({k:True for k in image.WATCH_CHECKS})
            x['raw_fields'].update(WH_SAMPLES=0 if refused else 32,WH_COMPLETE=int(not refused),
                                  WH_ERROR=1 if refused else 0,WH_SOURCE_REFUSAL=6 if refused else 7,
                                  WH_READS=0 if refused else 128,WLED_READONLY_RESULT=6 if refused else 7)
        image.admit(d,m,True)
        with self.assertRaises(ValueError):image.admit(d,m)
        for key in ('WLED_readonly_fault_watch','controlled_fault_pulse'):
            bad=copy.deepcopy(m);bad[0][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):image.admit(d,bad,True)
        bad=copy.deepcopy(m);bad[0]['raw_fields']['WH_FAULT_OR']=0
        # Full per-word completeness is checked by actual-model code, not this
        # synthetic fixture. Missing mandatory model checks must be rejected.
        bad[0]['checks'].pop('watch_keeps_all_fault_words')
        with self.assertRaises(ValueError):image.admit(d,bad,True)
        ios = load('polaris-uefi-xnu-image')
        for key in ('WLED_readonly_fault_watch','controlled_WLED_fault_pulse'):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'pre-XNU'):
                ios.admit({key:True},{},None,None,None)

    def test_builder_rejects_writer_and_physical_synthetic_modes_before_inputs(self):
        base=['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),'--zig','/missing',
              '--kernel','/missing','--payload','/missing','--output','/missing']
        for flags,expected in [(['--wled-fault-watch'],'no-writer'),
                               (['--test-wled-fault-pulse'],'QEMU readonly'),
                               (['--wled-fault-watch','--wled-power-cycle-only'],'no-writer')]:
            p=subprocess.run(base+flags,capture_output=True,text=True)
            self.assertEqual(p.returncode,2);self.assertIn(expected,p.stderr)


if __name__ == '__main__':unittest.main()
