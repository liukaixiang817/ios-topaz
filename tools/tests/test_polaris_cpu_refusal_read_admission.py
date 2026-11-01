"""Returned pre-mask refusal permits retirement only; exact source-bound READ scope."""
import ast
import subprocess
import unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a, desc

class CPURefusalReadAdmission(unittest.TestCase):
    def test_exact_new_scope(self):
        p=a.GCD_CLOCK_0168
        self.assertIs(a.original_gcd_policy(desc(p)),p)
        self.assertEqual((len(p['inputs']),len(p['metadata'])),(88,252))
        self.assertIn('shim/polaris/uefi-wifi-cpu-refusal-scope.md',p['power_scope_review'])
    def test_four_retirement_restrictions_required(self):
        for name in ('normal_ON_pending_known_refusal','CPU_refusal_requires_all_guard_returns_and_full_close',
                     'CPU_refusal_never_masks_or_stores','unsupported_or_unknown_CPU_state_quarantines'):
            for value in (None,False,1):
                d=desc(a.GCD_CLOCK_0168);key=a.POWER_PREFIX+'current_ARC_'+name
                if value is None:del d[key]
                else:d[key]=value
                with self.subTest(name=name,value=value),self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_no_vote_unknown_or_deadline_relaxation(self):
        for key,value in [('current_ARC_resource_WRITE_reachable',True),('current_ARC_read_qualified_response_semantics_proven',True),
                          ('prepared_original_private_deadline_ticks',3840001),('unknown_blocks_native_PON_receipt',False)]:
            d=desc(a.GCD_CLOCK_0168);d[a.POWER_PREFIX+key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_old_parent_or_metadata_cannot_substitute(self):
        d=desc(a.GCD_CLOCK_0168);d['inputs']['shim/polaris/uefi-wifi-power-path.h']=a.GCD_CLOCK_0167['inputs']['shim/polaris/uefi-wifi-power-path.h']
        with self.assertRaises(ValueError):a.original_gcd_policy(d)
        d=desc(a.GCD_CLOCK_0168)
        for key in set(a.GCD_CLOCK_0168['metadata'])-set(a.GCD_CLOCK_0167['metadata']):del d[key]
        d.update(a.GCD_CLOCK_0167['metadata'])
        with self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_twenty_one_prior_literals_immutable(self):
        root=Path(__file__).resolve().parents[2]
        old=subprocess.check_output(['git','show','e6fb4d416bcb00c5932fad2ce35ad39a5d00935c:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
        def values(s):return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('GCD_CLOCK_')}
        before,now=values(old),values((root/'tools/polaris_wled_runtime_admission.py').read_text())
        self.assertEqual(len(before)-1,21)
        for name,value in before.items():self.assertEqual(now[name],value,name)
