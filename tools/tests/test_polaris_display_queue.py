"""Publication coalescing/identity and strict real-log analysis; no phone FPS model."""
import importlib.util
import json
import re
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('presentation',ROOT/'tools/polaris-presentation-latency.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
H='#include "'+str(ROOT/'tools/polaris-display-queue.h')+'"\n'


class PublicationTests(unittest.TestCase):
    def test_explicit_firmware_intent_rejects_mismatch_and_write_modes(self):
        spec=importlib.util.spec_from_file_location('builder',ROOT/'tools/build-polaris-uefi-xnu.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        base=[b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1']
        tokens=base+[b'polarisfbwake=1']
        self.assertTrue(builder.framebuffer_wake_intent(tokens,True,7,4,False,None,True,False,False))
        self.assertTrue(builder.framebuffer_wake_intent(tokens,True,7,2,True,'success',False,False,False))
        for args in [(1,4,False,None,True,False,False),(7,1,False,None,True,False,False),
                     (7,4,False,None,False,False,False),(7,4,False,None,True,True,False),
                     (7,4,False,None,True,False,True),(7,4,True,None,False,False,False)]:
            with self.assertRaises(ValueError):builder.framebuffer_wake_intent(tokens,True,*args)
        for changed in [base,tokens+[b'polarisfbwake=1'],tokens+[b'ufsrw=1']]:
            with self.assertRaises(ValueError):builder.framebuffer_wake_intent(changed,True,7,4,False,None,True,False,False)
        with self.assertRaises(ValueError):builder.framebuffer_wake_intent(tokens,False,7,4,False,None,True,False,False)
        self.assertFalse(builder.framebuffer_wake_intent(base,False,7,4,False,None,True,False,False))

    def test_coalescing_latest_replacement_and_arrival_during_copy(self):
        run(H+r'''
#include <assert.h>
int main(void){struct pfb_queue q={0};struct pfb_publication first={0},next={0};
 assert(pfb_publish(&q,1,77,true));
 for(unsigned i=2;i<=100;i++)assert(!pfb_publish(&q,i,i,true));
 assert(q.sequence==100&&q.replaced==99&&q.wake_pending);
 pfb_wake_consumed(&q);assert(pfb_take(&q,&first));
 assert(first.sequence==100&&first.ready_us==100&&first.swap==100);
 /* The immutable copy snapshot must survive a new concurrent publication. */
 assert(pfb_publish(&q,101,0,true));assert(first.sequence==100);
 assert(!pfb_publish(&q,102,UINT32_MAX,true));
 assert(pfb_take(&q,&next)&&next.sequence==102&&next.swap==UINT32_MAX);
 assert(!pfb_take(&q,&next));pfb_wake_consumed(&q);
 for(unsigned i=103;i<20103;i++){
  assert(pfb_publish(&q,i,i,true));pfb_wake_consumed(&q);
  assert(pfb_take(&q,&next)&&next.sequence==i&&next.ready_us==i);
 }
 return 0;}
''')

    def test_disabled_wake_clock_wrap_and_invalid_identity_fail_closed(self):
        run(H+r'''
#include <assert.h>
int main(void){struct pfb_queue q={0};struct pfb_publication o={0};
 assert(!pfb_publish(&q,10,1,false)&&q.pending&&!q.wake_pending);
 assert(pfb_take(&q,&o)&&o.sequence==1);
 assert(!pfb_publish(&q,9,1,true)&&q.fault&&!q.pending);
 assert(!pfb_publish(&q,11,2,true)&&!pfb_take(&q,&o));
 q=(struct pfb_queue){0};q.sequence=UINT64_MAX;
 assert(!pfb_publish(&q,100,1,true)&&q.fault&&!pfb_take(&q,&o));
 q=(struct pfb_queue){0};assert(!pfb_publish(&q,0,1,true)&&q.fault);
 q=(struct pfb_queue){0};q.replaced=UINT64_MAX;
 assert(pfb_publish(&q,1,0,true)&&!pfb_publish(&q,2,0,true));
 assert(q.replaced==UINT64_MAX&&!q.fault);
 assert(!pfb_publish(0,1,0,true)&&!pfb_take(0,&o));return 0;}
''')

    def test_compact_console_record_cannot_truncate_at_native_limit(self):
        patch=(ROOT/'xnu/profiles/polaris/0889-polaris-presentation-publication-timing-and-coalesced-wake.patch').read_text()
        fmt=re.search(r'IOLog\("(POLARIS PFB: q=.*?\\n)"',patch)[1]
        run(r'''
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
int main(void){char b[512];int n=snprintf(b,sizeof(b),
'''+json.dumps(json.loads('"'+fmt+'"'))+r''',
 UINT64_MAX*1ull,UINT32_MAX,UINT64_MAX*1ull,UINT64_MAX*1ull,UINT64_MAX*1ull,
 UINT64_MAX*1ull,UINT64_MAX*1ull,1,1,1,UINT64_MAX*1ull);
 assert(n>0&&n<255&&b[n-1]=='\n');return 0;}
''')

    def sample(self):
        return ('POLARIS PFB: q=1 s=7 r=1000 t=900 b=1200 e=7200 n=800 w=1 v=1 c=1 d=0\n'
                'POLARIS PFB: q=3 s=0 r=9000 t=9010 b=9200 e=15200 n=17000 w=0 v=0 c=1 d=1\n'
                'POLARIS PANEL PERF: end_us=16000 span_us=15500 copies=2 fps10=1290 copy_mean_us=6000 maxgap_us=8000 cadence_us=16667\n')

    def test_actual_ready_can_follow_callback_entry_but_not_copy_begin(self):
        r=module.analyze(self.sample(),0,20000)
        self.assertEqual(r['ready_to_copy_begin_us']['median'],200)
        self.assertEqual(r['actual_copy_us']['median'],6000)
        self.assertEqual(r['complete_panel_windows'][0]['copies'],2)
        self.assertEqual(r['wake_callback_copies'],1)
        self.assertFalse(r['hardware_scanout_FPS_proven'])

    def test_panel_window_keeps_copy_published_before_analysis_boundary(self):
        text=self.sample().replace('span_us=15500','span_us=14500')
        r=module.analyze(text,1100,20000)
        self.assertEqual(r['native_records'],1)
        self.assertEqual(r['complete_panel_windows'][0]['copies'],2)

    def test_malformed_or_partial_or_duplicate_records_and_early_notify_rejected(self):
        s=self.sample()
        invalid=[s.replace(' r=1000',''),s.replace('q=1','q=1 q=1'),s.replace('c=1','c=2'),
                 s.replace('n=800','n=1900'),s.replace('b=1200','b=800'),
                 s.replace('e=7200','e=90000'),s.replace('q=3','q=1'),
                 s.replace('copies=2','copies=3'),s+'POLARIS PFB ERROR: failed\n',
                 s.replace('q=1','q=1oops'),s.replace('d=0\n','d=0 merged_writer\n'),
                 s.replace('d=1','d=0').replace('d=0\nPOLARIS PFB:','d=2\nPOLARIS PFB:'),
                 s.replace('q=1','q='+str(2**64))]
        for text in invalid:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):module.analyze(text,0,20000)


if __name__=='__main__':unittest.main()
