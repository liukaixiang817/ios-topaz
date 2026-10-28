"""Original HFI request transactions, bounded policy and failure retention.
ASan/UBSan callbacks test actual implementation; no physical MHz/FPS claim.
"""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class StockGPU(unittest.TestCase):
 def test_explicit_firmware_intent_no_accidental_mode_or_durable_bypass(self):
  import importlib.util
  spec=importlib.util.spec_from_file_location('builder',ROOT/'tools/build-polaris-uefi-xnu.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  base=[b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1']
  for mode in (1,2,3):
   tokens=base+[f'polarisgpup={mode}'.encode()]
   self.assertEqual(m.gpu_stock_intent(tokens,mode,7,4,False,None,True,False,False),mode)
   self.assertEqual(m.gpu_stock_intent(tokens,mode,7,4,True,'success',False,False,False),mode)
   for args in [(7,2,False,None,True,False,False),(1,4,False,None,True,False,False),(7,4,False,None,False,False,False),(7,4,False,None,True,True,False),(7,4,False,None,True,False,True),(7,4,True,None,False,False,False)]:
    with self.assertRaises(ValueError):m.gpu_stock_intent(tokens,mode,*args)
   for changed in [tokens[:-1],tokens+[tokens[-1]],tokens+[b'ufsrw=1'],[x for x in tokens if x!=b'polarisquiesce=1']]:
    with self.assertRaises(ValueError):m.gpu_stock_intent(changed,mode,7,4,False,None,True,False,False)
   with self.assertRaises(ValueError):m.gpu_stock_intent(tokens,0,7,4,False,None,True,False,False)
  self.assertEqual(m.gpu_stock_intent(base,0,1,1,False,None,False,False,False),0)
  for mode in [True,-1,4,'1']:
   with self.assertRaises(ValueError):m.gpu_stock_intent(base,mode,7,4,False,None,True,False,False)
 def test_transactions_policy_ownership_and_every_io_failure(self):
  code=r'''
#include "polaris-a630-probe.h"
#include "polaris-a630-power.h"
#include "polaris-a630-performance.h"
#include <assert.h>
#include <string.h>
struct model {uint32_t ack,perf,bw,ret,irq;unsigned op,fail,writes,sets,releases;bool held,stuck,bad,readback;};
static struct model m;
static bool owned(void*c){assert(c==&m);return m.held;}
static bool op(void){return ++m.op!=m.fail;}
static bool rd(void*c,unsigned bank,uint32_t off,uint32_t*v){assert(c==&m&&bank==2);if(!op())return false;
 switch(off){case A630_POST_ACK:*v=m.ack;break;case A630_POST_PERF:*v=m.perf;break;case A630_POST_BW:*v=m.bw;break;
 case A630_POST_RETURN:*v=m.ret;break;case A630_CH_INTR_INFO:*v=m.irq;break;default:assert(0);}return true;}
static bool wr(void*c,unsigned bank,uint32_t off,uint32_t v){assert(c==&m&&bank==2);m.writes++;if(!op())return false;
 switch(off){case A630_POST_ACK:assert(!v);m.ack=v;break;
 case A630_POST_PERF:assert(v==0x30000001||v==0x30000004);if(!m.readback)m.perf=v;break;
 case A630_POST_BW:assert(v==4||v==8);m.bw=v;break;
 case A630_CH_INTR_SET:assert(v==(1u<<23)||v==(1u<<31));
  if(v==(1u<<23)){m.sets++;if(!m.stuck)m.irq|=1u<<31;m.ret=m.bad?7:0;}else m.releases++;break;
 case A630_CH_INTR_CLEAR:assert(v==(1u<<31));m.irq&=~v;break;default:assert(0);}return true;}
static bool sync_io(void*c){assert(c==&m);return op();}
static void wait_io(void*c,uint32_t us){assert(c==&m&&us==10);}
static struct a630_channel_io io={owned,rd,wr,sync_io,wait_io,&m};
static void reset(struct a630_perf_state*s,unsigned mode){memset(&m,0,sizeof(m));m.held=true;m.perf=0x30000001;m.bw=4;
 assert(a630_perf_init(s,mode,true,&io)&&s->armed&&!m.writes);m.op=0;}
int main(void){struct a630_perf_state s;uint32_t perf,bus;
 for(unsigned mode=1;mode<=3;mode++){
  reset(&s,mode);assert(a630_perf_desired(&s,1,1,&perf,&bus));assert(perf==(mode==1?1:4)&&bus==(mode==2?4:8));
  assert(a630_perf_change(&s,&io,perf,bus,true));assert(s.transitions==1&&m.sets==1&&m.releases==1&&!m.irq);
  unsigned writes=m.writes;assert(a630_perf_desired(&s,250000001,1,&perf,&bus));assert(perf==s.target_perf);
  assert(a630_perf_desired(&s,250000002,1,&perf,&bus)&&perf==1&&bus==4);
  assert(a630_perf_change(&s,&io,perf,bus,true)&&m.writes>writes);
  assert(a630_perf_stop(&s,&io,true)&&s.stopped&&m.perf==0x30000001&&m.bw==4);
  assert(!a630_perf_desired(&s,250000003,250000003,&perf,&bus));
 }
 reset(&s,3);assert(a630_perf_desired(&s,100,100,&perf,&bus));assert(a630_perf_change(&s,&io,perf,bus,true));
 assert(a630_perf_desired(&s,30000000100ull,30000000100ull,&perf,&bus)&&perf==1&&bus==4);
 assert(s.cool_until==40000000100ull);assert(a630_perf_change(&s,&io,perf,bus,true));
 assert(a630_perf_desired(&s,40000000099ull,40000000099ull,&perf,&bus)&&perf==1);
 assert(a630_perf_desired(&s,40000000100ull,40000000100ull,&perf,&bus)&&perf==4);
 assert(a630_perf_change(&s,&io,perf,bus,true));assert(a630_perf_stop(&s,&io,true));
 reset(&s,3);assert(a630_perf_change(&s,&io,4,8,true));unsigned operations=m.op;
 for(unsigned fail=1;fail<=operations;fail++){
  reset(&s,3);m.fail=fail;assert(!a630_perf_change(&s,&io,4,8,true)&&s.fault);unsigned writes=m.writes;
  m.fail=0;assert(!a630_perf_stop(&s,&io,true));assert(!a630_perf_change(&s,&io,1,4,true)&&m.writes==writes);
 }
 for(unsigned fail=1;fail<=5;fail++){
  reset(&s,3);m.fail=fail;assert(!a630_perf_init(&s,3,true,&io)&&s.fault&&!m.writes);
 }
 reset(&s,3);m.held=false;assert(!a630_perf_change(&s,&io,4,8,true)&&!m.writes);
 reset(&s,3);assert(!a630_perf_change(&s,&io,4,8,false)&&!m.writes);
 reset(&s,3);m.perf=0x30000002;assert(!a630_perf_change(&s,&io,4,8,true)&&!m.writes);
 reset(&s,3);m.irq=1u<<31;assert(!a630_perf_change(&s,&io,4,8,true)&&!m.writes);
 reset(&s,3);m.irq=1u<<16;assert(!a630_perf_change(&s,&io,4,8,true)&&!m.writes);
 reset(&s,3);m.stuck=true;assert(!a630_perf_change(&s,&io,4,8,true)&&s.fault==A630_CH_TIMEOUT&&!m.releases);
 reset(&s,3);m.bad=true;assert(!a630_perf_change(&s,&io,4,8,true)&&s.fault==A630_CH_FW_ERROR&&!m.releases);
 reset(&s,3);m.readback=true;assert(!a630_perf_change(&s,&io,4,8,true)&&s.fault==A630_CH_PROTOCOL);
 reset(&s,3);assert(a630_perf_change(&s,&io,4,8,true));m.readback=true;assert(!a630_perf_stop(&s,&io,true)&&s.fault);
 reset(&s,3);assert(!a630_perf_desired(&s,1,2,&perf,&bus)&&s.fault&&!m.writes);
 reset(&s,3);assert(a630_perf_desired(&s,10,1,&perf,&bus));assert(!a630_perf_desired(&s,9,1,&perf,&bus));
 reset(&s,3);assert(!a630_perf_desired(&s,UINT64_MAX,0,&perf,&bus));
 for(unsigned mode=0;mode<6;mode++)for(unsigned cpu=0;cpu<8;cpu++){
  bool want=mode>=1&&mode<=3&&cpu>=4;
  assert(a630_perf_intent(mode,9,1,true,0,0,1,0x517f802d,cpu<<8,19200000,true)==want);
 }
 assert(!a630_perf_intent(1,9,1,true,0,0,1,0x410fd050,7,19200000,true));
 assert(!a630_perf_intent(1,9,1,true,0,0,1,0x517f802d,0x700,19200000,false));
 assert(!a630_perf_intent(1,9,0,true,0,0,1,0x517f802d,0x700,19200000,true));
 assert(!a630_perf_intent(1,9,1,true,1,0,1,0x517f802d,0x700,19200000,true));
 assert(!a630_perf_intent(1,9,1,false,0,0,1,0x517f802d,0x700,19200000,true));
 assert(!a630_perf_intent(1,9,1,true,0,1,1,0x517f802d,0x700,19200000,true));
 assert(!a630_perf_intent(1,9,1,true,0,0,0,0x517f802d,0x700,19200000,true));
 assert(!a630_perf_intent(1,8,1,true,0,0,1,0x517f802d,0x700,19200000,true));
 reset(&s,3);
 for(uint64_t n=1;n<20000;n++){
  uint64_t now=n*10000000,activity=n%100<70?now:0;
  assert(a630_perf_desired(&s,now,activity,&perf,&bus));
  if(perf!=s.perf||bus!=s.bus)assert(a630_perf_change(&s,&io,perf,bus,true));
 }
 assert(a630_perf_stop(&s,&io,true));return 0;
}'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'test.c').write_text(code)
   subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
 def test_native_hooks_keep_same_lock_worker_and_restore_before_peer_off(self):
  s=(ROOT/'tools/PolarisGPU.cpp').read_text()
  poll=s[s.index('extern "C" void polaris_gpu_performance_poll('):s.index('static bool polaris_gpu_performance_report(')]
  self.assertEqual(poll.count('IOLockLock(gpuLock);'),2)
  self.assertEqual(poll.count('IOLockUnlock(gpuLock);'),2)
  self.assertIn('callerKind==2 &&',s)
  native=(ROOT/'tools/polaris-a630-runtime.h').read_text()
  self.assertIn('(struct a630_channel_io){a630_core_owned,a630_read_register,',native)
  self.assertNotIn('(struct a630_channel_io){a630_runtime_held',native)
  self.assertIn('a630_perf_change(s,&io,perf,bus,polaris_gpu_quiescent())',native)
  self.assertIn('if(!ok)polaris_gpu_quarantine();return ok;',native)
  patch=(ROOT/'xnu/profiles/polaris/0888-polaris-bounded-original-GPU-and-bandwidth-request.patch').read_text()
  self.assertLess(patch.index('if(!polaris_gpu_performance_shutdown())return EIO;'),patch.index('if(polaris_perf_shutdown()!=0)return EIO;'))
  self.assertIn('REFUSED platform/mode before GPU MMIO',patch)
if __name__=='__main__':unittest.main()
