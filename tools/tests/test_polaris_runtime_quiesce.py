"""Native fault injection for policy only; not actual XNU/UFS shutdown proof."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class RuntimeQuiesce(unittest.TestCase):
    def test_partial_io_sticky_errors_and_shutdown_order(self):
        root = Path(__file__).resolve().parents[2]
        code = r'''
#include "runtime-quiesce.h"
#include <assert.h>
#include <stdio.h>
static const uint64_t cookie=UINT64_C(0xb3d061c0ffee);
static unsigned checks;
#define CHECK(x) do{checks++;assert(x);}while(0)
static bool ready(const struct polaris_q *q){
 struct polaris_shutdown_status s=polaris_q_status(q);
 return polaris_q_reset_ready(&s,cookie,1,2);
}
static struct polaris_q initialized(void){
 struct polaris_q q={0};CHECK(polaris_q_init(&q,cookie,true));return q;
}
static void finish_data(struct polaris_q *q,bool write,unsigned bytes){
 CHECK(polaris_q_begin(q,bytes,write));CHECK(!ready(q));
 CHECK(polaris_q_complete(q,true,true,bytes));CHECK(!ready(q));
}
int main(void){
 struct polaris_q q={0};CHECK(!polaris_q_init(&q,0,true));CHECK(!polaris_q_init(&q,cookie,false));
 CHECK(!ready(&q));q=initialized();CHECK(!polaris_q_init(&q,cookie,true));
 CHECK(!polaris_q_flush_begin(&q));CHECK(!polaris_q_seal(&q,0,0));
 finish_data(&q,true,4096);finish_data(&q,false,8192);CHECK(q.write_epoch==1);
 CHECK(!polaris_q_request(&q,cookie+1,1,2));CHECK(!polaris_q_request(&q,cookie,0,2));
 CHECK(!polaris_q_request(&q,cookie,1,0));CHECK(!polaris_q_request(&q,cookie,1,3));
 CHECK(polaris_q_request(&q,cookie,1,2));CHECK(polaris_q_request(&q,cookie,1,2));
 CHECK(!polaris_q_request(&q,cookie,2,2));CHECK(!polaris_q_request(&q,cookie,1,1));
 CHECK(!ready(&q));
 /* VFS shutdown can still perform its final journal/cache writes. */
 finish_data(&q,true,4096);CHECK(q.write_epoch==2);
 CHECK(!polaris_q_seal(&q,1,0));CHECK(!polaris_q_seal(&q,0,1));
 CHECK(polaris_q_begin(&q,4096,false));CHECK(!polaris_q_seal(&q,0,0));
 CHECK(polaris_q_complete(&q,true,true,4096));CHECK(polaris_q_seal(&q,0,0));CHECK(!ready(&q));
 CHECK(!polaris_q_begin(&q,4096,true));CHECK(!polaris_q_begin(&q,4096,false));
 CHECK(polaris_q_flush_begin(&q));CHECK(!ready(&q));CHECK(!polaris_q_flush_begin(&q));
 CHECK(!polaris_q_complete(&q,true,true,0));CHECK(!ready(&q));
 CHECK(polaris_q_flush_complete(&q,true,true));CHECK(ready(&q));
 CHECK(!polaris_q_init(&q,cookie,true));CHECK(!polaris_q_flush_begin(&q));
 CHECK(!polaris_q_begin(&q,4096,true));CHECK(!polaris_q_begin(&q,4096,false));
 struct polaris_shutdown_status status=polaris_q_status(&q),bad;
 CHECK(!polaris_q_reset_ready(&status,cookie,1,1));CHECK(!polaris_q_reset_ready(&status,cookie+1,1,2));
 CHECK(!polaris_q_reset_ready(&status,cookie,2,2));
 bad=status;bad.capabilities^=1;CHECK(!polaris_q_reset_ready(&bad,cookie,1,2));
 bad=status;bad.write_epoch++;CHECK(!polaris_q_reset_ready(&bad,cookie,1,2));
 bad=status;bad.error=1;CHECK(!polaris_q_reset_ready(&bad,cookie,1,2));
 bad=status;bad.phase=POLARIS_Q_REQUESTED;CHECK(!polaris_q_reset_ready(&bad,cookie,1,2));
 /* A known short write, failed completion or unknown DMA never permits reset,
  * even after repeated requests or an attempted successful flush/re-init. */
 for(unsigned fault=0;fault<4;fault++){
  q=initialized();CHECK(polaris_q_request(&q,cookie,1,2));CHECK(polaris_q_begin(&q,8192,true));
  CHECK(!polaris_q_complete(&q,fault!=0,fault<2,fault==1?4096:fault==3?12288:8192));
  CHECK(q.phase==POLARIS_Q_FAILED&&q.error==POLARIS_Q_IO_ERROR&&!ready(&q));
  if(!fault)CHECK(q.inflight);else CHECK(!q.inflight);
  CHECK(!polaris_q_request(&q,cookie,1,2));CHECK(!polaris_q_seal(&q,0,0));
  CHECK(!polaris_q_flush_begin(&q));CHECK(!polaris_q_flush_complete(&q,true,true));
  CHECK(!polaris_q_init(&q,cookie,true));CHECK(!ready(&q));
 }
 for(unsigned unknown=0;unknown<2;unknown++){
  q=initialized();finish_data(&q,true,4096);CHECK(polaris_q_request(&q,cookie,1,2));
  CHECK(polaris_q_seal(&q,0,0));CHECK(polaris_q_flush_begin(&q));
  CHECK(!polaris_q_flush_complete(&q,!unknown,false));CHECK(!ready(&q));
  CHECK(!polaris_q_flush_complete(&q,true,true));CHECK(!polaris_q_init(&q,cookie,true));
  if(unknown)CHECK(q.inflight);
 }
 q=initialized();q.write_epoch=UINT64_MAX;CHECK(!polaris_q_begin(&q,4096,true));
 CHECK(q.phase==POLARIS_Q_FAILED&&q.error==POLARIS_Q_COUNTER_ERROR&&!ready(&q));
 q=initialized();CHECK(!polaris_q_begin(&q,0,true));CHECK(!polaris_q_begin(&q,4095,true));
 CHECK(!polaris_q_begin(&q,(1u<<20)+4096,true));
 CHECK(polaris_q_begin(&q,1u<<20,true));CHECK(!polaris_q_begin(&q,4096,true));
 CHECK(polaris_q_complete(&q,true,true,1u<<20));
 q=initialized();CHECK(polaris_q_request(&q,cookie,UINT32_MAX,2));
 CHECK(!polaris_q_request(&q,cookie,0,2));CHECK(!polaris_q_request(&q,cookie,1,2));
 /* Clean idle still needs a real final cache-sync completion. */
 q=initialized();CHECK(polaris_q_request(&q,cookie,1,2));CHECK(polaris_q_seal(&q,0,0));
 CHECK(!ready(&q));CHECK(polaris_q_flush_begin(&q));CHECK(!ready(&q));
 CHECK(polaris_q_flush_complete(&q,true,true));CHECK(ready(&q));
 printf("QUIESCE_POLICY_PASS %u checks; no kernel/UFS execution claimed\n",checks);
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='polaris-quiesce-') as folder:
            path = Path(folder)
            (path / 'check.c').write_text(code)
            subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I'+str(root / 'shim/polaris'),
                            str(path / 'check.c'), '-o', str(path / 'check')],
                           check=True, capture_output=True)
            result = subprocess.run([str(path / 'check')], check=True, capture_output=True)
            self.assertIn(b'QUIESCE_POLICY_PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
