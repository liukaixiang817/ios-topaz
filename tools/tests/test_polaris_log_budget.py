"""The exact shipped policy must stay bounded under an AKS-style call flood."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LogBudgetTests(unittest.TestCase):
    def test_shipped_header_matches_actual_policy(self):
        patch = (ROOT / 'xnu/profiles/polaris/0817-polaris-interactive-console.patch').read_text()
        text = patch.split('+++ b/iokit/Kernel/arm/polaris_log_budget.h\n', 1)[1]
        header = '\n'.join(line[1:] for line in text.splitlines() if line.startswith('+')) + '\n'
        self.assertEqual(header, (ROOT / 'tools/polaris-log-budget.h').read_text())

    def test_call_flood_errors_selector_isolation_and_concurrency(self):
        source = r'''
#include <assert.h>
#include <pthread.h>
#include "polaris-log-budget.h"
static struct polaris_log_budget concurrent;
static uint32_t logged;
static void *worker(void *arg) {
    (void)arg;
    for(unsigned i=0;i<10000;i++) {
        if(polaris_log_allow(&concurrent,17,false))
            __atomic_fetch_add(&logged,1,__ATOMIC_RELAXED);
    }
    return 0;
}
int main(void) {
    struct polaris_log_budget b={0};unsigned success=0,error=0;
    for(unsigned i=0;i<100000;i++) success+=polaris_log_allow(&b,17,false);
    assert(success==2 && b.success[17]==100000 && !b.error[17]);
    /* Errors retain their own first observations after the success budget. */
    for(unsigned i=0;i<100000;i++) error+=polaris_log_allow(&b,17,true);
    assert(error>=4 && error<=20 && b.error[17]==100000);
    assert(polaris_log_allow(&b,35,false) && polaris_log_allow(&b,35,true));
    assert(polaris_log_allow(&b,UINT32_MAX,false));
    assert(polaris_log_allow(&b,256,false));
    assert(!polaris_log_allow(&b,257,false));
    assert(b.success[256]==3 && b.success[255]==0);
    /* Terminal state must stay terminal; no wrap back to verbose logging. */
    b.success[0]=UINT32_MAX-1;b.error[0]=UINT32_MAX-1;
    for(unsigned i=0;i<10;i++) {
        assert(!polaris_log_allow(&b,0,false) && !polaris_log_allow(&b,0,true));
    }
    assert(b.success[0]==UINT32_MAX && b.error[0]==UINT32_MAX);
    pthread_t threads[8];
    for(unsigned i=0;i<8;i++) assert(!pthread_create(&threads[i],0,worker,0));
    for(unsigned i=0;i<8;i++) assert(!pthread_join(threads[i],0));
    assert(logged==2 && concurrent.success[17]==80000);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-pthread', '-I', str(ROOT / 'tools'), str(p / 'test.c'),
                            '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)
