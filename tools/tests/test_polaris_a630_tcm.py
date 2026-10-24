"""A630 transfer model: no physical GMU access or firmware execution."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class A630TCMTests(unittest.TestCase):
    def test_flat_transfer_admission_and_failures(self):
        source = r'''
#include "polaris-a630-tcm.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
struct model {
    uint32_t words[0x8000 / 4], reset, writes, reads, guards, barriers;
    uint32_t drop_at, read_fail, write_fail, lost_after, reset_after;
    bool lease, sync_ok;
};
static bool admitted(void *p) {
    struct model *m=p; m->guards++;
    return m->lease && (!m->lost_after || m->writes < m->lost_after);
}
static bool rd(void *p, uint32_t off, uint32_t *v) {
    struct model *m=p; m->reads++;
    if(off==0x14000) {
        *v=m->reset_after && m->writes>=m->reset_after ? 0 : m->reset;
        return off!=m->read_fail;
    }
    assert(off>=0x3000 && off<0xb000 && !(off&3));
    if(off==m->read_fail) return false;
    *v=m->words[(off-0x3000)/4]; return true;
}
static bool wr(void *p, uint32_t off, uint32_t v) {
    struct model *m=p; m->writes++;
    /* Strict model allowlist: no reset, firmware-start, HFI or other CSR. */
    assert(off>=0x3000 && off<0xb000 && !(off&3));
    if(off==m->write_fail) return false;
    if(off!=m->drop_at) m->words[(off-0x3000)/4]=v;
    return true;
}
static bool sync_io(void *p) {
    struct model *m=p; m->barriers++; return m->sync_ok;
}
static void init(struct model *m) {
    memset(m,0,sizeof(*m));m->lease=true;m->sync_ok=true;m->reset=1;
    for(unsigned i=0;i<0x8000/4;i++)m->words[i]=0xaaaaaaaa;
}
int main(void) {
    uint8_t *allocation=malloc(0x8000+1);assert(allocation);
    uint8_t *fw=allocation+1; /* no host alignment assumption */
    for(unsigned n=0;n<0x8000;n++)fw[n]=(uint8_t)(n*17+3);
    const uint8_t vectors[8]={0x80,0x3f,4,0,9,0,0,0};
    memcpy(fw,vectors,8);
    struct a630_image image={fw,0x8000};
    struct a630_tcm_io io={admitted,rd,wr,sync_io};
    struct a630_tcm_snapshot s;struct model m;
    /* Independent original GPU-word -> physical address fixtures. */
    uint32_t off=0xdeadbeef;
    assert(a630_gmu_word_offset(0x1b400,&off) && 0x506a000+off==0x506d000);
    assert(a630_gmu_word_offset(0x1c400,&off) && 0x506a000+off==0x5071000);
    assert(a630_gmu_word_offset(0x1f800,&off) && off==0x14000);
    assert(a630_gmu_word_offset(0x1f81c,&off) && off==0x14070);
    assert(a630_gmu_word_offset(0x1a800,&off) && off==0);
    assert(a630_gmu_word_offset(0x267ff,&off) && off==0x2fffc);
    off=0xdeadbeef;
    assert(!a630_gmu_word_offset(0x1a7ff,&off));
    assert(!a630_gmu_word_offset(0x26800,&off));
    assert(!a630_gmu_word_offset(0xffffffff,&off) && off==0xdeadbeef);
    assert(!a630_gmu_word_offset(0x1b400,NULL));
    init(&m);
    assert(a630_tcm_load(false,true,&image,&io,&m,&s)==A630_TCM_DISABLED);
    assert(a630_tcm_load(true,false,&image,&io,&m,&s)==A630_TCM_DISABLED);
    assert(!m.guards && !m.reads && !m.writes);
    assert(a630_tcm_load(true,true,NULL,&io,&m,&s)==A630_TCM_ARGUMENT);
    assert(a630_tcm_load(true,true,&image,NULL,&m,&s)==A630_TCM_ARGUMENT);
    assert(a630_tcm_load(true,true,&image,&io,&m,NULL)==A630_TCM_ARGUMENT);
    for(unsigned n=0;n<4;n++) {
        struct a630_tcm_io bad=io;
        if(n==0)bad.admitted=NULL;if(n==1)bad.read=NULL;
        if(n==2)bad.write=NULL;if(n==3)bad.sync=NULL;
        assert(a630_tcm_load(true,true,&image,&bad,&m,&s)==A630_TCM_ARGUMENT);
    }
    image.bytes=0x7ffc;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_ARGUMENT);
    image.bytes=0x8004;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_ARGUMENT);
    image.bytes=0x8000;fw[4]=8;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_ARGUMENT);
    memcpy(fw,vectors,8);assert(!m.guards && !m.reads && !m.writes);
    m.lease=false;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_LEASE_LOST);
    assert(!m.reads && !m.writes);
    init(&m);m.reset=0;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_NOT_RESET);
    assert(!m.writes && s.offset==0x14000 && s.expected==1 && !s.actual);
    init(&m);
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_VERIFIED);
    assert(m.writes==8192 && s.writes==8192 && m.barriers==1 && s.barriers==1);
    assert(s.phase==A630_TCM_READBACK && m.reset==1);
    for(unsigned n=0;n<8192;n++)assert(m.words[n]==a630_image_word(fw+4*n));
    /* First, middle (DTCM-start), and last transferred words. */
    const uint32_t edges[3]={0x3000,0x7000,0xaffc};
    for(unsigned n=0;n<3;n++) {
        init(&m);m.write_fail=edges[n];
        assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_IO);
        assert(s.phase==A630_TCM_COPY && s.offset==edges[n]);
        assert(m.writes==(edges[n]-0x3000)/4+1 && m.reset==1);
        init(&m);m.read_fail=edges[n];
        assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_IO);
        assert(s.phase==A630_TCM_READBACK && s.offset==edges[n] && m.reset==1);
        init(&m);m.drop_at=edges[n];
        assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_MISMATCH);
        assert(s.offset==edges[n] && s.actual==0xaaaaaaaa);
        assert(s.expected==a630_image_word(fw+edges[n]-0x3000) && m.reset==1);
    }
    init(&m);m.read_fail=0x14000;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_IO);
    assert(m.writes==0 && s.offset==0x14000 && s.actual==0);
    init(&m);m.lost_after=7;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_LEASE_LOST);
    assert(m.writes==7 && m.reset==1);
    init(&m);m.reset_after=7;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_NOT_RESET);
    assert(m.writes==7 && s.offset==0x14000);
    init(&m);m.sync_ok=false;
    assert(a630_tcm_load(true,true,&image,&io,&m,&s)==A630_TCM_IO);
    assert(m.writes==8192 && m.barriers==1 && m.reset==1);
    free(allocation);return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(path / 'test.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
