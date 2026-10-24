"""Exercise the shipped endpoint command sequence, including every exit path."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Dwc3CommandTests(unittest.TestCase):
    def test_command_order_suspend_restore_and_failure(self):
        source = r'''
#include "polaris-dwc3-command.h"
#include <assert.h>
#include <string.h>
struct mock {
    uint32_t phy, initial, values[5], offsets[5], writes, reads, waits;
    uint32_t ep, cmd, mode, polls, response;
};
static uint32_t rd(void *p,uint32_t off) {
    struct mock *m=p;m->reads++;
    if(off==PDWC3_PHYCFG)return m->phy;
    assert(off==0xc80cu+m->ep*16);
    /* Either low-power control stalls HS commands on DWC3 3.30a. */
    m->polls++;
    if((m->phy&PDWC3_LOW_POWER)||m->mode==2)return m->cmd|PDWC3_CMDACT;
    if(m->mode==3 && m->polls<4)return m->cmd|PDWC3_CMDACT;
    return m->mode==1 ? 0x2000u|m->cmd : m->response;
}
static void wr(void *p,uint32_t off,uint32_t value) {
    struct mock *m=p;
    if(off==PDWC3_PHYCFG){
        assert(((value^m->phy)&~PDWC3_LOW_POWER)==0);
        if(value&PDWC3_LOW_POWER)assert(m->writes==4);
        else assert(!m->writes);
        m->phy=value;return;
    }
    assert(m->writes<4);
    m->offsets[m->writes]=off;m->values[m->writes++]=value;
    if(m->writes==4){
        assert(!(m->phy&PDWC3_LOW_POWER));
        /* A current unrelated bit must survive the later restore. */
        m->phy|=1u<<13;
    }
}
static void wait_us(void *p,uint32_t us){assert(us==1);((struct mock*)p)->waits++;}
int main(void){
    struct pdwc3_result s;
    for(unsigned bits=0;bits<4;bits++)for(unsigned mode=0;mode<4;mode++){
        struct mock m={.phy=0x8001u|((bits&1)?PDWC3_SUSPHY:0)|((bits&2)?PDWC3_ENBLSLPM:0),.ep=1,.cmd=0x20009,
            .mode=mode,.response=0x70001};m.initial=m.phy;
        struct pdwc3_io io={&m,rd,wr,wait_us};
        unsigned e=polaris_dwc3_command(&io,1,m.cmd,11,22,33,&s);
        assert(e==(mode==1?PDWC3_STATUS:mode==2?PDWC3_TIMEOUT:PDWC3_OK));
        assert(m.writes==4 && m.offsets[0]==0xc818 && m.offsets[1]==0xc814 &&
            m.offsets[2]==0xc810 && m.offsets[3]==0xc81c);
        assert(m.values[0]==11&&m.values[1]==22&&m.values[2]==33);
        assert(m.values[3]==(m.cmd|PDWC3_CMDACT));
        assert(m.phy==(m.initial|(1u<<13)));
        assert(s.phy_before==m.initial&&s.phy_after==m.phy&&s.ep==1&&s.command==m.cmd);
        assert(s.polls==(mode==2?1000:mode==3?4:1));
        assert(m.waits==(mode==2?1000:mode==3?3:0));
    }
    struct mock m={0};struct pdwc3_io io={&m,rd,wr,wait_us};
    assert(polaris_dwc3_command(&io,32,1,0,0,0,&s)==PDWC3_ARGUMENT);
    assert(polaris_dwc3_command(&io,0,0,0,0,0,&s)==PDWC3_ARGUMENT);
    assert(polaris_dwc3_command(&io,0,PDWC3_CMDACT|1,0,0,0,&s)==PDWC3_ARGUMENT);
    assert(polaris_dwc3_command(0,0,1,0,0,0,&s)==PDWC3_ARGUMENT);
    assert(polaris_dwc3_command(&io,0,1,0,0,0,0)==PDWC3_ARGUMENT);
    assert(!m.reads&&!m.writes&&!m.waits);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
