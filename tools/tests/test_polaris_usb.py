"""Actual USB admission helper: no MMIO before opt-in, no gated-core reads."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('usb_adt', ROOT / 'tools/mkadt-polaris.py')
adt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adt)


class USBTests(unittest.TestCase):
    def test_shipped_admission_header(self):
        text = (ROOT / 'xnu/profiles/polaris/0819-polaris-usb-debug-admission.patch').read_text()
        part = text.split('+++ b/bsd/dev/polaris_usb.h\n')[1]
        shipped = ''.join(line[1:] + '\n' for line in part.splitlines() if line.startswith('+'))
        self.assertEqual(shipped, (ROOT / 'tools/polaris-usb.h').read_text())

    def test_board_opt_in_is_separate_and_not_for_qemu(self):
        with patch.object(adt.mkadt, 'd22ap_product', return_value=None):
            base = adt.build(seed=b'x' * 64, display=True, touch=True,
                             touch_wake=True, touch_irq_input=True)
            root = adt.build(seed=b'x' * 64, display=True, touch=True,
                             touch_wake=True, touch_irq_input=True, usb=True)
            with self.assertRaises(ValueError):
                adt.build(qemu=True, usb=True)
        node = adt.child(root, 'polaris-usb')
        self.assertEqual(adt.props(node)['reg'], adt.mkadt.u64(0xa600000, 0xcd00))
        self.assertEqual(adt.props(node)['gcc-reg'], adt.mkadt.u64(0x100000, 0x90000))
        self.assertEqual(adt.props(node)['scratch-reg'], adt.mkadt.u64(0xa6f8800, 0x100))
        self.assertEqual(adt.props(node)['version'], adt.mkadt.u32(1))
        root.children.remove(node)
        self.assertEqual(adt.adt.serialize(root), adt.adt.serialize(base))

    def test_actual_gate_with_fake_mmio_and_sanitizers(self):
        source = r'''
#include "polaris-usb.h"
#include <assert.h>
#include <string.h>
struct mock {
    unsigned calls, core_reads, fail_at;
    uint32_t power, clocks[7], id, gctl, dctl, dsts;
};
static struct mock normal(void) {
    return (struct mock){.power=0x80000000,.id=0x5533300a,
        .gctl=0x112000,.dsts=1u<<22};
}
static bool rd(void *ctx, unsigned region, uint32_t off, uint32_t *v) {
    struct mock *m=ctx;
    if (++m->calls==m->fail_at) return false;
    if (region==0) {
        if (off==0xf004) { *v=m->power; return true; }
        for (unsigned i=0;i<7;i++) if(off==polaris_usb_clocks[i]) {
            *v=m->clocks[i];return true;
        }
        assert(!"foreign GCC register");
    }
    assert(region==1);m->core_reads++;
    assert(m->power & (1u<<31));
    for(unsigned i=0;i<7;i++) assert(!(m->clocks[i] & (1u<<31)));
    switch(off) {
    case 0xc120: *v=m->id;break;
    case 0xc110: *v=m->gctl;break;
    case 0xc704: *v=m->dctl;break;
    case 0xc70c: *v=m->dsts;break;
    case 0xc140: *v=0x1234;break;
    default: assert(!"unexpected device register");
    }
    return true;
}
int main(void) {
    struct polaris_usb_snapshot s;
    struct mock m=normal();
    assert(polaris_usb_probe(0,true,rd,&m,&s)==POLARIS_USB_DISABLED && !m.calls);
    assert(polaris_usb_probe(3,true,rd,&m,&s)==POLARIS_USB_DISABLED && !m.calls);
    assert(polaris_usb_probe(2,false,rd,&m,&s)==POLARIS_USB_DISABLED && !m.calls);
    assert(polaris_usb_probe(2,true,0,&m,&s)==POLARIS_USB_DISABLED && !m.calls);
    assert(polaris_usb_probe(2,true,rd,&m,0)==POLARIS_USB_DISABLED && !m.calls);
    m.power=0;
    assert(polaris_usb_probe(2,true,rd,&m,&s)==POLARIS_USB_POWER);
    assert(m.calls==1 && !m.core_reads);
    for(unsigned i=0;i<7;i++) {
        m=normal();m.clocks[i]=1u<<31;
        assert(polaris_usb_probe(2,true,rd,&m,&s)==POLARIS_USB_CLOCK);
        assert(!m.core_reads && s.clocks[i]==(1u<<31));
    }
    m=normal();m.id=0xdeadbeef;
    assert(polaris_usb_probe(2,true,rd,&m,&s)==POLARIS_USB_ID);
    assert(m.core_reads==1);
    for(unsigned role=0;role<4;role++) if(role!=2) {
        m=normal();m.gctl=role<<12;
        assert(polaris_usb_probe(2,true,rd,&m,&s)==POLARIS_USB_ROLE);
        assert(m.core_reads==2);
    }
    m=normal();m.dctl=1u<<31;
    assert(polaris_usb_probe(2,true,rd,&m,&s)==POLARIS_USB_BUSY);
    m=normal();m.dsts=0;
    assert(polaris_usb_probe(2,true,rd,&m,&s)==POLARIS_USB_BUSY);
    for(unsigned fail=1;fail<=13;fail++) {
        m=normal();m.fail_at=fail;
        assert(polaris_usb_probe(2,true,rd,&m,&s)==POLARIS_USB_IO);
        assert(m.calls==fail);
    }
    for(unsigned mode=1;mode<=2;mode++) {
        m=normal();
        assert(polaris_usb_probe(mode,true,rd,&m,&s)==POLARIS_USB_READY);
        assert(s.result==POLARIS_USB_READY && s.reads==13 && m.calls==13 && m.core_reads==5);
        assert(s.hwparams0==0x1234 && s.id==m.id && s.gctl==m.gctl);
    }
    /* Regression: SDM845 uses master=f00c and clkref=8c008, not sweet's
     * master=f010 / sleep=f014 / utmi=f018 / clkref=8c010. */
    assert(polaris_usb_clocks[0]==0xf00c && polaris_usb_clocks[1]==0xf010);
    assert(polaris_usb_clocks[2]==0xf014 && polaris_usb_clocks[6]==0x8c008);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
