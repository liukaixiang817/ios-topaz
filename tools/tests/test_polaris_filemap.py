"""Exercise actual C block translation and lowest-level read allowlist."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class FileMapTests(unittest.TestCase):
    def test_kernel_ships_exact_tested_header(self):
        patch = (ROOT / 'xnu/profiles/polaris/0803-polaris-readonly-file-root.patch').read_text()
        section = patch.split('+++ b/bsd/dev/polaris_filemap.h\n', 1)[1].split('--- a/', 1)[0]
        header = '\n'.join(line[1:] for line in section.splitlines() if line.startswith('+')) + '\n'
        self.assertEqual(header, (ROOT / 'tools/polaris-filemap.h').read_text())

    def test_fragmented_map_and_cdb_boundaries(self):
        source = r'''
#include <assert.h>
#include <string.h>
#include "polaris-filemap.h"
static void cdb(uint8_t out[10], uint32_t lba, uint32_t count) {
    memset(out, 0, 10); out[0]=0x28;
    out[2]=lba>>24; out[3]=lba>>16; out[4]=lba>>8; out[5]=lba;
    out[7]=count>>8; out[8]=count;
}
static void le64(uint8_t *p, uint64_t n) {
    for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(8*i));
}
int main(void) {
    static uint8_t head[1<<20];
    head[510]=0x55; head[511]=0xaa; memcpy(head+4096,"EFI PART",8);
    le64(head+4096+72,2); head[4096+80]=1; head[4096+84]=128;
    le64(head+8192+32,900); le64(head+8192+40,5899);
    for(unsigned i=0;i<8;i++)head[8192+56+2*i]="userdata"[i];
    assert(polaris_userdata_bounds(head,900,5000));
    assert(!polaris_userdata_bounds(head,901,4999));
    assert(!polaris_userdata_bounds(head,900,4999));
    assert(!polaris_userdata_bounds(head,UINT64_MAX,2));
    head[8192+56+16]='x';assert(!polaris_userdata_bounds(head,900,5000));head[8192+56+16]=0;
    memcpy(head+8192+128,head+8192,128);head[4096+80]=2;
    assert(!polaris_userdata_bounds(head,900,5000));head[4096+80]=1;
    /* Reject impossible bounds; valid larger tables/strides are permitted. */
    const unsigned bad_fields[]={73,74,75,76,77,78,79,81,82,83,84,86,87};
    for(unsigned i=0;i<sizeof(bad_fields)/sizeof(bad_fields[0]);i++) {
        unsigned off=bad_fields[i];
        uint8_t saved=head[4096+off];head[4096+off]=0xff;
        assert(!polaris_userdata_bounds(head,900,5000));head[4096+off]=saved;
    }
    assert(polaris_userdata_bounds(head,900,5000));
    struct polaris_extent map[]={{0,1000,300},{300,2000,1},{301,4000,511}};
    assert(polaris_map_valid(map,3,812,900,5000));
    assert(!polaris_map_valid(map,3,811,900,5000));
    assert(!polaris_map_valid(map,3,813,900,5000));
    assert(!polaris_map_valid(map,0,812,900,5000));
    assert(!polaris_map_valid(map,3,812,0,5000));
    assert(!polaris_map_valid(map,3,812,UINT64_MAX,5000));
    assert(!polaris_map_valid(map,3,812,900,UINT64_MAX));
    assert(!polaris_map_valid(map,3,UINT64_MAX,900,5000));
    for (unsigned i=0;i<3;i++) {
        struct polaris_extent copy[3]; memcpy(copy,map,sizeof(copy));
        copy[i].logical++; assert(!polaris_map_valid(copy,3,812,900,5000));
        memcpy(copy,map,sizeof(copy)); copy[i].physical=899;
        assert(!polaris_map_valid(copy,3,812,900,5000));
        copy[i].physical=5899; assert(!polaris_map_valid(copy,3,812,900,5000) || i==1);
        memcpy(copy,map,sizeof(copy)); copy[i].blocks=UINT64_MAX;
        assert(!polaris_map_valid(copy,3,812,900,5000));
        memcpy(copy,map,sizeof(copy)); copy[i].blocks=0;
        assert(!polaris_map_valid(copy,3,812,900,5000));
    }
    struct polaris_extent overlap[]={{0,1000,300},{300,1299,512}};
    assert(!polaris_map_valid(overlap,2,812,900,5000));
    uint64_t phys; uint32_t blocks;
    for (unsigned l=0;l<812;l++) for (unsigned want=1;want<=256;want++) {
        assert(polaris_map_read(map,3,l,want,&phys,&blocks));
        unsigned i=l<300?0:l==300?1:2;
        assert(phys==map[i].physical+l-map[i].logical);
        uint64_t left=map[i].blocks-(l-map[i].logical);
        assert(blocks==(left<want?left:want));
        uint8_t rd[10]; cdb(rd,(uint32_t)phys,blocks);
        assert(polaris_map_cdb_allowed(map,3,rd,10,blocks*4096,false,0));
        assert(!polaris_map_cdb_allowed(map,3,rd,10,blocks*4096,true,0));
        assert(!polaris_map_cdb_allowed(map,3,rd,10,blocks*4096,false,1));
        assert(!polaris_map_cdb_allowed(map,3,rd,10,blocks*4096-1,false,0));
    }
    assert(!polaris_map_read(map,3,812,1,&phys,&blocks));
    assert(!polaris_map_read(map,3,UINT64_MAX,1,&phys,&blocks));
    assert(!polaris_map_read(map,3,0,0,&phys,&blocks));
    assert(!polaris_map_read(map,3,0,257,&phys,&blocks));
    for (unsigned l=0;l<6000;l++) for (unsigned n=0;n<=257;n++) {
        uint8_t rd[10]; cdb(rd,l,n);
        bool expected=n && n<=256 && ((l>=1000 && l<1300 && n<=1300-l) ||
            (l==2000 && n==1) || (l>=4000 && l<4511 && n<=4511-l));
        assert(polaris_map_cdb_allowed(map,3,rd,10,n*4096,false,0)==expected);
    }
    uint8_t rd[10]; cdb(rd,1000,1);
    for (unsigned op=0;op<256;op++) {
        rd[0]=op; assert(polaris_map_cdb_allowed(map,3,rd,10,4096,false,0)==(op==0x28));
    }
    cdb(rd,1000,1);
    for (unsigned i=0;i<10;i++) if(i==1||i==6||i==9) {
        rd[i]=1; assert(!polaris_map_cdb_allowed(map,3,rd,10,4096,false,0)); rd[i]=0;
    }
    for (unsigned n=0;n<32;n++)
        assert(polaris_map_cdb_allowed(map,3,rd,n,4096,false,0)==(n==10));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'test.c').write_text(source)
            subprocess.run(['cc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
