"""Independent wire fixtures, malformed requests and lossy/reordered transfer."""
import importlib.util
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pdbg', ROOT / 'tools/polaris-usb-debug.py')
debug = importlib.util.module_from_spec(spec)
spec.loader.exec_module(debug)


class DebugTests(unittest.TestCase):
    def test_actual_native_parser_bounds_and_independent_crc(self):
        source = r'''
#include "polaris-debug-wire.h"
#include <assert.h>
#include <string.h>
int main(void) {
    uint8_t request[25]={'P','D','B','G',1,0,1,0,0x78,0x56,0x34,0x12};
    struct pdbg_request r={0},before={.token=99};
    assert(pdbg_parse(request,24,&r) && r.token==0x12345678 && r.op==PDBG_LOG);
    for(unsigned n=0;n<=25;n++) if(n!=24)assert(!pdbg_parse(request,n,&r));
    for(unsigned op=0;op<256;op++) {
        request[6]=(uint8_t)op;r=before;
        bool ok=pdbg_parse(request,24,&r);
        if(op==1 || op==2)assert(ok);else assert(!ok && !memcmp(&r,&before,sizeof(r)));
    }
    request[6]=3;pdbg_put32(request+20,1400);
    assert(pdbg_parse(request,24,&r));
    struct pdbg_snapshot s={.token=r.token,.kind=PDBG_LOG,.bytes=4096};
    assert(pdbg_span(&s,&r));r.offset=UINT32_MAX;assert(!pdbg_span(&s,&r));
    r.offset=4096;r.length=1;assert(!pdbg_span(&s,&r));
    r.offset=4095;assert(pdbg_span(&s,&r));r.length=2;assert(!pdbg_span(&s,&r));
    r.token++;assert(!pdbg_span(&s,&r));r.token--;
    r.offset=0;r.length=1401;assert(!pdbg_span(&s,&r));
    r.length=1;s.bytes=PDBG_LOG_LIMIT+1;assert(!pdbg_span(&s,&r));
    s=(struct pdbg_snapshot){.token=r.token,.kind=PDBG_FRAME,.bytes=PDBG_FRAME_BYTES,
        .width=1080,.height=2160,.stride=4320};
    assert(pdbg_span(&s,&r));s.stride++;assert(!pdbg_span(&s,&r));s.stride--;
    assert(pdbg_crc((const uint8_t *)"123456789",9)==0xcbf43926);
    assert(pdbg_crc(NULL,0)==0);
    uint8_t out[42];memset(out,0xa5,sizeof(out));
    assert(pdbg_reply(out+1,&s,&r,PDBG_OK,(const uint8_t *)"x",1));
    assert(out[0]==0xa5 && out[41]==0xa5 && !memcmp(out+1,"PDBR",4));
    assert(pdbg_u32(out+1+24)==PDBG_FRAME_BYTES && pdbg_u32(out+1+28)==1);
    assert(pdbg_reply(out+1,&s,&r,PDBG_STALE,NULL,0));
    for(unsigned i=16;i<40;i++)assert(out[1+i]==0);
    assert(!pdbg_reply(out,&s,&r,PDBG_OK,NULL,1));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_host_recovers_drops_corruption_and_reordering(self):
        raw = bytes((i * 37 + 19) % 256 for i in range(50001))
        class Peer:
            def __init__(self):
                self.queue, self.counts = [], {}
            def settimeout(self, value):
                pass
            def send(self, packet):
                magic, version, op, token, offset, size = struct.unpack('<4sHHQII', packet)
                assert (magic, version) == (b'PDBG', 1)
                key = (op, offset)
                self.counts[key] = self.counts.get(key, 0) + 1
                if self.counts[key] == 1 and (op == 1 or offset == 1400):
                    return len(packet)
                data = raw[offset:offset+size] if op == 3 else b''
                header = struct.pack('<4sHHQIIIIHHI', b'PDBR', 1, 0, token, 1,
                                     offset, len(raw), len(data), 0, 0, zlib.crc32(data))
                reply = header + data
                if self.counts[key] == 1 and offset == 2800:
                    reply = reply[:-1] + bytes([reply[-1] ^ 1])
                self.queue.extend([b'truncated', reply])
                return len(packet)
            def recv(self, size):
                if not self.queue:
                    raise socket.timeout()
                return self.queue.pop()  # reorder each request window
        peer = Peer()
        got, metadata = debug.fetch(peer, 1, timeout=0.01, token=0x1234)
        self.assertEqual(got, raw)
        self.assertEqual(metadata, (1, len(raw), 0, 0))
        self.assertGreaterEqual(peer.counts[(3, 1400)], 2)
        self.assertGreaterEqual(peer.counts[(3, 2800)], 2)

    def test_host_refuses_foreign_geometry_bounds_and_crc(self):
        good = struct.pack('<4sHHQIIIIHHI', b'PDBR', 1, 0, 7, 1, 0, 3, 3, 0, 0,
                           zlib.crc32(b'abc')) + b'abc'
        self.assertEqual(debug.decode(good, 7)[2], b'abc')
        for offset in (0, 4, 8, 24, 28, 32, 36, 40):
            bad = bytearray(good)
            if offset == 24:
                struct.pack_into('<I', bad, offset, 0xffffffff)
            else:
                bad[offset] ^= 0x80
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                debug.decode(bad, 7)
        for length in range(40):
            with self.assertRaises(ValueError):
                debug.decode(good[:length], 7)

    def test_png_preserves_bgra_channels_and_dimensions(self):
        raw = bytes([3, 2, 1, 255]) * (1080 * 2160)
        png = debug.panel_png(raw)
        width, height = struct.unpack_from('>II', png, 16)
        self.assertEqual((width, height), (1080, 2160))
        at, image = 8, b''
        while at < len(png):
            size = struct.unpack_from('>I', png, at)[0]
            kind, body = png[at+4:at+8], png[at+8:at+8+size]
            self.assertEqual(zlib.crc32(kind + body), struct.unpack_from('>I', png, at+8+size)[0])
            if kind == b'IDAT':
                image += body
            at += 12 + size
        pixels = zlib.decompress(image)
        self.assertEqual(pixels[:7], b'\0\1\2\3\1\2\3')
        self.assertEqual(len(pixels), (1 + 1080 * 3) * 2160)
        with self.assertRaises(ValueError):
            debug.panel_png(raw[:-1])


if __name__ == '__main__':
    unittest.main()
