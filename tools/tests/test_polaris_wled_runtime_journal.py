"""Strict new RAM-only page/receipt protocol; no hardware/reset authority."""
import struct
import unittest
import zlib
from tools import polaris_wled_runtime_journal as wire


def pages(records=None):
    if records is None:
        states=[(0,130)]*2
        for cycle in range(3):
            states += [(cycle*2+1,c) for c in [130,130,2,2,2,2,0,0,0,0]]
            states += [(cycle*2+2,c) for c in [0,0,128,128,128,128,130,130,130,130,130,130,130,130]]
        states += [(6,130)]*4
        records=[(100+i*20,110+i*20,i&1,(i>>1)&1,3,c,seq) for i,(seq,c) in enumerate(states)]
    raw=b''.join(wire.RECORD.pack(*r) for r in records)
    out=[];fault=rt=0
    for r in records:fault|=r[2];rt|=r[3]
    for offset in range(0,len(records),32):
        count=min(32,len(records)-offset);header=bytearray(80);header[:8]=b'WLRPAGE3'
        struct.pack_into('<QIIIHHI',header,8,123,1,len(records),offset,count,28,zlib.crc32(raw))
        struct.pack_into('<IIIIIQQ',header,36,0,0,0,12,12,6,6)
        header[72:77]=bytes([128,2,27,fault,rt])
        body=bytes(header)+raw[offset*28:(offset+count)*28]
        out.append(body+struct.pack('<I',zlib.crc32(body)))
    return out


def receipt(j):
    b=bytearray(60);b[:4]=b'WLR3'
    struct.pack_into('<QQIIIIIIQ',b,4,123,456,2,1,j['total'],j['total']-2,j['total'],j['prefix_crc'],6)
    struct.pack_into('<I',b,56,1);struct.pack_into('<I',b,52,zlib.crc32(b[:52]+b[56:]))
    return bytes(b)


def reCRC(b):
    return bytes(b[:-4])+struct.pack('<I',zlib.crc32(b[:-4]))


class RuntimeWire(unittest.TestCase):
    def test_complete_history_and_final_pairs_bind_native_session_without_physical_claim(self):
        p=pages();j=wire.journal(p);r=wire.receipt(receipt(j),j,cookie=123,native_cookie=456,native_sequence=1,mode=2)
        self.assertTrue(j['analysis_passed'] and r['restoration_consistent'])
        self.assertEqual(len(j['records']),78)
        self.assertEqual(j['fault_or'],1);self.assertEqual(j['rt_or'],1)
        self.assertFalse(r['physical_admission']);self.assertFalse(r['optical_off_proven'])

    def test_every_truncation_and_bit_of_page_or_receipt_refuses(self):
        p=pages();j=wire.journal(p);r=receipt(j)
        for b,decode in [(p[0],wire.page),(r,lambda b:wire.receipt(b,j,cookie=123,native_cookie=456,native_sequence=1,mode=2))]:
            for length in range(len(b)):
                with self.assertRaises(ValueError):decode(b[:length])
            for i in range(len(b)):
                for bit in range(8):
                    v=bytearray(b);v[i]^=1<<bit
                    with self.assertRaises(ValueError):decode(bytes(v))

    def test_missing_duplicate_reordered_or_foreign_snapshot_never_merges(self):
        p=pages()
        for bad in [p[1:],p[:2],p+[p[-1]],list(reversed(p)),[p[0],p[0],p[2]]]:
            with self.assertRaises(ValueError):wire.journal(bad)
        for field,value in [(8,124),(16,2),(20,77),(24,64),(32,0),(75,0)]:
            v=bytearray(p[1]);v[field]=value
            with self.assertRaises(ValueError):wire.journal([p[0],reCRC(v),p[2]])

    def test_raw_fault_or_partial_is_retained_but_cannot_restore(self):
        records=[(100+i*20,110+i*20,0,0,3,130,6) for i in range(78)]
        records[-1]=(1640,1650,2,0,1,130,6)
        p=pages(records)
        for at,b in enumerate(p):
            v=bytearray(b);struct.pack_into('<I',v,36,65);p[at]=reCRC(v)
        j=wire.journal(p)
        self.assertTrue(j['failed']);self.assertFalse(j['observations_valid'])
        self.assertEqual(j['records'][-1]['fault'],2)
        self.assertEqual(j['records'][-1]['valid'],1)
        self.assertEqual(j['fault_or'],2)
        with self.assertRaises(ValueError):wire.receipt(receipt(j),j,cookie=123,native_cookie=456,native_sequence=1,mode=2)
        with self.assertRaises(ValueError):wire.journal(pages(records))

    def test_recomputed_receipt_crc_cannot_change_cookie_mode_counters_or_terminal_state(self):
        p=pages();j=wire.journal(p);r=receipt(j)
        for i in range(52):
            v=bytearray(r);v[i]^=1;struct.pack_into('<I',v,52,zlib.crc32(v[:52]+v[56:]))
            with self.assertRaises(ValueError):wire.receipt(bytes(v),j,cookie=123,native_cookie=456,native_sequence=1,mode=2)
        for k,v in [('cookie',124),('native_cookie',457),('native_sequence',2),('mode',1)]:
            args=dict(cookie=123,native_cookie=456,native_sequence=1,mode=2);args[k]=v
            with self.assertRaises(ValueError):wire.receipt(r,j,**args)
        for field in ('failed','flags','module','irq','issued','ack'):
            bad=dict(j);bad[field]=True if field=='failed' else j[field]^1
            with self.assertRaises(ValueError):wire.receipt(r,bad,cookie=123,native_cookie=456,native_sequence=1,mode=2)

    def test_recomputed_whole_history_crc_cannot_replace_a_complete_pair(self):
        records=[(100+i*20,110+i*20,0,0,3,130,6) for i in range(78)]
        bad_cases=[records[:-1]]
        for field,value in [(5,128),(6,5)]:
            index=1 if field==5 else 0
            bad=list(records);r=list(bad[index]);r[field]=value;bad[index]=tuple(r)
            bad_cases.append(bad)
        # Individually bounded and monotonic observations, but their combined
        # pair exceeds the original verification's elapsed bound.
        late=[(100+i*200010,110+i*200010,0,0,3,130,6) for i in range(78)]
        bad_cases.append(late)
        for bad in bad_cases:
            with self.assertRaises(ValueError):wire.journal(pages(bad))
            p=pages(bad)
            for at,b in enumerate(p):
                v=bytearray(b);struct.pack_into('<I',v,36,65);p[at]=reCRC(v)
            j=wire.journal(p)
            self.assertTrue(j['failed']);self.assertFalse(j['observations_valid'])
            self.assertEqual(len(j['records']),len(bad))


if __name__=='__main__':unittest.main()
