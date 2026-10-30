"""Strict bounded WLED journal and final-reset receipt; no health/optical claim.

The final two real reset-gate reads travel inside the reset response. They must
extend the captured history exactly and reproduce its cumulative checksum.
"""
import hashlib
import struct
import zlib
from polaris_uefi_usb_transport import KernelProtocol

LIMIT=1348


def _record(raw):
    began,ended,fault,rt,valid,expected=struct.unpack('<QQBBBB',raw)
    if valid not in (0,1,3) or expected & ~0x82 or (not valid and fault) or (not valid&2 and rt):
        raise ValueError('invalid WLED raw observation mask/configuration')
    return dict(began_us=began,ended_us=ended,fault=fault,rt=rt,valid=valid,expected=expected)


def _history(records,healthy):
    fault=rt=previous=0
    for r in records:
        fault|=r['fault'];rt|=r['rt']
        if healthy and (r['valid']!=3 or (r['fault']|r['rt'])&~1 or
                        not r['began_us'] or r['began_us']<previous or r['ended_us']<=r['began_us'] or
                        r['ended_us']-r['began_us']>200000):
            raise ValueError('failed, stale or serious WLED observation claimed successful')
        previous=r['ended_us']
    return fault,rt


def parse_packet(raw):
    if not isinstance(raw,bytes) or not 68<=len(raw)<=LIMIT or raw[:8]!=b'WLEDJ2\0\0':
        raise ValueError('invalid WLED journal envelope')
    cookie,origin,sequence,count,werror,hcrc=struct.unpack_from('<QQIHHI',raw,8)
    error,phase,flags,issued,completed,module,irq=struct.unpack_from('<H6B',raw,36)
    request,ack=struct.unpack_from('<QQ',raw,44)
    if (not cookie or not sequence or count>64 or len(raw)!=68+20*count or phase>9 or flags&~7 or
        any(raw[62:64]) or completed>issued or ack>request or
        zlib.crc32(raw[:-4])!=struct.unpack_from('<I',raw,len(raw)-4)[0]):
        raise ValueError('invalid WLED journal count/state/checksum')
    record_wire=raw[64:-4]
    if zlib.crc32(record_wire)!=hcrc:
        raise ValueError('WLED raw history checksum mismatch')
    records=[_record(record_wire[i:i+20]) for i in range(0,len(record_wire),20)]
    if origin!=(records[0]['began_us'] if records else 0):
        raise ValueError('WLED history clock origin mismatch')
    fault,rt=_history(records,not(error or werror))
    if (fault,rt)!=(raw[60],raw[61]):
        raise ValueError('WLED cumulative status history was discarded')
    restored=(not(error or werror) and phase==1 and flags==3 and issued==completed==4 and
              module==0x80 and irq==2 and request==ack==2 and count>=26 and count%2==0 and
              {r['expected'] for r in records}=={0,2,0x80,0x82} and
              all(r['expected']==0x82 for r in records[-2:]))
    return dict(cookie=cookie,origin_us=origin,sequence=sequence,count=count,error=error,
                witness_error=werror,phase=phase,flags=flags,issued=issued,completed=completed,
                module=module,irq=irq,request=request,acknowledged=ack,records=records,
                fault_or=fault,rt_or=rt,history_crc32=hcrc,packet_sha256=hashlib.sha256(raw).hexdigest(),
                cycle_restored_readbacks=restored,physical_darkness_proven=False,
                actual_FASTBOOT_proven=False,hardware_health_proven=False)


def parse_reset_receipt(receipt,packet,mode=2):
    before=parse_packet(packet)
    if not before['cycle_restored_readbacks'] or mode not in (1,2) or len(receipt)!=56 or receipt[:4]!=b'WLR2':
        raise ValueError('no restored cycle or invalid final WLED receipt')
    cookie,base,total,crc,error=struct.unpack_from('<QHHIH',receipt,4)
    if (cookie!=before['cookie'] or base!=before['count'] or total!=base+2 or total>64 or
        error or receipt[22:24]!=b'\x04\x04' or receipt[26]!=mode or receipt[27:29]!=b'\x01\x03' or
        any(receipt[29:32])):
        raise ValueError('stale, foreign or incomplete final WLED receipt')
    final=[];wire=bytearray(packet[64:-4]);origin=before['origin_us']
    for at in (32,44):
        begin,end,fault,rt,valid,expected=struct.unpack_from('<IIBBBB',receipt,at)
        if origin+end>0xffffffffffffffff:
            raise ValueError('WLED receipt clock overflow')
        record=struct.pack('<QQBBBB',origin+begin,origin+end,fault,rt,valid,expected)
        final.append(_record(record));wire.extend(record)
    fault,rt=_history(before['records']+final,True)
    if (any(r['expected']!=0x82 for r in final) or final[-1]['ended_us']-final[0]['began_us']>200000 or
        (fault,rt)!=(receipt[24],receipt[25]) or zlib.crc32(wire)!=crc):
        raise ValueError('lost, changed or failed final WLED history')
    return dict(cookie=cookie,prior_packet_sha256=before['packet_sha256'],prior_count=base,
                final_count=total,final_records=final,full_history_crc32=crc,fault_or=fault,rt_or=rt,
                target_mode=mode,final_restore_receipt_valid=True,physical_darkness_proven=False,
                actual_FASTBOOT_proven=False,hardware_health_proven=False)


class WledOemProtocol(KernelProtocol):
    """Dedicated pre-XNU client. It exposes no touch, native shutdown or raw reset."""
    limits=dict(KernelProtocol.limits,**{'wled-journal':LIMIT})

    def __init__(self,transport):
        super().__init__(transport);self.journal=None;self.reset_sent=False

    def _control(self,command):
        if command not in (b'getvar:kernel-state',b'oem boot'):
            raise ValueError('not a WLED pre-XNU command')
        return super()._control(command)

    def capture_journal(self):
        if self.state()!='prepared':
            raise ValueError('WLED journal requires the pre-XNU hold')
        self.stage('wled-journal');raw=self.upload();parsed=parse_packet(raw)
        if self.journal is not None:
            old=parse_packet(self.journal)
            if (old['cookie']!=parsed['cookie'] or parsed['sequence']<=old['sequence'] or
                old['records']!=parsed['records'][:old['count']]):
                raise ValueError('WLED journal changed its published prefix')
        self.journal=raw;return raw,parsed

    def reboot(self,bootloader=False):
        raise ValueError('use the evidence-bound WLED reset')

    def reboot_restored(self,bootloader=True):
        if type(bootloader) is not bool or not self.verified or self.journal is None or self.reset_sent:
            raise ValueError('no captured WLED journal for reset')
        if not parse_packet(self.journal)['cycle_restored_readbacks'] or self.state()!='prepared':
            raise ValueError('WLED cycle not restored in the pre-XNU hold')
        mode=2 if bootloader else 1
        self.reset_sent=True
        self.transport.write(b'reboot-bootloader' if bootloader else b'reboot')
        response=self.transport.read(64)
        if not response.startswith(b'OKAY'):
            raise RuntimeError('WLED reset refused: '+response.decode('ascii',errors='replace'))
        return parse_reset_receipt(response[4:],self.journal,mode)

    def recover_unstarted_fastboot(self):
        if not self.verified or self.reset_sent:
            raise ValueError('unverified or already requested WLED reset')
        state=self.state()
        if state=='prepared':
            if self.journal is None:
                raise ValueError('preparation refusal requires the actual journal')
            p=parse_packet(self.journal)
            if p['issued'] or p['completed'] or p['flags']&4 or not p['error']:
                raise ValueError('not a proven zero-write preparation refusal')
        elif state not in ('waiting-payload','validated'):
            raise ValueError('no unstarted WLED recovery')
        self.reset_sent=True;self.transport.write(b'reboot-bootloader');response=self.transport.read(64)
        if not response.startswith(b'OKAY'):
            raise RuntimeError('unstarted WLED reset refused')
        raw=response[4:]
        if len(raw)!=16 or raw[:4]!=b'WLR0' or raw[12]!=2 or any(raw[14:]):
            raise ValueError('invalid zero-write WLED reset receipt')
        if state=='prepared' and (struct.unpack_from('<Q',raw,4)[0]!=p['cookie'] or raw[13]!=p['error']):
            raise ValueError('foreign zero-write WLED reset receipt')
        return dict(no_PMIC_command_issued_receipt=True,actual_FASTBOOT_proven=False)
