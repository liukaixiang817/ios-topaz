"""Bounded native WLED transport. No image admission or arbitrary OEM/reset API."""
import re
from polaris_uefi_usb_transport import KernelProtocol
from polaris_wled_runtime_journal import page,journal,exit_footer,exit_receipt,zero_write_receipt


class WledRuntimeProtocol(KernelProtocol):
    limits=dict(KernelProtocol.limits,**{'wled-runtime':980})

    def __init__(self,transport):
        super().__init__(transport);self.exit_sent=False;self.actual_footer=b'';self.actual_reply=b''

    def _control(self,command):
        if command in (b'reboot',b'reboot-bootloader',b'oem drained-reboot:1',b'oem drained-reboot:2'):
            raise ValueError('runtime reset requires atomic raw-history exit')
        return super()._control(command)

    def capture_history(self):
        pages=[];wanted=1
        for n in range(256):
            if n>=wanted:break
            if not self.verified:raise ValueError('unverified runtime service')
            self.transport.write(f'oem wled-runtime-page:{n:08x}'.encode())
            if self.transport.read(64)!=b'OKAY':raise RuntimeError('runtime page unavailable')
            self.staged='wled-runtime';raw=self.upload();p=page(raw);pages.append(raw)
            if not n:wanted=(p['total']+31)//32
        return pages,journal(pages)

    def atomic_exit(self,prefix,*,recover=False):
        if not self.verified or self.exit_sent or type(recover) is not bool or self.shutdown_token is None:
            raise ValueError('one atomic exit per verified native-drain session')
        cookie,sequence,mode=self.shutdown_token
        if mode!=2:raise ValueError('runtime exit only returns to FASTBOOT')
        cmd='oem wled-recover:' if recover else 'oem wled-exit:'
        cmd+=f"{prefix['cookie']:016x}:{prefix['total']:08x}:{prefix['prefix_crc']:08x}"
        self.exit_sent=True;self.transport.write(cmd.encode())
        header=self.transport.read(64)
        if not re.fullmatch(rb'DATA[0-9a-fA-F]{8}',header):raise RuntimeError('atomic exit footer refused')
        count=int(header[4:],16)
        if count not in (100,212) or count!=(100 if recover else 212):raise ValueError('bounded atomic footer length')
        raw=bytearray()
        while len(raw)<count:
            part=self.transport.read(count-len(raw))
            if not part or len(part)>count-len(raw):raise ValueError('truncated atomic exit footer')
            raw.extend(part);self.actual_footer=bytes(raw)
        self.actual_reply=self.transport.read(64)
        if len(self.actual_reply)!=64 or self.actual_reply[:4]!=b'OKAY':raise RuntimeError('fresh atomic exit receipt unavailable')
        sealed=exit_footer(bytes(raw),prefix,native_cookie=cookie,native_sequence=sequence,recover=recover)
        return exit_receipt(self.actual_reply[4:],sealed)

    def recover_prestart(self):
        if not self.verified or self.exit_sent:raise ValueError('one prestart recovery per verified session')
        if self.state() not in ('waiting-payload','validated','prepared','admission-refused'):
            raise ValueError('prestart refusal not observed; native drain required')
        self.exit_sent=True;self.transport.write(b'reboot-bootloader');self.actual_reply=self.transport.read(64)
        if len(self.actual_reply)!=44 or self.actual_reply[:4]!=b'OKAY':raise RuntimeError('prestart zero-write receipt missing')
        return zero_write_receipt(self.actual_reply[4:])
