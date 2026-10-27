"""Direct host transport for the synthetic Polaris UEFI service.

ReadOnlyProtocol admits diagnostic reads only. The separate KernelProtocol
opts into manifest-bound RAM downloads, kernel start and two reboot targets.
Neither client exposes flash, erase, arbitrary OEM commands, USB configuration
changes or driver detachment. libusb follows the caller's public library ABI.
"""
import ctypes as C
import hashlib
from pathlib import Path
import re
import struct
import time


class DeviceDescriptor(C.Structure):
    _fields_ = [(name, kind) for name, kind in [
        ('length', C.c_uint8), ('type', C.c_uint8), ('usb', C.c_uint16),
        ('device_class', C.c_uint8), ('subclass', C.c_uint8),
        ('protocol', C.c_uint8), ('packet', C.c_uint8),
        ('vendor', C.c_uint16), ('product', C.c_uint16), ('version', C.c_uint16),
        ('manufacturer', C.c_uint8), ('name', C.c_uint8), ('serial', C.c_uint8),
        ('configurations', C.c_uint8)]]


def validate_configuration(raw):
    """Admit one ordinary fastboot interface with the expected bulk endpoints."""
    if len(raw) < 9 or raw[:2] != b'\x09\x02':
        raise ValueError('invalid USB configuration header')
    if struct.unpack_from('<H', raw, 2)[0] != len(raw) or raw[4:6] != b'\x01\x01':
        raise ValueError('unexpected configuration size/count/value')
    interface = None
    endpoints = []
    at = 0
    while at < len(raw):
        if at + 2 > len(raw) or raw[at] < 2 or at + raw[at] > len(raw):
            raise ValueError('invalid USB descriptor length')
        d = raw[at:at + raw[at]]
        if d[1] == 4:
            if interface is not None or len(d) != 9 or d[2:8] != b'\x00\x00\x02\xff\x42\x03':
                raise ValueError('unexpected USB interface')
            interface = d
        if d[1] == 5:
            if interface is None or len(d) != 7 or d[3] & 3 != 2:
                raise ValueError('unexpected USB endpoint')
            if struct.unpack_from('<H', d, 4)[0] not in (512, 1024):
                raise ValueError('unexpected bulk packet size')
            endpoints.append(d[2])
        at += len(d)
    if interface is None or sorted(endpoints) != [1, 0x81]:
        raise ValueError('missing diagnostic bulk endpoints')


class ReadOnlyProtocol:
    limits = {'logs': 32768, 'memmap': 65568, 'screenshot': 16 * 1024 * 1024}

    def __init__(self, transport):
        self.transport = transport
        self.verified = False
        self.staged = None

    def _request(self, command):
        allowed = [b'getvar:product', b'upload'] + [b'oem ' + k.encode() for k in self.limits]
        if command not in allowed:
            raise ValueError('command is outside read-only diagnostics')
        self.transport.write(command)
        reply = self.transport.read(64)
        if reply.startswith(b'FAIL'):
            raise RuntimeError('UEFI refused request: ' + reply[4:].decode('ascii', errors='replace'))
        return reply

    def product(self):
        reply = self._request(b'getvar:product')
        if reply != b'OKAYpolaris-uefi-diag':
            raise ValueError('wrong diagnostic product; no OEM commands sent')
        self.verified = True
        return 'polaris-uefi-diag'

    def stage(self, what):
        if not self.verified or what not in self.limits:
            raise ValueError('unverified device or unsupported capture')
        self.staged = None
        if self._request(b'oem ' + what.encode()) != b'OKAY':
            raise ValueError('invalid staging response')
        self.staged = what

    def upload(self):
        if not self.verified or self.staged is None:
            raise ValueError('no verified staged diagnostic')
        limit = self.limits[self.staged]
        self.staged = None
        reply = self._request(b'upload')
        if not re.fullmatch(rb'DATA[0-9a-fA-F]{8}', reply):
            raise ValueError('invalid upload header')
        count = int(reply[4:], 16)
        if not 0 < count <= limit:
            raise ValueError('upload exceeds diagnostic bounds')
        result = bytearray()
        while len(result) < count:
            wanted = min(65536, count - len(result))
            chunk = self.transport.read(wanted)
            if not chunk or len(chunk) > wanted:
                raise ValueError('invalid upload data length')
            result.extend(chunk)
        if self.transport.read(64) != b'OKAY':
            raise ValueError('upload did not finish successfully')
        return bytes(result)


class LibusbTransport:
    def __init__(self, library):
        self.library = Path(library).resolve(strict=True)
        self.usb = C.CDLL(str(self.library))
        ptr, byteptr = C.c_void_p, C.POINTER(C.c_ubyte)
        declarations = {
            'init': ([C.POINTER(ptr)], C.c_int), 'exit': ([ptr], None),
            'get_device_list': ([ptr, C.POINTER(C.POINTER(ptr))], C.c_ssize_t),
            'free_device_list': ([C.POINTER(ptr), C.c_int], None),
            'get_device_descriptor': ([ptr, C.POINTER(DeviceDescriptor)], C.c_int),
            'open': ([ptr, C.POINTER(ptr)], C.c_int), 'close': ([ptr], None),
            'get_string_descriptor_ascii': ([ptr, C.c_uint8, byteptr, C.c_int], C.c_int),
            'get_configuration': ([ptr, C.POINTER(C.c_int)], C.c_int),
            'claim_interface': ([ptr, C.c_int], C.c_int),
            'release_interface': ([ptr, C.c_int], C.c_int),
            'control_transfer': ([ptr, C.c_uint8, C.c_uint8, C.c_uint16, C.c_uint16,
                                  byteptr, C.c_uint16, C.c_uint], C.c_int),
            'bulk_transfer': ([ptr, C.c_ubyte, byteptr, C.c_int,
                               C.POINTER(C.c_int), C.c_uint], C.c_int),
        }
        for name, (args, result) in declarations.items():
            fn = getattr(self.usb, 'libusb_' + name)
            fn.argtypes, fn.restype = args, result
        if C.sizeof(DeviceDescriptor) != 18:
            raise ValueError('unexpected host USB descriptor ABI')
        self.context, self.handle = ptr(), ptr()
        self.claimed = False
        self._check(self.usb.libusb_init(C.byref(self.context)), 'initialize libusb')

    @staticmethod
    def _check(code, action):
        if code < 0:
            raise RuntimeError(f'libusb {action} failed ({code})')
        return code

    def _config(self, handle, count):
        data = (C.c_ubyte * count)()
        got = self._check(self.usb.libusb_control_transfer(
            handle, 0x80, 6, 0x200, 0, data, count, 5000), 'read configuration descriptor')
        if got != count:
            raise ValueError('short configuration descriptor')
        return bytes(data)

    def open_target(self):
        if self.handle:
            return True
        devices = C.POINTER(C.c_void_p)()
        count = self._check(self.usb.libusb_get_device_list(
            self.context, C.byref(devices)), 'enumerate')
        candidates = []
        try:
            for i in range(count):
                desc = DeviceDescriptor()
                if self.usb.libusb_get_device_descriptor(devices[i], C.byref(desc)) < 0:
                    continue
                if desc.vendor != 0x18d1 or desc.product != 0xd00d:
                    continue
                handle = C.c_void_p()
                self._check(self.usb.libusb_open(devices[i], C.byref(handle)), 'open target')
                try:
                    serial = (C.c_ubyte * 128)()
                    got = self.usb.libusb_get_string_descriptor_ascii(handle, desc.serial, serial, 128)
                    if got != 12 or bytes(serial[:got]) != b'polaris-uefi':
                        continue
                    header = self._config(handle, 9)
                    length = struct.unpack_from('<H', header, 2)[0]
                    if not 9 <= length <= 4096:
                        raise ValueError('configuration descriptor too large')
                    validate_configuration(self._config(handle, length))
                    value = C.c_int()
                    self._check(self.usb.libusb_get_configuration(handle, C.byref(value)), 'read active configuration')
                    if value.value != 1:
                        raise ValueError('diagnostic interface is not configured; no configuration change attempted')
                    candidates.append(handle)
                    handle = C.c_void_p()
                finally:
                    if handle:
                        self.usb.libusb_close(handle)
            if len(candidates) > 1:
                raise ValueError('multiple synthetic diagnostic devices; refusing ambiguous access')
            if not candidates:
                return False
            self._check(self.usb.libusb_claim_interface(candidates[0], 0), 'claim interface')
            self.handle = candidates.pop()
            self.claimed = True
            return True
        finally:
            for handle in candidates:
                self.usb.libusb_close(handle)
            self.usb.libusb_free_device_list(devices, 1)

    def write(self, data):
        if not self.claimed or not data or len(data) > 64:
            raise ValueError('invalid diagnostic command transfer')
        self._out(data)

    def write_data(self,data):
        if not self.claimed or not 0<len(data)<=65536:
            raise ValueError('invalid RAM payload chunk')
        self._out(data)

    def _out(self,data):
        buf = (C.c_ubyte * len(data)).from_buffer_copy(data)
        done = C.c_int()
        self._check(self.usb.libusb_bulk_transfer(self.handle, 1, buf, len(data), C.byref(done), 10000), 'command transfer')
        if done.value != len(data):
            raise ValueError('short diagnostic command transfer')

    def read(self, count):
        if not self.claimed or not 0 < count <= 65536:
            raise ValueError('invalid diagnostic read bounds')
        buf = (C.c_ubyte * count)()
        done = C.c_int()
        self._check(self.usb.libusb_bulk_transfer(self.handle, 0x81, buf, count, C.byref(done), 10000), 'response transfer')
        if not 0 < done.value <= count:
            raise ValueError('invalid diagnostic completion length')
        return bytes(buf[:done.value])

    def close(self):
        if self.claimed:
            self.usb.libusb_release_interface(self.handle, 0)
            self.claimed = False
        if self.handle:
            self.usb.libusb_close(self.handle)
            self.handle = C.c_void_p()
        if self.context:
            self.usb.libusb_exit(self.context)
            self.context = C.c_void_p()


class KernelProtocol(ReadOnlyProtocol):
    """Explicit RAM-boot/reset client. ReadOnlyProtocol keeps its old whitelist."""
    limits=dict(ReadOnlyProtocol.limits,logs=(4<<20)+32768+128,**{'boot-options':65536})

    def _control(self,command):
        contact=re.fullmatch(rb'oem touch:[01]:[0-9]{1,4}:[0-9]{1,4}',command)
        if not self.verified or (command not in [b'getvar:kernel-state',b'getvar:input',b'oem boot',b'reboot',b'reboot-bootloader'] and not contact):
            raise ValueError('unsupported or unverified control command')
        self.transport.write(command);reply=self.transport.read(64)
        if not reply.startswith(b'OKAY'):
            raise RuntimeError('UEFI control refused: '+reply.decode('ascii',errors='replace'))
        return reply[4:]

    def state(self):
        result=self._control(b'getvar:kernel-state')
        if result not in [b'CPU_ON-refused',b'AP-early-fault',b'AP-wrong-EL',b'kernel-entered',
                          b'AP-start-pending',b'prepared',b'validated',b'receiving',b'waiting-payload',b'admission-refused']:
            raise ValueError('unknown kernel state')
        return result.decode()

    def stage_payload(self,data,manifest):
        if self.state()!='waiting-payload':raise ValueError('RAM loader is not idle; reset before replacing a kernel')
        if (not manifest.get('RAM_only_XNU_loader') or manifest.get('storage_write_api') is not False or
            manifest.get('NVRAM_write_api') is not False or manifest.get('QEMU_variant') is not False or
            manifest.get('payload_bytes')!=len(data) or not 0<len(data)<=128<<20 or
            hashlib.sha256(data).hexdigest()!=manifest.get('payload_sha256')):
            raise ValueError('RAM payload does not match the physical loader manifest')
        command=f'download:{len(data):08x}'.encode();self.transport.write(command)
        if self.transport.read(64)!=b'DATA'+command[9:]:raise ValueError('RAM download admission did not match size')
        for at in range(0,len(data),65536):self.transport.write_data(data[at:at+65536])
        if self.transport.read(64)!=b'OKAY':raise ValueError('device rejected RAM payload validation')
        if self.state()!='validated':raise ValueError('device did not publish validated payload state')

    def boot(self):
        if self.state()!='validated':raise ValueError('no validated RAM kernel')
        if self._control(b'oem boot'):raise ValueError('invalid RAM boot acknowledgement')

    def reboot(self,bootloader=False):
        if self._control(b'reboot-bootloader' if bootloader else b'reboot'):
            raise ValueError('invalid reset acknowledgement')

    def input_status(self):
        raw=self._control(b'getvar:input')
        if not re.fullmatch(rb'[01]/[0-9a-f]{8}/[0-9a-f]{8}/[0-9a-f]{8}',raw):raise ValueError('invalid input status')
        ready,request,ack,error=raw.split(b'/')
        return dict(ready=ready==b'1',request=int(request,16),acknowledged=int(ack,16),error=int(error,16))

    def touch(self,down,x,y,timeout=3):
        if (type(down) is not int or down not in [0,1] or type(x) is not int or type(y) is not int or
            not 0<=x<1080 or not 0<=y<2160 or not 0<timeout<=10):raise ValueError('invalid contact')
        before=self.input_status()
        if not before['ready'] or before['request']!=before['acknowledged'] or before['request']==0xffffffff:
            raise RuntimeError('input channel not ready or has an outstanding contact')
        if self._control(f'oem touch:{down}:{x}:{y}'.encode()):raise ValueError('invalid contact acknowledgement')
        wanted=before['request']+1;start=time.monotonic()
        while True:
            after=self.input_status()
            if after['acknowledged']==wanted:
                if after['error']:raise RuntimeError('kernel refused contact')
                return wanted
            if after['request']!=wanted or time.monotonic()-start>=timeout:raise RuntimeError('contact consumption not proven')
            time.sleep(.01)

    def tap(self,x,y):
        self.touch(1,x,y)
        try:time.sleep(.09)
        finally:self.touch(0,x,y)

    def swipe(self,x,y,to_x,to_y,duration_ms=400):
        if any(type(v) is not int for v in [x,y,to_x,to_y,duration_ms]) or not 0<=to_x<1080 or not 0<=to_y<2160 or not 100<=duration_ms<=1500:
            raise ValueError('invalid swipe')
        current_x,current_y=x,y;self.touch(1,x,y)
        try:
            for step in range(1,17):
                time.sleep(duration_ms/16000)
                current_x=x+(to_x-x)*step//16;current_y=y+(to_y-y)*step//16
                self.touch(1,current_x,current_y)
        finally:self.touch(0,current_x,current_y)
