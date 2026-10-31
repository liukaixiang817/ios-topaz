"""Bounded duplex ADB exec stream; hold transport until remote completion.

The fixed-size receiver does not need stdin EOF. Never half-close/close the
socket immediately after sending: retain it for the remote completion/close.
No command retry or device selection policy is implemented by this module.
"""
import socket
import time


def execute(serial, command, source, size, *, timeout, port=5037):
    if not serial or any(c in serial for c in '\r\n\0') or not command or '\0' in command:
        raise ValueError('ordinary private device identity and command required')
    if type(size) is not int or not 0 < size <= 16 << 30 or not 0 < timeout <= 660:
        raise ValueError('bounded fixed-size stream required')
    deadline=time.monotonic()+timeout
    with socket.create_connection(('127.0.0.1',port),timeout=min(8,timeout)) as conn:
        def budget():
            left=deadline-time.monotonic()
            if left<=0:raise TimeoutError('ADB stream deadline; completion unknown, never resend')
            conn.settimeout(left)
        def receive(n):
            data=bytearray()
            while len(data)<n:
                budget();chunk=conn.recv(n-len(data))
                if not chunk:raise RuntimeError('ADB status truncated')
                data.extend(chunk)
            return bytes(data)
        def request(service):
            encoded=service.encode();assert len(encoded)<=65535
            budget();conn.sendall(f'{len(encoded):04x}'.encode()+encoded)
            status=receive(4)
            if status==b'FAIL':
                length=int(receive(4),16)
                if length<=65535:receive(length)
                raise RuntimeError('ADB service refused; private identity/message withheld')
            if status!=b'OKAY':raise RuntimeError('ADB invalid service status')
        request('host:transport:'+serial)
        request('exec:'+command)
        sent=0
        while sent<size:
            data=source.read(min(1<<20,size-sent))
            if not data:raise RuntimeError('short host stream; never resend')
            budget();conn.sendall(data);sent+=len(data)
        # Remote may still hash/readback/fsync. Leave the sending half open:
        # its fixed-size stdin is complete; wait for its actual service close.
        output=bytearray()
        while True:
            budget();chunk=conn.recv(65536)
            if not chunk:break
            output.extend(chunk)
            if len(output)>1<<20:raise RuntimeError('unbounded remote output; completion unknown')
        return bytes(output)
