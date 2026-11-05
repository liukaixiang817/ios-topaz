#!/usr/bin/env python3
"""Real secret input and terminal recovery; no network/device ioctl."""
import os
from pathlib import Path
import pty
import signal
import subprocess
import sys
import termios
import time

binary=str(Path(sys.argv[1]).resolve())
subprocess.run([binary],check=True)
for raw,accepted in [(b'a'*7+b'\n',False),(b'a'*8+b'\n',True),
                     (b'a'*63+b'\n',True),(b'a'*64+b'\n',False),
                     (b'1234567\t\n',False),(b'abcdefgh',True)]:
    p=subprocess.run([binary,'--secret'],input=raw,capture_output=True)
    assert (p.returncode==0)==accepted,(len(raw),p.returncode,p.stderr)
    assert raw.strip() not in p.stdout+p.stderr
for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
    master,slave=pty.openpty()
    original=termios.tcgetattr(slave)
    proc=subprocess.Popen([binary,'--secret'],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+5
        while termios.tcgetattr(slave)[3]&termios.ECHO:
            assert proc.poll() is None and time.monotonic()<deadline
            time.sleep(.01)
        os.write(master,b'partial')
        proc.send_signal(sig)
        out,err=proc.communicate(timeout=5)
        assert proc.returncode==-sig,(sig,proc.returncode,err)
        assert termios.tcgetattr(slave)==original
        assert b'partial' not in out+err
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
        os.close(master);os.close(slave)
print('PASS secret bounds, no echoed/buffered secret and terminal recovery on 3 signals')
