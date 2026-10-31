"""Real TCP duplex transport integration with delayed remote completion."""
import io
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from polaris_adb_stream import execute

class StreamTests(unittest.TestCase):
    def test_fixed_stream_waits_for_actual_remote_completion(self):
        payload=bytes(range(256))*(8192+1);errors=[];seen=[]
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(1)
            def remote():
                try:
                    with server.accept()[0] as c:
                        c.settimeout(5)
                        def exact(n):
                            b=bytearray()
                            while len(b)<n:
                                v=c.recv(min(4093,n-len(b)))
                                if not v:raise RuntimeError('premature client close')
                                b.extend(v)
                            return bytes(b)
                        for expected in (b'host:transport:test-only',b'exec:fixed-receiver'):
                            n=int(exact(4),16);self.assertEqual(exact(n),expected);c.sendall(b'OKAY')
                        seen.append(exact(len(payload)))
                        time.sleep(.05)
                        c.sendall(b'actual-completion')
                except BaseException as e:errors.append(e)
            thread=threading.Thread(target=remote);thread.start()
            output=execute('test-only','fixed-receiver',io.BytesIO(payload),len(payload),timeout=5,port=server.getsockname()[1]);thread.join(5)
            self.assertFalse(thread.is_alive());self.assertFalse(errors,errors);self.assertEqual(seen,[payload]);self.assertEqual(output,b'actual-completion')
    def test_bad_bounds_fail_before_connect(self):
        for size in (0,-1,(16<<30)+1,True):
            with self.assertRaises(ValueError):execute('test','cmd',io.BytesIO(),size,timeout=1)
if __name__=='__main__':unittest.main()
