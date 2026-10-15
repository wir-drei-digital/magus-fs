"""Real pipe/socket transport tests; these do not qualify hosted TLS."""
import concurrent.futures
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

ROOT=Path(__file__).parent


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]


class RelayTests(unittest.TestCase):
    def spawn(self,mode,read,write,p,target=0,lifetime=4):
        code="from ssh_relay import relay;import sys;relay(sys.argv[1],0,1,int(sys.argv[2]),int(sys.argv[3]),float(sys.argv[4]))"
        proc=subprocess.Popen([sys.executable,'-c',code,mode,str(p),str(target),str(lifetime)],
            cwd=ROOT,stdin=read,stdout=write,stderr=subprocess.PIPE)
        self.addCleanup(self.close_process,proc);return proc

    @staticmethod
    def close_process(p):
        if p.poll() is None:p.terminate()
        p.wait(timeout=3)
        for stream in (p.stdin,p.stdout,p.stderr):
            if stream:stream.close()

    def connect(self,p):
        end=time.monotonic()+2
        while True:
            try:return socket.create_connection(('127.0.0.1',p),timeout=2)
            except ConnectionRefusedError:
                if time.monotonic()>end:raise
                time.sleep(.01)

    def test_concurrent_binary_and_half_close(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('ssh_relay'),'relay implementation missing')
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        self.addCleanup(listener.close)
        def echo():
            for unused in range(4):
                conn,_=listener.accept()
                def one(c):
                    with c:
                        body=b''
                        while True:
                            b=c.recv(8192)
                            if not b:break
                            body+=b
                        c.sendall(body[::-1])
                threading.Thread(target=one,args=(conn,),daemon=True).start()
        threading.Thread(target=echo,daemon=True).start()
        ar,aw=os.pipe();br,bw=os.pipe();p=port()
        local=self.spawn('local',ar,bw,p,listener.getsockname()[1])
        remote=self.spawn('remote',br,aw,p)
        for fd in (ar,aw,br,bw):os.close(fd)
        def exchange(n):
            data=bytes(range(256))*(n+100)
            with self.connect(p) as c:
                c.sendall(data);c.shutdown(socket.SHUT_WR);got=b''
                while True:
                    b=c.recv(8192)
                    if not b:break
                    got+=b
            self.assertEqual(got,data[::-1])
        with concurrent.futures.ThreadPoolExecutor(4) as pool:list(pool.map(exchange,range(4)))
        local.terminate();local.wait(timeout=2)
        self.assertNotEqual(remote.wait(timeout=2),0)

    def test_invalid_and_truncated_frames_fail_closed(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('ssh_relay'))
        for frame in (b'xx',struct.pack('!BII',9,1,0),struct.pack('!BII',2,1,65537),
                      struct.pack('!BII',2,1,1)+b'x'):
            with self.subTest(frame=frame):
                p=self.spawn('remote',subprocess.PIPE,subprocess.PIPE,port())
                p.stdin.write(frame);p.stdin.close();p.stdin=None
                self.assertNotEqual(p.wait(timeout=2),0)

    def test_stream_capacity_fails_closed(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('ssh_relay'))
        pport=port();p=self.spawn('remote',subprocess.PIPE,subprocess.PIPE,pport)
        conns=[]
        try:
            for unused in range(17):conns.append(self.connect(pport))
            self.assertNotEqual(p.wait(timeout=2),0)
        finally:
            for c in conns:c.close()

    def test_full_close_shutdown_already_disconnected(self):
        import ssh_relay
        self.assertTrue(hasattr(ssh_relay,'close_write'))
        with socket.socket() as disconnected:
            ssh_relay.close_write(disconnected)

    def test_byte_capacity_rejects_before_mutating_queue(self):
        import ssh_relay
        self.assertTrue(hasattr(ssh_relay,'append_bounded'))
        pending=bytearray(b'x')
        ssh_relay.append_bounded(pending,b'y',ssh_relay.QUEUED-1)
        self.assertEqual(pending,b'xy')
        with self.assertRaisesRegex(ValueError,'queued byte capacity'):
            ssh_relay.append_bounded(pending,b'z',ssh_relay.QUEUED)
        self.assertEqual(pending,b'xy')

    def test_bounded_lifetime(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('ssh_relay'))
        p=self.spawn('remote',subprocess.PIPE,subprocess.PIPE,port(),lifetime=.1)
        self.assertEqual(p.wait(timeout=2),0)

if __name__=='__main__':unittest.main()
