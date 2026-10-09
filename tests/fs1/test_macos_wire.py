"""Real RPC regressions for durable lazy NFS, not a substitute for native gates."""
import json,os,socket,struct,tempfile,unittest
from pathlib import Path
from macos_wire import Fixture,attrs,opaque,words,read,write

@unittest.skipUnless(os.uname().sysname=='Darwin','macOS adapter')
class MacWire(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fs1-task6-wire-',dir='/private/tmp');self.addCleanup(self.temp.cleanup)
        self.f=Fixture(Path(self.temp.name));self.addCleanup(self.f.close)
    def test_lazy_write_file_sync_restart_and_identity(self):
        p,rpc,info=self.f.endpoint();root=rpc.mount();handle=rpc.lookup(root,b'binary')
        self.assertEqual(self.f.counts['body_bytes'],0)
        self.assertEqual(write(rpc,handle,b'ACK',100)[-12:-8],words(2))
        self.assertEqual(self.f.counts['body_bytes'],0) # no eager private backing / base hydration
        self.assertEqual(read(rpc,handle,96,12),(0,b'`abcACKghijk'))
        # Capabilities retain original identity after rename replacement and unlink/reuse.
        self.assertEqual(rpc.call(100003,14,opaque(root)+opaque(b'binary')+opaque(root)+opaque(b'renamed'))[:4],words(0))
        self.assertEqual(rpc.call(100003,12,opaque(root)+opaque(b'renamed'))[:4],words(0))
        self.assertEqual(read(rpc,handle,100,3),(0,b'ACK'))
        self.assertEqual(write(rpc,handle,b'old',100)[:4],words(0))
        self.assertEqual(rpc.call(100003,3,opaque(root)+opaque(b'renamed'))[:4],words(2))
        create=rpc.call(100003,8,opaque(root)+opaque(b'durable')+words(0)+attrs(0o666))
        self.assertEqual(create[:4],words(0));new=rpc.lookup(root,b'durable')
        self.assertEqual(write(rpc,new,b'\0\xffdurable')[:4],words(0))
        status=self.f.cli('status');self.assertTrue(status['uncaptured'])
        p.kill();p.communicate(timeout=10) # no kernel mount exists in this wire-only test
        _,again,_=self.f.endpoint('restart');new=again.lookup(again.mount(),b'durable')
        self.assertEqual(read(again,new,0,100),(0,b'\0\xffdurable'))
        self.assertNotEqual(again.call(100003,1,opaque(handle))[:4],words(0))
    def test_permissions_optional_attrs_and_forged_credentials(self):
        _,rpc,_=self.f.endpoint();root=rpc.mount();locked=rpc.lookup(root,b'locked')
        self.assertEqual(rpc.call(100003,2,opaque(locked)+attrs(0o000)+words(0))[:4],words(0))
        for uid in [0,12345,os.getuid()]:
            self.assertEqual(rpc.call(100003,6,opaque(locked)+struct.pack('>QI',0,10),uid)[:4],words(13))
        directory=rpc.lookup(root,b'read-dir');child=rpc.lookup(directory,b'child')
        self.assertEqual(rpc.call(100003,2,opaque(directory)+attrs(0o400)+words(0))[:4],words(0))
        self.assertEqual(rpc.call(100003,1,opaque(child))[:4],words(13))
        info=rpc.call(100003,19,opaque(child));self.assertEqual(info[:8],words(0,0))
        plus=rpc.call(100003,17,opaque(directory)+struct.pack('>Q',0)+b'\0'*8+words(4096,4096))
        self.assertEqual(plus[:4],words(0));self.assertIn(opaque(b'child')+struct.pack('>Q',int.from_bytes(child[-8:],'big'))+words(0,0),plus)
        forged=bytearray(child);forged[0]^=1
        self.assertNotEqual(rpc.call(100003,1,opaque(bytes(forged)))[:4],words(0))
    def test_server_cache_time_create_and_client_time_rejection(self):
        import time
        _,rpc,_=self.f.endpoint();root=rpc.mount();before=int(time.time())
        server_time_attrs=words(1,0o640,0,0,0,1,1)
        response=rpc.call(100003,8,opaque(root)+opaque(b'timed')+words(1)+server_time_attrs)
        self.assertEqual(response[:4],words(0));handle=rpc.lookup(root,b'timed')
        fields=rpc.call(100003,1,opaque(handle));atime,mtime=struct.unpack('>I',fields[-24:-20])[0],struct.unpack('>I',fields[-16:-12])[0]
        self.assertGreaterEqual(atime,before);self.assertGreaterEqual(mtime,before)
        self.assertEqual(write(rpc,handle,b'original')[:4],words(0))
        from concurrent.futures import ThreadPoolExecutor
        from macos_wire import Rpc
        def contender(_):return Rpc(rpc.port).call(100003,8,opaque(root)+opaque(b'concurrent')+words(1)+server_time_attrs)[:4]
        with ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sorted(pool.map(contender,range(2))),[words(0),words(17)])
        duplicate=rpc.call(100003,8,opaque(root)+opaque(b'timed')+words(1)+server_time_attrs)
        self.assertEqual(duplicate[:4],words(17));self.assertEqual(rpc.lookup(root,b'timed'),handle);self.assertEqual(read(rpc,handle,0,20),(0,b'original'))
        group=rpc.lookup(root,b'group');unchanged=rpc.call(100003,1,opaque(group))
        server_now=opaque(group)+words(0,0,0,0,1,1,0)
        self.assertEqual(rpc.call(100003,2,server_now)[:4],words(13))
        self.assertEqual(rpc.call(100003,1,opaque(group)),unchanged)
        _,ro,_=self.f.endpoint('ro','readonly','read-only');readonly=ro.lookup(ro.mount(),b'binary')
        self.assertEqual(ro.call(100003,2,opaque(readonly)+words(0,0,0,0,1,1,0))[:4],words(30))
        # Unsupported client-chosen times cannot mutate mode as a side effect.
        client_time=words(1,0o777,0,0,0,2,12345,0,0)
        self.assertEqual(rpc.call(100003,2,opaque(handle)+client_time+words(0))[:4],words(10004))
        self.assertEqual(rpc.call(100003,1,opaque(handle))[8:12],words(0o640))

    def test_server_now_owner_authorization_does_not_dirty_generation(self):
        _,rpc,_=self.f.endpoint();handle=rpc.lookup(rpc.mount(),b'binary')
        self.assertEqual(rpc.call(100003,2,opaque(handle)+attrs(0o444)+words(0))[:4],words(0))
        generation=self.f.cli('status')['working_generation']
        self.f.cli('checkpoint','lazy','--operation-id','operation:'+'7'*32,'--expected-generation',str(generation))
        before=self.f.cli('status')
        self.assertEqual(rpc.call(100003,2,opaque(handle)+words(0,0,0,0,1,1,0))[:4],words(0))
        self.assertEqual(self.f.cli('status'),before)
        self.assertEqual(rpc.call(100003,1,opaque(handle))[8:12],words(0o444))

    def test_exact_port_recovery_returns_stale_for_lost_process_handles(self):
        p,rpc,info=self.f.endpoint();handle=rpc.lookup(rpc.mount(),b'binary')
        self.assertEqual(write(rpc,handle,b'acknowledged',100)[:4],words(0))
        p.kill();p.communicate(timeout=5)
        _,again,recovery=self.f.endpoint('recovery1',port=info['port'])
        self.assertEqual(recovery['port'],info['port'])
        self.assertEqual(again.call(100003,1,opaque(handle))[:4],words(70))
        current=again.lookup(again.mount(),b'binary');self.assertEqual(read(again,current,100,12),(0,b'acknowledged'))

    def test_remove_and_rmdir_preserve_wrong_type_targets(self):
        _,rpc,_=self.f.endpoint();root=rpc.mount()
        self.assertEqual(rpc.call(100003,12,opaque(root)+opaque(b'empty'))[:4],words(21))
        self.assertEqual(rpc.call(100003,13,opaque(root)+opaque(b'binary'))[:4],words(20))
        self.assertTrue(rpc.lookup(root,b'empty'));self.assertTrue(rpc.lookup(root,b'binary'))

    def test_parent_delete_and_mkdir_attribute_validation(self):
        _,rpc,_=self.f.endpoint();root=rpc.mount();handle=rpc.lookup(root,b'binary')
        self.assertEqual(rpc.call(100003,2,opaque(handle)+attrs(0o444)+words(0))[:4],words(0))
        self.assertEqual(rpc.call(100003,4,opaque(handle)+words(16))[-4:],words(16))
        for mode in [0o700,0o777]:
            name=('d'+str(mode)).encode();result=rpc.call(100003,9,opaque(root)+opaque(name)+attrs(mode))
            self.assertEqual(result[:4],words(0));h=rpc.lookup(root,name)
            self.assertEqual(rpc.call(100003,1,opaque(h))[8:12],words(mode & ~0o022))
        for name,attribute in [(b'badmode',attrs(0o4755)),(b'badsize',attrs(0o700,10)),(b'baduid',words(1,0o700,1,0,0,0,0,0))]:
            self.assertNotEqual(rpc.call(100003,9,opaque(root)+opaque(name)+attribute)[:4],words(0))
            self.assertEqual(rpc.call(100003,3,opaque(root)+opaque(name))[:4],words(2))

    def test_readonly_and_private_peer_control(self):
        _,rpc,_=self.f.endpoint('ro','readonly','read-only');root=rpc.mount();handle=rpc.lookup(root,b'binary')
        requests=[(7,opaque(handle)+struct.pack('>QII',0,1,2)+opaque(b'X')),(2,opaque(handle)+attrs(0o777)+words(0)),(2,opaque(handle)+attrs(size=0)+words(0)),(8,opaque(root)+opaque(b'new')+words(1)+attrs(0o600)),(9,opaque(root)+opaque(b'made')+attrs(0o700)),(12,opaque(root)+opaque(b'binary')),(13,opaque(root)+opaque(b'empty')),(14,opaque(root)+opaque(b'binary')+opaque(root)+opaque(b'renamed'))]
        for uid in [0,os.getuid(),10001,12345]:
            for procedure,body in requests:self.assertEqual(rpc.call(100003,procedure,body,uid)[:4],words(30))
        self.assertEqual(self.f.cli('checkpoint','readonly','--operation-id','operation:'+'2'*32,code=1)['error'],'read_only')
        with socket.socket(socket.AF_UNIX) as sock:
            sock.connect(str(self.f.d/'readonly/control.sock'));sock.sendall(json.dumps({'command':'status','options':{},'principal':'root'}).encode());sock.shutdown(socket.SHUT_WR)
            self.assertEqual(json.loads(sock.recv(65536))['exit'],2)
        self.assertEqual((self.f.d/'readonly/control.sock').stat().st_mode&0o777,0o600)
if __name__=='__main__':unittest.main()
