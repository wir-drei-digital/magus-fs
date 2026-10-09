"""Owned Linux helper; unmount before stopping resources or deleting any live mount."""
import errno,hashlib,http.server,json,os,signal,socket,subprocess,threading,time
from pathlib import Path
P=Path('/private'); S=Path('/shared'); processes=[]; mounts={}; counts={'body_bytes':0,'requests':0}; offline=False; source=None; source_thread=None; report={'cleanup':[],'reaped':[]}
def cli(command,state='lazy',*args,binary='magus-fs',code=0):
    argv=[binary,command,'--state',str(P/state),*map(str,args)]
    r=subprocess.run(argv,capture_output=True,text=True,timeout=15)
    if r.returncode!=code: raise RuntimeError((argv,r.returncode,r.stdout,r.stderr))
    return json.loads(r.stdout)
def mounted(path): return any(x.split()[4]==str(path) for x in Path('/proc/self/mountinfo').read_text().splitlines())
def stop(name,kill=False):
    item=mounts[name];p=item['process'];path=S/name
    if kill and p.poll() is None: p.kill();p.wait(timeout=5)
    if mounted(path):
        r=subprocess.run(['umount',str(path)],capture_output=True,text=True,timeout=5)
        report['cleanup'].append({'path':str(path),'returncode':r.returncode,'stderr':r.stderr,'still_mounted':mounted(path),'daemon_loss':kill})
        if r.returncode or mounted(path): raise RuntimeError('owned mount retained '+str(path))
    if p.poll() is None: p.wait(timeout=5)
    if path.exists(): path.rmdir()
    item['reaped']=p.returncode
    return {'pid':p.pid,'returncode':p.returncode,'mounted':False}
def mount(name,state='lazy',mode='private',fault=False):
    path=S/name
    env=dict(os.environ)
    if fault: env.update(MAGUS_TEST_FAULT_POINT='object-sync',MAGUS_TEST_FAULT_ACTION='ENOSPC')
    log=P/(name+'-stderr');out=P/(name+'-stdout')
    argv=['magus-fs-faults' if fault else 'magus-fs','mount','--state',str(P/state),'--revision',revision,'--mountpoint',str(path),'--mode',mode]
    with log.open('w') as e,out.open('w') as o: p=subprocess.Popen(argv,stdout=o,stderr=e,env=env)
    processes.append(p);mounts[name]={'process':p,'state':state,'argv':argv}
    deadline=time.monotonic()+12
    while not mounted(path):
        if p.poll() is not None or time.monotonic()>deadline: raise AssertionError({'mount_did_not_start':argv,'exit':p.poll(),'stdout':out.read_text(),'stderr':log.read_text()})
        time.sleep(.05)
    return {'pid':p.pid,'mountpoint':str(path),'argv':argv}
class Source(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global counts
        if offline: self.send_error(503);return
        name=self.path.rsplit('/',1)[-1]
        if not name.startswith('sha256:') or '/' in name: self.send_error(404);return
        file=P/'source/objects'/name
        if not file.is_file(): self.send_error(404);return
        b=file.read_bytes();counts['body_bytes']+=len(b);counts['requests']+=1
        self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def log_message(self,*_): pass
def command(d):
    global offline,source,source_thread
    action=d['action']
    if action=='stats': return counts
    if action=='offline':
        source.shutdown();source.server_close();source_thread.join();source=None;offline=True
        with socket.socket() as probe:
            probe.settimeout(1);error=probe.connect_ex(('127.0.0.1',8765));assert error==errno.ECONNREFUSED,error
        return {'offline':True,'listener_closed':True,'connect_errno':error,'thread_joined':True}
    if action=='online':
        source=http.server.ThreadingHTTPServer(('127.0.0.1',8765),Source);source_thread=threading.Thread(target=source.serve_forever);source_thread.start();offline=False
        return {'offline':False}
    if action=='control-checks':
        def wire(state,payload):
            with socket.socket(socket.AF_UNIX) as sock:
                sock.connect(str(P/state/'control.sock'));sock.sendall(json.dumps(payload).encode());sock.shutdown(socket.SHUT_WR);data=b''
                while chunk:=sock.recv(65536):data+=chunk
                return json.loads(data)
        forged=wire('lazy',{'command':'status','options':{},'principal':'principal:'+'1'*32})
        assert forged['exit']==2 and forged['value']['error']=='invalid_descriptor',forged
        readonly=wire('readonly',{'command':'checkpoint','options':{'operation-id':'operation:'+'9'*32}})
        assert readonly['exit']==1 and readonly['value']['error']=='read_only',readonly
        stale=P/'faultstate/control.sock';stale.write_bytes(b'owned sentinel');stale.chmod(0o600)
        attempt=subprocess.run(['magus-fs','mount','--state',str(P/'faultstate'),'--revision',revision,'--mountpoint',str(S/'fault'),'--mode','private'],capture_output=True,text=True,timeout=5)
        assert attempt.returncode==1 and json.loads(attempt.stdout)['error']=='unsafe_storage',attempt.stdout
        assert stale.read_bytes()==b'owned sentinel';stale.unlink()
        meta=(P/'lazy/control.sock').stat();assert meta.st_uid==0 and meta.st_mode&0o777==0o600
        return {'forged_actor':forged,'readonly_checkpoint':readonly,'stale_regular_file_preserved':True,'mode':oct(meta.st_mode&0o777),'uid':meta.st_uid}

    if action=='owner-busy':
        results={}
        for name,args in [('export',['--revision',revision,'--destination','/private/busy-export']),('restore',['--revision',revision,'--operation-id','operation:'+'8'*32]),('prune',['--dry-run']),('history-grants',['--config','/private/config.json'])]:
            r=subprocess.run(['magus-fs',name,'--state','/private/lazy',*args],capture_output=True,text=True,timeout=5)
            value=json.loads(r.stdout);assert r.returncode==1 and value['error']=='replica_busy',(name,r.stdout);results[name]=value['error']
        assert not Path('/private/busy-export').exists()
        return results
    if action=='mount': return mount(d['name'],d.get('state','lazy'),d.get('mode','private'),d.get('fault',False))
    if action=='stop': return stop(d['name'],d.get('kill',False))
    if action=='cli': return cli(d['command'],d.get('state','lazy'),*d.get('args',[]),code=d.get('code',0))
    if action=='copy-full':
        return cli('materialize','source','--revision',revision,'--destination','/shared/full')
    raise ValueError(action)
class Control(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            data=json.loads(self.rfile.read(int(self.headers['Content-Length'])));value={'ok':True,'result':command(data)}
        except Exception as e: value={'ok':False,'error':repr(e)}
        b=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def log_message(self,*_): pass
def main():
    global revision,source,source_thread
    with (S/".fs1-owned").open("x") as marker: marker.write(os.environ["FS1_OWNER_TOKEN"])
    P.mkdir(exist_ok=True);tree=P/'tree';tree.mkdir();tree.chmod(0o755)
    digest=hashlib.sha256()
    with (tree/'large').open('wb') as f:
        for start in range(0,2097152,8192):
            block=b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(start,start+8192));f.write(block);digest.update(block)
    (tree/'uncached').write_bytes(b'unhydrated original revision'*12000)
    for name,body,mode in [('locked',b'locked',0),('group',b'group',0o640)]: (tree/name).write_bytes(body);(tree/name).chmod(mode)
    for name,mode in [('empty',0o755),('read-dir',0o400),('search-dir',0o100),('unlink-parent',0o700)]:
        (tree/name).mkdir()
        if name!='empty': (tree/name/('no-write' if name=='unlink-parent' else 'child')).write_bytes(b'child')
        (tree/name).chmod(mode)
    (tree/'unlink-parent/no-write').chmod(0o444)
    from inventory import corpus
    corpus(tree)
    for root,dirs,files in os.walk(tree):
        os.chown(root,1001,1001)
        for name in files: os.chown(Path(root)/name,1001,1001)
    group='group:'+'1'*32
    authorities=[]
    for uid,gid,groups in [(0,0,[group,'group:'+'0'*32]),(1001,1001,[group]),(1002,1002,[group,'group:'+'2'*32]),(1003,1003,['group:'+'3'*32])]:
        authorities.append({'principal':'principal:'+str(uid).zfill(32),'uid':uid,'primary_group':group if uid==1001 else 'group:'+str(0 if uid==0 else uid-1000)*32,'gid':gid,'groups':groups,'dac_override':uid==0,'ownership_transfer':True})
    config={'replica':{'replica':'replica:'+'1'*32,'authorities':authorities,'content_roots':[str(tree),str(S/'view'),str(S/'ro'),str(S/'fault'),str(S/'full')],'cache_bytes':134217728},'root':str(tree),'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
    cfg=P/'config.json';cfg.write_text(json.dumps(config));cli('init','source','--config',cfg)
    revision=cli('capture','source','--root',tree,'--operation-id','operation:'+'1'*32)['revision']
    history=cli('history','source');manifest=P/'revision.json';manifest.write_text(history['revisions'][0]['canonical_descriptor'])
    source=http.server.ThreadingHTTPServer(('127.0.0.1',8765),Source);source_thread=threading.Thread(target=source.serve_forever);source_thread.start()
    control=http.server.HTTPServer(('127.0.0.1',9001),Control);control_thread=threading.Thread(target=control.serve_forever);control_thread.start()
    try:
        for state in ['lazy','readonly','faultstate','parity']:
            cli('init',state,'--config',cfg,'--revision-manifest',manifest,'--source','http://127.0.0.1:8765')
        report['capabilities']=[line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('Cap','NoNewPrivs'))]
        report['binaries']={name:hashlib.sha256(Path('/usr/local/bin',name).read_bytes()).hexdigest() for name in ['magus-fs','magus-fs-faults']}
        (P/'fixture.json').write_text(json.dumps({'revision':revision,'sha256':digest.hexdigest(),'counts':dict(counts),'source_descriptor':history['revisions'][0]['descriptor']}))
        print(json.dumps({'ready':True,'revision':revision,'sha256':digest.hexdigest()}),flush=True)
        signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(InterruptedError()))
        while True: signal.pause()
    except InterruptedError: pass
    finally:
        errors=[]
        for name in reversed(list(mounts)):
            try: stop(name)
            except Exception as e: errors.append(repr(e))
        if errors:
            print(json.dumps({'cleanup_errors':errors,'retained_serving_helpers':True}),flush=True)
            while True: time.sleep(1)
        control.shutdown();control.server_close();control_thread.join()
        if source is not None: source.shutdown();source.server_close();source_thread.join()
        report['reaped']=[{'pid':p.pid,'returncode':p.poll()} for p in processes]
        report['mounted_remaining']=[line for line in Path('/proc/self/mountinfo').read_text().splitlines() if '/shared/' in line]
        print(json.dumps(report),flush=True)
if __name__=='__main__': main()
