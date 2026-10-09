"""Owned real NFS fixture and protocol client; no native mount in this module."""
import hashlib,http.server,json,os,selectors,socket,struct,subprocess,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/fs0'))
from test_nfs import Rpc,words,opaque
sys.path.remove(str(ROOT/'tests/fs0'))
from inventory import corpus
BIN=Path(os.environ.get('MAGUS_FS_BIN',ROOT/'target/debug/magus-fs'))
P='principal:'+'1'*32;G='group:'+'1'*32;P2='principal:'+'2'*32;G2='group:'+'2'*32

def attrs(mode=None,size=None):
    return (words(0) if mode is None else words(1,mode))+words(0,0)+(words(0) if size is None else words(1)+struct.pack('>Q',size))+words(0,0)

def read(rpc,handle,offset=0,count=1048576):
    value=rpc.call(100003,6,opaque(handle)+struct.pack('>QI',offset,count))
    status=struct.unpack('>I',value[:4])[0]
    if status:return status,None
    start=8+(84 if value[4:8]==words(1) else 0)
    length=struct.unpack('>I',value[start+8:start+12])[0]
    return 0,value[start+12:start+12+length]

def write(rpc,handle,data,offset=0):
    return rpc.call(100003,7,opaque(handle)+struct.pack('>QII',offset,len(data),0)+opaque(data))

class Fixture:
    def __init__(self,d,large=False):
        self.d=Path(d);self.processes=[];self.commands=[];self.counts={'body_bytes':0,'requests':0};self.server=None;self.thread=None
        try:self.initialize(large)
        except BaseException:
            self.close();raise
    def initialize(self,large):
        self.tree=self.d/'tree';self.tree.mkdir();self.tree.chmod(0o755)
        (self.tree/'binary').write_bytes(bytes(range(256))*2400)
        (self.tree/'uncached').write_bytes(b'unhydrated original revision'*12000)
        for name in ['group','other','denied-other']:(self.tree/name).write_bytes(name.encode())
        for name,mode in [('run',0o755),('noexec',0o644)]:
            (self.tree/name).write_bytes(b'#!/bin/sh\nprintf \'executed\\n\'\n');(self.tree/name).chmod(mode)
        (self.tree/'partialbase').write_bytes(b'partial-base-uncached-'*400000)
        (self.tree/'empty').mkdir();(self.tree/'locked').write_bytes(b'locked')
        (self.tree/'read-dir').mkdir();(self.tree/'read-dir/child').write_bytes(b'child')
        (self.tree/'search-dir').mkdir();(self.tree/'search-dir/child').write_bytes(b'child')
        if large:
            with (self.tree/'large').open('wb') as file:
                for start in range(0,2097152,8192):file.write(b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(start,start+8192)))
        corpus(self.tree)
        self.config=self.d/'config.json'
        self.config.write_text(json.dumps({'replica':{'replica':'replica:'+'1'*32,'authorities':[{'principal':P,'uid':os.geteuid(),'primary_group':G,'gid':self.tree.stat().st_gid,'groups':[G],'dac_override':False,'ownership_transfer':True},{'principal':P2,'uid':10001,'primary_group':G2,'gid':10001,'groups':[G,G2],'dac_override':False,'ownership_transfer':False}], 'content_roots':[str(self.tree)]+[str(self.d/x) for x in ['view','ro','restart','fault','old','recovery1','recovery2','recovery3','history','fault-restart','full']],'cache_bytes':134217728},'root':str(self.tree),'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}))
        self.cli('init','source','--config',self.config)
        self.revision=self.cli('capture','source','--root',self.tree,'--operation-id','operation:'+'1'*32)['revision']
        original=self.cli('history','source')['revisions'][0]['canonical_descriptor'];(self.d/'original-revision.json').write_text(original)
        projected=json.loads(original)
        for e in projected['tree']['entries']:
            if e['path'] in ['group','other','denied-other']:
                e['owner']=P2;e['group']=G if e['path']=='group' else G2;e['mode']=0o604 if e['path']=='other' else 0o640
        canonical=json.dumps(projected,separators=(',',':'),ensure_ascii=False)
        self.original_revision=self.revision;self.revision='sha256:'+hashlib.sha256(canonical.encode()).hexdigest()
        self.manifest=self.d/'revision.json';self.manifest.write_text(canonical)
        (self.d/'fixture-projection.json').write_text(json.dumps({'original_revision':self.original_revision,'projected_revision':self.revision,'changes':'only group/other synthetic owner/group/mode; object bytes unchanged'},indent=2))
        self.online()
        self.cli('init','fullstate','--config',self.config,'--revision-manifest',self.d/'original-revision.json','--source',self.url)
        for state in ['lazy','readonly','faultstate']:
            self.cli('init',state,'--config',self.config,'--revision-manifest',self.manifest,'--source',self.url)
    def cli(self,command,state='lazy',*args,code=0):
        argv=[str(BIN),command,'--state',str(self.d/state),*map(str,args)]
        p=subprocess.run(argv,capture_output=True,text=True,timeout=60 if command=="capture" else 15)
        self.commands.append({'argv':argv,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        (self.d/'fixture-commands.json').write_text(json.dumps(self.commands,indent=2))
        assert p.returncode==code,(argv,p.returncode,p.stdout,p.stderr)
        return json.loads(p.stdout)
    def online(self):
        fixture=self
        class Source(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                name=self.path.rsplit('/',1)[-1];path=fixture.d/'source/objects'/name
                if not name.startswith('sha256:') or not path.is_file():self.send_error(404);return
                data=path.read_bytes();fixture.counts['body_bytes']+=len(data);fixture.counts['requests']+=1
                self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            def log_message(self,*args):pass
        port=getattr(self,'port',0)
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Source);self.port=self.server.server_port
        self.url='http://127.0.0.1:'+str(self.port)
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
    def offline(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.server=None
    def endpoint(self,name='view',state='lazy',mode='private',binary=None,env=None,port=None,revision=None):
        argv=[str(binary or BIN),'mount','--state',str(self.d/state),'--revision',revision or self.revision,'--mountpoint',str(self.d/name),'--mode',mode,'--prepare-only','true']
        if port is not None:argv+=['--nfs-port',str(port)]
        log=self.d/(name+'-daemon.stderr');out=self.d/(name+'-daemon.stdout')
        with log.open('w') as err:p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=err,text=True,env=env)
        self.processes.append(p)
        sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ);events=sel.select(15);sel.close()
        assert events,('endpoint readiness timeout',argv)
        line=p.stdout.readline();out.write_text(line)
        assert line,('endpoint exited before readiness',p.poll(),log.read_text())
        info=json.loads(line);assert 'port' in info,('durable macOS NFS endpoint missing',info,log.read_text())
        info['daemon_command']=argv
        return p,Rpc(info['port']),info
    def close(self):
        for p in reversed(self.processes):
            if p.poll() is None:p.terminate()
            p.communicate(timeout=10)
        if self.server:self.offline()
