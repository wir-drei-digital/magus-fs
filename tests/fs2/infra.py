"""Owned, bounded, private-network PG/S3/service fixture. No ambient credentials."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PG = 'postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c'
S3 = 'chrislusf/seaweedfs:4.48@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d'
LABEL = 'magus.fs2.owner'

class InfrastructureUnavailable(Exception):
    pass

def classify_docker(code, output):
    if code == 0 and 'linux' in output:
        return 0
    if any(s in output.lower() for s in ('cannot connect', 'permission denied', 'no such file', 'not found', 'is the docker daemon')):
        return 2
    return 1

class OwnedInfra:
    def __init__(self, output):
        self.output = Path(output)
        if not self.output.is_absolute():
            raise ValueError('absolute new output required')
        self.output.mkdir(mode=0o700)
        self.control = self.output / 'control'
        self.control.mkdir(mode=0o700)
        self.owner = 'fs2-' + secrets.token_hex(8)
        self.resources = []
        self.commands = []
        self.save()

    def save(self):
        self.write_json('ownership.json', {'owner':self.owner, 'resources':self.resources})
        self.write_json('commands.json', self.commands)

    def write_json(self, name, value):
        (self.output/name).write_text(json.dumps(value, indent=2)+'\n')

    def private(self, name, value):
        p = self.control/name
        fd = os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(value if isinstance(value, str) else json.dumps(value))
        return p

    def run(self, argv, timeout=120, input=None, check=True, evidence=True):
        start = time.monotonic()
        try:
            p = subprocess.run(argv, cwd=ROOT, input=input, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            def decoded(value):
                return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
            p = subprocess.CompletedProcess(argv,124,decoded(e.stdout),decoded(e.stderr)+'\nfixture command deadline exceeded')
        if evidence:
            index = len(self.commands)
            (self.output/f'command-{index}.log').write_text(p.stdout+p.stderr)
            self.commands.append({'argv':argv, 'status':p.returncode, 'seconds':time.monotonic()-start, 'log':f'command-{index}.log'})
            self.save()
        if check and p.returncode:
            raise RuntimeError(f'command failed ({p.returncode}): {argv[0:3]}')
        return p

    def docker(self, *args, **kw):
        return self.run(['docker', *args], **kw)

    def preflight(self):
        for command in ('docker','cargo','rustc','openssl'):
            if shutil.which(command) is None:
                raise InfrastructureUnavailable(command+' missing')
        try:
            p = self.docker('version', '--format', '{{.Server.Os}} {{.Server.Version}}', check=False)
        except FileNotFoundError as e:
            raise InfrastructureUnavailable('docker missing') from e
        classification = classify_docker(p.returncode, p.stdout+p.stderr)
        if classification == 2:
            raise InfrastructureUnavailable('docker unavailable')
        if classification:
            raise RuntimeError('Docker returned unexpected server response')
        self.run(['openssl','version'])

    def create(self, kind, suffix, args):
        name = self.owner+'-'+suffix
        row = {'kind':kind, 'name':name, 'id':None}
        self.resources.append(row)
        self.save()  # ownership intent precedes creation, recoverable after interruption
        if kind == 'container':
            command = ['create','--name',name,'--label',LABEL+'='+self.owner,*args]
        else:
            command = [kind,'create','--label',LABEL+'='+self.owner,*args,name]
        p = self.docker(*command)
        row['id'] = p.stdout.strip()
        self.save()
        return name

    def inspect(self, kind, name):
        return json.loads(self.docker(kind,'inspect',name, evidence=False).stdout)[0]

    def validate_owned(self, row, data):
        labels = data.get('Config',{}).get('Labels',{}) if row['kind']=='container' else data.get('Labels',{})
        identity = data.get('Id', data.get('Name'))
        if labels.get(LABEL)!=self.owner or (row['id'] and identity!=row['id']):
            raise ValueError('resource ownership mismatch; retained')

    def remove(self, kind, name):
        row = next((r for r in self.resources if r['kind']==kind and r['name']==name), None)
        if row is None:
            raise ValueError('unrecorded resource')
        probe = self.docker(kind,'inspect',name, check=False, evidence=False)
        if probe.returncode:
            # Absence is only accepted when a successful list confirms it.
            existing = self.docker(kind,'ls','--format','{{.Name}}' if kind!='container' else '{{.Names}}', *(['-a'] if kind=='container' else [])).stdout.splitlines()
            if name in existing:
                raise RuntimeError('inspect failed for existing resource')
            row['removed']=True
            self.save()
            return
        self.validate_owned(row, json.loads(probe.stdout)[0])
        if kind == 'container':
            self.docker('stop','--time','5',name)
        self.docker(kind,'rm',name)
        row['removed']=True
        self.save()

    def cleanup(self):
        errors=[]
        for row in reversed(self.resources):
            if not row.get('removed'):
                try:
                    self.remove(row['kind'],row['name'])
                except Exception as e:
                    errors.append(type(e).__name__+': '+str(e))
        self.write_json('cleanup.json', {'ok':not errors,'errors':errors,'resources':self.resources})
        if errors:
            raise RuntimeError('owned cleanup incomplete')

    def setup(self, image):
        self.preflight()
        self.net=self.create('network','net',['--internal'])
        self.ingress=self.create('network','ingress',[])
        self.pgvol=self.create('volume','pg',[])
        self.s3vol=self.create('volume','s3',[])
        pgpass=secrets.token_hex(32)
        self.access=secrets.token_hex(16)
        self.secret=secrets.token_hex(32)
        self.private('pg-password',pgpass)
        self.private('s3.json',{'identities':[{'name':'fixture','credentials':[{'accessKey':self.access,'secretKey':self.secret}],'actions':['Admin','Read','Write','List','Tagging']}]})
        self.private('s3-client.json',{'access':self.access,'secret':self.secret})
        self.pg=self.create('container','pg',['--network',self.net,'--network-alias','pg','--memory','512m','--cpus','2','--pids-limit','256','-e','POSTGRES_PASSWORD_FILE=/control/pg-password','-v',str(self.control)+':/control:ro','-v',self.pgvol+':/var/lib/postgresql',PG,'-c','fsync=on','-c','full_page_writes=on','-c','synchronous_commit=on'])
        self.s3=self.create('container','s3',['--network',self.net,'--network-alias','s3','--memory','1g','--cpus','2','--pids-limit','256','-v',str(self.control)+':/control:ro','-v',self.s3vol+':/data',S3,'server','-master.resumeState=true','-master.telemetry=false','-dir=/data','-ip=s3','-ip.bind=0.0.0.0','-volume.max=1','-master.volumeSizeLimitMB=1024','-filer','-s3','-s3.config=/control/s3.json'])
        self.docker('start',self.pg,self.s3)
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            if self.docker('exec',self.pg,'pg_isready','-U','postgres',check=False,evidence=False).returncode==0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('PG readiness timeout')
        self.certificates()
        config={'listen':'0.0.0.0:8443','database':f'host=pg user=postgres password={pgpass} dbname=postgres connect_timeout=2 options=\'-c statement_timeout=2000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=5000\'','s3_endpoint':'http://s3:8333','s3_bucket':'fs2','s3_access_key':self.access,'s3_secret_key':self.secret,'private_backend_http':True,'tls_cert':'/control/server.crt','tls_key':'/control/server.key'}
        self.private('service.json',config)
        self.service=self.create('container','service',['--network',self.ingress,'--network-alias','service','--memory','512m','--cpus','2','--pids-limit','256','-p','127.0.0.1::8443','-v',str(self.control)+':/control:ro',image,'sleep','infinity'])
        self.docker('network','connect','--alias','service',self.net,self.service)
        self.docker('start',self.service)
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            p=self.s3_request('PUT','/fs2',check=False)
            if p.returncode==0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError('S3 readiness timeout')
        self.provenance()

    def certificates(self):
        d=str(self.control)
        for prefix,cn in [('ca','Fixture CA'),('wrong-ca','Wrong CA')]:
            self.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',f'{d}/{prefix}.key','-out',f'{d}/{prefix}.crt','-subj',f'/CN={cn}','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
        self.run(['openssl','req','-newkey','rsa:2048','-nodes','-keyout',d+'/server.key','-out',d+'/server.csr','-subj','/CN=service'])
        self.private('extensions','subjectAltName=DNS:service,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n')
        self.run(['openssl','x509','-req','-in',d+'/server.csr','-CA',d+'/ca.crt','-CAkey',d+'/ca.key','-CAcreateserial','-days','2','-extfile',d+'/extensions','-out',d+'/server.crt'])
        for path in self.control.iterdir():
            path.chmod(0o600)

    def sql(self, sql):
        return self.docker('exec','-i',self.pg,'psql','-X','-q','-A','-t','-U','postgres',input=sql, evidence=False).stdout.strip()

    def s3_request(self, method, path, body='', check=True, anonymous=False):
        p=self.docker('exec','-i',self.service,'timeout','8','python3','/src/tests/fs2/s3_probe.py',method,path,*(['--anonymous'] if anonymous else []),input=body,check=False,evidence=False,timeout=10)
        if not hasattr(self,'s3_probes'):
            self.s3_probes=[]
        self.s3_probes.append({'method':method,'path':path,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        self.write_json('s3-probes.json',self.s3_probes)
        if check and p.returncode:
            raise RuntimeError('independent S3 probe failed; see s3-probes.json')
        return p

    def wait_s3(self, label, require_volumes=False):
        if require_volumes and not getattr(self, 'expected_volumes', []):
            raise ValueError('persisted volume IDs required before acknowledged-content restart')
        attempts=[];start=time.monotonic()
        while time.monotonic()-start<30:
            p=self.s3_request('HEAD','/fs2',check=False)
            attempts.append({'seconds':time.monotonic()-start,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
            self.write_json(label+'-s3-readiness.json',attempts)
            if p.returncode==0:
                registered=[]
                for volume in getattr(self,'expected_volumes',[]):
                    state=self.backend_http(9333,'/dir/lookup?volumeId='+str(volume))
                    registered.append({'volume':volume,'response':state})
                attempts[-1]['registered']=registered
                self.write_json(label+'-s3-readiness.json',attempts)
                if all(r['response']['status']==200 and r['response']['body'].get('locations') for r in registered):
                    return
            time.sleep(.25)
        raise RuntimeError('S3 restart readiness timeout')

    def backend_http(self,port,path):
        script="import http.client,json,sys; c=http.client.HTTPConnection('s3',int(sys.argv[1]),timeout=3);c.request('GET',sys.argv[2]);r=c.getresponse();print(json.dumps({'status':r.status,'body':json.loads(r.read())}))"
        p=self.docker('exec',self.service,'timeout','5','python3','-c',script,str(port),path,timeout=8,evidence=False)
        return json.loads(p.stdout)

    def snapshot_volumes(self):
        state=self.backend_http(8080,'/status')
        assert state['status']==200
        self.expected_volumes=[v['Id'] for v in state['body']['Volumes']]
        assert len(self.expected_volumes)==1
        self.write_json('persistent-volumes-before-restart.json',state)

    def provision(self, records):
        name='provision-'+secrets.token_hex(4)+'.json'
        self.private(name,records)
        return self.docker('exec',self.service,'magus-fs-service','provision','/control/service.json','/control/'+name)

    def start_service(self, faults=False):
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if self.docker('exec',self.pg,'pg_isready','-U','postgres',check=False,evidence=False).returncode==0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('PG restart readiness timeout')
        binary='magus-fs-service-faults' if faults else 'magus-fs-service'
        self.docker('exec','-d','-e','HTTP_PROXY=http://127.0.0.1:1','-e','HTTPS_PROXY=http://127.0.0.1:1','-e','ALL_PROXY=http://127.0.0.1:1',self.service,'sh','-c','echo $$ > /tmp/service.pid; exec '+binary+' serve /control/service.json > /tmp/service.log 2>&1')
        port=self.docker('port',self.service,'8443/tcp').stdout.strip().split(':')[-1]
        self.port=int(port)

    def restart_service(self, faults=False):
        self.docker('restart','--time','5',self.service)
        self.start_service(faults)

    def provenance(self):
        records={}
        for kind,name in [('container',self.pg),('container',self.s3),('container',self.service)]:
            x=self.inspect(kind,name)
            # Env contains only password FILE name, never credential values.
            records[name]={'image':x['Image'],'config':x['Config'],'mounts':x['Mounts'],'host_config':x['HostConfig'],'network':x['NetworkSettings']}
            if name in (self.pg,self.s3):
                assert not x['HostConfig']['PortBindings']
                assert set(x['NetworkSettings']['Networks'])=={self.net}
            else:
                assert set(x['NetworkSettings']['Networks'])=={self.net,self.ingress}
                assert x['NetworkSettings']['Ports']['8443/tcp'][0]['HostIp']=='127.0.0.1'
        records['pg_settings']=self.sql("SELECT name||'='||setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit','data_directory','server_version');")
        records['config_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.control.iterdir() if p.is_file()}
        for ref in [PG,S3]:
            records[ref]=json.loads(self.docker('image','inspect',ref).stdout)
        self.write_json('backends.json',records)
