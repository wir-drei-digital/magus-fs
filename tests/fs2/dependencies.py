#!/usr/bin/env python3
"""Task4 real dependency publication gate. Missing enforcement must fail this gate."""
import copy, json, secrets, time
from reconciliation import Reconciliation
from service_protocol import identity, file_entry, GROUP, REPLICA
from service_storage import NS, ALICE

class Dependencies(Reconciliation):
    def setup_dependencies(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        self.warm_storage()
        data=b'amount\n10\n20\n'
        entries=[file_entry('input.csv',self.tree_root['id'],data),file_entry('report.txt',self.tree_root['id'],b'30\n')]
        upload,rid=self.stage(self.descriptor(entries),bodies=[data,b'30\n'])
        self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
    def report_candidate(self,body=b'30\n'):
        view,r=self.view();original=copy.deepcopy(r)
        next(e for e in r['tree']['entries'] if e['path']=='report.txt')['content']=file_entry('x',self.tree_root['id'],body)['content']
        _,receipt=self.candidate(view,r,'alice',[body]);self.output_revisions=getattr(self,'output_revisions',{});self.output_revisions[receipt['receipt']]=copy.deepcopy(r);return view,original,receipt
    def declaration(self,view,r,receipt,coverage='complete_declared',missing=None,validator=None):
        request={'operation':identity('operation'),'replica':REPLICA,'candidate':receipt['receipt'],'reads':[{'view':view['view'],'revision':view['revision'],'entry':next(e['id'] for e in r['tree']['entries'] if e['path']=='input.csv')}], 'missing':missing or [],'coverage':coverage,'validator':validator}
        self.declared=getattr(self,'declared',{});self.declared[receipt['receipt']]=request;return request
    def run(self):
        self.setup_dependencies()
        view,r,private=self.report_candidate()
        request=self.declaration(view,r,private)
        declaration=self.expect('declare-stale-report','POST',self.root+'/declarations',200,body=request)
        self.set_file('input.csv',b'amount\n10\n25\n','ordinary-csv-update')
        self.expect('unchanged-report-stale-input-held','POST',self.root+'/integrations',409,{'code':'dependency_changed'},body=self.integrate_request(private,{'head':self.head()}))
        self.expect('declare-exact-replay-after-input-head-change','POST',self.root+'/declarations',200,declaration,body=request)
        self.expect('declare-digest-mismatch','POST',self.root+'/declarations',409,body=dict(request,coverage='partial'))
        self.record('service','stale-input-held',declaration=declaration,private=private)
        self.missing_and_coverage()
        self.cross_branch_missing()
    def missing_and_coverage(self):
        view,r,private=self.report_candidate(b'35\n')
        assertion={'view':view['view'],'revision':view['revision'],'path':'optional.csv'}
        request=self.declaration(view,r,private,missing=[assertion])
        dec=self.expect('declare-missing','POST',self.root+'/declarations',200,body=request)
        self.set_file('optional.csv',b'appeared','missing-now-appears')
        self.expect('appeared-input-held','POST',self.root+'/integrations',409,{'code':'dependency_changed'},body=self.integrate_request(private,{'head':self.head()}))
        self.expect('missing-result-replay-after-appearance','POST',self.root+'/declarations',200,dec,body=request)
        for coverage in ['partial','unknown']:
            view,r,private=self.report_candidate(b'35\n')
            request=self.declaration(view,r,private,coverage)
            self.expect('declare-'+coverage,'POST',self.root+'/declarations',200,body=request)
            self.expect('optional-'+coverage+'-allowed','POST',self.root+'/integrations',200,body=self.integrate_request(private,view))
        view,r,private=self.report_candidate(b'35\n')
        req=self.declaration(view,r,private)
        forged=copy.deepcopy(req);forged['reads'][0]['entry']=identity('entry')
        self.expect('forged-input-denied','POST',self.root+'/declarations',404,body=forged)
        forged=copy.deepcopy(req);forged['reads'][0]['revision']='sha256:'+'0'*64
        self.expect('forged-input-revision-denied','POST',self.root+'/declarations',404,body=forged)
        forged=copy.deepcopy(req);forged['missing']=[{'view':view['view'],'revision':view['revision'],'path':'../outside'}]
        self.expect('unnormalized-missing-denied','POST',self.root+'/declarations',400,body=forged)
        self.record('service','missing-coverage-forged-input',coverage=['partial','unknown'])
    def cross_branch_missing(self):
        # Identical absent paths in distinct views must retain their own branch binding.
        self.tokens['cross']=secrets.token_hex(32)
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':self.tokens['cross'],'expires':int(time.time())+600,'actions':['admin','read','write','integrate','history'],'branches':['main','other'],'prefixes':['']}])
        up,rid=self.stage(self.descriptor([]),'cross')
        self.expect('seed-other','POST',self.root+'/seed',200,actor='cross',body={'branch':'other','revision':rid,'upload':up})
        main,mr=self.view('cross')
        other=self.expect('other-view','POST',self.root+'/views',200,actor='cross',body={'branch':'other'})
        ort=self.expect('other-descriptor','GET',self.root+'/views/'+other['view']+'/descriptor',200,actor='cross')
        _,private=self.candidate(main,mr,'cross')
        request=self.declaration(main,mr,private,missing=[{'view':v['view'],'revision':v['revision'],'path':'same-absent.csv'} for v in [main,other]])
        self.expect('declare-two-branch-missing','POST',self.root+'/declarations',200,actor='cross',body=request)
        ort['tree']['entries'].append(file_entry('same-absent.csv',self.tree_root['id'],b'appeared'))
        _,appeared=self.candidate(other,ort,'cross',[b'appeared'])
        self.expect('publish-other-appearance','POST',self.root+'/integrations',200,actor='cross',body=dict(self.integrate_request(appeared,other),branch='other'))
        self.expect('second-branch-missing-held','POST',self.root+'/integrations',409,{'code':'dependency_changed'},actor='cross',body=self.integrate_request(private,main))
        self.record('service','cross-branch-missing-predicates',private=private)
    def configured(self):
        from pathlib import Path
        from infra import ROOT
        self.i.docker('build','-t',self.i.owner+'-validator','tests/fs2/validator',timeout=600)
        image=self.i.docker('image','inspect','--format','{{.Id}}',self.i.owner+'-validator').stdout.strip()
        executable='sha256:'+__import__('hashlib').sha256((ROOT/'tests/fs2/validator/csv_validator.py').read_bytes()).hexdigest()
        self.worker='principal:'+'d'*32;self.worker_replica='replica:'+'d'*32;self.tokens['validator']=secrets.token_hex(32)
        self.policy={'branch':'main','validator':'integer-csv','version':'1','executable_hash':executable,'image_digest':image,'worker_principal':self.worker,'worker_replica':self.worker_replica,'output_paths':['report.txt']}
        self.i.provision([{'namespace':NS,'principal':self.worker,'replica':self.worker_replica,'token':self.tokens['validator'],'expires':int(time.time())+3600,'actions':['validate'],'branches':['main'],'prefixes':[''],'validator_policy':self.policy}])
        self.i.write_json('validator-identity.json',self.policy)
        for coverage in [None,'unknown','partial']:
            view,r,private=self.report_candidate(b'wrong\n')
            if coverage:
                req=self.declaration(view,r,private,coverage,validator='integer-csv')
                self.expect('declare-required-'+coverage,'POST',self.root+'/declarations',200,body=req)
            self.expect('required-'+str(coverage)+'-held','POST',self.root+'/integrations',409,{'code':'recompute_required'},body=self.integrate_request(private,view))
        view,r,private=self.report_candidate(b'35\n')
        req=self.declaration(view,r,private,validator='integer-csv')
        dec=self.expect('declare-validated','POST',self.root+'/declarations',200,body=req)
        record=self.validation_record(view,private,dec)
        self.expect('ordinary-caller-cannot-forge-pass','POST',self.root+'/validations',404,body=record)
        self.expect('worker-cannot-publish','POST',self.root+'/integrations',404,actor='validator',body=self.integrate_request(private,view))
        self.expect('worker-cannot-upload','POST',self.root+'/uploads',404,actor='validator',body={})
        self.expect('forged-executable-denied','POST',self.root+'/validations',404,actor='validator',body=dict(record,executable_hash='sha256:'+'0'*64))
        for outcome in ['fail','timeout']:
            raw=self.expect('record-'+outcome,'POST',self.root+'/validations',200,actor='validator',body=dict(record,operation=identity('operation'),outcome=outcome))
            self.expect('nonpass-held','POST',self.root+'/validated-integrations',409,{'code':'recompute_required'},body={'integration':self.integrate_request(private,view),'declaration':dec['id'],'validation':raw})
        result=self.worker_run(view,r,b'35\n',private);assert result['outcome']=='pass',result
        validation=self.expect('record-pass','POST',self.root+'/validations',200,actor='validator',body=record)
        self.set_file('input.csv',b'amount\n10\n30\n','csv-alone-allowed-under-policy')
        self.expect('stale-record-replay','POST',self.root+'/validations',200,validation,actor='validator',body=record)
        stale=self.expect('raw-stale-pass-retained','POST',self.root+'/validations',200,actor='validator',body=dict(record,operation=identity('operation')))
        self.expect('stale-pass-cannot-publish','POST',self.root+'/validated-integrations',409,{'code':'dependency_changed'},body={'integration':self.integrate_request(private,{'head':self.head()}),'declaration':dec['id'],'validation':stale})
        # Candidate modifies its declared input and output together; even a trusted pass
        # over the old published view must not authorize the proposed final state.
        view,r=self.view();original=copy.deepcopy(r)
        next(e for e in r['tree']['entries'] if e['path']=='input.csv')['content']=file_entry('x',self.tree_root['id'],b'amount\n999\n')['content']
        next(e for e in r['tree']['entries'] if e['path']=='report.txt')['content']=file_entry('x',self.tree_root['id'],b'40\n')['content']
        _,combined=self.candidate(view,r,'alice',[b'amount\n999\n',b'40\n'])
        d=self.expect('declare-combined','POST',self.root+'/declarations',200,body=self.declaration(view,original,combined,validator='integer-csv'))
        v=self.expect('record-combined-old-input-pass','POST',self.root+'/validations',200,actor='validator',body=self.validation_record(view,combined,d))
        self.expect('combined-input-output-held','POST',self.root+'/validated-integrations',409,{'code':'dependency_changed'},body={'integration':self.integrate_request(combined,view),'declaration':d['id'],'validation':v})
        # Fresh result, immutable publication replay after a later input change.
        view,r,private=self.report_candidate(b'40\n')
        request=self.declaration(view,r,private,validator='integer-csv')
        d=self.expect('declare-fresh','POST',self.root+'/declarations',200,body=request)
        assert self.worker_run(view,r,b'40\n',private)['outcome']=='pass'
        record=self.validation_record(view,private,d);v=self.expect('record-fresh','POST',self.root+'/validations',200,actor='validator',body=record)
        integration=self.integrate_request(private,view)
        shared=self.expect('old-route-enforces-and-accepts-validation','POST',self.root+'/integrations',200,body=integration)
        self.set_file('input.csv',b'amount\n11\n30\n','post-result-input-change')
        self.expect('committed-exact-replay-after-input-change','POST',self.root+'/integrations',200,shared,body=integration)
        self.expect('committed-digest-change-denied','POST',self.root+'/integrations',409,body=dict(integration,expected_head=self.head()))
        self.record('service','configured-validation',policy=self.policy,raw_stale=stale,exact_shared=shared)
    def validation_record(self,view,private,declaration):
        return {'operation':identity('operation'),'replica':self.worker_replica,'declaration':declaration['id'],'expected_head':view['head'],'validator':self.policy['validator'],'version':self.policy['version'],'executable_hash':self.policy['executable_hash'],'inputs':view,'output':private['receipt'],'outcome':'pass'}
    def worker_run(self,view,r,report,receipt):
        from validation_worker import run,verify_snapshot
        snapshot=self.i.output/('snapshot-'+secrets.token_hex(4));snapshot.mkdir(mode=0o700)
        e=next(e for e in r['tree']['entries'] if e['path']=='input.csv')
        data=self.body(view,e)
        verify_snapshot(view,r,self.output_revisions[receipt['receipt']],receipt,self.declared[receipt['receipt']],data,report)
        (snapshot/'input.csv').write_bytes(data);(snapshot/'report.txt').write_bytes(report)
        return run(self.i,self.policy['image_digest'],snapshot,self.i.output/('worker-output-'+secrets.token_hex(4)),self.policy['executable_hash'])
    def confinement(self):
        from validation_worker import run
        checks={
            'blocked':'''import socket,json
from pathlib import Path
r={}
try:
 socket.create_connection(('1.1.1.1',53),1)
 r['network']=False
except OSError:r['network']=True
try:
 Path('/input/input.csv').write_text('mutated')
 r['input_write']=False
except OSError:r['input_write']=True
r['host']=not Path('/Users/daniel').exists() and not Path('/control').exists() and not Path('/var/run/docker.sock').exists()
assert all(r.values()),r
print(json.dumps(r))
''',
            'timeout':'import time\ntime.sleep(90)\n',
            'bounds':"import os\nos.write(1,b'x'*2097152)\n",
        }
        results={}
        for name,script in checks.items():
            context=self.i.output/('probe-'+name);context.mkdir();(context/'probe.py').write_text(script)
            assert self.i.docker('image','inspect','--format','{{.Id}}',self.i.owner+'-validator').stdout.strip()==self.policy['image_digest']
            (context/'Dockerfile').write_text('FROM '+self.i.owner+'-validator'+'\nCOPY probe.py /validator.py\n')
            tag=self.i.owner+'-probe-'+name;self.i.docker('build','-t',tag,str(context),timeout=600)
            image=self.i.docker('image','inspect','--format','{{.Id}}',tag).stdout.strip()
            snapshot=self.i.output/('probe-input-'+name);snapshot.mkdir();(snapshot/'input.csv').write_bytes(b'amount\n1\n');(snapshot/'report.txt').write_bytes(b'1\n')
            result=run(self.i,image,snapshot,self.i.output/('probe-output-'+name),'sha256:'+__import__('hashlib').sha256(script.encode()).hexdigest());results[name]={k:v for k,v in result.items() if k!='launch' and k!='stdout'}
            if name=='blocked':assert result['outcome']=='pass' and json.loads(result['stdout'])=={'network':True,'input_write':True,'host':True}
            if name=='timeout':assert result['outcome']=='timeout' and 30<=result['seconds']<40
            if name=='bounds':assert result['bounded'] and result['outcome']=='fail' and result['result_bytes']==1048576
        self.record('worker','real-confinement-deadline-result-bound',results=results)
    def mounted_report(self):
        from connected import Lazy
        from full_native import Endpoint
        self.lazy=Lazy(self,'dependency-mount');l=self.lazy;l.start('reporter')
        ep=Endpoint(self,'macos',self.image);self.endpoints.append(ep);mac=ep.create('observer');ep.start(mac);self.until(lambda:ep.ready(mac))
        before=l.status('reporter');view=before['status']['binding']['view']
        r=self.expect('mounted-pinned-input-descriptor','GET',self.root+'/views/'+view['view']+'/descriptor',200)
        prior={p['operation'] for p in before['status']['submissions']}
        script="import csv,time,os\nvalues=[int(r['amount']) for r in csv.DictReader(open('/shared/reporter/input.csv'))]\nopen('/tmp/report-read','w').write(str(sum(values)))\nwhile not os.path.exists('/tmp/report-resume'):time.sleep(.02)\nwith open('/shared/reporter/report.txt','w') as f:f.write(str(sum(values))+'\\n');f.flush();os.fsync(f.fileno())\nopen('/tmp/report-done','w').close()"
        pid=l.execute("import subprocess,json,sys;p=subprocess.Popen(['python3','-c',json.load(sys.stdin)],stdout=open('/tmp/report-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",script,user='1001:1001')
        self.i.write_json('dependency-workload.json',{'container':l.daemon,'pid':pid,'uid':1001,'script':script})
        self.until(lambda:l.execute("import os,json;print(json.dumps(os.path.exists('/tmp/report-read')))"),10)
        self.set_file('input.csv',b'amount\n12\n30\n','csv-while-report-paused')
        self.until(lambda:l.read('reporter/input.csv')==b'amount\n12\n30\n'.hex(),15)
        l.execute("open('/tmp/report-resume','w').close();print('{}')",user='1001:1001')
        self.until(lambda:l.execute("import os,json;print(json.dumps(os.path.exists('/tmp/report-done')))"),10)
        def held():return next((p for p in l.status('reporter')['status']['submissions'] if p['operation'] not in prior and p['private_receipt'] and p['error']=='recompute_required'),None)
        stale=self.until(held,30)
        assert not stale['shared_receipt'] and l.read('reporter/report.txt')==b'41\n'.hex()
        request=self.declaration(view,r,stale['private_receipt'],validator='integer-csv')
        declared=l.cli('sync','declare','--state','/private/reporter/state','--request',json.dumps(request))
        assert declared['ok'],declared
        retry=l.cli('sync','integrate','--state','/private/reporter/state','--revision',stale['local_revision'],'--expected-head',self.head())
        assert retry['progress']['error']=='dependency_changed' and retry['progress']['private_receipt']==stale['private_receipt'],retry
        shared_view,files,_=self.tree();assert self.body(shared_view,files['report.txt'])==b'40\n'
        assert bytes.fromhex(ep.read(mac,'report.txt'))==b'40\n'
        # Read pinned current input through normal mounted Python, then create a fresh output
        # candidate; no candidate request/digest or original private receipt is rewritten.
        current_view,current=self.view();known={p['operation'] for p in l.status('reporter')['status']['submissions']}
        l.execute("import csv,os\nvalues=[int(r['amount']) for r in csv.DictReader(open('/shared/reporter/input.csv'))]\nwith open('/shared/reporter/report.txt','w') as f:f.write(str(sum(values))+'\\n');f.flush();os.fsync(f.fileno())\nprint('{}')",user='1001:1001')
        fresh=self.until(lambda:next((p for p in l.status('reporter')['status']['submissions'] if p['operation'] not in known and p['private_receipt'] and p['error']=='recompute_required'),None),30)
        request=self.declaration(current_view,current,fresh['private_receipt'],validator='integer-csv')
        declared=l.cli('sync','declare','--state','/private/reporter/state','--request',json.dumps(request))
        history=l.cli('history','--state','/private/reporter/state')
        self.output_revisions[fresh['private_receipt']['receipt']]=next(x['descriptor'] for x in history['revisions'] if x['revision']==fresh['local_revision'])
        result=self.worker_run(current_view,current,b'42\n',fresh['private_receipt']);assert result['outcome']=='pass'
        v=self.expect('mounted-fresh-validation','POST',self.root+'/validations',200,actor='validator',body=self.validation_record(current_view,fresh['private_receipt'],declared['declaration']))
        integrated=l.cli('sync','integrate','--state','/private/reporter/state','--revision',fresh['local_revision'],'--expected-head',self.head())
        assert integrated['progress']['shared_receipt'],integrated
        head=integrated['progress']['shared_receipt']['head']
        self.until(lambda:ep.ready(mac,head) and ep.read(mac,'report.txt')==b'42\n'.hex(),15)
        self.until(lambda:l.status('reporter')['live']['applied'] and l.status('reporter')['status']['binding']['view']['head']==head,20)
        self.record('both','paused-mounted-report-recompute-validate-visible',original_view=view,stale=stale,retry=retry,fresh=fresh,validation=v,integrated=integrated,expected_report_hex=b'42\n'.hex(),mac=ep.status(mac),mounted=l.status('reporter'))
    def cleanup(self):
        if hasattr(self,'lazy'):self.lazy.cleanup()
        super().cleanup()
    def publication_routes_and_races(self):
        import concurrent.futures
        # Direct restore is an effect without a candidate: protected output holds.
        view,r=self.view()
        page=self.expect('history-for-protected-restore','GET',self.root+'/history?view='+view['view'],200)
        report=next(e for e in r['tree']['entries'] if e['path']=='report.txt')
        history=next(x for x in page['items'] if x['entry']==report['id'])
        restore={'operation':identity('operation'),'replica':REPLICA,'history':history['id'],'expected_head':view['head'],'restore_metadata':False}
        # Select a historical report differing from the current value, if page starts current.
        for item in page['items']:
            if item['entry']!=report['id']:continue
            bound=self.expect('protected-history-pin','POST',self.root+'/history/'+item['id']+'/view',200,body={})
            old=self.expect('protected-history-descriptor','GET',self.root+'/views/'+bound['view']+'/descriptor',200)
            if next(e for e in old['tree']['entries'] if e['id']==report['id'])['content']!=report['content']:
                restore['history']=item['id'];break
        self.expect('protected-restore-held','POST',self.root+'/restores',409,{'code':'recompute_required'},body=restore)
        # Replacement resolution includes a protected output; central enforcement applies.
        self.set_file('conflict.bin',b'base','resolution-seed')
        view,r=self.view();next(e for e in r['tree']['entries'] if e['path']=='conflict.bin')['content']=file_entry('x',self.tree_root['id'],b'left')['content']
        _,left=self.candidate(view,r,'alice',[b'left'])
        self.set_file('conflict.bin',b'right','resolution-right')
        conflicts=self.expect('retain-resolution-conflict','POST',self.root+'/integrations',409,body=self.integrate_request(left,{'head':self.head()}))
        view,r=self.view()
        next(e for e in r['tree']['entries'] if e['path']=='report.txt')['content']=file_entry('x',self.tree_root['id'],b'forged')['content']
        _,replacement=self.candidate(view,r,'alice',[b'forged'])
        self.expect('resolution-protected-output-held','POST',self.root+'/resolutions',409,{'code':'recompute_required'},body={'operation':identity('operation'),'replica':REPLICA,'conflicts':conflicts['conflicts'],'expected_head':view['head'],'replacement':replacement['receipt']})
        # A valid pass at old head becomes ineligible even when its inputs did not change.
        view,r,private=self.report_candidate(b'42\n')
        dec=self.expect('declare-head-race','POST',self.root+'/declarations',200,body=self.declaration(view,r,private,validator='integer-csv'))
        record=self.validation_record(view,private,dec)
        validation=self.expect('head-race-pass','POST',self.root+'/validations',200,actor='validator',body=record)
        self.set_file('unrelated.txt',b'advance','head-only-advance')
        self.expect('stale-head-validation-held','POST',self.root+'/validated-integrations',409,{'code':'recompute_required'},body={'integration':self.integrate_request(private,{'head':self.head()}),'declaration':dec['id'],'validation':validation})
        # Pause after snapshot/merge, change required policy through trusted provision,
        # and prove the current policy wins the actual transaction, not the old pass.
        view,r,private=self.report_candidate(b'42\n')
        dec=self.expect('declare-policy-race','POST',self.root+'/declarations',200,body=self.declaration(view,r,private,validator='integer-csv'))
        record=self.validation_record(view,private,dec)
        validation=self.expect('policy-race-pass','POST',self.root+'/validations',200,actor='validator',body=record)
        self.stop_service();self.start_service(True)
        self.i.private('pause-integration','pause')
        self.i.docker('exec',self.i.service,'rm','-f','/tmp/fs2-integration-barrier')
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future=pool.submit(self.request,'POST',self.root+'/integrations',body=self.integrate_request(private,view))
            self.until(lambda:self.i.docker('exec',self.i.service,'test','-f','/tmp/fs2-integration-barrier',check=False,evidence=False).returncode==0,10)
            changed=dict(self.policy,version='2')
            self.i.provision([{'namespace':NS,'principal':self.worker,'replica':self.worker_replica,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['validate'],'branches':['main'],'prefixes':[''],'validator_policy':changed}])
            (self.i.control/'pause-integration').unlink()
            actual=future.result(timeout=15)
        assert actual==(409,{'code':'recompute_required'}),actual
        self.expect('old-result-replay-after-policy-change','POST',self.root+'/validations',200,validation,actor='validator',body=record)
        self.policy=changed
        self.record('service','publication-route-and-policy-races',protected_restore=restore,resolution=conflicts,policy_race=actual,old_validation=validation)
    def scoped_and_revoke(self):
        # Typed request bounds and one immutable declaration/candidate.
        view,r,private=self.report_candidate(b'42\n');request=self.declaration(view,r,private)
        over=copy.deepcopy(request);over['reads']*=129
        self.expect('observation-count-limit','POST',self.root+'/declarations',413,body=over)
        self.expect('control-body-limit','POST',self.root+'/declarations',413,raw=b' '*65537)
        first=self.expect('single-declaration','POST',self.root+'/declarations',200,body=request)
        self.expect('second-declaration-denied','POST',self.root+'/declarations',409,body=dict(request,operation=identity('operation')))
        # Exact output-only scope cannot forge a reference to an input it cannot read.
        replica=identity('replica');_,grant=self.request('POST',self.root+'/grants',body={'delegate':{'replica':replica,'expires':int(time.time())+600,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['report.txt']}})
        self.tokens['scoped']=grant['token'];sv,sr=self.view('scoped');sr['principal']=ALICE
        req,sp=self.submit('scoped',replica,sv,sr,[])
        d=self.declaration(view,r,sp);d['replica']=replica
        self.expect('out-of-scope-input-denied','POST',self.root+'/declarations',404,actor='scoped',body=d)
        # Revocation wins for declarations and a previously recorded validation result.
        replica=identity('replica');_,grant=self.request('POST',self.root+'/grants',body={'delegate':{'replica':replica,'expires':int(time.time())+600,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['']}})
        self.tokens['scoped']=grant['token'];sv,sr=self.view('scoped');original=copy.deepcopy(sr);sr['principal']=ALICE
        req,sp=self.submit('scoped',replica,sv,sr,[])
        d=self.declaration(sv,original,sp,validator='integer-csv');d['replica']=replica
        declared=self.expect('revocable-declaration','POST',self.root+'/declarations',200,actor='scoped',body=d)
        record=self.validation_record(sv,sp,declared)
        validation=self.expect('revocable-validation','POST',self.root+'/validations',200,actor='validator',body=record)
        self.expect('validation-digest-mismatch','POST',self.root+'/validations',409,actor='validator',body=dict(record,outcome='fail'))
        self.expect('revoke-declaration-submitter','POST',self.root+'/grants',200,body={'revoke':grant['credential']})
        self.expect('revoked-declaration-replay-denied','POST',self.root+'/declarations',401,actor='scoped',body=d)
        self.expect('revoked-publication-denied','POST',self.root+'/integrations',401,actor='scoped',body=self.integrate_request(sp,sv))
        self.expect('revoked-owner-validation-replay-denied','POST',self.root+'/validations',401,actor='validator',body=record)
        self.record('service','limits-scope-revocation',declaration=first,revoked_validation=validation)

def main():
    import argparse,hashlib,os,shutil,sys,traceback
    from infra import OwnedInfra,InfrastructureUnavailable,ROOT
    from provenance import capture,verify_image,resolve_reused_image,sources
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--reuse-image');ap.add_argument('--phase',action='append',choices=['service','worker','mounted','races']);a=ap.parse_args()
    i=OwnedInfra(a.output);j=None;code=1;records=[];reuse=None
    def record(platform,case,**data):records.append({'platform':platform,'case':case,**data});i.write_json('dependencies-evidence.json',records)
    try:
        if sys.platform!='darwin':raise InfrastructureUnavailable('qualified macOS host required')
        i.preflight();source=capture(i)
        i.run(['rdctl','shell','df','-k','/var/lib/docker'])
        if a.reuse_image:reuse=resolve_reused_image(i,a.reuse_image)
        image=reuse['image'] if reuse else i.owner+'-dependencies'
        i.write_json('image-ownership.json',{'tag':image,'intent':'owned dependency gate image','reuse':reuse})
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','--features','test-faults'],timeout=900)
        shutil.copyfile(ROOT/'target/debug/magus-fs',ROOT/'target/debug/magus-fs-client-faults');os.chmod(ROOT/'target/debug/magus-fs-client-faults',0o755)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=900)
        if not reuse:i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=0','--label','magus.fs2.owner='+i.owner,'-t',image,'.',timeout=2400)
        i.setup(image);i.isolate_service_control();verify_image(i,source)
        i.write_json('client-binaries.json',{'host':hashlib.sha256((ROOT/'target/debug/magus-fs').read_bytes()).hexdigest(),'linux':i.docker('exec',i.service,'sha256sum','/usr/local/bin/magus-fs').stdout.split()[0]})
        j=Dependencies(i,image,[]);j.record=record;j.run();j.configured()
        phases=a.phase or ['service','worker','mounted','races']
        if 'mounted' in phases:j.mounted_report()
        if 'worker' in phases:j.confinement()
        if 'races' in phases:j.publication_routes_and_races()
        j.scoped_and_revoke()
        after=sources();i.write_json('source-after.json',{'sha256':after});assert after==source['sha256'],'source changed during gate';code=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});code=2
    except Exception as e:
        i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()});traceback.print_exc()
        if j and hasattr(j,'lazy'):
            try:i.write_json('failure-mounted-status.json',j.lazy.status('reporter'))
            except Exception:pass
        if hasattr(i,'service'):
            logs=i.docker('exec',i.service,'cat','/tmp/service.log',check=False,evidence=False);(i.output/'service.log').write_text(logs.stdout+logs.stderr)
    finally:
        errors=[]
        for cleanup in ([j.cleanup] if j else [])+[i.cleanup]:
            try:cleanup()
            except Exception as e:errors.append(str(e));code=1
        i.write_json('result.json',{'passed':code==0,'exit':code,'scope':'FS2-B Task4 dependencies','complete_gate':not a.phase and not a.reuse_image,'phases':a.phase,'reuse':reuse,'records':len(records),'cleanup_errors':errors})
    print(json.dumps({'exit':code,'output':str(i.output)}));return code
if __name__=='__main__':raise SystemExit(main())
