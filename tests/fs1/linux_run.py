"""Native FS1 acceptance. New output, explicit image, owned confined workloads only."""
import argparse,hashlib,json,subprocess,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def run(output,image,only_review=False):
    assert output.is_absolute() and not output.exists();output.mkdir()
    token='fs1-task5-'+uuid.uuid4().hex[:12];daemon=token+'-daemon';vm='/tmp/'+token
    report={'token':token,'commands':[],'cases':{},'cleanup':[],'passed':False,'image_name':image,'scope':'review-regressions' if only_review else 'full-task5','owned_containers':[daemon],'owned_vm_path':vm}
    def save(): (output/'result.json').write_text(json.dumps(report,indent=2))
    def cmd(argv,name,timeout=45,check=True):
        r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,cwd=ROOT)
        (output/(name+'.stdout')).write_text(r.stdout);(output/(name+'.stderr')).write_text(r.stderr)
        report['commands'].append({'argv':argv,'exit':r.returncode,'stdout':name+'.stdout','stderr':name+'.stderr'});save()
        if check and r.returncode: raise AssertionError((name,r.returncode,r.stdout[-2000:],r.stderr[-2000:]))
        return r
    def request(data):
        script="import json,urllib.request;d="+repr(json.dumps(data))+"; print(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9001',d.encode()),timeout=20).read().decode())"
        r=json.loads(cmd(['docker','exec',daemon,'python3','-c',script],'control-'+str(len(report['commands'])),timeout=25).stdout)
        assert r['ok'],r
        return r['result']
    def workload(name,case,view='view',user='1001:1001',permissions=False):
        container=token+'-'+name;report['owned_containers'].append(container)
        argv=['docker','run','--rm','--name',container,'--read-only','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--user',user,'--tmpfs','/tmp:rw,nosuid,nodev,size=4m','-v',vm+'/'+view+':/view:rslave']
        if user=='0:0': argv+=['--cap-add','DAC_OVERRIDE']
        if user=='1002:1002': argv+=['--group-add','1001']
        argv+=[image,'python3','/opt/fs1/'+('permission_io.py' if permissions else 'ordinary_io.py'),case]
        r=cmd(argv,name,timeout=45);value=json.loads(r.stdout);report['cases'][name]=value;save();return value
    started=False
    try:
        report['revision']=cmd(['git','rev-parse','HEAD'],'revision').stdout.strip();report['dirty']=cmd(['git','status','--short'],'dirty').stdout
        inputs={ROOT/name for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','tests/fs0/permission_source.py','tests/fs0/root_confinement.py','tests/fs1/Dockerfile.linux']}
        for directory in ['src','crates','vendor','benches']:
            inputs.update(p for p in (ROOT/directory).rglob('*') if p.is_file())
        inputs.update(ROOT.glob('tests/*.rs'));inputs.update(ROOT.glob('tests/fs1/*.py'))
        report['source_hashes']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inputs)}
        report['prerequisite_phase']=True
        cmd(['docker','info','--format','{{.ServerVersion}}'],'docker-info')
        report['image']=json.loads(cmd(['docker','image','inspect',image],'image').stdout)[0]['Id']
        cmd(['docker','run','-d','--name',daemon,'--read-only','--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges','--device','/dev/fuse','--env','FS1_OWNER_TOKEN='+token,'--tmpfs','/private:rw,nosuid,nodev,size=768m','--tmpfs','/tmp:rw,nosuid,nodev,size=16m','-v',vm+':/shared:rshared',image,'python3','/opt/fs1/resources.py'],'start');started=True;report['prerequisite_phase']=False
        deadline=time.monotonic()+40
        while True:
            logs=cmd(['docker','logs',daemon],'ready',check=False).stdout
            if logs.strip(): break
            assert time.monotonic()<deadline,'setup timeout';time.sleep(.3)
        report['fixture']=json.loads(logs.splitlines()[0]);report['initial_stats']=request({'action':'stats'});assert report['initial_stats']['body_bytes']==0
        request({'action':'mount','name':'view'})
        if only_review:
            failures=[]
            for case in ['review-create','review-append','review-metadata']:
                try:workload(case,case)
                except Exception as error:failures.append(repr(error))
            assert not failures,failures
        else:
            workload('metadata','metadata');after_meta=request({'action':'stats'});assert after_meta['body_bytes']==0
            workload('cold','partial');cold=request({'action':'stats'});assert 0<cold['body_bytes']<=2097152
            workload('warm','partial');warm=request({'action':'stats'});assert warm==cold
            report['transfer']={'metadata':after_meta,'cold':cold,'warm':warm}
            full=workload('full','full');assert full['size']==67108864 and full['sha256']==report['fixture']['sha256']
            report['transfer']['full']=request({'action':'stats'})
            request({'action':'copy-full'});native=workload('native-full','full',view='full');assert native==full
            workload('native-metadata','metadata',view='full')
            request({'action':'stop','name':'view'})
            request({'action':'mount','name':'view','state':'parity'})
            mounted_closure=workload('mounted-closure','brain-closure',user='0:0')
            request({'action':'stop','name':'view'})
            full_closure=workload('full-closure-daemon-stopped','brain-closure',view='full',user='0:0')
            assert full_closure==mounted_closure
            report['full_closure']={'verified':True,'daemon_stopped':True,'revision':report['fixture']['revision'],'mounted':mounted_closure,'full':full_closure}
            request({'action':'mount','name':'view'})
            report['mounted_owner_busy']=request({'action':'owner-busy'})
            workload('owner-permissions','owner',permissions=True);workload('group','group',user='1002:1002',permissions=True);workload('other','other',user='1003:1003',permissions=True)
            workload('writes','writes')
            for case in ['review-create','review-append','review-metadata']:workload(case,case)
            request({'action':'mount','name':'ro','state':'readonly','mode':'read-only'})
            workload('readonly-owner','readonly',view='ro',permissions=True);workload('readonly-root','readonly',view='ro',user='0:0',permissions=True);workload('root-confinement','root',view='ro',user='0:0',permissions=True)
            report['control_checks']=request({'action':'control-checks'})
            peer_script="import errno,json,socket; s=socket.socket(socket.AF_UNIX);\ntry: s.connect('/private/lazy/control.sock')\nexcept OSError as e: assert e.errno==errno.EACCES;print(json.dumps({'foreign_uid_socket_errno':e.errno}))\nelse: raise AssertionError('foreign UID reached control socket')"
            report['foreign_peer']=json.loads(cmd(['docker','exec','--user','1001:1001',daemon,'python3','-c',peer_script],'foreign-peer').stdout)
            status=request({'action':'cli','command':'status'});assert status['uncaptured'] is True
            report['source_outage']=request({'action':'offline'});report['offline']=workload('offline','offline')
            dirty=request({'action':'cli','command':'status'});assert dirty['uncaptured'] is True
            report['dirty_fsync_loss']=request({'action':'stop','name':'view','kill':True})
            request({'action':'mount','name':'view'});workload('dirty-fsync-recovered','recovered')
            recovered=request({'action':'cli','command':'status'});assert recovered['uncaptured'] is True and recovered['captured_revision']==dirty['captured_revision'] and recovered['working_generation']==dirty['working_generation']
            report['dirty_recovery']={'before':dirty,'after':recovered}

            status=request({'action':'cli','command':'status'});generation=status['working_generation']
            cp=request({'action':'cli','command':'checkpoint','args':['--operation-id','operation:'+'5'*32,'--expected-generation',str(generation)]})
            history=request({'action':'cli','command':'history'});assert len(history['revisions'])==2 and history['revisions'][0]['revision']==report['fixture']['revision'];report['checkpoint']=cp
            report['fault_point']='after native fsync + checkpoint ACK; owned SIGKILL; bounded umount before restart'
            report['loss']=request({'action':'stop','name':'view','kill':True});request({'action':'mount','name':'view'});workload('recovered','recovered')
            retry=request({'action':'cli','command':'checkpoint','args':['--operation-id','operation:'+'5'*32,'--expected-generation',str(generation)]});assert retry==cp;report['checkpoint_replay']=retry;report['postcheckpoint_status']=request({'action':'cli','command':'status'})
            report['checkpoint_mismatch']=request({'action':'cli','command':'checkpoint','args':['--operation-id','operation:'+'5'*32,'--expected-generation',str(generation+1)],'code':1});assert report['checkpoint_mismatch']['error']=='operation_mismatch'
            report['postmismatch_status']=request({'action':'cli','command':'status'});assert report['postmismatch_status']==report['postcheckpoint_status']
            request({'action':'online'});request({'action':'mount','name':'fault','state':'faultstate','fault':True});before=request({'action':'cli','command':'status','state':'faultstate'})
            workload('diskfull','diskfull',view='fault');after=request({'action':'cli','command':'status','state':'faultstate'});assert before['captured_revision']==after['captured_revision'] and before['working_generation']==after['working_generation'];report['diskfull_head']={'before':before,'after':after}
            request({'action':'stop','name':'fault'});request({'action':'mount','name':'fault','state':'faultstate'});workload('old-head','old-head',view='fault')
            request({'action':'stop','name':'view'});request({'action':'mount','name':'view','mode':'read-only'});workload('old-revision','historical')
        report['passed']=True
    except BaseException as e:
        report['interrupted']=isinstance(e,(KeyboardInterrupt,InterruptedError))
        report['error']=repr(e)
        if report.get('prerequisite_phase'): report['blocked']=True
    finally:
        for container in report['owned_containers'][1:]:
            alive=cmd(['docker','ps','-a','--filter','name=^/'+container+'$','--format','{{.Names}}'],'workload-check-'+container,check=False).stdout.strip()
            if alive==container:cmd(['docker','rm','-f',container],'workload-stop-'+container)
        if started:
            try:
                cmd(['docker','kill','--signal','TERM',daemon],'term');cmd(['docker','wait',daemon],'wait',timeout=20)
                logs=cmd(['docker','logs',daemon],'final-log').stdout;cleanup=json.loads(logs.splitlines()[-1]);report['cleanup'].append(cleanup)
                assert all(x['returncode']==0 and not x['still_mounted'] for x in cleanup['cleanup'])
                assert all(x['returncode'] is not None for x in cleanup['reaped']) and not cleanup['mounted_remaining']
                cmd(['docker','rm',daemon],'remove')
                script="import shutil; from pathlib import Path;p=Path('/owned');assert (p/'.fs1-owned').read_text()=="+repr(token)+";assert not any(x.split()[4].startswith('/owned/') for x in Path('/proc/self/mountinfo').read_text().splitlines());[(shutil.rmtree(x) if x.is_dir() else x.unlink()) for x in p.iterdir()]"
                cmd(['docker','run','--rm','--network','none','--cap-drop','ALL','--cap-add','DAC_OVERRIDE','--read-only','-v',vm+':/owned',image,'python3','-c',script],'remove-owned-content')
                cmd(['docker','run','--rm','--network','none','--cap-drop','ALL','--read-only','-v','/tmp:/vm',image,'python3','-c',"from pathlib import Path;p=Path('/vm')/"+repr(token)+";p.rmdir();assert not p.exists()"],'remove-owned-directory')
            except Exception as e: report['cleanup_error']=repr(e);report['passed']=False
        report['remaining_owned_containers']=cmd(['docker','ps','-a','--filter','name='+token,'--format','{{.Names}}'],'remaining',check=False).stdout.strip()
        if report['remaining_owned_containers']:report['passed']=False
        report['exit_code']=0 if report['passed'] else 2 if report.get('blocked') else 1
        save()
    print(output/'result.json');return report['exit_code']
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--only-review',action='store_true');p.add_argument('--image',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();raise SystemExit(run(a.output,a.image,a.only_review))
