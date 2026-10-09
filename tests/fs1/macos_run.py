"""Supervised native durable NFS qualification, with only owned synthetic resources."""
import argparse,errno,fcntl,hashlib,importlib.util,json,os,platform,shutil,socket,signal,stat,subprocess,sys,threading,time
from pathlib import Path
from macos_wire import BIN,ROOT,Fixture,attrs,opaque,words,read,write
FAULT_BIN=Path(os.environ.get("MAGUS_FS_FAULT_BIN",ROOT/"target/debug/magus-fs-faults"))

def denied(fn,codes=(errno.EACCES,errno.EPERM)):
    try:fn()
    except OSError as e:
        assert e.errno in codes,(e.errno,codes);return e.errno
    raise AssertionError('operation unexpectedly succeeded')
def expected(offset,length):
    first=offset//32;end=(offset+length+31)//32
    return b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(first,end))[offset%32:offset%32+length]
def case(name,root):
    p=root/'binary'
    if name=='metadata':
        names=os.listdir(root);assert {'binary','large','empty'}<=set(names)
        for path in [root,p,root/'empty']:
            s=path.stat();assert (s.st_uid,s.st_gid)==(os.getuid(),(root.parent/'tree').stat().st_gid)
        assert stat.S_IMODE(root.stat().st_mode)==0o755
        return {'names':names,'uid':os.getuid(),'gid':(root.parent/'tree').stat().st_gid,'root_mode':'0755'}
    if name in ['partial','full']:
        with (root/'large').open('rb',buffering=0) as f:
            if name=='partial':
                for off in [0,67108864-4096]:assert os.pread(f.fileno(),4096,off)==expected(off,4096)
                return {'head_tail':4096}
            digest=hashlib.sha256();size=0
            while data:=f.read(1048576):digest.update(data);size+=len(data)
            return {'size':size,'sha256':digest.hexdigest()}
    if name=='writes':
        p=root/'new';fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o666)
        try:
            assert stat.S_IMODE(os.fstat(fd).st_mode)==0o644
            os.write(fd,b'abc');os.fsync(fd)
            a=os.open(p,os.O_WRONLY|os.O_APPEND);os.write(a,b'de');os.close(a)
            os.ftruncate(fd,9);assert os.pread(fd,20,0)==b'abcde\0\0\0\0'
            os.pwrite(fd,b'Z',8);os.fsync(fd);assert os.pread(fd,20,0)==b'abcde\0\0\0Z'
            p.unlink();assert os.pread(fd,20,0)==b'abcde\0\0\0Z';os.pwrite(fd,b'OLD',0)
            p.write_bytes(b'replacement');assert os.pread(fd,3,0)==b'OLD';assert p.read_bytes()==b'replacement'
        finally:os.close(fd)
        old=os.open(p,os.O_RDWR)
        try:
            q=root/'atomic';q.write_bytes(b'new generation');os.replace(q,p)
            assert os.pread(old,99,0)==b'replacement';os.pwrite(old,b'OLD',0);os.fsync(old)
            assert p.read_bytes()==b'new generation';os.fchmod(old,0o640);assert stat.S_IMODE(os.fstat(old).st_mode)==0o640
        finally:os.close(old)
        d=root/'made';d.mkdir(mode=0o700);assert stat.S_IMODE(d.stat().st_mode)==0o700
        (d/'child').write_bytes(b'child');os.rename(d,root/'moved');assert (root/'moved/child').read_bytes()==b'child'
        (root/'moved/child').unlink();(root/'moved').rmdir()
        os.chmod(p,0o640);os.chown(p,os.getuid(),root.stat().st_gid);assert stat.S_IMODE(p.stat().st_mode)==0o640
        with p.open('rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            code="import fcntl,sys,json;f=open(sys.argv[1],'rb');\ntry:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError as e:print(json.dumps({'errno':e.errno}));sys.exit(75)\nelse:sys.exit(7)"
            result=subprocess.run([sys.executable,'-c',code,str(p)],capture_output=True,text=True,timeout=4)
            assert result.returncode==75 and json.loads(result.stdout)['errno']==errno.EAGAIN,result
        with p.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return {'create_append_sparse_truncate_unlink_replace_modes_fsync':True,'flock_errno':errno.EAGAIN,'flock_exit':75}
    if name=='permissions':
        lock=root/'locked';os.chmod(lock,0);e=denied(lock.read_bytes);os.chmod(lock,0o600)
        d=root/'read-dir';os.chmod(d,0o400);assert os.listdir(d)==['child'];search=denied(lambda:(d/'child').read_bytes());os.chmod(d,0o700)
        d=root/'search-dir';os.chmod(d,0o100);assert (d/'child').read_bytes()==b'child';listing=denied(lambda:os.listdir(d));os.chmod(d,0o700)
        p=root/'no-write';p.write_bytes(b'child');os.chmod(p,0o444);p.unlink();assert not p.exists()
        return {'mode000_errno':e,'no_search_errno':search,'no_read_errno':listing,'readonly_child_unlink':True}
    if name=='unsupported':
        errors={};before_names=set(os.listdir(root));before_bytes=p.read_bytes()
        def metadata():
            value=p.stat()
            return {name:getattr(value,name) for name in ['st_ino','st_mode','st_uid','st_gid','st_size','st_atime_ns','st_mtime_ns','st_ctime_ns']}
        before=metadata()
        # Darwin26.5.2 maps NFS NOTSUPP to EIO here; LINK is RPC PROC_UNAVAIL.
        for operation,fn in [('symlink',lambda:os.symlink('binary',root/'unsupported-symlink')),('hardlink',lambda:os.link(root/'binary',root/'unsupported-hardlink')),('client-times',lambda:os.utime(p,ns=(123456000000000,123456000000000)))]:
            errors[operation]=denied(fn,(errno.EPROCUNAVAIL,) if operation=='hardlink' else (errno.EIO,))
        time.sleep(1.1) # expire the qualified attribute TTL before the no-effects observation
        after=metadata();assert after==before,(before,after)
        assert p.read_bytes()==before_bytes and set(os.listdir(root))==before_names
        assert not os.path.lexists(root/'unsupported-symlink') and not os.path.lexists(root/'unsupported-hardlink')
        return {'errors':errors,'before_metadata':before,'after_metadata':after,'bytes_sha256':hashlib.sha256(before_bytes).hexdigest(),'namespace_unchanged':True}
    if name=='review-parity':
        for mode in [0o444,0]:
            path=root/('restrictive-'+str(mode));fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,mode)
            try:
                assert stat.S_IMODE(os.fstat(fd).st_mode)==mode
                os.fchmod(fd,0o600);os.write(fd,b'allowed');os.fsync(fd)
            finally:os.close(fd)
            assert path.read_bytes()==b'allowed';path.unlink()
        path=root/'flags';path.write_bytes(b'abc');fd=os.open(path,os.O_RDWR|os.O_APPEND)
        try:
            fcntl.fcntl(fd,fcntl.F_SETFL,fcntl.fcntl(fd,fcntl.F_GETFL)&~os.O_APPEND);os.write(fd,b'Z');os.fsync(fd);assert path.read_bytes()==b'Zbc'
            fcntl.fcntl(fd,fcntl.F_SETFL,fcntl.fcntl(fd,fcntl.F_GETFL)|os.O_APPEND);os.lseek(fd,0,os.SEEK_SET);os.write(fd,b'Q');os.fsync(fd);assert path.read_bytes()==b'ZbcQ'
            denied(lambda:os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600),(errno.EEXIST,));assert path.read_bytes()==b'ZbcQ'
        finally:os.close(fd)
        path.unlink();return {'restrictive_creation_returns_fd':True,'set_clear_append':True,'exclusive_duplicate_preserves_bytes':True}
    if name=='sidecars':
        observed={}
        for path in sorted(root.glob('._*')):
            assert (root/path.name[2:]).exists(),path
            data=path.read_bytes();assert data[:8]==bytes.fromhex('0005160700020000'),path
            assert b'com.apple.provenance\0' in data,path
            observed[path.name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':stat.S_IMODE(path.stat().st_mode)}
        return observed
    if name=='mapping':
        assert (root/'group').read_bytes()==b'group';assert (root/'other').read_bytes()==b'other'
        errors={name:denied(lambda path=root/name:os.open(path,os.O_WRONLY)) for name in ['group','other']}
        errors['denied-other']=denied(lambda:(root/'denied-other').read_bytes())
        assert (root/'group').stat().st_uid==10001 and (root/'other').stat().st_gid==10001
        result=subprocess.run([str(root/'run')],capture_output=True,text=True,timeout=4);assert result.returncode==0 and result.stdout=='executed\n'
        errors['noexec']=denied(lambda:subprocess.run([str(root/'noexec')],check=True))
        return {'foreign_owner_uid':10001,'other_gid':10001,'group_other_and_execute':errors}
    if name=='native-partial-write':
        fd=os.open(root/'partialbase',os.O_WRONLY)
        try:assert os.pwrite(fd,b'NATIVE-ACK',100)==10;os.fsync(fd)
        finally:os.close(fd)
        return {'offset':100,'bytes':10,'fsync_ack':True}
    if name=='historical':
        assert (root/'binary').read_bytes()==bytes(range(256))*2400
        assert (root/'uncached').read_bytes()==b'unhydrated original revision'*12000
        assert (root/'partialbase').read_bytes()==b'partial-base-uncached-'*400000
        assert not (root/'new').exists() and not (root/'offline-new').exists()
        return {'original_revision_bytes':True,'new_paths_absent':True}
    if name=='fault':
        def status():
            process=subprocess.run([str(BIN),'status','--state',str(root.parent/'faultstate')],capture_output=True,text=True,timeout=5)
            assert process.returncode==0,(process.stdout,process.stderr)
            return json.loads(process.stdout)
        def working():
            import sqlite3
            with sqlite3.connect('file:'+str(root.parent/'faultstate/journal.sqlite')+'?mode=ro',uri=True) as db:
                return json.loads(db.execute('SELECT value FROM working').fetchone()[0])
        before_open=status();open_working=working();fd=os.open(root/'binary',os.O_WRONLY)
        try:
            before_write=status();write_working=working()
            original={e['path']:e for e in open_working['tree']['entries']};current={e['path']:e for e in write_working['tree']['entries']}
            assert all(current.get(name)==entry for name,entry in original.items())
            created={name:entry for name,entry in current.items() if name not in original}
            assert set(created)<= {'._binary'},created
            for entry in created.values():assert entry['content']=={'kind':'file','version':{'size':0,'extents':[]}},entry
            def attempt():os.pwrite(fd,b'failed',0);os.fsync(fd)
            result=denied(attempt,(errno.ENOSPC,));after_write=status();after_working=working();assert after_working==write_working,(write_working,after_working)
            assert before_write['working_generation']==after_write['working_generation'],(before_write,after_write)
            assert before_write['captured_revision']==after_write['captured_revision']
        finally:os.close(fd)
        return {'durable_write_errno':result,'before_open':before_open,'before_write':before_write,'after_write':after_write,'entries_created_during_open':created,'binary_descriptor':current['binary'],'working_sha256_before_after':hashlib.sha256(json.dumps(write_working,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
    if name in ['closure','complete-closure']:
        result={}
        for path in sorted(root.rglob('*')):
            if path.is_file() and (name=='complete-closure' or path.name!='denied-other'):
                data=path.read_bytes();result[str(path.relative_to(root))]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':stat.S_IMODE(path.stat().st_mode)}
        return result
    if name=='readonly':
        actions=[lambda:os.open(p,os.O_WRONLY),lambda:p.write_bytes(b'no'),lambda:os.truncate(p,0),lambda:p.unlink(),lambda:os.rename(p,root/'renamed'),lambda:(root/'new').write_bytes(b'no'),lambda:(root/'made').mkdir(),lambda:os.chmod(p,0o777),lambda:os.chown(p,os.getuid(),root.stat().st_gid)]
        return {'denials':[denied(fn,(errno.EROFS,)) for fn in actions]}
    if name=='offline':
        with (root/'large').open('rb',buffering=0) as f:assert os.pread(f.fileno(),4096,0)==expected(0,4096)
        started=time.monotonic();err=denied(lambda:(root/'uncached').read_bytes(),(errno.EIO,errno.ENETDOWN));elapsed=time.monotonic()-started;assert elapsed<5,elapsed
        with (root/'uncached').open('wb',buffering=0) as f:f.write(b'full offline replacement');os.fsync(f.fileno())
        with (root/'offline-new').open('wb',buffering=0) as f:f.write(b'ACK survives daemon loss');os.fsync(f.fileno())
        return {'uncached_errno':err,'uncached_seconds':elapsed,'cached_read':True,'offline_replacement_new_fsync':True}
    if name=='recovered':
        assert (root/'new').read_bytes()==b'new generation';assert stat.S_IMODE((root/'new').stat().st_mode)==0o640
        assert (root/'uncached').read_bytes()==b'full offline replacement'
        assert (root/'offline-new').read_bytes()==b'ACK survives daemon loss'
        assert not (root/'moved').exists() and not (root/'atomic').exists() and not (root/'no-write').exists()
        assert stat.S_IMODE((root/'read-dir').stat().st_mode)==0o700 and stat.S_IMODE((root/'locked').stat().st_mode)==0o600
        return {'bytes':{'new':'new generation','uncached':'full offline replacement','offline-new':'ACK survives daemon loss'},'modes':{'new':'0640','read-dir':'0700','locked':'0600'},'absent':['moved','atomic','no-write']}
    if name=='binary':assert p.read_bytes()==bytes(range(256))*2400;return {'bytes':614400,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    raise ValueError(name)

def run(output,focused=False,fault_focused=False):
    # Load qualified lifecycle helpers explicitly; do not import the FS1 Linux resources module.
    sys.path.insert(0,str(ROOT/'tests/fs0'))
    from resources import OwnedOutput
    spec=importlib.util.spec_from_file_location('qualified_fs0_macos',ROOT/'tests/fs0/macos_run.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    owned=OwnedOutput(output);guard=m.MountGuard(owned)
    report={'schema':'fs1-macos-task6-v1','owned_token':owned.token,'state':'running','passed':False,'commands':[],'cases':{},'mounts':{},'cleanup':[],'cleanup_errors':[],'remaining_owned_resources':[],'environment':{'platform':platform.platform(),'python':sys.version},'qualification_limits':['real foreign-kernel-UID control probe unavailable: existing sudo -n policy requires a password']}
    fixture=None;endpoints={};interrupted=[False]
    def save():
        report['owned_pids']=sorted({p.pid for p in owned.processes} | {p.pid for p in (fixture.processes if fixture else [])})
        temp=output/'result.json.tmp';temp.write_text(json.dumps(report,indent=2));temp.replace(output/'result.json')
    def cmd(argv,name,seconds=30,check=True,mountpoint=None):
        value=m.command(argv,output/(name+'.stdout'),seconds,owned=owned,guard=guard,mountpoint=mountpoint);report['commands'].append(value);save()
        if check:assert value.get('returncode')==0,value
        return value
    def workload(name,view='view'):
        value=cmd([sys.executable,str(Path(__file__).resolve()),'--case',name,'--view',str(output/view)],name+'-'+str(len(report['commands'])),seconds=45)
        result=json.loads(Path(value['log']).read_text());report['cases'][name+'-'+view]=result;save();return result
    def endpoint(name,state='lazy',mode='private',fault=False,revision=None):
        guard.candidate(output/name)
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT})
        try:
            p,rpc,info=fixture.endpoint(name,state,mode,binary=FAULT_BIN if fault else None,revision=revision,env={**os.environ,'MAGUS_TEST_FAULT_POINT':'object-sync','MAGUS_TEST_FAULT_ACTION':'ENOSPC'} if fault else None);owned.own_process(p);endpoints[name]=(p,rpc,info)
            report['mounts'][name]=info;save()
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        cmd(info['mount_command'],'mount-'+name,mountpoint=output/name)
        assert m.mount_state(output/name) is True
        options=cmd(['/usr/bin/nfsstat','-m'],'options-'+name)
        report['mounts'][name]['effective_options']=m.effective_options(Path(options['log']).read_text(),output/name,mode=='read-only');save()
        return rpc
    def unmount(name):
        path=output/name
        if m.mount_state(path) is True:cmd(['/sbin/umount',str(path)],'unmount-'+name+'-'+str(len(report['commands'])),seconds=5)
        assert m.mount_state(path) is False
        report['cleanup'].append({'mountpoint':str(path),'unmounted':True});save()
    def crash(name):
        p,rpc,info=endpoints[name];old_handle=rpc.lookup(rpc.mount(),b'offline-new')
        recovery_name='recovery'+str(len(report.get('crashes',[]))+1)
        ready=threading.Event();done=threading.Event();result={}
        def recover():
            ready.set()
            try:
                p.wait()
                result['endpoint']=fixture.endpoint(recovery_name,'cleanupstate','read-only',port=info['port'],revision=cleanup_revision)
            except BaseException as error:result['error']=repr(error)
            finally:done.set()
        watcher=threading.Thread(target=recover);watcher.start();assert ready.wait(2)
        record={'daemon_pid':p.pid,'port':info['port'],'owned_recovery_thread_ready':True,'prequalified_wire_case':'test_exact_port_recovery_returns_stale_for_lost_process_handles','fresh_nonce_policy':'old handles STALE; no alias/recreated open capability','crashed_state':str(output/'lazy'),'cleanup_state':str(output/'cleanupstate'),'cleanup_revision':cleanup_revision,'workload_processes_exited':all(p.poll() is not None for p in owned.processes if p not in [v[0] for v in endpoints.values()]),'source_helpers_retained':True}
        assert record['workload_processes_exited'];report.setdefault('crashes',[]).append(record);save()
        assert m.mount_state(output/name) is True
        p.kill();assert done.wait(20),result;watcher.join();assert 'endpoint' in result,result
        replacement,again,recovery=result['endpoint'];owned.own_process(replacement);record['recovery_pid']=replacement.pid;record['recovery_endpoint']=recovery;record['killed_exit']=p.returncode;save()
        stale=again.call(100003,1,opaque(old_handle));assert stale[:4]==words(70),stale.hex();record['old_handle_status']=70;record['old_handle_hex']=old_handle.hex();fresh_root=again.mount();record['cleanup_root_handle_hex']=fresh_root.hex();assert old_handle[:-8]!=fresh_root[:-8];assert again.call(100003,4,opaque(fresh_root)+words(63))[-4:]==words(0);record['cleanup_root_access']=0
        unmount(name);record['normal_unmount']=True
        replacement.terminate();replacement.communicate(timeout=5);record['recovery_exit']=replacement.returncode;save()
    def verify_fault():
        endpoint('fault','faultstate',fault=True);observation=workload('fault','fault')
        unmount('fault');endpoints['fault'][0].terminate();endpoints['fault'][0].communicate(timeout=5)
        endpoint('fault-restart','faultstate');workload('binary','fault-restart')
        report['fault']={'native':observation,'old_bytes_after_restart':True}
    def signal_handler(*_):interrupted[0]=True;raise InterruptedError('native runner interrupted')
    previous={sig:signal.signal(sig,signal_handler) for sig in [signal.SIGINT,signal.SIGTERM]}
    try:
        if platform.system()!='Darwin' or not Path('/sbin/mount_nfs').is_file() or not BIN.is_file() or not FAULT_BIN.is_file():report['state']='blocked';return 2
        report['revision']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();report['dirty']=subprocess.check_output(['git','status','--short'],cwd=ROOT,text=True)
        inputs={ROOT/x for x in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']}
        for directory in ['src','crates','vendor','benches','tests']:
            inputs.update(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in str(p))
        report['source_hashes']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inputs)}
        archive=output/'compiler-fixture-inputs';archive.mkdir()
        for path in sorted(inputs):destination=archive/path.relative_to(ROOT);destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)
        shutil.copy2(FAULT_BIN,output/'magus-fs-faults-tested');report['fault_binary_sha256']=hashlib.sha256(FAULT_BIN.read_bytes()).hexdigest()
        shutil.copy2(BIN,output/'magus-fs-tested');report['binary_sha256']=hashlib.sha256(BIN.read_bytes()).hexdigest()
        cmd(['uname','-a'],'uname');cmd(['rustc','+stable','--version','--verbose'],'rust-version');cmd(['/usr/bin/sw_vers'],'sw-vers');cmd(['/sbin/mount','-t','nfs'],'initial-mount-table')
        fixture=Fixture(output,large=not (focused or fault_focused));report['fixture_revision']=fixture.revision
        # Cleanup-only state never references a served root and contains no useful content.
        cleanup_config=json.loads(fixture.config.read_text());cleanup_config['replica']['content_roots']=[str(fixture.tree)]+[str(output/name) for name in ['recovery1','recovery2','recovery3']]
        cleanup_config_path=output/'cleanup-config.json';cleanup_config_path.write_text(json.dumps(cleanup_config))
        descriptor=json.loads(fixture.manifest.read_text());descriptor['tree']['entries']=[];descriptor['tree']['root']['mode']=0
        canonical=json.dumps(descriptor,separators=(',',':'),ensure_ascii=False);cleanup_revision='sha256:'+hashlib.sha256(canonical.encode()).hexdigest()
        cleanup_manifest=output/'cleanup-revision.json';cleanup_manifest.write_text(canonical)
        fixture.cli('init','cleanupstate','--config',cleanup_config_path,'--revision-manifest',cleanup_manifest,'--source',fixture.url)
        bootstrap,probe,bootstrap_info=fixture.endpoint('recovery3','cleanupstate','read-only',revision=cleanup_revision);owned.own_process(bootstrap)
        cleanup_root=probe.mount();assert probe.call(100003,4,opaque(cleanup_root)+words(63))[-4:]==words(0)
        report['cleanup_bootstrap']={'state':str(output/'cleanupstate'),'config':cleanup_config,'revision':cleanup_revision,'empty_tree_mode':'0000','readonly':True,'endpoint':bootstrap_info,'root_access':0,'root_handle_hex':cleanup_root.hex(),'scope':'wire-only prequalification; never mounted or consumed for workload'}
        bootstrap.terminate();bootstrap.communicate(timeout=5);report['cleanup_bootstrap']['exit']=bootstrap.returncode;save()
        rpc=endpoint('view');report['private_initial_transfer']=dict(fixture.counts);assert fixture.counts['body_bytes']==0
        if fault_focused:
            unmount('view');endpoints['view'][0].terminate();endpoints['view'][0].communicate(timeout=5)
            verify_fault();report['passed']=True;report['state']='passed';raise StopIteration
        if focused:
            workload('writes');workload('review-parity');workload('unsupported');report['passed']=True;report['state']='passed';raise StopIteration
        workload('metadata');report['metadata_transfer']=dict(fixture.counts);assert fixture.counts['body_bytes']==0
        workload('partial');cold=dict(fixture.counts);assert 0<cold['body_bytes']<=2097152
        workload('partial');assert fixture.counts==cold;report['cold_warm_transfer']=cold
        # Real native partial write to an entirely uncached base is qualified before the full scan.
        h=rpc.lookup(rpc.mount(),b'uncached');assert write(rpc,h,b'ACK',100)[-12:-8]==words(2);assert fixture.counts==cold
        report['wire_partial_write_uncached']={'bytes':3,'body_bytes_delta':0,'stability':'FILE_SYNC'}
        before_partial=dict(fixture.counts);workload('native-partial-write');report['native_partial_transfer']={'before':before_partial,'after':dict(fixture.counts)};assert fixture.counts['body_bytes']-before_partial['body_bytes']<=2097152
        workload('binary');workload('writes');workload('review-parity');workload('permissions');workload('mapping');workload('unsupported')
        full=workload('full');assert full=={'size':67108864,'sha256':'0d9f8390657caaf114fa00a6a191f1559b488bb89f7c61b9e8d95b392330c3e4'}
        report['full_transfer']=dict(fixture.counts)
        endpoint('ro','readonly','read-only');workload('readonly','ro')
        def private_request(state,payload):
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(5);sock.connect(str(output/state/'control.sock'));sock.sendall(json.dumps(payload).encode());sock.shutdown(socket.SHUT_WR);data=b''
                while part:=sock.recv(65536):data+=part
            return json.loads(data)
        forged=private_request('lazy',{'command':'status','options':{},'principal':'root'});assert forged['exit']==2 and forged['value']['error']=='invalid_descriptor'
        ro_control=fixture.cli('checkpoint','readonly','--operation-id','operation:'+'9'*32,code=1);assert ro_control['error']=='read_only'
        meta=(output/'lazy/control.sock').stat();assert meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o600
        sentinel=output/'faultstate/control.sock';sentinel.write_bytes(b'owned sentinel');sentinel.chmod(0o600)
        blocked=fixture.cli('mount','faultstate','--revision',fixture.revision,'--mountpoint',output/'fault','--mode','private','--prepare-only','true',code=1);assert blocked['error']=='unsafe_storage';assert sentinel.read_bytes()==b'owned sentinel';sentinel.unlink()
        report['private_control']={'kernel_peer_api':'getpeereid','owner_uid':meta.st_uid,'socket_mode':'0600','forged':forged,'readonly':ro_control,'regular_file_preserved':True,'foreign_kernel_uid':'blocked by existing noninteractive sudo policy; see task6 foreign-peer.json'}
        unmount('ro')
        report['mounted_status']=fixture.cli('status');fixture.offline();report['source_offline']={'listener_closed':True,'thread_joined':True}
        workload('offline');sidecars=workload('sidecars');report['precrash_sidecars']=sidecars;before=fixture.cli('status');report['prekill_status']=before;crash('view')
        endpoint('restart');workload('recovered','restart');after=fixture.cli('status');assert after==before,(after,before)
        op='operation:'+'2'*32;generation=str(before['working_generation'])
        captured=fixture.cli('checkpoint','lazy','--operation-id',op,'--expected-generation',generation);report['checkpoint']=captured
        crash('restart');endpoint('old');workload('recovered','old');assert fixture.cli('checkpoint','lazy','--operation-id',op,'--expected-generation',generation)==captured
        fixture.online();report['source_online_again']=True
        closure=workload('closure','old')
        expected_files={}
        for path in sorted(fixture.tree.rglob('*')):
            if path.is_file() and path.name!='denied-other':
                data=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
                if path.name=='uncached':data=b'full offline replacement'
                if path.name=='partialbase':data=data[:100]+b'NATIVE-ACK'+data[110:]
                if path.name=='locked':mode=0o600
                if path.name=='group':mode=0o640
                if path.name=='other':mode=0o604
                expected_files[str(path.relative_to(fixture.tree))]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':mode}
        for name,data,mode in [('new',b'new generation',0o640),('offline-new',b'ACK survives daemon loss',0o644)]:expected_files[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':mode}
        expected_files.update(sidecars)
        assert closure==expected_files,(closure,expected_files)
        report['authorized_closure_sha256']=hashlib.sha256(json.dumps(closure,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        report['closure_excluded_by_authority']=['denied-other']
        unmount('old');endpoints['old'][0].terminate();endpoints['old'][0].communicate(timeout=5)
        endpoint('history','lazy','read-only');workload('historical','history');unmount('history');endpoints['history'][0].terminate();endpoints['history'][0].communicate(timeout=5)
        verify_fault()
        endpoint('full','fullstate','read-only',revision=fixture.original_revision)
        complete=workload('complete-closure','full');original={}
        for path in sorted(fixture.tree.rglob('*')):
            if path.is_file():
                data=path.read_bytes();original[str(path.relative_to(fixture.tree))]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':stat.S_IMODE(path.stat().st_mode)}
        assert complete==original,(complete,original)
        report['complete_base_closure_sha256']=hashlib.sha256(json.dumps(complete,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        full_status=fixture.cli('status','fullstate');assert full_status['missing_bytes']==0 and full_status['ready_mode']=='full';report['full_status']=full_status
        report['passed']=True;report['state']='passed'
    except StopIteration:pass
    except BaseException as e:report['state']='failed';report['error']=repr(e)
    finally:
        for sig in previous:signal.signal(sig,lambda *_:interrupted.__setitem__(0,True))
        for name in reversed(list(endpoints)):
            try:unmount(name)
            except BaseException as e:report['cleanup_errors'].append(repr(e))
        while not guard.safe():
            report['passed']=False;report['state']='cleanup_pending';report['remaining_owned_resources']=[str(p) for p in guard.paths if m.mount_state(p) is not False]
            report['recovery_action']={'retain_pids':[p.pid for p in owned.processes if p.poll() is None],'commands':[['/sbin/umount',p] for p in report['remaining_owned_resources']],'instruction':'Confirm exact owned mount table entries, then normally unmount. Do not kill helpers or delete mounted paths.'};save();time.sleep(1)
        report['cleanup_errors']+=owned.cleanup(remove_output=False)
        if fixture:
            try:fixture.close()
            except BaseException as e:report['cleanup_errors'].append(repr(e))
        report['mountpoint_directories_removed']=[]
        for path in guard.paths:
            if m.mount_state(path) is False and path.is_dir():
                try:path.rmdir();report['mountpoint_directories_removed'].append(str(path))
                except OSError as e:report['cleanup_errors'].append(repr(e))
        report['reaped']=[{'pid':p.pid,'exit':p.poll()} for p in owned.processes]
        report['remaining_owned_resources']=[]
        if report['cleanup_errors'] or interrupted[0]:report['passed']=False;report['state']='failed'
        save()
        for sig,handler in previous.items():signal.signal(sig,handler)
    return 0 if report['passed'] else 2 if report['state']=='blocked' else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);parser.add_argument('--native',action='store_true');parser.add_argument('--focused',action='store_true');parser.add_argument('--fault-focused',action='store_true');parser.add_argument('--case');parser.add_argument('--view',type=Path);a=parser.parse_args()
    if a.case:print(json.dumps(case(a.case,a.view)));sys.exit(0)
    if not a.output or not a.output.is_absolute() or a.output.exists():parser.error('--output must be new and absolute')
    if a.native:sys.exit(run(a.output,a.focused,a.fault_focused))
    from macos_supervisor import supervise,SupervisionFailure
    try:sys.exit(supervise([sys.executable,str(Path(__file__).resolve()),'--native','--output',str(a.output)]+(['--focused'] if a.focused else [])+(['--fault-focused'] if a.fault_focused else []),a.output))
    except SupervisionFailure as e:print(json.dumps(e.supervision));sys.exit(1)
