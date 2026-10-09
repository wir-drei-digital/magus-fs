"""Affected native history permission gate; isolated new output root, normal unmount only."""
import argparse, hashlib, json, os, pathlib, platform, subprocess, sys, time


def run(binary, base):
    base.mkdir(); base.chmod(0o755)
    linux = platform.system() == 'Linux'
    uid, gid = (1001, 1001) if linux else (os.geteuid(), os.getegid())
    tree, view = base/'tree', base/'view'
    tree.mkdir(); tree.chmod(0o755)
    if not linux: gid = tree.stat().st_gid
    (tree/'dir').mkdir(); (tree/'dir').chmod(0o700)
    for name in ['file', 'dir/inside', 'owner', 'group']:
        p=tree/name; p.write_bytes(b'old historical bytes'); p.chmod(0o600)
    if linux:
        for p in [tree, tree/'dir', *[tree/n for n in ['file','dir/inside','owner','group']]]: os.chown(p,uid,gid)
        for name in ['owner','group']:os.chown(tree/name,1002,1002)
        (tree/'group').chmod(0o040)
    principal=lambda n:'principal:'+format(n,'032x')
    group=lambda n:'group:'+format(n,'032x')
    def authority(n,u,g,groups,override=False):
        return dict(principal=principal(n),uid=u,primary_group=group(g),gid=g,groups=[group(x) for x in groups],dac_override=override,ownership_transfer=True)
    authorities=[authority(1,uid,gid,[gid])]
    if linux:
        authorities += [authority(2,1002,1002,[1001,1002]),authority(3,1003,1001,[1001]),authority(4,0,0,[0,1001,1002],True)]
    cfg={'replica':{'replica':'replica:'+'1'*32,'authorities':authorities,'content_roots':[str(tree),str(view)],'cache_bytes':33554432},'root':str(tree),'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
    (base/'config.json').write_text(json.dumps(cfg))
    report={'platform':platform.platform(),'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'commands':[],'processes':[],'cases':{},'cleanup':[],'passed':False}
    process=None
    def save(): (base/'result.json').write_text(json.dumps(report,indent=2))
    def command(argv,check=True,**kwargs):
        p=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=20,**kwargs)
        report['commands'].append({'argv':list(map(str,argv)),'uid':kwargs.get('user',os.geteuid()),'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr});save()
        if check:assert p.returncode==0,report['commands'][-1]
        return p
    def cli(name,*args):return json.loads(command([binary,name,'--state',base/'state',*args]).stdout)
    def user(code,u=uid,g=gid):
        # No credentials, host mounts or existing data; all foreign IDs are synthetic Linux users.
        kwargs=dict(user=u,group=g,extra_groups=[]) if linux else {}
        return command([sys.executable,'-c','import os,json,errno,pathlib;v=pathlib.Path('+repr(str(view))+');'+code],**kwargs)
    def mounted():
        if linux:return any(line.split()[4]==str(view) for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines())
        return ' on '+str(view)+' (' in subprocess.check_output(['/sbin/mount'],text=True)
    def mount(revision,mode):
        nonlocal process
        argv=[str(binary),'mount','--state',str(base/'state'),'--revision',revision,'--mountpoint',str(view),'--mode',mode]
        log=base/('daemon-'+str(len(report['processes']))+'.log')
        with log.open('w') as output:process=subprocess.Popen(argv,stdout=output,stderr=output)
        report['processes'].append({'pid':process.pid,'argv':argv,'log':str(log)});save()
        deadline=time.monotonic()+20
        while not mounted():
            assert process.poll() is None and time.monotonic()<deadline,(process.poll(),log.read_text());time.sleep(.05)
    def unmount():
        nonlocal process
        if mounted():command(['umount' if linux else '/sbin/umount',view])
        assert not mounted()
        if process:
            if not linux and process.poll() is None:process.terminate()
            exit_code=process.wait(timeout=10)
            report['cleanup'].append({'pid':process.pid,'exit':exit_code,'mount_absent':True});process=None
        if view.exists():view.rmdir()
        save()
    def checkpoint():
        s=cli('status');return cli('checkpoint','--operation-id','operation:'+os.urandom(16).hex(),'--expected-generation',s['working_generation'])['revision']
    def denies(code,allowed='(errno.EACCES,errno.EPERM)'):
        return '\ntry: '+code+'\nexcept OSError as e: assert e.errno in '+allowed+';print(json.dumps({"errno":e.errno}))\nelse: raise AssertionError("unexpected permission grant")'
    try:
        cli('init','--config',base/'config.json');first=cli('capture','--root',tree,'--operation-id','operation:'+'1'*32)['revision']
        mount(first,'private')
        user("os.chmod(v/'file',0);os.chmod(v/'dir',0)")
        old=checkpoint()
        user("os.chmod(v/'file',0o600);os.chmod(v/'dir',0o700);(v/'file').write_bytes(b'current longer bytes than history')")
        if linux:user("os.chown(v/'owner',1001,1001);os.chown(v/'group',1002,1001)",0,0)
        current=checkpoint();granted=current;unmount();mount(old,'read-only')
        result=user("f=os.open(v/'file',os.O_RDONLY);s=os.fstat(f);data=os.read(f,100);os.close(f);assert data==b'old historical bytes';assert s.st_size==20 and s.st_mode&511==0o600;assert (v/'dir').stat().st_mode&511==0o700;assert (v/'dir/inside').read_bytes()==data;print(json.dumps({'file_mode':s.st_mode&511,'size':s.st_size,'uid':s.st_uid,'gid':s.st_gid,'historical_bytes':data.decode(),'ancestor_mode':(v/'dir').stat().st_mode&511}))")
        report['cases']['later_file_and_ancestor_grants']=json.loads(result.stdout)
        if linux:
            result=user("s=(v/'owner').stat();assert (s.st_uid,s.st_gid)==(1001,1001);assert (v/'owner').read_bytes()==b'old historical bytes';print(json.dumps({'uid':s.st_uid,'gid':s.st_gid}))")
            report['cases']['later_owner_grant']=json.loads(result.stdout)
            result=user("s=(v/'group').stat();assert (s.st_uid,s.st_gid)==(1002,1001);assert (v/'group').read_bytes()==b'old historical bytes';print(json.dumps({'uid':s.st_uid,'gid':s.st_gid}))",1003,1001)
            report['cases']['later_group_grant']=json.loads(result.stdout)
        for u,g in ([(uid,gid),(0,0)] if linux else [(uid,gid)]):
            for name,code in [('write',"os.open(v/'file',os.O_WRONLY)"),('chmod',"os.chmod(v/'file',0o777)"),('create',"os.open(v/'new',os.O_WRONLY|os.O_CREAT,0o600)"),('unlink',"os.unlink(v/'file')")]:
                result=user(denies(code,'(errno.EROFS,)'),u,g);report['cases'][f'readonly_{u}_{name}']=json.loads(result.stdout)
        unmount();mount(current,'private')
        user("os.chmod(v/'file',0);os.chmod(v/'dir',0)")
        if linux:user("os.chown(v/'owner',1002,1002);os.chown(v/'group',1002,1002)",0,0)
        current=checkpoint();unmount();mount(granted,'read-only')
        for name in ['file','dir/inside']:
            result=user(denies('(v/'+repr(name)+').read_bytes()'));report['cases']['later_revoke_'+name]=json.loads(result.stdout)
        if linux:
            report['cases']['later_owner_revocation']=json.loads(user(denies("(v/'owner').read_bytes()")).stdout)
            report['cases']['later_group_revocation']=json.loads(user(denies("(v/'group').read_bytes()"),1003,1001).stdout)
        unmount();report['revisions']={'historical':old,'granted':granted,'current':current};report['passed']=True
    finally:
        try:unmount()
        except BaseException as error:
            report['cleanup_failure']=repr(error);save()
            # Leave serving process alive, and report exact resources for supervised cleanup.
            raise
        save()
        print(json.dumps(report,indent=2), flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=pathlib.Path,required=True);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args();run(args.binary.resolve(),args.output)
