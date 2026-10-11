#!/usr/bin/env python3
"""R49 focused real-process correction proof; exact release image required.

Two independent invocations qualify the changed boundaries only. Original app/agent/
archive cohorts keep their original source identities. This runner never rewrites them.
"""
import argparse, copy, hashlib, json, os, secrets, sys, time, traceback
from pathlib import Path
from infra import OwnedInfra, ROOT
from provenance import capture, verify_image, sources
from reconciliation import Reconciliation
from linux_live import LiveJourney
from service_protocol import identity, file_entry, GROUP, REPLICA
from service_storage import NS, ALICE, object_id

class FinalReview(Reconciliation):
    def run(self):
        super().run()
        self.collision_selection()
        self.current_ancestor()
        self.live_import()
        self.scoped_negatives()
        self.identity_rulings()

    def collision_selection(self):
        self.mounted = LiveJourney(self.i,self.image);m=self.mounted;m.tokens=self.tokens;m.ca=self.ca;m.root=self.root
        m.daemon=self.i.create('container','collision-mount',['--network',self.i.ingress,'--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','DAC_OVERRIDE','--security-opt','apparmor=unconfined','--security-opt','no-new-privileges','--device','/dev/fuse','--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/private:rw,nosuid,nodev,mode=700,size=256m','--tmpfs','/shared:rw,nosuid,nodev,mode=755,size=16m',self.image,'python3','-c',"import os,signal,time\ndef reap(*a):\n while True:\n  try:p,s=os.waitpid(-1,os.WNOHANG)\n  except ChildProcessError:return\n  if p==0:return\nsignal.signal(signal.SIGCHLD,reap)\nwhile True:time.sleep(.2)"])
        self.i.docker('start',m.daemon)
        for n, (reverse, select) in enumerate([(False, 'current'), (True, 'current'), (False, 'candidate'), (True, 'candidate')]):
            prefix = 'reports/final-' + str(n)
            a, b, x = prefix + '-a', prefix + '-b', prefix + '-x'
            rx = prefix + '-X' if reverse else x
            ids = ['entry:' + f'{10000+n*2+k:032x}' for k in ([1,0] if reverse else [0,1])]
            def seed(t):
                parent = next(e['id'] for e in t['entries'] if e['path'] == 'reports')
                for path, eid, data in [(a, ids[0], b'identity A'), (b, ids[1], b'identity B')]:
                    e = file_entry(path, parent, data);e['id'] = eid;t['entries'].append(e)
            self.publish_tree(seed, [b'identity A', b'identity B'], 'collision-seed')
            name='collision-'+str(n);mounted=m.start(name,publication='isolated');state='/private/'+name+'/state'
            m.execute("import os,json,sys;s=json.load(sys.stdin);os.rename(s[0],s[1]);print('{}')",['/shared/'+name+'/'+b,'/shared/'+name+'/'+rx],user='1001:1001')
            checkpoint=m.cli('checkpoint','--state',state,'--operation-id',identity('operation'));revision=checkpoint['revision']
            held=m.cli('sync','drain','--state',state,'--revision',revision,'--level','private-remote','--deadline-ms','15000')['progress']
            history=m.cli('history','--state',state)['revisions'];candidate=next(r['descriptor'] for r in history if r['revision']==revision)
            candidate_entries={e['id']:e for e in candidate['tree']['entries']}
            assert candidate_entries[ids[0]]['path']==a and candidate_entries[ids[1]]['path']==rx, candidate
            advanced=self.publish_tree(lambda t: next(e for e in t['entries'] if e['id'] == ids[0]).update(path=x), label='current-rename')
            integrated=m.cli('sync','integrate','--state',state,'--revision',revision,'--expected-head',advanced['head'])['progress']
            assert integrated['error']=='conflicted', integrated
            items=[i for i in m.cli('sync','conflicts','list','--state',state)['page']['items'] if i['receipt']==held['private_receipt']['receipt']]
            assert len(items)==2 and all(i['reason']=='path_collision' for i in items),items
            self.i.write_json('collision-input-'+str(n)+'.json',{'base':mounted['binding'],'candidate':candidate,'current':self.tree()[2],'ids':ids,'selection':select,'conflicts':items})
            args=['sync','resolve','--state',state,'--conflicts',','.join(i['id'] for i in items),'--expected-head',self.head(),'--select',select]
            decision=m.execute("import json,subprocess,sys;s=json.load(sys.stdin);p=subprocess.run(['magus-fs',*s],capture_output=True,text=True,timeout=30);print(json.dumps({'exit':p.returncode,'body':json.loads(p.stdout)}))",args)
            result=decision['body']['progress']
            assert decision['exit']!=0 and decision['body']['error']=='durability_unmet' and result['state']=='PrivateRemote' and result['shared_receipt'] is None,decision
            replacement=next(r['descriptor'] for r in m.cli('history','--state',state)['revisions'] if r['revision']==result['local_revision'])
            self.i.write_json('collision-private-decision-'+str(n)+'.json',{'decision':decision,'replacement':replacement})
            # Resolve is explicit publication authority even for an isolated owner.
            # Its first bounded tick may only reach PrivateRemote. Resume the saved
            # resolution by its original operation, never create another target.
            result=m.cli(*args,'--operation-id',result['operation'])['progress']
            assert result['state']=='Shared' and result['resolution'] and result['shared_receipt'],result
            shared=result['shared_receipt'];assert self.head()==shared['head']
            v, files, _ = self.tree();expected = [(x,ids[0],b'identity A'),(b,ids[1],b'identity B')] if select == 'current' else [(a,ids[0],b'identity A'),(rx,ids[1],b'identity B')]
            for path,eid,data in expected:
                assert files[path]['id'] == eid and self.body(v,files[path]) == data
            self.record('linux','selected-collision-arrangement',reverse=reverse,selection=select,conflicts=items,resolution=result,shared=shared,expected=[{'path':p,'id':eid,'sha256':hashlib.sha256(d).hexdigest()} for p,eid,d in expected])
            m.unmount(name);m.mounts.remove(name)
        readonly=m.start('readonly-final',readonly=True,publication='isolated');state='/private/readonly-final/state'
        guards=m.execute("import json,subprocess,sys;s=json.load(sys.stdin);out={}\nfor action in ['import','compare']:\n p=subprocess.run(['magus-fs','sync','recovery',action,'--state',s,'--archive','/private/nonexistent']+(['--operation-id','operation:'+'1'*32] if action=='import' else []),capture_output=True,text=True,timeout=10);out[action]=json.loads(p.stdout)\nprint(json.dumps(out))",state)
        assert guards['import']['error']=='read_only' and guards['compare']['error']=='io_error',guards
        self.record('linux','readonly-live-owner-recovery-guards',owner=readonly,responses=guards)
        m.unmount('readonly-final');m.mounts.remove('readonly-final')

    def cleanup(self):
        if hasattr(self,'mounted'):self.mounted.cleanup()
        super().cleanup()

    def current_ancestor(self):
        principal = 'principal:' + f'{99:032x}'; replica = identity('replica'); token = secrets.token_hex(32)
        self.tokens['ancestor-reader'] = token
        authority = {'principal':principal,'uid':1002,'gid':1002,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':principal,'replica':replica,'token':token,'expires':int(time.time())+1800,'actions':['read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority}])
        def seed(t):
            public = {'path':'public-final','id':identity('entry'),'parent':t['root']['id'],'owner':ALICE,'group':GROUP,'mode':0o777,'content':{'kind':'directory'}}
            private = {**public,'path':'private-final','id':identity('entry')}
            f = file_entry('public-final/f',public['id'],b'ancestor base');f['mode']=0o666
            t['entries'].extend([public,private,f])
        self.publish_tree(seed,[b'ancestor base'],'ancestor-seed')
        view, r = self.view('ancestor-reader');r['principal']=principal
        f = next(e for e in r['tree']['entries'] if e['path']=='public-final/f');eid=f['id'];f['content']=file_entry('x',f['parent'],b'ancestor private alternative')['content']
        self.set_file('public-final/f',b'ancestor current','ancestor-current',mode=0o666)
        _, private = self.submit('ancestor-reader',replica,view,r,[b'ancestor private alternative'])
        conflicted=self.expect('ancestor-conflict','POST',self.root+'/integrations',409,body=self.integrate_request(private,{'head':self.head()}),actor='ancestor-reader')
        cid=conflicted['conflicts'][0];url=self.root+'/conflicts/'+cid
        detail=self.expect('ancestor-detail','GET',url,200,actor='ancestor-reader');alt=next(a for a in detail['alternatives'] if a['side']=='candidate');pinurl=url+'/alternatives/'+alt['id']
        pin=self.expect('ancestor-pin','GET',pinurl,200,actor='ancestor-reader');descurl=self.root+'/views/'+pin['view']+'/descriptor';objurl=self.root+'/views/'+pin['view']+'/objects/'+object_id(b'ancestor private alternative')
        assert self.bytes_request(objurl,'ancestor-reader')==(200,b'ancestor private alternative')
        def move(t):
            e=next(e for e in t['entries'] if e['id']==eid);e.update(path='private-final/f',parent=next(e['id'] for e in t['entries'] if e['path']=='private-final'))
        self.publish_tree(move,label='ancestor-move-within-scope')
        self.expect('ancestor-moved-pin-readable','GET',descurl,200,actor='ancestor-reader')
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='private-final').update(mode=0o700),label='ancestor-revoke-traverse')
        assert cid not in [c['id'] for c in self.conflicts('ancestor-reader')]
        for label,url_ in [('detail',url),('fresh-pin',pinurl),('issued-descriptor',descurl)]:
            self.expect('ancestor-denied-'+label,'GET',url_,404,{'code':'not_found'},actor='ancestor-reader')
        assert self.bytes_request(objurl,'ancestor-reader')[0]==404
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='private-final').update(mode=0o777),label='ancestor-restore-traverse')
        assert cid in [c['id'] for c in self.conflicts('ancestor-reader')]
        for label,url_ in [('detail',url),('fresh-pin',pinurl),('issued-descriptor',descurl)]:self.expect('ancestor-restored-'+label,'GET',url_,200,actor='ancestor-reader')
        assert self.bytes_request(objurl,'ancestor-reader')==(200,b'ancestor private alternative')
        self.record('service','current-ancestor-revocation',conflict=cid,entry=eid,pin=pin,list_detail_fresh_pin_issued_descriptor_object_denied=True,rights_restoration=True)

    def live_import(self):
        for ep in self.endpoints:
            c=ep.create('live-import');ep.start(c);self.until(lambda:ep.ready(c),25);ep.stop(c)
            local=self.ok(ep,c,'status')['captured_revision'];archive=c['path']+'/archive'
            exported=self.ok(ep,c,'export','--revision',local,'--destination',archive)
            verified=ep.run("p=subprocess.run([s[0],'verify','--archive',s[1]],capture_output=True,text=True,timeout=15);assert p.returncode==0,(p.stdout,p.stderr);print(p.stdout)",[ep.binary,archive])
            ep.start(c);self.until(lambda:ep.ready(c),25);pid=c['pid'];before=self.head();status=self.ok(ep,c,'status');queue=self.subs(ep,c)
            compared=self.ok(ep,c,'sync','recovery','compare','--archive',archive)
            operation=identity('operation');imported=self.ok(ep,c,'sync','recovery','import','--archive',archive,'--operation-id',operation)
            replay=self.ok(ep,c,'sync','recovery','import','--archive',archive,'--operation-id',operation)
            assert imported==replay and not imported['recovery']['published'] and imported['recovery']['source_revision']==local
            assert compared['published'] is False and compared['changed_paths']==[]
            assert self.ok(ep,c,'status')['captured_revision']==status['captured_revision'] and self.subs(ep,c)==queue and self.head()==before
            assert imported['recovery'] in self.ok(ep,c,'sync','recovery','list')['imports']
            ep.run("os.kill(s,0);print('{}')",pid)
            # Archive validation still rejects corruption through the live owner.
            broken=c['path']+'/broken-archive'
            ep.run("import shutil\nshutil.copytree(s[0],s[1]);open(s[1]+'/archive.json','w').write('{}');print('{}')",[archive,broken])
            invalid=self.fail(ep,c,'sync','recovery','import','--archive',broken,'--operation-id',identity('operation'))
            assert self.head()==before and self.ok(ep,c,'status')['captured_revision']==local
            self.record(ep.platform,'live-owner-import-compare',pid=pid,exported=exported,verified=verified,comparison=compared,imported=imported,replay=replay,invalid_archive=invalid,shared_head_before=before,shared_head_after=self.head(),local_head=local,owner_stayed_alive=True)
            ep.stop(c)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--image',required=True);a=ap.parse_args()
    i=OwnedInfra(a.output);i.runtime_profile='release';j=None;code=1
    try:
        i.preflight();source=capture(i);image=json.loads(i.docker('image','inspect',a.image).stdout)[0]
        assert image['Config']['Labels']['magus.fs2.build-profile']=='release'
        i.setup(image['Id']);verify_image(i,source,host_profile='release')
        names=['magus-fs','magus-fs-client-faults','magus-fs-service','magus-fs-service-faults']
        i.write_json('runtime-binaries.json',{'host':{n:hashlib.sha256((ROOT/'target/release'/n).read_bytes()).hexdigest() for n in names},'linux':{n:i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+n).stdout.split()[0] for n in names},'image':image['Id'],'profile':'release'})
        j=FinalReview(i,image['Id'],['macos','linux'],['final']);j.run();assert sources()==source['sha256'];i.write_json('source-after.json',source);code=0
    except Exception as e:
        i.write_json('failure.json',{'reason':str(e),'trace':traceback.format_exc()});traceback.print_exc()
        if hasattr(i,'service'):
            log=i.docker('exec',i.service,'cat','/tmp/service.log',check=False,evidence=False);(i.output/'service.log').write_text(log.stdout+log.stderr)
    finally:
        errors=[]
        for action in ([j.cleanup] if j else [])+[i.cleanup]:
            try:action()
            except Exception as e:errors.append(repr(e));code=1
        i.write_json('result.json',{'exit':code,'passed':code==0,'scope':'R49 affected collision/current-ancestor/live-owner plus existing scoped and identity negatives','complete_poc':False,'cleanup_errors':errors})
    return code
if __name__=='__main__':sys.exit(main())
