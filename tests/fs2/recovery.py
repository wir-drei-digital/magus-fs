#!/usr/bin/env python3
"""Task 3 real authenticated history/recovery gate. Focused runs are incomplete evidence."""
import argparse, concurrent.futures, copy, hashlib, json, os, secrets, shutil, sys, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture, verify_image, resolve_reused_image, sources
from reconciliation import Reconciliation
from service_protocol import identity, file_entry, GROUP, REPLICA
from service_storage import NS, ALICE, object_id
from full_native import Endpoint

class Recovery(Reconciliation):
    CASES = ['history', 'storage', 'reconnect', 'offline']
    def __init__(self, i, image, platforms, cases):
        super().__init__(i, image, platforms, ['recovery']);self.cases = cases
    def candidate(self, view, r, actor='worker', bodies=(), drop=False):
        if actor=='alice':r['principal']=ALICE
        return super().candidate(view,r,actor,bodies,drop)
    def run(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.tokens['alice']=secrets.token_hex(32)
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':self.tokens['alice'],'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history','retained_history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        self.expected_live=b'old content'
        self.warm_storage()
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':493,'content':{'kind':'directory'}}
        secret={**reports,'path':'secret','id':identity('entry')}
        seed=[reports,secret,file_entry('reports/live',reports['id'],b'old content'),file_entry('secret/private',secret['id'],b'hidden content')]
        seed[2]['mode']=0o644
        upload,rid=self.stage(self.descriptor(seed),bodies=[b'old content',b'hidden content'])
        self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        if 'history' in self.cases:self.history_cases()
        if 'reconnect' in self.cases:self.reconnect_cases()
        if 'offline' in self.cases:self.offline_cases()
        if 'storage' in self.cases:self.storage_cases()
    def grant(self, actions, prefixes, actor):
        replica=identity('replica');g=self.expect('grant-'+actor,'POST',self.root+'/grants',200,body={'delegate':{'replica':replica,'expires':int(time.time())+1800,'actions':actions,'branches':['main'],'prefixes':prefixes}});self.tokens[actor]=g['token'];return replica,g
    def history(self, view, actor='alice', cursor=None):
        return self.expect('history-page','GET',self.root+'/history?view='+view['view']+('' if cursor is None else '&cursor='+cursor),200,actor=actor)
    def history_cases(self):
        original,files,_=self.tree();oldid=files['reports/live']['id']
        self.set_file('reports/live',b'new content','advance',mode=0o600)
        current,files,_=self.tree();page=self.history(current);old=next(x for x in page['items'] if x['entry']==oldid)
        historical=self.expect('history-pin','POST',self.root+'/history/'+old['id']+'/view',200,body={})
        data=self.expect_bytes('historical-descriptor',self.root+'/views/'+historical['view']+'/descriptor')
        desc=json.loads(data);assert desc['parents']==[] and all(e['path'].startswith('reports') for e in desc['tree']['entries'])
        selected=next(e for e in desc['tree']['entries'] if e['id']==oldid);assert self.body(historical,selected)==b'old content'
        reader,rg=self.grant(['read'],['reports'],'reader');rv,_=self.view('reader')
        self.expect('reader-no-history','GET',self.root+'/history?view='+rv['view'],404,{'code':'not_found'},actor='reader')
        scoped,sg=self.grant(['read','write','history','integrate'],['reports'],'historian');hv,_=self.view('historian')
        listing=self.history(hv,'historian');assert all(x['entry']!=files['secret/private']['id'] for x in listing['items'])
        self.expect('foreign-pin','POST',self.root+'/history/'+old['id']+'/view',404,{'code':'not_found'},actor='historian',body={})
        request={'operation':identity('operation'),'replica':REPLICA,'history':old['id'],'expected_head':current['head'],'restore_metadata':False}
        before=int(self.sql('SELECT count(*) FROM changes;'));restored=self.expect('restore','POST',self.root+'/restores',200,body=request)
        view,files,full=self.tree();assert files['reports/live']['mode']==0o600 and self.body(view,files['reports/live'])==b'old content';assert self.body(view,files['secret/private'])==b'hidden content'
        assert full['parents']==[] and 'restoration' not in full
        self.expect('restore-replay','POST',self.root+'/restores',200,restored,body=request);self.expect('restore-lookup','GET',self.op_path(request),200,restored)
        assert int(self.sql('SELECT count(*) FROM changes;'))==before+1
        metadata_request={**request,'operation':identity('operation'),'expected_head':self.head(),'restore_metadata':True}
        self.expect('explicit-metadata-restore','POST',self.root+'/restores',200,body=metadata_request)
        assert self.tree()[1]['reports/live']['mode']==0o644
        self.expect('restore-changed-digest' ,'POST',self.root+'/restores',409,{'code':'conflict'},body={**request,'restore_metadata':True})
        code,source=self.request('POST',self.root+'/history/'+old['id']+'/view',body={});assert code==200
        self.publish_tree(lambda t:t['entries'].__setitem__(slice(None),[e for e in t['entries'] if e['id']!=oldid]),label='delete')
        self.expect('deleted-ordinary-history','POST',self.root+'/history/'+next(x['id'] for x in listing['items'] if x['entry']==oldid)+'/view',404,{'code':'not_found'},actor='historian',body={})
        pinned=self.expect('deleted-admin-pin','POST',self.root+'/history/'+old['id']+'/view',200,body={})
        self.expect('old-pin-admin-authorized','GET',self.root+'/views/'+pinned['view']+'/descriptor',200)
        self.sql("UPDATE grants SET actions=array_remove(actions,'retained_history') WHERE credential=(SELECT id FROM credentials WHERE token_hash='"+hashlib.sha256(self.tokens['alice'].encode()).hexdigest()+"');")
        self.expect('retained-pin-current-grant-denial','GET',self.root+'/views/'+pinned['view']+'/descriptor',404,{'code':'not_found'})
        assert self.bytes_request(self.root+'/views/'+pinned['view']+'/objects/'+object_id(b'old content'))[0]==404
        self.sql("UPDATE grants SET actions=array_append(actions,'retained_history') WHERE credential=(SELECT id FROM credentials WHERE token_hash='"+hashlib.sha256(self.tokens['alice'].encode()).hexdigest()+"');")
        request2={**request,'operation':identity('operation'),'expected_head':self.head()}
        self.expect('deleted-admin-restore','POST',self.root+'/restores',200,body=request2)
        v,f,r=self.tree();assert f['reports/live']['id']!=oldid and f['reports/live']['mode']==0o644 and self.body(v,f['reports/live'])==b'old content'
        replay_count=int(self.sql('SELECT count(*) FROM changes;'))
        self.expect('restore-replay-after-fresh-identity','POST',self.root+'/restores',200,restored,body=request)
        self.expect('restore-lookup-after-fresh-identity','GET',self.op_path(request),200,restored)
        self.expect('new-restore-name-collision','POST',self.root+'/restores',404,{'code':'not_found'},body={**request,'operation':identity('operation'),'expected_head':self.head()})
        assert int(self.sql('SELECT count(*) FROM changes;'))==replay_count
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o555),label='deny-replay-parent-write')
        self.expect('restore-replay-current-parent-write-denial','POST',self.root+'/restores',404,{'code':'not_found'},body=request)
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o755),label='restore-replay-parent-write')
        rv,rf=self.view('reader');assert 'restoration' not in rf and self.body(rv,next(e for e in rf['tree']['entries'] if e['path']=='reports/live'),'reader')==b'old content'
        guest='principal:'+'d'*32;self.tokens['guest']=secrets.token_hex(32)
        self.i.provision([{'namespace':NS,'principal':guest,'replica':identity('replica'),'token':self.tokens['guest'],'expires':int(time.time())+1800,'actions':['read','history','admin','retained_history'],'branches':['main'],'prefixes':['reports'],'authority':{'principal':guest,'uid':1002,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}}])
        gv,_=self.view('guest');gp=self.history(gv,'guest');gh=next(x['id'] for x in gp['items'] if x['entry']==f['reports/live']['id'])
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o700),label='deny-parent')
        self.expect('current-parent-denial','POST',self.root+'/history/'+gh+'/view',404,{'code':'not_found'},actor='guest',body={})
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o755),label='restore-parent')
        # A pinned historical view rechecks grants for descriptor and object on every use.
        bound=self.expect('guest-history-pin','POST',self.root+'/history/'+gh+'/view',200,actor='guest',body={})
        self.sql("UPDATE grants SET actions=ARRAY['read'] WHERE credential=(SELECT id FROM credentials WHERE token_hash='"+hashlib.sha256(self.tokens['guest'].encode()).hexdigest()+"');")
        self.expect('pinned-history-grant-narrowing','GET',self.root+'/views/'+bound['view']+'/descriptor',404,{'code':'not_found'},actor='guest')
        assert self.bytes_request(self.root+'/views/'+bound['view']+'/objects/'+object_id(b'old content'),actor='guest')[0]==404
        fresh=self.tree()[1]['reports/live']['id'];scope_view,_=self.view('historian');ordinary_source=next(x['id'] for x in self.history(scope_view,'historian')['items'] if x['entry']==fresh)
        _,retained_grant=self.grant(['read','history','admin','retained_history'],['reports'],'retained-scoped');retained_view,_=self.view('retained-scoped')
        retained_source=next(x['id'] for x in self.history(retained_view,'retained-scoped')['items'] if x['entry']==fresh)
        def move_out(t):
            e=next(e for e in t['entries'] if e['id']==fresh);e['path']='secret/moved-live';e['parent']=next(e['id'] for e in t['entries'] if e['path']=='secret');e['mode']=0o600;e['content']=file_entry('x',e['parent'],b'new outside-scope bytes')['content']
        self.publish_tree(move_out,[b'new outside-scope bytes'],label='history-moved-out')
        self.expect('moved-ordinary-history-denied','POST',self.root+'/history/'+ordinary_source+'/view',404,{'code':'not_found'},actor='historian',body={})
        scoped_pin=self.expect('moved-retained-admin-old-source','POST',self.root+'/history/'+retained_source+'/view',200,actor='retained-scoped',body={})
        scoped_bytes=self.expect_bytes('scoped-descriptor',self.root+'/views/'+scoped_pin['view']+'/descriptor','retained-scoped')
        scoped_descriptor=json.loads(scoped_bytes);assert 'secret' not in scoped_bytes.decode() and object_id(b'new outside-scope bytes') not in scoped_bytes.decode()
        selected=next(e for e in scoped_descriptor['tree']['entries'] if e['id']==fresh);assert selected['mode']==0o644 and self.body(scoped_pin,selected,'retained-scoped')==b'old content'
        def move_back(t):
            e=next(e for e in t['entries'] if e['id']==fresh);e['path']='reports/live';e['parent']=next(e['id'] for e in t['entries'] if e['path']=='reports');e['mode']=0o644;e['content']=file_entry('x',e['parent'],b'old content')['content']
        self.publish_tree(move_back,[b'old content'],label='history-moved-back')
        self.expect('revoked-history' ,'POST',self.root+'/grants',200,body={'revoke':sg['credential']})
        assert self.request('GET',self.root+'/history?view='+hv['view'],actor='historian')[0]==401
        assert self.request('GET',self.root.replace(NS,'f'*32)+'/history?view='+view['view'])[0] in (401,404)
        view,r=self.view();parent=next(e['id'] for e in r['tree']['entries'] if e['path']=='reports')
        r['tree']['entries'].append(file_entry('reports/merge-private',parent,b'private merge ancestry'));r['tree']['entries'].sort(key=lambda e:e['path'])
        _,private=self.candidate(view,r,'alice',[b'private merge ancestry'])
        self.set_file('secret/merge-sibling',b'hidden merged sibling','history-dag-head')
        self.expect('history-dag-merge','POST',self.root+'/integrations',200,body=self.integrate_request(private,{'head':self.head()}))
        full_private=self.sql("SELECT derived_revision FROM operations WHERE receipt='"+private['receipt']+"';")
        assert self.sql("SELECT count(*) FROM published_entries WHERE namespace='"+NS+"' AND revision='"+full_private+"';")=='0'
        # One atomic publication supplies enough real entries to exercise paging.
        def many(t):
            parent=next(e['id'] for e in t['entries'] if e['path']=='reports')
            t['entries'].extend(file_entry('reports/page-%02d'%n,parent,b'') for n in range(35))
        self.publish_tree(many,label='history-pages');pv,_=self.view();pg=self.history(pv);assert len(pg['items'])<=32 and pg['next'] and len(json.dumps(pg).encode())<=65536
        pg2=self.history(pv,cursor=pg['next']);assert len(pg2['items'])<=32
        scoped_view,_=self.view('reader');self.expect('history-cursor-no-history','GET',self.root+'/history?view='+scoped_view['view']+'&cursor='+pg['next'],404,{'code':'not_found'},actor='reader')
        self.historical_path_policy(old)
        self.record('service','history-restore',new_revision=True,current_metadata=True,fresh_deleted_identity=True,hidden_sibling_untouched=True,no_projected_lineage=True,former_reader_denied=True,current_parent_denied=True,exact_replay_cardinality=True)
    def historical_path_policy(self, alice_source):
        guest='principal:'+'d'*32;replica=identity('replica');self.tokens['path-admin']=secrets.token_hex(32)
        self.i.provision([{'namespace':NS,'principal':guest,'replica':replica,'token':self.tokens['path-admin'],'expires':int(time.time())+1800,'actions':['read','write','history','admin','retained_history'],'branches':['main'],'prefixes':[''],'authority':{'principal':guest,'uid':1002,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}}])
        fresh=self.tree()[1]['reports/live']['id'];gv,_=self.view('path-admin');page=self.history(gv,'path-admin')
        while not any(x['entry']==fresh for x in page['items']):
            assert page['next'];page=self.history(gv,'path-admin',page['next'])
        source=next(x['id'] for x in page['items'] if x['entry']==fresh)
        self.publish_tree(lambda t:t['entries'].__setitem__(slice(None),[e for e in t['entries'] if e['id']!=fresh]),label='path-policy-delete')
        pinned=self.expect('path-policy-retained-pin','POST',self.root+'/history/'+source+'/view',200,actor='path-admin',body={})
        replacement=identity('entry')
        def move_parent(t):
            for e in t['entries']:
                if e['path']=='reports':e['path']='archive';e['mode']=0o777
                elif e['path'].startswith('reports/'):e['path']='archive/'+e['path'][8:]
            t['entries'].append({'path':'reports','id':replacement,'parent':t['root']['id'],'owner':ALICE,'group':GROUP,'mode':0o700,'content':{'kind':'directory'}})
        self.publish_tree(move_parent,label='path-policy-move-parent-replace')
        self.expect('path-policy-retained-pin-denied','POST',self.root+'/history/'+source+'/view',404,{'code':'not_found'},actor='path-admin',body={})
        self.expect('path-policy-issued-pin-denied','GET',self.root+'/views/'+pinned['view']+'/descriptor',404,{'code':'not_found'},actor='path-admin')
        assert self.bytes_request(self.root+'/views/'+pinned['view']+'/objects/'+object_id(b'old content'),'path-admin')[0]==404
        current,_=self.view('path-admin');page=self.history(current,'path-admin');items=page['items'][:]
        while page['next']:page=self.history(current,'path-admin',page['next']);items+=page['items']
        assert all(x['id']!=source for x in items)
        request={'operation':identity('operation'),'replica':replica,'history':source,'expected_head':self.head(),'restore_metadata':False}
        self.expect('path-policy-restore-denied','POST',self.root+'/restores',404,{'code':'not_found'},actor='path-admin',body=request)
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o755),label='path-policy-permit-read')
        self.expect('path-policy-issued-pin-recovered','GET',self.root+'/views/'+pinned['view']+'/descriptor',200,actor='path-admin')
        readable=self.expect('path-policy-retained-pin-recovered','POST',self.root+'/history/'+source+'/view',200,actor='path-admin',body={})
        raw=self.expect_bytes('readable-descriptor',self.root+'/views/'+readable['view']+'/descriptor','path-admin');assert 'archive' not in raw.decode()
        desc=json.loads(raw);parent=next(e for e in desc['tree']['entries'] if e['path']=='reports');assert parent['mode']==0o755
        assert self.body(readable,next(e for e in desc['tree']['entries'] if e['path']=='reports/live'),'path-admin')==b'old content'
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o775),label='path-policy-permit-write')
        request.update(expected_head=self.head());receipt=self.expect('path-policy-restore-rebound','POST',self.root+'/restores',200,actor='path-admin',body=request)
        v,f,_=self.tree();assert f['reports/live']['parent']==replacement and f['reports/live']['id']!=fresh and self.body(v,f['reports/live'])==b'old content'
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o700),label='path-policy-deny-replay')
        self.expect('path-policy-replay-denied','POST',self.root+'/restores',404,{'code':'not_found'},actor='path-admin',body=request)
        self.expect('path-policy-lookup-denied','GET',self.op_path(request),404,{'code':'not_found'},actor='path-admin')
        self.publish_tree(lambda t:next(e for e in t['entries'] if e['path']=='reports').update(mode=0o775),label='path-policy-permit-replay')
        count=self.sql('SELECT count(*) FROM changes;');self.expect('path-policy-replay-recovered','POST',self.root+'/restores',200,receipt,actor='path-admin',body=request);assert count==self.sql('SELECT count(*) FROM changes;')
        # Missing prefixes use current enclosing root policy for read/export, while
        # a new restore still requires an actual destination parent.
        self.publish_tree(lambda t:t['entries'].__setitem__(slice(None),[e for e in t['entries'] if e['path']!='reports' and not e['path'].startswith('reports/')]),label='path-policy-parent-absent')
        self.publish_tree(lambda t:t['root'].update(mode=0o775),label='path-policy-enclosing-root-write-permitted')
        missing=self.expect('path-policy-absent-parent-read','POST',self.root+'/history/'+source+'/view',200,actor='path-admin',body={})
        self.expect('path-policy-absent-parent-restore','POST',self.root+'/restores',404,{'code':'not_found'},actor='path-admin',body={**request,'operation':identity('operation'),'expected_head':self.head()})
        count=self.sql('SELECT count(*) FROM changes;')
        self.expect('path-policy-absent-parent-replay','POST',self.root+'/restores',200,receipt,actor='path-admin',body=request)
        self.expect('path-policy-absent-parent-lookup','GET',self.op_path(request),200,receipt,actor='path-admin');assert count==self.sql('SELECT count(*) FROM changes;')
        self.publish_tree(lambda t:t['root'].update(mode=0o555),label='path-policy-enclosing-root-write-denied')
        self.expect('path-policy-absent-parent-replay-write-denied','POST',self.root+'/restores',404,{'code':'not_found'},actor='path-admin',body=request)
        self.expect('path-policy-absent-parent-lookup-write-denied','GET',self.op_path(request),404,{'code':'not_found'},actor='path-admin')
        self.publish_tree(lambda t:t['root'].update(mode=0o775),label='path-policy-enclosing-root-write-permitted')
        self.publish_tree(lambda t:t['root'].update(mode=0o700),label='path-policy-enclosing-root-denied')
        self.expect('path-policy-absent-parent-root-denied','POST',self.root+'/history/'+source+'/view',404,{'code':'not_found'},actor='path-admin',body={})
        self.expect('path-policy-absent-issued-pin-root-denied','GET',self.root+'/views/'+missing['view']+'/descriptor',404,{'code':'not_found'},actor='path-admin')
        self.publish_tree(lambda t:t['root'].update(mode=0o755),label='path-policy-enclosing-root-permitted')
        self.publish_tree(lambda t:t['entries'].append(file_entry('reports',t['root']['id'],b'path blocker')),[b'path blocker'],label='path-policy-parent-nondirectory')
        self.expect('path-policy-nondirectory-denied','POST',self.root+'/history/'+source+'/view',404,{'code':'not_found'},actor='path-admin',body={})
        credential=self.sql("SELECT id FROM credentials WHERE token_hash='"+hashlib.sha256(self.tokens['path-admin'].encode()).hexdigest()+"';")
        self.expect('path-policy-revoke','POST',self.root+'/grants',200,actor='path-admin',body={'revoke':credential})
        self.expect('path-policy-revoked-replay','POST',self.root+'/restores',401,{'code':'invalid_credential'},actor='path-admin',body=request)
        self.expect('path-policy-revoked-lookup','GET',self.op_path(request),401,{'code':'invalid_credential'},actor='path-admin')
        def normal_parent(t):
            t['entries']=[e for e in t['entries'] if e['path']!='reports'];t['entries'].append({'path':'reports','id':identity('entry'),'parent':t['root']['id'],'owner':ALICE,'group':GROUP,'mode':0o755,'content':{'kind':'directory'}})
        self.publish_tree(normal_parent,label='path-policy-normal-parent')
        self.expect('path-policy-normal-restore','POST',self.root+'/restores',200,body={'operation':identity('operation'),'replica':REPLICA,'history':alice_source['id'],'expected_head':self.head(),'restore_metadata':False})
        v,f,_=self.tree();assert self.body(v,f['secret/private'])==b'hidden content' and self.body(v,f['reports/live'])==b'old content' and f['reports/live']['owner']==ALICE
        self.record('service','historical-path-parent-authority',replacement_parent_denied=True,issued_pin_rechecked=True,restored_parent_rebound=True,immutable_replay_current_policy=True,absent_prefix_enclosing_root=True,nondirectory_denied=True,hidden_sibling_unchanged=True)
    def cleanup(self):
        if getattr(self,'mounted',None):self.mounted.cleanup()
        super().cleanup()
    def gc(self, plan=None):
        args=['/usr/local/bin/magus-fs-service','gc',self.i.service_config,'--namespace',NS]
        args+=['--plan',plan] if plan else ['--dry-run']
        p=self.i.docker('exec',self.i.service,*args,check=False);assert p.returncode==0,(p.stdout,p.stderr);return json.loads(p.stdout)
    def storage_cases(self):
        orphan=b'gc expired unreferenced';upload=self.create('alice');oid=object_id(orphan)
        self.expect('gc-install','PUT',self.root+'/uploads/'+upload+'/objects/'+oid,200,raw=orphan)
        self.sql("UPDATE upload_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id='"+upload+"';UPDATE objects SET lease_until=clock_timestamp()-interval '1 second' WHERE object_id='"+oid+"';")
        view,files,_=self.tree();baseline=(self.head(),self.sql('SELECT count(*) FROM operations;'),self.sql('SELECT count(*) FROM changes;'))
        plan=self.gc();assert any(x['object']==oid for x in plan['objects']),plan
        # A new active session protects the original generation after a dry-run.
        active=self.create('alice');self.expect('renew-before-gc','PUT',self.root+'/uploads/'+active+'/objects/'+oid,200,raw=orphan)
        done=self.gc(plan['plan']);assert oid not in done['deleted']
        self.sql("UPDATE upload_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id='"+active+"';UPDATE objects SET lease_until=clock_timestamp()-interval '1 second' WHERE object_id='"+oid+"';")
        done=self.gc(self.gc()['plan']);assert oid in done['deleted'];assert baseline==(self.head(),self.sql('SELECT count(*) FROM operations;'),self.sql('SELECT count(*) FROM changes;'))
        # A referenced private candidate and its original base remain roots after lease
        # expiry. Dry-run preceding publication cannot retire that generation.
        data=b'gc concurrent publication';u=self.create('alice');obj=object_id(data)
        self.expect('gc-before-publish-install','PUT',self.root+'/uploads/'+u+'/objects/'+obj,200,raw=data)
        self.sql("UPDATE upload_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id='"+u+"';UPDATE objects SET lease_until=clock_timestamp()-interval '1 second' WHERE object_id='"+obj+"';")
        stale_plan=self.gc();v,r=self.view();parent=next(e['id'] for e in r['tree']['entries'] if e['path']=='reports');r['tree']['entries'].append(file_entry('reports/gc-retained',parent,data));r['tree']['entries'].sort(key=lambda e:e['path'])
        request,private=self.candidate(v,r,'alice',[data]);integration=self.integrate_request(private,v)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future=pool.submit(self.request,'POST',self.root+'/integrations',body=integration)
            collected=self.gc(stale_plan['plan']);status,shared=future.result();assert status==200 and obj not in collected['deleted']
        self.sql("UPDATE objects SET lease_until=clock_timestamp()-interval '1 second' WHERE object_id='"+obj+"';UPDATE upload_sessions SET expires=clock_timestamp()-interval '1 second' WHERE namespace='"+NS+"';")
        assert all(x['object']!=obj for x in self.gc()['objects'])
        # Kill an exact owned collector after its mark commit. Its saved plan resumes the
        # original generation; backend deletion is idempotent and cannot publish a witness.
        partial=b'interrupted collector';u=self.create('alice');obj2=object_id(partial)
        self.expect('gc-interrupted-install','PUT',self.root+'/uploads/'+u+'/objects/'+obj2,200,raw=partial)
        self.sql("UPDATE upload_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id='"+u+"';UPDATE objects SET lease_until=clock_timestamp()-interval '1 second' WHERE object_id='"+obj2+"';")
        interrupted=self.gc()['plan'];self.i.private('pause-gc','pause')
        self.i.docker('exec','-d',self.i.service,'sh','-c',"echo $$ > /tmp/gc-owned.pid; exec magus-fs-service-faults gc "+self.i.service_config+" --namespace "+NS+" --plan "+interrupted+" > /tmp/gc-owned.log 2>&1")
        self.until(lambda:self.i.docker('exec',self.i.service,'test','-f','/tmp/fs2-gc-barrier',check=False,evidence=False).returncode==0,10)
        assert self.sql("SELECT state FROM objects WHERE object_id='"+obj2+"';")=='deleting'
        old_generation=self.sql("SELECT generation FROM objects WHERE object_id='"+obj2+"';")
        v,r=self.view();parent=next(e['id'] for e in r['tree']['entries'] if e['path']=='reports');r['tree']['entries'].append(file_entry('reports/gc-contested',parent,partial));r['tree']['entries'].sort(key=lambda e:e['path']);r['parents']=[v['revision']];r['operation']=identity('operation');r['replica']=REPLICA
        competing_upload,competing_revision=self.stage(r,'alice',[])
        competing={'operation':r['operation'],'replica':REPLICA,'original_view':v['view'],'original_head':v['head'],'revision':competing_revision,'upload':competing_upload}
        def admission_state():
            return {'head':self.head(),'operations':self.sql('SELECT count(*) FROM operations;'),'references':self.sql('SELECT count(*) FROM revision_objects;'),'sessions':self.sql("SELECT count(*) FROM session_objects WHERE object_id='"+obj2+"';"),'generation':self.sql("SELECT generation FROM objects WHERE object_id='"+obj2+"';")}
        marked_state=admission_state()
        self.expect('gc-marked-upload-denied','PUT',self.root+'/uploads/'+competing_upload+'/objects/'+obj2,409,{'code':'conflict'},raw=partial)
        self.expect('gc-marked-reference-denied','POST',self.root+'/candidates',404,{'code':'not_found'},body=competing)
        assert admission_state()==marked_state and self.sql("SELECT state FROM objects WHERE object_id='"+obj2+"';")=='deleting'
        self.i.docker('exec',self.i.service,'python3','-c',"import os,signal;p=int(open('/tmp/gc-owned.pid').read());assert os.readlink('/proc/%d/exe'%p).endswith('magus-fs-service-faults');os.kill(p,signal.SIGKILL)")
        (self.i.control/'pause-gc').unlink();assert obj2 in self.gc(interrupted)['deleted']
        later_request,later_private=self.candidate(v,r,'alice',[partial]);fresh_generation=self.sql("SELECT generation FROM objects WHERE object_id='"+obj2+"';");assert fresh_generation!=old_generation
        later_integration=self.integrate_request(later_private,v);later_shared=self.expect('gc-fresh-generation-publish','POST',self.root+'/integrations',200,body=later_integration)
        current,entries,_=self.tree();assert self.body(current,entries['reports/gc-contested'])==partial
        assert self.sql("SELECT count(*) FROM revision_objects ro JOIN objects o ON o.namespace=ro.namespace AND o.object_id=ro.object_id AND o.generation=ro.generation WHERE ro.namespace='"+NS+"' AND o.state!='ready';")=='0'
        self.expect('gc-fresh-private-reconstructable','GET',self.op_path(later_request),200,later_private);self.expect('gc-fresh-shared-reconstructable','GET',self.op_path(later_integration),200,later_shared)
        self.record('service','gc-mark-before-admission',marked_state=marked_state,old_generation=old_generation,fresh_generation=fresh_generation,upload_denied=True,reference_denied=True,cardinality_unchanged=True,shared_receipt=later_shared,verified_body_hash=obj2)
        self.i.snapshot_volumes()
        for container in [self.i.pg,self.i.s3]:
            self.i.docker('kill','--signal','KILL',container);self.i.docker('start',container)
            if container==self.i.pg:self.until(lambda:self.i.docker('exec',self.i.pg,'pg_isready','-U','postgres',check=False,evidence=False).returncode==0,60)
            else:self.i.wait_s3('recovery-s3',require_volumes=True)
        self.stop_service();self.start_service();v,f,_=self.tree();assert self.body(v,f['reports/live'])==self.body(view,files['reports/live'])
        self.expect('private-receipt-after-backend-restart','GET',self.op_path(request),200,private)
        self.expect('shared-receipt-after-backend-restart','GET',self.op_path(integration),200,shared)
        target=f['reports/live']['content']['version']['extents'][0]['object'];key=self.sql("SELECT storage_key FROM objects WHERE object_id='"+target+"';")
        self.i.s3_request('PUT','/fs2/'+key,'corrupt generation')
        status,body=self.bytes_request(self.root+'/views/'+v['view']+'/objects/'+target);assert status==400 and json.loads(body)['code']=='corrupt_object'
        assert self.sql("SELECT state FROM objects WHERE object_id='"+target+"';")=='corrupt'
        # Content expected independently from this synthetic setup, never read corrupt source.
        original=self.expected_live
        self.i.private('repair-body',original.decode());self.i.copy_service_control('repair-body')
        immutable=self.sql("SELECT string_agg(revision||':'||encode(descriptor,'hex'),',' ORDER BY revision) FROM revisions WHERE namespace='"+NS+"';")
        receipts=self.sql("SELECT string_agg(operation||':'||digest||':'||result,',' ORDER BY operation) FROM operations WHERE namespace='"+NS+"';")
        self.i.private('repair-wrong','not canonical');self.i.copy_service_control('repair-wrong')
        denied=self.i.docker('exec',self.i.service,'magus-fs-service','repair',self.i.service_config,'--namespace',NS,'--object',target,'--source',self.i.service_control+'/repair-wrong',check=False);assert denied.returncode==1 and 'hash_mismatch' in denied.stderr
        self.i.private('pause-repair','pause')
        self.i.docker('exec','-d',self.i.service,'sh','-c',"echo $$ > /tmp/repair-owned.pid; exec magus-fs-service-faults repair "+self.i.service_config+" --namespace "+NS+" --object "+target+" --source "+self.i.service_control+"/repair-body > /tmp/repair-owned.log 2>&1")
        self.until(lambda:self.i.docker('exec',self.i.service,'test','-f','/tmp/fs2-repair-barrier',check=False,evidence=False).returncode==0,10)
        proposed=self.sql("SELECT generation FROM repair_attempts WHERE object_id='"+target+"' AND state='prepared';");assert proposed
        assert self.bytes_request(self.root+'/views/'+v['view']+'/objects/'+target)[0]==404
        self.i.docker('exec',self.i.service,'python3','-c',"import os,signal;p=int(open('/tmp/repair-owned.pid').read());assert os.readlink('/proc/%d/exe'%p).endswith('magus-fs-service-faults');os.kill(p,signal.SIGKILL)")
        (self.i.control/'pause-repair').unlink()
        repaired=self.i.docker('exec',self.i.service,'magus-fs-service','repair' ,self.i.service_config,'--namespace',NS,'--object',target,'--source',self.i.service_control+'/repair-body')
        assert json.loads(repaired.stdout)['repaired'] and json.loads(repaired.stdout)['generation']==proposed;assert self.body(v,f['reports/live'])==original
        assert immutable==self.sql("SELECT string_agg(revision||':'||encode(descriptor,'hex'),',' ORDER BY revision) FROM revisions WHERE namespace='"+NS+"';") and receipts==self.sql("SELECT string_agg(operation||':'||digest||':'||result,',' ORDER BY operation) FROM operations WHERE namespace='"+NS+"';")
        assert self.sql("SELECT count(*) FROM quarantined_generations WHERE object_id='"+target+"';")=='1'
        repaired_key=self.sql("SELECT storage_key FROM objects WHERE object_id='"+target+"';");self.i.s3_request('DELETE','/fs2/'+repaired_key)
        missing_code,missing_body=self.bytes_request(self.root+'/views/'+v['view']+'/objects/'+target)
        assert missing_code==503 and json.loads(missing_body)['code']=='base_unavailable' and self.sql("SELECT state FROM objects WHERE object_id='"+target+"';")=='corrupt'
        self.i.docker('exec',self.i.service,'magus-fs-service','repair',self.i.service_config,'--namespace',NS,'--object',target,'--source',self.i.service_control+'/repair-body');assert self.body(v,f['reports/live'])==original
        assert self.sql("SELECT count(*) FROM quarantined_generations WHERE object_id='"+target+"';")=='2' 
        plan=self.gc();assert all(x['object']!=target for x in plan['objects']),plan
        self.record('service','storage-gc-restart-quarantine',concurrent_publication=True,collector_killed_after_mark=True,lease_rechecked=True,expired_deleted=True,roots_retained=True,pg_s3_service_process_restart=True,corrupt_quarantined=True,cardinality_unchanged=True)
    def reconnect_cases(self):
        for ep in [Endpoint(self,p,self.image) for p in self.platforms]:
            self.endpoints.append(ep);c=ep.create('reconnect');ep.start(c);self.until(lambda:ep.ready(c),20)
            self.stop_service();ep.write(c,b'queued original across partition');self.until(lambda:len(self.subs(ep,c))>0,10)
            original=copy.deepcopy(self.subs(ep,c)[-1]);ep.stop(c,kill=True);ep.start(c);self.start_service()
            self.until(lambda:any(s['state']=='Shared' for s in self.subs(ep,c)),30);done=self.subs(ep,c)[-1]
            assert done['operation']==original['operation'] and done['local_revision']==original['local_revision']
            before=(done['request']['original_view'],done['request']['original_head'],done['request_digest']);ep.stop(c,kill=True);ep.start(c);self.until(lambda:ep.ready(c),20)
            after=self.subs(ep,c)[-1];assert before==(after['request']['original_view'],after['request']['original_head'],after['request_digest'])
            # Expire only the synthetic feed; owner must resnapshot while retaining candidates.
            ep.stop(c);old_cursor=ep.status(c)['status']['incoming']['cursor']
            self.set_file('reports/cursor-new',b'cursor expiry snapshot','cursor-new')
            cursor=self.sql("SELECT COALESCE(max(sequence),0) FROM changes;");assert int(cursor)>old_cursor
            self.sql("INSERT INTO change_retention(namespace,branch,floor) VALUES('"+NS+"','main',"+cursor+") ON CONFLICT(namespace,branch) DO UPDATE SET floor=excluded.floor;")
            ep.start(c);self.until(lambda:ep.status(c)['status']['incoming']['cursor']>=int(cursor),15)
            self.record(ep.platform,'reconnect-original-and-cursor',operation=done['operation'],original_base=before,private_receipt=done['private_receipt'],shared_receipt=done['shared_receipt'],cursor_recovered=True)
            ep.stop(c);self.repeated_crashes(ep);self.apply_crashes(ep)
    def repeated_crashes(self,ep):
        c=ep.create('crash-boundaries');points=['sync-upload-created','sync-before-send','sync-lost-ack','sync-lost-ack'];proof=[]
        for n,point in enumerate(points):
            ep.start(c,fault=point)
            if n==0:
                self.until(lambda:ep.ready(c),20);ep.write(c,b'repeated upload private integration crashes')
            self.until(lambda:ep.exists(c['marker']),40);ep.stop(c,kill=True)
            progress=self.subs(ep,c)[-1];proof.append(copy.deepcopy(progress))
            assert progress['request']['original_view']==proof[0]['request']['original_view'] and progress['request']['original_head']==proof[0]['request']['original_head'] and progress['local_revision']==proof[0]['local_revision']
        ep.start(c);self.until(lambda:any(p['state']=='Shared' for p in self.subs(ep,c)),30);self.until(lambda:ep.ready(c),20)
        final=self.subs(ep,c)[-1];assert final['request']==proof[0]['request'] and final['request_digest']==proof[0]['request_digest']
        assert self.sql("SELECT count(*) FROM operations WHERE operation='"+final['operation']+"';")=='1'
        assert self.sql("SELECT count(*) FROM operations WHERE operation='"+final['integration']['operation']+"';")=='1'
        assert self.sql("SELECT count(*) FROM changes WHERE head='"+final['shared_receipt']['head']+"';")=='1'
        self.expected_live=b'repeated upload private integration crashes'
        self.record(ep.platform,'repeated-boundary-crashes',points=points,progress=proof,final=final,exact_operation_and_event_cardinality=True);ep.stop(c)
    def apply_crashes(self,ep):
        c=ep.create('apply-recovery');ep.start(c);self.until(lambda:ep.ready(c),20);ep.stop(c)
        ep.start(c,fault='native-before-commit');self.until(lambda:ep.ready(c),20)
        shared=self.set_file('reports/live',b'apply crash recovered exact bytes','apply-recovery-shared');count=self.sql('SELECT count(*) FROM changes;');proof=[]
        for attempt in range(2):
            ep.barrier(c);ep.stop(c,kill=True);proof.append(ep.status(c)['native'])
            if attempt==0:ep.start(c,fault='native-before-commit')
        ep.start(c);self.ready_files(ep,c,{'reports/live':b'apply crash recovered exact bytes'},head=shared['head'],seconds=25)
        assert self.sql('SELECT count(*) FROM changes;')==count;self.expected_live=b'apply crash recovered exact bytes'
        self.record(ep.platform,'repeated-apply-crashes',phase='native-before-commit',crashes=2,retained=proof,shared_receipt=shared,no_republication=True);ep.stop(c)
    def offline_cases(self):
        if 'linux' in self.platforms:self.mounted_offline()
        if not self.endpoints:self.endpoints=[Endpoint(self,p,self.image) for p in self.platforms]
        for ep in self.endpoints:
            c=ep.create('offline');ep.start(c);self.until(lambda:ep.ready(c),20);cached=ep.read(c)
            self.stop_service();assert ep.read(c)==cached;ep.write(c,b'offline supported local capture');self.until(lambda:len(self.subs(ep,c))>0,10)
            self.expected_live=b'offline supported local capture'
            queued=self.subs(ep,c)[-1];assert queued['private_receipt'] is None;assert ep.read(c)==b'offline supported local capture'.hex()
            self.record(ep.platform,'offline-native-cached-read-local-capture',queued=queued,plaintext_retained=True)
            self.start_service();self.until(lambda:any(s['state']=='Shared' for s in self.subs(ep,c)),30);ep.stop(c)
    def mounted_offline(self):
        from linux_live import LiveJourney
        self.set_file('reports/uncached',b'uncached offline object','offline-uncached')
        j=LiveJourney(self.i,self.image);j.tokens=self.tokens;self.mounted=j
        j.daemon=self.i.create('container','offline-mount',['--network',self.i.ingress,'--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','DAC_OVERRIDE','--cap-add','SYS_CHROOT','--security-opt','apparmor=unconfined','--security-opt','no-new-privileges','--device','/dev/fuse','--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/private:rw,nosuid,nodev,mode=700,size=256m','--tmpfs','/shared:rw,nosuid,nodev,mode=755,size=16m',self.image,'python3','-c',"import os,signal,time\ndef reap(*a):\n while True:\n  try:p,s=os.waitpid(-1,os.WNOHANG)\n  except ChildProcessError:return\n  if p==0:return\nsignal.signal(signal.SIGCHLD,reap)\nwhile True:time.sleep(.2)"])
        self.i.docker('start',j.daemon);mounted=j.start('offline',publication='isolated');cached=j.execute("import json;print(json.dumps(open('/shared/offline/reports/live','rb').read().hex()))",user='1001:1001')
        self.i.docker('network','disconnect',self.i.ingress,j.daemon)
        result=j.execute("""import time,os,json
cached=open('/shared/offline/reports/live','rb').read().hex()
with open('/shared/offline/reports/mounted-private','wb') as f:f.write(b'offline mounted private');f.flush();os.fsync(f.fileno())
assert open('/shared/offline/reports/mounted-private','rb').read()==b'offline mounted private'
start=time.monotonic()
try:open('/shared/offline/reports/uncached','rb').read();error=None
except OSError as e:error=e.errno
print(json.dumps({'cached':cached,'missing_error':error,'missing_seconds':time.monotonic()-start,'local_write':True}))""",user='1001:1001')
        assert result['cached']==cached and result['missing_error'] and result['missing_seconds']<=5,result
        self.i.docker('network','connect',self.i.ingress,j.daemon)
        self.record('linux','mounted-offline-network-partition',binding=mounted['binding'],**result);j.cleanup();self.mounted=None

def main(default_cases=None):
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--platform',choices=['all','macos','linux'],default='all');ap.add_argument('--case',action='append',choices=Recovery.CASES);ap.add_argument('--reuse-image');a=ap.parse_args()
    cases=a.case or default_cases or Recovery.CASES;platforms=['macos','linux'] if a.platform=='all' else [a.platform]
    i=OwnedInfra(a.output);j=None;code=1;records=[];reuse=None
    def record(platform,case,**data):records.append({'platform':platform,'case':case,**data});i.write_json('recovery-evidence.json',records)
    try:
        if 'macos' in platforms and any(c in cases for c in ['reconnect','offline']) and sys.platform!='darwin':raise InfrastructureUnavailable('macOS host required for actual native recovery')
        i.preflight();source=capture(i);reuse=resolve_reused_image(i,a.reuse_image) if a.reuse_image else None;image=reuse['image'] if reuse else i.owner+'-recovery'
        for command in [['cargo','+stable','build','--locked','-p','magus-fs','--features','test-faults'],['cargo','+stable','build','--locked','-p','magus-fs','-p','magus-fs-service']]:
            i.run(command,timeout=900)
            if '--features' in command:shutil.copyfile(ROOT/'target/debug/magus-fs',ROOT/'target/debug/magus-fs-client-faults');os.chmod(ROOT/'target/debug/magus-fs-client-faults',0o755)
        if not reuse:i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=0','--label','magus.fs2.owner='+i.owner,'-t',image,'.',timeout=2400)
        i.setup(image);verify_image(i,source);i.isolate_service_control()
        i.write_json('client-binaries.json',{'host':{n:hashlib.sha256((ROOT/'target/debug'/n).read_bytes()).hexdigest() for n in ['magus-fs','magus-fs-client-faults']},'linux':{n:i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+n).stdout.split()[0] for n in ['magus-fs','magus-fs-client-faults']}})
        j=Recovery(i,image,platforms,cases);j.record=record;started=time.monotonic();j.run();i.write_json('journey-duration.json',{'seconds':time.monotonic()-started})
        after=sources();i.write_json('source-after.json',{'sha256':after,'matched':after==source['sha256']});assert after==source['sha256'],'source changed during recovery gate';code=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});code=2
    except Exception as e:
        i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()});traceback.print_exc()
        if hasattr(i,'service'):
            p=i.docker('exec',i.service,'cat','/tmp/service.log',check=False,evidence=False);(i.output/'service.log').write_text(p.stdout+p.stderr)
            for role in ['service','pg','s3']:
                container=getattr(i,role,None)
                if container:
                    try:
                        x=i.inspect('container',container);i.write_json('failure-'+role+'-state.json',{'State':x.get('State'),'image':x.get('Image')})
                        log=i.docker('logs',container,check=False,evidence=False);(i.output/('failure-'+role+'.log')).write_text(log.stdout+log.stderr)
                    except Exception as failure:i.write_json('failure-'+role+'-diagnostic.json',{'reason':str(failure)})
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e),'trace':traceback.format_exc()});code=1
        i.write_json('result.json',{'exit':code,'passed':code==0,'scope':'FS2-B Task 3 service faults' if default_cases else 'FS2-B Task 3 recovery','cases':cases,'platforms':platforms,'complete_gate':not a.case and not a.reuse_image and a.platform=='all','build_reuse':reuse,'evidence_records':len(records)})
    print(json.dumps({'exit':code,'output':str(i.output)}));return code
if __name__=='__main__':sys.exit(main())
