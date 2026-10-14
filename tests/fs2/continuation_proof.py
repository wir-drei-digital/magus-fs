#!/usr/bin/env python3
"""Owned actual TLS/PG/S3 continuation producer journey; execution requires combined P3.

Unit tests of this runner are not live producer qualification. No builds or historical
suite replay are performed here. All failures and owned cleanup results are retained.
"""
import copy
import concurrent.futures
import json
import secrets
import socket
import time
import traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable
from provenance import capture, verify_linux_image
from service_protocol import Journey as ProtocolJourney, identity, file_entry, canonical, GROUP, REPLICA, WORKER
from service_storage import NS, ALICE, BOB, object_id


def validate_image(image):
    if not image.startswith('sha256:') or len(image) != 71 or any(c not in '0123456789abcdef' for c in image[7:]):
        raise ValueError('immutable source-attributed P3 image required')


def execute(infra, image, journey_type=None, capture_source=None, verify_source=None):
    status = 1
    try:
        validate_image(image)
        infra.preflight()
        source = (capture_source or capture)(infra)
        infra.setup(image)
        infra.isolate_service_control()
        (verify_source or verify_linux_image)(infra, source)
        journey = (journey_type or Journey)(infra)
        started = time.monotonic()
        journey.run()
        (verify_source or verify_linux_image)(infra, source)
        elapsed = time.monotonic() - started
        assert elapsed < 600, elapsed
        infra.write_json('journey-duration.json', {'seconds': elapsed, 'limit': 600})
        status = 0
    except InfrastructureUnavailable as error:
        infra.write_json('failure.json', {'classification': 'blocked', 'reason': str(error)})
        status = 2
    except Exception as error:
        infra.write_json('failure.json', {'classification': 'failed', 'type': type(error).__name__, 'reason': str(error), 'trace': traceback.format_exc()})
    finally:
        try:
            infra.cleanup()
        except Exception as error:
            infra.write_json('cleanup-failure.json', {'reason': str(error)})
            status = 1
        infra.write_json('result.json', {'status': status, 'scope': 'actual continuation producer TLS/PG/S3'})
    return status


class Journey(ProtocolJourney):
    def delegate(self, name):
        # Grant responses contain bearer tokens: never put them in observations/tracebacks.
        status,result=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','integrate'],'branches':['main'],'prefixes':['']}})
        assert status==200,('delegate-'+name,status)
        self.observations.append({'case':'delegate-'+name,'status':status,'credential':result['credential'],'token':'[redacted]'})
        self.i.write_json('observations.json',self.observations)
        return result

    def proof(self, receipt, actor='worker', status=200, code=None, name='proof'):
        result = self.expect(name, 'POST', self.root + '/continuations/proof', status,
                             {'code': code} if code else None, body={'receipt': receipt}, actor=actor)
        if status == 200:
            p = result['proof']
            assert p['format'] == 'magus-fs/continuation-proof/v1'
            assert p['namespace'] == NS and p['principal'] == ALICE
            assert p['request'] == {'receipt': receipt} and p['complete_projection'] is True
            assert p['descriptor_digest'] == p['view']['revision'] == object_id(canonical(result['descriptor']))
            assert result['descriptor']['parents'] == []
            actual = self.i.sql("SELECT published_revision FROM publication_results WHERE namespace='"+NS+"' AND receipt='"+receipt['receipt']+"';")
            assert p['published_revision'] == actual
            assert self.i.sql("SELECT revision FROM branches WHERE namespace='"+NS+"' AND name='main';") == p['current_revision']
        return result

    def publish(self, actor, path):
        view, tree = self.view(actor)
        tree['tree']['entries'].append(file_entry(path, self.tree_root['id'], b''))
        request, private = self.candidate(view, tree, actor)
        integration = self.integrate_request(private, view)
        shared = self.expect('publish-'+path, 'POST', self.root+'/integrations', 200, body=integration, actor=actor)
        assert shared['operation'] != request['operation'] and shared['submitted_revision'] == request['revision']
        return shared

    def grant(self, actions, prefixes=None):
        # Trusted fixture mutation under the same namespace lock as real grant updates.
        encoded = ','.join("'"+a+"'" for a in actions)
        scope = '' if prefixes is None else ',prefixes=ARRAY['+','.join("'"+p+"'" for p in prefixes)+']::text[]'
        self.i.sql("BEGIN;SELECT id FROM namespaces WHERE id='"+NS+"' FOR UPDATE;UPDATE grants SET actions=ARRAY["+encoded+"]::text[]"+scope+" WHERE credential='"+self.worker_credential+"';UPDATE credentials SET generation=generation+1 WHERE id='"+self.worker_credential+"';COMMIT;")

    def run(self):
        self.i.start_service(); self.wait()
        authority = {'principal': ALICE, 'uid': 1001, 'gid': 1001, 'primary_group': GROUP, 'groups': [GROUP], 'dac_override': False, 'ownership_transfer': False}
        self.i.provision([{'namespace': NS, 'principal': ALICE, 'replica': REPLICA, 'token': secrets.token_hex(32), 'expires': int(time.time())+3600, 'actions': ['admin','read','write','integrate'], 'branches': ['main'], 'prefixes': [''], 'authority': authority, 'root_policy': self.tree_root}])
        seed_tree = self.descriptor([file_entry('base', self.tree_root['id'], b'base')])
        upload, rid = self.stage(seed_tree, bodies=[b'base'])
        seed = self.expect('seed', 'POST', self.root+'/seed', 200, body={'branch':'main','revision':rid,'upload':upload})
        self.proof(seed, actor='alice', name='seed-publication-mapping')
        worker = self.delegate('worker')
        self.tokens['worker'] = worker['token']; self.worker_credential = worker['credential']
        self.i.private('continuation-worker-token',worker['token'])
        first = self.publish('worker','first')
        first_proof=self.proof(first, name='fast-forward')
        assert self.proof(first,name='same-current-view-reused')['proof']['view']==first_proof['proof']['view']
        self.expect('unknown-request-field', 'POST', self.root+'/continuations/proof', 400, body={'receipt':first,'extra':True}, actor='worker')
        self.expect('oversize-request', 'POST', self.root+'/continuations/proof', 413, raw=b' '*65537, headers={'Content-Type':'application/json'}, actor='worker')
        other_token=secrets.token_hex(32)
        other_authority=dict(authority,principal=BOB,uid=1002,dac_override=True)
        self.i.provision([{'namespace':NS,'principal':BOB,'replica':WORKER,'token':other_token,'expires':int(time.time())+1800,'actions':['read','write','integrate'],'branches':['main'],'prefixes':[''],'authority':other_authority}])
        self.tokens['other-principal']=other_token
        self.proof(first,actor='other-principal',status=404,code='not_found',name='same-namespace-other-principal')
        for actor in ['alice','readonly','bob']:
            self.proof(first,actor=actor,status=404,code='not_found',name='foreign-owner-'+actor)
        for field, value in [('head','0'*32),('submitted_revision','sha256:'+'f'*64),('operation',identity('operation')),('receipt','0'*32)]:
            self.proof(dict(first,**{field:value}),status=404,code='not_found',name='receipt-binding-'+field)
        # Same principal and replica under a different current credential still cannot own it.
        alternate=self.delegate('other-credential')
        self.tokens['other-credential']=alternate['token']
        self.proof(first,actor='other-credential',status=404,code='not_found',name='same-replica-other-credential')
        # A candidate prepared against the old base merges an unrelated foreign addition.
        view, tree = self.view('worker'); tree['tree']['entries'].append(file_entry('merge-own',self.tree_root['id'],b''))
        local, private = self.candidate(view,tree)
        self.publish('alice','merge-foreign')
        current, _ = self.view('worker')
        shared = self.expect('merge','POST',self.root+'/integrations',200,body=self.integrate_request(private,current),actor='worker')
        proof = self.proof(shared,name='proof-uses-committed-merge-result')
        candidate = self.i.sql("SELECT derived_revision FROM operations WHERE operation='"+shared['operation']+"';")
        assert proof['proof']['published_revision'] != candidate
        assert shared['submitted_revision']==local['revision'] and shared['operation']!=local['operation']
        assert {'merge-own','merge-foreign'} <= {e['path'] for e in proof['descriptor']['tree']['entries']}
        self.proof(first,name='earlier-own-result-is-ancestor')
        self.other_publication_sources()
        self.rollback_mapping()
        self.loss_and_races(shared)
        self.scope_and_retention(shared)
        self.old_server(first)
        self.expect('revoke-original-credential','POST',self.root+'/grants',200,body={'revoke':self.worker_credential})
        self.proof(first,status=401,code='invalid_credential',name='rotated-original-credential-refused')
        self.proof(first,actor='other-credential',status=404,code='not_found',name='rotation-does-not-transfer-receipt-ownership')
        self.legacy_and_bound(seed)
        self.i.write_json('observations.json',self.observations)

    def other_publication_sources(self):
        # Conflicting opaque edits retain alternatives; explicit resolution also records
        # its actual result, independently of the replacement candidate's identity.
        view, tree=self.view('worker');entry=next(e for e in tree['tree']['entries'] if e['path']=='base')
        entry['content']=file_entry('unused',self.tree_root['id'],b'worker-change')['content']
        _,private=self.candidate(view,tree,bodies=[b'worker-change'])
        av,at=self.view('alice');next(e for e in at['tree']['entries'] if e['path']=='base')['content']=file_entry('unused',self.tree_root['id'],b'alice-change')['content']
        _,ap=self.candidate(av,at,'alice',bodies=[b'alice-change'])
        self.expect('conflict-winner','POST',self.root+'/integrations',200,body=self.integrate_request(ap,av))
        current,_=self.view('worker')
        conflicted=self.expect('retained-conflict','POST',self.root+'/integrations',409,body=self.integrate_request(private,current),actor='worker')
        assert conflicted['code']=='conflicted' and conflicted['conflicts']
        current,replacement=self.view('worker');next(e for e in replacement['tree']['entries'] if e['path']=='base')['content']=file_entry('unused',self.tree_root['id'],b'resolved')['content']
        _,rp=self.candidate(current,replacement,bodies=[b'resolved'])
        receipt=self.expect('resolution','POST',self.root+'/resolutions',200,body={'operation':identity('operation'),'replica':WORKER,'conflicts':conflicted['conflicts'],'expected_head':current['head'],'replacement':rp['receipt']},actor='worker')
        self.proof(receipt,name='resolution-publication-mapping')
        # Restore is authorized explicitly with Alice's existing history grant. The
        # proof itself still uses only read/write/integrate and no historical GET.
        av,at=self.view('alice');entry=next(e for e in at['tree']['entries'] if e['path']=='base')
        page=self.expect('restore-history','GET',self.root+'/history?view='+av['view'],200)
        history=next(h for h in page['items'] if h['entry']==entry['id'])
        restored=self.expect('restore','POST',self.root+'/restores',200,body={'operation':identity('operation'),'replica':REPLICA,'history':history['id'],'expected_head':av['head'],'restore_metadata':False})
        self.proof(restored,actor='alice',name='restore-publication-mapping')

    def rollback_mapping(self):
        view, tree=self.view('worker');tree['tree']['entries'].append(file_entry('rollback',self.tree_root['id'],b''))
        _, private=self.candidate(view,tree);request=self.integrate_request(private,view)
        before=self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")
        self.i.sql("CREATE FUNCTION reject_continuation_mapping() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic mapping failure'; END $$; CREATE TRIGGER reject_mapping BEFORE INSERT ON publication_results FOR EACH ROW EXECUTE FUNCTION reject_continuation_mapping();")
        try:
            self.expect('publication-mapping-commits-atomically','POST',self.root+'/integrations',503,{'code':'backend_unavailable'},body=request,actor='worker')
            assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
            assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+request['operation']+"';")=='0'
            assert self.i.sql("SELECT count(*) FROM publication_results WHERE operation='"+request['operation']+"';")=='0'
        finally:
            self.i.sql('DROP TRIGGER reject_mapping ON publication_results;DROP FUNCTION reject_continuation_mapping();')
        shared=self.expect('mapping-retry-after-rollback','POST',self.root+'/integrations',200,body=request,actor='worker')
        self.proof(shared,name='mapping-after-success')

    def loss_and_races(self, shared):
        # Discard a proven issued response. A fresh query must observe new current authority.
        self.publish('alice','before-loss')
        before=int(self.i.sql('SELECT count(*) FROM views;'))
        payload=json.dumps({'receipt':shared}).encode()
        with socket.create_connection(('127.0.0.1',self.i.port),timeout=2) as raw:
            with self.ca.wrap_socket(raw,server_hostname='localhost') as sock:
                sock.sendall(('POST '+self.root+'/continuations/proof HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+self.tokens['worker']+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload))+'\r\nConnection: close\r\n\r\n').encode()+payload)
                deadline=time.monotonic()+10
                while int(self.i.sql('SELECT count(*) FROM views;'))<=before:
                    assert time.monotonic()<deadline,'lost proof never committed a view'
                    time.sleep(.05)
        self.grant(['read'])
        self.proof(shared,status=404,code='not_found',name='proof-requery-after-loss-reauthorizes')
        self.grant(['read','write','integrate'])
        self.proof(shared,name='proof-requery-restored-current-grant')
        self.i.restart_service(faults=True);self.wait()
        for mutate in ['head','grant','both','generation']:
            self.i.docker('exec',self.i.service,'rm','-f','/tmp/fs2-continuation-barrier')
            pause=self.i.private('pause-continuation','pause')
            count=self.i.sql("SELECT count(*) FROM views WHERE credential='"+self.worker_credential+"';")
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future=pool.submit(self.request,'POST',self.root+'/continuations/proof',body={'receipt':shared},actor='worker')
                try:
                    self.barrier('continuation')
                    if mutate in ['head','both']:self.publish('alice','race-'+mutate)
                    if mutate in ['grant','both']:self.grant(['read'])
                    if mutate=='generation':self.grant(['read','write','integrate'])
                finally:pause.unlink(missing_ok=True)
                status, body=future.result()
            expected=409 if mutate=='head' else 404
            assert status==expected,(mutate,status,body)
            self.observations.append({'case':'precommit-'+mutate,'status':status,'body':body})
            assert self.i.sql("SELECT count(*) FROM views WHERE credential='"+self.worker_credential+"';")==count
            # Alice's publication may issue its own view; no worker proof committed.
            self.grant(['read','write','integrate'])
        self.i.restart_service();self.wait()

    def scope_and_retention(self, shared):
        self.grant(['read','write','integrate'],['base'])
        self.proof(shared,status=409,code='continuation_scope_unsupported',name='filtered-current-projection')
        self.grant(['read','write','integrate'],[''])
        # Current ancestor denial removes descendants even with broad path scope.
        view,tree=self.view('alice')
        directory={'path':'denied','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':448,'content':{'kind':'directory'}}
        tree['tree']['entries'] += [directory,file_entry('denied/child',directory['id'],b'')]
        _,private=self.candidate(view,tree,'alice');self.expect('add-ancestor','POST',self.root+'/integrations',200,body=self.integrate_request(private,view))
        view,tree=self.view('alice');next(e for e in tree['tree']['entries'] if e['path']=='denied')['mode']=0
        _,private=self.candidate(view,tree,'alice');self.expect('deny-ancestor','POST',self.root+'/integrations',200,body=self.integrate_request(private,view))
        self.proof(shared,status=409,code='continuation_scope_unsupported',name='denied-ancestor')
        # Restore fixture head to prior committed revision for independent retention/bound checks.
        previous=self.i.sql("SELECT full_revision FROM views WHERE id='"+view['view']+"';")
        self.i.sql("UPDATE branches SET revision='"+previous+"',head='"+view['head']+"' WHERE namespace='"+NS+"' AND name='main';")
        before=self.i.sql('SELECT count(*) FROM publication_results;')
        plan=json.loads(self.i.docker('exec',self.i.service,'magus-fs-service','gc',self.i.service_config,'--namespace',NS,'--dry-run').stdout)
        self.i.docker('exec',self.i.service,'magus-fs-service','gc',self.i.service_config,'--namespace',NS,'--plan',plan['plan'])
        assert self.i.sql('SELECT count(*) FROM publication_results;')==before
        self.proof(shared,name='retention-keeps-publication-result')

    def old_server(self, receipt):
        # Retained Task1 P2 actual image/binary; no new build and no source relabelling.
        image='sha256:9c7b55e2e231b8f06e6b7f6f2110fa056bd9e21d2b4e5c8b473ac4f286e18569'
        expected='627a80396e4118c5f7b4c1bab80ff124b2616debd1a4b49b55e7ef77fd38ab45'
        if self.i.docker('image','inspect',image,check=False).returncode:
            raise InfrastructureUnavailable('retained P2 image required for actual old-server404')
        legacy=self.i.create('container','legacy-service',['--network',self.i.ingress,'--memory','512m','--cpus','2','--pids-limit','256','-p','127.0.0.1::8443','-v',str(self.i.control)+':/control:ro',image,'sleep','infinity'])
        self.i.docker('network','connect',self.i.net,legacy);self.i.docker('start',legacy)
        actual=self.i.docker('exec',legacy,'sha256sum','/usr/local/bin/magus-fs-service').stdout.split()[0]
        assert actual==expected
        self.i.write_json('old-server-source.json',{'image':image,'actual_image':self.i.inspect('container',legacy)['Image'],'binary_sha256':actual,'prior_evidence':'/private/tmp/magus-collaboration-p2-20261014-a/image-source.json','scope':'only actual unsupported-route404; not current producer qualification'})
        service,port=self.i.service,self.i.port
        try:
            self.i.service=legacy
            # Preserve the original ownership evidence rather than overwrite its file.
            self.i.docker('exec',legacy,'python3','-c',"import os;os.mkdir('/fs2-owned-control',0o700)")
            for name in ['service.json','server.crt','server.key']:self.i.copy_service_control(name)
            self.i.start_service();self.wait()
            self.expect('actual-old-server-capability-unavailable','POST',self.root+'/continuations/proof',404,body={'receipt':receipt},actor='worker',response_bytes=True)
            view,tree=self.view('worker');tree['tree']['entries'].append(file_entry('legacy-candidate',self.tree_root['id'],b''))
            local,private=self.candidate(view,tree)
            legacy_request=self.integrate_request(private,view)
        finally:
            self.i.service,self.i.port=service,port
        self.i.remove('container',legacy)
        assert self.i.sql("SELECT count(*) FROM revisions WHERE namespace='"+NS+"' AND revision='"+local['revision']+"';")=='0'
        published=self.expect('legacy-candidate-new-publication','POST',self.root+'/integrations',200,body=legacy_request,actor='worker')
        self.proof(published,name='legacy-candidate-preserves-publication')

    def legacy_and_bound(self, seed):
        row=json.loads(self.i.sql("SELECT row_to_json(p) FROM publication_results p WHERE receipt='"+seed['receipt']+"';"))
        self.i.sql("DELETE FROM publication_results WHERE receipt='"+seed['receipt']+"';")
        self.proof(seed,actor='alice',status=409,code='continuation_evidence_unavailable',name='legacy-receipt-without-mapping')
        # Restore only this fixture row; production never reconstructs/backfills evidence.
        self.i.sql('INSERT INTO publication_results('+','.join(row)+") VALUES("+','.join("'"+v+"'" for v in row.values())+');')
        # Verified canonical 256-node graph in the real DB avoids 256 unrelated HTTP publications.
        # The synthetic chain is explicitly not evidence of publication throughput.
        base=json.loads(self.i.sql("SELECT convert_from(descriptor,'UTF8') FROM revisions WHERE namespace='"+NS+"' AND revision='"+row['published_revision']+"';"))
        parent=row['published_revision']; statements=[]
        for n in range(256):
            revision=copy.deepcopy(base);revision['parents']=[parent];revision['operation']=identity('operation');revision['captured_at_ns']=n+100
            raw=canonical(revision);current=object_id(raw)
            statements.append("INSERT INTO revisions(namespace,revision,descriptor) VALUES('"+NS+"','"+current+"',decode('"+raw.hex()+"','hex'));")
            parent=current
            if n==254:at256=current
        self.i.sql('BEGIN;'+''.join(statements)+"UPDATE branches SET revision='"+at256+"',head='"+'a'*32+"' WHERE namespace='"+NS+"' AND name='main';COMMIT;")
        self.proof(seed,actor='alice',name='256-nodes-accepted')
        self.i.sql("UPDATE branches SET revision='"+parent+"',head='"+'b'*32+"' WHERE namespace='"+NS+"' AND name='main';")
        self.proof(seed,actor='alice',status=409,code='continuation_evidence_limit',name='257th-node-required')
        # A valid independent root demonstrates non-descendant refusal.
        independent=copy.deepcopy(base);independent['operation']=identity('operation');raw=canonical(independent);rid=object_id(raw)
        self.i.sql("INSERT INTO revisions VALUES('"+NS+"','"+rid+"',decode('"+raw.hex()+"','hex'));UPDATE branches SET revision='"+rid+"',head='"+'c'*32+"' WHERE namespace='"+NS+"' AND name='main';")
        self.proof(seed,actor='alice',status=409,code='continuation_not_descendant',name='unrelated-current-root')


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args(argv);validate_image(args.image)
    infra=OwnedInfra(Path(args.output));infra.runtime_profile='release'
    return execute(infra,args.image)

if __name__=='__main__':
    raise SystemExit(main())
