#!/usr/bin/env python3
"""Focused real HTTPS/PG/S3 immutable-view reuse regression (0/1/2)."""
import argparse
import concurrent.futures
import copy
import json
from pathlib import Path
import secrets
import sys
import time
import traceback
from infra import OwnedInfra, InfrastructureUnavailable
from provenance import capture, verify_image
from service_protocol import Journey as ProtocolJourney, NS, ALICE, GROUP, REPLICA, WORKER, canonical, file_entry, identity, object_id

class Journey(ProtocolJourney):
    def poll(self, actor):
        status, binding = self.request('POST', self.root+'/views', actor=actor, body={'branch':'main'})
        assert status == 200, (status, binding)
        return binding

    def bounded(self, actor, expected, label):
        before = int(self.i.sql('SELECT count(*) FROM views;'))
        bindings = [self.poll(actor) for _ in range(12)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            bindings += list(pool.map(lambda _: self.poll(actor), range(16)))
        after = int(self.i.sql('SELECT count(*) FROM views;'))
        result = {'case':label,'requests':28,'rows_before':before,'rows_after':after,
                  'distinct_bindings':len({json.dumps(v,sort_keys=True) for v in bindings}),
                  'original_binding':expected}
        self.observations.append(result)
        self.i.write_json('observations.json', self.observations)
        assert all(v == expected for v in bindings) and after == before, result

    def delegate(self, actor, replica=WORKER, prefixes=None):
        status, grant = self.request('POST', self.root+'/grants',
            body={'delegate':{'replica':replica,'expires':int(time.time())+1800,
                'actions':['read','write','history','integrate'],'branches':['main'],
                'prefixes':['reports'] if prefixes is None else prefixes}})
        assert status == 200, (status, grant.get('code'))
        self.observations.append({'case':'delegate-'+actor,'status':status,'credential':grant['credential']})
        self.i.write_json('observations.json',self.observations)
        self.tokens[actor] = grant['token']
        self.i.private(actor+'-token', grant['token'])
        return grant

    def denied(self, actor, view, operation, request):
        self.expect('revoked-reuse-'+actor,'POST',self.root+'/views',401,actor=actor,body={'branch':'main'})
        self.expect('revoked-descriptor-'+actor,'GET',self.root+'/views/'+view['view']+'/descriptor',401,actor=actor)
        self.expect('revoked-object-'+actor,'GET',self.root+'/views/'+view['view']+'/objects/'+object_id(b'visible'),401,actor=actor)
        self.expect('revoked-operation-'+actor,'GET',self.op_path(operation),401,actor=actor)
        self.expect('revoked-replay-'+actor,'POST',self.root+'/candidates',401,actor=actor,body=request)

    def run(self):
        self.i.start_service(); self.wait()
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,
            'token':secrets.token_hex(32),'expires':int(time.time())+3600,
            'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],
            'authority':{'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],
                         'dac_override':False,'ownership_transfer':False},'root_policy':self.tree_root}])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],
                 'owner':ALICE,'group':GROUP,'mode':448,'content':{'kind':'directory'}}
        full=self.descriptor([reports,file_entry('reports/input',reports['id'],b'visible'),
                              file_entry('secret',self.tree_root['id'],b'hidden')])
        upload,rid=self.stage(full,bodies=[b'visible',b'hidden'])
        self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        grant=self.delegate('worker')
        original,projected=self.view('worker')
        self.bounded('worker',original,'unchanged-sequential-concurrent-bounded')
        self.i.restart_service(); self.wait()
        self.bounded('worker',original,'restart-additive-schema-stable')
        assert self.i.sql("SELECT count(*) FROM pg_indexes WHERE indexname='views_reuse_lookup';") == '1'
        # A legacy row keeps its ID, references and usability. No guessed grant backfill.
        legacy=dict(original,view=secrets.token_hex(16))
        self.i.sql("INSERT INTO views(id,namespace,branch,credential,principal,replica,full_revision,head,projected_revision,descriptor) SELECT '"+legacy['view']+"',namespace,branch,credential,principal,replica,full_revision,head,projected_revision,descriptor FROM views WHERE id='"+original['view']+"';")
        self.bounded('worker',original,'legacy-duplicate-preserved-without-new-growth')
        # Original issued and legacy bindings remain candidate/replay roots after reuse.
        request,receipt=self.candidate(original,copy.deepcopy(projected))
        self.expect('original-view-exact-replay','POST',self.root+'/candidates',200,receipt,body=request,actor='worker')
        old_request,old_receipt=self.candidate(legacy,copy.deepcopy(projected))
        self.expect('legacy-view-exact-replay','POST',self.root+'/candidates',200,old_receipt,body=old_request,actor='worker')
        rotated=self.delegate('rotated')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first=list(pool.map(lambda _: self.poll('rotated'),range(2)))
        assert first[0] == first[1], first
        rotation,_=self.view('rotated'); assert rotation == first[0]
        assert rotation['view'] != original['view'] and rotation['revision'] == original['revision']
        self.bounded('rotated',rotation,'same-principal-replica-new-credential')
        scope=self.delegate('narrow',replica='replica:'+f'{6:032x}',prefixes=['reports/input'])
        narrower,_=self.view('narrow'); assert narrower['view'] != original['view']
        # Actual effective-grant changes also cannot reuse a prior generation even
        # when the projected descriptor is unchanged. Fixture SQL is explicit.
        self.i.sql("BEGIN; SELECT id FROM namespaces WHERE id='"+NS+"' FOR UPDATE; UPDATE credentials SET generation=generation+1 WHERE id='"+rotated['credential']+"'; COMMIT;")
        generation,_=self.view('rotated'); assert generation['view'] != rotation['view'] and generation['revision'] == rotation['revision']
        self.bounded('rotated',generation,'changed-generation-distinct')
        self.i.sql("BEGIN; SELECT id FROM namespaces WHERE id='"+NS+"' FOR UPDATE; UPDATE grants SET actions=ARRAY['read','write','integrate']::text[] WHERE credential='"+rotated['credential']+"'; COMMIT;")
        changed_grant,_=self.view('rotated'); assert changed_grant['view'] != generation['view']
        self.bounded('rotated',changed_grant,'changed-effective-grant-distinct')
        rotated_edit=copy.deepcopy(projected); rotated_edit['parents']=[changed_grant['revision']]; rotated_edit['replica']=WORKER; rotated_edit['operation']=identity('operation')
        rotated_upload,rotated_id=self.stage(rotated_edit,'rotated')
        rq={'operation':rotated_edit['operation'],'replica':WORKER,'original_view':changed_grant['view'],'original_head':changed_grant['head'],'revision':rotated_id,'upload':rotated_upload}
        self.expect('rotated-original-view-submit','POST',self.root+'/candidates',200,body=rq,actor='rotated')
        # Construct a valid hidden-only full revision with unchanged visible
        # canonical metadata, so exact full-base matching is tested independently
        # of projected hashes. Owned fixture administrator installs it atomically.
        hidden=copy.deepcopy(full)
        hidden['tree']['entries'][-1]['content']={'kind':'file','version':{'size':0,'extents':[]}}
        raw=canonical(hidden); hidden_id=object_id(raw); hidden_head=secrets.token_hex(16)
        self.i.sql("BEGIN; SELECT id FROM namespaces WHERE id='"+NS+"' FOR UPDATE; INSERT INTO revisions(namespace,revision,descriptor) VALUES('"+NS+"','"+hidden_id+"',decode('"+raw.hex()+"','hex')); INSERT INTO revision_objects SELECT namespace,'"+hidden_id+"',object_id,generation FROM revision_objects WHERE namespace='"+NS+"' AND revision='"+rid+"' AND object_id='"+object_id(b'visible')+"'; UPDATE branches SET revision='"+hidden_id+"',head='"+hidden_head+"' WHERE namespace='"+NS+"' AND name='main'; COMMIT;")
        hidden_view,hidden_projection=self.view('worker')
        assert hidden_view['view'] != original['view'] and hidden_view['head'] != original['head']
        assert hidden_view['revision'] == original['revision'] and hidden_projection == projected
        self.bounded('worker',hidden_view,'changed-full-base-unchanged-projection')
        edit=copy.deepcopy(hidden_projection); edit['tree']['entries'].append(file_entry('reports/result',reports['id'],b'report'))
        q,private=self.candidate(hidden_view,edit,bodies=[b'report'])
        integration=self.integrate_request(private,hidden_view)
        self.expect('visible-integrate','POST',self.root+'/integrations',200,body=integration,actor='worker')
        changed,_=self.view('worker'); assert changed['revision'] != hidden_view['revision'] and changed['view'] != hidden_view['view']
        self.bounded('worker',changed,'changed-visible-projection-distinct')
        status,data=self.bytes_request(self.root+'/views/'+original['view']+'/objects/'+object_id(b'visible'))
        assert status == 200 and data == b'visible'
        self.expect('revoke-worker','POST',self.root+'/grants',200,body={'revoke':grant['credential']})
        self.denied('worker',original,request,request)
        parent=self.i.sql("SELECT id FROM credentials WHERE token_hash='"+hash_token(self.tokens['alice'])+"';")
        self.expect('revoke-parent','POST',self.root+'/grants',200,body={'revoke':parent})
        self.denied('rotated',changed_grant,rq,rq)
        assert int(self.i.sql('SELECT count(*) FROM views;')) == 8
        self.i.write_json('view-bounds.json',{'passed':True,'unchanged_requests_per_batch':28,
            'batches':8,'expected_total_rows':8,'actual_rows':int(self.i.sql('SELECT count(*) FROM views;')),
            'legacy_preserved':self.i.sql("SELECT count(*) FROM views WHERE id='"+legacy['view']+"';")=='1'})

def hash_token(token):
    import hashlib
    return hashlib.sha256(token.encode()).hexdigest()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',required=True); ap.add_argument('--image',default='magus-fs2-view-reuse')
    ap.add_argument('--red',action='store_true'); ap.add_argument('--skip-build',action='store_true'); ap.add_argument('--skip-checks',action='store_true'); args=ap.parse_args()
    i=OwnedInfra(Path(args.output)); status=1
    try:
        i.preflight(); source=capture(i)
        if not args.red and not args.skip_checks:
            for argv in [['cargo','+stable','fmt','--all','--check'],['cargo','+stable','clippy','--locked','-p','magus-fs-service','--all-targets','--all-features','--','-D','warnings'],['cargo','+stable','test','--locked','-p','magus-fs-service','--all-features'],['cargo','+stable','build','--locked','-p','magus-fs-service']]: i.run(argv,timeout=300)
        if not args.skip_build: i.docker('build','--pull=false','--progress=plain','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=0' if args.skip_checks else 'VERIFY=service','-t',args.image,'.',timeout=900)
        i.setup(args.image)
        if not args.red: verify_image(i,source)
        else: i.write_json('red-image.json',{'service_image':i.inspect('container',i.service)['Image'],'note':'retained baseline runtime; new test source is intentionally outside image'})
        Journey(i).run(); status=0
    except InfrastructureUnavailable as e: i.write_json('failure.json',{'classification':'blocked','reason':str(e)}); status=2
    except Exception as e:
        if hasattr(i,'service'): i.docker('exec',i.service,'cat','/tmp/service.log',check=False)
        i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()})
    finally:
        try: i.cleanup()
        except Exception: status=1
        i.write_json('result.json',{'status':status,'scope':'FS2-A final view reuse actual HTTPS/PG/S3'})
    print(json.dumps({'status':status,'output':str(i.output)})); return status
if __name__=='__main__': sys.exit(main())
