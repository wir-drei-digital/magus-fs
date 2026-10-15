#!/usr/bin/env python3
"""Fresh owned F3-1/F3-2 ordinary Linux mounts and direct HTTPS attempts."""
import argparse
import hashlib
import json
import secrets
import time
import traceback
from common import PhaseInfra, RecordedLazy, InfrastructureUnavailable, source_bridge, restart_retained
from qualification import normalize, ISOLATION_CASES
from full_native import NativeJourney
from service_protocol import ALICE, GROUP, REPLICA, file_entry, identity
from service_storage import NS, BOB, object_id


def actors():
    """Logical identities are independent of identical per-container OS UIDs."""
    return {name: {'principal': principal, 'replica': REPLICA if name == 'a1' else identity('replica'),
                   'uid': 1001, 'gid': 1001, 'group': GROUP}
            for name, principal in [('a1', ALICE), ('a2', ALICE), ('b', BOB),
                                    ('readonly', ALICE), ('peer', 'principal:'+'d'*32)]}


def mount_authorities(actor, identities):
    principals = [actor['principal']]+sorted({r['principal'] for r in identities.values()}-{actor['principal']})
    return [{'principal': principal, 'uid': 1001+n, 'gid': 1001,
             'primary_group': GROUP, 'groups': [GROUP], 'dac_override': False, 'ownership_transfer': False}
            for n, principal in enumerate(principals)]


def provision_record(name, actor, identities, token, root):
    return {'namespace': NS, 'principal': actor['principal'], 'replica': actor['replica'],
            'token': token, 'expires': int(time.time())+3600,
            'actions': ['read'] if name == 'readonly' else ['read','write','history','integrate','admin'],
            'branches': ['main'], 'prefixes': ['reports'] if name in ('a2','readonly') else [''],
            'authority': mount_authorities(actor, identities)[0], **({'root_policy': root} if name == 'a1' else {})}


def validate_history_absence(page, private_entry, hidden_entry):
    """This small fixture must fit one complete page; never ignore a cursor."""
    assert page['next'] is None, 'bounded history fixture unexpectedly paginated'
    entries = [item['entry'] for item in page['items']]
    assert private_entry not in entries and hidden_entry not in entries, 'private or hidden entry disclosed in history'
    return {'private_entry':private_entry,'hidden_entry':hidden_entry,'observed_entries':entries,'page':page}


def private_object_probe(journey, actor, private_object):
    view, descriptor = journey.view(actor)
    allowed = next(e for e in descriptor['tree']['entries'] if e['path']=='reports/live')['content']['version']['extents'][0]['object']
    control = journey.expect('own-view-allowed-object','GET',journey.root+'/views/'+view['view']+'/objects/'+allowed,200,actor=actor,response_bytes=True)
    assert object_id(control)==allowed, 'allowed object control has wrong bytes'
    denied = journey.expect('own-view-private-object','GET',journey.root+'/views/'+view['view']+'/objects/'+private_object,404,actor=actor)
    return {'actor':actor,'view':view,'allowed_object':allowed,'allowed_status':200,'private_object':private_object,'private_status':404,'denied':denied}


class Isolation(NativeJourney):
    def __init__(self, infra, image, result):
        super().__init__(infra, image, ['linux'])
        self.result = result
        self.endpoints = {}
        self.identities = actors()
        self.bindings = {}

    def assertion(self, case, details):
        leaf = case+'.json'
        self.i.write_json(leaf, details)
        self.result['assertions'].append({'acceptance': ISOLATION_CASES[case], 'case': case,
            'expected': 'verified', 'observed': 'verified', 'passed': True,
            'provenance': [leaf, 'observations.json']})
        self.i.write_json('result.json', self.result)

    def head(self):
        return self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")

    def effect(self):
        return {'head': self.head(), 'operations': self.i.sql('SELECT count(*) FROM operations;'),
                'published': self.i.sql('SELECT count(*) FROM published_entries;')}

    def write(self, name, path, body):
        return self.endpoints[name].execute("import os,json,sys,hashlib\ns=json.load(sys.stdin)\nwith open('/shared/'+s['name']+'/'+s['path'],'wb') as f:f.write(bytes.fromhex(s['body']));f.flush();os.fsync(f.fileno())\nprint(json.dumps({'uid':os.geteuid(),'sha256':hashlib.sha256(bytes.fromhex(s['body'])).hexdigest()}))",
            {'name': name, 'path': path, 'body': body.hex()}, user='1001:1001')

    def read(self, name, path):
        return self.endpoints[name].read(name+'/'+path)

    def visible(self, names, path, body, head):
        rows = {}
        for name in names:
            ep = self.endpoints[name]
            self.until(lambda: ep.has(name+'/'+path) and self.read(name, path) == body.hex()
                       and ep.status(name)['status']['binding']['view']['head'] == head
                       and ep.status(name)['live']['applied'], 30)
            rows[name] = {'status': ep.status(name), 'fresh_sha256': hashlib.sha256(bytes.fromhex(self.read(name, path))).hexdigest()}
        return rows

    def denied_io(self, name, operations):
        return self.endpoints[name].execute("import json,os,sys\ns=json.load(sys.stdin);rows={}\nfor op,path in s['operations']:\n try:\n  p='/shared/'+s['name']+'/'+path\n  if op=='read':open(p,'rb').read()\n  elif op=='write':\n   with open(p,'wb') as f:f.write(b'denied')\n  elif op=='unlink':os.unlink(p)\n  rows[op+':'+path]=0\n except OSError as e:rows[op+':'+path]=e.errno\nprint(json.dumps(rows))",
            {'name': name, 'operations': operations}, user='1001:1001')

    def seed(self):
        self.i.start_service(); self.wait()
        rows = []
        for name, actor in self.identities.items():
            self.tokens[name] = secrets.token_hex(32)
            rows.append(provision_record(name, actor, self.identities, self.tokens[name], self.tree_root))
        self.i.provision(rows)
        self.tokens['alice'] = self.tokens['a1']
        reports = {'path': 'reports', 'id': identity('entry'), 'parent': self.tree_root['id'],
                   'owner': ALICE, 'group': GROUP, 'mode': 0o777, 'content': {'kind': 'directory'}}
        secret = file_entry('secret', self.tree_root['id'], b'private sibling')
        mode = file_entry('reports/owner-only', reports['id'], b'owner only')
        readable = file_entry('reports/read-only-mode', reports['id'], b'readable no group write'); readable['mode'] = 0o644
        live = file_entry('reports/live', reports['id'], b'seed'); live['mode'] = 0o666
        upload, revision = self.stage(self.descriptor([reports, secret, mode, readable, live]), bodies=[b'private sibling', b'owner only', b'readable no group write', b'seed'])
        self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':revision,'upload':upload})
        self.i.write_json('identity-map.json', self.identities)
        self.hidden_entry = secret['id']

    def setup(self):
        self.seed()
        for name, actor in self.identities.items():
            ep = RecordedLazy(self, name); self.endpoints[name] = ep
            self.bindings[name] = ep.start(name, readonly=name=='readonly', publication='isolated' if name=='a2' else 'shared-live', actor=name,
                replica_identity=actor['replica'], principal=actor['principal'], group=actor['group'], additional_authorities=mount_authorities(actor, self.identities)[1:])
            proof = ep.execute("import os,json,sys;sys.path.insert(0,'/src/tests/fs2');from connected import kernel_mount_present\nn=json.load(sys.stdin);print(json.dumps({'kernel_mounted':kernel_mount_present('/shared/'+n,open('/proc/self/mountinfo').read()),'ordinary_uid':os.geteuid()}))",name,user='1001:1001')
            assert proof == {'kernel_mounted': True, 'ordinary_uid': 1001}
            self.result['measurements']['mounts'].append({'actor':name, **proof, 'provenance':name+'-commands.json'})
            controls = ep.execute("import json,os\nrows={}\nfor p in ['/private','/control/service.json']:\n try:os.listdir(p) if p=='/private' else open(p).read();rows[p]=0\n except OSError as e:rows[p]=e.errno\nassert rows=={'/private':13,'/control/service.json':2};print(json.dumps(rows))", user='1001:1001')
            self.i.write_json(name+'-controls.json', controls)

    def run(self):
        self.setup()
        a2 = self.endpoints['a2']; state = '/private/a2/state'
        # Same principal, separately credentialed replicas: private work never leaks.
        body = b'isolated exact candidate bytes'
        self.write('a2','reports/result',body)
        op = identity('operation')
        revision = a2.cli('checkpoint','--state',state,'--operation-id',op)['revision']
        a2.cli('sync','run','--state',state,'--revision',revision,'--operation-id',op,'--enqueue-only','true')
        private = a2.cli('sync','drain','--state',state,'--revision',revision,'--level','private-remote','--deadline-ms','60000')['progress']
        assert private['state']=='PrivateRemote' and private['private_receipt']['submitted_revision']==revision
        assert private['private_receipt']['replica']==self.identities['a2']['replica']
        before = self.effect()
        for name in ('a1','b','readonly','peer'):
            assert not self.endpoints[name].has(name+'/reports/result')
        self.assertion('same-principal', {'identities': self.identities, 'private': private, 'other_replica_absent': True})
        self.assertion('isolated-private', {'private': private, 'head': before['head'], 'all_other_mounts_absent': True})
        local = next(r['descriptor'] for r in a2.cli('history','--state',state)['revisions'] if r['revision']==revision)
        private_entry = next(e['id'] for e in local['tree']['entries'] if e['path']=='reports/result')
        view = self.private_checks(private, private_entry, body)
        denied = self.denied_io('readonly',[('write','reports/live'),('write','reports/denied'),('unlink','reports/live')])
        assert set(denied.values())=={30}, denied
        self.expect('readonly-upload','POST',self.root+'/uploads',404,body={},actor='readonly')
        scope = self.denied_io('a2',[('read','secret')])
        mode = self.denied_io('b',[('read','reports/owner-only'),('write','reports/read-only-mode')])
        assert all(v in (2,13) for v in scope.values()),scope
        assert all(v in (2,13) for v in mode.values()),mode
        assert self.effect()==before
        self.assertion('readonly', {'errnos':denied,'before':before,'after':self.effect()})
        self.scope_evidence = {'scope':scope,'mode':mode,'identities':self.identities}
        integrated = a2.cli('sync','integrate','--state',state,'--revision',revision,'--expected-head',before['head'])['progress']
        assert integrated['integration']['candidate_receipt']==private['private_receipt']['receipt']
        shared=integrated['shared_receipt']; assert shared['submitted_revision']==revision
        observed=self.visible(('a1','b','readonly','peer'),'reports/result',body,shared['head'])
        self.assertion('explicit-integration', {'private':private,'integrated':integrated,'receivers':observed})
        # Distinct B principal has group authority, despite the same OS UID mapping.
        self.write('b','reports/live',b'principal B shared')
        self.until(lambda:self.head()!=shared['head'],30)
        head=self.head();observed=self.visible(('a1','b','peer'),'reports/live',b'principal B shared',head)
        self.assertion('different-principal', {'identities':self.identities,'receivers':observed})
        # F1: local new identities are private; publication enforces remote prefix.
        before_scope = self.effect()
        scoped_view, projected = self.view('a2')
        projected['parents'] = [scoped_view['revision']]
        projected['principal'] = self.identities['a2']['principal']
        projected['replica'] = self.identities['a2']['replica']
        projected['operation'] = identity('operation')
        projected['tree']['entries'].append(file_entry('outside-scope-new',self.tree_root['id'],b'out of prefix'))
        upload, denied_revision = self.stage(projected,'a2',[b'out of prefix'])
        denied_request = {'operation':projected['operation'],'replica':projected['replica'],
            'original_view':scoped_view['view'],'original_head':scoped_view['head'],'revision':denied_revision,'upload':upload}
        self.expect('absent-out-of-prefix-candidate','POST',self.root+'/candidates',404,{'code':'not_found'},actor='a2',body=denied_request)
        self.expect('absent-out-of-prefix-no-operation','GET',self.op_path(denied_request),404,actor='a2')
        known = {p['operation'] for p in a2.status('a2')['status']['submissions']}
        self.write('a2','secret',b'new local collision retained')
        def rejected():
            return next((p for p in a2.status('a2')['status']['submissions']
                         if p['operation'] not in known and p.get('request') and p.get('error')), None)
        rejected_progress = self.until(rejected,30)
        assert rejected_progress['private_receipt'] is None and rejected_progress['shared_receipt'] is None
        self.expect('mounted-hidden-collision-candidate','POST',self.root+'/candidates',404,{'code':'not_found'},actor='a2',body=rejected_progress['request'])
        self.expect('mounted-hidden-collision-no-operation','GET',self.op_path(rejected_progress['request']),404,actor='a2')
        assert self.effect()==before_scope
        assert self.read('a1','secret')==b'private sibling'.hex()
        assert self.read('a2','secret')==b'new local collision retained'.hex()
        self.assertion('scope-mode', {**self.scope_evidence,'before':before_scope,'after':self.effect(),
            'prefix_request':denied_request,'collision':rejected_progress,'local_new_identity_retained':True,
            'owner_secret_unchanged':True,'boundary':'local private creation allowed; exact remote candidate denied'})
        self.reconnect_case(private, integrated, view)

    def private_checks(self, private, private_entry, body):
        before = self.effect()
        revision = private['local_revision']
        view, descriptor = self.view('a2')
        history = self.expect('private-not-history','GET',self.root+'/history?view='+view['view'],200,actor='a2')
        history_evidence = validate_history_absence(history, private_entry, self.hidden_entry)
        readonly_view, _ = self.view('readonly')
        self.expect('readonly-no-history','GET',self.root+'/history?view='+readonly_view['view'],404,actor='readonly')
        self.expect('guessed-history-selector','POST',self.root+'/history/'+'0'*32+'/view',404,body={},actor='a1')
        self.assertion('private-history', {**history_evidence,'private_revision':revision,'readonly_denied':404})
        for name in ('a1','b','readonly'):
            self.expect(name+'-private-operation','GET',self.op_path(private['request']),404,actor=name)
            self.expect(name+'-private-replay','POST',self.root+'/candidates',404,body=private['request'],actor=name)
            self.expect(name+'-private-receipt','POST',self.root+'/integrations',404,
                body=self.integrate_request(private['private_receipt'],view),actor=name)
            self.expect(name+'-foreign-view','GET',self.root+'/views/'+view['view']+'/descriptor',404,actor=name)
        self.expect('private-selector-closed','POST',self.root+'/views',400,body={'branch':'main','revision':revision},actor='a1')
        self.expect('guessed-view','GET',self.root+'/views/'+'0'*32+'/descriptor',404,actor='a2')
        self.expect('hidden-object','GET',self.root+'/views/'+view['view']+'/objects/'+object_id(b'private sibling'),404,actor='a2')
        object_evidence = private_object_probe(self, 'a1', object_id(body))
        self.expect('wrong-branch','POST',self.root+'/views',404,body={'branch':'other'},actor='a2')
        assert self.effect()==before
        self.assertion('api-bypass', {'before':before,'after':self.effect(),'observations':'observations.json','own_view_private_object':object_evidence})
        return view

    def run_api_correction(self):
        self.seed()
        body = b'isolated API correction private bytes'
        view, descriptor = self.view('a2')
        parent = next(e['id'] for e in descriptor['tree']['entries'] if e['path']=='reports')
        entry = file_entry('reports/result', parent, body)
        descriptor['tree']['entries'].append(entry)
        descriptor.update(principal=self.identities['a2']['principal'], replica=self.identities['a2']['replica'],
                          operation=identity('operation'), parents=[view['revision']])
        upload, revision = self.stage(descriptor, 'a2', [body])
        request = {'operation':descriptor['operation'],'replica':descriptor['replica'],'original_view':view['view'],
                   'original_head':view['head'],'revision':revision,'upload':upload}
        receipt = self.expect('correction-private-candidate','POST',self.root+'/candidates',200,actor='a2',body=request)
        assert receipt['submitted_revision']==revision and receipt['replica']==descriptor['replica']
        self.i.write_json('candidate-binding.json',{'descriptor':descriptor,'request':request,'receipt':receipt,
                          'private_entry':entry['id'],'hidden_entry':self.hidden_entry,'private_object':object_id(body)})
        self.private_checks({'local_revision':revision,'request':request,'private_receipt':receipt},entry['id'],body)

    def reconnect_case(self, private, integrated, view, already_disconnected=False):
        a2 = self.endpoints['a2']
        # Isolated retained state survives disconnect; current authority is rechecked.
        if not already_disconnected:
            self.i.docker('network','disconnect',self.i.ingress,a2.daemon)
            self.write('a2','reports/offline',b'revoked disconnected candidate')
        credential=self.i.sql("SELECT id FROM credentials WHERE replica='"+self.identities['a2']['replica']+"';")
        if not already_disconnected:
            self.expect('revoke-disconnected','POST',self.root+'/grants',200,body={'revoke':credential})
        before=self.effect()
        restarted=restart_retained(a2,'a2')
        self.i.docker('network','connect',self.i.ingress,a2.daemon)
        self.until(lambda:not a2.status('a2')['live']['authorized'],30)
        denied=self.denied_io('a2',[('read','reports/result'),('write','reports/offline')])
        assert set(denied.values())=={13},denied
        for method,path,payload in [('POST','/views',{'branch':'main'}),('GET','/views/'+view['view']+'/descriptor',None),
                ('GET',self.op_path(private['request']).replace(self.root,''),None),('POST','/candidates',private['request']),
                ('POST','/integrations',integrated['integration'])]:
            self.expect('revoked-'+path,method,self.root+path,401,actor='a2',**({'body':payload} if payload is not None else {}))
        assert self.effect()==before
        self.assertion('revoked-reconnect',{'restart':restarted,'denied':denied,'before':before,'after':self.effect(),'retained':a2.status('a2')})
        self.write('peer','reports/live',b'healthy peer after revoke')
        self.until(lambda:self.head()!=before['head'],30)
        head=self.head();observed=self.visible(('b','peer'),'reports/live',b'healthy peer after revoke',head)
        assert not self.endpoints['b'].has('b/reports/offline')
        self.assertion('unaffected-peer',{'receivers':observed,'revoked_offline_absent':True})

    def cleanup(self):
        for ep in self.endpoints.values():
            ep.cleanup()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--api-correction',action='store_true',help='only reviewed history/object API checks; not a phase qualification')
    args=parser.parse_args(argv)
    infra=PhaseInfra(args.output);journey=None
    result={'schema':1,'phase':'isolation-api-correction' if args.api_correction else 'isolation','status':'failed','source':{},'binaries':{},'assertions':[],
            'measurements':{'mounts':[]},'cleanup':{},'failures':[],'blocked':[]}
    try:
        infra.setup(args.image);infra.isolate_service_control()
        result['source'],result['binaries']=source_bridge(infra,args.image)
        journey=Isolation(infra,args.image,result)
        if args.api_correction:journey.run_api_correction()
        else:journey.run()
        after_source,after_binary=source_bridge(infra,args.image)
        assert (after_source,after_binary)==(result['source'],result['binaries'])
        result['status']='passed'
    except InfrastructureUnavailable as error:
        result['status']='blocked';result['blocked'].append(str(error))
    except Exception as error:
        result['failures'].append(str(error));(infra.output/'failure.txt').write_text(traceback.format_exc())
        print(traceback.format_exc(),flush=True)
    finally:
        try:
            if journey:journey.cleanup()
            infra.cleanup()
            result['cleanup']={'ok':True,'mounts_absent':True,'resources_removed':all(r.get('removed') for r in infra.resources),
                               'provenance':['cleanup.json']+[n+'-kernel-mount-cleanup.json' for n in (journey.endpoints if journey else [])]}
        except Exception as error:
            result['cleanup']={'ok':False,'error':str(error)};result['failures'].append('cleanup: '+str(error))
        if not args.api_correction:result=normalize(result)
        elif result['failures'] or not result['cleanup'].get('ok'):result['status']='failed'
        infra.write_json('result.json',result)
    return {'passed':0,'failed':1,'blocked':2}[result['status']]


if __name__=='__main__':raise SystemExit(main())
