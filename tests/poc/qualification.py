"""Exact artifact-linked full FS2/PoC evidence, distinct from the connected slice."""
import hashlib,json,sys
from pathlib import Path
import qualification as connected

CASES={
 'mounted':{'mounted-roots':['roots'],'captured-before-admission-original-binding':['frozen','before','progress'],'disconnected-original-captures':['before','local'],'retained-conflict-explicit-resolution':['base','details','resolution','retained'],'dirty-incoming-contention':['before','during','after'],'automatic-isolated-private-pinned':['initial','progress','status'],'authorized-inventory-and-readiness':['a','b','mac','head','status'],'actual-agent-file':['phase','name','body','metadata','report_sha256'],'actual-agent-receipts':['phase','name','progress','before']},
 'reconciliation':{'disconnected-compatible-and-text-merge':['base_head','final_head','local_before_reconnect','results','merges','observed'],'conflicted-candidate-retained-atomically':['loser','conflicts','details','export_sha256'],'explicit-and-delayed-resolution':['resolution','choices','observed','modes'],'scoped-negatives':['revoked_status','hidden_merge']},
 'recovery':{'history-restore':['new_revision','current_metadata','exact_replay_cardinality'],'historical-path-parent-authority':['replacement_parent_denied','immutable_replay_current_policy'],'reconnect-original-and-cursor':['original_base','private_receipt','shared_receipt'],'repeated-boundary-crashes':['points','progress','final'],'repeated-apply-crashes':['retained','shared_receipt'],'offline-native-cached-read-local-capture':['queued','plaintext_retained'],'mounted-offline-network-partition':['binding'],'storage-gc-restart-quarantine':['concurrent_publication','corrupt_quarantined','roots_retained'],'gc-mark-before-admission':['marked_state','fresh_generation','shared_receipt']},
 'native':{'structural-service-matrix':['before','steps','released'],'held-fd-cwd-root-exchange-recovery-settlement-resume':['records','selection','receipt','crashes','settled','unknown_after_fresh_reread'],'stale-ram-save-unknown-causality':['progress','provenance','parents','drain'],'root-replaced-before-exchange':['status','unowned_listing','original_preserved'],'kill-after-exchange-recovers':['interrupted','recovered','status'],'nfs-live-epochs':[],'nfs-structural-and-parent-replacement':['old_cwd','listing'],'nfs-authority-refresh':['write_denied_visible_errno','revoked_errno','renewed']},
 'dependencies':{'dependency-declarations':['requests','policy'],'stale-input-held':['declaration','private'],'configured-validation':['policy','raw_stale','exact_shared'],'paused-mounted-report-recompute-validate-visible':['original_view','stale','retry','fresh','validation','integrated','mac','mounted'],'publication-route-and-policy-races':['protected_restore','resolution','policy_race','old_validation'],'limits-scope-revocation':['declaration','revoked_validation']},
 'client':{'client-protocol':['drain_owner','checkpoint_admission']},
 'connected':{'connected':['journey','editor','archive']}}
MATRIX={
 'S1':['connected'],'S2':['connected'],'S3':['connected','mounted'],'S4':['mounted','reconciliation'],'S5':['connected','recovery','client'],'S6':['recovery','native'],'S7':['connected','native'],'S8':['recovery'],'S9':['connected','reconciliation'],'S10':['recovery'],'S11':['dependencies'],'S12':['crdt'],'S13':['native','mounted'],'S14':['recovery','client'],'S15':['connected','mounted'],
 'P1':['connected'],'P2':['connected'],'P3':['connected'],'P4':['dependencies'],'P5':['mounted','reconciliation'],'P6':['mounted','reconciliation'],'P7':['reconciliation'],'P8':['connected','reconciliation'],'P9':['connected','recovery','client'],'P10':['native','connected'],'P11':['recovery'],'P12':['connected']}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def artifact(path):return {'path':str(path),'sha256':sha(path)}
def read(ref):
    assert set(ref)=={'path','sha256'} and connected.digest(ref['sha256']) and sha(ref['path'])==ref['sha256'],'artifact hash'
    return json.loads(Path(ref['path']).read_text())
def normalize(e):
    if not isinstance(e,dict):return {'exit':1,'passed':False,'scope':'FS2 and integrated PoC','errors':['malformed evidence']}
    errors=[]
    def need(v,label):
        if not v:errors.append(label)
    try:
        need(e.get('scope')=='FS2 and integrated PoC','full scope');need(e.get('matrix')==MATRIX,'complete exact matrix');need(e.get('platform')=='all','platforms')
        need(e.get('failures')==[] and e.get('blocked')==[],'failed or blocked')
        source=e['source'];need(source['build_profile']['runtime']=='release','release profile');need(source['matched'] is True,'source match')
        for ref in e['source_artifacts']:read(ref)
        need(bool(e['source_artifacts']),'raw source artifacts')
        static=read(e['static']);need(static['crdt']['passed'] is True and bool(static['predecessors']),'static bridges')
        for ref in static['artifacts']:read(ref)
        journeys=e['journeys'];need(len(journeys)==2,'two journeys');need(len({j['owner'] for j in journeys})==2,'fresh owners');owners=[];connected_rows=[]
        for j in journeys:
            need(j['seconds']<=5400,'journey deadline');need(set(j['components'])==set(CASES),'all components')
            for name,required in CASES.items():
                c=j['components'][name];owners.append(c['owner']);need(type(c['exit']) is int and c['exit']==0,'component exit '+name);need(c['image']==source['image'] and c['profile']=='release','immutable profile '+name)
                need(c['source_sha256']==source['sha256'],'component source '+name);need(c['cleanup']['verified'] is True and all(c['cleanup'][k]==[] for k in ['mounts','pids','resources']),'cleanup '+name)
                records=read(c['raw']);need(isinstance(records,list),'raw records '+name)
                for case,fields in required.items():
                    rows=[r for r in records if r.get('case')==case];need(bool(rows),'case '+case)
                    for row in rows:
                        need(all(k in row and row[k] is not None for k in fields),'raw fields '+case)
                        for field in ['new_revision','current_metadata','exact_replay_cardinality','replacement_parent_denied','immutable_replay_current_policy','plaintext_retained','concurrent_publication','corrupt_quarantined','roots_retained','original_preserved','renewed']:
                            if field in fields:need(row.get(field) is True,'raw positive '+case+'.'+field)
                if name=='connected':
                    row=records[0];replacement=row['journey']['replacement'];need(replacement['actual']==replacement['expected'] and replacement['unmount']['still_mounted'] is False and replacement['discarded']=='/private/live','ephemeral replacement reconstruction');connected_rows.append(row['journey']);editor=row['editor'];archive=row['archive']
                    need(editor['api']=='TextDocument.save' and editor['saved'] is True and editor['dirty'] is False and bool(editor['installed_version']) and editor['cleanup']['remaining']==[],'real editor')
                    need(editor['sha256']==editor['expected_sha256'] and editor['progress']['shared_receipt'] is not None,'editor shared bytes')
                    need(archive['network_mode']=='none' and archive['mounts']==[] and archive['credentials_absent'] is True and len(archive['network_denied'])==2 and len(archive['original_denied'])>=3,'independent restore')
                    need(archive['actual']==archive['expected']['inventory'] and archive['rejected_absent'] is True and archive['corruption']['ok'] is False,'archive bytes/corruption')
                    need(archive['actual']['instructions.md']['sha256']==editor['sha256'] and archive['actual']['reports/result.json']['sha256']==row['journey']['worker_private']['expected_hash'],'same journey editor/report archive')
                if name=='mounted':
                    rows=[r for r in records if r['case']=='actual-agent-file'];need(len(rows)==4,'two agents/two phases');ids={}
                    for row in rows:
                        m=row['metadata'];need(bool(m['agent_id']) and Path(m['report']).is_file() and sha(m['report'])==row['report_sha256'],'actual agent report');ids.setdefault(row['name'],[]).append(m['agent_id'])
                    need(set(ids)=={'a','b'} and all(len(v)==2 and len(set(v))==1 for v in ids.values()) and len({v[0] for v in ids.values()})==2,'same two agents')
                    before=max(i for i,r in enumerate(records) if r['case']=='actual-agent-file' and r['phase']=='write');after=min(i for i,r in enumerate(records) if r['case']=='actual-agent-file' and r['phase']=='follow-up')
                    need(all(before<next(i for i,r in enumerate(records) if r['case']==k)<after for k in ['captured-before-admission-original-binding','disconnected-original-captures','retained-conflict-explicit-resolution']),'agents span faults')
                if name=='dependencies':
                    d=next(r for r in records if r['case']=='dependency-declarations');initial=next(r for r in records if r['case']=='configured-validation')['policy'];race=next(r for r in records if r['case']=='publication-route-and-policy-races')['policy_race']
                    need(initial['version']=='1' and d['policy']['version']=='2' and {k:v for k,v in initial.items() if k!='version'}=={k:v for k,v in d['policy'].items() if k!='version'} and race==[409,{'code':'recompute_required'}],'validator policy transition')
                    need(bool(d['requests']) and connected.revision(d['policy']['image_digest']) and connected.revision(d['policy']['executable_hash']),'validator version/source')
                    for request in d['requests'].values():
                        need(request['coverage'] in ['complete_declared','partial','unknown'] and bool(request['reads']),'dependency coverage')
                        for read_input in request['reads']:need(connected.revision(read_input['revision']) and bool(read_input['view']) and bool(read_input['entry']),'dependency input version')
                    r=next(r for r in records if r['case']=='paused-mounted-report-recompute-validate-visible');need(r['retry']['progress']['error']=='dependency_changed' and r['stale']['shared_receipt'] is None and bool(r['integrated']['progress']['shared_receipt']),'dependency held/recomputed')
            need(set(j['components']['native']['platforms'])=={'macos','linux'},'native both')
        need(len(owners)==len(set(owners)),'fresh component owners')
        legacy=connected.normalize({**e,'journeys':connected_rows});need(legacy['passed'],'connected raw contract: '+repr(legacy['errors']))
    except (AssertionError,KeyError,TypeError,ValueError,AttributeError,OSError,StopIteration,IndexError,RuntimeError) as ex:errors.append('malformed or absent raw evidence: '+str(ex))
    code=0 if not errors else 2 if e.get('blocked') and not e.get('failures') else 1
    return {'exit':code,'passed':code==0,'scope':'FS2 and integrated PoC','errors':errors,'evidence':e}
