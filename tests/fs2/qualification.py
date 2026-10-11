"""Strict, recursively complete FS2-A connected-slice evidence; never full FS2."""
import math

ASSERTIONS={'native':('offline','live','worker'),'lazy':('metadata_zero','cold_bounded','warm_zero','full_hash'),'security':('api','hash','history','readonly','revoked'),'faults':('service_restart','client_restart','committed_ack','wss_hint','watch_event')}

def digest(v):return isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v)
def revision(v):return isinstance(v,str) and v.startswith('sha256:') and digest(v[7:])
def number(v):return type(v) in (int,float) and math.isfinite(v) and v>=0
def count(v):return type(v) is int and v>=0

def normalize(evidence):
    if not isinstance(evidence,dict):return {"exit":1,"passed":False,"scope":"FS2-A connected slice only","errors":["malformed evidence"]}
    errors=[]
    def require(value,label):
        if not value:errors.append(label)
    try:
        require(evidence.get('platform')=='all','both platforms required')
        require(evidence.get('failures')==[],'failed attempts in this gate')
        require(evidence.get('blocked')==[],'missing prerequisites')
        source=evidence.get('source',{})
        require(source.get('matched') is True,'source match')
        require(isinstance(source.get('sha256'),dict) and bool(source['sha256']) and all(digest(h) for h in source['sha256'].values()),'source inventory')
        require(digest(source.get('host_binary')) and digest(source.get('linux_binary')) and revision(source.get('image')),'binary/image provenance')
        require(source.get('fault_hooks_absent_default') is True,'default fault hooks absent')
        checks=source.get('checks',{})
        require(all(type(checks.get(k)) is int and checks[k]==0 for k in ['host','linux','python','fmt','clippy']),'source checks')
        journeys=evidence.get('journeys',[])
        require(isinstance(journeys,list) and len(journeys)==2,'two fresh journeys')
        owners=[]
        for j in journeys:
            owners.append(j.get('fresh_owner'))
            require(bool(j.get('id')) and bool(j.get('fresh_owner')),'journey ownership')
            require(set(j.get('platforms',[]))=={'macos','linux'},'journey platforms')
            for group,keys in ASSERTIONS.items():
                assertions=j.get('assertions',{}).get(group,{})
                require(all(assertions.get(k) is True for k in keys),'native assertion '+group)
            receipts=j.get('receipts',[])
            require(isinstance(receipts,list) and bool(receipts),'receipts')
            for r in receipts:
                private=r.get('private',{});shared=r.get('shared',{})
                raw=r.get('raw_progress',{});integration=r.get('integration',{})
                require(revision(r.get('revision')) and revision(r.get('applied')) and raw.get('local_revision')==r.get('revision') and raw.get('operation')==r.get('operation') and raw.get('applied_revision')==r.get('applied'),'revision identities')
                require(all(private.get(k)==r.get(v) and r.get(v) is not None for k,v in [('operation','operation'),('submitted_revision','revision'),('original_view','original_view'),('original_head','original_head')]),'original receipt/base')
                require(bool(integration) and raw.get('integration')==integration and integration.get('expected_head')==r.get('original_head') and integration.get('candidate_receipt')==private.get('receipt') and all(bool(integration.get(k)) and integration[k]==shared.get(k) for k in ['operation','replica','branch']) and integration.get('replica')==private.get('replica'),'original integration binding')
                require(shared.get('candidate_receipt')==r.get('private_receipt')==private.get('receipt') and bool(r.get('private_receipt')) and shared.get('submitted_revision')==r.get('revision') and raw.get('private_receipt')==private and raw.get('shared_receipt')=={k:v for k,v in shared.items() if k!='candidate_receipt'},'private/shared receipt binding')
            saves=j.get('saves',[])
            require(len(saves)==20,'20 serialized saves')
            targets=[]
            for sample in saves:
                times=[sample.get(k) for k in ['capture','private','shared','visible']]
                require(all(number(t) for t in times) and times==sorted(times),'save latency timeline')
                require(number(sample.get('visible')) and sample['visible']<=15,'15s save visibility budget')
                index=sample.get('receipt_index');valid=type(index) is int and 0<=index<len(receipts)
                require(valid,'target save receipt')
                if valid:
                    require(sample.get('local_revision')==receipts[index].get('revision') and sample.get('operation')==receipts[index].get('operation'),'exact target drain')
                    targets.append(sample.get('operation'))
            require(len(set(targets))==20,'unique serialized save targets')
            transfer=j.get('transfer',{})
            require(all(count(transfer.get(k)) for k in ['procedure_body_bytes','report_body_bytes','backend_verification_bytes','retries']),'physical transfer counters')
            require(0<transfer.get('procedure_body_bytes',0)<=2*1024*1024 and 0<transfer.get('report_body_bytes',0)<=2*1024*1024 and transfer.get('unchanged_chunks_reused') is True,'bounded delta/reuse')
            cleanup=j.get('cleanup',{})
            require(cleanup.get('verified') is True and cleanup.get('resources_removed') is True and all(cleanup.get(k)==[] for k in ['mounts','pids','containers']),'owned cleanup')
        require(len(owners)==2 and len(set(owners))==2,'fresh distinct owners')
    except (TypeError,ValueError,KeyError,AttributeError):errors.append('malformed evidence')
    exit_code=0 if not errors else 2 if evidence.get('blocked') and not evidence.get('failures') else 1
    return {'exit':exit_code,'passed':exit_code==0,'scope':'FS2-A connected slice only','errors':errors,'evidence':evidence}

def normalize_full(evidence):
    import importlib.util
    from pathlib import Path
    spec=importlib.util.spec_from_file_location('poc_qualification',Path(__file__).parents[1]/'poc'/'qualification.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.normalize(evidence)
