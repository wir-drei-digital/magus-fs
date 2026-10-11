#!/usr/bin/env python3
"""Full FS2 + twice-fresh integrated PoC. Never upgrades component-only success."""
import argparse,hashlib,importlib.util,json,os,shutil,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/fs2'))
from infra import OwnedInfra,InfrastructureUnavailable
from provenance import capture,sources
from qualification import normalize_full
spec=importlib.util.spec_from_file_location('poc_journey',Path(__file__).with_name('journey.py'));journey=importlib.util.module_from_spec(spec);spec.loader.exec_module(journey)
audit=journey.local_module('evidence')

def current_crdt(folders):
    from crdt_comparison import validate_evidence
    if not folders:raise InfrastructureUnavailable('two current standalone CRDT proofs required; use --crdt-from FIRST SECOND')
    assert len(folders)==2 and len({str(Path(p).resolve()) for p in folders})==2,'two distinct CRDT evidence owners required'
    rows=[];refs=[]
    for folder in folders:
        out=Path(folder);assessment=validate_evidence(out)
        source=json.loads((out/'source.json').read_text());assert all(journey.q.sha(ROOT/n)==h for n,h in source['sha256'].items()),'CRDT current source mismatch'
        result=json.loads((out/'result.json').read_text());assert result['passed'] is True and result['assessments']==assessment and result['semantic_findings'],'CRDT raw intent assessment'
        def stable(value):
            if isinstance(value,dict):return {k:stable(v) for k,v in value.items() if not k.endswith('_us') and k!='state_path'}
            if isinstance(value,list):return [stable(v) for v in value]
            return value
        raw={p.name:[stable(json.loads(line)) for line in p.read_text().splitlines() if line] for p in sorted(out.glob('*.jsonl'))}
        states={str(p.relative_to(out)):journey.q.sha(p) for p in out.rglob('*.am')}
        assert raw and states
        rows.append({'source':source['sha256'],'assessment':assessment,'binary':json.loads((out/'binary.json').read_text()),'dependencies':json.loads((out/'dependencies.json').read_text()),'raw':raw,'states':states})
        refs += [journey.q.artifact(out/n) for n in ['source.json','registry.json','binary.json','dependencies.json','result.json','benchmarks.json']]
    assert rows[0]==rows[1],'CRDT source/binary/dependencies/raw semantic/state repeatability mismatch'
    return refs,{'passed':True,'owners':[str(Path(p).resolve()) for p in folders],'source_files':len(rows[0]['source']),'raw_jsonl_files':len(rows[0]['raw'])*2,'state_files':len(rows[0]['states'])*2,'same_source_binary_dependencies_raw_semantics_and_states':True,'timings_compared':False}

def static(i,folders=None):
    refs,repeat=current_crdt(folders);i.write_json('crdt-repeatability.json',repeat);refs.append(journey.q.artifact(i.output/'crdt-repeatability.json'))
    canonical=Path('/Users/daniel/Development/magus-fs');preservation=canonical/'.superpowers/sdd/fs2-a-plan/preservation-inventory.json';p=json.loads(preservation.read_text());verified=[]
    for entry in p['files']:
        if entry['path'].startswith(('.superpowers/sdd/fs0-plan/','.superpowers/sdd/fs1-plan/')):
            path=canonical/entry['path'];assert journey.q.sha(path)==entry['sha256'];verified.append(entry)
    assert verified
    bridge={'scope':'Unchanged FS0/FS1 historical primitive/format qualifications; changed engine/adapter behavior covered by checked Rust scope recorded in final-source.json + current native component','preservation_manifest':journey.q.artifact(preservation),'files':verified,'current_unchanged_inputs':{}}
    for folder in ['vendor','tests/fs0','tests/fs1']:
        for path in (ROOT/folder).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                relative=path.relative_to(ROOT);prior=canonical/relative
                if prior.is_file() and journey.q.sha(path)==journey.q.sha(prior):bridge['current_unchanged_inputs'][str(relative)]=journey.q.sha(path)
    i.write_json('static.json',{'crdt':{'passed':True,'disposition':'reject automatic ordinary-file adoption; retained intent failure'},'predecessors':bridge,'artifacts':refs});return journey.q.artifact(i.output/'static.json')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=Path);ap.add_argument('--crdt-from',nargs=2,type=Path,metavar=('FIRST','SECOND'),help='two distinct completed standalone CRDT evidence outputs with exact current inputs');ap.add_argument('--checks-from',type=Path,help='reuse completed checks only when exact Rust/Cargo/toolchain and affected test inputs match');ap.add_argument('--r41-checks-from',type=Path,help='explicit R42 checked-source release: current Core sync_state + CLI tests and workspace fmt/clippy on both platforms, not full workspace Rust');ap.add_argument('--linux-checks-from',type=Path,help='reuse completed full Linux checks for exact unchanged runtime/build inputs');ap.add_argument('--platform',choices=['all','linux','macos'],default='all');a=ap.parse_args()
    if not a.output.is_absolute() or a.output.exists() or not a.output.parent.is_dir():ap.error('new absolute output with existing parent required')
    i=OwnedInfra(a.output);e={'scope':'FS2 and integrated PoC','platform':a.platform,'matrix':journey.q.MATRIX,'failures':[],'blocked':[],'journeys':[],'source':{},'source_artifacts':[]}
    try:
        if a.platform!='all' or sys.platform!='darwin':raise InfrastructureUnavailable('both macOS and Linux required on qualified Mac host')
        if os.environ.get('RUSTFLAGS') or any(k.startswith('CARGO_PROFILE_RELEASE_') for k in os.environ):raise InfrastructureUnavailable('default release profile required')
        i.preflight();disk=i.run(['rdctl','shell','df','-Pk','/var/lib/docker']).stdout;assert int(disk.splitlines()[-1].split()[3])>=20*1024*1024,'Docker free below20GiB'
        e['static']=static(i,a.crdt_from);source=capture(i);source['build_profile']={'runtime':'release','checks':'debug','flags':'default release without RUSTFLAGS'};checks={}
        rust_checks=[('fmt',['cargo','+stable','fmt','--all','--check']),('clippy',['cargo','+stable','clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings']),('host',['cargo','+stable','test','--locked','--workspace','--all-features'])]
        checked_release=None
        if a.r41_checks_from:
            if a.checks_from or a.linux_checks_from:raise ValueError('R41 checked release cannot be combined with prior full-check options')
            checked_release=json.loads((a.r41_checks_from/'final-source.json').read_text())
            assert source['sha256']==checked_release['sha256'] and source['compiler']==checked_release['compiler'] and source['dockerignore_sha256']==checked_release['dockerignore_sha256'] and source['build_profile']==checked_release['build_profile'],'R41 checked-source mismatch'
            proof=journey.q.read(checked_release['scoped_checks'])
            assert proof['scope']=={'host':'Core sync_state23 + CLI17; workspace fmt/clippy all targets/features','linux':'Core sync_state23 + CLI16; workspace fmt/clippy all targets/features','full_workspace_rust':False} and proof['source_sha256']==source['sha256'],'R42 exact check scope/source required'
            expected_host=[rust_checks[0][1],rust_checks[1][1],['cargo','+stable','test','--locked','-p','magus-fs-core','--all-features','--test','sync_state'],['cargo','+stable','test','--locked','-p','magus-fs','--all-features']]
            assert [row['argv'] for row in proof['host']]==expected_host
            for row in [*proof['host'],proof['linux']]:
                assert type(row['status']) is int and row['status']==0 and journey.q.sha(row['log']['path'])==row['log']['sha256'],'failed/missing scoped check log'
            assert proof['linux']['argv'][:6]==['docker','build','--pull=false','--progress=plain','-f','tests/fs2/Dockerfile.linux'] and 'VERIFY=r41' in proof['linux']['argv'] and 'BUILD_PROFILE=release' in proof['linux']['argv']
            source['checked_release']={'source':journey.q.artifact(a.r41_checks_from/'final-source.json'),'checks':checked_release['scoped_checks'],'scope':proof['scope'],'prior_full_workspace_rust':proof['prior_full_workspace_rust']}
            checks.update(fmt=0,clippy=0,host=0,linux=0)
        elif a.checks_from:
            prior=json.loads((a.checks_from/'source.json').read_text());commands=json.loads((a.checks_from/'commands.json').read_text())
            inputs={n:h for n,h in source['sha256'].items() if not n.startswith(('tests/poc/','tests/fs2/'))}
            assert inputs=={n:h for n,h in prior['sha256'].items() if not n.startswith(('tests/poc/','tests/fs2/'))},'reused checks source mismatch'
            proofs=[]
            for label,argv in rust_checks:
                row=next(r for r in commands if r['argv']==argv and type(r['status']) is int and r['status']==0);proofs.append({'check':label,'command':row,'log':journey.q.artifact(a.checks_from/row['log'])});checks[label]=0
            for directory in ['tests/fs0','tests/fs1']:
                row=next(r for r in commands if r['argv'][-3:]==[directory,'-p','test_*.py'] and r['status']==0);proofs.append({'check':directory,'command':row,'log':journey.q.artifact(a.checks_from/row['log'])})
            source['reused_checks']={'source':journey.q.artifact(a.checks_from/'source.json'),'inputs':inputs,'proofs':proofs,'reason':'only qualification harness changed; exact Rust/Cargo/toolchain/fs0/fs1 inputs unchanged'}
        else:
            for label,argv in rust_checks:i.run(argv,timeout=600);checks[label]=0
            for directory in ['tests/fs0','tests/fs1']:i.run([sys.executable,'-m','unittest','discover','-s',directory,'-p','test_*.py'],timeout=600)
        for directory in ['tests/fs2','tests/poc']:i.run([sys.executable,'-m','unittest','discover','-s',directory,'-p','test_*.py'],timeout=600)
        checks['python']=0
        if checked_release:
            immutable=checked_release['image'];image=json.loads(i.docker('image','inspect',immutable).stdout)[0]
            assert image['Id']==immutable and image['Config']['Labels']['magus.fs2.build-profile']=='release'
            for name,expected in checked_release['runtime_binaries']['host'].items():assert journey.q.sha(ROOT/'target/release'/name)==expected,'checked host binary changed'
        else:
            i.run(['cargo','+stable','build','--release','--locked','-p','magus-fs','-p','magus-fs-service','--features','test-faults'],timeout=300)
            for name in ['magus-fs','magus-fs-service']:
                destination=ROOT/'target/release'/('magus-fs-client-faults' if name=='magus-fs' else name+'-faults');shutil.copyfile(ROOT/'target/release'/name,destination);destination.chmod(0o755)
            i.run(['cargo','+stable','build','--release','--locked','-p','magus-fs','-p','magus-fs-service','--examples'],timeout=300)
            i.run(['cargo','+stable','build','--release','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=300)
            tag=i.owner+'-full';i.write_json('image-ownership.json',{'tag':tag,'intent':'retained exact release full FS2 image'})
            verify='1';linux_bridge=None
            binary_names=['magus-fs','magus-fs-client-faults','magus-fs-service','magus-fs-service-faults','client_probe']
            binary_script="import hashlib,json;from pathlib import Path;print(json.dumps({n:hashlib.sha256(Path('/usr/local/bin/'+n).read_bytes()).hexdigest() for n in "+repr(binary_names)+"}))"
            if a.linux_checks_from:
                prior=json.loads((a.linux_checks_from/'final-source.json').read_text());commands=json.loads((a.linux_checks_from/'commands.json').read_text())
                inputs=lambda data:{n:h for n,h in data['sha256'].items() if not n.startswith('tests/poc/') and n!='tests/fs2/connected.py'}
                assert inputs(source)==inputs(prior) and source['dockerignore_sha256']==prior['dockerignore_sha256'] and source['compiler']==prior['compiler'] and source['build_profile']==prior['build_profile'],'Linux build/check inputs changed'
                row=next(r for r in commands if r['argv'][:7]==['docker','build','--pull=false','--progress=plain','-f','tests/fs2/Dockerfile.linux','--build-arg'] and 'VERIFY=1' in r['argv'] and 'BUILD_PROFILE=release' in r['argv'] and 'BIN_DIR=release' in r['argv'] and type(r['status']) is int and r['status']==0)
                previous=json.loads(i.docker('image','inspect',prior['image']).stdout)[0];assert previous['Id']==prior['image'] and previous['Config']['Labels']['magus.fs2.build-profile']=='release'
                prior_binaries=json.loads(i.docker('run','--rm','--network','none',prior['image'],'python3','-c',binary_script).stdout)
                linux_bridge={'source':journey.q.artifact(a.linux_checks_from/'final-source.json'),'command':row,'log':journey.q.artifact(a.linux_checks_from/row['log']),'unchanged_inputs':inputs(source),'compiler':source['compiler'],'profile':source['build_profile'],'dockerignore_sha256':source['dockerignore_sha256'],'previous_image':prior['image'],'previous_binaries':prior_binaries,'changed_host_sources':{n:{'before':prior['sha256'].get(n),'after':source['sha256'].get(n)} for n in sorted(set(prior['sha256'])|set(source['sha256'])) if prior['sha256'].get(n)!=source['sha256'].get(n)}}
                verify='0'
            i.docker('build','--pull=false','--progress=plain','-f','tests/fs2/Dockerfile.linux','--build-arg','BUILD_PROFILE=release','--build-arg','BIN_DIR=release','--build-arg','VERIFY='+verify,'--label','magus.fs2.owner='+i.owner,'-t',tag,'.',timeout=1200);checks['linux']=0
            image=json.loads(i.docker('image','inspect',tag).stdout)[0];assert image['Config']['Labels']['magus.fs2.build-profile']=='release';immutable=image['Id']
            if linux_bridge:
                rebuilt=json.loads(i.docker('run','--rm','--network','none',immutable,'python3','-c',binary_script).stdout)
                assert rebuilt==linux_bridge['previous_binaries'],'rebuilt runtime binaries differ from qualified image'
                linux_bridge.update(current_image=immutable,current_binaries=rebuilt,verified=True);i.write_json('linux-checks-bridge.json',linux_bridge);source['linux_checks_bridge']=journey.q.artifact(i.output/'linux-checks-bridge.json')
        markers=[b'MAGUS_TEST_DROP_WSS_HINTS',b'MAGUS_TEST_DROP_NATIVE_HINTS',b'MAGUS_TEST_TRANSFER_LOG',b'MAGUS_TEST_FAULT_POINT',b'MAGUS_TEST_LOOKUP_EPOCH_BARRIER']
        host={n:journey.q.sha(ROOT/'target/release'/n) for n in ['magus-fs','magus-fs-client-faults','magus-fs-service','magus-fs-service-faults']}
        assert all(m not in (ROOT/'target/release'/n).read_bytes() for n in ['magus-fs','magus-fs-service'] for m in markers)
        raw=i.docker('run','--rm','--network','none',immutable,'python3','-c',"import hashlib,json;from pathlib import Path;markers="+repr(markers)+";names="+repr(list(host))+";assert all(m not in Path('/usr/local/bin/'+n).read_bytes() for n in ['magus-fs','magus-fs-service'] for m in markers);print(json.dumps({n:hashlib.sha256(Path('/usr/local/bin/'+n).read_bytes()).hexdigest() for n in names}))").stdout
        linux=json.loads(raw)
        if checked_release:assert linux==checked_release['runtime_binaries']['linux'],'checked Linux binaries changed'
        e['source']={**source,'matched':True,'checks':checks,'host_binary':host['magus-fs'],'linux_binary':linux['magus-fs'],'image':immutable,'fault_hooks_absent_default':True,'runtime_binaries':{'host':host,'linux':linux}}
        i.write_json('final-source.json',e['source']);e['source_artifacts']=[journey.q.artifact(i.output/'source.json'),journey.q.artifact(i.output/'final-source.json')]
        for number in [1,2]:e['journeys'].append(journey.run(a.output/('journey-'+str(number)),immutable,e['source'],number));i.write_json('evidence.json',e)
        assert sources()==source['sha256']
    except InfrastructureUnavailable as error:e['blocked'].append(str(error))
    except Exception as error:e['failures'].append({'reason':str(error),'trace':traceback.format_exc()});traceback.print_exc()
    finally:
        result=normalize_full(e);i.write_json('evidence.json',e);result=audit.finalize(i.output,result);i.write_json('result.json',result)
    print(json.dumps({'exit':result['exit'],'output':str(a.output),'scope':e['scope']}));return result['exit']
if __name__=='__main__':raise SystemExit(main())
