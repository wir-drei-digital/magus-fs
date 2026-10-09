"""FS1 source/corpus inventory and directly observed CLI assertion evidence."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
CLI_CASES={
 'V5':['test_scan_barriers_and_failed_capture_retry'],
 'V6':['test_native_offline_history_and_materialization'],
 'V10':['test_historical_bytes_preserve_narrower_current_access_metadata','test_standalone_grant_provision_revoke_and_restore_head_are_explicit'],
 'V11':['test_hostile_descriptor_names_block_before_storage','test_unsupported_inventory_and_segment_selection','test_arbitrary_xattr_and_extended_acl_inventory','test_materialized_output_recaptures_without_stripping_host_metadata','test_manifest_replacement_cannot_write_an_unowned_file','test_inherited_staging_acl_blocks_before_hydration','test_external_parent_movement_never_reports_ready','test_archive_restore_parent_symlink_swap_cannot_redirect_output'],
 'V12':['test_checkpoint_and_private_owner_boundary','test_failure_json_and_existing_destination','test_scan_barriers_and_failed_capture_retry'],
}
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def sources():
    paths={ROOT/x for x in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']}
    for directory in ['src','crates','vendor','benches','tests']:
        paths.update(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    return {str(p.relative_to(ROOT)):digest(p) for p in sorted(paths)}
def corpus(tree):
    """Common small Brain assets; platform fixtures separately add 64MiB/permissions."""
    for name,data,mode in [('instructions.md',b'# Synthetic Brain\nRun ./report.sh against data.csv.\n',0o644),('data.csv',b'id,value\n1,synthetic\n',0o644),('report.sh',b'#!/bin/sh\nprintf "synthetic report\\n"\n',0o755),('binary',bytes(range(256))*2400,0o644)]:
        (tree/name).write_bytes(data);(tree/name).chmod(mode)

def tree_inventory(root):
    import stat
    result={}
    for path in [root,*sorted(root.rglob('*'))]:
        st=path.stat();entry={'kind':'directory' if path.is_dir() else 'file','mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}
        if path.is_file():entry.update(size=st.st_size,sha256=digest(path))
        result[str(path.relative_to(root))]=entry
    return result

def serial(value):
    if isinstance(value,bytes):return {'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()}
    if isinstance(value,dict):return {str(k):serial(v) for k,v in value.items()}
    if isinstance(value,(list,tuple,set)):return [serial(v) for v in value]
    if value is None or isinstance(value,(str,int,float,bool)):return value
    return str(value)

class Observations:
    def call(self,*args,**kwargs):
        value=super().call(*args,**kwargs)
        self.commands.append({'command':serial(args),'options':serial(kwargs),'result':value})
        return value

def assertion(method):
    def observe(self,*args,**kwargs):
        result=getattr(super(Observations,self),method)(*args,**kwargs)
        self.assertions.append({'name':method,'observed':serial(args[0]),'expected':serial(args[1]) if len(args)>1 else method,'passed':True})
        return result
    return observe
for method in ['assertEqual','assertNotEqual','assertTrue','assertFalse','assertIn','assertNotIn','assertGreater','assertGreaterEqual','assertLess','assertLessEqual']:
    setattr(Observations,method,assertion(method))

def cli_evidence(output):
    import test_cli
    import test_archive_cli
    report={'tests':{},'binary_sha256':digest(test_cli.BIN),'fault_features':os.environ.get('MAGUS_TEST_FEATURES'),'source_hashes':sources()}
    if report['fault_features']!='test-faults':raise RuntimeError('mandatory fault-enabled CLI binary unavailable')
    for name in sorted({name for names in CLI_CASES.values() for name in names}):
        base=test_cli.CLI if hasattr(test_cli.CLI,name) else test_archive_cli.ArchiveCLI
        cls=type('Observed'+base.__name__,(Observations,base),{})
        test=cls(name);test.assertions=[];test.commands=[]
        result=unittest.TestResult();stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout):test.run(result)
        record={'state':'passed' if result.wasSuccessful() and not result.skipped else 'failed','assertions':test.assertions,'commands':test.commands,'stdout':stdout.getvalue(),'failures':result.failures+result.errors,'skips':result.skipped,'cleanup_absent':not test.d.exists()}
        record['failures']=serial(record['failures']);record['skips']=serial(record['skips']);report['tests'][name]=record
        output.write_text(json.dumps(report,indent=2)+'\n')
    return 0 if all(t['state']=='passed' and t['cleanup_absent'] for t in report['tests'].values()) else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--cli',type=Path);p.add_argument('--sources',action='store_true');a=p.parse_args()
    if a.sources:print(json.dumps(sources(),sort_keys=True))
    elif a.cli:sys.exit(cli_evidence(a.cli))
    else:p.error('choose --cli or --sources')
