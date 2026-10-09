"""Fail closed on incomplete or contradictory combined evidence."""
import copy
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import ordinary_io
from qualification import aggregate, validate_profile


def profile(platform='macos', journey=1):
    cases={f'V{i}': {'state':'passed','assertions':[{'name':'direct','observed':1,'expected':1,'passed':True}], 'evidence':['native.json']} for i in range(1,13)}
    return {'platform':platform,'journey':journey,'cases':cases,'source_hashes':{'src/lib.rs':'a'*64},
            'binary_sha256':'b'*64,'fault_binary_sha256':'c'*64,'closure_verified':True,
            'warm_body_delta':0,'checkpoint_revision':'sha256:new','recovered_revision':'sha256:new',
            'cleanup':{'verified':True,'remaining_mounts':[],'remaining_containers':[],'remaining_pids':[]},
            'interrupted':False,'native_exit':0,'cli_exit':0,'archive_exit':0,'retention_exit':0}

class Qualification(unittest.TestCase):
    def test_recovered_ack_requires_metadata_and_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,data in [('offline-new',b'ACK survives daemon loss'),('uncached',b'full offline replacement'),('new',b'new generation')]:
                (root/name).write_bytes(data)
            (root/'new').chmod(0o644)
            with patch.object(ordinary_io,'ROOT',root):
                with self.assertRaises(AssertionError):ordinary_io.run('recovered')
                (root/'new').chmod(0o640);(root/'moved').mkdir()
                with self.assertRaises(AssertionError):ordinary_io.run('recovered')
                (root/'moved').rmdir();(root/'unlink-parent').mkdir();(root/'unlink-parent/no-write').touch()
                with self.assertRaises(AssertionError):ordinary_io.run('recovered')
                (root/'unlink-parent/no-write').unlink()
                self.assertEqual(ordinary_io.run('recovered')['modes']['new'],'0640')

    def test_complete_matrix(self):
        self.assertEqual(aggregate([profile(p,j) for p in ['macos','linux'] for j in [1,2]])['exit_code'],0)
    def test_absent_platform_or_journey_fails(self):
        self.assertNotEqual(aggregate([profile()])['exit_code'],0)
    def test_missing_case_fails(self):
        p=profile();del p['cases']['V5'];self.assertTrue(validate_profile(p))
    def test_unverified_closure_fails(self):
        p=profile();p['closure_verified']=False;self.assertTrue(validate_profile(p))
    def test_warm_transfer_fails(self):
        p=profile();p['warm_body_delta']=1;self.assertTrue(validate_profile(p))
    def test_missing_cleanup_fields_fail(self):
        for field in profile()['cleanup']:
            p=profile();del p['cleanup'][field];self.assertTrue(validate_profile(p),field)
    def test_stale_checkpoint_after_ack_fails(self):
        p=profile();p['recovered_revision']='sha256:old';self.assertTrue(validate_profile(p))
    def test_swallowed_interruption_fails(self):
        p=profile();p['interrupted']=True;self.assertTrue(validate_profile(p))
    def test_retained_resources_fail(self):
        for field in ['remaining_mounts','remaining_containers','remaining_pids']:
            p=profile();p['cleanup'][field]=['owned'];self.assertTrue(validate_profile(p))
    def test_skipped_case_and_empty_assertions_fail(self):
        for update in [{'state':'skipped'},{'assertions':[]},{'evidence':[]},{'assertions':[{'passed':True}]}]:
            p=profile();p['cases']['V8'].update(update);self.assertTrue(validate_profile(p))
    def test_missing_prerequisite_is_blocked_not_passed(self):
        result=aggregate([],blocked=['Docker unavailable']);self.assertEqual(result['exit_code'],2)


class Orchestration(unittest.TestCase):
    def test_interrupted_retained_runner_cannot_be_success(self):
        import os,signal,sys,time
        from run import execute
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'retained'
            class Interrupted:
                count=1
            started=time.monotonic()
            record=execute([sys.executable,'-c','import signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);time.sleep(30)'],output,Interrupted(),seconds=.2,grace=.1)
            self.assertLess(time.monotonic()-started,2)
            self.assertNotEqual(record['exit'],0)
            self.assertIn('supervision',record)
            if record['supervision']['runner_alive']:
                os.kill(record['supervision']['runner_pid'],signal.SIGKILL)
                os.waitpid(record['supervision']['runner_pid'],0)

class RawEvidence(unittest.TestCase):
    def normalized(self,native):
        from qualification import normalize
        return normalize('macos',1,native,{},{},{},{k:Path(k+'.json') for k in ['native','cli','archive','retention']})
    def test_closure_claim_without_comparable_inventories_fails(self):
        n={'full_closure':{'verified':True,'daemon_stopped':True}}
        self.assertEqual(self.normalized(n)['cases']['V1']['state'],'failed')
    def test_readonly_success_errno_cannot_qualify(self):
        n={'cases':{'permissions-view':{'mode000_errno':13,'no_search_errno':13,'no_read_errno':13,'readonly_child_unlink':True},'mapping-view':{'foreign_owner_uid':10001,'other_gid':10001,'group_other_and_execute':{'group':13,'other':13,'denied-other':13,'noexec':13}},'readonly-ro':{'denials':[0]*9}}}
        self.assertEqual(self.normalized(n)['cases']['V7']['state'],'failed')


def raw_profile(platform):
    """Small literal observations, independent of production normalization helpers."""
    import json
    from inventory import CLI_CASES
    revision='sha256:'+'1'*64;derived='sha256:'+'2'*64
    status={'ok':True,'captured_revision':revision,'base_revision':revision,'working_generation':1,'uncaptured':True}
    closure={name:{'kind':'directory' if name in ['.','empty'] else 'file','mode':0o755 if name in ['.','empty','report.sh'] else 0o644,'uid':501,'gid':20,**({} if name in ['.','empty'] else {'size':4,'sha256':'a'*64})} for name in ['.','empty','report.sh','instructions.md','binary','data.csv','large']}
    recovered={'bytes':{'new':'new generation','uncached':'full offline replacement','offline-new':'ACK survives daemon loss'},'modes':{'new':'0640'},'absent':['moved','atomic','no-write','made','unlink-parent/no-write']}
    native={'cases':{},'full_closure':{'verified':True,'daemon_stopped':True,'revision':revision,'mounted':closure,'full':copy.deepcopy(closure)},'checkpoint':{'ok':True,'revision':revision},'checkpoint_replay':{'ok':True,'revision':revision},'checkpoint_mismatch':{'error':'operation_mismatch'},'postcheckpoint_status':copy.deepcopy(status),'postmismatch_status':copy.deepcopy(status),'dirty_recovery':{'before':copy.deepcopy(status),'after':copy.deepcopy(status)},'mounted_owner_busy':{name:'replica_busy' for name in ['export','restore','prune','history-grants']}}
    cases=native['cases'];full={'size':67108864,'sha256':'0d9f8390657caaf114fa00a6a191f1559b488bb89f7c61b9e8d95b392330c3e4'}
    offline={'uncached_errno':5,'uncached_seconds':.01,'cached_read':True,'offline_replacement_new_fsync':True}
    if platform=='macos':
        native.update(metadata_transfer={'body_bytes':0},cold_warm_transfer={'body_bytes':524288},warm_transfer={'body_bytes':524288},source_offline={'listener_closed':True,'thread_joined':True},crashes=[{'killed_exit':-9,'old_handle_status':70,'normal_unmount':True,'cleanup_root_access':0} for _ in range(2)])
        fault={'durable_write_errno':28,'before_write':copy.deepcopy(status),'after_write':copy.deepcopy(status),'working_sha256_before_after':'a'*64}
        native['fault']={'native':fault,'old_bytes_after_restart':True}
        cases.update({'partial-view':{'head_tail':4096},'full-view':full,'writes-view':{'create_append_sparse_truncate_unlink_replace_modes_fsync':True},'historical-history':{'original_revision_bytes':True,'new_paths_absent':True},'recovered-old':recovered,'recovered-restart':copy.deepcopy(recovered),'offline-view':offline,'fault-fault':copy.deepcopy(fault),'binary-fault-restart':{'bytes':614400,'sha256':'3c7e7ecba97572f06d6792084bf56a8b2e428534e1e36f0bdf009facfac29512'},'permissions-view':{'mode000_errno':13,'no_search_errno':13,'no_read_errno':13,'readonly_child_unlink':True},'mapping-view':{'foreign_owner_uid':10001,'other_gid':10001,'group_other_and_execute':dict.fromkeys(['group','other','denied-other','noexec'],13)},'readonly-ro':{'denials':[30]*9}})
    else:
        status['uncaptured']='unknown'
        native.update(transfer={'metadata':{'body_bytes':0},'cold':{'body_bytes':524288},'warm':{'body_bytes':524288}},source_outage={'offline':True,'listener_closed':True,'thread_joined':True,'connect_errno':111},diskfull_head={'before':copy.deepcopy(status),'after':copy.deepcopy(status)},loss={'pid':10,'returncode':-9,'mounted':False},dirty_fsync_loss={'pid':11,'returncode':-9,'mounted':False})
        ro=dict.fromkeys(['write','create','mkdir','truncate','rename','unlink','chmod','chown','root-chmod','xattr'],30)
        cases.update({'cold':{'header_tail':4096},'warm':{'header_tail':4096},'full':full,'writes':{'append_sparse_unlink_replace_mkdir_rename_modes_fsync_flock':True},'old-revision':{'old_revision_references_preserved':True},'recovered':recovered,'dirty-fsync-recovered':copy.deepcopy(recovered),'offline':offline,'diskfull':{'errno':28},'old-head':{'old_head_bytes':True},'owner-permissions':{'read_without_search':13,'search_without_read':13,'mode000':13,'writable_parent_unlink':True},'group':{'group_write':13},'other':{'other_read':13},'readonly-owner':ro,'readonly-root':copy.deepcopy(ro),'root-confinement':{'configured_root_dac':True,'confinement':{'uid':0,'source_unreachable':True,'control_paths_absent':True,'daemon_pids_absent':True,'umount_remount_namespace_denied':True,'capabilities':{'CapEff':'0000000000000002','CapBnd':'0000000000000002','NoNewPrivs':'1'}}}})
    cli={'tests':{name:{'state':'passed','assertions':[{'name':'assertEqual','observed':1,'expected':1,'passed':True}], 'commands':[{'command':['status'],'options':{},'result':{'ok':True}}],'stdout':'','failures':[],'skips':[],'cleanup_absent':True} for names in CLI_CASES.values() for name in names}}
    original='/evidence/archive/macos/fixture/original' if platform=='macos' else '/tmp/fixture/original'
    restored={'source_revision':revision,'derived_revision':derived,'head_changed':False,'destination':'/worker/output','verified_bytes':5}
    files={name:{'length':1,'sha256':'b'*64,'mode':0o700 if name=='report.sh' else 0o600} for name in ['._ordinary','binary','data.csv','deleted.txt','report.sh']}
    errors={'missing':'io_error','corrupt':'corrupt_object','extra':'invalid_descriptor','descriptor_reference':'invalid_descriptor','provenance':'invalid_descriptor'}
    a={'passed':True,'original_access':[{'path':original+'/'+leaf,'errno':1 if platform=='macos' else 2,'error':'denied original access'} for leaf in ['state/journal.sqlite','state/objects','tree/binary']], 'network':[{'kind':kind,'address':['127.0.0.1',12345] if platform=='macos' and kind=='tcp' else ['192.0.2.1',9],'errno':1 if platform=='macos' else 101,'error':'network denied'} for kind in ['tcp','udp']],'files':files,'restored':restored,'malformed':[{'case':name,'error':error,'destination_absent':True} for name,error in errors.items()], 'commands':[{'argv':['magus-fs','verify','--archive','/worker/archive'],'exit':0,'stdout':json.dumps({'ok':True,'verification':{'revisions':3,'revision':revision}}),'stderr':''},{'argv':['magus-fs','restore','--archive','/worker/archive'],'exit':0,'stdout':json.dumps({'ok':True,'result':restored}),'stderr':''}]}
    a['commands'] += [{'argv':['magus-fs','restore','--archive','/worker/bad-'+name,'--destination','/worker/reject-'+name],'exit':1,'stdout':json.dumps({'ok':False,'error':error}),'stderr':'expected rejection'} for name,error in errors.items()]
    retention={'quota_error':'backpressure','corruption_error':'corrupt_object','last_copy_error':'base_unavailable','pinned_bytes':8,'reclaimed_bytes':8,'ack_bytes':'ACK','cleanup_absent':True,'generation_unchanged':1}
    return native,cli,{'platforms':{platform:a}},retention


class DecisiveRawEvidence(unittest.TestCase):
    def result(self,platform,values):
        from qualification import normalize
        paths={key:Path('/evidence')/key/'result.json' for key in ['native','cli','archive','retention']}
        updated=profile(platform,1);updated.update(normalize(platform,1,*values,paths))
        return aggregate([updated]+[profile(p,j) for p in ['macos','linux'] for j in [1,2] if (p,j)!=(platform,1)])

    def reject(self,platform,mutate):
        values=raw_profile(platform);mutate(*values)
        result=self.result(platform,values)
        self.assertEqual(result['exit_code'],1,result['failures'])

    def test_complete_raw_observations_qualify_each_platform(self):
        for platform in ['macos','linux']:
            with self.subTest(platform=platform):self.assertEqual(self.result(platform,raw_profile(platform))['exit_code'],0)

    def test_native_enospc_and_restart_are_mandatory(self):
        for platform,case,key in [('linux','diskfull','errno'),('linux','old-head','old_head_bytes'),('macos','binary-fault-restart','sha256')]:
            with self.subTest(platform=platform,case=case):self.reject(platform,lambda n,*_:n['cases'][case].pop(key))
        for key in ['durable_write_errno','before_write','after_write','working_sha256_before_after']:
            with self.subTest(key=key):self.reject('macos',lambda n,*_:n['fault']['native'].pop(key))
        self.reject('macos',lambda n,*_:n['fault']['native'].update(durable_write_errno=0))
        self.reject('linux',lambda n,*_:n['cases']['diskfull'].update(errno=0))
        self.reject('linux',lambda n,*_:n['cases']['old-head'].update(old_head_bytes=False))

    def test_every_cli_assertion_requires_fields_and_success(self):
        for assertion in [{},{'name':'assertEqual','observed':1,'expected':1,'passed':False},{'name':'','observed':1,'expected':1,'passed':True},*[dict((k,v) for k,v in {'name':'assertEqual','observed':1,'expected':1,'passed':True}.items() if k!=missing) for missing in ['name','observed','expected','passed']]]:
            with self.subTest(assertion=assertion):self.reject('linux',lambda n,c,*_:c['tests']['test_scan_barriers_and_failed_capture_retry']['assertions'].append(assertion))

    def test_cli_commands_failures_and_skips_cannot_be_empty_proof(self):
        for field,value in [('commands',[{}]),('failures',['failure']),('skips',['not run']),('stdout',None)]:
            with self.subTest(field=field):self.reject('linux',lambda n,c,*_:c['tests']['test_scan_barriers_and_failed_capture_retry'].update({field:value}))

    def test_expected_cli_rejection_is_distinct_from_failed_assertion(self):
        for code in [1,2]:
            values=raw_profile('linux')
            test=values[1]['tests']['test_scan_barriers_and_failed_capture_retry']
            test['commands'].append({'command':['capture'],'options':{'code':code},'result':{'ok':False,'error':'invalid_input'}})
            with self.subTest(code=code):self.assertEqual(self.result('linux',values)['exit_code'],0)
            test['assertions'][0]['passed']=False
            self.assertEqual(self.result('linux',values)['exit_code'],1)
        for command in [{'command':['capture'],'options':{'code':1},'result':{'ok':True}},
                        {'command':['capture'],'options':{'code':1},'result':{'ok':False}}]:
            self.reject('linux',lambda n,c,*_:c['tests']['test_scan_barriers_and_failed_capture_retry']['commands'].append(command))

    def test_invalid_status_and_missing_macos_offline_success_fail(self):
        self.reject('linux',lambda n,*_:n['diskfull_head'].update(before={'ok':True,'captured_revision':'sha256:'+'1'*64,'base_revision':'sha256:'+'1'*64,'working_generation':1,'uncaptured':None},after={'ok':True,'captured_revision':'sha256:'+'1'*64,'base_revision':'sha256:'+'1'*64,'working_generation':1,'uncaptured':None}))
        for field in ['cached_read','offline_replacement_new_fsync']:
            with self.subTest(field=field):self.reject('macos',lambda n,*_:n['cases']['offline-view'].pop(field))

    def test_each_original_access_requires_exact_path_errno_and_error(self):
        for platform in ['macos','linux']:
            for field in ['path','errno','error']:
                with self.subTest(platform=platform,field=field):self.reject(platform,lambda n,c,a,r:a['platforms'][platform]['original_access'][0].pop(field))
            self.reject(platform,lambda n,c,a,r:a['platforms'][platform]['original_access'][0].update(errno=0))
            self.reject(platform,lambda n,c,a,r:a['platforms'][platform]['original_access'][0].update(path='/unrelated/original/state/journal.sqlite'))
            self.reject(platform,lambda n,c,a,r:a['platforms'][platform]['original_access'].__setitem__(0,copy.deepcopy(a['platforms'][platform]['original_access'][1])))

    def test_each_malformed_archive_requires_case_error_and_absence(self):
        for index in range(5):
            for field in ['case','error','destination_absent']:
                with self.subTest(index=index,field=field):self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['malformed'][index].pop(field))
            self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['malformed'][index].update(error='wrong_error'))
            self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['malformed'][index].update(destination_absent=False))
        self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['malformed'].__setitem__(0,copy.deepcopy(a['platforms']['linux']['malformed'][1])))

    def test_network_file_and_archive_command_details_are_required(self):
        for field in ['kind','address','errno','error']:
            with self.subTest(network_field=field):self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['network'][0].pop(field))
        for field in ['sha256','length','mode']:
            with self.subTest(file_field=field):self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['files']['report.sh'].pop(field))
        self.reject('linux',lambda n,c,a,r:a['platforms']['linux'].update(commands=[]))
        self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['network'].__setitem__(0,copy.deepcopy(a['platforms']['linux']['network'][1])))

    def test_old_history_false_flag_and_incomplete_status_pairs_fail(self):
        self.reject('linux',lambda n,*_:n['cases']['old-revision'].update(old_revision_references_preserved=False))
        self.reject('macos',lambda n,*_:n['cases']['historical-history'].update(new_paths_absent=False))
        for field in ['captured_revision','working_generation','ok']:
            def remove(n,*_):
                n['dirty_recovery']['before'].pop(field);n['dirty_recovery']['after'].pop(field)
            with self.subTest(field=field):self.reject('linux',remove)
        self.reject('linux',lambda n,*_:n.update(diskfull_head={'before':{'ok':True},'after':{'ok':True}}))

    def test_missing_daemon_loss_offline_and_root_confinement_proof_fails(self):
        self.reject('linux',lambda n,*_:n.pop('loss'))
        self.reject('macos',lambda n,*_:n['crashes'][0].pop('normal_unmount'))
        self.reject('linux',lambda n,*_:n['cases'].pop('dirty-fsync-recovered'))
        self.reject('macos',lambda n,*_:n['source_offline'].pop('listener_closed'))
        self.reject('linux',lambda n,*_:n['cases']['root-confinement']['confinement'].pop('control_paths_absent'))

    def test_restoration_requires_source_identity(self):
        self.reject('linux',lambda n,c,a,r:a['platforms']['linux']['restored'].pop('source_revision'))

if __name__=='__main__':unittest.main()
