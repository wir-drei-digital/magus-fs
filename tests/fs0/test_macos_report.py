import copy
import json
from pathlib import Path
import unittest

from macos_report import summarize_macos
from qualification import validate_content_profile

FIXTURE = Path(__file__).with_name('fixtures') / 'macos-report.json'


class MacEvidence(unittest.TestCase):
    def setUp(self):
        self.native=json.loads(FIXTURE.read_text())
    def summary(self,native=None):
        return summarize_macos(native or self.native,1,262144,'synthetic/result.json')
    def state(self,native,case):
        return self.summary(native).get('cases',{}).get(case,{}).get('state')
    def test_complete_evidence_preserves_adapter_guarantees(self):
        result=self.summary()
        self.assertTrue(all(case['state']=='passed' for case in result['cases'].values()))
        self.assertEqual(result.get('guarantees',{}).get('private_hydration'),'eager')
        self.assertEqual(result.get('guarantees',{}).get('private_hydrated_bytes'),67108958)
        self.assertEqual(result.get('guarantees',{}).get('namespace_create_rename'),'unsupported')
        self.assertEqual(result.get('root_metadata',{}).get('uid'),501)
    def test_each_missing_scenario_cannot_pass(self):
        for name in self.native['cases']:
            with self.subTest(name=name):
                native=copy.deepcopy(self.native);del native['cases'][name]
                self.assertTrue(any(case['state']!='passed' for case in self.summary(native)['cases'].values()))
    def test_false_group_or_subprocess_outcome_cannot_pass(self):
        for name,key,case in [('group','read_via_group','permissions'),('directory400','names_readable_without_search','permissions'),('subprocess','direct_execute','subprocess')]:
            with self.subTest(name=name):
                native=copy.deepcopy(self.native);native['cases'][name]['observed'][key]=False
                self.assertNotEqual(self.state(native,case),'passed')
    def test_false_source_and_generation_outcomes_cannot_pass(self):
        for name,key in [('generation','old_open_and_mmap_pinned'),('source-failure','warmed_file_survives_source_failure'),('source-recovery','exact_head_tail')]:
            with self.subTest(name=name):
                native=copy.deepcopy(self.native);native['cases'][name]['observed'][key]=False
                self.assertNotEqual(self.state(native,'range_reads'),'passed')
    def test_unknown_leaked_or_interrupted_cleanup_cannot_pass(self):
        for change in ('unknown','missing-mount','missing-pid','leak','command','interrupt'):
            with self.subTest(change=change):
                native=copy.deepcopy(self.native)
                if change=='unknown':native['cleanup'][0]['still_mounted']=None
                elif change=='missing-mount':native['cleanup'].pop()
                elif change=='missing-pid':native['reaped'].pop()
                elif change=='leak':native['remaining_owned_resources']=['synthetic-owned-mount']
                elif change=='command':native['commands'][0]['returncode']=None
                else:native['cleanup_interrupts']=1
                self.assertNotEqual(self.state(native,'cleanup'),'passed')
    def test_wrong_mounted_manifest_cannot_pass(self):
        self.native['mounts']['normal-ro']['manifest_digest']='f'*64
        self.assertNotEqual(self.state(self.native,'mount'),'passed')
    def test_private_unsupported_operation_cannot_claim_support(self):
        self.native['cases']['private']['observed']['rename_replacement_old_handle']['observed_support']='supported replacement'
        self.assertNotEqual(self.state(self.native,'private_writes'),'passed')
    def test_false_fsync_or_remount_cannot_pass(self):
        for name,key in [('persist','native_fsync_returned'),('resumed','native_remount_data_and_chmod_preserved')]:
            native=copy.deepcopy(self.native);native['cases'][name]['observed'][key]=False
            self.assertNotEqual(self.state(native,'private_writes'),'passed')
    def test_bad_options_or_missing_root_metadata_cannot_pass(self):
        self.native['mounts']['normal-ro']['effective_options']='vers=3,tcp,nolocks'
        self.assertNotEqual(self.state(self.native,'mount'),'passed')
        native=json.loads(FIXTURE.read_text());del native['cases']['readonly']['observed']['root_metadata']
        self.assertNotEqual(self.state(native,'mount'),'passed')
    def test_composite_commands_include_every_contributor(self):
        result=self.summary()
        for case,contributors in [('permissions',['group','other','file000','file644','directory000','directory400','directory100','private']),('range_reads',['readonly','generation','failure-warm','source-failure','source-recovery']),('subprocess',['subprocess','private','file644'])]:
            with self.subTest(case=case):
                commands=result['cases'][case]['command']
                for name in contributors:self.assertIn(self.native['cases'][name]['command'],commands)
    def test_failed_worker_cannot_pass_from_outer_flag(self):
        self.native['cases']['partial-cold']['state']='failed'
        self.assertNotEqual(self.state(self.native,'partial_cold'),'passed')

    def test_false_final_native_status_cannot_pass(self):
        self.native['passed']=False
        self.assertNotEqual(self.state(self.native,'cleanup'),'passed')


class TransferEvidence(unittest.TestCase):
    def test_matching_but_false_digest_is_rejected(self):
        transfer=json.loads(FIXTURE.read_text())['transfer']
        transfer['full_scan']['digest']=transfer['full_scan']['independent_digest']='f'*64
        self.assertFalse(validate_content_profile(transfer))
    def test_inconsistent_derived_delta_is_rejected(self):
        transfer=json.loads(FIXTURE.read_text())['transfer'];transfer['cold_delta']=1
        self.assertFalse(validate_content_profile(transfer))
