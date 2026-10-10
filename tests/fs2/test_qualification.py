"""Fail-closed connected evidence contract; these are normalizer tests, not filesystem mocks."""
import unittest
from qualification import normalize
H='a'*64
R='sha256:'+H

def complete():
    journeys=[]
    for i in [1,2]:
        receipts=[];saves=[]
        for n in range(20):
            operation='operation:'+format(i*100+n,'032x');revision='sha256:'+format(i*100+n,'064x');private={'receipt':'3'*32,'operation':operation,'submitted_revision':revision,'original_view':'1'*32,'original_head':'2'*32}
            shared={'receipt':'4'*32,'submitted_revision':revision,'candidate_receipt':'3'*32}
            receipts.append({'operation':operation,'revision':revision,'original_view':'1'*32,'original_head':'2'*32,'private':private,'shared':shared,'private_receipt':'3'*32,'applied':R,'raw_progress':{'operation':operation,'local_revision':revision,'private_receipt':private,'shared_receipt':{k:v for k,v in shared.items() if k!='candidate_receipt'},'applied_revision':R}})
            saves.append({'capture':.1,'private':.2,'shared':.3,'visible':.4,'receipt_index':n,'operation':operation,'local_revision':revision})
        journeys.append({'id':str(i),'fresh_owner':str(i),'platforms':['macos','linux'],'assertions':{'native':{'offline':True,'live':True,'worker':True},'lazy':{'metadata_zero':True,'cold_bounded':True,'warm_zero':True,'full_hash':True},'security':{'api':True,'hash':True,'history':True,'readonly':True,'revoked':True},'faults':{'service_restart':True,'client_restart':True,'committed_ack':True,'wss_hint':True,'watch_event':True}},'receipts':receipts,'saves':saves,'transfer':{'procedure_body_bytes':4,'report_body_bytes':8,'backend_verification_bytes':12,'retries':0,'unchanged_chunks_reused':True},'cleanup':{'verified':True,'mounts':[],'pids':[],'containers':[],'resources_removed':True}})
    return {'platform':'all','failures':[],'blocked':[],'source':{'matched':True,'sha256':{'src.rs':H},'host_binary':H,'linux_binary':H,'image':'sha256:'+H,'checks':{'host':0,'linux':0,'python':0,'fmt':0,'clippy':0},'fault_hooks_absent_default':True},'journeys':journeys}

class QualificationTests(unittest.TestCase):
    def test_complete(self):self.assertEqual(normalize(complete())['exit'],0)
    def rejected(self,change):
        e=complete();change(e);self.assertNotEqual(normalize(e)['exit'],0)
    def test_absent_nested_assertion(self):self.rejected(lambda e:e['journeys'][0]['assertions']['native'].pop('offline'))
    def test_false_nested_assertion(self):self.rejected(lambda e:e['journeys'][0]['assertions']['native'].update(live=False))
    def test_wrong_original_base(self):self.rejected(lambda e:e['journeys'][0]['receipts'][0]['private'].update(original_head='9'*32))
    def test_wrong_receipt(self):self.rejected(lambda e:e['journeys'][0]['receipts'][0]['shared'].update(candidate_receipt='9'*32))
    def test_skipped_platform(self):self.rejected(lambda e:e['journeys'][0].update(platforms=['macos']))
    def test_missing_provenance(self):self.rejected(lambda e:e['source'].pop('sha256'))
    def test_unresolved_mount(self):self.rejected(lambda e:e['journeys'][0]['cleanup'].update(mounts=['/shared/live']))
    def test_incomplete_cleanup(self):self.rejected(lambda e:e['journeys'][0]['cleanup'].update(resources_removed=False))
    def test_duplicate_owner(self):self.rejected(lambda e:e['journeys'][1].update(fresh_owner='1'))
    def test_missing_measurement(self):self.rejected(lambda e:e['journeys'][0]['saves'].pop())
    def test_wrong_applied_identity(self):self.rejected(lambda e:e['journeys'][0]['receipts'][0].update(applied='bad'))
    def test_skipped_check(self):self.rejected(lambda e:e['source']['checks'].update(linux=None))
    def test_boolean_integer(self):self.rejected(lambda e:e['journeys'][0]['transfer'].update(procedure_body_bytes=True))
    def test_wrong_valid_applied_identity(self):self.rejected(lambda e:e['journeys'][0]['receipts'][0].update(applied='sha256:'+'f'*64))
    def test_duplicate_save_target(self):self.rejected(lambda e:e['journeys'][0]['saves'].__setitem__(1,e['journeys'][0]['saves'][0]))
    def test_target_drain_mismatch(self):self.rejected(lambda e:e['journeys'][0]['saves'][0].update(local_revision='sha256:'+'f'*64))
    def test_private_receipt_mismatch(self):self.rejected(lambda e:e['journeys'][0]['receipts'][0]['private'].update(receipt='f'*32))
    def test_malformed_is_failed(self):self.assertEqual(normalize(None)['exit'],1)
if __name__=='__main__':unittest.main()
