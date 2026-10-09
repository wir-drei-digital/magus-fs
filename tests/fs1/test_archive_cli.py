"""Archive CLI must operate in fresh processes without opening original state."""
import json
import subprocess
import unittest
import test_cli
BIN = test_cli.BIN

class ArchiveCLI(unittest.TestCase):
    setUp = test_cli.CLI.setUp
    call = test_cli.CLI.call
    init = test_cli.CLI.init
    capture = test_cli.CLI.capture
    def test_archive_subprocess_roundtrip(self):
        self.init()
        first = self.capture()
        (self.root/'run').write_bytes(b'new revision\n')
        second = self.capture(2)
        archive = self.d/'archive'
        self.call('export', '--revision', second, '--destination', archive)
        config = json.loads(self.config.read_text())['replica']
        authority = config['authorities'][0]
        policy = self.d/'current-policy.json'
        policy.write_text(json.dumps({'authorities':config['authorities'], 'actor':{'principal':authority['principal']}, 'owner':authority['principal'], 'group':authority['primary_group'], 'file_mode':384, 'directory_mode':448}))
        for command,args in [('verify',[]),('restore',['--destination',str(self.d/'restored'),'--config',str(policy)])]:
            r=subprocess.run([str(BIN),command,'--archive',str(archive),*args],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,(r.stdout,r.stderr))
        self.assertEqual((self.d/'restored/run').read_bytes(),b'new revision\n')
        self.assertEqual((self.d/'restored/binary').read_bytes(),bytes(range(256))*2400)
        self.assertTrue((self.d/'restored/empty').is_dir())
        self.assertFalse((self.d/'restored/archive.json').exists())
        self.assertEqual(len(list((archive/'revisions').iterdir())),2)

    def test_post_rename_sync_failure_reports_owned_present_output(self):
        import os
        if os.environ.get('MAGUS_TEST_FEATURES')!='test-faults': self.skipTest('requires test-faults binary')
        self.init(); revision=self.capture()
        env=dict(os.environ, MAGUS_TEST_FAULT_POINT='materialize-directory-sync', MAGUS_TEST_FAULT_ACTION='EIO')
        self.call('materialize','--revision',revision,'--destination',self.d/'sync-failed',code=1,env=env)
        record=self.call('status')['materializations'][-1]
        self.assertEqual(record['status'],'unacknowledged')
        self.assertTrue(record['destination_identity_verified'])
        self.assertTrue(record['content_verified'])
        self.assertEqual((self.d/'sync-failed/run').read_bytes(),(self.root/'run').read_bytes())
        (self.d/'sync-failed').rename(self.d/'owned-output')
        (self.d/'sync-failed').mkdir(); (self.d/'sync-failed/user-file').write_bytes(b'keep replacement')
        record=self.call('status')['materializations'][-1]
        self.assertFalse(record['destination_identity_verified'])
        self.assertFalse(record['content_verified'])
        self.assertEqual((self.d/'sync-failed/user-file').read_bytes(),b'keep replacement')

    def test_archive_restore_parent_symlink_swap_cannot_redirect_output(self):
        import os
        import time
        if os.environ.get('MAGUS_TEST_FEATURES')!='test-faults':self.skipTest('requires test-faults binary')
        self.init();revision=self.capture();archive=self.d/'archive'
        self.call('export','--revision',revision,'--destination',archive)
        a=json.loads(self.config.read_text())['replica']['authorities'][0]
        policy=self.d/'policy.json';policy.write_text(json.dumps({'authorities':[a],'actor':{'principal':a['principal']},'owner':a['principal'],'group':a['primary_group'],'file_mode':384,'directory_mode':448}))
        parent=self.d/'parent';parent.mkdir();unrelated=self.d/'unrelated';unrelated.mkdir();(unrelated/'sentinel').write_bytes(b'keep')
        marker=self.d/'barrier';env=dict(os.environ,MAGUS_TEST_FAULT_POINT='materialize-publish',MAGUS_TEST_FAULT_ACTION='barrier',MAGUS_TEST_FAULT_MARKER=str(marker))
        process=subprocess.Popen([str(BIN),'restore','--archive',str(archive),'--destination',str(parent/'out'),'--config',str(policy)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        try:
            observed=marker.with_name(marker.name+'.1');deadline=time.monotonic()+15
            while not observed.exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(observed.exists())
            parent.rename(self.d/'moved');os.symlink(unrelated,parent)
            marker.with_name(marker.name+'.1.release').write_text('release')
            stdout,stderr=process.communicate(timeout=15)
        finally:
            if process.poll() is None:process.kill();process.communicate()
        self.assertEqual(process.returncode,1,(stdout,stderr));self.assertFalse((unrelated/'out').exists());self.assertEqual((unrelated/'sentinel').read_bytes(),b'keep')

    def test_standalone_grant_provision_revoke_and_restore_head_are_explicit(self):
        config=json.loads(self.config.read_text());principal=config['replica']['authorities'][0]['principal'];config['replica']['history_administrators']=[principal];self.config.write_text(json.dumps(config));self.init()
        old=self.capture();entries=self.call('history')['revisions'][0]['descriptor']['tree']['entries'];entry=next(e for e in entries if e['path']=='run');(self.root/'run').unlink();current=self.capture(2)
        grants=self.d/'grants.json';grants.write_text(json.dumps([{'principal':principal,'revision':old,'entries':[entry['id']]}]))
        self.call('history-grants','--config',grants)
        grants.write_text('[]');self.call('history-grants','--config',grants)
        self.assertEqual(self.call('restore','--revision',old,'--operation-id','operation:'+'4'*32,code=1)['error'],'permission_denied')
        grants.write_text(json.dumps([{'principal':principal,'revision':old,'entries':[entry['id']]}]));self.call('history-grants','--config',grants)
        result=self.call('restore','--revision',old,'--operation-id','operation:'+'5'*32)
        self.assertTrue(result['head_changed']);self.assertFalse(result['materialized']);self.assertNotEqual(result['revision'],current);self.assertFalse((self.root/'run').exists())
        report=self.call('prune','--dry-run')['report'];self.assertIn('token',report);self.assertEqual(report['candidate_bytes'],0)
        applied=self.call('prune','--token',report['token'])['report'];self.assertEqual(applied['reclaimed_bytes'],0)

if __name__=='__main__':
    unittest.main()
