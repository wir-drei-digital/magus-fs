import unittest
from isolation import actors


class IdentityTests(unittest.TestCase):
    def test_same_uid_is_not_same_logical_principal(self):
        rows = actors()
        self.assertEqual(set(rows), {'a1', 'a2', 'b', 'readonly', 'peer'})
        self.assertEqual(rows['a1']['principal'], rows['a2']['principal'])
        self.assertNotEqual(rows['a1']['principal'], rows['b']['principal'])
        self.assertEqual(len({r['replica'] for r in rows.values()}), 5)
        self.assertEqual({r['uid'] for r in rows.values()}, {1001})


class FixtureContractTests(unittest.TestCase):
    def test_every_owner_is_mapped_without_uid_aliasing(self):
        from isolation import mount_authorities
        rows=actors()
        for name, actor in rows.items():
            mappings=mount_authorities(actor, rows)
            self.assertEqual({r['principal'] for r in mappings}, {r['principal'] for r in rows.values()})
            self.assertEqual(len({r['uid'] for r in mappings}),len(mappings))
            self.assertEqual(next(r['principal'] for r in mappings if r['uid']==1001),actor['principal'])
            self.assertEqual({r['gid'] for r in mappings},{1001})
            self.assertFalse(any(r['dac_override'] or r['ownership_transfer'] for r in mappings))

    def test_only_owner_provisions_root_policy(self):
        from isolation import provision_record
        rows=actors();root={'owner':rows['a1']['principal']}
        for name,actor in rows.items():
            record=provision_record(name,actor,rows,'a'*64,root)
            self.assertEqual('root_policy' in record,name=='a1')
            self.assertEqual(record['principal'],record['authority']['principal'])
            if name=='readonly':self.assertEqual(record['actions'],['read']);self.assertEqual(record['prefixes'],['reports'])

class SourceBridgeTests(unittest.TestCase):
    def test_runtime_and_unlisted_fixture_changes_are_rejected(self):
        from common import allowed_source_changes
        self.assertFalse(allowed_source_changes({'crates/magus-fs/src/main.rs':{}}, 'old', 'new'))
        self.assertFalse(allowed_source_changes({'tests/fs2/connected.py':{}}, 'old', 'unreviewed'))
        self.assertTrue(allowed_source_changes({'tests/fs3/isolation.py':{}}, 'same', 'same'))

class SecurityPredicateTests(unittest.TestCase):
    def test_private_or_hidden_entry_in_history_rejected(self):
        from isolation import validate_history_absence
        for entry in ('private-entry','hidden-entry'):
            with self.assertRaises(AssertionError):validate_history_absence({'items':[{'id':'selector','entry':entry,'change':'version'}],'next':None},'private-entry','hidden-entry')

    def test_unexamined_history_page_rejected(self):
        from isolation import validate_history_absence
        with self.assertRaises(AssertionError):validate_history_absence({'items':[],'next':'cursor'},'private-entry','hidden-entry')

    def test_private_object_probe_uses_own_view_and_allowed_control(self):
        from isolation import private_object_probe
        from service_storage import object_id
        class Requests:
            root='/v1/n/test'
            def __init__(self):self.calls=[]
            def view(self,actor):
                self.calls.append(('view',actor));return {'view':actor+'-view'},{'tree':{'entries':[{'path':'reports/live','content':{'version':{'extents':[{'object':object_id(b'allowed')}]}}}]}}
            def expect(self,name,method,path,status,**kw):
                self.calls.append((name,kw['actor'],path,status))
                assert '/'+kw['actor']+'-view/' in path
                return b'allowed' if status==200 else {'code':'not_found'}
        requests=Requests();private_object_probe(requests,'a1',object_id(b'private'))
        self.assertEqual(requests.calls[0],('view','a1'))
        self.assertEqual([r[-1] for r in requests.calls[1:]],[200,404])

if __name__ == '__main__': unittest.main()
