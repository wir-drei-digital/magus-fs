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

if __name__ == '__main__': unittest.main()
