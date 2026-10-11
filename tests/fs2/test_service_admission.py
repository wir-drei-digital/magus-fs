"""Bounded fixture admission handling; never runtime qualification evidence."""
import json,unittest
from unittest.mock import Mock,patch
from service_storage import Journey
class AdmissionTests(unittest.TestCase):
    def make(self,replies,duration=0):
        j=Journey.__new__(Journey);j.i=Mock();j.observations=[];j.tokens={'alice':'original-auth'};self.clock=0;self.sleeps=[];self.calls=[]
        def sleep(seconds):self.sleeps.append(seconds);self.clock+=seconds
        def request(*args,**kw):
            self.calls.append((args,dict(kw)));self.clock+=duration;j.tokens['alice']='changed-auth';return replies.pop(0)
        j.request=request
        for p in [patch('service_storage.time.monotonic',side_effect=lambda:self.clock),patch('service_storage.time.sleep',side_effect=sleep)]:p.start();self.addCleanup(p.stop)
        return j
    def test_pressure_then_success_preserves_serialized_request_identity(self):
        j=self.make([(503,{'code':'backpressure'}),(200,{'ok':True})]);body={'operation':'fixed','upload':'fixed','revision':'fixed'}
        self.assertEqual(j.expect('candidate','POST','/same',200,body=body),{'ok':True})
        self.assertEqual(len(self.calls),2);self.assertEqual(self.sleeps,[.1]);self.assertEqual([r['status'] for r in j.observations],[503,200])
        for args,kw in self.calls:
            self.assertEqual(args,('POST','/same'));self.assertEqual(kw['raw'],json.dumps(body).encode());self.assertEqual(kw['headers']['Authorization'],'Bearer original-auth')
        self.assertEqual(j.observations[0]['request'],j.observations[1]['request']);self.assertLess(self.calls[1][1]['timeout'],self.calls[0][1]['timeout'])
    def test_exhaustion_is_three_recorded_attempts(self):
        j=self.make([(503,{'code':'backpressure'})]*3)
        with self.assertRaises(AssertionError):j.expect('stage','PUT','/fixed',200,raw=b'fixed')
        self.assertEqual(len(self.calls),3);self.assertEqual(self.sleeps,[.1,.3]);self.assertEqual(len(j.observations),3);self.assertEqual(j.i.write_json.call_count,3)
    def test_expected_pressure_is_single_shot(self):
        j=self.make([(503,{'code':'backpressure'})]);j.expect('negative','POST','/fixed',503,{'code':'backpressure'})
        self.assertEqual(len(self.calls),1);self.assertEqual(self.sleeps,[])
    def test_other_failures_never_retry(self):
        for status,body in [(503,{'code':'backend_unavailable'}),(503,{'code':'backpressure','extra':True}),(401,{'code':'invalid_credential'}),(404,{'code':'not_found'}),(409,{'code':'stale_head'}),(500,{})]:
            with self.subTest(status=status,body=body):
                j=self.make([(status,body)])
                with self.assertRaises(AssertionError):j.expect('negative','PUT','/fixed',200,raw=b'fixed')
                self.assertEqual(len(self.calls),1);self.assertEqual(len(j.observations),1);self.assertFalse(self.sleeps)
    def test_original_ten_second_budget_bounds_retry(self):
        j=self.make([(503,{'code':'backpressure'})],duration=9.9)
        with self.assertRaises(AssertionError):j.expect('deadline','PUT','/fixed',200)
        self.assertEqual(len(self.calls),1);self.assertEqual(len(j.observations),1);self.assertEqual(self.clock,10)
    def test_slow_success_is_recorded_but_rejected(self):
        j=self.make([(200,{'ok':True})],duration=10.01)
        with self.assertRaises(AssertionError):j.expect('deadline','PUT','/fixed',200)
        self.assertEqual(len(j.observations),1)
    def test_caller_cannot_mutate_recorded_response(self):
        j=self.make([(200,{'tree':{'entries':['original']}})])
        result=j.expect('descriptor','GET','/owned',200)
        result['tree']['entries'].append('caller change')
        self.assertEqual(j.observations[0]['body'],{'tree':{'entries':['original']}})

class BinaryAdmissionTests(unittest.TestCase):
    make=AdmissionTests.make
    def binary(self,replies,duration=0):
        import tempfile
        from pathlib import Path
        j=self.make(replies,duration);tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);j.i.output=Path(tmp.name);j.bytes_request=lambda path,actor='alice':j.request('GET',path,actor=actor)
        return j
    def test_binary_pressure_then_success_retains_each_exact_body(self):
        j=self.binary([(503,b'{"code":"backpressure"}'),(200,b'\x00actual binary\xff')]);data=j.expect_bytes('export','/same')
        self.assertEqual(data,b'\x00actual binary\xff');self.assertEqual(len(self.calls),2)
        self.assertEqual([r['status'] for r in j.observations],[503,200]);self.assertEqual(self.sleeps,[.1])
        for row,expected in zip(j.observations,[b'{"code":"backpressure"}',data]):
            self.assertEqual((j.i.output/row['body']['artifact']).read_bytes(),expected)
        self.assertEqual(j.observations[0]['request'],j.observations[1]['request'])
    def test_binary_other_errors_single_shot_and_retained(self):
        for status,body in [(503,b'{"code":"backend_unavailable"}'),(503,b'not json'),(503,b'{"code":"backpressure","extra":true}'),(404,b'{"code":"not_found"}'),(400,b'{"code":"corrupt_object"}')]:
            with self.subTest(status=status,body=body):
                j=self.binary([(status,body)])
                with self.assertRaises(AssertionError):j.expect_bytes('export','/same')
                self.assertEqual(len(self.calls),1);self.assertEqual(len(j.observations),1)
                self.assertEqual((j.i.output/j.observations[0]['body']['artifact']).read_bytes(),body)
    def test_binary_pressure_exhaustion_and_deadline(self):
        j=self.binary([(503,b'{"code":"backpressure"}')]*3)
        with self.assertRaises(AssertionError):j.expect_bytes('export','/same')
        self.assertEqual(len(self.calls),3);self.assertEqual(self.sleeps,[.1,.3]);self.assertEqual(len(j.observations),3)
        j=self.binary([(503,b'{"code":"backpressure"}')],9.9)
        with self.assertRaises(AssertionError):j.expect_bytes('export','/same')
        self.assertEqual(len(self.calls),1);self.assertEqual(self.clock,10);self.assertEqual(len(j.observations),1)
    def test_success_bytes_that_look_like_error_are_content(self):
        body=b'{"code":"backpressure"}';j=self.binary([(200,body)])
        self.assertEqual(j.expect_bytes('export','/same'),body);self.assertEqual(len(self.calls),1);self.assertEqual(len(j.observations),1)
