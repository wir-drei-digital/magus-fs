"""Exercise real owned subprocess bookkeeping across multiple client kills."""
import json,sys,tempfile,unittest
from pathlib import Path
from client_protocol import Journey
from infra import OwnedInfra
class ClientHarnessTests(unittest.TestCase):
    def test_second_process_intent_preserves_first_owned_process(self):
        with tempfile.TemporaryDirectory() as p:
            journey=object.__new__(Journey);journey.i=OwnedInfra(Path(p).resolve()/'run');journey.children=[];journey.proxy=None
            try:
                first=journey.spawn([sys.executable,'-c','import time;time.sleep(10)'],'first')
                second=journey.spawn([sys.executable,'-c','import time;time.sleep(10)'],'second')
                rows=json.loads((journey.i.output/'client-processes.json').read_text())
                self.assertEqual([r['pid'] for r in rows],[first.pid,second.pid])
            finally:journey.cleanup()
            self.assertTrue(all(r['reaped'] for r in json.loads((journey.i.output/'client-processes.json').read_text())))
if __name__=='__main__':unittest.main()
