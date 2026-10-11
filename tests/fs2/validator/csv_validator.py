"""Allowlisted deterministic integer CSV validator. Content is never executed."""
import csv, json
from pathlib import Path
values=[int(r['amount']) for r in csv.DictReader(Path('/input/input.csv').open())]
expected=(str(sum(values))+'\n').encode()
actual=Path('/input/report.txt').read_bytes()
Path('/output/expected.txt').write_bytes(expected)
passed=actual==expected
print(json.dumps({'outcome':'pass' if passed else 'fail','count':len(values)}))
raise SystemExit(0 if passed else 1)
