"""Isolated actual original-v3 typed observer/body/path contracts."""
from pathlib import Path
import os,sys,json,subprocess,unittest
ROOT=Path(__file__).resolve().parents[3]
WITNESS=ROOT/'docs/specifications/smir/portable/conformance/execution/source-observer/witness.py'
CASES=('fixture-integrity','original-body','immutable-coordinates','same-numeric-namespaces',
       'ordinary-ssa-ffffffff','physical-type-ffffffff','ordinary-block-ffffffff','wrong-result-type','malformed-op',
       'source-id-boundary','type-oracle-substitute','duplicate-ssa','ordinary-copy-use',
       'ordinary-use-before-def','scope-undefined-at-pre','scope-stale-at-pre','profile-mode',
       'changed-original-budget','editable-abi-flag','collector-original-afterguard',
       'predicate-quota-before-type','collector-quota-before-output',
       'legacy-machine-and-registry-refusal','public-v2-rejects-observer')
class SourceObserverBody(unittest.TestCase):
    def run_case(self,case):
        command=[sys.executable,'-B']+(['-O']if sys.flags.optimize else[])+[str(WITNESS),case]
        run=subprocess.run(command,cwd=ROOT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);receipt=json.loads(run.stdout)
        self.assertTrue(receipt['passed']);self.assertEqual(receipt['case'],case);self.assertEqual(receipt['optimize'],sys.flags.optimize)
for case in CASES:
    def test(self,selected=case):self.run_case(selected)
    setattr(SourceObserverBody,'test_'+case.replace('-','_'),test)
if __name__=='__main__':unittest.main(verbosity=2)
