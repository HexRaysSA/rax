"""Each genuine-context case runs with isolated canonical module imports."""
from pathlib import Path
import json,os,subprocess,sys,unittest
ROOT=Path(__file__).resolve().parents[3]
WITNESS=ROOT/'docs/specifications/smir/portable/conformance/execution/root3-context/witness.py'
CASES=('fixture-integrity','complete-pipeline','source-call-custody','version2-schema',
       'different-ledger','editable-abi-flag','embedded-mutation','external-replacement',
       'no-execution-admission','observer-unavailable','text-256-boundary','text-257-refusal','text-utf8-refusal',
       'nominal-pointer-width','unknown-float-format','function-params','raw-width','array-count','dynamic-record',
       'exception-profile','list-cardinality','zero-before-copy','low-before-abi',
       'low-before-body','type-layout-parity','deepcopy-budget','spent-before-type-copy',
       'spent-before-layout-copy','zero-before-types',
       'legacy-error-priority','targets-precharge','uses-precharge','helper-precharge')
class GenuineRoot3Context(unittest.TestCase):
    def run_case(self,case):
        command=[sys.executable,'-B']+(['-O']if sys.flags.optimize else[])+[str(WITNESS),case]
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
        run=subprocess.run(command,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        receipt=json.loads(run.stdout)
        self.assertTrue(receipt['passed']);self.assertEqual(receipt['case'],case)
        self.assertEqual(receipt['optimize'],sys.flags.optimize)
for case in CASES:
    def test(self,selected=case):self.run_case(selected)
    setattr(GenuineRoot3Context,'test_'+case.replace('-','_'),test)
if __name__=='__main__':unittest.main(verbosity=2)
