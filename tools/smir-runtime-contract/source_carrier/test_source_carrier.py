"""Discovery-safe launcher: legacy execution parent module namespaces stay intact."""
from pathlib import Path
import os,subprocess,sys,unittest
class SourceCarrierWitness(unittest.TestCase):
    def test_isolated_actual_source_carrier_contracts(self):
        if 'SMIR_SOURCE_CARRIER_ORACLE'not in os.environ:self.fail('SMIR_SOURCE_CARRIER_ORACLE must name the actual guarded C++ oracle build')
        root=Path(__file__).resolve().parents[3];before=list(sys.path);codec=sys.modules.get('codec')
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1');env['PYTHONPATH']=str(root/'tools/smir-runtime-contract')+os.pathsep+env.get('PYTHONPATH','')
        argv=[sys.executable,'-B']+(['-O']if sys.flags.optimize else[])+['-m','source_carrier.witness']
        r=subprocess.run(argv,cwd=root,env=env,capture_output=True,text=True,timeout=120)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertEqual(sys.path,before);self.assertIs(sys.modules.get('codec'),codec)
if __name__=='__main__':unittest.main()
