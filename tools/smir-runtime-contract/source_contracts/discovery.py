"""Discovery boundary only; actual verifier import guards remain unchanged."""
from pathlib import Path
import os,subprocess,sys,unittest,fnmatch
from .witness import MODULES


def isolated_suite(loader, pattern):
    selected=pattern if pattern is not None else 'test_*.py'
    if type(selected)is not str or len(selected)>128:raise ValueError('bounded test pattern required')
    if not any(fnmatch.fnmatchcase(name+'.py',selected)for name in MODULES):return unittest.TestSuite()
    class OriginalSourceContractChild(unittest.TestCase):
        def runTest(self):
            root=Path(__file__).resolve().parents[3]
            before_path=list(sys.path);before={name:sys.modules.get(name)for name in ('candidate','codec','common')}
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
            env['PYTHONPATH']=str(root/'tools/smir-runtime-contract')+os.pathsep+env.get('PYTHONPATH','')
            argv=[sys.executable,'-B']+(['-O']if sys.flags.optimize else[])+['-m','source_contracts.witness','--pattern',selected]
            result=subprocess.run(argv,cwd=root,env=env,capture_output=True,text=True,timeout=180)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(sys.path,before_path)
            for name,value in before.items():self.assertIs(sys.modules.get(name),value)
    return unittest.TestSuite([OriginalSourceContractChild()])
