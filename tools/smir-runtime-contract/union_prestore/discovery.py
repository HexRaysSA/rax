"""Child-only registration preserves the legacy Runtime candidate namespace."""
import fnmatch,json,os,subprocess,sys,unittest
from pathlib import Path

def isolated_suite(pattern):
    selected='test_*.py' if pattern is None else pattern
    if type(selected) is not str or len(selected)>128:raise ValueError('bounded test pattern required')
    if not fnmatch.fnmatchcase('test_reference.py',selected):return unittest.TestSuite()
    class UnionReferenceChild(unittest.TestCase):
        def runTest(self):
            root=Path(__file__).resolve().parents[3]
            before_path=list(sys.path)
            before={name:sys.modules.get(name) for name in ('candidate','codec','common','schema')}
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
            env['PYTHONPATH']=str(root/'tools/smir-runtime-contract')+os.pathsep+env.get('PYTHONPATH','')
            cmd=[sys.executable,'-B']+(['-'+'O'*sys.flags.optimize] if sys.flags.optimize else [])+['-m','union_prestore.reference','--check','--selftest']
            result=subprocess.run(cmd,cwd=root,env=env,capture_output=True,text=True,timeout=180)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            report=json.loads(result.stdout)
            self.assertEqual(report['optimize'],sys.flags.optimize)
            self.assertIs(report['dont_write_bytecode'],True)
            self.assertEqual(report['pycache_prefix'],sys.pycache_prefix)
            self.assertGreater(report['tests'],0)
            self.assertEqual(sys.path,before_path)
            for name,value in before.items():self.assertIs(sys.modules.get(name),value)
    return unittest.TestSuite([UnionReferenceChild()])
