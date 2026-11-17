"""Exact file/name selection in an isolated core interpreter."""
import fnmatch,json,os,subprocess,sys,unittest
from pathlib import Path
from .fixtures import test_names

def isolated_suite(loader,pattern):
    selected='test_*.py' if pattern is None else pattern
    if type(selected)is not str or len(selected)>128:raise ValueError('bounded file pattern required')
    if not fnmatch.fnmatchcase('test_reference.py',selected):return unittest.TestSuite()
    filters=list(loader.testNamePatterns or [])
    if len(filters)>32 or any(type(p)is not str or len(p)>128 for p in filters):raise ValueError('bounded name patterns required')
    names=test_names()
    expected=[name for name in names if not filters or any(fnmatch.fnmatchcase(name,p) for p in filters)]
    if not expected:return unittest.TestSuite()
    class NestedReferenceChild(unittest.TestCase):
        def runTest(self):
            root=Path(__file__).resolve().parents[3]
            before_path=list(sys.path);before={n:sys.modules.get(n) for n in ('candidate','codec','common','schema')}
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
            env['PYTHONPATH']=str(root/'tools/smir-runtime-contract')+os.pathsep+env.get('PYTHONPATH','')
            cmd=[sys.executable,'-B']+(['-'+'O'*sys.flags.optimize] if sys.flags.optimize else [])+['-m','union_nested.reference','--check','--selftest']
            for f in filters:cmd+=['--name-pattern',f]
            result=subprocess.run(cmd,cwd=root,env=env,capture_output=True,text=True,timeout=180)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr);report=json.loads(result.stdout)
            self.assertEqual(report['tests'],len(expected));self.assertEqual(report['cases'],9)
            self.assertEqual(report['optimize'],sys.flags.optimize);self.assertIs(report['dont_write_bytecode'],True)
            self.assertEqual(report['pycache_prefix'],sys.pycache_prefix)
            self.assertEqual(sys.path,before_path)
            for n,v in before.items():self.assertIs(sys.modules.get(n),v)
    return unittest.TestSuite([NestedReferenceChild()])
