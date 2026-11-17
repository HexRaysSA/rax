"""Execute the original six modules plus explicit original-v3 comparison tests under their actual canonical imports."""
import argparse,fnmatch,sys,unittest
from pathlib import Path
MODULES=('test_checker','test_factory','test_identity','test_independent_abi_counters','test_independent_nominal_aliases','test_public','test_v3_identity','test_observer')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pattern',default='test_*.py');args=parser.parse_args()
    if len(args.pattern)>128:parser.error('bounded test pattern required')
    actual={p.stem for p in Path(__file__).resolve().parent.glob('test_*.py')}
    if actual!=set(MODULES):raise RuntimeError('SCV_TEST_INVENTORY: update the explicit original test module inventory')
    names=['source_contracts.'+name for name in MODULES if fnmatch.fnmatchcase(name+'.py',args.pattern)]
    suite=unittest.defaultTestLoader.loadTestsFromNames(names)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful()else 1
if __name__=='__main__':raise SystemExit(main())
