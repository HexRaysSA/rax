"""Fail closed on another candidate namespace; never remove or replace modules."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]

def initialize():
    expected=ROOT/'tools/smir-format/execution/candidate'
    existing=sys.modules.get('candidate')
    if existing is not None:
        path=getattr(existing,'__file__',None)
        if path is None or Path(path).resolve().parent!=expected.resolve():
            raise RuntimeError('UNION_REFERENCE_NAMESPACE: run in an isolated interpreter')
    paths=[ROOT/'tools/smir-format/execution',ROOT/'tools/smir-format',
           ROOT/'tools/smir-abi',ROOT/'tools/smir-runtime-contract']
    selected=[str(path) for path in paths]
    sys.path[:]=selected+[path for path in sys.path if path not in selected]
