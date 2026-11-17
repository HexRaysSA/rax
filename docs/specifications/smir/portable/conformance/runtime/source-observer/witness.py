"""Actual public source verification of SEM's original observer fixture."""
from pathlib import Path
import argparse,sys,json
ROOT=Path(__file__).resolve().parents[7]
sys.path.insert(0,str(ROOT/'tools/smir-runtime-contract'))
from source_contracts.__main__ import bootstrap,precharge_schemas,read_file,parse_json

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--budget',required=True,type=Path);args=parser.parse_args()
    budget=bootstrap(args.budget);precharge_schemas(budget)
    from source_contracts import verify
    from source_contracts.api import report
    from candidate.context import RootContext
    folder=ROOT/'docs/specifications/smir/portable/conformance/execution/source-observer'
    raw=read_file(folder/'inline-retained-observer.smo',16*1024*1024,budget)
    owner=RootContext.from_module(raw,budget=budget)
    document=parse_json(read_file(folder/'inline-retained-observer.source-contract.json',8*1024*1024,budget),64,budget)
    result=verify(owner,document,budget=budget)
    print(json.dumps(report(result,budget=budget),sort_keys=True))
if __name__=='__main__':main()
