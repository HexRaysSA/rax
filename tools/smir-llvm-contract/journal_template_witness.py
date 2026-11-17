#!/usr/bin/env python3
"""Read fixed journal-capture types from actual admitted RootContext ABI graphs."""
import copy
import json
from pathlib import Path
import sys

import bindings

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
from test_candidate_storage_join import storage_wrapper
from candidate.context import RootContext
from candidate.type_system import ref


def main():
    rows=[]
    for formals in ([],[dict(id=907,type=ref(1)),dict(id=2,type=ref(4))]):
        roots=storage_wrapper()
        roots[10]['journals']=[dict(id=0,signature=0,params=formals,slots=[dict(
            id=0,type=ref(1),offset=0,extent=4,align=4,parent=None,role='root',
            count=1,stride=4,count_source=None,constructor=None,destructor=None,
            destructor_kind='none',covers=[],owner=0,dependencies=[],child_program=None)],
            normal_order=[0],exception_order=[0])]
        context=RootContext(roots)
        context.verify_abi();context.verify_execution()
        program=context.abi_entity('journal',ref(0))
        captures=bindings.journal_capture_types(program,context.nominal,context.types.get)
        _,records=bindings.catalog()
        record=copy.deepcopy(records['journal_begin'])
        result=bindings.instantiate(record,[],contract='construction',journal_captures=captures)
        if result['variadic'] or len(result['params'])!=len(formals)+1:
            raise AssertionError('Actual source capture formals changed fixed arity')
        kinds=[value['kind'] for value in captures]
        if kinds!=(['int','data_ptr'] if formals else []):
            raise AssertionError(('Capture source graph/order mismatch',kinds))
        rows.append(dict(formals=len(formals),capture_kinds=kinds,fixed_arity=len(result['params'])))
    inputs=sorted({str(Path(module.__file__).resolve().relative_to(ROOT))
        for module in sys.modules.values() if isinstance(getattr(module,'__file__',None),str)
        and Path(module.__file__).resolve().is_relative_to(ROOT)
        and not Path(module.__file__).resolve().is_relative_to(Path(__file__).parent)})
    print(json.dumps(dict(cases=rows,loaded_source_inputs=inputs)))


if __name__=='__main__':main()
