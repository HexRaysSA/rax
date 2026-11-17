#!/usr/bin/env python3
"""Actual SEM admission + LLVM projection + independent runtime normalization."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
from candidate_projection import project_function
from canonical import canonical_function
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
from candidate.verify import verify


def main():
    request = json.load(sys.stdin)
    verified = verify(request['types'], request['functions'], request['exceptions'])
    function = verified.functions_root['functions'][0]
    eh = verified.exceptions_root['functions'][0]
    def identity(namespace, reference):
        raise ValueError('Actual cross-root identity unavailable: ' + namespace)
    view = project_function(function, eh, verified.types, identity)
    # Import runtime under an isolated package name: SEM also has candidate/.
    import importlib.util
    path = ROOT / 'tools/smir-runtime-contract/candidate'
    spec = importlib.util.spec_from_file_location('runtime_candidate', path/'__init__.py',
        submodule_search_locations=[str(path)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    from runtime_candidate.comdat import function_body
    llvm = canonical_function(view)
    runtime = function_body(view)
    if llvm != runtime:
        raise ValueError('Independent runtime comparison mismatch')
    report={'view':view,'canonical':llvm.decode('utf8'),'independent_equal':True}
    if request.get('run_reference_exception') is True:
        from candidate.machine import Machine
        if len(function['params']) != 1 or verified.types.get(function['params'][0]['type'])['kind'] != 'exception':
            raise ValueError('Not the closed selector reference fixture')
        machine=Machine(verified)
        exception=machine.handle(function['params'][0]['type'],{'nominal':('self',0)})
        machine.start(function['id'],[exception])
        result=machine.run()
        report['reference_result']=result['values'][0].data
    report['loaded_source_inputs']=sorted({str(Path(module.__file__).resolve().relative_to(ROOT))
        for module in sys.modules.values() if isinstance(getattr(module,'__file__',None),str)
        and Path(module.__file__).resolve().is_relative_to(ROOT)
        and not Path(module.__file__).resolve().is_relative_to(Path(__file__).parent)})
    print(json.dumps(report))


if __name__ == '__main__':
    main()
