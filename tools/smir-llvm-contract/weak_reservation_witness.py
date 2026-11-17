#!/usr/bin/env python3
"""Independent consumer check of actual weak absence and provider snapshots."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
from test_candidate_weak_initializers import weak_modules
from test_candidate_initializers import evaluate
from test_candidate_storage_join import reference_image
from candidate.type_system import ref


def main():
    cases=[]
    for kind in ('data','function'):
        consumer,registry=weak_modules(kind)
        proof=registry.reserve_weak(consumer,ref(901,0))
        machine=reference_image(consumer)
        symbols={**machine.symbols,('dependency',0,901):proof}
        result=evaluate(consumer,machine,ref(9),symbols=symbols)
        if result.value.data or result.data_exposed or result.code_exposed or any(
                byte.bits or byte.poison or byte.undef or byte.origins for byte in result.bytes):
            raise AssertionError('Resolved weak absence fabricated bits, shadow, origin or exposure')
        provider=next(c for c in registry.contexts.values() if c is not consumer)
        provider.sections[2]['manifest']['key']['abi_minor']+=1
        try:
            evaluate(consumer,machine,ref(9),symbols=symbols)
        except Exception as error:
            if 'context_snapshot_changed' not in str(error):
                raise
        else:
            raise AssertionError('Weak absence survived a changed provider snapshot')
        cases.append(dict(kind=kind,value=0,exposures=0,changed_provider_rejected=True))
    inputs=sorted({str(Path(module.__file__).resolve().relative_to(ROOT))
        for module in sys.modules.values() if isinstance(getattr(module,'__file__',None),str)
        and Path(module.__file__).resolve().is_relative_to(ROOT)
        and not Path(module.__file__).resolve().is_relative_to(Path(__file__).parent)})
    print(json.dumps(dict(cases=cases,loaded_source_inputs=inputs)))


if __name__=='__main__':
    main()
