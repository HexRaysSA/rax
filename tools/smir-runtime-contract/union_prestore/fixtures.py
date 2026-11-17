"""Closed authored reference products; --check never writes or executes a guest."""
import ast,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
FOLDER=ROOT/'docs/specifications/smir/portable/conformance/runtime/union-prestore-reference'
INPUTS=('tools/smir-runtime-contract/check.py', 'tools/smir-runtime-contract/test_fixture_inventory.py', 'docs/specifications/smir/portable/schema/abi/candidate.json', 'docs/specifications/smir/portable/schema/execution/candidate.json', 'docs/specifications/smir/portable/schema/execution/exceptions.json', 'docs/specifications/smir/portable/schema/execution/records.json', 'docs/specifications/smir/portable/schema/execution/types.json', 'tools/smir-abi/candidate_codec.py', 'tools/smir-abi/contract_json.py', 'tools/smir-abi/factory_meter.py', 'tools/smir-abi/function_address/errors.py', 'tools/smir-abi/layout.py', 'tools/smir-abi/nominal.py', 'tools/smir-abi/record_layout/__init__.py', 'tools/smir-abi/record_layout/checked.py', 'tools/smir-abi/record_layout/materialization.py', 'tools/smir-abi/record_layout/model.py', 'tools/smir-format/execution/candidate/__init__.py', 'tools/smir-format/execution/candidate/bindings.py', 'tools/smir-format/execution/candidate/context.py', 'tools/smir-format/execution/candidate/factory_meter.py', 'tools/smir-format/execution/candidate/fp.py', 'tools/smir-format/execution/candidate/layouts.py', 'tools/smir-format/execution/candidate/machine.py', 'tools/smir-format/execution/candidate/memory.py', 'tools/smir-format/execution/candidate/operations.py', 'tools/smir-format/execution/candidate/pure.py', 'tools/smir-format/execution/candidate/ranges.py', 'tools/smir-format/execution/candidate/raw.py', 'tools/smir-format/execution/candidate/schema_build.py', 'tools/smir-format/execution/candidate/source_call_projection.py', 'tools/smir-format/execution/candidate/source_registry_projection.py', 'tools/smir-format/execution/candidate/type_system.py', 'tools/smir-format/execution/candidate/values.py', 'tools/smir-format/execution/candidate/verify.py', 'tools/smir-format/execution/candidate/wire.py', 'tools/smir-format/execution/common.py', 'tools/smir-format/execution/evaluate.py', 'tools/smir-format/execution/floating.py', 'tools/smir-format/execution/verify.py', 'tools/smir-runtime-contract/source_roles/source_data.py', 'tools/smir-runtime-contract/schema.py', 'docs/specifications/smir/portable/schema/runtime/union_prestore_reference.schema.json', 'tools/smir-runtime-contract/union_prestore/__init__.py', 'tools/smir-runtime-contract/union_prestore/bootstrap.py', 'tools/smir-runtime-contract/union_prestore/discovery.py', 'tools/smir-runtime-contract/union_prestore/model.py', 'tools/smir-runtime-contract/union_prestore/test_reference.py', 'tools/smir-runtime-contract/union_prestore/fixtures.py', 'tools/smir-runtime-contract/union_prestore/reference.py', 'tools/smir-runtime-contract/union_prestore/README.md')
EXPECTATIONS=(('initialized-store', {'physical': 42, 'source_init': 0, 'stores': 1, 'generation': 1, 'cursor': 2}), ('sticky-freeze-store', {'physical': 0, 'source_init': 255, 'numeric_error': 'source_indeterminate_numeric_use'}), ('same-live-arm', {'generation': 1, 'physical_sibling': 17, 'sibling_init': 0, 'stores': 2}), ('replace-arm', {'generation': 1, 'old_live': False, 'physical_sibling': 17, 'sibling_init': 255}), ('reactivate-ended-arm', {'generation': 2, 'physical_sibling': 17, 'sibling_init': 255}), ('first-birth-stale', {'error': 'stale_or_unborn_handle'}), ('physical-origin-copy', {'physical_origins': 1, 'observed_origins': 0, 'source_init': 18446744073709551615}), ('overlap-snapshot', {'physical': [1, 2, 1, 2, 3, 4, 5, 6], 'source_init': 280379743338240}), ('untracked-allocation', {'error': 'unmodeled_allocation', 'effects': 0, 'tracked': False}), ('range-numeric-conversion', {'error': 'ub_inrange_address_conversion', 'language_ub': True}), ('ordinary-origin-conversion', {'value': 65536, 'raw_origins': 1}), ('core-poison-undef', {'poison_state': 'poison', 'undef_state': 'concrete', 'undef_value': 5}), ('readonly-preflight', {'error': 'memory_permission', 'cells': 0, 'cursor': 0, 'effects': 0}), ('post-store-resume', {'error': 'effect_replay_or_stage', 'physical': 42, 'stores': 1, 'cursor': 2}))

def document():
    parsed=ast.parse((Path(__file__).with_name('test_reference.py')).read_bytes())
    tests=sorted('union_prestore.test_reference.'+cls.name+'.'+method.name
        for cls in parsed.body if isinstance(cls,ast.ClassDef)
        for method in cls.body if isinstance(method,ast.FunctionDef) and method.name.startswith('test_'))
    return dict(format='union-prestore-reference',revision=1,binding='unbound',
        source_fact_authority=False,runtime_authority=False,semantic_admission=False,
        cost_profile_qualified=False,scope='quiescent-single-tracked-union-reference',
        cases=[dict(scenario=name,expected=expected) for name,expected in EXPECTATIONS],tests=tests)

def products():
    doc=document()
    provenance=dict(format='union-prestore-reference-provenance',revision=1,
        binding='unbound',source_fact_authority=False,runtime_authority=False,
        semantic_admission=False,cost_profile_qualified=False,
        origin='Authored finite model observations of actual independent execution Machine/Raw/Memory, never compiler-emitted source or private facts.',
        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in sorted(INPUTS)},
        limitation='Only quiescent single tracked allocation, scalar assignment and bounded init data laws; no construction phase issuer, CPP source event, cleanup, group/call protocol, production parallel runtime or registered cost profile.')
    return {n:(json.dumps(d,indent=2)+'\n').encode() for n,d in [('cases.json',doc),('provenance.json',provenance)]}

def check():
    for name,raw in products().items():
        if not (FOLDER/name).is_file() or (FOLDER/name).read_bytes()!=raw:
            raise ValueError('UNION_REFERENCE_FIXTURE_DRIFT: '+name)

def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:check()
    else:
        FOLDER.mkdir(parents=True,exist_ok=True)
        for name,raw in products().items():(FOLDER/name).write_bytes(raw)
    print('union reference2products; no SMO written; '+('nonwriting check passed' if args.check else 'metadata written'))
if __name__=='__main__':main()
