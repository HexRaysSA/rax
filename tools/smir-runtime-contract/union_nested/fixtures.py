"""Authored unbound fixture products; --check never writes."""
import ast,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
FOLDER=ROOT/'docs/specifications/smir/portable/conformance/runtime/union-nested-reference'
INPUTS=('docs/specifications/smir/portable/schema/abi/candidate.json', 'docs/specifications/smir/portable/schema/execution/candidate.json', 'docs/specifications/smir/portable/schema/execution/exceptions.json', 'docs/specifications/smir/portable/schema/execution/records.json', 'docs/specifications/smir/portable/schema/execution/types.json', 'docs/specifications/smir/portable/schema/runtime/union_nested_reference.schema.json', 'tools/smir-abi/candidate_codec.py', 'tools/smir-abi/contract_json.py', 'tools/smir-abi/factory_meter.py', 'tools/smir-abi/function_address/errors.py', 'tools/smir-abi/layout.py', 'tools/smir-abi/nominal.py', 'tools/smir-abi/record_layout/__init__.py', 'tools/smir-abi/record_layout/checked.py', 'tools/smir-abi/record_layout/materialization.py', 'tools/smir-abi/record_layout/model.py', 'tools/smir-format/execution/candidate/__init__.py', 'tools/smir-format/execution/candidate/bindings.py', 'tools/smir-format/execution/candidate/context.py', 'tools/smir-format/execution/candidate/factory_meter.py', 'tools/smir-format/execution/candidate/fp.py', 'tools/smir-format/execution/candidate/layouts.py', 'tools/smir-format/execution/candidate/machine.py', 'tools/smir-format/execution/candidate/memory.py', 'tools/smir-format/execution/candidate/operations.py', 'tools/smir-format/execution/candidate/pure.py', 'tools/smir-format/execution/candidate/ranges.py', 'tools/smir-format/execution/candidate/raw.py', 'tools/smir-format/execution/candidate/source_call_projection.py', 'tools/smir-format/execution/candidate/source_registry_projection.py', 'tools/smir-format/execution/candidate/type_system.py', 'tools/smir-format/execution/candidate/values.py', 'tools/smir-format/execution/candidate/verify.py', 'tools/smir-format/execution/candidate/wire.py', 'tools/smir-format/execution/common.py', 'tools/smir-format/execution/evaluate.py', 'tools/smir-format/execution/floating.py', 'tools/smir-format/execution/verify.py', 'tools/smir-runtime-contract/check.py', 'tools/smir-runtime-contract/schema.py', 'tools/smir-runtime-contract/source_roles/source_data.py', 'tools/smir-runtime-contract/test_contract.py', 'tools/smir-runtime-contract/test_fixture_inventory.py', 'tools/smir-runtime-contract/union_nested/README.md', 'tools/smir-runtime-contract/union_nested/__init__.py', 'tools/smir-runtime-contract/union_nested/discovery.py', 'tools/smir-runtime-contract/union_nested/fixtures.py', 'tools/smir-runtime-contract/union_nested/model.py', 'tools/smir-runtime-contract/union_nested/reference.py', 'tools/smir-runtime-contract/union_nested/test_reference.py', 'tools/smir-runtime-contract/union_prestore/__init__.py', 'tools/smir-runtime-contract/union_prestore/bootstrap.py', 'tools/smir-runtime-contract/union_prestore/model.py')
BASE={'format': 'nested-union-prestore-reference', 'binding': 'unbound', 'source_fact_authority': False, 'runtime_authority': False, 'semantic_admission': False, 'cost_profile_qualified': False, 'cases': [{'scenario': 'both-births', 'expected': {'generations': [1, 1, 1], 'stores': 1, 'cursor': 2, 'physical': 42}}, {'scenario': 'same-parent-switch-child', 'expected': {'parent': 1, 'child': 1, 'sibling': 17, 'sibling_init': 0, 'old_child_live': False}}, {'scenario': 'parent-replacement', 'expected': {'container_live': False, 'child_live': False, 'physical': 17, 'source_init': 255}}, {'scenario': 'readonly-inner', 'expected': {'error': 'memory_permission', 'cursor': 0, 'effects': 0, 'live': 0}}, {'scenario': 'huge-symbolic', 'expected': {'objects': 1, 'physical_bytes': 16, 'logical_index': 1099511627775}}, {'scenario': 'index128-alias', 'expected': {'error': 'index_not_u64', 'kind': 'semantic', 'cursor': 0, 'effects': 0, 'live': 0}}, {'scenario': 'unknown-phase', 'expected': {'error': 'phase_assumption_unavailable', 'kind': 'unavailable', 'cursor': 0, 'effects': 0, 'live': 0}}, {'scenario': 'first-parent-birth-stale', 'expected': {'error': 'stale_or_unborn_designation', 'parent_generation': 2}}, {'scenario': 'physical-origin-copy', 'expected': {'physical_origins': 1, 'observed_origin_bits': 8, 'source_init': 18446744073709551360}}]}

def test_names():
    tree=ast.parse(Path(__file__).with_name('test_reference.py').read_bytes())
    return sorted('union_nested.test_reference.'+cls.name+'.'+m.name for cls in tree.body if isinstance(cls,ast.ClassDef) for m in cls.body if isinstance(m,ast.FunctionDef)and m.name.startswith('test_'))

def document():return dict(BASE,tests=test_names())
def products():
    provenance=dict(format='nested-union-reference-provenance',revision=1,binding='unbound',source_fact_authority=False,runtime_authority=False,semantic_admission=False,cost_profile_qualified=False,
        input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in INPUTS},
        origin='Authored fixed16Bouter8Binner/sibling model +actual independent core operations, not source facts/compiler output.',
        limits='Quiescent/2levels/allbitsvalue/publicmaskassumptions; no actual source/phase/event/cleanup/parallel/fullcost authority.')
    return {n:(json.dumps(d,indent=2)+'\n').encode()for n,d in [('cases.json',document()),('provenance.json',provenance)]}
def check():
    for n,raw in products().items():
        if not(FOLDER/n).is_file()or(FOLDER/n).read_bytes()!=raw:raise ValueError('NESTED_FIXTURE_DRIFT: '+n)
def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');a=p.parse_args()
    if a.check:check()
    else:
        FOLDER.mkdir(parents=True,exist_ok=True)
        for n,raw in products().items():(FOLDER/n).write_bytes(raw)
    print('nested reference2products; no SMO written; '+('nonwriting check passed'if a.check else'metadata written'))
if __name__=='__main__':main()
