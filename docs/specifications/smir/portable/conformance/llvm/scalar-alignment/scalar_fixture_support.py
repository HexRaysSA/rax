"""Fixture-only manual body data + existing codec seal. NO AST/compiler input."""
from pathlib import Path
import copy
import hashlib
import json
import os
import sys
HERE = Path(__file__).resolve().parent
PROJECT_OVERRIDE = os.environ.get('SCALAR_REFERENCE_PROJECT')
PROJECT = Path(PROJECT_OVERRIDE) if PROJECT_OVERRIDE is not None else HERE.parents[6]
sys.path.insert(0, str(PROJECT / 'tools/smir-llvm-contract'))
import semantic_observation as A
A.R.apis()

def ref(n):
    return dict(module=dict(kind='self'), id=n)

def budget():
    return A.R.apis()[4].SourceQueryBudget(max_work=10 ** 18, max_edges=10 ** 15, max_copied_bytes=10 ** 18, max_depth=128)

def original(name):
    path = HERE / (name + '.smo')
    b = budget()
    owner = A.R.apis()[0].RootContext.from_module(path.read_bytes(), budget=b)
    return (owner, b)

def write_fixture(name, baseline, ops):
    from candidate import root3_context as D
    schemas = {n: json.loads((PROJECT / 'docs/specifications/smir/portable/schema' / n / 'candidate.json').read_bytes()) for n in ('abi', 'execution', 'runtime')}
    codec = A.R.apis()[5].CandidateCodec(schemas)
    source = PROJECT / 'docs/specifications/smir/portable/conformance/llvm/ordinary-scalar' / baseline
    roots = codec.decode(source.read_bytes()).roots
    roots[3]['functions'][0]['blocks'][0]['ops'] = copy.deepcopy(ops)
    roots[3]['functions'][0]['blocks'][0]['term']['values'] = [ops[-1]['results'][0]['id']]
    b = budget()
    roots[3].update(payload_revision=3, source_contract=D.codec().wire_contract(dict(revision=1, bindings=[], scopes=[], scope_values=[], exits=[], phase_sites=[], ends=[], returns=[], adoptions=[]), budget=b))
    folder = HERE
    folder.mkdir(exist_ok=True)
    (folder / (name + '.roots.json')).write_text(json.dumps(roots, indent=2) + '\n')
    raw = D.codec().encode_module(roots, budget=b)
    (folder / (name + '.smo')).write_bytes(raw)
    sealed_roots = D.codec().decode_module(raw, budget=b).roots
    (folder / (name + '.sealed-roots.json')).write_text(json.dumps(sealed_roots, indent=2) + '\n')
    return dict(name=name, baseline=str(source), baseline_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), root_json_sha256=hashlib.sha256((folder / (name + '.roots.json')).read_bytes()).hexdigest(), smo_sha256=hashlib.sha256(raw).hexdigest())

def main():
    rows = []
    for name, value in [('one', '01000000'), ('two', '02000000')]:
        rows.append(write_fixture(name, 'cpp-unsigned-int.smo', [dict(op='constant', results=[dict(id=1, type=ref(17))], operands=[], literal=dict(kind='bits', value=value))]))
    for name, opcode in [('subtract', 'i_sub'), ('add', 'i_add'), ('xor', 'i_xor')]:
        op = dict(op=opcode, results=[dict(id=2, type=ref(17))], operands=[0, 1])
        op['flags'] = []
        rows.append(write_fixture(name, 'cpp-unsigned-int.smo', [dict(op='constant', results=[dict(id=1, type=ref(17))], operands=[], literal=dict(kind='bits', value='01000000')), op]))
    rows.append(write_fixture('unsigned-casts', 'cpp-unsigned-short.smo', [dict(op='zext', results=[dict(id=1, type=ref(17))], operands=[0]), dict(op='constant', results=[dict(id=2, type=ref(17))], operands=[], literal=dict(kind='bits', value='01000000')), dict(op='i_add', results=[dict(id=3, type=ref(17))], operands=[1, 2], flags=[]), dict(op='trunc', results=[dict(id=4, type=ref(600))], operands=[3])]))
    rows.append(write_fixture('signed-casts', 'cpp-signed-char.smo', [dict(op='sext', results=[dict(id=1, type=ref(17))], operands=[0]), dict(op='trunc', results=[dict(id=2, type=ref(2))], operands=[1])]))
    (HERE / 'manual-provenance.json').write_text(json.dumps(dict(scope='Hand-authored SMIR body fixtures, existing platform/ABI baseline roots + codec custody; NO AST inputs/generator/emitter/compiler-output claim.', rows=rows), indent=2) + '\n')
    print('manually authored fixture rows', len(rows))
if __name__ == '__main__':
    main()
