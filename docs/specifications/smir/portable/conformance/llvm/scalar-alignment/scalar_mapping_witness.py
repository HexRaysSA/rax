"""Explicit author-supplied mappings for fixed manually authored test bodies."""
from pathlib import Path
import json
import os
import scalar_conditions as C
import scalar_alignment as S
import scalar_fixture_support as F
HERE = Path(__file__).resolve().parent
AST_ORACLE = Path(os.environ.get('SCALAR_AST_ORACLE', '/nonexistent-scalar-ast-oracle'))
CONDITION_ORACLE = Path(os.environ.get('SCALAR_CONDITION_ORACLE', '/nonexistent-scalar-condition-oracle'))
NODE_ROWS = {'one': [(2, 1)], 'two': [(2, 1)], 'subtract': [(2, 2), (3, 0), (4, 0), (5, 1)], 'add': [(2, 2), (3, 0), (4, 0), (5, 1)], 'xor': [(2, 2), (3, 0), (4, 0), (5, 1)], 'unsigned-casts': [(2, 4), (3, 4), (4, 3), (5, 1), (6, 1), (7, 0), (8, 0), (9, 2)], 'signed-casts': [(2, 2), (3, 2), (4, 1), (5, 1), (6, 0), (7, 0)]}
TYPE_ROWS = {'one': [(1, 17)], 'two': [(1, 17)], 'subtract': [(1, 17)], 'add': [(1, 17)], 'xor': [(1, 17)], 'unsigned-casts': [(1, 600), (2, 17)], 'signed-casts': [(1, 2), (2, 17)]}

def mapping(name, owner, witness, b):
    stamp = owner.prepare_source_data(budget=b)
    return dict(format='smir-scalar-source-alignment-map', revision=1, source_sha256=witness.report(budget=b)['source_sha256'], ast_function=0, smir_module_digest=owner.sections[2]['manifest']['identity'], smir_root3_sha256=dict(stamp.root_digests)[3].hex(), smir_function=0, parameters=[dict(declaration=1, value=0)], types=[dict(type=aid, execution=F.ref(tid)) for aid, tid in TYPE_ROWS[name]], nodes=[dict(node=nid, value=val) for nid, val in NODE_ROWS[name]], return_node=1)

def inputs(name, *, source_name=None, ast_oracle=AST_ORACLE, condition_oracle=CONDITION_ORACLE):
    owner, b = F.original(name)
    src = HERE / ((source_name or name) + '.cpp')
    w = C.A.observe(src, ast_oracle, budget=b)
    c = C.observe_conditions(src, condition_oracle, witness=w, budget=b)
    m = mapping(source_name or name, owner, w, b)
    return (owner, b, w, c, m)

def main():
    rows = []
    for name in NODE_ROWS:
        owner, b, w, c, m = inputs(name)
        result = S.verify(w, owner, m, conditions=c, budget=b)
        report = result.report(budget=b)
        assert report['finite_alignment_checked'] and (not report['source_to_smir_full_provenance'])
        rows.append(dict(case=name, status='PASS', original_v3=owner.sections[3]['payload_revision'], execution_checked_none=owner.execution_checked is None))
        print(name, 'PASS', flush=True)
    print(json.dumps(dict(status='PASS', rows=rows, scope='Finite static conditional value-body alignment only; no execution/admission/emission.')))
if __name__ == '__main__':
    main()
