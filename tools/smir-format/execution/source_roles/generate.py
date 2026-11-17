"""Whole-object unused-import source-role witnesses; no guest code execution.

Expected outcomes come from accepted INT032, independently of the runtime source
predicate. Full CLI observations may remain red until owner implementation. This
script writes only SEM-owned source-roles conformance files.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from sem_fixtures import (base, builtin_state, atomic_flag, reference_cell, nominal,
                          geometry, append_nominals, STATE, STATE_EXEC)
from candidate.bindings import runtime_package_module
from candidate.context import RootContext
from candidate.type_system import ref
from test_candidate_storage_join import storage_wrapper

ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec
SCHEMAS = {o: json.loads((SPEC / f'schema/{o}/candidate.json').read_text())
           for o in ['execution', 'runtime', 'abi']}
CODEC = CandidateCodec(SCHEMAS)
HELPERS = runtime_package_module('helpers')
OUT = SPEC / 'conformance/execution/candidate/source-roles'


def imported(roots, name, source, *, contract='default', typ=None, target=None):
    row = HELPERS.helper(name)
    fixed = dict(u8=2, u32=1, i32=1, u64=5, data_ptr=4, exception=7, i1=4010)
    if {4010, 4011} & {t['id'] for t in roots[1]['types']}:
        raise ValueError('SEM_SOURCE_FIXTURE_ID_COLLISION')
    roots[1]['types'].append(dict(id=4010, kind='int', bits=1))
    signature = dict(id=4011, kind='function', cc='portable', variadic=False)
    for side, attrs in [('params', 'param_noundef'), ('results', 'result_noundef')]:
        signature[side] = [deepcopy(typ) if p['type'] == 'type0' else ref(fixed[p['type']]) for p in row[side]]
        signature[attrs] = [p['noundef'] for p in row[side]]
    roots[1]['types'].append(signature)
    roots[1]['types'].sort(key=lambda t: t['id'])
    options = deepcopy(HELPERS.DEFAULT_OPTIONS)
    if name.startswith('atomic_flag_'):
        options['order'] = 'relaxed'
    if target is not None:
        options['target'] = {'some': target}
    roots[6]['imports'].append(dict(id=len(roots[6]['imports']), kind='internal',
        namespace=row['namespace'], name=name, version=1, catalog=HELPERS.digest(),
        signature=ref(4011), abi={'some': source}, types=[] if typ is None else [typ],
        contract=contract, options=options))


def cases():
    result = []
    def add(name, roots, helper, source, accept, *, contract='default', typ=None, target=None):
        imported(roots, helper, source, contract=contract, typ=typ, target=target)
        # Wrong ROLE cases must still be well-formed admitted source graphs.
        context = RootContext(roots)
        context.verify_abi()
        encoded = CODEC.encode(roots)
        result.append(dict(name=name, helper=helper, contract=contract,
            expected_source_role='accept' if accept else 'reject',
            expected_diagnostic=None if accept else (
                'RT_HELPER_SOURCE_EXECUTION' if helper == 'va_arg' else
                'RT_HELPER_SOURCE_COMPATIBILITY' if helper == 'tls_address' else
                'RT_HELPER_SOURCE_ROLE'),
            source=source, source_graph_abi_verified=True,
            capabilities=roots[9]['capabilities'], encoded_hex=encoded.hex(),
            encoded_sha256=hashlib.sha256(encoded).hexdigest()))
    for helper in ['atomic_flag_test', 'atomic_flag_test_and_set', 'atomic_flag_clear']:
        roots = base(); source = atomic_flag(roots)
        add(helper + '-flag', roots, helper, source, True)
        add(helper + '-int32', base(), helper, ref(1), False)
        roots = base()
        append_nominals(roots, [nominal(3012, 'scalar', 'unsigned char', 2, bits=8)], [geometry(3012, 1, 1)])
        add(helper + '-uchar1B', roots, helper, ref(3012), False)
    for helper in ['va_start', 'va_copy', 'va_end']:
        roots = base(); source = builtin_state(roots, 'va')
        add(helper + '-canonical-array', roots, helper, source, True)
        roots = base(); builtin_state(roots, 'va')
        add(helper + '-underlying-record', roots, helper, ref(STATE), False)
        add(helper + '-int32', base(), helper, ref(1), False)
    for helper in ['setjmp_capture', 'longjmp_restore']:
        for contract in ['setjmp', 'sigsetjmp']:
            roots = base(); source = builtin_state(roots, 'jmp')
            add(helper + '-' + contract + '-canonical-array', roots, helper, source, True, contract=contract)
            roots = base(); builtin_state(roots, 'jmp')
            add(helper + '-' + contract + '-underlying-record', roots, helper, ref(STATE), False, contract=contract)
            add(helper + '-' + contract + '-int32', base(), helper, ref(1), False, contract=contract)
    add('va_arg-int32', base(), 'va_arg', ref(1), True, typ=ref(17))
    add('va_arg-wrong-execution', base(), 'va_arg', ref(1), False, typ=ref(5))
    roots = base(); builtin_state(roots, 'va')
    add('va_arg-explicit-aggregate', roots, 'va_arg', ref(STATE), True, typ=ref(STATE_EXEC))
    for prefix in ['', 'tls_']:
        for action in ['acquire', 'release', 'abort']:
            helper = prefix + 'guard_' + action
            add(helper + '-int-variable', base(), helper, ref(1), True)
            roots = base(); source = reference_cell(roots, incomplete=True)
            add(helper + '-reference-cell-incomplete-referent', roots, helper, source, True)
            add(helper + '-function-invalid', base(), helper, ref(12), False)
    add('eh_allocate-c23-int', base(), 'eh_allocate', ref(1), True)
    add('eh_allocate-function-invalid', base(), 'eh_allocate', ref(12), False)
    roots = storage_wrapper()
    add('tls_address-whole-object', roots, 'tls_address', ref(1), True, target=ref(0))
    roots = storage_wrapper()
    add('tls_address-wrong-source-pointer', roots, 'tls_address', ref(4), False, target=ref(0))
    return result


if __name__ == '__main__':
    OUT.mkdir(exist_ok=True)
    rows = cases()
    for row in rows:
        (OUT / (row['name'] + '.smo')).write_bytes(bytes.fromhex(row['encoded_hex']))
    # Explicit static role expectations, not a successful runtime/reference receipt.
    sources = [Path(__file__).resolve(), Path(__file__).with_name('sem_fixtures.py'),
               SPEC / 'schema/abi/candidate.json', SPEC / 'schema/runtime/helpers-v1.json']
    manifest = dict(interface='INT032/ABI030REV6', scope='Unused-import static source role; all source graphs actually ABI-verified, no guest/native execution or live grant.',
        sources={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}, cases=rows)
    (OUT / 'cases.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(len(rows), 'cases', sum(r['expected_source_role'] == 'accept' for r in rows), 'positive',
          len({(r['helper'], r['contract']) for r in rows}), 'helper contracts')
