"""Full ten-root reference oracles for the accepted finite scalar profile.

Writes only SEM-owned NEW P2 fixtures. Broader grammar fixtures are preserved.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec, reference_report
from oracle_sources import input_roots, input_sources, interpreter_identity

SCHEMAS = {owner: json.loads((SPEC / f'schema/{owner}/candidate.json').read_text())
           for owner in ['execution', 'runtime', 'abi']}
CODEC = CandidateCodec(SCHEMAS)
SOURCE = SPEC / 'conformance/execution/candidate/portable-identity.json'
BASE = {int(key): value for key, value in json.loads(SOURCE.read_text())['sections'].items()}
BASE[5] = dict(payload_revision=2, relocations=[], constant_initializers=[])
BASE[7] = dict(payload_revision=1, segments=[])
BASE[9] = dict(payload_revision=1, capabilities=[], requirements=[], limits=[])
CASES = []


def ref(i):
    return dict(module=dict(kind='self'), id=i)


def decl(i, ty):
    return dict(id=i, type=ref(ty))


def op(name, results=(), operands=(), **fields):
    if name == 'call':
        fields = {'source_plan': None, **fields}
    return dict(op=name, results=list(results), operands=list(operands), **fields)


def block(i, operations, term, phis=()):
    if term['op'] in {'invoke', 'tailcall'}:
        term = {'source_plan': None, **term}
    return dict(id=i, ops=operations, term=term, phis=list(phis))


def add(name, roots, *, coverage=False):
    encoded = CODEC.encode(roots)
    try:
        reference_report(encoded)
        reference = 'ok'
    except ValueError as error:
        reference = getattr(error, 'code', str(error).split(':', 1)[0])
    if coverage:
        assert reference == 'ok', (name, reference)
    CASES.append(dict(name=name, reference=reference,
        expected='unavailable' if coverage else reference,
        encoded_hex=encoded.hex(), sha256=hashlib.sha256(encoded).hexdigest()))


def cases():
    fn = BASE[3]['functions'][0]
    ty = fn['params'][0]['type']['id']
    parameter = fn['params'][0]['id']
    bool_ty = max(t['id'] for t in BASE[1]['types']) + 1
    exception_ty = next(t['id'] for t in BASE[1]['types'] if t['kind'] == 'exception')
    add('identity', BASE)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['params'][0]['id'] = 700
    roots[3]['functions'][0]['blocks'][0]['term']['values'] = [700]
    roots[2]['manifest']['key']['name'] = 'renamed_scalar_module'
    roots[2]['symbols'][0]['namespace'] = 'renamed_namespace'
    roots[2]['symbols'][0]['name'] = '_Z14renamed_scalari'
    add('renamed_ssa_and_valid_names', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [op('i_add', [decl(1, ty)], [parameter, parameter], flags=[])], dict(op='return', values=[1]))]
    add('scalar_add_body', roots)

    roots = deepcopy(BASE)
    roots[1]['types'].append(dict(id=400, kind='code_ptr', signature=deepcopy(fn['signature'])))
    wrapper = deepcopy(fn)
    wrapper.update(id=1, abi_signature=None)
    wrapper['blocks'] = [block(0, [op('address_of', [decl(1, 400)], symbol=ref(0)),
        op('call', [decl(2, ty)], [parameter],
           target=dict(kind='indirect', value=1, signature=deepcopy(fn['signature'])), unwind='nounwind')],
        dict(op='return', values=[2]))]
    roots[3]['functions'].append(wrapper)
    add('actual_indirect_call_through_code_pointer', roots)
    wrong = deepcopy(roots)
    wrong[3]['functions'][1]['blocks'][0]['ops'][1]['target']['value'] = parameter
    add('reject_indirect_call_integer_value', wrong)
    wrong = deepcopy(roots)
    wrong[3]['functions'][1]['blocks'][0]['ops'][1]['target']['signature'] = ref(13)
    add('reject_indirect_call_signature_mismatch', wrong)

    for kind in ['zero', 'poison', 'undef']:
        roots = deepcopy(BASE)
        roots[3]['functions'][0]['blocks'] = [block(0,
            [op('constant', [decl(1, ty)], literal=dict(kind=kind))], dict(op='return', values=[1]))]
        add('scalar_literal_' + kind, roots)
    roots = deepcopy(BASE)
    roots[1]['types'].append(dict(id=401, kind='struct', fields=[ref(ty), ref(ty)]))
    roots[3]['functions'][0]['blocks'] = [block(0,
        [op('constant', [decl(1, 401)], literal=dict(kind='aggregate', elements=[
            dict(kind='bits', value='01000000'), dict(kind='zero')])),
         op('extract', [decl(2, ty)], [1], indices=[1])], dict(op='return', values=[2]))]
    add('aggregate_literal_two_fields', roots)
    bad = deepcopy(roots)
    bad[3]['functions'][0]['blocks'][0]['ops'][0]['literal']['elements'].pop()
    add('reject_aggregate_literal_arity', bad)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0,
        [op('constant', [decl(1, 10)], literal=dict(kind='bits', value='ffffffffffffffff01')),
         op('trunc', [decl(2, ty)], [1])], dict(op='return', values=[2]))]
    add('i65_literal_last_bit', roots)
    bad = deepcopy(roots)
    bad[3]['functions'][0]['blocks'][0]['ops'][0]['literal']['value'] = 'ffffffffffffffff81'
    add('reject_i65_literal_high_padding_bits', bad)

    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0,
        [op('constant', [decl(1, 5)], literal=dict(kind='bits', value='0000000000000000')),
         op('inttoptr', [decl(2, 4)], [1]),
         op('ptr_offset', [decl(3, 4)], [2, 1], inbounds=False, check_base=False,
            nuw=False, nusw=False, inrange={'some': dict(lower=0, upper=0)})],
        dict(op='return', values=[parameter]))]
    add('bounded_pointer_offset_range', roots)
    bad = deepcopy(roots)
    bad[3]['functions'][0]['blocks'][0]['ops'][2]['inrange']['some']['lower'] = 1
    add('reject_pointer_offset_reversed_range', bad)

    loop = deepcopy(BASE)
    loop[1]['types'].append(dict(id=bool_ty, kind='int', bits=1))
    loop[3]['functions'][0]['blocks'] = [
        block(0, [op('constant', [decl(1, ty)], literal=dict(kind='bits', value='00000000'))], dict(op='jump', target=1)),
        block(1, [op('icmp', [decl(4, bool_ty)], [2, parameter], predicate='slt')],
            dict(op='cbranch', condition=4, **{'true': 2, 'false': 3}),
            [dict(result=decl(2, ty), incoming=[dict(predecessor=0, value=1), dict(predecessor=2, value=3)])]),
        block(2, [op('i_add', [decl(3, ty)], [2, parameter], flags=[])], dict(op='jump', target=1)),
        block(3, [], dict(op='return', values=[2]))]
    add('scalar_loop_phi', loop)
    roots = deepcopy(loop)
    roots[3]['functions'][0]['blocks'][1]['phis'][0]['incoming'][1]['predecessor'] = 0
    add('reject_phi_predecessor_bijection', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [op('copy', [decl(parameter, ty)], [parameter])], dict(op='return', values=[parameter]))]
    add('reject_duplicate_parameter_definition', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [op('copy', [decl(1, ty)], [2]), op('copy', [decl(2, ty)], [parameter])], dict(op='return', values=[1]))]
    add('reject_forward_value_use', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'][0]['term']['values'] = [999]
    add('reject_missing_return_value', roots)
    roots = deepcopy(BASE)
    roots[1]['types'].append(dict(id=bool_ty, kind='int', bits=1))
    roots[3]['functions'][0]['blocks'] = [block(0, [op('constant', [decl(1, bool_ty)], literal=dict(kind='bits', value='00'))], dict(op='return', values=[1]))]
    add('reject_wrong_return_type', roots)
    roots = deepcopy(BASE)
    roots[1]['types'].append(dict(id=bool_ty, kind='int', bits=0))
    add('reject_unused_zero_width_integer', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [op('i_add', [decl(1, ty)], [999, parameter], flags=[])], dict(op='return', values=[parameter]))]
    add('reject_bad_dead_operation_operand', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [], dict(op='cbranch', condition=parameter, **{'true': 1, 'false': 2})),
        block(1, [], dict(op='return', values=[parameter])), block(2, [], dict(op='return', values=[parameter]))]
    add('reject_nonboolean_branch', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [op('constant', [decl(1, ty)], literal=dict(kind='bits', value='0000000000'))], dict(op='return', values=[1]))]
    add('reject_constant_byte_extent', roots)
    for term in ['throw', 'rethrow', 'resume']:
        roots = deepcopy(BASE)
        roots[3]['functions'][0]['blocks'] = [block(0, [], dict(op=term, exception=parameter, region=None))]
        add('reject_' + term + '_nonexception', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [], dict(op='cleanup_return', exception=None, region=None))]
    add('reject_cleanup_without_exception', roots)
    roots = deepcopy(BASE)
    roots[3]['functions'][0]['blocks'] = [block(0, [op('constant', [decl(1, exception_ty)], literal=dict(kind='undef')),
        op('landingpad', [decl(2, ty)], [1], region=999)], dict(op='return', values=[2]))]
    add('reject_landingpad_without_region', roots)
    roots = deepcopy(BASE)
    target = dict(kind='direct', function=ref(fn['id']), signature=deepcopy(fn['signature']))
    roots[3]['functions'][0]['blocks'] = [block(0, [], dict(op='invoke', target=target, operands=[parameter],
        normal=dict(target=1, results=[decl(1, ty)]), unwind=dict(target=2, exception=decl(2, exception_ty)), region=999)),
        block(1, [], dict(op='return', values=[1])), block(2, [], dict(op='return', values=[parameter]))]
    add('reject_invoke_missing_region', roots)
    roots[3]['functions'][0]['blocks'][2]['term']['values'] = [1]
    add('reject_normal_result_on_unwind_edge', roots)
    roots = deepcopy(BASE)
    roots[8]['functions'] = [dict(function=fn['id'], actions=[], regions=[])]
    # Accepted R-PROD005REV2: action-free logical EH reaches the real SEM phase.
    add('unused_legal_eh_record', roots)
    fixture = SPEC / 'conformance/runtime/candidate/joint/common-symbol-type-domain.json'
    for case in json.loads(fixture.read_text())['cases']:
        if case['accept']:
            add('unqualified_' + case['name'], CODEC.decode(bytes.fromhex(case['encoded_hex'])).roots, coverage=True)


if __name__ == '__main__':
    cases()
    sources = {Path(module.__file__).resolve() for module in list(sys.modules.values())
               if getattr(module, '__file__', None) and Path(module.__file__).resolve().is_relative_to(ROOT)}
    sources.update([SOURCE, Path(__file__).resolve(), SPEC / 'conformance/runtime/candidate/joint/common-symbol-type-domain.json'])
    document = dict(scope='Actual all-root reference plus genuine audited scalar production profile; unavailable cases are coverage unknown, not semantic rejections.',
        sources=input_sources(ROOT, sources), oracle_input_roots=input_roots(), oracle_interpreter=interpreter_identity(), cases=CASES)
    output = Path(__file__).with_name('profile-cases.json')
    output.write_text(json.dumps(document, separators=(',', ':')) + '\n')
    print(len(CASES), {kind: sum(c['expected'] == kind for c in CASES) for kind in ['ok', 'unavailable']},
          'semantic rejects', sum(c['expected'] not in {'ok', 'unavailable'} for c in CASES))
