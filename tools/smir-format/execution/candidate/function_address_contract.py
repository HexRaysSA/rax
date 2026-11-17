"""Static CodeAddress fixtures; no address/permit/runtime authority issuer.

Local probes consume the real execution checker. Source probes consume genuine
RootContext ABI and execution verification. Both scopes remain explicit.
"""
from copy import deepcopy

from candidate.operations import Dependencies
from candidate.type_system import ref
from candidate.verify import verify

LITERAL_EXPECTATION_MIGRATION = {'proposal': 'P1-CODEADDRESS-LITERAL-CONSISTENCY-01', 'case': 'reject-nonnull-literal', 'previous_expected': 'literal_pointer', 'expected': 'ok', 'encoded_bytes_unchanged': True, 'reason': 'Accepted S-PROD016REV7 noncall bits semantics; legacy case identifier and wire bytes retained. No authority or new qualification from historical receipts.'}


def local_roots():
    from test_candidate import fixture
    roots = fixture()
    roots[0]['types'] += [
        {'id': 300, 'kind': 'code_address'},
        {'id': 301, 'kind': 'vector', 'element': ref(300), 'count': 2},
        {'id': 302, 'kind': 'code_ptr', 'signature': ref(15)},
        {'id': 303, 'kind': 'vector', 'element': ref(302), 'count': 2},
        {'id': 304, 'kind': 'vector', 'element': ref(0), 'count': 2},
    ]
    return roots


def source_roots():
    from candidate_fixtures import portable_identity
    document = portable_identity()['sections']
    document[1]['types'] += [{'id': 300, 'kind': 'code_address'},
                             {'id': 301, 'kind': 'code_ptr', 'signature': ref(12)}]
    document[5] = {'payload_revision': 2, 'relocations': [], 'constant_initializers': []}
    document[7] = {'payload_revision': 1, 'segments': []}
    document[9] = {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []}
    return document


def verify_source(document):
    from candidate.context import RootContext
    context = RootContext(document)
    context.verify_abi()
    return context, context.verify_execution()


def cases():
    from test_candidate import operation, decl, constant
    result = []

    def local(name, operations, expected, *, configure=None):
        roots = local_roots()
        roots[1]['functions'][0]['blocks'][0]['ops'] = [constant(0, 2, '2a000000')] + operations
        if configure is not None:
            configure(roots)
        result.append({'id': name, 'scope': 'execution-local',
                       'sections': dict(zip((1, 3, 8), roots)), 'expected': expected})

    local('null-copy-freeze', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('copy', [decl(2, 300)], [1]), operation('freeze', [decl(3, 300)], [2])], 'ok')
    local('null-bitcast-raw-roundtrip', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('bitcast', [decl(2, 4)], [1]), operation('bitcast', [decl(3, 300)], [2])], 'ok')
    local('null-equality', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('icmp', [decl(2, 0)], [1, 1], predicate='eq')], 'ok')
    local('reject-ordering', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('icmp', [decl(2, 0)], [1, 1], predicate='ult')], 'code_address_predicate')
    local('reject-integer-arithmetic', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('i_add', [decl(2, 300)], [1, 1], flags=[])], 'operand_class')
    local('reject-address-indirect-call', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('call', [decl(2, 2)], [], target={'kind': 'indirect', 'value': 1, 'signature': ref(15)},
                    unwind='propagate')], 'call_indirect_signature')
    local('erase-legacy-type', [operation('constant', [decl(1, 302)], literal={'kind': 'zero'}),
          operation('code_erase', [decl(2, 300)], [1])], 'ok')
    local('reject-erase-address', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('code_erase', [decl(2, 300)], [1])], 'code_erase_type')
    local('reject-bitcast-address-to-callable', [operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
          operation('bitcast', [decl(2, 302)], [1])], 'bitcast_pointer')
    local('reject-nonnull-literal', [operation('constant', [decl(1, 300)],
          literal={'kind': 'bits', 'value': '0200000000000000'})], 'ok')
    local('vector-equality', [operation('constant', [decl(1, 301)], literal={'kind': 'zero'}),
          operation('icmp', [decl(2, 304)], [1, 1], predicate='ne')], 'ok')
    local('vector-erase', [operation('constant', [decl(1, 303)], literal={'kind': 'zero'}),
          operation('code_erase', [decl(2, 301)], [1])], 'ok')
    local('reject-erase-lanes', [operation('constant', [decl(1, 303)], literal={'kind': 'zero'}),
          operation('code_erase', [decl(2, 300)], [1])], 'code_address_lanes')

    def source(name, change, expected):
        document = source_roots()
        change(document)
        result.append({'id': name, 'scope': 'abi-and-execution', 'sections': document, 'expected': expected})

    def binding(document, **changes):
        node = operation('code_bind', [decl(2, 301)], [1], plan=ref(0), **changes)
        document[3]['functions'][0]['blocks'][0]['ops'] = [
            operation('constant', [decl(1, 300)], literal={'kind': 'zero'}), node,
            operation('code_erase', [decl(3, 300)], [2])]

    source('genuine-ordinary-bind-plan', binding, 'ok')
    source('reject-bind-plan-reference', lambda d: (binding(d), d[3]['functions'][0]['blocks'][0]['ops'][1].update(plan=ref(999))), 'source_plan_reference')
    source('reject-bind-wrong-input', lambda d: (binding(d), d[3]['functions'][0]['blocks'][0]['ops'][1].update(operands=[0])), 'code_bind_type')

    def caller(document, plan):
        callee = deepcopy(document[3]['functions'][0]); callee['id'] = 1
        document[3]['functions'].append(callee)
        document[3]['functions'][0]['blocks'][0]['ops'] = [operation('call', [decl(1, 17)], [0],
            target={'kind': 'direct', 'function': ref(1), 'signature': ref(12)},
            unwind='propagate', source_plan=plan)]
        document[3]['functions'][0]['blocks'][0]['term']['values'] = [1]

    source('genuine-caller-plan-C', lambda d: caller(d, {'some': ref(0)}), 'ok')
    source('explicit-generic-None', lambda d: caller(d, None), 'ok')
    source('reject-caller-plan-C-reference', lambda d: caller(d, {'some': ref(999)}), 'source_plan_reference')

    def wrong_fn(document, bind=False):
        alternate = deepcopy(next(t for t in document[1]['types'] if t['id'] == 12))
        alternate.update(id=302, param_noundef=[False])
        document[1]['types'].append(alternate)
        if bind:
            next(t for t in document[1]['types'] if t['id'] == 301)['signature'] = ref(302)
            binding(document)
        else:
            caller(document, {'some': ref(0)})
            document[3]['functions'][1].update(signature=ref(302), abi_signature=None)
            document[3]['functions'][0]['blocks'][0]['ops'][0]['target']['signature'] = ref(302)

    source('reject-bind-execution-Fn', lambda d: wrong_fn(d, True), 'source_plan_execution')
    source('reject-caller-execution-Fn', wrong_fn, 'source_plan_execution')

    def dependency_caller(document, identifier=1):
        document[2]['manifest']['dependencies'] = [{'slot': 0,
            'key': {'namespace': 'example', 'name': 'provider', 'abi_major': 1, 'abi_minor': 0},
            'minimum_minor': 0, 'maximum_minor': None, 'site': document[10]['identity'],
            'declarations': [dict(id=1, kind='function', symbol_kind='none', source_linkage='cpp',
                namespace='example', name='callee', execution={'some': ref(12)},
                nominal={'some': ref(12)}, abi_signature={'some': ref(0)}, weak=False),
                dict(id=2, kind='nominal', symbol_kind='none', source_linkage='none', namespace='example',
                     name='not_a_plan', execution=None, nominal={'some': ref(12)}, abi_signature=None, weak=False)]}]
        caller(document, {'some': ref(identifier, 0)})

    source('genuine-original-DEP-caller-plan', dependency_caller, 'ok')
    source('reject-DEP-nominal-is-not-plan', lambda d: dependency_caller(d, 2), 'source_plan_reference')
    return result


def observe(case):
    """Invoke independent actual reference stages; report no runtime authority."""
    from common import Reject
    try:
        sections = case['sections']
        if case['scope'] == 'execution-local':
            verify(*(sections[n] for n in (1, 3, 8)), dependencies=Dependencies())
        else:
            verify_source(sections)
    except Reject as error:
        return error.code
    return 'ok'
