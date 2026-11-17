"""Independent Python execution oracle; writes only NEW SEM-owned test cases.

These objects exercise Rust's local execution body/type phase. ABI/runtime
factories are not invoked and no complete object admission is claimed.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
from candidate.operations import Dependencies
from candidate.type_system import ref
from candidate.verify import verify
from candidate.context import RootContext
from candidate.bindings import runtime_package_module
from common import Reject
from oracle_sources import input_roots, input_sources, interpreter_identity
from test_candidate import block, constant, decl, fixture, operation

SPEC = ROOT / 'docs/specifications/smir/portable'
SCHEMAS = {owner: json.loads((SPEC / f'schema/{owner}/candidate.json').read_text())
           for owner in ['execution', 'runtime', 'abi']}
CODEC = CandidateCodec(SCHEMAS)
BASE = json.loads((SPEC / 'conformance/execution/candidate/portable-identity.json').read_text())
CASES = []
ORACLES = {}
PHASE_CASES = []


def add(name, roots, dependencies=None):
    ORACLES[name] = ('local', deepcopy(roots), dependencies, 0)
    try:
        verify(*deepcopy(roots), dependencies=dependencies)
        expected = 'ok'
    except Reject as error:
        expected = error.code
    sections = {int(key): deepcopy(value) for key, value in BASE['sections'].items()}
    sections[1], sections[3], sections[8] = deepcopy(roots)
    sections[2]['symbols'] = []
    sections[5] = dict(payload_revision=2, relocations=[], constant_initializers=[])
    sections[7] = dict(payload_revision=1, segments=[])
    sections[9] = dict(payload_revision=1, capabilities=[], requirements=[], limits=[])
    CASES.append(dict(name=name, oracle_scope='execution-local', expected=expected, encoded_hex=CODEC.encode(sections).hex()))


def add_sections(name, sections, function=0):
    ORACLES[name] = ('bound', deepcopy(sections), None, function)
    context = RootContext(sections)
    try:
        context.verify_abi()
        context.verify_execution()
        expected = 'ok'
    except Reject as error:
        expected = error.code
    sections = deepcopy(sections)
    sections.setdefault(5, dict(payload_revision=2, relocations=[], constant_initializers=[]))
    sections.setdefault(7, dict(payload_revision=1, segments=[]))
    sections.setdefault(9, dict(payload_revision=1, capabilities=[], requirements=[], limits=[]))
    CASES.append(dict(name=name, oracle_scope='abi-and-execution', function=function, expected=expected, encoded_hex=CODEC.encode(sections).hex()))


def add_phase(name, sections):
    sections = deepcopy(sections)
    context = RootContext(sections)
    try:
        context.verify_abi()
        context.verify_execution()
        expected = 'ok'
    except Reject as error:
        expected = error.code
    sections.setdefault(5, dict(payload_revision=2, relocations=[], constant_initializers=[]))
    sections.setdefault(7, dict(payload_revision=1, segments=[]))
    sections.setdefault(9, dict(payload_revision=1, capabilities=[], requirements=[], limits=[]))
    PHASE_CASES.append(dict(name=name, expected=expected, encoded_hex=CODEC.encode(sections).hex()))


def phase_cases():
    from test_candidate_selectors import package, nested
    from test_candidate_initializers import initializer_roots
    sections = package()
    add_phase('typed_handler_selector', sections)
    for selector in [0, 1 << 31, 0xffffffff]:
        add_phase('reject_selector_' + str(selector), package(selector=selector))
    sections = package()
    second = nested(sections, ref(1))
    add_phase('nested_same_type_same_selector', sections)
    second['handlers'][0]['selector'] = 8
    add_phase('reject_same_type_different_selector', sections)
    second['handlers'][0].update(kind='catch_all', nominal=None)
    add_phase('typed_and_catch_all_distinct_selectors', sections)
    second['handlers'][0]['selector'] = 7
    add_phase('reject_catch_all_selector_alias', sections)
    sections = package()
    sections[8]['functions'][0]['regions'][0]['parent'] = {'some': 0}
    add_phase('reject_region_parent_cycle', sections)
    sections = package()
    sections[8]['functions'][0]['regions'][0]['blocks'] = [0, 0]
    add_phase('reject_region_block_duplicate', sections)
    sections = package()
    second = nested(sections, ref(1))
    second['parent'] = None
    add_phase('reject_independent_region_overlap', sections)
    sections = package()
    sections[8]['functions'][0]['regions'][0]['handlers'][0]['entry'] = 999
    add_phase('reject_handler_unknown_entry', sections)
    sections = package()
    sections[3]['functions'][1]['blocks'][0]['term']['region'] = 999
    add_phase('reject_invoke_unknown_region', sections)
    sections = package()
    sections[3]['functions'][1]['blocks'][2]['ops'][0]['region'] = 999
    add_phase('reject_landingpad_unknown_region', sections)
    sections = package()
    sections[3]['functions'][2]['blocks'][0]['term'] = dict(op='cleanup_return', exception=None, region=None)
    add_phase('reject_cleanup_without_explicit_exception', sections)
    sections = package()
    fn = sections[3]['functions'][1]
    call = dict(op='call', results=[decl(1, 17)], operands=[0], target=dict(kind='direct', function=ref(2), signature=ref(302)), unwind='propagate', source_plan=None)
    fn['blocks'] = [block(0, [call], dict(op='jump', target=1)), block(1, [], dict(op='return', values=[1]))]
    sections[8]['functions'][0]['regions'][0]['handlers'][0]['entry'] = 1
    add_phase('reject_protected_call_without_invoke', sections)
    fn['blocks'] = [block(0, [], dict(op='tailcall', operands=[0], target=dict(kind='direct', function=ref(2), signature=ref(302))))]
    sections[8]['functions'][0]['regions'][0]['handlers'][0]['entry'] = 0
    add_phase('reject_tailcall_with_local_handler', sections)
    sections = initializer_roots()
    add_phase('constant_initializer_restricted_graph', sections)
    sections = deepcopy(ORACLES['catch_begin'][1])
    sections[3]['functions'][1]['blocks'][0]['ops'][0]['handler'] = 999
    add_phase('reject_catch_unknown_handler', sections)

    # S-PROD004: the loaded-provider reference cannot discharge an absent recipe
    # body. This positive is derived from the accepted STATIC declaration
    # contract, explicitly not reported as independent provider-oracle parity.
    from test_candidate_eh_bindings import journal_package
    sections = package()
    sections[10]['journals'] = deepcopy(journal_package()[0][10]['journals'])
    sections[2]['manifest']['dependencies'] = [dict(slot=0,
        key=dict(namespace='example', name='cleanup-provider', abi_major=1, abi_minor=0),
        minimum_minor=0, maximum_minor=None, site=sections[10]['identity'], declarations=[dict(
            id=9, kind='recipe', symbol_kind='none', source_linkage='none', namespace='example',
            name='cleanup', execution=None, nominal=None, abi_signature=None, weak=False)])]
    sections[8]['functions'][0]['actions'] = [dict(id=0, program=ref(0), recipe=ref(9, 0), captures=[])]
    sections[8]['functions'][0]['regions'][0]['exit_actions'] = [0]
    sections[5] = dict(payload_revision=2, relocations=[], constant_initializers=[])
    sections[7] = dict(payload_revision=1, segments=[])
    sections[9] = dict(payload_revision=1, capabilities=[], requirements=[], limits=[])
    PHASE_CASES.append(dict(name='static_external_recipe_obligation', expected='ok',
        oracle_scope='accepted-S-PROD004-static-contract-provider-oracle-unavailable',
        expected_requirement=dict(function=1, action=0, slot=0, declaration=9),
        encoded_hex=CODEC.encode(sections).hex()))


def helper_cases():
    from candidate_fixtures import canonical_helper_source
    from test_candidate_context import roots as context_roots
    from test_candidate_eh_bindings import journal_package
    helpers = runtime_package_module('helpers')
    add_sections('full_joint_identity', context_roots())
    for op_name, helper_name in [('alloca', 'stack_alloc'), ('lifetime_start', 'lifetime_start'),
                                ('lifetime_end', 'lifetime_end'), ('stack_save', 'stack_save'),
                                ('stack_restore', 'stack_restore'), ('va_start', 'va_start'),
                                ('va_arg', 'va_arg'), ('va_copy', 'va_copy'), ('va_end', 'va_end'),
                                ('setjmp', 'setjmp_capture'), ('longjmp', 'longjmp_restore'),
                                ('catch_begin', 'eh_begin_catch'), ('catch_end', 'eh_end_catch')]:
        sections = context_roots()
        sections[1]['types'] += [dict(id=300, kind='stack_mark')]
        fixed = dict(u8=2, u32=1, u64=5, i32=1, data_ptr=4, exception=7, stack_mark=300)
        specification = helpers.helper(helper_name)
        template_type = lambda name: 16 if name == 'type0' else fixed[name]
        signature = dict(id=201, kind='function', cc='portable', variadic=False)
        for side, attributes in [('params', 'param_noundef'), ('results', 'result_noundef')]:
            signature[side] = [ref(template_type(item['type'])) for item in specification[side]]
            signature[attributes] = [item['noundef'] for item in specification[side]]
        sections[1]['types'].append(signature)
        contract = 'setjmp' if op_name in {'setjmp', 'longjmp'} else 'default'
        needs_nominal = specification['abi_namespace'][contract] == 'nominal'
        source = ref(1)
        if op_name in {'va_start', 'va_copy', 'va_end', 'setjmp', 'longjmp'}:
            source = canonical_helper_source(sections, 'jmp' if op_name in {'setjmp', 'longjmp'} else 'va')
        binding = dict(id=0, kind='internal', namespace=specification['namespace'], name=helper_name,
                       version=1, catalog=helpers.digest(), signature=ref(201),
                       abi={'some': source} if needs_nominal else None,
                       types=[ref(16)] if specification['type_parameters'] else [], contract=contract,
                       options=deepcopy(helpers.DEFAULT_OPTIONS))
        sections[6]['imports'] = [binding]
        params = [template_type(item['type']) for item in specification['params']]
        if op_name == 'alloca':
            params = params[:1]
        signature = dict(id=500, kind='function', cc='portable', variadic=False,
                         params=[ref(typ) for typ in params], results=[ref(17)],
                         param_noundef=[False] * len(params), result_noundef=[True])
        sections[1]['types'].append(signature)
        sections[1]['types'].sort(key=lambda item: item['id'])
        target = dict(kind='import', **{'import': ref(0)}, signature=ref(201))
        outputs = [decl(20 + i, template_type(item['type'])) for i, item in enumerate(specification['results'])]
        if op_name in {'catch_begin', 'catch_end'}:
            fields = dict(helper=target)
            if op_name == 'catch_begin':
                fields['handler'] = 0
            node = operation(op_name, outputs, range(len(params)), **fields)
            sections[8]['functions'] = [dict(function=1, actions=[], regions=[dict(id=0, parent=None, blocks=[],
                exit_actions=[], handlers=[dict(id=0, selector=1, kind='catch_all', nominal=None,
                    entry=0, cleanup_actions=[], catch_copy=None)], escape='continue')])]
        else:
            node = operation(op_name, outputs, range(len(params)), helper=target,
                             alignment=8 if op_name == 'alloca' else 0, binding=None)
        operations = [node, constant(99, 17, '2a000000')]
        term = dict(op='return', values=[99])
        if op_name == 'longjmp':
            operations = [node]
            term = dict(op='unreachable')
        wrapper = dict(id=1, signature=ref(500), abi_signature=None, params=[decl(i, typ) for i, typ in enumerate(params)],
                       entry=0, escape='propagate', no_return=False, blocks=[block(0, operations, term)])
        sections[3]['functions'].append(wrapper)
        add_sections(op_name, sections, 1)
    sections, _, _ = journal_package()
    add_sections('journal', sections, 1)

    # An actual TLS descriptor/storage/source binding, not a synthetic resolver.
    sections = {int(key): val for key, val in json.loads((SPEC / 'conformance/execution/candidate/storage-tls-wrapper.json').read_text())['sections'].items()}
    binding = deepcopy(sections[6]['imports'][0])
    binding.update(id=1, name='tls_address', abi={'some': ref(1)})
    sections[6]['imports'].append(binding)
    sections[1]['types'].append(dict(id=600, kind='function', cc='portable', variadic=False,
        params=[ref(5)], results=[ref(17)], param_noundef=[False], result_noundef=[True]))
    node = operation('tls_address', [decl(20, 4)], [0], helper=dict(kind='import', **{'import': ref(1)}, signature=ref(201)), alignment=0, binding={'some': ref(0)})
    sections[3]['functions'].append(dict(id=1, signature=ref(600), abi_signature=None, params=[decl(0, 5)], entry=0,
        escape='propagate', no_return=False, blocks=[block(0, [node, constant(99, 17, '2a000000')], dict(op='return', values=[99]))]))
    add_sections('tls_address', sections, 1)

    sections = context_roots()
    sections[1]['types'] += [dict(id=500, kind='function', cc='portable', variadic=False,
        params=[], results=[ref(17)], param_noundef=[], result_noundef=[True]),
        dict(id=501, kind='code_ptr', signature=ref(12))]
    node = operation('address_of', [decl(0, 501)], [], symbol=ref(0))
    sections[3]['functions'].append(dict(id=1, signature=ref(500), abi_signature=None, params=[], entry=0,
        escape='propagate', no_return=False, blocks=[block(0, [node, constant(99, 17, '2a000000')], dict(op='return', values=[99]))]))
    add_sections('address_of', sections, 1)


def control_cases():
    roots = fixture()
    fn = roots[1]['functions'][0]
    fn['blocks'] = [block(0, [operation('block_address', [decl(0, 16)], [], function=0, block=1)], dict(op='jump', target=1)),
                    block(1, [constant(99, 2, '2a000000')], dict(op='return', values=[99]))]
    add('block_address', roots)
    for term in ['throw', 'rethrow', 'resume', 'cleanup_return', 'terminate']:
        roots = fixture()
        roots[0]['types'][15].update(params=[ref(10)], param_noundef=[False])
        fn = roots[1]['functions'][0]
        fn['params'] = [decl(0, 10)]
        end = dict(op=term, exception={'some': 0} if term in {'cleanup_return', 'terminate'} else 0)
        if term == 'terminate':
            end['reason'] = 'explicit'
        else:
            end['region'] = None
        fn['blocks'] = [block(0, [], end)]
        add(term, roots)

    for term in ['trap', 'unreachable']:
        roots = fixture()
        end = dict(op=term)
        if term == 'trap':
            end['reason'] = 'explicit'
        roots[1]['functions'][0]['blocks'] = [block(0, [], end)]
        add(term, roots)
    for term, typ in [('cbranch', 0), ('switch', 2), ('indirect_branch', 16)]:
        roots = fixture()
        roots[0]['types'][15].update(params=[ref(typ)], param_noundef=[False])
        fn = roots[1]['functions'][0]
        fn['params'] = [decl(0, typ)]
        end = (dict(op='cbranch', condition=0, **{'true': 1, 'false': 2}) if term == 'cbranch' else
               dict(op='switch', index=0, cases=[dict(value='01000000', target=1)], default=2) if term == 'switch' else
               dict(op='indirect_branch', address=0, targets=[1, 2]))
        fn['blocks'] = [block(0, [], end), block(1, [constant(1, 2, '01000000')], dict(op='return', values=[1])),
                        block(2, [constant(2, 2, '02000000')], dict(op='return', values=[2]))]
        add(term, roots)


def ssa_cases():
    roots = fixture()
    roots[0]['types'][15].update(params=[ref(0)], param_noundef=[False])
    fn = roots[1]['functions'][0]
    fn['params'] = [decl(90, 0)]
    fn['blocks'] = [block(0, [constant(0, 2, '00000000'), constant(1, 2, '01000000')], dict(op='jump', target=1)),
        block(1, [], dict(op='cbranch', condition=90, **{'true': 2, 'false': 3}),
            [{'result': decl(2, 2), 'incoming': [dict(predecessor=0, value=0), dict(predecessor=2, value=3)]}]),
        block(2, [operation('i_add', [decl(3, 2)], [2, 1], flags=[])], dict(op='jump', target=1)),
        block(3, [], dict(op='return', values=[2]))]
    add('loop_phi_backedge', roots)
    bad = deepcopy(roots)
    bad[1]['functions'][0]['blocks'][1]['phis'][0]['incoming'][1]['predecessor'] = 0
    add('reject_phi_duplicate_predecessor', bad)
    bad = deepcopy(roots)
    bad[1]['functions'][0]['blocks'][0]['ops'][0]['results'][0]['id'] = 1
    add('reject_activation_duplicate_id', bad)
    bad = deepcopy(roots)
    bad[1]['functions'][0]['blocks'][0]['ops'] = [operation('copy', [decl(0, 2)], [1]), constant(1, 2, '01000000')]
    add('reject_same_block_forward_use', bad)
    bad = deepcopy(roots)
    bad[1]['functions'][0]['blocks'][3]['term']['values'] = [3]
    add('reject_branch_definition_not_dominating_exit', bad)
    roots = fixture()
    roots[0]['types'][15].update(params=[ref(0)], param_noundef=[False])
    fn = roots[1]['functions'][0]
    fn['params'] = [decl(90, 0)]
    fn['blocks'] = [block(0, [constant(0, 2, '01000000'), constant(1, 2, '02000000')], dict(op='jump', target=1)),
        block(1, [], dict(op='cbranch', condition=90, **{'true': 2, 'false': 3}),
            [{'result': decl(2, 2), 'incoming': [dict(predecessor=0, value=0), dict(predecessor=2, value=3)]},
             {'result': decl(3, 2), 'incoming': [dict(predecessor=0, value=1), dict(predecessor=2, value=2)]}]),
        block(2, [], dict(op='jump', target=1)), block(3, [], dict(op='return', values=[2]))]
    add('simultaneous_phi_cross_backedge', roots)



def rejection_coverage():
    selected = {}
    for case in list(CASES):
        if case['expected'] != 'ok':
            continue
        mode, roots, dependencies, fn_id = ORACLES[case['name']]
        functions = roots[1]['functions'] if mode == 'local' else roots[3]['functions']
        function = next(fn for fn in functions if fn['id'] == fn_id)
        for b, block_record in enumerate(function['blocks']):
            for n, node in enumerate(block_record['ops']):
                selected.setdefault(node['op'], (case['name'], b, n))
    assert set(selected) == set(SCHEMAS['execution']['operation_contracts'])
    for op, (source, block_index, node_index) in sorted(selected.items()):
        mode, roots, dependencies, fn_id = ORACLES[source]
        mutated = deepcopy(roots)
        types = mutated[0]['types'] if mode == 'local' else mutated[1]['types']
        i32 = next(t['id'] for t in types if t['kind'] == 'int' and t['bits'] == 32)
        functions = mutated[1]['functions'] if mode == 'local' else mutated[3]['functions']
        function = next(fn for fn in functions if fn['id'] == fn_id)
        function['blocks'][block_index]['ops'][node_index]['results'].append(decl(0xfffffffe, i32))
        if mode == 'local':
            add('reject_result_arity_' + op, mutated, dependencies)
        else:
            add_sections('reject_result_arity_' + op, mutated, fn_id)
        assert CASES[-1]['expected'] in {'result_arity', 'call_results'}, CASES[-1]


def semantic_boundaries():
    add('reject_duplicate_integer_flag', node_case('i_add', [2, 2], [2], flags=['nsw', 'nsw']))
    add('reject_flag_on_urem', node_case('i_urem', [2, 2], [2], flags=['nsw']))
    add('reject_bswap_byte_width', node_case('i_bswap', [1], [1], zero_is_poison=False))
    add('reject_icmp_predicate', node_case('icmp', [2, 2], [0], predicate='ordered'))
    add('reject_extract_outside_struct', node_case('extract', [9], [2], indices=[2]))
    add('reject_shuffle_outside_two_inputs', node_case('shuffle', [8, 8], [8], mask=[{'some': 8}] * 4))
    add('reject_pointer_to_integer_bitcast', node_case('bitcast', [7], [3]))
    add('reject_trunc_widening', node_case('trunc', [1], [2]))
    add('reject_ptrtoaddr_non64', node_case('ptrtoaddr', [7], [2]))
    add('reject_reversed_inrange', node_case('ptr_offset', [7, 3], [7], inbounds=False, check_base=False,
        nuw=False, nusw=False, inrange={'some': dict(lower=1, upper=-1)}))
    bad_mode = dict(environment='constrained', rounding='downward', exceptions='strict')
    add('reject_fp_to_int_not_toward_zero', node_case('fptosi', [5], [2], mode=bad_mode))
    add('reject_fp_integer_input', node_case('fp_add', [2, 2], [2], mode=dict(environment='default', rounding='nearest_even', exceptions='ignore')))
    add('reject_fcmp_predicate', node_case('fcmp', [5, 5], [0], signaling=False, predicate='eq',
        mode=dict(environment='default', rounding='nearest_even', exceptions='ignore')))
    add('reject_unknown_environment_flag', node_case('fenv_raise', [], [], flags=['invalid', 'unknown']))
    add('reject_weak_fence_order', node_case('fence', [], [], order='relaxed', scope='process'))
    add('reject_bulk_alignment_zero', node_case('memcpy', [7, 7, 3], [], alignment=0, volatile=False))
    add('reject_memset_wide_byte', node_case('memset', [7, 2, 3], [], alignment=1, volatile=False))
    for source, mutation, value in [('atomic_load', 'order', 'release'), ('atomic_store', 'order', 'acquire'),
                                     ('cmpxchg', 'failure_order', 'release'), ('load', 'order', 'acquire'),
                                     ('load', 'alignment', 0), ('atomic_rmw', 'order', 'unordered')]:
        _, roots, dependencies, _ = ORACLES[source]
        changed = deepcopy(roots)
        changed[1]['functions'][0]['blocks'][0]['ops'][0]['mode'][mutation] = value
        add('reject_' + source + '_' + mutation + '_' + str(value), changed, dependencies)
    _, roots, dependencies, _ = ORACLES['atomic_rmw']
    changed = deepcopy(roots)
    changed[1]['functions'][0]['blocks'][0]['ops'][0]['action'] = 'fadd'
    add('reject_float_rmw_on_integer', changed, dependencies)
    _, roots, dependencies, _ = ORACLES['load']
    changed = deepcopy(roots)
    changed[1]['functions'][0]['blocks'][0]['ops'][0]['storage']['bytes'] = 3
    add('reject_memory_access_extent', changed, dependencies)
    sections = deepcopy(ORACLES['alloca'][1])
    sections[3]['functions'][1]['blocks'][0]['ops'][0]['alignment'] = 0
    add_sections('reject_alloca_alignment_zero', sections, 1)
    sections = deepcopy(ORACLES['journal'][1])
    sections[3]['functions'][1]['blocks'][0]['ops'][2]['action'] = 'construct_commit'
    add_sections('reject_journal_binding_contract', sections, 1)
    sections = deepcopy(ORACLES['catch_end'][1])
    sections[6]['imports'][0]['name'] = 'eh_release'
    add_sections('reject_catch_end_wrong_helper', sections, 1)


def node_case(name, args, outs, **fields):
    roots = fixture()
    signature = roots[0]['types'][15]
    signature['params'] = [ref(typ) for typ in args]
    signature['param_noundef'] = [False] * len(args)
    roots[1]['functions'][0]['params'] = [decl(i, typ) for i, typ in enumerate(args)]
    node = operation(name, [decl(20 + i, typ) for i, typ in enumerate(outs)], range(len(args)), **fields)
    roots[1]['functions'][0]['blocks'][0]['ops'] = [node, constant(99, 2, '2a000000')]
    roots[1]['functions'][0]['blocks'][0]['term']['values'] = [99]
    return roots


def cases():
    add('constant', fixture())
    for name in ['copy', 'freeze']:
        add(name, node_case(name, [2], [2]))
    binary = ['i_add', 'i_sub', 'i_mul', 'i_shl', 'i_lshr', 'i_ashr', 'i_udiv', 'i_sdiv',
              'i_urem', 'i_srem', 'i_and', 'i_or', 'i_xor', 'i_rotl', 'i_rotr']
    for name in binary:
        add(name, node_case(name, [2, 2], [2], flags=[]))
    for name in ['i_clz', 'i_ctz', 'i_popcount', 'i_abs', 'i_bswap', 'i_bitreverse']:
        add(name, node_case(name, [2], [2], zero_is_poison=False))
    add('icmp', node_case('icmp', [2, 2], [0], predicate='slt'))
    add('select', node_case('select', [0, 2, 2], [2]))
    add('extract', node_case('extract', [9], [2], indices=[1]))
    add('insert', node_case('insert', [9, 2], [9], indices=[1]))
    add('extract_element', node_case('extract_element', [8, 3], [1]))
    add('insert_element', node_case('insert_element', [8, 1, 3], [8]))
    add('shuffle', node_case('shuffle', [8, 8], [8], mask=[{'some': 7}, None, {'some': 0}, {'some': 3}]))
    for name, args, outs in [('trunc', [2], [1]), ('zext', [1], [2]), ('sext', [1], [2]),
                             ('bitcast', [3], [4]), ('ptrtoint', [7], [2]),
                             ('ptrtoaddr', [7], [3]), ('inttoptr', [3], [7])]:
        add(name, node_case(name, args, outs))
    add('ptr_offset', node_case('ptr_offset', [7, 3], [7], inbounds=True, check_base=True, nuw=False, nusw=False, inrange={'some': {'lower': -8, 'upper': 16}}))
    mode = dict(environment='default', rounding='nearest_even', exceptions='ignore')
    for name in ['fp_add', 'fp_sub', 'fp_mul', 'fp_div', 'fp_frem', 'fp_copysign',
                 'fp_minimum', 'fp_maximum', 'fp_minnum', 'fp_maxnum', 'fp_minimumnum', 'fp_maximumnum']:
        add(name, node_case(name, [5, 5], [5], mode=mode))
    for name in ['fp_sqrt', 'fp_neg', 'fp_abs']:
        add(name, node_case(name, [5], [5], mode=mode))
    add('fp_fma', node_case('fp_fma', [5, 5, 5], [5], mode=mode))
    add('fcmp', node_case('fcmp', [5, 5], [0], mode=mode, predicate='uno', signaling=False))
    for name, args, outs in [('sitofp', [2], [5]), ('uitofp', [2], [5]), ('fptosi', [5], [2]),
                             ('fptoui', [5], [2]), ('fpconvert', [5], [6]),
                             ('fptosi_sat', [5], [2]), ('fptoui_sat', [5], [2])]:
        add(name, node_case(name, args, outs, mode=mode))
    add('fenv_get', node_case('fenv_get', [], [11]))
    add('fenv_set', node_case('fenv_set', [11], []))
    for name in ['fenv_clear', 'fenv_raise', 'fenv_test']:
        add(name, node_case(name, [], [0] if name == 'fenv_test' else [], flags=['inexact', 'invalid']))
    add('effect_barrier', node_case('effect_barrier', [], []))
    for name in ['memcpy', 'memmove', 'memset']:
        add(name, node_case(name, [7, 1 if name == 'memset' else 7, 3], [], alignment=1, volatile=False))
    add('fence', node_case('fence', [], [], order='seq_cst', scope='process'))
    for name in ['load', 'store', 'atomic_load', 'atomic_store', 'atomic_rmw', 'cmpxchg']:
        args = [7] if name.endswith('load') or name == 'load' else [7, 2, 2] if name == 'cmpxchg' else [7, 2]
        outs = [] if name.endswith('store') or name == 'store' else [2, 0] if name == 'cmpxchg' else [2]
        storage = dict(type=ref(2), layout=ref(0), nominal=None, abi_binding=None, bytes=4)
        access = dict(alignment=4, volatile=False, order='none' if name in {'load', 'store'} else 'relaxed',
                      failure_order='seq_cst' if name == 'cmpxchg' else 'none', scope='process', elementwise=False)
        extras = dict(weak=False) if name == 'cmpxchg' else dict(action='add') if name == 'atomic_rmw' else {}
        roots = node_case(name, args, outs, storage=storage, mode=access, **extras)
        layout = dict(id=0, type=ref(2), size=4, alignment=4, access_bytes=4, fields=[], element=None, stride=0)
        roots[0]['memory_layouts'] = [layout]
        deps = Dependencies(layouts={('self', 0): layout})
        add(name, roots, deps)
    bad = node_case('i_add', [2, 1], [2], flags=[])
    add('reject_integer_mixed_width', bad)
    add('reject_integer_reserved_flag', node_case('i_add', [2, 2], [2], flags=['exact']))
    add('reject_unused_zero_flag', node_case('i_popcount', [2], [2], zero_is_poison=True))
    add('reject_select_non_boolean', node_case('select', [2, 2, 2], [2]))
    add('reject_pointer_index32', node_case('ptr_offset', [7, 2], [7], inbounds=False, check_base=False, nuw=False, nusw=False, inrange=None))
    add('reject_check_base_without_inbounds', node_case('ptr_offset', [7, 3], [7], inbounds=False, check_base=True, nuw=False, nusw=False, inrange=None))
    add('reject_fenv_freeze_opaque', node_case('freeze', [10], [10]))
    bad = deepcopy(mode, )
    bad['rounding'] = 'downward'
    add('reject_default_fp_rounding', node_case('fp_sqrt', [5], [5], mode=bad))
    add('reject_undefined_ssa', (lambda roots: (roots[0], dict(payload_revision=2, functions=[dict(roots[1]['functions'][0], blocks=[block(0, [], {'op': 'return', 'values': [88]})])]), roots[2]))(fixture()))
    roots = fixture()
    roots[1]['functions'][0]['blocks'] = [block(0, [], {'op': 'jump', 'target': 1}), block(1, [], {'op': 'return', 'values': [20]}, [{'result': decl(20, 2), 'incoming': [{'predecessor': 0, 'value': 20}]}])]
    add('reject_phi_self_not_dominating_predecessor', roots)
    roots = fixture()
    roots[1]['functions'][0]['blocks'] += [block(1, [], {'op': 'unreachable'})]
    add('reject_unreachable_block', roots)
    # Fixed-byte fenv transport is distinct from nonspillable private handles.
    roots = fixture()
    roots[0]['types'].append(dict(id=17, kind='raw', bits=256))
    roots[1]['functions'][0]['blocks'][0]['ops'] = [operation('fenv_get', [decl(0, 11)]),
        operation('fenv_pack', [decl(1, 17)], [0]), operation('fenv_unpack', [decl(2, 11), decl(3, 0)], [1]),
        constant(99, 2, '2a000000')]
    roots[1]['functions'][0]['blocks'][0]['term']['values'] = [99]
    add('fenv_pack_unpack', roots)
    # Direct calls and invoke edge-defined values use real local bodies.
    roots = fixture()
    callee = deepcopy(roots[1]['functions'][0])
    callee['id'] = 1
    roots[1]['functions'].append(callee)
    target = dict(kind='direct', function=ref(1), signature=ref(15))
    roots[1]['functions'][0]['blocks'][0]['ops'] = [operation('call', [decl(0, 2)], [], target=target, unwind='nounwind')]
    add('call', roots)
    roots[1]['functions'][0]['blocks'][0]['ops'] = []
    roots[1]['functions'][0]['blocks'][0]['term'] = dict(op='tailcall', target=target, operands=[], source_plan=None)
    add('tailcall', roots)
    roots[1]['functions'][0]['blocks'] = [
        block(0, [], dict(op='invoke', target=target, operands=[], normal=dict(target=1, results=[decl(0, 2)]), unwind=dict(target=2, exception=decl(1, 10)), region=0)),
        block(1, [], dict(op='return', values=[0])),
        block(2, [constant(2, 2, '00000000')], dict(op='return', values=[2]))]
    roots[2]['functions'] = [dict(function=0, actions=[], regions=[dict(id=0, parent=None, blocks=[0], exit_actions=[], handlers=[], escape='continue')])]
    add('invoke_edges', roots)
    bad = deepcopy(roots)
    bad[1]['functions'][0]['blocks'][2]['term']['values'] = [0]
    add('reject_invoke_normal_result_on_unwind', bad)
    roots[1]['functions'][0]['blocks'][2]['ops'] = [operation('landingpad', [decl(2, 2)], [1], region=0)]
    add('landingpad', roots)
    helper_cases()
    control_cases()
    ssa_cases()
    # Genuine ABI-checked static bind/erase witness also supplies the new
    # operation-family arity mutations below; no executable permit is issued.
    from candidate.function_address_contract import source_roots
    source = source_roots()
    source[3]['functions'][0]['blocks'][0]['ops'] = [
        operation('constant', [decl(1, 300)], literal={'kind': 'zero'}),
        operation('code_bind', [decl(2, 301)], [1], plan=ref(0)),
        operation('code_erase', [decl(3, 300)], [2])]
    add_sections('code_address_static_bind_erase', source)


if __name__ == '__main__':
    cases()
    rejection_coverage()
    semantic_boundaries()
    phase_cases()
    sources = sorted({Path(module.__file__).resolve() for module in list(sys.modules.values())
                      if getattr(module, '__file__', None) and Path(module.__file__).resolve().is_relative_to(ROOT)})
    sources.append(Path(__file__).resolve())
    result = dict(purpose='Local static execution predicates only; no ABI/runtime success certificate and no executable admission.',
                  sources=input_sources(ROOT, sources), oracle_input_roots=input_roots(), oracle_interpreter=interpreter_identity(),
                  cases=CASES)
    output = Path(__file__).with_name('core-cases.json')
    output.write_text(json.dumps(result, separators=(',', ':')) + '\n')
    phase_output = output.with_name('phase-cases.json')
    phase_output.write_text(json.dumps(dict(purpose='Actual ABI/execution oracle and actual Rust all-role phase factories; no test proof constructors.', sources=result['sources'], oracle_input_roots=result['oracle_input_roots'], oracle_interpreter=result['oracle_interpreter'], cases=PHASE_CASES), separators=(',', ':')) + '\n')
    print(f'{len(CASES)} independent cases; {sum(case["expected"] == "ok" for case in CASES)} accept, {sum(case["expected"] != "ok" for case in CASES)} reject; {output.stat().st_size}bytes')
    print(f'{len(PHASE_CASES)} phase cases; {sum(case["expected"] == "ok" for case in PHASE_CASES)} accept, {sum(case["expected"] != "ok" for case in PHASE_CASES)} reject; {phase_output.stat().st_size}bytes')
