"""Coherent candidate type/SSA/CFG/invoke-edge/exception-region admission."""
from copy import deepcopy
from dataclasses import dataclass

from common import Limits, bit_pattern, require
from candidate.operations import Dependencies, call_types, check_operation, optional, source_call_plan
from candidate.type_system import Types, key, ref, unique
from candidate.wire import encode
from . import factory_meter as M


def targets(term):
    name = term['op']
    if name == 'jump':
        return [term['target']]
    if name == 'cbranch':
        return [term['true'], term['false']]
    if name == 'switch':
        return [term['default']] + [case['target'] for case in term['cases']]
    if name == 'invoke':
        return [term['normal']['target'], term['unwind']['target']]
    if name == 'indirect_branch':
        return term['targets']
    return []


def uses(node):
    result = list(node.get('operands', []))
    if node['op'] == 'cbranch':
        result.append(node['condition'])
    elif node['op'] == 'switch':
        result.append(node['index'])
    elif node['op'] == 'indirect_branch':
        result.append(node['address'])
    elif node['op'] == 'return':
        result += node['values']
    if 'exception' in node:
        value = node['exception']
        if isinstance(value, int):
            result.append(value)
        elif value is not None:
            result.append(optional(value))
    for name in ['target', 'helper']:
        if isinstance(node.get(name), dict) and node[name].get('kind') == 'indirect':
            result.append(node[name]['value'])
    return result


@dataclass(frozen=True)
class Verified:
    types_root: dict
    functions_root: dict
    exceptions_root: dict
    types: Types
    dependencies: Dependencies


def verify(types_root, functions_root, exceptions_root, dependencies=None, external_types=None, limits=Limits()):
    for kind, root in [('execution_types', types_root), ('execution_functions', functions_root),
                       ('execution_exceptions', exceptions_root)]:
        encode(kind, root, limits)  # Exact logical fields/quotas before references.
        require(root['payload_revision'] == (1 if kind == 'execution_exceptions' else 2), 'revision', kind)
    return _verify_body_common(types_root, functions_root, exceptions_root, dependencies, external_types, limits)


def _verify_v3_body(types_root, functions_root, exceptions_root, dependencies=None,
                    external_types=None, limits=Limits(), *, budget):
    from . import root3_context as V3
    V3.canonical_budget(budget)
    require(functions_root['payload_revision'] == 3, 'V3_REVISION')
    V3.codec().encode_root3(functions_root, budget=budget)
    for kind, root in [('execution_types', types_root), ('execution_exceptions', exceptions_root)]:
        M.json_bound(root, budget)
        encode(kind, root, limits)
        require(root['payload_revision'] == (1 if kind == 'execution_exceptions' else 2), 'revision', kind)
    return _verify_body_common(types_root, functions_root, exceptions_root, dependencies, external_types, limits, budget=budget)


def _verify_body_common(types_root, functions_root, exceptions_root, dependencies, external_types, limits, *, budget=None):
    M.check(budget)
    M.json_bound(functions_root, budget)
    types = Types(types_root, external_types, budget=budget)
    if budget is not None: M.collection(budget, len(functions_root['functions']))
    functions = unique(functions_root['functions'])
    require(len(functions) <= limits.max_functions, 'limit', 'candidate functions')
    if budget is not None and dependencies is not None:
        for name in ('functions','imports','layouts','nominals','actions','symbols',
                     'cleanup_programs','storage_bindings','abi_signatures','bridges',
                     'abi_masks','host_descriptors','tls'):
            M.snapshot_bound(getattr(dependencies, name), budget)
    deps = deepcopy(dependencies or Dependencies())
    from candidate.layouts import Layouts
    layouts = Layouts(types_root, types, {identity: item for identity, item in M.iter_rows(budget, deps.layouts.items()) if identity[0] == 'dependency'}, budget=budget)
    deps.layouts = layouts.items
    if budget is not None: M.collection(budget, len(exceptions_root['functions']))
    eh = unique(exceptions_root['functions'], 'function')
    require(set(eh) <= set(functions), 'eh_function_reference')
    for identifier, function in M.iter_rows(budget, functions.items()):
        require(identifier < 0xffffffff, 'function_id')
        signature = types.get(function['signature'])
        require(signature['kind'] == 'function', 'function_signature')
        if ('self', identifier) in deps.functions:
            require(types.equal(deps.functions[('self', identifier)], function['signature']), 'function_declaration_conflict')
        deps.functions[('self', identifier)] = function['signature']
        require(function['escape'] in {'propagate', 'terminate', 'nothrow'}, 'function_escape')
        require(len(function['params']) == len(signature['params']) and all(
            types.equal(parameter['type'], expected)
            for parameter, expected in M.iter_rows(budget, zip(function['params'], signature['params']))), 'parameter_signature')
        abi_signature = optional(function['abi_signature'])
        if abi_signature is not None:
            require(abi_signature['module']['kind'] == 'self', 'function_abi_signature_self')
            require(key(abi_signature) in deps.abi_signatures, 'function_abi_signature')
            descriptor = deps.abi_signatures[key(abi_signature)]
            require(types.equal(descriptor['execution'], function['signature']), 'function_plan_execution')
            # The ABI-verified entry association includes hidden this/VTT/sret.
            # Exact lowered FullFn, nominal types and noundef remain checked below.
            params = descriptor['lowered_params']
            results = descriptor['lowered_results']
            require(len(params) == len(signature['params']) and len(results) == len(signature['results']), 'abi_lowered_arity')
            for actual, parameter, noundef in M.iter_rows(budget, zip(signature['params'], params, signature['param_noundef'])):
                require(key(parameter['value_type']) in deps.nominals, 'abi_parameter_nominal')
                expected = optional(deps.nominals[key(parameter['value_type'])]['execution'])
                require(expected is not None and types.equal(actual, expected)
                        and parameter['noundef'] == noundef, 'abi_lowered_parameter')
            for actual, result, noundef in M.iter_rows(budget, zip(signature['results'], results, signature['result_noundef'])):
                require(key(result) in deps.nominals, 'abi_result_nominal')
                expected = optional(deps.nominals[key(result)]['execution'])
                require(expected is not None and types.equal(actual, expected)
                        and descriptor['return_noundef'] == noundef, 'abi_lowered_result')
        require(not signature['variadic'], 'variadic_requires_abi_lowering',
                'source variadic belongs in ABI descriptor; execution signature has exact hidden arena/bytes suffix')
    for identifier, function in M.iter_rows(budget, functions.items()):
        exception_data = eh.get(identifier, {'regions': [], 'actions': []})
        if functions_root['payload_revision'] == 3:
            verify_function(function, exception_data, types, deps, limits,
                            budget=budget, source_revision=3)
        else:
            verify_function(function, exception_data, types, deps, limits, budget=budget)
    M.snapshot_bound(types_root, budget)
    M.snapshot_bound(functions_root, budget)
    M.snapshot_bound(exceptions_root, budget)
    return Verified(deepcopy(types_root), deepcopy(functions_root), deepcopy(exceptions_root), types, deps)


def verify_function(function, exception_data, types, dependencies, limits, *, budget=None, source_revision=2):
    require(type(source_revision) is int and source_revision in (2, 3), 'V3_BODY_REVISION')
    M.json_bound(function, budget)
    M.json_bound(exception_data, budget)
    blocks = unique(function['blocks'])
    require(0 < len(blocks) <= limits.max_blocks and function['entry'] in blocks, 'cfg_entry')
    entry = function['entry']
    predecessors = {identifier: set() for identifier in M.iter_rows(budget, blocks)}
    edges = {}
    for block in M.iter_rows(budget, blocks.values()):
        M.body_node(block['term'], budget)
        for target in M.iter_rows(budget, targets(block['term'])):
            require(target in blocks, 'cfg_target')
            predecessors[target].add(block['id'])
        term = block['term']
        if term['op'] == 'invoke':
            normal, unwind = term['normal'], term['unwind']
            require(normal['target'] != unwind['target'], 'invoke_edge_alias')
            for role, edge, declarations in M.iter_rows(budget, [('normal', normal, normal['results']),
                                              ('unwind', unwind, [unwind['exception']])]):
                require(edge['target'] not in edges, 'invoke_shared_edge')
                edges[edge['target']] = (block['id'], role, declarations)
    require(not predecessors[entry] and not blocks[entry]['phis'], 'entry_predecessor')
    for target, (origin, role, declarations) in M.iter_rows(budget, edges.items()):
        require(predecessors[target] == {origin} and not blocks[target]['phis'], 'invoke_edge_canonical', role)
    reached, pending = set(), [entry]
    while (M.step(budget) and (pending)):
        identifier = pending.pop()
        if identifier not in reached:
            reached.add(identifier)
            M.body_node(blocks[identifier]['term'], budget)
            pending.extend(targets(blocks[identifier]['term']))
    require(reached == set(blocks), 'cfg_unreachable')
    indices = {identifier: index for index, identifier in M.iter_rows(budget, enumerate(blocks))}
    full = (1 << len(blocks)) - 1
    dominators = {identifier: 1 << indices[entry] if identifier == entry else full for identifier in M.iter_rows(budget, blocks)}
    changed = True
    while (M.step(budget) and (changed)):
        if budget is not None: M.collection(budget, len(blocks)**2)
        changed = False
        for identifier in M.iter_rows(budget, blocks):
            if identifier == entry:
                continue
            common = full
            for predecessor in M.iter_rows(budget, predecessors[identifier]):
                common &= dominators[predecessor]
            updated = common | (1 << indices[identifier])
            changed |= updated != dominators[identifier]
            dominators[identifier] = updated
    definitions = {}

    def define(declaration, block, position):
        identifier = declaration['id']
        require(identifier not in definitions, 'ssa_duplicate')
        require(types.get(declaration['type'])['kind'] != 'function', 'ssa_type')
        definitions[identifier] = (declaration['type'], block, position)

    for parameter in M.iter_rows(budget, function['params']):
        define(parameter, None, -1)
    for target, (_, role, declarations) in M.iter_rows(budget, edges.items()):
        for declaration in M.iter_rows(budget, declarations):
            define(declaration, target, -2)
        if role == 'unwind':
            require(types.get(declarations[0]['type'])['kind'] == 'exception', 'invoke_exception_type')
    for block in M.iter_rows(budget, blocks.values()):
        for phi in M.iter_rows(budget, block['phis']):
            define(phi['result'], block['id'], -1)
        for position, operation in M.iter_rows(budget, enumerate(block['ops'])):
            if operation['op'] == 'longjmp':
                require(position == len(block['ops']) - 1 and block['term']['op'] == 'unreachable', 'longjmp_normal_continuation')
            for declaration in M.iter_rows(budget, operation['results']):
                define(declaration, block['id'], position)

    def value_type(identifier):
        require(identifier in definitions, 'ssa_reference', str(identifier))
        return definitions[identifier][0]

    def use(identifier, block, position):
        value_type(identifier)
        _, origin, birth = definitions[identifier]
        require(origin is None or (origin == block and birth < position)
                or (origin != block and dominators[block] & (1 << indices[origin])), 'ssa_dominance', str(identifier))

    for block in M.iter_rows(budget, blocks.values()):
        identifier = block['id']
        for phi in M.iter_rows(budget, block['phis']):
            incoming = [item['predecessor'] for item in M.iter_rows(budget, phi['incoming'])]
            require(len(incoming) == len(set(incoming)) and set(incoming) == predecessors[identifier], 'phi_edges')
            for item in M.iter_rows(budget, phi['incoming']):
                use(item['value'], item['predecessor'], len(blocks[item['predecessor']]['ops']))
                require(types.equal(value_type(item['value']), phi['result']['type']), 'phi_type')
        for position, operation in M.iter_rows(budget, enumerate(block['ops'])):
            M.operation_shell(operation, dependencies, budget)
            for value in M.iter_rows(budget, uses(operation)):
                use(value, identifier, position)
            if operation['op'] == 'source_journal_observe':
                require(source_revision == 3, 'V3_OBSERVER_TYPE_CONTEXT')
                from . import source_observer
                source_observer.check(operation, types, budget=budget)
            else:
                check_operation(operation, types, dependencies, value_type, function)
            if operation['op'] == 'block_address':
                require(operation['function'] == function['id'] and operation['block'] in blocks
                        and operation['block'] != entry, 'block_address')
        term = block['term']
        M.operation_shell(term, dependencies, budget)
        for value in M.iter_rows(budget, uses(term)):
            use(value, identifier, len(block['ops']))
        name = term['op']
        if name == 'return':
            expected = types.get(function['signature'])['results']
            require(not function['no_return'] and len(term['values']) == len(expected)
                    and all(types.equal(value_type(value), typ) for value, typ in M.iter_rows(budget, zip(term['values'], expected))), 'return_signature')
        elif name == 'cbranch':
            condition = types.get(value_type(term['condition']))
            require(condition['kind'] == 'int' and condition['bits'] == 1, 'branch_boolean')
        elif name == 'switch':
            typ = types.get(value_type(term['index']))
            require(typ['kind'] == 'int', 'switch_type')
            values = [bit_pattern(case['value'], typ['bits']) for case in M.iter_rows(budget, term['cases'])]
            require(values == sorted(set(values)), 'switch_cases')
        elif name == 'indirect_branch':
            require(types.get(value_type(term['address']))['kind'] == 'code_ptr'
                    and term['targets'] and term['targets'] == sorted(set(term['targets']))
                    and entry not in term['targets'], 'indirect_branch_targets')
        elif name in {'invoke', 'tailcall'}:
            results = (term['normal']['results'] if name == 'invoke' else
                       [{'id': 0, 'type': typ} for typ in M.iter_rows(budget, types.get(function['signature'])['results'])])
            callee_signature = call_types(term['target'], term['operands'], results, types, dependencies, value_type)
            source_call_plan(term, types, dependencies)
            if name == 'tailcall':
                require(not function['no_return'] and callee_signature['result_noundef'] ==
                        types.get(function['signature'])['result_noundef'], 'tail_result_contract')
        elif name in {'throw', 'rethrow', 'resume', 'cleanup_return', 'terminate'}:
            exception = term.get('exception')
            require(name != 'cleanup_return' or exception is not None, 'cleanup_requires_explicit_exception')
            if exception is not None:
                value = exception if type(exception) is int else optional(exception)
                require(types.get(value_type(value))['kind'] == 'exception', 'exception_value')
    verify_regions(function, exception_data, blocks, types, dependencies, value_type, use, budget=budget)


def verify_regions(function, exception_data, blocks, types, dependencies, value_type, use, *, budget=None):
    M.json_bound(exception_data, budget)
    regions = unique(exception_data['regions'])
    actions = unique(exception_data['actions'])
    for action in M.iter_rows(budget, actions.values()):
        require(key(action['program']) in dependencies.cleanup_programs, 'cleanup_program_reference')
        require(key(action['recipe']) in dependencies.actions, 'cleanup_recipe_reference')
        recipe = dependencies.actions[key(action['recipe'])]
        formals = {parameter['id']: parameter for parameter in M.iter_rows(budget, recipe['params'])}
        require(len(formals) == len(recipe['params']), 'cleanup_formal_duplicate')
        captures = [capture['parameter'] for capture in M.iter_rows(budget, action['captures'])]
        require(len(captures) == len(set(captures)) and set(captures) == set(formals), 'cleanup_capture_bijection')
        for capture in M.iter_rows(budget, action['captures']):
            nominal = formals[capture['parameter']]['type']
            require(key(nominal) in dependencies.nominals, 'cleanup_capture_nominal')
            expected = optional(dependencies.nominals[key(nominal)]['execution'])
            require(expected is not None and types.equal(expected, capture['type']), 'cleanup_capture_type')
            source = capture['source']
            if source['kind'] == 'value':
                require(types.equal(value_type(source['value']), capture['type']), 'cleanup_capture_value_type')
            elif source['kind'] == 'exception':
                require(types.get(capture['type'])['kind'] == 'exception', 'cleanup_capture_exception')
            else:
                require(types.get(capture['type'])['kind'] == 'journal'
                        and source['program'] == action['program'], 'cleanup_capture_journal')
    require(len(regions) <= 1024, 'limit', 'regions')
    ancestry = {}
    handler_ids = set()
    selector_types = []

    def same_catch_type(left, right):
        require(callable(dependencies.nominal_equal), 'handler_nominal_comparator')
        try:
            equal = dependencies.nominal_equal(left, right)
        except ValueError as error:
            require(False, 'handler_nominal_type', str(error))
        require(type(equal) is bool, 'handler_nominal_comparator')
        return equal

    memberships = {block: [] for block in M.iter_rows(budget, blocks)}
    for identifier, region in M.iter_rows(budget, regions.items()):
        parent = optional(region['parent'])
        require(parent is None or parent in regions, 'region_parent')
        require(region['blocks'] == sorted(set(region['blocks'])) and set(region['blocks']) <= set(blocks), 'region_blocks')
        require(region['escape'] in {'continue', 'terminate'}, 'region_escape')
        for block in M.iter_rows(budget, region['blocks']):
            memberships[block].append(identifier)
        seen, current = set(), identifier
        while (M.step(budget) and (current is not None)):
            require(current not in seen, 'region_cycle')
            seen.add(current)
            require(len(seen) <= 64, 'limit', 'region depth')
            current = optional(regions[current]['parent'])
        ancestry[identifier] = seen
        if parent is not None:
            require(set(region['blocks']) <= set(regions[parent]['blocks']), 'region_nesting')
        catch_all = False
        for handler in M.iter_rows(budget, region['handlers']):
            require(handler['id'] not in handler_ids and handler['id'] < 0xffffffff
                    and handler['entry'] in blocks, 'handler_identity')
            handler_ids.add(handler['id'])
            require(len(handler_ids) <= 1024, 'reference_resource', 'handlers per function')
            require(1 <= handler['selector'] <= 0x7fffffff, 'handler_selector_range')
            require(not catch_all and handler['kind'] in {'typed', 'catch_all'}, 'handler_order')
            nominal = optional(handler['nominal'])
            require((handler['kind'] == 'typed' and nominal is not None and key(nominal) in dependencies.nominals)
                    or (handler['kind'] == 'catch_all' and nominal is None), 'handler_nominal')
            if nominal is not None:
                require(same_catch_type(nominal, nominal), 'handler_nominal_type')
            for previous_type, previous_selector in M.iter_rows(budget, selector_types):
                same = (nominal is previous_type if nominal is None or previous_type is None
                        else same_catch_type(nominal, previous_type))
                require(same == (handler['selector'] == previous_selector), 'handler_selector_type')
            selector_types.append((nominal, handler['selector']))
            catch_all |= handler['kind'] == 'catch_all'
            for action in M.iter_rows(budget, handler['cleanup_actions']):
                require(action in actions, 'cleanup_action_reference')
            copy = optional(handler['catch_copy'])
            require(copy is None or copy in actions, 'catch_copy_reference')
        for action in M.iter_rows(budget, region['exit_actions']):
            require(action in actions, 'cleanup_action_reference')
    for block, region_ids in M.iter_rows(budget, memberships.items()):
        # Overlap must be an ancestor chain, never two independent live regions.
        ordered = sorted(region_ids, key=lambda identifier: len(ancestry[identifier]))
        require(all(outer in ancestry[inner] for outer, inner in M.iter_rows(budget, zip(ordered, ordered[1:]))), 'region_overlap')
    for block in M.iter_rows(budget, blocks.values()):
        term = block['term']
        if term['op'] == 'invoke':
            require(term['region'] in regions and block['id'] in regions[term['region']]['blocks'], 'invoke_region')
            current = term['region']
            while (M.step(budget) and (current is not None)):
                region = regions[current]
                action_ids = list(region['exit_actions'])
                for handler in M.iter_rows(budget, region['handlers']):
                    action_ids += handler['cleanup_actions']
                    if handler['catch_copy'] is not None:
                        action_ids.append(optional(handler['catch_copy']))
                for action_id in M.iter_rows(budget, action_ids):
                    for capture in M.iter_rows(budget, actions[action_id]['captures']):
                        if capture['source']['kind'] == 'value':
                            use(capture['source']['value'], block['id'], len(block['ops']))
                current = optional(region['parent'])
        elif term['op'] in {'throw', 'rethrow', 'resume', 'cleanup_return'}:
            region = optional(term['region'])
            require(region is None or region in regions, 'exception_region')
            require(not any(regions[member]['handlers'] or regions[member]['exit_actions']
                            for member in M.iter_rows(budget, memberships[block['id']])),
                    'raise_requires_invoke', 'protected local raise must have explicit unwind edge')
        elif term['op'] == 'tailcall':
            require(not any(regions[member]['handlers'] or regions[member]['exit_actions']
                            for member in M.iter_rows(budget, memberships[block['id']])), 'tail_protected_region')
            require(not any(operation['op'] in {'journal', 'catch_begin', 'catch_end', 'stack_save', 'setjmp'}
                            for candidate in M.iter_rows(budget, blocks.values()) for operation in M.iter_rows(budget, candidate['ops'])), 'tail_local_obligations')
        for operation in M.iter_rows(budget, block['ops']):
            if operation['op'] == 'call' and operation['unwind'] == 'propagate':
                require(not any(regions[member]['handlers'] or regions[member]['exit_actions']
                                for member in M.iter_rows(budget, memberships[block['id']])), 'call_requires_invoke')
            if 'helper' in operation and operation['helper']['kind'] == 'import':
                binding = dependencies.imports[key(operation['helper']['import'])]
                if binding['kind'] == 'internal':
                    from candidate.bindings import validate
                    M.internal_helper(binding, dependencies, budget)
                    template = validate(binding, types, dependencies)
                    if template.get('completion') == 'raises' or 'exception' in template['traps']:
                        require(not any(regions[member]['handlers'] or regions[member]['exit_actions']
                                        for member in M.iter_rows(budget, memberships[block['id']])), 'helper_requires_invoke')
            if operation['op'] == 'landingpad':
                require(operation['region'] in regions, 'landingpad_region')
            elif operation['op'] == 'catch_begin':
                require(operation['handler'] in handler_ids, 'catch_handler')
