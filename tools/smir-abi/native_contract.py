"""Foreign adapter action CFG, native CFI/personality and catch recipe checks."""

import hashlib

from layout import alignment, require
from nominal import option, unique

# Input/output arities; None means signature-dependent. All effects have tickets.
ACTIONS = {
    'adjust': (1, 1), 'byte_copy': (2, 0), 'copy': (1, 1), 'move': (1, 1),
    'construct': (1, 1), 'destroy': (1, 0), 'retain': (1, 0), 'release': (1, 0),
    'convert': (1, 1), 'call': (None, None), 'virtual_call': (None, None),
    'rtti_cast': (1, 1), 'catch_copy': (1, 1), 'checkpoint': (None, None),
    'return': (None, 0), 'raise': (1, 0), 'terminate': (0, 0),
}
CALL_ACTIONS = {'copy', 'move', 'construct', 'destroy', 'retain', 'release',
                'convert', 'call', 'virtual_call', 'catch_copy', 'checkpoint'}

NATIVE_CC={('x86_64','linux'):'sysv_amd64',('x86_64','darwin'):'sysv_amd64',
           ('x86_64','windows'):'win64',('aarch64','linux'):'aapcs64',
           ('aarch64','darwin'):'aapcs64_darwin',('aarch64','windows'):'aapcs64_windows'}
PACKET_CC={'sysv_amd64':'sysv64_frame','win64':'win64_frame','aapcs64':'aapcs64_frame',
           'aapcs64_darwin':'aapcs64_frame','aapcs64_windows':'aapcs64_frame'}


def verify_captures(recipe, captures, graph, resolve_execution):
    formals = unique(recipe['params'], 'VALUE')
    require(len(captures) == len(formals) and
            {capture['parameter'] for capture in captures} == formals.keys(), 'ABI_CC_CAPTURE_BIJECTION')
    for capture in captures:
        formal = graph.resolve(formals[capture['parameter']]['type'])[1]
        require(formal['execution'] is not None, 'ABI_CC_CAPTURE_BINDING')
        actual = resolve_execution(capture['type'])
        expected = resolve_execution(option(formal['execution']))
        require(actual['identity'] == expected['identity'], 'ABI_CC_CAPTURE_TYPE')
        source = capture['source']
        require(source['kind'] in ('value', 'exception', 'journal'), 'ABI_CC_CAPTURE_SOURCE')
        if source['kind'] in ('exception', 'journal'):
            require(actual['kind'] == source['kind'], 'ABI_CC_CAPTURE_INJECTED_KIND')
    return True


def verify_adapter(recipe, graph, context, tables):
    require(recipe['domain'] in tables['domains'], 'ABI_CC_ADAPTER_DOMAIN')
    steps = unique(recipe['steps'], 'STEP')
    require(recipe['entry'] in steps, 'ABI_CC_ADAPTER_ENTRY')
    values = unique(recipe['params'], 'VALUE')
    initial = set(values)
    for decl in values.values():
        graph.resolve(decl['type'])
    predecessors = {identifier: [] for identifier in steps}
    edges = {}
    tickets = set()
    for identifier, step in steps.items():
        require(step['action'] in ACTIONS, 'ABI_CC_ADAPTER_ACTION')
        input_count, output_count = ACTIONS[step['action']]
        require(input_count is None or len(step['inputs']) == input_count, 'ABI_CC_ADAPTER_ARITY')
        require(output_count is None or len(step['outputs']) == output_count, 'ABI_CC_ADAPTER_ARITY')
        alignment(step['align'])
        declared = step['outputs'] + ([] if step['exception'] is None else [option(step['exception'])])
        for decl in declared:
            require(decl['id'] not in values, 'ABI_CC_ADAPTER_VALUE_REDEFINITION')
            values[decl['id']] = decl
            graph.resolve(decl['type'])
        if step['action'] in CALL_ACTIONS or step['action'] == 'byte_copy':
            require(step['ticket'] not in tickets, 'ABI_CC_ADAPTER_TICKET')
            tickets.add(step['ticket'])
        callee = option(step['callee'])
        require((callee is not None) == (step['action'] in CALL_ACTIONS), 'ABI_CC_ADAPTER_CALLEE')
        if callee is not None:
            symbol = context.symbol(callee)
            require(symbol['kind'] == 'function' and symbol['domain'] == recipe['domain'],
                    'ABI_CC_ADAPTER_CALLEE')
        require((step['adjustment'] is not None) == (step['action'] == 'adjust'), 'ABI_CC_ADAPTER_ADJUSTMENT')
        for field in ('source_type', 'target_type'):
            if step[field] is not None:
                graph.resolve(option(step[field]))
        if step['action'] == 'catch_copy':
            require(step['journal_slot'] is not None, 'ABI_CC_CATCH_COPY_JOURNAL')
        if step['action'] in ('return', 'raise', 'terminate'):
            require(step['normal'] is None and step['unwind'] is None and step['exception'] is None,
                    'ABI_CC_ADAPTER_TERMINATOR')
        else:
            require(step['normal'] is not None, 'ABI_CC_ADAPTER_CONTINUATION')
        require((step['exception'] is not None) == (step['unwind'] is not None), 'ABI_CC_ADAPTER_UNWIND_VALUE')
        for edge in ('normal', 'unwind'):
            target = option(step[edge])
            if target is None:
                continue
            require(target in steps, 'ABI_CC_ADAPTER_CONTINUATION')
            predecessors[target].append((identifier, edge))
            produced = {decl['id'] for decl in step['outputs']} if edge == 'normal' else {
                option(step['exception'])['id']}
            edges[identifier, edge] = produced
    require(not predecessors[recipe['entry']], 'ABI_CC_ADAPTER_ENTRY')
    ready = [recipe['entry']]
    available, visited = {recipe['entry']: initial}, set()
    while ready:
        identifier = ready.pop()
        if identifier in visited:
            continue
        step = steps[identifier]
        require(set(step['inputs']) <= available[identifier], 'ABI_CC_ADAPTER_DOMINANCE')
        action = step['action']
        if action in CALL_ACTIONS:
            callee = context.symbol(option(step['callee']))
            _, signature = graph.resolve(callee['signature'])
            require(signature['kind'] == 'function' and signature['elements'], 'ABI_CC_ADAPTER_SIGNATURE')
            expected_params = signature['elements'][:-1]
            expected_result = signature['elements'][-1]
            require(len(step['inputs']) == len(expected_params) and all(
                graph.compatible(values[value]['type'], expected)
                for value, expected in zip(step['inputs'], expected_params)), 'ABI_CC_ADAPTER_ARGUMENT_TYPE')
            result_is_void = graph.resolve(expected_result)[1]['kind'] == 'void'
            require(len(step['outputs']) == (0 if result_is_void else 1) and
                    (result_is_void or graph.compatible(step['outputs'][0]['type'], expected_result)),
                    'ABI_CC_ADAPTER_RESULT_TYPE')
            if action == 'catch_copy' and step['unwind'] is not None:
                require(steps[option(step['unwind'])]['action'] == 'terminate', 'ABI_CC_CATCH_COPY_TERMINATION')
        if action == 'return':
            require(len(step['inputs']) == len(recipe['results']) and all(
                graph.compatible(values[value]['type'], expected)
                for value, expected in zip(step['inputs'], recipe['results'])), 'ABI_CC_ADAPTER_RETURN')
        if action == 'raise':
            raised=graph.resolve(values[step['inputs'][0]]['type'])[1]
            require(raised['kind'] == 'handle' and raised['identity']['entity']=='rax.exception_lease',
                    'ABI_CC_ADAPTER_EXCEPTION_TYPE')
        if step['exception'] is not None:
            raised=graph.resolve(option(step['exception'])['type'])[1]
            require(raised['kind'] == 'handle' and raised['identity']['entity']=='rax.exception_lease',
                    'ABI_CC_ADAPTER_EXCEPTION_TYPE')
        visited.add(identifier)
        for edge in ('normal', 'unwind'):
            target = option(step[edge])
            if target is None or target in visited:
                continue
            if all(parent in visited for parent, _ in predecessors[target]):
                incoming = [available[parent] | edges[parent, branch] for parent, branch in predecessors[target]]
                available[target] = set.intersection(*incoming)
                ready.append(target)
    require(visited == steps.keys(), 'ABI_CC_ADAPTER_CYCLE_OR_UNREACHABLE')


def public_base_paths(graph, thrown, caught, owner=None, caught_owner=None):
    """Return distinct subobject paths, deduplicating admitted virtual identities."""
    owner = owner or graph.module_id
    caught_owner = caught_owner or graph.module_id
    results = {}
    active = set()

    def walk(current, module, path, public, offset, virtual_identity):
        current_module, item = graph.resolve(current, module)
        key = current_module, item['id']
        require(key not in active, 'ABI_CC_BASE_CYCLE')
        active.add(key)
        try:
            resolved = {'module': {'kind': 'self'}, 'id': item['id']}
            if graph.compatible(resolved, caught, current_module, caught_owner, ignore_top_cv=True):
                identity = ('virtual', virtual_identity, offset) if virtual_identity is not None else ('fixed', tuple(path), offset)
                results.setdefault(identity, []).append((public, path, offset))
                return
            if item['kind'] != 'record':
                return
            source = option(item['record_input'])
            require(source is not None, 'ABI_CC_SOURCE_HIERARCHY_UNAVAILABLE')
            layout = graph.layout(resolved, current_module)
            for index, base in enumerate(source['bases']):
                identity = (graph.fingerprint(base['type'], current_module, ignore_top_cv=True)
                            if base['virtual'] else virtual_identity)
                if base['virtual']:
                    new_offset = 0  # Runtime virtual component query remains separate.
                else:
                    placement = next((b for b in layout['bases'] if not b['virtual'] and
                                      option(b['declaration_index']) == index), None)
                    require(placement is not None, 'ABI_CC_BASE_DERIVATION')
                    new_offset = offset + placement['offset']
                walk(base['type'], current_module, path + [str(index)],
                     public and base['access'] == 'public', new_offset, identity)
        finally:
            active.remove(key)

    walk(thrown, owner, [], True, 0, None)
    return results


def catch_relation(graph, thrown, caught, *, null_pointer=False, nested=False,
                   thrown_owner=None, caught_owner=None):
    """Pinned generic Itanium matching: exact, public base, pointer/CV/null/member.

    Result is a normalized matching kind plus paths, not a host pointer adjustment.
    Virtual adjustment requires an admitted guest vptr/metadata recipe at runtime.
    """
    if caught is None:
        return {'kind': 'catch_all', 'paths': []}
    thrown_owner = thrown_owner or graph.module_id
    caught_owner = caught_owner or graph.module_id
    if graph.compatible(thrown, caught, thrown_owner, caught_owner, ignore_top_cv=True):
        return {'kind': 'exact', 'paths': []}
    tm, t = graph.resolve(thrown, thrown_owner)
    cm, c = graph.resolve(caught, caught_owner)
    if t['kind'] == 'scalar' and t['identity']['entity'] == 'nullptr_t' and c['kind'] in ('pointer', 'member_pointer'):
        return {'kind': 'nullptr', 'paths': []}
    if t['kind'] == c['kind'] == 'record':
        paths = public_base_paths(graph, thrown, caught, thrown_owner, caught_owner)
        if len(paths) == 1 and any(public for group in paths.values() for public, _, _ in group):
            return {'kind': 'base', 'paths': [path for group in paths.values() for public, path, _ in group if public]}
        return None
    if t['kind'] != c['kind'] or t['kind'] not in ('pointer', 'member_pointer'):
        return None
    if nested and not set(t['qualifiers']) <= set(c['qualifiers']):
        return None
    if t['kind'] == 'member_pointer':
        # No Derived->Base member-pointer conversion in exception matching.
        return {'kind': 'member_pointer', 'paths': []} if len(t['elements']) == len(c['elements']) == 2 and all(
            graph.compatible(a, b, tm, cm) for a, b in zip(t['elements'], c['elements'])) else None
    require(len(t['elements']) == len(c['elements']) == 1, 'ABI_CC_POINTER_TYPE')
    tp, cp = t['elements'][0], c['elements'][0]
    _, pt = graph.resolve(tp, tm)
    _, pc = graph.resolve(cp, cm)
    if not set(pt['qualifiers']) <= set(pc['qualifiers']):
        return None
    if pc['kind'] == 'void' and pt['kind'] != 'function' and not nested:
        return {'kind': 'pointer', 'paths': []}
    if pt['kind'] == pc['kind'] == 'function':
        if 'noexcept' not in pt['flags'] and 'noexcept' in pc['flags']:
            return None
        return {'kind': 'pointer', 'paths': []} if pt['extent'] == pc['extent'] and (
            'variadic' in pt['flags']) == ('variadic' in pc['flags']) and len(pt['elements']) == len(pc['elements']) and all(
            graph.compatible(a, b, tm, cm) for a, b in zip(pt['elements'], pc['elements'])) else None
    if pt['kind'] == pc['kind'] == 'record' and not nested:
        result = catch_relation(graph, tp, cp, null_pointer=null_pointer, thrown_owner=tm, caught_owner=cm)
        return None if result is None else {'kind': 'pointer', 'paths': result['paths']}
    if pt['kind'] in ('pointer', 'member_pointer') and pc['kind'] == pt['kind']:
        if 'const' not in pc['qualifiers']:
            return None
        return catch_relation(graph, tp, cp, null_pointer=null_pointer, nested=True,
                              thrown_owner=tm, caught_owner=cm)
    # Exact underlying leaf with added qualifiers; no arithmetic conversions.
    same = graph.compatible(tp, cp, tm, cm, ignore_top_cv=True)
    return {'kind': 'pointer', 'paths': []} if same else None


def verify_native(document, graph, tables, context):
    domains = tables['domains']
    require(sum(domain['isa'] == 'portable' for domain in domains.values()) == 1 and len(domains) <= 4096,
            'ABI_CC_DOMAIN_COUNT')
    foreign=[domain for domain in domains.values() if domain['isa']!='portable']
    require(len({domain['isa'] for domain in foreign})<=1,'ABI_CC_FOREIGN_ISA_SELECTION')
    require(len({domain['personality'] for domain in foreign})<=1,'ABI_CC_FOREIGN_PERSONALITY_SELECTION')
    for domain in domains.values():
        require(domain['isa'] in ('portable', 'x86_64', 'aarch64'), 'ABI_CC_FOREIGN_ISA')
        require(domain['abi'] in ('portable', 'itanium', 'microsoft'), 'ABI_CC_FOREIGN_ABI')
        if domain['isa'] == 'portable':
            require(domain['abi'] == 'portable' and domain['personality'] == 'portable', 'ABI_CC_FOREIGN_ABI')
        else:
            require(context.native_domains.get(domain['id'])==domain,'ABI_CC_NATIVE_DOMAIN_EVIDENCE')
        if domain['abi'] == 'itanium':
            require(domain['personality'] in ('linux','darwin','windows'), 'ABI_CC_FOREIGN_ABI')
        if domain['abi'] == 'microsoft':
            require(domain['personality'] == 'windows', 'ABI_CC_FOREIGN_ABI')
    for recipe in tables['recipes'].values():
        verify_adapter(recipe, graph, context, tables)
    for binding in tables['personalities'].values():
        require(binding['domain'] in domains and binding['flavor'] in
                ('logical_itanium', 'guest_itanium_dwarf', 'guest_itanium_darwin', 'guest_itanium_seh',
                 'guest_msvc_seh3', 'guest_msvc_seh4'),
                'ABI_CC_PERSONALITY_PROFILE')
        domain=domains[binding['domain']]
        if domain['isa']!='portable':
            require(context.native_personality({'module':{'kind':'self'},'id':binding['id']})==binding,
                    'ABI_CC_NATIVE_PERSONALITY_EVIDENCE')
            require(context.symbol(binding['entry']).get('native_cc')==NATIVE_CC.get((domain['isa'],domain['personality'])),
                    'ABI_CC_NATIVE_CC')
        expected_profile={'logical_itanium':('portable',{'portable'}),'guest_itanium_dwarf':('itanium',{'linux','darwin'}),
            'guest_itanium_darwin':('itanium',{'darwin'}),'guest_itanium_seh':('itanium',{'windows'}),
            'guest_msvc_seh3':('microsoft',{'windows'}),'guest_msvc_seh4':('microsoft',{'windows'})}[binding['flavor']]
        require(domain['abi']==expected_profile[0] and domain['personality'] in expected_profile[1],
                'ABI_CC_PERSONALITY_PROFILE')
        require(context.symbol(binding['entry'])['kind'] == 'function' and
                context.symbol(binding['entry'])['signature'] == binding['signature'] and
                context.symbol(binding['entry'])['domain'] == binding['domain'], 'ABI_CC_PERSONALITY_SIGNATURE')
        _, signature = graph.resolve(binding['signature'])
        require(signature['kind'] == 'function' and
                ('native' in signature['flags']) == (domains[binding['domain']]['isa'] != 'portable'),
                'ABI_CC_PERSONALITY_SIGNATURE')
        arguments = [graph.resolve(value)[1] for value in signature['elements'][:-1]]
        result = graph.resolve(signature['elements'][-1])[1]
        require(result['bits'] == 32, 'ABI_CC_PERSONALITY_SIGNATURE')
        if binding['flavor'].startswith('guest_msvc') or binding['flavor']=='guest_itanium_seh':
            require(len(arguments) == 4 and all(a['kind'] == 'pointer' and a['bits'] == 64 for a in arguments),
                    'ABI_CC_PERSONALITY_SIGNATURE')
        else:
            require(len(arguments) == 5 and [a['bits'] for a in arguments[:3]] == [32, 32, 64] and
                    all(a['kind'] == 'pointer' for a in arguments[3:]), 'ABI_CC_PERSONALITY_SIGNATURE')
        required={'search_readonly','cleanup_calls','forced_unwind'}
        require(len(set(binding['flags']))==len(binding['flags']) and required<=set(binding['flags'])<=
                required|{'cross_domain_translation'},
                'ABI_CC_PERSONALITY_PHASE')
    for unwind in tables['unwind'].values():
        require(unwind['domain'] in domains and unwind['personality'] in tables['personalities'],
                'ABI_CC_UNWIND_PERSONALITY')
        domain=domains[unwind['domain']]
        # CFI describes the foreign endpoint. Portable logical EH lives in
        # section8 and never selects a fallback native register namespace.
        require(domain['isa'] in ('x86_64', 'aarch64'), 'ABI_CC_CFI_PROFILE')
        require(unwind['source_format'] != 'logical', 'ABI_CC_CFI_PROFILE')
        require(tables['personalities'][unwind['personality']]['domain']==unwind['domain'],
                'ABI_CC_UNWIND_PERSONALITY')
        require(unwind['source_format'] in ('logical', 'dwarf_cfi_lsda', 'darwin_compact_dwarf',
                                           'windows_x64_unwind', 'windows_arm64_unwind'), 'ABI_CC_CFI_FORMAT')
        require(context.symbol(unwind['function']).get('code_size') == unwind['code_size'] > 0,
                'ABI_CC_CODE_EXTENT')
        require(context.symbol(unwind['function'])['domain']==unwind['domain'], 'ABI_CC_CODE_DOMAIN')
        allowed={'linux':{'dwarf_cfi_lsda'},
                 'darwin':{'dwarf_cfi_lsda','darwin_compact_dwarf'},
                 'windows':{'windows_x64_unwind' if domain['isa']=='x86_64' else 'windows_arm64_unwind'}}
        require(unwind['source_format'] in allowed.get(domain['personality'],set()), 'ABI_CC_CFI_PROFILE')
        if unwind['source_format'] != 'logical':
            require(unwind['metadata'], 'ABI_CC_MISSING_NATIVE_METADATA')
        for region in unwind['metadata']:
            data = context.metadata(region['symbol'])
            require(region['offset'] + region['bytes'] <= len(data) and region['bytes'] > 0,
                    'ABI_CC_METADATA_EXTENT')
            payload = data[region['offset']:region['offset'] + region['bytes']]
            require(hashlib.sha256(payload).hexdigest() == region['digest'], 'ABI_CC_METADATA_DIGEST')
        cursor = 0
        scalar = set(range(17 if domain['isa'] == 'x86_64' else 33))
        vector = set(range(17, 33)) if domain['isa'] == 'x86_64' else set(range(64, 96))
        pc = 16 if domain['isa'] == 'x86_64' else 32
        def recovery_rule(recovery, target):
            require(target in scalar | vector, 'ABI_CC_CFI_REGISTER')
            kind = recovery['kind']
            require(kind != 'expression', 'ABI_CC_CFI_EXPRESSION_UNSUPPORTED')
            if kind == 'register':
                source = recovery['reg']
                require((source in scalar and target in scalar) or
                        (source in vector and target in vector), 'ABI_CC_CFI_REGISTER_WIDTH')
            elif kind == 'cfa_offset':
                require(recovery['width'] in ((8, 16) if target in vector else (8,)),
                        'ABI_CC_CFI_WIDTH')
            elif kind == 'cfa_value':
                require(target in scalar, 'ABI_CC_CFI_REGISTER_WIDTH')
        for row in unwind['rows']:
            require(row['start'] == cursor < row['end'] <= unwind['code_size'], 'ABI_CC_CFI_COVERAGE')
            require(row['cfa']['base'] in ('sp', 'fp', 'register'), 'ABI_CC_CFA_RULE')
            require(row['cfa']['reg'] in scalar - {pc} if row['cfa']['base'] == 'register'
                    else row['cfa']['reg'] == 0, 'ABI_CC_CFA_REGISTER')
            registers = [rule['reg'] for rule in row['registers']]
            require(len(registers) == len(set(registers)), 'ABI_CC_CFI_REGISTER')
            recovery_rule(row['return_rule'], pc)
            for rule in row['registers']:
                recovery_rule(rule['rule'], rule['reg'])
            cursor = row['end']
        require(cursor == unwind['code_size'], 'ABI_CC_CFI_COVERAGE')
        actions = unique(unwind['actions'], 'UNWIND_ACTION')
        for action in actions.values():
            require(action['kind'] in ('cleanup', 'catch', 'terminate'), 'ABI_CC_UNWIND_ACTION')
            require(option(action['recipe']) is None or option(action['recipe']) in tables['recipes'], 'ABI_CC_ADAPTER_REFERENCE')
            require(option(action['catch']) is None or option(action['catch']) in tables['catches'], 'ABI_CC_CATCH_REFERENCE')
            seen, cursor = set(), action['id']
            while cursor is not None:
                require(cursor in actions and cursor not in seen, 'ABI_CC_UNWIND_ACTION_CYCLE')
                seen.add(cursor)
                cursor = option(actions[cursor]['next'])
        for region in unwind['regions']:
            require(0 <= region['start'] < region['end'] <= unwind['code_size'] and
                    set(region['actions']) <= actions.keys(), 'ABI_CC_PROTECTED_REGION')
            require(region['landing_offset'] < unwind['code_size'], 'ABI_CC_LANDING_PAD')
            require(region['landing_pad'] is None, 'ABI_CC_LANDING_PAD')
        if unwind['source_format'] != 'logical':
            require(context.native_unwind(unwind['function']) == unwind, 'ABI_CC_NATIVE_UNWIND_EVIDENCE')
    for mapping in tables['catches'].values():
        thrown, caught = option(mapping['thrown']), option(mapping['caught'])
        require(thrown is not None or mapping['kind'] == 'catch_all', 'ABI_CC_CATCH_TYPE')
        native_caught = option(mapping['native_caught'])
        if native_caught is not None:
            require(mapping['foreign_adapter'] is not None and caught is not None, 'ABI_CC_FOREIGN_CATCH_ADAPTER')
        relation = catch_relation(graph, thrown, native_caught if native_caught is not None else caught) if thrown is not None else {'kind': 'catch_all', 'paths': []}
        require(relation is not None and mapping['kind'] == relation['kind'], 'ABI_CC_CATCH_RELATION')
        require(not mapping['base_path'] or mapping['base_path'] in relation['paths'], 'ABI_CC_CATCH_PATH')
        require(mapping['mode'] in ('reference', 'value'), 'ABI_CC_CATCH_MODE')
        for name in ('copy', 'destroy', 'foreign_adapter'):
            require(option(mapping[name]) is None or option(mapping[name]) in tables['recipes'], 'ABI_CC_ADAPTER_REFERENCE')
        if mapping['mode'] == 'value' and caught is not None:
            typ = graph.resolve(caught)[1]
            require('trivial_copy' in typ['flags'] or mapping['copy'] is not None, 'ABI_CC_CATCH_COPY_RECIPE')
    for bridge in tables['bridges'].values():
        require(bridge['source'] in domains and bridge['target'] in domains and bridge['source'] != bridge['target'],
                'ABI_CC_BRIDGE_DOMAIN')
        require(domains[bridge['source']]['isa']=='portable' or domains[bridge['target']]['isa']=='portable',
                'ABI_CC_FOREIGN_BRIDGE_REQUIRES_PORTABLE')
        require(bridge['signature'] in tables['signatures'] and bridge['construction'] in tables['journals'] and
                bridge['arguments'] in tables['recipes'] and
                (bridge['result'] is None or option(bridge['result']) in tables['recipes']), 'ABI_CC_BRIDGE_BINDING')
        require(bridge['personality'] in tables['personalities'] and bridge['unwind'] in tables['unwind'],
                'ABI_CC_BRIDGE_UNWIND')
        if bridge['exceptions'] in ('mapped','opaque'):
            require('cross_domain_translation' in tables['personalities'][bridge['personality']]['flags'],
                    'ABI_CC_EXCEPTION_TRANSLATION')
        require(tables['unwind'][bridge['unwind']]['function']==bridge['entry'] and
                tables['unwind'][bridge['unwind']]['personality']==bridge['personality'], 'ABI_CC_BRIDGE_UNWIND')
        entry = context.symbol(bridge['entry'])
        _, source_signature = graph.resolve(entry['signature'])
        require(source_signature['kind'] == 'function' and 'native' in source_signature['flags'] and
                len(source_signature['elements']) == 2 and
                graph.resolve(source_signature['elements'][0])[1]['kind'] == 'pointer' and
                graph.resolve(source_signature['elements'][1])[1]['kind'] == 'void', 'ABI_CC_BRIDGE_SIGNATURE')
        pointer = graph.resolve(source_signature['elements'][0])[1]
        require(len(pointer['elements']) == 1, 'ABI_CC_BRIDGE_FRAME_TYPE')
        packet = graph.layout(pointer['elements'][0])
        require((packet['size'], packet['align']) == (80, 16) and
                [(field['offset_bits'], field['width_bits']) for field in packet['fields']] ==
                [(0,32),(32,32),(64,64),(128,64),(192,64),(256,64),(320,64),(384,64),(448,64),(512,32),(544,32),(576,64)],
                'ABI_CC_BRIDGE_FRAME_TYPE')
        target = domains[bridge['target']]
        native = target if target['isa'] != 'portable' else domains[bridge['source']]
        cc=entry.get('native_cc')
        require(cc==NATIVE_CC.get((native['isa'],native['personality'])),'ABI_CC_NATIVE_CC')
        require(entry['kind'] == 'function' and entry['domain'] == native['id'] and
                entry.get('bridge_abi') == PACKET_CC.get(cc),
                'ABI_CC_BRIDGE_ENTRY')
        require(bridge['callbacks'] in ('none', 'owner_thread', 'attached_thread') and
                bridge['exceptions'] in ('noexcept', 'opaque', 'mapped') and
                bridge['ownership'] in ('borrowed', 'owned', 'shared') and
                bridge['identity'] in ('preserve', 'proxy') and bridge['aliases'] in ('shared', 'exclusive', 'none'),
                'ABI_CC_BRIDGE_POLICY')
        require(bridge['identity'] != 'proxy' or bridge['aliases'] != 'shared', 'ABI_CC_UNREPRESENTABLE_ALIAS')
