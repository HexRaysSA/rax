"""Whole-definition transaction over admitted runtime roots (R032).

Callers supply actual graph comparators and comparison projections, never hashes
read from producer metadata. This plan grants no executable or address authority.
"""
from dataclasses import dataclass
import hashlib

from .comdat import canonical, function_body, select
from .errors import option, require, unique
from .linking import family


def ref(identity):
    return {'module': {'kind': 'self'}, 'id': identity}


def name(symbol):
    return symbol['namespace'], symbol['name'], symbol['kind'], symbol['source_linkage']


@dataclass
class Plan:
    # Every defined qualified symbol/function has one winning target or None.
    symbols: dict
    functions: dict
    kept_groups: tuple
    discarded_groups: tuple
    common: dict
    initializers: dict
    finalizers: dict
    owners: frozenset

    def symbol(self, artifact, identity):
        key = artifact, identity
        require(key in self.symbols and self.symbols[key] is not None,
                'RT_SELECTION_DISCARDED_MEMBER')
        return self.symbols[key]

    def function(self, artifact, identity):
        key = artifact, identity
        require(key in self.functions and self.functions[key] is not None,
                'RT_SELECTION_DISCARDED_FUNCTION')
        return self.functions[key]


def select_definitions(modules, contexts, order, execution_equal, nominal_compatible,
                       data_compatible=None, prior=None, signature_compatible=None):
    """O(N^2 + B), O(N+B); deterministic explicit order, no partial publication.

    modules: artifact -> six already-admitted runtime roots; contexts same keys.
    comparisons have (left_artifact,left_ref,right_artifact,right_ref) signatures.
    Context.symbol_body(self_ref) must project the actual admitted definition to
    llvm-comparison-v1 (functions) or canonical bytes (data/TLS). Projections may
    reject unsupported constructs, which rejects this complete transaction.
    prior optionally maps group scope keys to a retained winning (artifact,id);
    its actual roots/contexts must remain in modules. No live winner is replaced.
    """
    require(len(order) == len(set(order)) and set(order) == set(modules) == set(contexts),
            'RT_SELECTION_MODULE_SET')
    tables = {a: unique(modules[a][2]['symbols'], 'id') for a in order}
    all_symbols = {(a, s['id']): s for a in order for s in tables[a].values()}
    redirects = {key: key for key, s in all_symbols.items() if option(s['definition']) is not None}
    fn_members = {}
    for key, symbol in all_symbols.items():
        definition = option(symbol['definition'])
        if definition and definition['kind'] == 'function':
            target = key[0], definition['target']['id']
            fn_members.setdefault(target, []).append(key)
    groups, groups_by_key, member_group = {}, {}, {}
    ordinal = 0
    for artifact in order:
        for group in modules[artifact][2]['comdats']:
            key = artifact, group['id']
            members = [(artifact, i) for i in group['members']]
            require(members and all(k in all_symbols and k not in member_group for k in members),
                    'RT_SELECTION_GROUP')
            exposed = [k for k in members if all_symbols[k]['binding'] != 'local']
            if not exposed:exposed = [(artifact, group['key_symbol'])]
            scopes = {('public',) if all_symbols[k]['visibility'] == 'default' else
                      ('family', *family(modules[artifact][2]['manifest']['key'])) for k in exposed}
            require(len(scopes) == 1, 'RT_COMDAT_MIXED_SCOPE')
            scope = next(iter(scopes)) + (group['namespace'], group['name'])
            record = {'artifact': artifact, 'group': group, 'members': members, 'ordinal': ordinal}
            ordinal += 1
            groups[key] = record
            groups_by_key.setdefault(scope, []).append(record)
            for k in members:
                require(option(all_symbols[k]['definition']) is not None and
                        option(all_symbols[k]['definition'])['kind'] != 'native', 'RT_COMDAT_DEFINITION')
                member_group[k] = key
    # A body cannot simultaneously belong to independently selected groups.
    for members in fn_members.values():
        memberships = {member_group.get(k) for k in members}
        require(len(memberships) == 1, 'RT_COMDAT_SHARED_FUNCTION')

    def compatible(left, right):
        a, b = all_symbols[left], all_symbols[right]
        require(name(a) == name(b) and a['visibility'] == b['visibility'], 'RT_SELECTION_IDENTITY')
        untyped_common = (a['nominal'] is None and b['nominal'] is None and a['kind'] == b['kind'] == 'data' and
                          (option(a['definition'])['kind'] == option(b['definition'])['kind'] == 'common' or
                           left in member_group and right in member_group))
        require(untyped_common or execution_equal(left[0], a['execution'], right[0], b['execution']),
                'RT_SELECTION_EXECUTION')
        x, y = option(a['nominal']), option(b['nominal'])
        require((x is None) == (y is None), 'RT_SELECTION_SOURCE_PRESENCE')
        if x is not None:
            compare = data_compatible if a['kind'] in {'data', 'tls'} and a['source_linkage'] == 'c' else nominal_compatible
            require(compare is not None and compare(left[0], x, right[0], y), 'RT_SELECTION_SOURCE')
        x,y=option(a['abi_signature']),option(b['abi_signature'])
        require((x is None)==(y is None),'RT_SELECTION_SOURCE_PLAN_PRESENCE')
        if x is not None:
            require(signature_compatible is not None,'RT_SELECTION_ABI_COMPARATOR')
            require(signature_compatible(left[0],x,right[0],y),'RT_SELECTION_SOURCE_PLAN')
        require(a['alignment'] == b['alignment'] or untyped_common, 'RT_SELECTION_ALIGNMENT')

    def projected(key):
        body = contexts[key[0]].symbol_body(ref(key[1]))
        if type(body) is dict:
            require(all_symbols[key]['kind'] == 'function', 'RT_COMDAT_BODY')
            return function_body(body)
        require(type(body) is bytes, 'RT_COMDAT_BODY')
        return body

    kept, discarded, owners = [], [], set()
    for scope, candidates in groups_by_key.items():
        representatives, normalized, origins, bodies = {}, [], {}, {}
        for candidate in candidates:
            rows, row_names = [], {}
            for key in candidate['members']:
                symbol = all_symbols[key]
                identity = name(symbol)
                require(identity not in row_names, 'RT_COMDAT_MEMBER_IDENTITY')
                row_names[identity] = key
                if identity in representatives:
                    compatible(representatives[identity], key)
                else:
                    representatives[identity] = key
                # This is an internal equivalence-class index AFTER graph checks.
                witness = hashlib.sha256(canonical(list(identity))).hexdigest()
                body = projected(key)
                bodies[key] = body
                label = canonical(list(identity)).decode('utf8')
                definition = option(symbol['definition'])
                size = len(body) if symbol['kind'] == 'function' else option(symbol['size'])
                require(type(size) is int, 'RT_COMDAT_EXTENT')
                rows.append({'symbol': label, 'abi': witness, 'kind': symbol['kind'],
                             'extent': size, 'body': body, 'extent_policy':
                             'selected_definition' if definition['kind'] == 'common' or
                             symbol['kind'] in {'data', 'tls'} and symbol['nominal'] is None else 'fixed'})
            group = candidate['group']
            key_label = canonical(list(name(tables[candidate['artifact']][group['key_symbol']]))).decode('utf8')
            normalized.append({'key': repr(scope), 'selection': group['selection'], 'key_symbol': key_label,
                               'members': rows, 'input_ordinal': candidate['ordinal']})
            origins[candidate['ordinal']] = candidate, row_names
        winners = select(normalized)
        if prior and scope in prior:
            previous = prior[scope]
            require(previous in groups, 'RT_COMDAT_PRIOR_OWNER')
            prior_candidate = groups[previous]
            require(prior_candidate in candidates, 'RT_COMDAT_PRIOR_SCOPE')
            previous_ordinal = prior_candidate['ordinal']
            selections = {c['group']['selection'] for c in candidates}
            if selections <= {'any'} or selections <= {'exactmatch'}:
                winners = [previous_ordinal]
            elif selections == {'nodeduplicate'}:
                require(previous_ordinal in winners, 'RT_COMDAT_LIVE_REPLACEMENT')
            else:
                require(winners == [previous_ordinal], 'RT_COMDAT_LIVE_REPLACEMENT')
        for candidate in candidates:
            group_key = candidate['artifact'], candidate['group']['id']
            if candidate['ordinal'] in winners:
                kept.append(group_key)
                owners.add(candidate['artifact'])
                continue
            discarded.append(group_key)
            winning_members = origins[winners[0]][1]
            for key in candidate['members']:
                # Missing loser-only members remain explicit rejection sentinels.
                redirects[key] = winning_members.get(name(all_symbols[key]))

    # Resolve ordinary definitions after whole-group discard, scoped by family.
    ordinary = {}
    for key, symbol in all_symbols.items():
        if key not in redirects or redirects[key] != key or symbol['binding'] == 'local':
            continue
        scope = (*family(modules[key[0]][2]['manifest']['key']), *name(symbol))
        ordinary.setdefault(scope, []).append(key)
    common = {}
    for candidates in ordinary.values():
        baseline = candidates[0]
        for key in candidates[1:]:compatible(baseline, key)
        strong = [k for k in candidates if all_symbols[k]['binding'] == 'strong']
        commons = [k for k in candidates if all_symbols[k]['binding'] == 'common']
        weak = [k for k in candidates if all_symbols[k]['binding'] in {'weak', 'external_weak'}]
        require(len(strong) <= 1, 'RT_SELECTION_MULTIPLE_STRONG')
        require(strong or commons or weak, 'RT_SELECTION_BINDING')
        winner = (strong or commons or weak)[0]
        if not strong and commons:
            size = max(option(all_symbols[k]['definition'])['size'] for k in commons)
            align = max(option(all_symbols[k]['definition'])['alignment'] for k in commons)
            common[winner] = {'size': size, 'alignment': align}
        for key in candidates:redirects[key] = winner
        owners.add(winner[0])

    for key, symbol in all_symbols.items():
        definition = option(symbol['definition'])
        if redirects.get(key) == key and definition['kind'] == 'alias':
            target = key[0], definition['target']['id']
            require(target in redirects, 'RT_SELECTION_ALIAS_UNRESOLVED')
            redirects[key] = target

    def final(key):
        seen = set()
        while key is not None and redirects.get(key, key) != key:
            require(key not in seen, 'RT_SELECTION_REDIRECT_CYCLE')
            seen.add(key)
            key = redirects[key]
        return key

    redirects = {key: final(target) for key, target in redirects.items()}
    functions = {}
    for target, members in fn_members.items():
        destinations = set()
        for key in members:
            winner = redirects[key]
            if winner is None:
                destinations.add(None)
                continue
            definition = option(all_symbols[winner]['definition'])
            require(definition['kind'] == 'function', 'RT_SELECTION_FUNCTION_TARGET')
            destinations.add((winner[0], definition['target']['id']))
        require(len(destinations) == 1, 'RT_SELECTION_FUNCTION_REDIRECT_CONFLICT')
        functions[target] = next(iter(destinations))
    # Non-symbol source functions are still callable and retain their owner.
    for artifact in order:
        for list_name in ['initializers', 'finalizers']:
            for hook in modules[artifact][2][list_name]:
                functions.setdefault((artifact, hook['function']['id']), (artifact, hook['function']['id']))
    hooks = {}
    for list_name in ['initializers', 'finalizers']:
        hooks[list_name] = {}
        for artifact in order:
            selected = []
            for hook in modules[artifact][2][list_name]:
                association = option(hook['association'])
                if association is not None:
                    target = artifact, association['id']
                    if redirects.get(target) != target:continue
                target = (artifact, hook['function']['id'])
                require(functions.get(target, target) is not None, 'RT_SELECTION_HOOK_DISCARDED')
                selected.append(hook)
            hooks[list_name][artifact] = tuple(selected)
    return Plan(redirects, functions, tuple(kept), tuple(discarded), common,
                hooks['initializers'], hooks['finalizers'], frozenset(owners))
