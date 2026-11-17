"""Deterministic draft link validation/resolution and checked relocation algebra."""
import hashlib

from schema import alignment, require, unique_by, unique_list, validate


def storage_size(record):
    size = len(record['bytes']) // 2 + record['zero_fill']
    require(size < 2**64, 'STORAGE_OVERFLOW')
    return size


def verify_link(bundle):
    validate(bundle, 'link')
    module = bundle['module']
    types = module['type_ids']
    unique_list(types, 'DUPLICATE_TYPE')
    functions = unique_by(module['functions'], 'id', 'DUPLICATE_FUNCTION')
    for function in functions.values():
        require(function['signature'] in types, 'FUNCTION_TYPE')
    symbols = unique_by(bundle['symbols'], 'id', 'DUPLICATE_SYMBOL')
    data = unique_by(bundle['data'], 'id', 'DUPLICATE_DATA')
    tls = unique_by(bundle['tls'], 'id', 'DUPLICATE_TLS')
    imports = unique_by(bundle['imports'], 'id', 'DUPLICATE_IMPORT')
    unique_list(bundle['capabilities'], 'DUPLICATE_CAPABILITY')
    unique_by(bundle['dependencies'], 'identity', 'DUPLICATE_DEPENDENCY')
    require(module['identity'] not in [d['identity'] for d in bundle['dependencies']],
            'SELF_DEPENDENCY')
    for record in [*data.values(), *tls.values()]:
        require(alignment(record['alignment']), 'STORAGE_ALIGNMENT')
        storage_size(record)
    for record in tls.values():
        require(record['destructor'] is None or record['destructor'] in functions,
                'TLS_DESTRUCTOR')
    names = set()
    definitions = {'data': data, 'tls': tls, 'function': functions, 'import': imports}
    for symbol in symbols.values():
        key = (symbol['namespace'], symbol['name'], symbol['type'])
        require(key not in names, 'DUPLICATE_SYMBOL_IDENTITY')
        names.add(key)
        require(symbol['type'] in types, 'SYMBOL_TYPE')
        require(alignment(symbol['alignment']), 'SYMBOL_ALIGNMENT')
        definition = symbol['definition']
        require(not (symbol['binding'] == 'local' and definition is None),
                'LOCAL_UNDEFINED')
        require(symbol['comdat'] is None or definition is not None, 'COMDAT_UNDEFINED')
        if symbol['comdat'] is not None:
            require(len(symbol['comdat']) == 64 and
                    all(c in '0123456789abcdef' for c in symbol['comdat']), 'COMDAT_IDENTITY')
        if definition is None:
            continue
        table = definitions[symbol['kind']]
        require(definition in table, 'SYMBOL_DEFINITION')
        record = table[definition]
        if symbol['kind'] in {'data', 'tls'}:
            require(symbol['size'] == storage_size(record), 'SYMBOL_SIZE')
            require(symbol['alignment'] == record['alignment'], 'SYMBOL_STORAGE_ALIGNMENT')
        else:
            require(symbol['size'] == 0 and symbol['alignment'] == 1, 'TOKEN_LAYOUT')
            require(symbol['type'] == record['signature'], 'SYMBOL_SIGNATURE')
    for imp in imports.values():
        require(imp['signature'] in types, 'IMPORT_TYPE')
        require(imp['capability'] in bundle['capabilities'], 'IMPORT_CAPABILITY')
        if imp['namespace'] == 'smir.portable.v1':
            from catalog import verify_import
            verify_import(imp)
        else:
            expected = f"smir.{module['personality']}.v1"
            require(imp['namespace'] in {expected, 'smir.foreign.v1'}, 'IMPORT_NAMESPACE')
            require(imp['namespace'] != 'smir.foreign.v1' or module['foreign_isa'] != 'none',
                    'FOREIGN_ISA_REQUIRED')
            # Actual registry descriptor/signature matching is an admission prerequisite.
        unique_list([(b['pointer_param'], b['length_param']) for b in imp['buffers']],
                    'DUPLICATE_BUFFER')
    patches = {}
    for reloc in bundle['relocations']:
        source = {'data': data, 'tls': tls}[reloc['source_kind']]
        require(reloc['source'] in source, 'RELOCATION_SOURCE')
        width = {'u32': 4, 'u64': 8}[reloc['width']]
        start = reloc['offset']
        require(start + width <= storage_size(source[reloc['source']]), 'RELOCATION_BOUNDS')
        intervals = patches.setdefault((reloc['source_kind'], reloc['source']), [])
        require(all(start + width <= a or b <= start for a, b in intervals),
                'RELOCATION_OVERLAP')
        intervals.append((start, start + width))
        require(reloc['target'] in symbols, 'RELOCATION_TARGET')
        target = symbols[reloc['target']]
        domain = {'data_address': 'data', 'tls_offset': 'tls',
                  'function_token': 'function', 'import_token': 'import'}[reloc['kind']]
        require(target['kind'] == domain, 'RELOCATION_DOMAIN')
        if domain in {'function', 'import'}:
            require(reloc['width'] == 'u64' and reloc['addend'] == 0, 'TOKEN_RELOCATION')
        elif domain == 'data':
            require(reloc['width'] == 'u64', 'DATA_POINTER_WIDTH')
        if module['kind'] == 'image':
            require(target['definition'] is not None, 'IMAGE_UNRESOLVED')
    for records in (bundle['init'], bundle['fini']):
        unique_list([r['ordinal'] for r in records], 'DUPLICATE_INIT_ORDINAL')
        for record in records:
            require(record['function'] in functions, 'INIT_FUNCTION')
    if module['kind'] == 'image':
        require(all(s['definition'] is not None for s in symbols.values()), 'IMAGE_UNRESOLVED')
    return bundle


def relocate(base, addend, width, target_size=None):
    """Checked mathematical relocation, with no truncation or host pointer use."""
    require(type(base) is int and 0 <= base < 2**64, 'RELOCATION_BASE')
    require(type(addend) is int and -2**63 <= addend < 2**63, 'RELOCATION_ADDEND')
    require(width in {4, 8}, 'RELOCATION_WIDTH')
    if target_size is not None:
        require(0 <= addend <= target_size, 'RELOCATION_TARGET_BOUNDS')
    value = base + addend
    require(0 <= value < 2**(8 * width), 'RELOCATION_OVERFLOW')
    return value.to_bytes(width, 'little')


def resolve(bundles, type_identities=None, comdat_contents=None):
    """First-input weak selection; O(symbols), excluding validation costs.

    Exact ABI type equivalence must already be established across modules.
    Equal local type integers alone do not establish that equivalence.
    """
    require(type_identities is not None, 'SIGNATURE_IDENTITY_REQUIRED')
    selected = {}
    groups = {}
    discarded = set()
    unique_list([b['module']['identity'] for b in bundles], 'DUPLICATE_MODULE')
    for bundle in bundles:
        verify_link(bundle)
        identity = bundle['module']['identity']
        module_groups = {}
        for symbol in bundle['symbols']:
            if symbol['comdat'] is not None:
                module_groups.setdefault(symbol['comdat'], []).append(symbol)
        for group, members in module_groups.items():
            require(comdat_contents is not None and (identity, group) in comdat_contents,
                    'COMDAT_CONTENT_REQUIRED')
            content = comdat_contents[identity, group]
            require(type(content) is bytes and hashlib.sha256(content).hexdigest() == group,
                    'COMDAT_CONTENT_HASH')
            summary = []
            for member in members:
                type_key = (identity, member['type'])
                require(type_key in type_identities, 'SIGNATURE_IDENTITY_REQUIRED')
                summary.append((member['namespace'], member['name'], type_identities[type_key],
                                member['kind'], member['size'], member['alignment'],
                                member['binding'], member['visibility']))
            summary.sort()
            if group in groups:
                require(groups[group][1] == summary, 'COMDAT_MEMBERS')
                require(groups[group][2] == content, 'COMDAT_CONTENT_MISMATCH')
                discarded.add((identity, group))
            else:
                groups[group] = (identity, summary, content)
        for symbol in bundle['symbols']:
            if (identity, symbol['comdat']) in discarded:
                continue
            if symbol['binding'] == 'local' or symbol['visibility'] == 'hidden':
                continue
            if symbol['definition'] is None:
                continue
            type_key = (bundle['module']['identity'], symbol['type'])
            require(type_key in type_identities, 'SIGNATURE_IDENTITY_REQUIRED')
            signature = type_identities[type_key]
            require(type(signature) is str and len(signature) == 64 and
                    all(c in '0123456789abcdef' for c in signature), 'SIGNATURE_IDENTITY')
            key = (symbol['namespace'], symbol['name'], signature)
            current = selected.get(key)
            candidate = (bundle['module']['identity'], symbol)
            if current is None:
                selected[key] = candidate
                continue
            previous = current[1]
            require((previous['kind'], previous['size'], previous['alignment']) ==
                    (symbol['kind'], symbol['size'], symbol['alignment']), 'SYMBOL_LAYOUT_MISMATCH')
            require(previous['comdat'] is None and symbol['comdat'] is None,
                    'COMDAT_SYMBOL_COLLISION')
            require(not (previous['binding'] == symbol['binding'] == 'strong'),
                    'DUPLICATE_STRONG')
            if previous['binding'] == 'weak' and symbol['binding'] == 'strong':
                selected[key] = candidate
    return selected


def initialization_order(bundles):
    """Stable iterative dependency DFS; O(modules + edges + initializers log N)."""
    by_id = {b['module']['identity']: b for b in bundles}
    require(len(by_id) == len(bundles), 'DUPLICATE_MODULE')
    require(len(by_id) <= 65536, 'MODULE_LIMIT')
    visiting = set()
    visited = set()
    result = []
    for root in by_id:
        if root in visited:
            continue
        stack = [(root, 0)]
        while stack:
            identity, edge_index = stack[-1]
            require(identity in by_id, 'MISSING_DEPENDENCY')
            visiting.add(identity)
            bundle = by_id[identity]
            dependencies = bundle['dependencies']
            if edge_index < len(dependencies):
                dependency = dependencies[edge_index]['identity']
                stack[-1] = (identity, edge_index + 1)
                require(dependency not in visiting, 'DEPENDENCY_CYCLE')
                if dependency not in visited:
                    stack.append((dependency, 0))
                continue
            stack.pop()
            visiting.remove(identity)
            visited.add(identity)
            for initializer in sorted(bundle['init'],
                                      key=lambda r: (r['priority'], r['ordinal'])):
                result.append((identity, initializer['function']))
    return result


def admit_code_token(token):
    require(type(token) is int and 0 < token < 2**64 and token % 2 == 0,
            'CODE_TOKEN')
    return token


def apply_relocations(bundle, bindings, code_registry, module_generations,
                      type_identities, max_storage_bytes=16 * 1024 * 1024):
    """Stage all patches before publication; input binding values are guest domains.

    bindings[symbol_id] contains value/module/generation from admitted mapping or
    token lookup. No storage is returned on any failure. O(patches + storage)
    after verify_link, whose overlap checks are quadratic per source.
    """
    verify_link(bundle)
    symbols = {s['id']: s for s in bundle['symbols']}
    sources = {('data', d['id']): d for d in bundle['data']}
    sources.update({('tls', t['id']): t for t in bundle['tls']})
    require(sum(storage_size(s) for s in sources.values()) <= max_storage_bytes,
            'STORAGE_LIMIT')
    patches = []
    for record in bundle['relocations']:
        target = symbols[record['target']]
        require(target['id'] in bindings, 'BINDING_MISSING')
        binding = bindings[target['id']]
        require(module_generations.get(binding['module']) == binding['generation'],
                'BINDING_STALE')
        value = binding['value']
        width = {'u32': 4, 'u64': 8}[record['width']]
        if record['kind'] in {'function_token', 'import_token'}:
            admit_code_token(value)
            signature_key = (bundle['module']['identity'], target['type'])
            require(signature_key in type_identities, 'SIGNATURE_IDENTITY_REQUIRED')
            code_entry = code_registry.lookup(value, module_generations,
                                              type_identities[signature_key])
            require(code_entry[0] == binding['module'] and code_entry[1] == binding['generation'],
                    'CODE_BINDING_IDENTITY')
            expected_kind = 'function' if record['kind'] == 'function_token' else 'import'
            require(code_entry[3] == expected_kind, 'CODE_BINDING_KIND')
            encoded = relocate(value, record['addend'], width)
        else:
            encoded = relocate(value, record['addend'], width, target['size'])
            if record['kind'] == 'data_address':
                require(value != 0, 'NULL_DATA_BINDING')
        patches.append(((record['source_kind'], record['source']), record['offset'], encoded))
    storage = {key: bytearray.fromhex(source['bytes']) + bytearray(source['zero_fill'])
               for key, source in sources.items()}
    for source, offset, encoded in patches:
        storage[source][offset:offset + len(encoded)] = encoded
    return {key: bytes(value) for key, value in storage.items()}
