#!/usr/bin/env python3
"""Validate draft foreign descriptors against separately admitted build evidence.

This model never loads code. Evidence must come from the loader/compiler pipeline;
a descriptor cannot certify its own compiler identity or object layout.
"""

import hashlib
import json
from pathlib import Path
import re
import sys

from layout import ABIError, MAX_OBJECT, alignment, integer, keys, require
from contract_json import check_named, loads


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'ABI_DIGEST')
    return value


def identity(value):
    require(isinstance(value, str) and 0 < len(value) <= 1024, 'ABI_IDENTITY')
    return value


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(',', ':')).encode('ascii')).hexdigest()


def indexed(records):
    require(isinstance(records, list) and len(records) <= 4096, 'ABI_LIMIT')
    result = {}
    for record in records:
        require(isinstance(record, dict), 'ABI_SHAPE')
        name = identity(record.get('id'))
        require(name not in result, 'ABI_DUPLICATE_ID')
        result[name] = record
    return result


def validate(document, evidence):
    """O(records + fields + edges), space O(records + edges), excluding JSON parse.

    Evidence's domain/type/symbol maps are inputs admitted independently by a
    future loader. Synthetic fixtures test contract enforcement, not real binary
    metadata extraction. An absent certificate rejects before any call or copy.
    """
    try:
        check_named(document, 'descriptor.schema.json')
    except ValueError as error:
        raise ABIError(str(error)) from error
    keys(document, ('revision', 'domains', 'types', 'mappings', 'calls'))
    require(document['revision'] == 'abi-descriptor-draft-v1', 'ABI_REVISION')
    keys(evidence, ('domains', 'types', 'symbols'))
    require(all(isinstance(evidence[key], dict) for key in evidence), 'ABI_EVIDENCE')
    domains = indexed(document['domains'])
    types = indexed(document['types'])
    mappings = indexed(document['mappings'])
    calls = indexed(document['calls'])
    require(1 <= len(domains) <= 2, 'ABI_DOMAIN_COUNT')
    portable = 0
    for name, domain in domains.items():
        keys(domain, ('id', 'isa', 'personality', 'abi', 'compiler', 'runtime',
                      'build', 'unwind'))
        for key in ('compiler', 'runtime', 'build'):
            digest(domain[key])
        if domain['isa'] == 'portable':
            portable += 1
            require(domain['abi'] == 'portable' and domain['unwind'] == 'logical',
                    'ABI_DOMAIN_PROFILE')
        else:
            require(domain['isa'] in ('x86_64', 'aarch64'), 'ABI_FOREIGN_ISA')
            require(domain['abi'] in ('itanium', 'microsoft'), 'ABI_DOMAIN_PROFILE')
            require(domain['personality'] in ('linux', 'darwin', 'windows'),
                    'ABI_DOMAIN_PROFILE')
            if domain['abi'] == 'microsoft':
                require(domain['personality'] == 'windows' and domain['unwind'] == 'seh',
                        'ABI_DOMAIN_PROFILE')
            else:
                require(domain['unwind'] in ('dwarf', 'darwin'), 'ABI_DOMAIN_PROFILE')
                require(domain['unwind'] != 'darwin' or domain['personality'] == 'darwin',
                        'ABI_DOMAIN_PROFILE')
        require(domain == evidence['domains'].get(name), 'ABI_BUILD_EVIDENCE')
    require(portable == 1, 'ABI_DOMAIN_COUNT')

    token_bindings = {}

    def symbol(name, domain, role):
        require(isinstance(name, str), 'ABI_MISSING_METADATA')
        record = evidence['symbols'].get(name)
        require(isinstance(record, dict) and record.get('domain') == domain and
                record.get('role') == role, 'ABI_SYMBOL_EVIDENCE')
        token = integer(record.get('token'), 2, (1 << 64) - 2)
        require(token % 2 == 0, 'ABI_CODE_TOKEN')
        binding = (domain, role, record.get('signature'))
        require(token not in token_bindings or token_bindings[token] == binding,
                'ABI_TOKEN_IDENTITY')
        token_bindings[token] = binding

    for name, record in types.items():
        keys(record, ('id', 'domain', 'identity', 'library', 'layout', 'trivial',
                      'ownership', 'destructor', 'copy', 'move', 'allocator',
                      'deallocator', 'retain', 'release'))
        require(record['domain'] in domains, 'ABI_UNKNOWN_DOMAIN')
        identity(record['identity'])
        if record['library'] is not None:
            digest(record['library'])
        require(type(record['trivial']) is bool, 'ABI_SHAPE')
        require(record['ownership'] in ('borrowed', 'owned', 'shared'), 'ABI_OWNERSHIP')
        layout = record['layout']
        keys(layout, ('size', 'align', 'fields', 'bases', 'vptrs', 'rtti'))
        size = integer(layout['size'], 1, MAX_OBJECT)
        align = alignment(layout['align'])
        require(size % align == 0, 'ABI_LAYOUT_EXTENT')
        require(isinstance(layout['fields'], list) and isinstance(layout['bases'], list)
                and isinstance(layout['vptrs'], list), 'ABI_SHAPE')
        for field in layout['fields']:
            keys(field, ('name', 'type_identity', 'offset_bits', 'width_bits'))
            identity(field['name'])
            identity(field['type_identity'])
            start = integer(field['offset_bits'], 0, size * 8)
            width = integer(field['width_bits'], 1, size * 8, 'ABI_LAYOUT_EXTENT')
            require(start + width <= size * 8, 'ABI_LAYOUT_EXTENT')
        for base in layout['bases']:
            keys(base, ('type_identity', 'offset_bytes', 'virtual', 'public'))
            identity(base['type_identity'])
            integer(base['offset_bytes'], 0, size - 1)
            require(type(base['virtual']) is bool and type(base['public']) is bool,
                    'ABI_SHAPE')
        for vptr in layout['vptrs']:
            keys(vptr, ('offset_bytes', 'slots'))
            integer(vptr['offset_bytes'], 0, size - 1)
            require(vptr['offset_bytes'] % 8 == 0 and vptr['offset_bytes'] + 8 <= size,
                    'ABI_VPTR')
            require(isinstance(vptr['slots'], list), 'ABI_SHAPE')
            for slot in vptr['slots']:
                symbol(slot, record['domain'], 'method')
        if layout['rtti'] is not None:
            digest(layout['rtti'])
        require(record == evidence['types'].get(name), 'ABI_TYPE_EVIDENCE')
        if not record['trivial']:
            symbol(record['destructor'], record['domain'], 'destroy')
        if record['ownership'] in ('owned', 'shared'):
            symbol(record['allocator'], record['domain'], 'allocate')
            symbol(record['deallocator'], record['domain'], 'deallocate')
        if record['copy'] is not None:
            symbol(record['copy'], record['domain'], 'copy')
        if record['move'] is not None:
            symbol(record['move'], record['domain'], 'move')
        if record['ownership'] == 'shared':
            symbol(record['retain'], record['domain'], 'retain')
            symbol(record['release'], record['domain'], 'release')

    for mapping in mappings.values():
        keys(mapping, ('id', 'source', 'target', 'mode', 'lifetime', 'alias',
                       'identity', 'adapter', 'typed_catch'))
        require(mapping['source'] in types and mapping['target'] in types,
                'ABI_UNKNOWN_TYPE')
        source, target = types[mapping['source']], types[mapping['target']]
        require(source['domain'] != target['domain'], 'ABI_MAPPING_DOMAIN')
        require(mapping['mode'] in ('share', 'adapt', 'opaque'), 'ABI_MAPPING_MODE')
        require(mapping['lifetime'] in ('call', 'object', 'shared'), 'ABI_LIFETIME')
        require(mapping['alias'] in ('shared', 'exclusive', 'none'), 'ABI_ALIAS')
        require(mapping['identity'] in ('preserve', 'proxy'), 'ABI_OBJECT_IDENTITY')
        require(type(mapping['typed_catch']) is bool, 'ABI_SHAPE')
        if mapping['mode'] == 'share':
            require(source['layout'] == target['layout'] and
                    source['trivial'] == target['trivial'] and
                    source['ownership'] == target['ownership'] and
                    source['library'] == target['library'], 'ABI_LAYOUT_MISMATCH')
            # Vtable/RTTI pointers cannot be shared across ABI domains even if
            # object member offsets happen to match.
            require(not source['layout']['vptrs'] and source['layout']['rtti'] is None,
                    'ABI_POLYMORPHIC_SHARING')
            require(mapping['identity'] == 'preserve' and mapping['adapter'] is None,
                    'ABI_OBJECT_IDENTITY')
            require(mapping['alias'] in ('shared', 'exclusive'), 'ABI_ALIAS')
        else:
            require(mapping['identity'] == 'proxy' and mapping['alias'] != 'shared',
                    'ABI_UNREPRESENTABLE_ALIAS')
            symbol(mapping['adapter'], target['domain'], 'adapter')
        if mapping['typed_catch']:
            require(source['layout']['rtti'] is not None and
                    target['layout']['rtti'] is not None and mapping['adapter'] is not None,
                    'ABI_EXCEPTION_TYPE_MAPPING')

    for call in calls.values():
        keys(call, ('id', 'source_domain', 'target_domain', 'bridge', 'params',
                    'result', 'variadic', 'callback', 'exceptions', 'mappings'))
        require(call['source_domain'] in domains and call['target_domain'] in domains and
                call['source_domain'] != call['target_domain'], 'ABI_CALL_DOMAIN')
        symbol(call['bridge'], call['target_domain'], 'bridge')
        require(isinstance(call['params'], list), 'ABI_SHAPE')
        for name in call['params']:
            require(name in types and types[name]['domain'] == call['target_domain'],
                    'ABI_CALL_TYPE')
            require(types[name]['trivial'] or types[name]['copy'] is not None or
                    types[name]['move'] is not None, 'ABI_NONTRIVIAL_COPY_METADATA')
        require(call['result'] is None or call['result'] in types and
                types[call['result']]['domain'] == call['target_domain'], 'ABI_CALL_TYPE')
        require(call['variadic'] in ('none', 'typed-pack'), 'ABI_VARARGS_ADAPTER')
        require(call['callback'] in ('none', 'owner-thread', 'attached-thread'),
                'ABI_CALLBACK_THREAD')
        require(call['exceptions'] in ('noexcept', 'opaque', 'mapped'), 'ABI_EXCEPTION_POLICY')
        require(isinstance(call['mappings'], list), 'ABI_SHAPE')
        require(all(name in mappings for name in call['mappings']), 'ABI_UNKNOWN_MAPPING')
        mapped_targets = set()
        for name in call['mappings']:
            mapping = mappings[name]
            require(types[mapping['source']]['domain'] == call['source_domain'] and
                    types[mapping['target']]['domain'] == call['target_domain'],
                    'ABI_MAPPING_DOMAIN')
            require(mapping['target'] not in mapped_targets, 'ABI_AMBIGUOUS_MAPPING')
            mapped_targets.add(mapping['target'])
        used_types = set(call['params'])
        if call['result'] is not None:
            used_types.add(call['result'])
        require(used_types <= mapped_targets, 'ABI_MISSING_TYPE_MAPPING')
        if call['exceptions'] == 'mapped':
            require(any(mappings[name]['typed_catch'] for name in call['mappings']),
                    'ABI_EXCEPTION_TYPE_MAPPING')
        bridge = evidence['symbols'][call['bridge']]
        expected_signature = canonical_hash({key: call[key] for key in
                                             ('params', 'result', 'variadic', 'exceptions')})
        require(bridge.get('signature') == expected_signature, 'ABI_SIGNATURE_EVIDENCE')
    return {'domains': len(domains), 'types': len(types), 'mappings': len(mappings),
            'calls': len(calls), 'admitted_for_execution': False}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = validate(loads(args.input.read_text()), loads(args.evidence.read_text()))
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
