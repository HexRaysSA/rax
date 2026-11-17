"""Runtime-root semantic checks and explicit declaration/deployment binding.

No constructor executes and no pointer/token authority is created here. Actual
whole-module admission also requires execution and ABI validators on the same
roots; supplied resolvers are not certificates minted by these metadata bytes.
"""
from dataclasses import dataclass
import copy
import hashlib
import struct

from .errors import exact, option, require, uint, unique
from .helpers import instantiate, helper
from .helpers import match_type
from .services import instantiate as instantiate_service
from .startup import validate as validate_startup
from .requirements import validate as validate_requirements
from .wire import validate_shape

ROOTS = {2: 'runtime_symbols', 4: 'runtime_data', 5: 'runtime_relocations',
         6: 'runtime_imports', 7: 'runtime_tls', 9: 'runtime_capabilities'}
SYMBOL_KINDS = {'function', 'data', 'tls', 'import', 'function_address'}
ENTITY_KINDS = {'type', 'function', 'symbol', 'nominal', 'recipe'}
SELECTIONS = {'any', 'exactmatch', 'largest', 'samesize', 'noduplicates', 'nodeduplicate'}
CAPABILITIES = {'memory', 'file', 'clock', 'entropy', 'thread', 'sync', 'process',
                'module', 'foreign', 'environment', 'network', 'locale', 'host_value'}
LIMITS = {'memory_bytes', 'atomic_bytes', 'stack_bytes', 'threads', 'modules',
          'code_bytes', 'helper_chunk_bytes', 'poll_operations', 'handles'}


def family(key):
    return key['namespace'], key['name'], key['abi_major']


def self_ref(reference):
    return reference['module']['kind'] == 'self'


def alignment(value):
    return type(value) is int and 1 <= value <= 2**63 and value & (value - 1) == 0


def identifier(text):
    require(type(text) is str and text and '\0' not in text, 'RT_LINK_NAME')
    text.encode('utf-8')


def validate_native_cc(facts):
    pairs = {'sysv_amd64': 'sysv64_frame', 'win64': 'win64_frame',
             'aapcs64': 'aapcs64_frame', 'aapcs64_darwin': 'aapcs64_frame',
             'aapcs64_windows': 'aapcs64_frame'}
    require(facts['native_cc'] in pairs and facts['bridge_abi'] in {'none', pairs[facts['native_cc']]},
            'RT_NATIVE_CC')
    expected = 'aarch64_v1' if facts['native_cc'].startswith('aapcs64') else 'x86_64_v1'
    require(facts['profile'] == expected, 'RT_NATIVE_CC_ISA')


def ordered(items, field='id'):
    table = unique(items, field)
    require(list(table) == sorted(table), 'RT_LINK_ORDER', field)
    return table


def extent(segment):
    return len(bytes.fromhex(segment['initial'])) + segment['zero_fill']


@dataclass
class Context:
    site: str
    execution: object
    nominal: object
    function: object
    symbol: object
    execution_equal: object
    nominal_compatible: object
    storage_layout: object
    symbol_body: object
    symbol_identity: object
    abi_entity: object = None
    target_entity: object = None
    native_symbol: object = None
    nominal_layout: object = None
    grants: frozenset = frozenset()
    requirement: object = None
    host_import: object = None
    signature_compatible: object = None
    source_compatible: object = None


def source_plan(record, context, *, required=None):
    signature = option(record['abi_signature'])
    nominal = option(record['nominal'])
    require(nominal is not None or record['source_linkage']=='none','RT_SOURCE_LINKAGE_WITHOUT_NOMINAL')
    callable_ = None
    if record['kind'] in SYMBOL_KINDS:
        callable_ = record['kind'] in {'function', 'import', 'function_address'}
    elif record['kind'] == 'symbol':
        callable_ = record['symbol_kind'] in {'function', 'import', 'function_address'}
    if nominal is not None and callable_ is not None:
        require((context.nominal(nominal)['kind'] == 'function') == callable_,
                'RT_SOURCE_FUNCTION_NOMINAL')
    address_only = (record['kind'] == 'function_address' or
                    record['kind'] == 'symbol' and record['symbol_kind'] == 'function_address')
    if address_only:
        require(nominal is not None and record['source_linkage'] in {'c', 'cpp'}
                and signature is None, 'RT_FUNCTION_ADDRESS_SHAPE')
        return None
    if required is None:
        source = context.nominal(nominal) if nominal is not None else None
        required = False
        if source is not None and source['kind'] == 'function' and record['source_linkage'] != 'none':
            require(context.abi_entity is not None, 'RT_SOURCE_PLAN_NAMESPACE')
            # Keep the original nominal qref: its domain ID belongs to the
            # resolved nominal's owner, never to a guessed consumer/provider.
            domain = context.abi_entity('nominal_domain', nominal)
            require(domain['id'] == source['domain'], 'RT_SOURCE_PLAN_DOMAIN')
            required = domain['isa'] == 'portable'
    require((signature is not None) == required, 'RT_SOURCE_PLAN_PRESENCE')
    if signature is not None:
        require(self_ref(signature),'RT_SOURCE_PLAN_SELF')
        require(context.abi_entity is not None, 'RT_SOURCE_PLAN_NAMESPACE')
        actual = context.abi_entity('signature', signature)
        require(nominal is not None and context.nominal_compatible(nominal, actual['function_type']),
                'RT_SOURCE_PLAN_NOMINAL')
    return signature


def same_plan(before, after, context, code):
    require((before is None) == (after is None), code + '_PRESENCE')
    if before is not None:
        require(context.signature_compatible is not None, 'RT_SOURCE_PLAN_COMPARATOR')
        require(context.signature_compatible(before, after), code)


def validate(roots, context):
    require(type(roots) is dict and set(roots) == set(ROOTS), 'RT_ROOT_SET')
    for index, name in ROOTS.items():
        validate_shape(name, roots[index])
        require(roots[index]['payload_revision'] == (2 if index in {2,5} else 1), 'RT_PAYLOAD_REVISION')
    symbols_root = roots[2]
    manifest = symbols_root['manifest']
    identifier(manifest['key']['namespace'])
    identifier(manifest['key']['name'])
    require(manifest['kind'] in {'object', 'image'}, 'RT_MODULE_KIND')
    require(manifest['personality'] in {'linux', 'darwin', 'windows'}, 'RT_PERSONALITY')
    require(manifest['foreign_isa'] in {'none', 'x86_64', 'aarch64'}, 'RT_FOREIGN_ISA')
    require(manifest['site'] == context.site, 'RT_SITE_IDENTITY')
    entry = option(manifest['entry'])
    require((manifest['kind'] == 'image') == (entry is not None), 'RT_IMAGE_ENTRY')
    if entry is not None:
        require(manifest['kind'] == 'image' and self_ref(entry), 'RT_ENTRY')
        validate_startup(context.function(entry), context)
    dependencies = ordered(manifest['dependencies'], 'slot')
    for dependency in dependencies.values():
        low, high = dependency['minimum_minor'], option(dependency['maximum_minor'])
        require(low <= dependency['key']['abi_minor'] and
                (high is None or dependency['key']['abi_minor'] <= high), 'RT_VERSION_BASELINE')
        if high is not None:
            require(low <= high, 'RT_VERSION_RANGE')
        declarations = unique(dependency['declarations'], 'id')
        names = set()
        for declaration in declarations.values():
            identity = declaration['kind'], declaration['namespace'], declaration['name']
            require(declaration['kind'] in ENTITY_KINDS and identity not in names,
                    'RT_DECLARATION_IDENTITY')
            require(declaration['symbol_kind'] in SYMBOL_KINDS if declaration['kind']=='symbol'
                    else declaration['symbol_kind']=='none','RT_DECLARATION_SYMBOL_KIND')
            require(declaration['source_linkage'] in {'none', 'c', 'cpp'} and
                    (declaration['kind'] in {'function', 'symbol'} or declaration['source_linkage'] == 'none'),
                    'RT_SOURCE_LINKAGE')
            names.add(identity)
            identifier(declaration['namespace'])
            identifier(declaration['name'])
            for field in ('execution', 'nominal'):
                reference = option(declaration[field])
                if reference is not None:
                    require(self_ref(reference), 'RT_DECLARATION_SELF')
                    (context.execution if field == 'execution' else context.nominal)(reference)
            execution = option(declaration['execution'])
            if declaration['kind'] == 'function':
                require(execution is not None and context.execution(execution)['kind'] == 'function',
                        'RT_DECLARATION_FUNCTION_TYPE')
            plan = source_plan(declaration, context)
            if plan is not None and execution is not None:
                actual = context.abi_entity('signature', plan)['execution']
                require(context.execution_equal(actual, execution),
                        'RT_DECLARATION_SOURCE_PLAN_EXECUTION')
            if declaration['kind']=='symbol':
                execution=option(declaration['execution'])
                callable_=declaration['symbol_kind'] in {'function','import'}
                require(execution is not None or not (callable_ or declaration['symbol_kind']=='function_address'),
                        'RT_DECLARATION_EXECUTION')
                if execution is not None:
                    require((context.execution(execution)['kind']=='function')==callable_,
                            'RT_DECLARATION_SYMBOL_TYPE')
                    if declaration['symbol_kind']=='function_address':
                        require(context.execution(execution)['kind']=='code_address','RT_DECLARATION_SYMBOL_TYPE')
            require(not declaration['weak'] or declaration['kind'] in {'function', 'symbol'},
                    'RT_WEAK_DECLARATION_KIND')
    exports = ordered(manifest['exports'])
    names = set()
    for exported in exports.values():
        identity = exported['kind'], exported['namespace'], exported['name']
        require(exported['kind'] in ENTITY_KINDS and identity not in names,
                'RT_EXPORT_IDENTITY')
        require(exported['source_linkage'] in {'none', 'c', 'cpp'} and
                (exported['kind'] in {'function', 'symbol'} or exported['source_linkage'] == 'none'),
                'RT_SOURCE_LINKAGE')
        names.add(identity)
        identifier(exported['namespace'])
        identifier(exported['name'])
        require(self_ref(exported['target']), 'RT_EXPORT_SELF')
        for field in ('execution', 'nominal'):
            reference = option(exported[field])
            if reference is not None:
                require(self_ref(reference), 'RT_EXPORT_SELF')
                (context.execution if field == 'execution' else context.nominal)(reference)
    symbols = ordered(symbols_root['symbols'])
    for exported in exports.values():
        reference = exported['target']
        claimed_execution = option(exported['execution'])
        claimed_nominal = option(exported['nominal'])
        kind = exported['kind']
        actual_execution, actual_nominal, actual_plan = None, None, None
        if kind == 'function':
            body = context.function(reference)
            actual_execution = body['signature']
            descriptor = option(body['abi_signature'])
            require(descriptor is None or self_ref(descriptor),'RT_SOURCE_PLAN_SELF')
            actual_plan = descriptor
            if descriptor is not None:
                require(context.abi_entity is not None, 'RT_EXPORT_ABI')
                actual_nominal = context.abi_entity('signature', descriptor)['function_type']
            linkage = 'none' if actual_nominal is None else (
                'c' if 'c_linkage' in context.nominal(actual_nominal)['flags'] else 'cpp')
            require(exported['source_linkage'] == linkage, 'RT_EXPORT_SOURCE_LINKAGE')
        elif kind == 'symbol':
            require(reference['id'] in symbols, 'RT_EXPORT_TARGET')
            target = symbols[reference['id']]
            require(exported['source_linkage'] == target['source_linkage'], 'RT_EXPORT_SOURCE_LINKAGE')
            actual_execution, actual_nominal = target['execution'], option(target['nominal'])
            actual_plan = option(target['abi_signature'])
        elif kind == 'type':
            context.execution(reference)
            actual_execution = reference
            if claimed_nominal is not None:
                actual_nominal = claimed_nominal
                bound = option(context.nominal(claimed_nominal)['execution'])
                require(bound is not None and context.execution_equal(reference, bound), 'RT_EXPORT_NOMINAL_BINDING')
        elif kind == 'nominal':
            target = context.nominal(reference)
            actual_nominal, actual_execution = reference, option(target['execution'])
        else:
            require(context.abi_entity is not None, 'RT_EXPORT_RECIPE')
            context.abi_entity('recipe', reference)
        require((actual_execution is None) == (claimed_execution is None) and
                (actual_nominal is None) == (claimed_nominal is None), 'RT_EXPORT_TYPE_PRESENCE')
        if actual_execution is not None:
            require(context.execution_equal(actual_execution, claimed_execution), 'RT_EXPORT_EXECUTION')
        if actual_nominal is not None:
            require(context.nominal_compatible(actual_nominal, claimed_nominal), 'RT_EXPORT_NOMINAL')
        same_plan(option(exported['abi_signature']), actual_plan, context, 'RT_EXPORT_SOURCE_PLAN')
    data = ordered(roots[4]['segments'])
    tls = ordered([record['storage'] for record in roots[7]['segments']])
    imports = ordered(roots[6]['imports'])
    for segment in [*data.values(), *tls.values()]:
        require(alignment(segment['alignment']) and extent(segment) < 2**64, 'RT_SEGMENT_EXTENT')
        length = len(bytes.fromhex(segment['initial']))
        require(len(bytes.fromhex(segment['poison'])) == len(bytes.fromhex(segment['undef'])) == length,
                'RT_SEGMENT_SHADOW')
        require(all(not (a & b) for a, b in zip(bytes.fromhex(segment['poison']),
                                              bytes.fromhex(segment['undef']))), 'RT_SEGMENT_SHADOW')
        require(segment['zero_shadow'] in {'defined', 'poison', 'undef'}, 'RT_SEGMENT_ZERO_SHADOW')
        layout = option(segment['layout'])
        if layout is not None:
            expected = context.storage_layout(layout)
            require(expected['size'] == extent(segment) and
                    segment['alignment'] >= expected['alignment'], 'RT_SEGMENT_LAYOUT')
        nominal, binding = option(segment['nominal']), option(segment['abi_binding'])
        require((nominal is None) == (binding is None), 'RT_SEGMENT_SOURCE_BINDING')
        if nominal is not None:
            require(layout is not None and context.abi_entity is not None and context.nominal_layout is not None,
                    'RT_SEGMENT_SOURCE_BINDING')
            actual = context.abi_entity('storage_binding', binding)
            source = context.nominal_layout(nominal)
            require(actual['nominal'] == nominal and actual['execution_layout'] == layout and
                    actual['kind'] in {'object_bytes', 'allocation'} and actual['view_offset_bits'] == 0 and
                    actual['view_width_bits'] == extent(segment) * 8 and source['size'] == extent(segment) and
                    source['align'] <= segment['alignment'] and actual['required_alignment'] <= segment['alignment'],
                    'RT_SEGMENT_SOURCE_BINDING')
    names = set()
    definitions = {'data': data, 'tls': tls, 'import': imports}
    for symbol in symbols.values():
        identifier(symbol['namespace'])
        identifier(symbol['name'])
        name = symbol['namespace'], symbol['name']
        require(name not in names, 'RT_SYMBOL_DUPLICATE')
        names.add(name)
        require(symbol['kind'] in SYMBOL_KINDS and symbol['binding'] in
                {'local', 'strong', 'weak', 'external_weak', 'common'}, 'RT_SYMBOL_KIND')
        require(symbol['source_linkage'] in {'none', 'c', 'cpp'}, 'RT_SOURCE_LINKAGE')
        require(symbol['visibility'] in {'default', 'hidden', 'protected'} and
                alignment(symbol['alignment']), 'RT_SYMBOL_VISIBILITY')
        definition = option(symbol['definition'])
        if symbol['kind']=='function_address':
            require(symbol['binding'] in {'strong','weak','external_weak'} and
                    symbol['source_linkage'] in {'c','cpp'} and symbol['nominal'] is not None and
                    symbol['abi_signature'] is None and symbol['size'] is None and
                    symbol['alignment']==1 and symbol['comdat'] is None and symbol['fallback'] is None,
                    'RT_FUNCTION_ADDRESS_SHAPE')
            require(definition is None or definition['kind']=='native','RT_FUNCTION_ADDRESS_DEFINITION')
            if definition is not None:
                require(symbol['binding'] in {'strong','weak'},'RT_FUNCTION_ADDRESS_BINDING')
        # Preserve established definition-category diagnostics before the global
        # callable/object checks, including the independently found INT024 case.
        if definition is not None and definition['kind'] == 'function':
            require(symbol['kind'] == 'function', 'RT_DEFINITION_DOMAIN')
        if definition is not None and definition['kind'] == 'native':
            require(symbol['kind'] in {'function','function_address'}, 'RT_NATIVE_DEFINITION')
        execution = context.execution(symbol['execution'])
        if symbol['kind']=='function_address':
            require(execution['kind']=='code_address','RT_SYMBOL_SIGNATURE')
        require((execution['kind'] == 'function') == (symbol['kind'] in {'function', 'import'}),
                'RT_SYMBOL_SIGNATURE')
        nominal = option(symbol['nominal'])
        if nominal is not None:
            context.nominal(nominal)
        plan = source_plan(symbol, context, required=False if definition is not None and
                           definition['kind'] == 'native' else None)
        require(symbol['binding'] != 'local' or definition is not None, 'RT_LOCAL_UNDEFINED')
        if definition is None:
            continue
        if definition['kind'] == 'native':
            require(symbol['kind'] in {'function','function_address'} and nominal is not None and context.native_symbol is not None,
                    'RT_NATIVE_DEFINITION')
            native = context.native_symbol({'module': {'kind': 'self'}, 'id': symbol['id']}, definition)
            require(native['image'] == definition['image'] and native['domain'] == definition['domain'] and
                    native['offset'] == definition['offset'] and native['code_size'] == definition['size'] > 0 and
                    native['signature'] == nominal and native['execution_identity'] == execution['identity'] and
                    native['permissions'] == 'rx' and native['entry_boundary'] is True, 'RT_NATIVE_EVIDENCE')
            validate_native_cc(native)
            require(native['profile'] == manifest['foreign_isa'] + '_v1', 'RT_NATIVE_PROCESS_ISA')
        elif definition['kind'] in {'function', 'alias'}:
            if definition['kind'] == 'function':
                require(symbol['kind'] == 'function', 'RT_DEFINITION_DOMAIN')
            require(self_ref(definition['target']), 'RT_DEFINITION_SELF')
            target = (context.function if definition['kind'] == 'function' else context.symbol)(definition['target'])
            if definition['kind'] == 'alias':
                require(target['kind'] == symbol['kind'], 'RT_ALIAS_KIND')
            target_type = target['signature'] if definition['kind'] == 'function' else target['execution']
            require(context.execution_equal(symbol['execution'], target_type), 'RT_DEFINITION_SIGNATURE')
            if definition['kind'] == 'function':
                body_abi = option(target['abi_signature'])
                require(body_abi is None or self_ref(body_abi),'RT_SOURCE_PLAN_SELF')
                require((body_abi is None) == (nominal is None), 'RT_FUNCTION_SOURCE_PRESENCE')
                if body_abi is not None:
                    require(context.abi_entity is not None, 'RT_FUNCTION_SOURCE_ABI')
                    source = context.abi_entity('signature', body_abi)['function_type']
                    require(context.nominal_compatible(nominal, source), 'RT_FUNCTION_SOURCE_TYPE')
                same_plan(plan, body_abi, context, 'RT_FUNCTION_SOURCE_PLAN')
            else:
                other_nominal = option(target['nominal'])
                require((nominal is None) == (other_nominal is None) and
                        symbol['source_linkage'] == target['source_linkage'], 'RT_ALIAS_SOURCE')
                if nominal is not None:
                    require(context.nominal_compatible(nominal, other_nominal), 'RT_ALIAS_SOURCE')
                same_plan(plan, option(target['abi_signature']), context, 'RT_ALIAS_SOURCE_PLAN')
        elif definition['kind'] == 'common':
            require(symbol['binding'] == 'common' and symbol['kind'] == 'data' and
                    alignment(definition['alignment']), 'RT_COMMON_DEFINITION')
        else:
            require(definition['kind'] == symbol['kind'], 'RT_DEFINITION_DOMAIN')
            field = 'import' if definition['kind'] == 'import' else 'segment'
            require(definition[field] in definitions[symbol['kind']], 'RT_DEFINITION_REFERENCE')
            if symbol['kind'] == 'import':
                require(context.execution_equal(symbol['execution'], imports[definition[field]]['signature']),
                        'RT_IMPORT_SIGNATURE')
                imported = imports[definition[field]]
                actual_plan = ({'module': imported['descriptor']['module'],
                                'id': context.abi_entity('bridge', imported['descriptor'])['signature']}
                               if imported['kind'] == 'foreign' else None)
                same_plan(plan, actual_plan, context, 'RT_IMPORT_SOURCE_PLAN')
            if symbol['kind'] in {'data', 'tls'}:
                storage = definitions[symbol['kind']][definition[field]]
                require(option(symbol['size']) == extent(storage) and symbol['alignment'] == storage['alignment'],
                        'RT_SYMBOL_EXTENT')
                require(nominal == option(storage['nominal']), 'RT_SYMBOL_STORAGE_NOMINAL')
                physical = option(storage['layout'])
                if physical is not None:
                    require(context.execution_equal(symbol['execution'], context.storage_layout(physical)['type']),
                            'RT_SYMBOL_STORAGE_TYPE')
                require(execution['kind'] == 'array' and execution['count'] == extent(storage) and
                        context.execution(execution['element'])['kind'] == 'raw' and
                        context.execution(execution['element'])['bits'] == 8, 'RT_SYMBOL_STORAGE_CANONICAL')
        if nominal is not None and symbol['kind'] in {'function', 'import'} and definition['kind'] != 'native':
            source = context.nominal(nominal)
            require(plan is not None and context.abi_entity is not None, 'RT_SYMBOL_NOMINAL_EXECUTION')
            actual = context.abi_entity('signature', plan)['execution']
            require(context.execution_equal(actual, symbol['execution']),
                    'RT_SYMBOL_NOMINAL_EXECUTION')
            require(symbol['source_linkage'] == ('c' if 'c_linkage' in source['flags'] else 'cpp'),
                    'RT_SYMBOL_SOURCE_LINKAGE')
    groups = ordered(symbols_root['comdats'])
    membership = {}
    for group in groups.values():
        require(group['selection'] in SELECTIONS and group['members'] and
                group['key_symbol'] in group['members'], 'RT_COMDAT')
        require(len(set(group['members'])) == len(group['members']), 'RT_COMDAT_MEMBERS')
        for identifier_ in group['members']:
            require(identifier_ in symbols and identifier_ not in membership and
                    option(symbols[identifier_]['comdat']) == group['id'], 'RT_COMDAT_MEMBERSHIP')
            membership[identifier_] = group['id']
    for symbol in symbols.values():
        require(option(symbol['comdat']) == membership.get(symbol['id']), 'RT_COMDAT_MEMBERSHIP')
        fallback = option(symbol['fallback'])
        if fallback is not None:
            require(symbol['definition'] is None and symbol['binding'] in {'weak', 'external_weak'},
                    'RT_FALLBACK_POLICY')
            target = context.symbol(fallback)
            require(target['kind'] == symbol['kind'] and
                    context.execution_equal(target['execution'], symbol['execution']), 'RT_FALLBACK_TYPE')
            other = option(target['nominal'])
            require((other is None) == (option(symbol['nominal']) is None) and
                    symbol['source_linkage'] == target['source_linkage'], 'RT_FALLBACK_SOURCE')
            if other is not None:
                require(context.nominal_compatible(option(symbol['nominal']), other), 'RT_FALLBACK_SOURCE')
            same_plan(option(symbol['abi_signature']), option(target['abi_signature']), context,
                      'RT_FALLBACK_SOURCE_PLAN')
    # Definition aliases are local; fallback edges can also reference local
    # declarations. Reject a cycle before any resolver/token lookup can loop.
    alias_graph = {identity: [] for identity in symbols}
    for identity, symbol in symbols.items():
        definition = option(symbol['definition'])
        candidates = ([definition['target']] if definition is not None and definition['kind'] == 'alias' else [])
        fallback = option(symbol['fallback'])
        if fallback is not None:
            candidates.append(fallback)
        for target in candidates:
            if self_ref(target):
                require(target['id'] in symbols, 'RT_ALIAS_REFERENCE')
                alias_graph[identity].append(target['id'])
    complete, active = set(), set()
    for start in symbols:
        pending = [(start, False)]
        while pending:
            node, leaving = pending.pop()
            if leaving:
                active.remove(node)
                complete.add(node)
            elif node not in complete:
                require(node not in active, 'RT_ALIAS_CYCLE')
                active.add(node)
                pending.append((node, True))
                pending.extend((child, False) for child in alias_graph[node])
    patches = {}
    for relocation in roots[5]['relocations']:
        require(relocation['source_kind'] in {'data', 'tls'}, 'RT_RELOCATION_SOURCE')
        table = data if relocation['source_kind'] == 'data' else tls
        require(relocation['source'] in table and relocation['width']>0, 'RT_RELOCATION_SOURCE')
        start, width = relocation['offset'], relocation['width']
        require(start + width <= extent(table[relocation['source']]), 'RT_RELOCATION_BOUNDS')
        key = relocation['source_kind'], relocation['source']
        prior = patches.setdefault(key, [])
        require(all(start + width <= a or b <= start for a, b in prior), 'RT_RELOCATION_OVERLAP')
        prior.append((start, start + width))
        target = context.symbol(relocation['target'])
        expected = {'code_address':'function_address','data_address': 'data', 'tls_offset': 'tls', 'function_token': 'function',
                    'import_token': 'import', 'data_integer':'data',
                    'function_integer':'function','import_integer':'import'}.get(relocation['kind'])
        require(expected is not None and
                (target['kind'] in {'function','import','function_address'} if relocation['kind']=='code_address'
                 else target['kind'] == expected), 'RT_RELOCATION_DOMAIN')
        from .relocations import INTEGER_KINDS, validate_step
        integer=relocation['kind'] in INTEGER_KINDS
        require((relocation['integer_bits']>0 and width==(relocation['integer_bits']+7)//8) if integer
                else relocation['integer_bits']==0 and width in {4,8},'RT_RELOCATION_INTEGER_WIDTH')
        require(len(relocation['derivation'])<=4096,'RT_PATCH_RESOURCE')
        for step in [*relocation['derivation'],{'offset':relocation['addend'],
                    'check_base':relocation['check_base'],
                    'flags':relocation['flags'],'inrange':relocation['inrange']}]:validate_step(step)
        if expected!='data':
            require(not relocation['derivation'] and not relocation['check_base'] and not relocation['flags'] and relocation['inrange'] is None,
                    'RT_PATCH_UNUSED_POINTER_OPTIONS')
        if relocation['kind']=='code_address':
            require(width==8 and relocation['addend']==0, 'RT_CODE_RELOCATION')
        elif expected in {'function', 'import'}:
            require(integer or width == 8 and relocation['addend'] == 0, 'RT_CODE_RELOCATION')
            definition = option(target['definition'])
            require(definition is None or definition['kind'] != 'native', 'RT_NATIVE_PORTABLE_TOKEN')
        elif expected == 'data':
            require(integer or width == 8, 'RT_POINTER_WIDTH')
    from .initialization import validate_records
    validate_records(roots,context)
    for entry_ in roots[7]['segments']:
        require(entry_['initialization'] in {'static', 'namespace_dynamic', 'block_dynamic'},
                'RT_TLS_INITIALIZATION')
        require(entry_['initialization'] != 'static' or not entry_['initializers'], 'RT_STATIC_TLS_INITIALIZER')
        for role in ['initializers', 'destructors']:
            for reference in entry_[role]:
                function = context.function(reference)
                signature = context.execution(function['signature'])
                require(signature['kind'] == 'function' and signature['cc'] == 'portable' and
                        not signature['variadic'] and signature['params'] == signature['results'] == [],
                        'RT_TLS_HOOK_SIGNATURE')
                if role == 'destructors' or entry_['initialization'] == 'namespace_dynamic':
                    require(function['escape'] in {'terminate', 'nothrow'}, 'RT_TLS_HOOK_ESCAPE')
    caps = roots[9]
    require(caps['capabilities'] == sorted(set(caps['capabilities'])) and
            set(caps['capabilities']) <= CAPABILITIES, 'RT_CAPABILITIES')
    require(set(caps['capabilities']) <= set(context.grants), 'RT_CAPABILITY_GRANT')
    validate_requirements(caps['requirements'], context.requirement)
    limits = ordered(caps['limits'], 'name')
    require(set(limits) <= LIMITS and all(item['value'] > 0 for item in limits.values()), 'RT_LIMIT')
    for imported in imports.values():
        if imported['kind'] == 'internal':
            arguments = {'source_layout': context.nominal_layout,
                         'source_compatible': context.source_compatible}
            if any(formal['type'] == 'journal_captures' for formal in helper(imported['name'])['params']):
                reference = option(imported['abi'])
                require(reference is not None and self_ref(reference) and context.abi_entity is not None,
                        'RT_HELPER_JOURNAL_CAPTURES')
                program = context.abi_entity('journal', reference)
                require(type(program) is dict and type(program.get('params')) is list,
                        'RT_HELPER_JOURNAL_CAPTURES')
                captures = []
                for formal in program['params']:
                    # A DEP nominal resolves the actual local expectation. Its
                    # execution qref stays in that checked nominal-owner scope.
                    nominal = context.abi_entity('nominal', formal['type'])
                    execution = option(nominal['execution'])
                    require(execution is not None, 'RT_HELPER_JOURNAL_CAPTURES')
                    captures.append(context.execution(execution))
                arguments['journal_captures'] = captures
            instantiate(imported, context.execution, context.abi_entity, context.target_entity, **arguments)
        else:
            require(imported['capability'] in caps['capabilities'], 'RT_IMPORT_CAPABILITY')
            context.execution(imported['signature'])
            if imported['kind'] == 'host':
                require(context.host_import is not None, 'RT_HOST_UNREGISTERED')
                context.host_import(imported, context.execution)
            elif imported['kind'] == 'foreign':
                require(manifest['foreign_isa'] != 'none', 'RT_FOREIGN_ISA')
                require(self_ref(imported['descriptor']),'RT_FOREIGN_BRIDGE_SELF')
                require(context.abi_entity is not None, 'RT_FOREIGN_DESCRIPTOR')
                bridge = context.abi_entity('bridge', imported['descriptor'])
                source_signature = context.abi_entity('signature',
                    {'module': imported['descriptor']['module'], 'id': bridge['signature']})
                source_type = context.abi_entity('nominal', source_signature['function_type'])
                execution = option(source_type['execution'])
                require(execution is not None and match_type('type0', context.execution(execution),
                    [context.execution(imported['signature'])]), 'RT_FOREIGN_SIGNATURE')
            else:
                instantiate_service(imported, context.execution, context.abi_entity)
    for records in [symbols_root['initializers'], symbols_root['finalizers']]:
        require(len({r['ordinal'] for r in records}) == len(records), 'RT_INIT_ORDINAL')
        for record in records:
            function = context.function(record['function'])
            signature = context.execution(function['signature'])
            require(signature['params'] == signature['results'] == [], 'RT_INIT_SIGNATURE')
    return roots


def content_identity(sections):
    require(type(sections) is dict and set(sections) == set(range(1, 11)), 'RT_HASH_SECTIONS')
    require(all(type(k) is int and type(v) is bytes for k, v in sections.items()), 'RT_HASH_BYTES')
    require(len(sections[2]) >= 36, 'RT_HASH_MANIFEST')
    normalized = sections[2][:4] + bytes(32) + sections[2][36:]
    hasher = hashlib.sha256(b'SMIR0.2\0' + struct.pack('<I', 2))
    for index in range(1, 11):
        payload = normalized if index == 2 else sections[index]
        hasher.update(struct.pack('<HQ', index, len(payload)))
        hasher.update(payload)
    return hasher.hexdigest()


def components(graph, order):
    """Iterative Kosaraju then dependency-first SCC condensation; O(V+E)."""
    positions = {node: index for index, node in enumerate(order)}
    reverse = {node: [] for node in graph}
    for node, edges in graph.items():
        for dependency in edges:
            reverse[dependency].append(node)
    done, finished = set(), []
    for start in order:
        if start in done:
            continue
        pending = [(start, False)]
        while pending:
            node, leave = pending.pop()
            if leave:
                finished.append(node)
            elif node not in done:
                done.add(node)
                pending.append((node, True))
                pending.extend((edge, False) for edge in reversed(graph[node]) if edge not in done)
    groups, seen = [], set()
    for start in reversed(finished):
        if start in seen:
            continue
        group, pending = [], [start]
        while pending:
            node = pending.pop()
            if node not in seen:
                seen.add(node)
                group.append(node)
                pending.extend(reverse[node])
        groups.append(sorted(group, key=positions.__getitem__))
    owner = {node: i for i, group in enumerate(groups) for node in group}
    emitted, result = set(), []
    for start in range(len(groups)):
        stack = [(start, False)]
        while stack:
            group, leave = stack.pop()
            if group in emitted:
                continue
            if leave:
                emitted.add(group)
                result.append(groups[group])
            else:
                stack.append((group, True))
                edges = {owner[n] for v in groups[group] for n in graph[v] if owner[n] != group}
                stack.extend((edge, False) for edge in sorted(edges, reverse=True) if edge not in emitted)
    return result


def bind_deployment(modules, deployment, execution_equal, nominal_compatible,
                    process_personality=None, process_isa='none', data_compatible=None,
                    address_compatible=None, signature_compatible=None):
    """Atomic metadata transaction, supports SCCs and private-ID remapping.

    modules maps independently VERIFIED artifact digests to runtime_symbols roots.
    No authority is derived from self-declared hashes; integrator verifies encoded
    content digests before supplying this map. Return a complete immutable plan,
    never partially published bindings. Callbacks compare actual normalized graphs.
    """
    validate_shape('runtime_deployment', deployment)
    require(deployment['payload_revision'] == 1, 'RT_DEPLOY_REVISION')
    pinned, order = {}, []
    for binding in deployment['modules']:
        artifact = binding['artifact']
        require(artifact in modules and artifact not in order, 'RT_DEPLOY_ARTIFACT')
        manifest = modules[artifact]['manifest']
        require(manifest['identity'] == artifact and manifest['key'] == binding['key'],
                'RT_DEPLOY_IDENTITY')
        identity = family(binding['key'])
        pinned.setdefault(identity, []).append(artifact)
        order.append(artifact)
    require(set(modules) == set(order), 'RT_DEPLOY_MODULE_SET')
    personalities = {modules[a]['manifest']['personality'] for a in order}
    foreign = {modules[a]['manifest']['foreign_isa'] for a in order} - {'none'}
    require(len(personalities) == 1 and personalities <= {'linux', 'darwin', 'windows'},
            'RT_PROCESS_PERSONALITY')
    personality = next(iter(personalities))
    require(process_personality is None or process_personality == personality,
            'RT_PROCESS_PERSONALITY')
    require(process_isa in {'none', 'x86_64', 'aarch64'} and len(foreign) <= 1 and
            foreign <= {'x86_64', 'aarch64'}, 'RT_PROCESS_ISA')
    foreign_isa = next(iter(foreign), process_isa)
    require(process_isa == 'none' or foreign_isa == process_isa, 'RT_PROCESS_ISA')
    edges = {}
    for edge in deployment['edges']:
        key = edge['source'], edge['slot']
        require(key not in edges, 'RT_DEPLOY_DUPLICATE_EDGE')
        edges[key] = edge
    graph, bindings, used = {artifact: [] for artifact in order}, {}, set()
    for source in order:
        manifest = modules[source]['manifest']
        for dependency in manifest['dependencies']:
            candidates = pinned.get(family(dependency['key']), [])
            require(candidates, 'RT_DEPLOY_DEPENDENCY')
            key = source, dependency['slot']
            require(key in edges and edges[key]['target'] in candidates, 'RT_DEPLOY_EDGE')
            used.add(key)
            edge = edges[key]
            expected = edge['target']
            target = modules[expected]['manifest']
            actual = target['key']['abi_minor']
            low, high = dependency['minimum_minor'], option(dependency['maximum_minor'])
            require(low <= dependency['key']['abi_minor'] and
                    (high is None or dependency['key']['abi_minor'] <= high), 'RT_VERSION_BASELINE')
            require(low <= actual and (high is None or actual <= high), 'RT_DEPLOY_VERSION')
            require(target['site'] == dependency['site'], 'RT_DEPLOY_SITE')
            declarations = unique(dependency['declarations'], 'id')
            exports = unique(target['exports'], 'id')
            mapped = {}
            for entry in edge['entities']:
                identifier_ = entry['declaration']
                require(identifier_ in declarations and identifier_ not in mapped, 'RT_DEPLOY_DECLARATION')
                declared = declarations[identifier_]
                require(entry['entity_kind'] == declared['kind'], 'RT_DEPLOY_ENTITY_KIND')
                if entry['kind'] == 'weak_null':
                    require(declared['weak'] and declared['kind'] in {'function', 'symbol'},
                            'RT_DEPLOY_WEAK_NULL')
                    require(declared['symbol_kind']!='tls','RT_DEPLOY_WEAK_TLS')
                    require(not any((e['kind'], e['namespace'], e['name']) ==
                            (declared['kind'], declared['namespace'], declared['name'])
                            for e in exports.values()), 'RT_DEPLOY_WEAK_PRESENT')
                    mapped[identifier_] = None
                    continue
                require(entry['export'] in exports, 'RT_DEPLOY_EXPORT')
                exported = exports[entry['export']]
                require(all(declared[f] == exported[f] for f in ('kind', 'source_linkage', 'namespace', 'name')),
                        'RT_DEPLOY_EXPORT_NAME')
                actual_kind = None
                if exported['kind'] == 'symbol':
                    actual_symbols = unique(modules[expected]['symbols'], 'id')
                    require(exported['target']['id'] in actual_symbols, 'RT_DEPLOY_PRIVATE_TARGET')
                    actual_kind = actual_symbols[exported['target']['id']]['kind']
                    require(actual_kind in {'function','import','function_address'}
                            if declared['symbol_kind']=='function_address'
                            else declared['symbol_kind']==actual_kind,'RT_DEPLOY_SYMBOL_KIND')
                function_address = declared.get('symbol_kind')=='function_address'
                address_only = (actual_kind in {'data', 'tls'} and declared['execution'] is None and
                                exported['execution'] is not None and declared['nominal'] is not None)
                for field, compare in [('execution', execution_equal), ('nominal', nominal_compatible)]:
                    before, after = option(declared[field]), option(exported[field])
                    if field == 'execution' and (address_only or function_address):
                        continue
                    require((before is None) == (after is None), 'RT_DEPLOY_TYPE_PRESENCE')
                    if before is not None:
                        if field == 'nominal' and actual_kind in {'data', 'tls'}:
                            if declared['source_linkage'] == 'c':
                                require(data_compatible is not None, 'RT_DEPLOY_C_DATA_COMPARATOR')
                                compare = data_compatible
                            elif address_only:
                                require(address_compatible is not None, 'RT_DEPLOY_ADDRESS_COMPARATOR')
                                compare = address_compatible
                        require(compare(source, before, expected, after), 'RT_DEPLOY_' + field.upper())
                require(self_ref(exported['target']), 'RT_DEPLOY_PRIVATE_TARGET')
                before, after = option(declared['abi_signature']), option(exported['abi_signature'])
                if function_address:
                    require(before is None, 'RT_DEPLOY_SOURCE_PLAN_PRESENCE')
                    mapped[identifier_] = (expected, exported['target']['id'])
                    continue
                require((before is None) == (after is None), 'RT_DEPLOY_SOURCE_PLAN_PRESENCE')
                if before is not None:
                    require(signature_compatible is not None, 'RT_DEPLOY_ABI_COMPARATOR')
                    require(signature_compatible(source, before, expected, after), 'RT_DEPLOY_SOURCE_PLAN')
                mapped[identifier_] = (expected, exported['target']['id'])
            require(set(mapped) == set(declarations), 'RT_DEPLOY_UNBOUND_DECLARATION')
            for identifier_, target_ in mapped.items():
                bindings[source, dependency['slot'], identifier_] = target_
            graph[source].append(expected)
    require(used == set(edges), 'RT_DEPLOY_EXTRA_EDGE')
    return {'bindings': bindings, 'components': components(graph, order), 'order': order,
            'personality': personality, 'foreign_isa': foreign_isa}
