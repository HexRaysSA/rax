"""Executable exact helper signature/option instantiation contract."""
import hashlib
import json
from pathlib import Path
import re

from .errors import Reject, exact, option, require

ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = ROOT / 'docs/specifications/smir/portable/schema/runtime/helpers-v1.json'
DEFAULT_OPTIONS = {'alignment': 1, 'scope': 'process', 'order': 'none',
                   'failure_order': 'none', 'weak': False, 'comparison': 'none',
                   'mask': '', 'rounding': 'none', 'exceptions': 'none',
                   'predicate': 'none', 'target': None, 'flags': []}
ORDERS = {'runtime', 'none', 'relaxed', 'consume', 'acquire', 'release', 'acq_rel', 'seq_cst'}
PREDICATES = {'false', 'oeq', 'ogt', 'oge', 'olt', 'ole', 'one', 'ord',
              'ueq', 'ugt', 'uge', 'ult', 'ule', 'une', 'uno', 'true'}


def catalog():
    return json.loads(CATALOG_PATH.read_text())


def digest(document=None):
    document = catalog() if document is None else document
    raw = json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False).encode('ascii')
    return hashlib.sha256(b'SMIR-HELPERS-V1\0' + raw).hexdigest()


def helper(name):
    matches = [entry for entry in catalog()['records'] if entry['name'] == name]
    require(len(matches) == 1, 'RT_HELPER_UNKNOWN', name)
    return matches[0]


def verify_options(record, specification, layout=None):
    options = record['options']
    exact(options, DEFAULT_OPTIONS, 'RT_HELPER_OPTIONS')
    alignment = options['alignment']
    require(type(alignment) is int and 1 <= alignment <= 2**63 and
            alignment & (alignment - 1) == 0, 'RT_HELPER_ALIGNMENT')
    require(options['scope'] in {'process', 'system', 'singlethread'}, 'RT_HELPER_SCOPE')
    require(options['order'] in ORDERS and options['failure_order'] in ORDERS,
            'RT_HELPER_ORDER')
    require(type(options['weak']) is bool, 'RT_HELPER_WEAK')
    require(options['comparison'] in {'none', 'full_storage', 'value_mask', 'llvm_precision'},
            'RT_HELPER_COMPARISON')
    require(type(options['mask']) is str and re.fullmatch(r'(?:[0-9a-f]{2})*', options['mask']),
            'RT_HELPER_MASK')
    require(options['rounding'] in {'none', 'dynamic', 'nearest_even', 'nearest_away',
                                    'toward_zero', 'upward', 'downward'}, 'RT_HELPER_ROUNDING')
    require(options['exceptions'] in {'none', 'ignore', 'maytrap', 'strict'}, 'RT_HELPER_EXCEPTIONS')
    require(options['predicate'] == 'none' or options['predicate'] in PREDICATES,
            'RT_HELPER_PREDICATE')
    option(options['target'])
    require(type(options['flags']) is list and len(set(options['flags'])) == len(options['flags'])
            and set(options['flags']) <= {'volatile', 'elementwise', 'nontemporal'}, 'RT_HELPER_FLAGS')
    policy = specification['policy']
    name = specification['name']
    if policy not in {'atomic', 'atomic_flag'}:
        require(options['scope'] == 'process', 'RT_HELPER_UNUSED_SCOPE')
    memory = policy in {'guarded_value', 'bulk', 'atomic'} and name not in {'atomic_fence', 'atomic_is_lock_free'}
    if not memory:
        require(options['alignment'] == 1 and not options['flags'], 'RT_HELPER_UNUSED_MEMORY_OPTIONS')
    else:
        require('elementwise' not in options['flags'] or policy == 'bulk', 'RT_HELPER_ELEMENTWISE_POLICY')
    if policy == 'atomic_flag' or name in {'atomic_fence', 'atomic_is_lock_free'}:
        require(options['comparison'] == 'none' and not options['mask'], 'RT_HELPER_UNUSED_COMPARISON')
    if policy == 'atomic' and memory:
        expected = record['contract'] if record['contract'] in {'full_storage','value_mask','llvm_precision'} else 'none'
        require(options['comparison'] == expected, 'RT_HELPER_COMPARISON_CONTRACT')
    if name == 'atomic_is_lock_free':
        require(options['order'] == 'none' and options['scope'] == 'process', 'RT_HELPER_UNUSED_ORDER')
    if policy not in {'atomic', 'atomic_flag'}:
        require(options['order'] == options['failure_order'] == 'none' and not options['weak'],
                'RT_HELPER_UNUSED_ORDER')
    else:
        require(options['order'] != 'none' or name == 'atomic_is_lock_free', 'RT_HELPER_ORDER')
        if name != 'atomic_cmpxchg':
            require(options['failure_order'] == 'none' and not options['weak'], 'RT_HELPER_UNUSED_FAILURE')
        else:
            require(options['failure_order'] in {'runtime', 'relaxed', 'consume', 'acquire', 'seq_cst'},
                    'RT_HELPER_FAILURE_ORDER')
        require(options['order'] != 'seq_cst' or 'elementwise' not in options['flags'],
                'RT_HELPER_ELEMENTWISE_SC')
    if policy not in {'fp', 'libm', 'atomic'}:
        require(options['rounding'] == options['exceptions'] == options['predicate'] == 'none',
                'RT_HELPER_UNUSED_FP')
    if policy in {'fp', 'libm'} or (policy == 'atomic' and
                                   specification['type_parameters'] == ['float']):
        require(options['rounding'] != 'none' and options['exceptions'] != 'none', 'RT_HELPER_FP_CONTEXT')
        require(options['predicate'] != 'none' if specification['name'] == 'fp_compare'
                else options['predicate'] == 'none', 'RT_HELPER_PREDICATE')
        if specification['name'] in {'fp_lround', 'fp_llround'}:
            require(options['rounding'] == 'nearest_away', 'RT_HELPER_ROUND_FIXED')
    elif policy == 'atomic':
        require(options['rounding'] == options['exceptions'] == options['predicate'] == 'none',
                'RT_HELPER_UNUSED_FP')
    if options['comparison'] == 'value_mask':
        require(layout is not None and 'comparison_mask' in layout, 'RT_HELPER_ABI_MASK')
        require(not options['mask'] or bytes.fromhex(options['mask']) == layout['comparison_mask'],
                'RT_HELPER_ABI_MASK')
    elif options['mask']:
        require(options['comparison'] == 'llvm_precision', 'RT_HELPER_UNUSED_MASK')
    if policy not in {'atomic', 'atomic_flag'}:
        require(options['comparison'] == 'none' and not options['mask'], 'RT_HELPER_UNUSED_COMPARISON')
    return options


def match_type(template, actual, bindings):
    if template.startswith('type'):
        expected = bindings[int(template[4:])]
        if 'identity' in actual and 'identity' in expected:
            return actual['identity'] == expected['identity']
        return actual == expected
    if template in {'u8', 'u32', 'u64', 'i1', 'i32', 'i64'}:
        width = int(template[1:])
        return actual.get('kind') == 'int' and actual.get('bits') == width
    return actual.get('kind') == template and (template != 'data_ptr' or
                                               actual.get('space') == 'guest_data')


def instantiate(record, resolve_type, resolve_abi=None, resolve_target=None, *,
                journal_captures=None, source_layout=None, source_compatible=None):
    """Resolver returns admitted type definitions; record alone cannot certify them."""
    from .wire import validate_shape
    validate_shape('runtime_import', record)
    require(record['kind'] == 'internal', 'RT_HELPER_IMPORT_KIND')
    specification = helper(record['name'])
    require(record['namespace'] == specification['namespace'] and
            record['version'] == specification['version'] and record['catalog'] == digest(),
            'RT_HELPER_VERSION')
    require(record['contract'] in specification['contracts'], 'RT_HELPER_CONTRACT')
    signature = resolve_type(record['signature'])
    require(signature['kind'] == 'function' and signature['cc'] == 'portable' and
            signature['variadic'] is False, 'RT_HELPER_SIGNATURE')
    require(len(record['types']) == len(specification['type_parameters']), 'RT_HELPER_TYPE_ARITY')
    bindings = [resolve_type(reference) for reference in record['types']]
    for value, constraint in zip(bindings, specification['type_parameters']):
        if constraint == 'storage_value':
            accepted = value['kind'] in {'int', 'raw', 'float', 'data_ptr', 'code_ptr', 'code_address',
                                        'vector', 'array', 'struct'}
        elif constraint == 'integer':
            accepted = value['kind'] == 'int'
        elif constraint == 'pointer':
            accepted = value['kind'] in {'data_ptr', 'code_ptr', 'code_address'}
        elif constraint in {'floating_value', 'integer_value'}:
            element = resolve_type(value['element']) if value['kind'] == 'vector' else value
            accepted = element['kind'] == ('float' if constraint == 'floating_value' else 'int')
            accepted = accepted and value['kind'] in {'float', 'int', 'vector'}
        else:
            accepted = value['kind'] == constraint
        require(accepted, 'RT_HELPER_TYPE_CONSTRAINT')
    if record['contract'] == 'c_fenv' and specification['policy'] == 'libm':
        require(bindings[0]['kind'] != 'vector', 'RT_HELPER_C_LIBM_SCALAR')
    if 'integer_value' in specification['type_parameters']:
        left, right = bindings[:2]
        require((left['kind'] == 'vector') == (right['kind'] == 'vector') and
                (left['kind'] != 'vector' or left['count'] == right['count']),
                'RT_HELPER_VECTOR_SHAPE')
    expanded_captures=[]
    placeholders=[p for p in specification['params'] if p['type']=='journal_captures']
    require(not placeholders or len(placeholders)==1,'RT_HELPER_JOURNAL_TEMPLATE')
    require(placeholders or journal_captures is None,'RT_HELPER_UNUSED_CAPTURES')
    if placeholders:
        abi_reference=option(record['abi'])
        require(abi_reference is not None and abi_reference['module']['kind']=='self' and
                resolve_abi is not None and journal_captures is not None,'RT_HELPER_JOURNAL_CAPTURES')
        program=resolve_abi('journal',abi_reference)
        require(len(journal_captures)==len(program['params']),'RT_HELPER_JOURNAL_CAPTURES')
        for formal,supplied in zip(program['params'],journal_captures):
            nominal=resolve_abi('nominal',formal['type']);execution=option(nominal['execution'])
            require(execution is not None,'RT_HELPER_JOURNAL_CAPTURES')
            actual=resolve_type(execution)
            require(match_type('type0',supplied,[actual]),'RT_HELPER_JOURNAL_CAPTURES')
            expanded_captures.append(actual)
    for side, key in [('params', 'param_noundef'), ('results', 'result_noundef')]:
        expected=[]
        for formal in specification[side]:
            if formal['type']=='journal_captures':
                expected.extend({'type':'capture','actual':typ,'noundef':False} for typ in expanded_captures)
            else:expected.append(formal)
        actual = signature[side]
        require(len(expected) == len(actual), 'RT_HELPER_ARITY')
        require(signature[key] == [item['noundef'] for item in expected], 'RT_HELPER_NOUNDEF')
        for formal, reference in zip(expected, actual):
            require(match_type('type0',resolve_type(reference),[formal['actual']]) if formal['type']=='capture'
                    else match_type(formal['type'], resolve_type(reference), bindings), 'RT_HELPER_TYPE')
    if record['name'] in {'eh_get_terminate','eh_set_terminate'}:
        for reference in signature['params']+signature['results']:
            pointer=resolve_type(reference)
            target=resolve_type(pointer['signature'])
            require(target['kind']=='function' and target['cc']=='portable' and not target['variadic'] and
                    target['params']==target['results']==target['param_noundef']==target['result_noundef']==[],
                    'RT_HELPER_TERMINATE_SIGNATURE')
    layout = None
    abi = option(record['abi'])
    namespace = specification['abi_namespace'][record['contract']]
    optional = namespace.startswith('optional_')
    selected = namespace.removeprefix('optional_')
    if selected == 'none':
        require(abi is None, 'RT_HELPER_UNUSED_ABI')
    elif abi is None:
        require(optional, 'RT_HELPER_ABI_REQUIRED')
    else:
        require(resolve_abi is not None, 'RT_HELPER_ABI_REQUIRED')
        layout = resolve_abi(selected, abi)
    physical = None
    target = option(record['options']['target'])
    target_namespace = specification['target_namespace'][record['contract']]
    if target_namespace == 'none':
        require(target is None, 'RT_HELPER_UNUSED_TARGET')
    else:
        require(target is not None and resolve_target is not None, 'RT_HELPER_TARGET_REQUIRED')
        physical = resolve_target(target_namespace, target)
        if target_namespace == 'storage_layout':
            require(bindings and match_type('type0', resolve_type(physical['type']), bindings),
                    'RT_HELPER_STORAGE_TYPE')
            if layout is not None:
                require(layout['kind'] != 'allocation', 'RT_HELPER_ALLOCATION_NOT_VALUE')
                require(layout['execution_layout'] == target and
                        layout['access_bytes'] == physical['access_bytes'] and
                        record['options']['alignment'] >= layout['required_alignment'],
                        'RT_HELPER_STORAGE_BINDING')
    verify_options(record, specification, layout)
    if selected == 'nominal':
        # A role-specific import name avoids the ABI owner's source_roles package.
        import importlib.util
        import sys
        name = 'rax_runtime_source_roles_contract'
        if name not in sys.modules:
            path = Path(__file__).resolve().parents[1] / 'source_roles/__init__.py'
            source = importlib.util.spec_from_file_location(name,path)
            module = importlib.util.module_from_spec(source)
            sys.modules[name] = module
            source.loader.exec_module(module)
        module = sys.modules[name]
        try:
            module.verify_import(record,resolve_abi,source_layout,resolve_type,
                                 source_compatible,physical)
        except module.SourceRoleError as error:
            raise Reject(error.code,error.detail) from error
    return specification
