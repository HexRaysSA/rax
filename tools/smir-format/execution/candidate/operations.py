"""Exact candidate operation typing and compiler-internal helper binding checks."""
from common import bit_pattern, require
from candidate.type_system import HANDLES, key
from candidate.wire import SCHEMA

ROUND = {'nearest_even', 'nearest_away', 'toward_zero', 'upward', 'downward', 'dynamic'}
FLAGS = {'invalid', 'divide_by_zero', 'overflow', 'underflow', 'inexact'}
ENV_FLAGS = FLAGS | {'denormal'}
ORDERS = {'none', 'unordered', 'relaxed', 'acquire', 'release', 'acq_rel', 'seq_cst'}
RMW = {'exchange', 'add', 'sub', 'and', 'nand', 'or', 'xor', 'min', 'max', 'umin', 'umax',
       'uinc_wrap', 'udec_wrap', 'usub_cond', 'usub_sat', 'fadd', 'fsub', 'fmin', 'fmax',
       'fminimum', 'fmaximum', 'fminimumnum', 'fmaximumnum'}
FCMP = {'false', 'true', 'oeq', 'one', 'olt', 'ole', 'ogt', 'oge', 'ord',
        'ueq', 'une', 'ult', 'ule', 'ugt', 'uge', 'uno'}
ICMP = {'eq', 'ne', 'ult', 'ule', 'ugt', 'uge', 'slt', 'sle', 'sgt', 'sge'}


def optional(value):
    return None if value is None else value['some']


def power2(value):
    return value > 0 and value & (value - 1) == 0


def fp_mode(mode, operation):
    require(mode['environment'] in {'default', 'constrained'} and mode['rounding'] in ROUND
            and mode['exceptions'] in {'ignore', 'maytrap', 'strict'}, 'fp_mode')
    if mode['environment'] == 'default':
        require(mode['rounding'] == 'nearest_even' and mode['exceptions'] == 'ignore', 'fp_default')
    if operation in {'fptosi', 'fptoui'} and mode['environment'] == 'constrained':
        require(mode['rounding'] == 'toward_zero', 'fp_conversion_rounding')


class Dependencies:
    """Explicit adapter to independently admitted section2/6/10 metadata.

    A caller must supply the registry from the combined verifier. These maps are
    reference-test certificates, not self-authenticating file authority. Every
    consumer verifies matching type/signature/layout properties again.
    """
    def __init__(self, functions=None, imports=None, layouts=None, nominals=None, actions=None, symbols=None,
                 cleanup_programs=None, storage_bindings=None, abi_signatures=None, bridges=None, tls=None, abi_masks=None,
                 host_descriptors=None, nominal_equal=None, source_layout=None, source_compatible=None):
        self.functions = functions or {}
        self.imports = imports or {}
        self.layouts = layouts or {}
        self.nominals = nominals or {}
        self.actions = actions or {}
        self.symbols = symbols or {}
        self.cleanup_programs = cleanup_programs or {}
        self.storage_bindings = storage_bindings or {}
        self.abi_signatures = abi_signatures or {}
        self.bridges = bridges or {}
        self.tls = tls or {}
        self.abi_masks = abi_masks or {}
        self.host_descriptors = host_descriptors or {}
        self.nominal_equal = nominal_equal
        self.source_layout = source_layout
        self.source_compatible = source_compatible

    def __deepcopy__(self, memo):
        """Isolate certificates while retaining original source callback owners."""
        from copy import deepcopy
        result = type(self).__new__(type(self))
        memo[id(self)] = result
        memo[id(self.__dict__)] = result.__dict__
        callbacks = ('nominal_equal', 'source_layout', 'source_compatible')
        for name in callbacks:
            value = getattr(self, name)
            if value is not None:
                memo[id(value)] = value
        for name, value in self.__dict__.items():
            result.__dict__[name] = value if name in callbacks else deepcopy(value, memo)
        return result

    def layout(self, reference, execution_type, size, types):
        require(key(reference) in self.layouts, 'abi_layout_reference')
        layout = self.layouts[key(reference)]
        require(set(layout) == {'id', 'type', 'size', 'alignment', 'access_bytes', 'fields', 'element', 'stride'}, 'execution_layout_shape')
        require(types.equal(layout['type'], execution_type), 'abi_layout_type')
        require(type(layout['size']) is int and 0 <= layout['size'] < 2**64
                and type(layout['access_bytes']) is int and layout['access_bytes'] == size
                and 0 <= size <= layout['size'] and power2(layout['alignment']), 'abi_layout_extent')
        item = types.get(execution_type)
        if item['kind'] in {'int', 'raw', 'float', 'data_ptr', 'code_ptr', 'code_address'}:
            require(size == (types.width(execution_type) + 7) // 8, 'abi_scalar_access')
        elif item['kind'] == 'struct':
            require(len(layout['fields']) == len(item['fields']), 'execution_field_layout')
        elif item['kind'] in {'array', 'vector'}:
            require(layout['element'] is not None, 'execution_element_layout')
        else:
            require(False, 'abi_opaque_memory')
        return layout

    def target(self, target, types, value_type):
        signature = target['signature']
        require(types.get(signature)['kind'] == 'function', 'call_signature')
        if target['kind'] == 'direct':
            require(key(target['function']) in self.functions, 'call_function_reference')
            require(types.equal(self.functions[key(target['function'])], signature), 'call_signature')
        elif target['kind'] == 'indirect':
            pointer = types.get(value_type(target['value']))
            require(pointer['kind'] == 'code_ptr' and types.equal(pointer['signature'], signature), 'call_indirect_signature')
        else:
            require(key(target['import']) in self.imports, 'call_import_reference')
            binding = self.imports[key(target['import'])]
            from candidate.bindings import validate
            validate(binding, types, self)
            require(types.equal(binding['signature'], signature), 'helper_binding_signature')
        return types.get(signature)


def call_types(target, operands, results, types, dependencies, value_type):
    signature = dependencies.target(target, types, value_type)
    require(len(operands) == len(signature['params']), 'call_arguments')
    require(len(results) == len(signature['results']), 'call_results')
    require(all(types.equal(value_type(value), expected)
                for value, expected in zip(operands, signature['params'])), 'call_argument_type')
    require(all(types.equal(result['type'], expected)
                for result, expected in zip(results, signature['results'])), 'call_result_type')
    return signature


def ordinary_plan(reference, execution, types, dependencies):
    """Static join of actual ABI-verified caller expectations, never a permit."""
    require(key(reference) in dependencies.abi_signatures, 'source_plan_reference')
    plan = dependencies.abi_signatures[key(reference)]
    require(plan['this_type'] is None and plan['vtt'] is False, 'source_plan_ordinary')
    require(types.get(plan['execution'])['kind'] == 'function' and
            types.equal(plan['execution'], execution), 'source_plan_execution')
    return plan


def source_call_plan(node, types, dependencies):
    source = optional(node['source_plan'])
    if source is not None:
        ordinary_plan(source, node['target']['signature'], types, dependencies)


def check_operation(operation, types, dependencies, value_type, function):
    name = operation['op']
    contract = SCHEMA['operation_contracts'][name]
    args = [value_type(value) for value in operation['operands']]
    outputs = [declaration['type'] for declaration in operation['results']]
    if type(contract['operands']) is int:
        require(len(args) == contract['operands'], 'operand_arity', name)
    if type(contract['results']) is int:
        require(len(outputs) == contract['results'], 'result_arity', name)

    def same(a, b):
        require(types.equal(a, b), 'operand_type', name)

    def scalar_kind(reference, expected):
        require(types.scalar(reference)['kind'] in expected, 'operand_class', name)

    def boolean(reference, vector_source=None):
        item = types.get(reference)
        if vector_source is not None and types.get(vector_source)['kind'] == 'vector':
            source = types.get(vector_source)
            require(item['kind'] == 'vector' and item['count'] == source['count'], 'boolean_lanes')
            item = types.get(item['element'])
        require(item['kind'] == 'int' and item['bits'] == 1, 'boolean_type')

    family = contract['family']
    if name == 'constant':
        types.literal(outputs[0], operation['literal'])
    elif name in {'copy', 'freeze'}:
        same(args[0], outputs[0])
        require(name != 'freeze' or not types.contains_value_kind(args[0], HANDLES), 'freeze_opaque')
    elif family == 'integer':
        scalar_kind(args[0], {'int'})
        same(args[0], outputs[0])
        for arg in args[1:]:
            same(arg, args[0])
        if 'flags' in operation:
            flags = operation['flags']
            allowed = {'nsw', 'nuw'} if name in {'i_add', 'i_sub', 'i_mul', 'i_shl'} else (
                {'exact'} if name in {'i_lshr', 'i_ashr', 'i_udiv', 'i_sdiv'} else set())
            require(flags == sorted(set(flags)) and set(flags) <= allowed, 'integer_flags')
        if name == 'i_bswap':
            require(types.scalar(args[0])['bits'] % 16 == 0, 'bswap_width')
        if name in {'i_popcount', 'i_bswap', 'i_bitreverse'}:
            require(not operation['zero_is_poison'], 'unused_integer_flag')
    elif name == 'icmp':
        same(args[0], args[1])
        scalar_kind(args[0], {'int', 'data_ptr', 'code_ptr', 'code_address'})
        if types.scalar(args[0])['kind'] == 'code_address':
            require(operation['predicate'] in {'eq', 'ne'}, 'code_address_predicate')
        require(operation['predicate'] in ICMP, 'predicate')
        boolean(outputs[0], args[0])
    elif name == 'select':
        same(args[1], args[2])
        same(outputs[0], args[1])
        if types.get(args[0])['kind'] == 'vector':
            require(types.get(args[1])['kind'] == 'vector', 'select_vector')
            boolean(args[0], args[1])
        else:
            boolean(args[0])
    elif name in {'extract', 'insert'}:
        current = args[0]
        require(operation['indices'], 'aggregate_index')
        for index in operation['indices']:
            item = types.get(current)
            require(item['kind'] in {'struct', 'array'}, 'aggregate_index')
            current = types.child(current, index)
        same(outputs[0], current if name == 'extract' else args[0])
        if name == 'insert':
            same(current, args[1])
    elif family == 'vector':
        vector = types.get(args[0])
        require(vector['kind'] == 'vector', 'vector_operand')
        if name == 'extract_element':
            scalar_kind(args[1], {'int'})
            require(types.get(args[1])['kind'] == 'int', 'vector_index')
            same(outputs[0], vector['element'])
        elif name == 'insert_element':
            same(args[1], vector['element'])
            require(types.get(args[2])['kind'] == 'int', 'vector_index')
            same(outputs[0], args[0])
        else:
            same(args[1], args[0])
            result = types.get(outputs[0])
            require(result['kind'] == 'vector' and len(operation['mask']) == result['count'], 'shuffle_result')
            same(result['element'], vector['element'])
            require(all(index is None or optional(index) < 2 * vector['count'] for index in operation['mask']), 'shuffle_index')
    elif family == 'cast':
        source, destination = types.scalar(args[0]), types.scalar(outputs[0])
        source_vector, dest_vector = types.get(args[0]), types.get(outputs[0])
        if name in {'trunc', 'zext', 'sext'}:
            require(source['kind'] == destination['kind'] == 'int', 'cast_type')
            require((destination['bits'] < source['bits'] if name == 'trunc'
                     else destination['bits'] > source['bits']), 'cast_width')
            require((source_vector['kind'] == dest_vector['kind'] == 'vector'
                     and source_vector['count'] == dest_vector['count'])
                    or (source_vector['kind'] != 'vector' and dest_vector['kind'] != 'vector'), 'cast_lanes')
        elif name == 'bitcast':
            require(types.width(args[0]) == types.width(outputs[0])
                    and source['kind'] in {'int', 'raw', 'float', 'data_ptr', 'code_ptr', 'code_address'}
                    and destination['kind'] in {'int', 'raw', 'float', 'data_ptr', 'code_ptr', 'code_address'}, 'bitcast_width')
            if source['kind'].endswith('ptr') or source['kind'] == 'code_address':
                require(destination['kind'] in {'raw', source['kind']}, 'bitcast_pointer')
        elif name in {'ptrtoint', 'ptrtoaddr'}:
            require(source['kind'] in {'data_ptr', 'code_ptr', 'code_address'} and destination['kind'] == 'int', 'pointer_cast')
            if name == 'ptrtoaddr':
                require(destination['bits'] == 64, 'pointer_index_width')
        else:
            require(source['kind'] == 'int' and destination['kind'] in {'data_ptr', 'code_ptr', 'code_address'}, 'pointer_cast')
        if name in {'ptrtoint', 'ptrtoaddr', 'inttoptr'}:
            require((source_vector['kind'] == dest_vector['kind'] == 'vector'
                     and source_vector['count'] == dest_vector['count'])
                    or (source_vector['kind'] != 'vector' and dest_vector['kind'] != 'vector'), 'pointer_cast_lanes')
    elif family == 'code_address':
        source, destination = types.scalar(args[0]), types.scalar(outputs[0])
        a, b = types.get(args[0]), types.get(outputs[0])
        require((a['kind'] == b['kind'] == 'vector' and a['count'] == b['count']) or
                (a['kind'] != 'vector' and b['kind'] != 'vector'), 'code_address_lanes')
        if name == 'code_bind':
            require(source['kind'] == 'code_address' and destination['kind'] == 'code_ptr', 'code_bind_type')
            ordinary_plan(operation['plan'], destination['signature'], types, dependencies)
        else:
            require(source['kind'] == 'code_ptr' and destination['kind'] == 'code_address', 'code_erase_type')
    elif family == 'pointer':
        require(types.get(outputs[0])['kind'] in {'data_ptr', 'code_ptr', 'code_address'}, 'pointer_result')
        if name == 'block_address':
            require(types.get(outputs[0])['kind'] != 'code_address', 'block_address_type')
        if name == 'ptr_offset':
            require(not operation['check_base'] or operation['inbounds'], 'pointer_check_base')
            require(types.get(args[0])['kind'] == 'data_ptr' and types.get(args[1])['kind'] == 'int'
                    and types.get(args[1])['bits'] == 64, 'pointer_offset')
            same(args[0], outputs[0])
            restricted = optional(operation['inrange'])
            require(restricted is None or restricted['lower'] <= restricted['upper'], 'inrange_bounds')
        elif name == 'address_of':
            require(key(operation['symbol']) in dependencies.symbols, 'symbol_reference')
            symbol = dependencies.symbols[key(operation['symbol'])]
            if types.get(outputs[0])['kind'] == 'code_address':
                require(symbol['kind'] in {'function', 'import', 'function_address'}, 'symbol_code_address')
                source = optional(symbol['nominal'])
                require(source is not None and key(source) in dependencies.nominals
                        and dependencies.nominals[key(source)]['kind'] == 'function', 'symbol_code_source')
                # Static obligation only: actual provider/native issuer remains
                # required; the old Machine must not manufacture an address.
                return
            definition = optional(symbol.get('definition'))
            require(not symbol.get('native_only', False) and (definition is None or definition['kind'] != 'native'),
                    'native_symbol_requires_bridge')
            if symbol['kind'] in {'function', 'import'} and types.get(symbol['execution'])['kind'] == 'function':
                pointer_type = types.get(outputs[0])
                require(pointer_type['kind'] == 'code_ptr'
                        and types.equal(pointer_type['signature'], symbol['execution']), 'symbol_code_signature')
            else:
                require(types.get(outputs[0])['kind'] == 'data_ptr', 'symbol_data_address')
    elif family in {'fp', 'fp_compare', 'fp_cast'}:
        fp_mode(operation['mode'], name)
        if family == 'fp':
            scalar_kind(args[0], {'float'})
            same(outputs[0], args[0])
            for arg in args[1:]:
                same(arg, args[0])
        elif family == 'fp_compare':
            scalar_kind(args[0], {'float'})
            same(args[0], args[1])
            boolean(outputs[0], args[0])
            require(operation['predicate'] in FCMP, 'predicate')
        else:
            scalar_kind(args[0], {'int'} if name in {'sitofp', 'uitofp'} else {'float'})
            scalar_kind(outputs[0], {'int'} if name in {'fptosi', 'fptoui', 'fptosi_sat', 'fptoui_sat'} else {'float'})
            a, b = types.get(args[0]), types.get(outputs[0])
            require((a['kind'] == b['kind'] == 'vector' and a['count'] == b['count'])
                    or (a['kind'] != 'vector' and b['kind'] != 'vector'), 'conversion_lanes')
    elif family == 'environment':
        if name in {'fenv_get', 'fenv_unpack'}:
            require(types.get(outputs[0])['kind'] == 'fenv', 'fenv_type')
            if name == 'fenv_unpack':
                require(types.get(args[0])['kind'] == 'raw' and types.width(args[0]) == 256, 'fenv_encoding_type')
                boolean(outputs[1])
        elif name == 'fenv_set':
            require(types.get(args[0])['kind'] == 'fenv', 'fenv_type')
        elif name == 'fenv_pack':
            require(types.get(args[0])['kind'] == 'fenv' and types.get(outputs[0])['kind'] == 'raw'
                    and types.width(outputs[0]) == 256, 'fenv_encoding_type')
        else:
            require(operation['flags'] == sorted(set(operation['flags']))
                    and set(operation['flags']) <= ENV_FLAGS, 'fenv_flags')
            if name == 'fenv_test':
                require(types.get(outputs[0])['kind'] == 'int' and types.get(outputs[0])['bits'] == 1, 'fenv_type')
    elif family == 'memory':
        if name == 'fence':
            require(operation['order'] in {'acquire', 'release', 'acq_rel', 'seq_cst'}
                    and operation['scope'] == 'process', 'fence_order')
            return
        require(types.get(args[0])['kind'] == 'data_ptr', 'memory_address')
        storage = operation['storage']
        dependencies.layout(storage['layout'], storage['type'], storage['bytes'], types)
        nominal, binding_ref = optional(storage['nominal']), optional(storage['abi_binding'])
        require((nominal is None) == (binding_ref is None), 'storage_nominal_binding_pair')
        if nominal is not None:
            require(key(nominal) in dependencies.nominals and key(binding_ref) in dependencies.storage_bindings,
                    'storage_binding_reference')
            binding = dependencies.storage_bindings[key(binding_ref)]
            require(binding['kind'] != 'allocation', 'storage_allocation_not_value')
            require(binding['nominal'] == nominal and binding['execution_layout'] == storage['layout']
                    and binding['access_bytes'] == storage['bytes'], 'storage_binding_match')
        mode = operation['mode']
        require(power2(mode['alignment']) and mode['scope'] == 'process'
                and mode['order'] in ORDERS, 'memory_mode')
        if nominal is not None:
            require(mode['alignment'] >= binding['required_alignment'], 'storage_binding_alignment')
        atomic = name.startswith('atomic_') or name == 'cmpxchg'
        if mode['elementwise']:
            require(name in {'atomic_load', 'atomic_store', 'atomic_rmw'}
                    and types.get(storage['type'])['kind'] == 'vector' and mode['order'] != 'seq_cst', 'elementwise_atomic')
            vector = types.get(storage['type'])
            require(power2(types.width(storage['type'])) and types.width(storage['type']) >= 8
                    and power2(types.width(vector['element'])) and types.width(vector['element']) >= 8, 'elementwise_width')
        elif not atomic:
            require(not mode['elementwise'], 'elementwise_ordinary')
        if not atomic:
            require(mode['order'] == mode['failure_order'] == 'none', 'ordinary_order')
        elif name == 'atomic_load':
            require(mode['order'] in {'unordered', 'relaxed', 'acquire', 'seq_cst'}, 'atomic_load_order')
        elif name == 'atomic_store':
            require(mode['order'] in {'unordered', 'relaxed', 'release', 'seq_cst'}, 'atomic_store_order')
        else:
            require(mode['order'] in {'relaxed', 'acquire', 'release', 'acq_rel', 'seq_cst'}, 'atomic_rmw_order')
        if name == 'cmpxchg':
            require(mode['failure_order'] in {'relaxed', 'acquire', 'seq_cst'}, 'cas_failure_order')
            boolean(outputs[1])
        else:
            require(mode['failure_order'] == 'none', 'failure_order_unused')
        if atomic:
            require(storage['bytes'] > 0, 'atomic_extent')
        for argument in args[1:]:
            same(argument, storage['type'])
        if outputs:
            same(outputs[0], storage['type'])
        if name == 'atomic_rmw':
            require(operation['action'] in RMW, 'atomic_action')
            action = operation['action']
            scalar = types.scalar(storage['type'])
            require((action == 'exchange' and (scalar['kind'] in {'int', 'float', 'data_ptr', 'code_ptr', 'code_address'}
                    or types.get(storage['type'])['kind'] == 'raw' and types.width(storage['type']) == 8))
                    or (action.startswith('f') and scalar['kind'] == 'float')
                    or (not action.startswith('f') and action != 'exchange' and scalar['kind'] == 'int'), 'atomic_action_type')
    elif family == 'memory_bulk':
        require(types.get(args[0])['kind'] == 'data_ptr' and types.get(args[2])['kind'] == 'int'
                and types.get(args[2])['bits'] == 64 and power2(operation['alignment']), 'bulk_memory')
        if name == 'memset':
            require(types.get(args[1])['kind'] == 'int' and types.get(args[1])['bits'] == 8, 'memset_byte')
        else:
            same(args[0], args[1])
    elif family == 'call':
        require(operation['unwind'] in {'nounwind', 'propagate'}, 'call_unwind_policy')
        call_types(operation['target'], operation['operands'], operation['results'], types, dependencies, value_type)
        source_call_plan(operation, types, dependencies)
    elif family == 'helper':
        require(operation['helper']['kind'] == 'import', 'helper_target')
        signature = dependencies.target(operation['helper'], types, value_type)
        binding = dependencies.imports[key(operation['helper']['import'])]
        helper_name = {'alloca': 'stack_alloc', 'setjmp': 'setjmp_capture', 'longjmp': 'longjmp_restore'}.get(name, name)
        require(binding['kind'] == 'internal' and binding['name'] == helper_name
                and binding['namespace'] == 'smir.internal.v1', 'helper_name')
        if name == 'alloca':
            require(len(signature['params']) == 2 and len(signature['results']) == 1
                    and types.equal(args[0], signature['params'][0])
                    and types.get(signature['params'][1])['kind'] == 'int'
                    and types.get(signature['params'][1])['bits'] == 64
                    and types.equal(outputs[0], signature['results'][0]), 'alloca_helper_signature')
        else:
            call_types(operation['helper'], operation['operands'], operation['results'], types, dependencies, value_type)
        require(operation['alignment'] == 0 or power2(operation['alignment']), 'helper_alignment')
        require(name != 'alloca' or operation['alignment'] > 0, 'alloca_alignment')
        nominal = optional(operation['binding'])
        if name != 'tls_address':
            require(nominal is None or key(nominal) in dependencies.nominals, 'helper_nominal')
        else:
            require(nominal is not None and binding['options']['target'] == operation['binding'], 'tls_binding')
    elif family == 'exception':
        if name == 'landingpad':
            require(types.get(args[0])['kind'] == 'exception'
                    and types.get(outputs[0])['kind'] == 'int' and types.get(outputs[0])['bits'] == 32, 'landingpad_type')
        elif name in {'catch_begin', 'catch_end'}:
            require(types.get(args[0])['kind'] == 'exception', 'catch_type')
            require(operation['helper']['kind'] == 'import', 'catch_helper')
            call_types(operation['helper'], operation['operands'], operation['results'], types, dependencies, value_type)
            binding = dependencies.imports[key(operation['helper']['import'])]
            expected_name = {'catch_begin': 'eh_begin_catch', 'catch_end': 'eh_end_catch'}[name]
            require(binding['kind'] == 'internal' and binding['name'] == expected_name, 'catch_helper')
        else:
            require(operation['action'] in {'construct_begin', 'construct_commit', 'destroy_begin',
                                           'destroy_commit', 'ownership_transfer', 'retain', 'release'}, 'journal_action')
            require(key(operation['program']) in dependencies.cleanup_programs, 'journal_program')
            require(operation['helper']['kind'] == 'import', 'journal_helper')
            call_types(operation['helper'], operation['operands'], operation['results'], types, dependencies, value_type)
            binding = dependencies.imports[key(operation['helper']['import'])]
            require(binding['kind'] == 'internal' and binding['name'] == 'journal_advance'
                    and binding['contract'] == operation['action']
                    and binding['abi'] == {'some': operation['program']}, 'journal_helper_binding')
