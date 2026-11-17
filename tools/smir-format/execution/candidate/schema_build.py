"""Owned generator for exact candidate ordered records and operation contracts."""
import json
from pathlib import Path


def schema():
    records = {}

    def fixed(name, fields):
        records[name] = {'fields': fields}

    def union(name, discriminator, variants):
        records[name] = {'discriminator': discriminator, 'variants': variants}

    union('module_ref', 'kind', {'self': [], 'dependency': [['slot', 'u32']]})
    fixed('entity_ref', [['module', 'module_ref'], ['id', 'u32']])
    fixed('decl', [['id', 'u32'], ['type', 'entity_ref']])
    fixed('execution_types', [['payload_revision', 'u32'], ['types', 'vec:type'], ['memory_layouts', 'vec:execution_memory_layout']])
    fixed('execution_memory_layout', [['id', 'u32'], ['type', 'entity_ref'], ['size', 'u64'], ['alignment', 'u32'],
                                      ['access_bytes', 'u64'], ['fields', 'vec:execution_memory_field'],
                                      ['element', 'opt:entity_ref'], ['stride', 'u64']])
    fixed('execution_memory_field', [['value_index', 'u32'], ['bit_offset', 'u64'],
                                     ['bit_width', 'u64'], ['layout', 'entity_ref']])
    variants = {}
    for kind in ['int', 'raw']:
        variants[kind] = [['id', 'u32'], ['bits', 'u32']]
    variants['float'] = [['id', 'u32'], ['format', 'token']]
    variants['data_ptr'] = [['id', 'u32'], ['space', 'token']]
    variants['code_ptr'] = [['id', 'u32'], ['signature', 'entity_ref']]
    variants['code_address'] = [['id', 'u32']]
    for kind in ['array', 'vector']:
        variants[kind] = [['id', 'u32'], ['element', 'entity_ref'], ['count', 'u64']]
    variants['struct'] = [['id', 'u32'], ['fields', 'vec:entity_ref']]
    variants['function'] = [['id', 'u32'], ['params', 'vec:entity_ref'], ['results', 'vec:entity_ref'],
                            ['variadic', 'bool'], ['param_noundef', 'vec:bool'],
                            ['result_noundef', 'vec:bool'], ['cc', 'token']]
    for kind in ['exception', 'fenv', 'stack_mark', 'va_list', 'journal']:
        variants[kind] = [['id', 'u32']]
    union('type', 'kind', variants)
    fixed('execution_functions', [['payload_revision', 'u32'], ['functions', 'vec:function']])
    fixed('function', [['id', 'u32'], ['signature', 'entity_ref'], ['abi_signature', 'opt:entity_ref'],
                       ['params', 'vec:decl'], ['entry', 'u32'], ['escape', 'token'],
                       ['no_return', 'bool'], ['blocks', 'vec:block']])
    fixed('block', [['id', 'u32'], ['phis', 'vec:phi'], ['ops', 'vec:operation'], ['term', 'terminator']])
    fixed('phi', [['result', 'decl'], ['incoming', 'vec:incoming']])
    fixed('incoming', [['predecessor', 'u32'], ['value', 'u32']])
    union('literal', 'kind', {'bits': [['value', 'hex']], 'aggregate': [['elements', 'vec:literal']],
                              'zero': [], 'poison': [], 'undef': []})
    fixed('fp_mode', [['environment', 'token'], ['rounding', 'token'], ['exceptions', 'token']])
    fixed('memory_mode', [['alignment', 'u32'], ['volatile', 'bool'], ['order', 'token'],
                          ['failure_order', 'token'], ['scope', 'token'], ['elementwise', 'bool']])
    fixed('storage', [['type', 'entity_ref'], ['layout', 'entity_ref'], ['nominal', 'opt:entity_ref'],
                       ['abi_binding', 'opt:entity_ref'], ['bytes', 'u64']])
    union('target', 'kind', {
        'direct': [['function', 'entity_ref'], ['signature', 'entity_ref']],
        'indirect': [['value', 'u32'], ['signature', 'entity_ref']],
        'import': [['import', 'entity_ref'], ['signature', 'entity_ref']]})
    base = [['results', 'vec:decl'], ['operands', 'vec:u32']]
    operations = {}
    contracts = {}

    def operation(name, fields=(), arity=0, results=1, family='pure', effect='none'):
        operations[name] = base + list(fields)
        contracts[name] = {'operands': arity, 'results': results, 'family': family, 'effect': effect}

    operation('constant', [['literal', 'literal']])
    for name in ['copy', 'freeze']:
        operation(name, arity=1)
    for name in ['add', 'sub', 'mul', 'shl', 'lshr', 'ashr', 'udiv', 'sdiv', 'urem', 'srem',
                 'and', 'or', 'xor', 'rotl', 'rotr']:
        operation('i_' + name, [['flags', 'vec:token']], arity=2, family='integer')
    for name in ['clz', 'ctz', 'popcount', 'abs', 'bswap', 'bitreverse']:
        operation('i_' + name, [['zero_is_poison', 'bool']], arity=1, family='integer')
    operation('icmp', [['predicate', 'token']], arity=2, family='compare')
    operation('select', arity=3, family='select')
    for name in ['extract', 'insert']:
        operation(name, [['indices', 'vec:u32']], arity=1 if name == 'extract' else 2, family='aggregate')
    operation('extract_element', arity=2, family='vector')
    operation('insert_element', arity=3, family='vector')
    operation('shuffle', [['mask', 'vec:opt:u32']], arity=2, family='vector')
    for name in ['trunc', 'zext', 'sext', 'bitcast', 'ptrtoint', 'ptrtoaddr', 'inttoptr']:
        operation(name, arity=1, family='cast', effect='expose' if name == 'ptrtoint' else 'none')
    fixed('access_range', [['lower', 'i64'], ['upper', 'i64']])
    operation('ptr_offset', [['inbounds', 'bool'], ['check_base', 'bool'], ['nuw', 'bool'], ['nusw', 'bool'],
                              ['inrange', 'opt:access_range']], arity=2, family='pointer')
    operation('address_of', [['symbol', 'entity_ref']], family='pointer')
    operation('code_bind', [['plan', 'entity_ref']], arity=1, family='code_address', effect='observe_code')
    operation('code_erase', arity=1, family='code_address', effect='observe_code')
    operation('block_address', [['function', 'u32'], ['block', 'u32']], family='pointer')
    for name, count in [('add', 2), ('sub', 2), ('mul', 2), ('div', 2), ('frem', 2),
                        ('fma', 3), ('sqrt', 1), ('neg', 1), ('abs', 1), ('copysign', 2),
                        ('minimum', 2), ('maximum', 2), ('minnum', 2), ('maxnum', 2),
                        ('minimumnum', 2), ('maximumnum', 2)]:
        operation('fp_' + name, [['mode', 'fp_mode']], arity=count, family='fp', effect='fenv')
    operation('fcmp', [['predicate', 'token'], ['signaling', 'bool'], ['mode', 'fp_mode']],
              arity=2, family='fp_compare', effect='fenv')
    for name in ['sitofp', 'uitofp', 'fptosi', 'fptoui', 'fpconvert', 'fptosi_sat', 'fptoui_sat']:
        operation(name, [['mode', 'fp_mode']], arity=1, family='fp_cast', effect='fenv')
    operation('fenv_get', family='environment', effect='fenv_read')
    operation('fenv_set', arity=1, results=0, family='environment', effect='fenv_write')
    operation('fenv_pack', arity=1, family='environment', effect='none')
    operation('fenv_unpack', arity=1, results=2, family='environment', effect='none')
    for name in ['clear', 'raise', 'test']:
        operation('fenv_' + name, [['flags', 'vec:token']], results=1 if name == 'test' else 0,
                  family='environment', effect='fenv_write' if name != 'test' else 'fenv_read')
    for name, count, result_count in [('load', 1, 1), ('store', 2, 0), ('atomic_load', 1, 1),
                                      ('atomic_store', 2, 0), ('atomic_rmw', 2, 1), ('cmpxchg', 3, 2)]:
        extra = [['storage', 'storage'], ['mode', 'memory_mode']]
        if name == 'atomic_rmw':
            extra += [['action', 'token']]
        if name == 'cmpxchg':
            extra += [['weak', 'bool']]
        operation(name, extra, arity=count, results=result_count, family='memory', effect=name)
    operation('fence', [['order', 'token'], ['scope', 'token']], results=0, family='memory', effect='fence')
    operation('effect_barrier', results=0, family='effect', effect='opaque_sideeffect')
    for name, count in [('memcpy', 3), ('memmove', 3), ('memset', 3)]:
        operation(name, [['alignment', 'u32'], ['volatile', 'bool']], arity=count, results=0,
                  family='memory_bulk', effect=name)
    for name, count, result_count in [('alloca', 1, 1), ('lifetime_start', 2, 0),
                                      ('lifetime_end', 2, 0), ('stack_save', 0, 1),
                                      ('stack_restore', 1, 0), ('tls_address', 1, 1),
                                      ('va_start', 3, 0), ('va_arg', 1, 1), ('va_copy', 2, 0),
                                      ('va_end', 1, 0), ('setjmp', 1, 1), ('longjmp', 2, 0)]:
        operation(name, [['helper', 'target'], ['binding', 'opt:entity_ref'], ['alignment', 'u32']],
                  arity=count, results=result_count, family='helper', effect=name)
    operation('call', [['target', 'target'], ['unwind', 'token'], ['source_plan', 'opt:entity_ref']], arity='signature', results='signature', family='call', effect='call')
    operation('landingpad', [['region', 'u32']], arity=1, family='exception', effect='search')
    operation('catch_begin', [['handler', 'u32'], ['helper', 'target']], arity=1, family='exception', effect='catch')
    operation('catch_end', [['helper', 'target']], arity=1, results=0, family='exception', effect='catch')
    operation('journal', [['action', 'token'], ['program', 'entity_ref'], ['helper', 'target']],
              arity=3, results=0, family='exception', effect='journal')
    union('operation', 'op', operations)
    fixed('switch_case', [['value', 'hex'], ['target', 'u32']])
    fixed('normal_edge', [['target', 'u32'], ['results', 'vec:decl']])
    fixed('unwind_edge', [['target', 'u32'], ['exception', 'decl']])
    union('terminator', 'op', {
        'jump': [['target', 'u32']],
        'cbranch': [['condition', 'u32'], ['true', 'u32'], ['false', 'u32']],
        'switch': [['index', 'u32'], ['cases', 'vec:switch_case'], ['default', 'u32']],
        'indirect_branch': [['address', 'u32'], ['targets', 'vec:u32']],
        'return': [['values', 'vec:u32']],
        'tailcall': [['target', 'target'], ['operands', 'vec:u32'], ['source_plan', 'opt:entity_ref']],
        'invoke': [['target', 'target'], ['operands', 'vec:u32'], ['normal', 'normal_edge'],
                   ['unwind', 'unwind_edge'], ['region', 'u32'], ['source_plan', 'opt:entity_ref']],
        'throw': [['exception', 'u32'], ['region', 'opt:u32']],
        'rethrow': [['exception', 'u32'], ['region', 'opt:u32']],
        'resume': [['exception', 'u32'], ['region', 'opt:u32']],
        'cleanup_return': [['exception', 'opt:u32'], ['region', 'opt:u32']],
        'terminate': [['reason', 'token'], ['exception', 'opt:u32']],
        'unreachable': [], 'trap': [['reason', 'token']]})
    fixed('execution_exceptions', [['payload_revision', 'u32'], ['functions', 'vec:eh_function']])
    fixed('eh_function', [['function', 'u32'], ['actions', 'vec:execution_action'], ['regions', 'vec:region']])
    fixed('execution_action', [['id', 'u32'], ['program', 'entity_ref'], ['recipe', 'entity_ref'],
                               ['captures', 'vec:execution_capture']])
    fixed('execution_capture', [['parameter', 'u32'], ['type', 'entity_ref'], ['source', 'execution_capture_source']])
    union('execution_capture_source', 'kind', {'value': [['value', 'u32']], 'exception': [],
                                              'journal': [['program', 'entity_ref']]})
    fixed('region', [['id', 'u32'], ['parent', 'opt:u32'], ['blocks', 'vec:u32'],
                     ['exit_actions', 'vec:u32'], ['handlers', 'vec:handler'], ['escape', 'token']])
    fixed('handler', [['id', 'u32'], ['selector', 'u32'], ['kind', 'token'], ['nominal', 'opt:entity_ref'], ['entry', 'u32'],
                      ['cleanup_actions', 'vec:u32'], ['catch_copy', 'opt:u32']])
    fixed('absolute_range', [['lower', 'u64'], ['upper', 'u64'], ['upper_is_limit', 'bool'], ['empty', 'bool']])
    fixed('execution_live_value', [['type', 'entity_ref'], ['payload', 'execution_live_payload']])
    fixed('execution_origin_span', [['offset', 'u32'], ['length', 'u32'], ['object', 'opt:u64'],
                                    ['generation', 'u64'], ['pointer_bits', 'u64'], ['source_bit', 'u32'],
                                    ['domain', 'token'], ['range', 'opt:absolute_range'], ['binding_permit', 'opt:u64']])
    union('execution_live_payload', 'kind', {
        'poison': [], 'undef': [], 'scalar': [['bits', 'hex']],
        'aggregate': [['elements', 'vec:execution_live_value']],
        'raw': [['bits', 'hex'], ['poison', 'hex'], ['undef', 'hex'], ['origins', 'vec:execution_origin_span']],
        'pointer': [['address', 'u64'], ['object', 'opt:u64'], ['generation', 'u64'],
                    ['domain', 'token'], ['range', 'opt:absolute_range'], ['binding_permit', 'opt:u64']],
        'handle': [['kind_name', 'token'], ['identity', 'u64'], ['generation', 'u64']],
        'fenv': [['rounding', 'token'], ['flags', 'vec:token'], ['traps', 'vec:token']]})
    union('execution_progress', 'kind', {'elementwise': [
        ['activation', 'u64'], ['block', 'u32'], ['operation', 'u32'], ['next_lane', 'u64'],
        ['observed', 'vec:execution_live_value'], ['inputs', 'vec:execution_live_value']]})
    return {'format': 'ordered_records_candidate_v1', 'status': 'draft_pending_cross_role_acceptance',
            'roots': {'1': 'execution_types', '3': 'execution_functions', '8': 'execution_exceptions'},
            'records': records, 'operation_contracts': contracts}


if __name__ == '__main__':
    destination = Path(__file__).resolve().parents[4] / 'docs/specifications/smir/portable/schema/execution/candidate.json'
    destination.write_text(json.dumps(schema(), indent=2) + '\n')
