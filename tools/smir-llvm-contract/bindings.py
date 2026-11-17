"""Resolved contract bindings. Does not emit or execute an LLVM/SMIR module."""
import copy
import hashlib
import json
from pathlib import Path

from canonical import require

ROOT = Path(__file__).resolve().parents[2]
PORTABLE = ROOT / 'docs/specifications/smir/portable'
CORE = {
    'return': ([], ['return']),
    'branch': ([], ['jump', 'cbranch', 'switch']),
    'integer': (['i_add','i_sub','i_mul','i_and','i_or','i_xor','i_shl','i_lshr','i_ashr'], []),
    'division': (['i_udiv','i_sdiv','i_urem','i_srem'], []),
    'fp': (['fp_add','fp_sub','fp_mul','fp_div','fp_frem','fp_fma','fp_sqrt','fp_neg','fcmp',
            'sitofp','uitofp','fptosi','fptoui','fpconvert'], []),
    'memory': (['load','store','alloca','lifetime_start','lifetime_end','stack_save','stack_restore'], []),
    'gep': (['ptr_offset'], []),
    'atomic': (['atomic_load','atomic_store','atomic_rmw','cmpxchg','fence'], []),
    'integer-cast': (['trunc','zext','sext'], []),
    'pointer': (['bitcast','ptrtoint','ptrtoaddr','inttoptr'], []),
    'compare': (['icmp'], []), 'phi': ([], []),
    'call': (['call'], ['tailcall']), 'select': (['select'], []),
    'freeze': (['freeze'], []),
    'aggregate': (['extract','insert','extract_element','insert_element','shuffle'], []),
    'varargs': (['va_start','va_arg','va_copy','va_end'], []),
    'logical-eh': (['landingpad','catch_begin','catch_end','journal'],
                   ['invoke','throw','rethrow','resume','cleanup_return','terminate']),
    'ub': ([], ['unreachable']),
}
ADDITIONAL_CORE = {
    'fenv_snapshot': ['fenv_get','fenv_set','fenv_pack','fenv_unpack','fenv_clear','fenv_raise','fenv_test'],
    'opaque_effect': ['effect_barrier'],
}
ADDITIONAL_TERMINATORS = {'terminal_diagnostic': ['trap']}

# These are exact currently published catalog names. Direct core operators do
# not require implicit guest helper imports; this map is for explicit libcalls /
# expanded imports, with exact options checked before invocation.
EXPLICIT = {
    'memory.intrinsic': ['memory_copy','memory_move','memory_set'],
    'stack.intrinsic': ['stack_alloc','stack_save','stack_restore'],
    'lifetime.intrinsic': ['lifetime_start','lifetime_end'],
    'tls.intrinsic': ['tls_address_raw','tls_address','tls_initialize'],
    'fenv.intrinsic': ['fenv_get','fenv_set','fenv_clear','fenv_raise','fenv_test'],
    'varargs.intrinsic': ['va_start','va_arg','va_copy','va_end','varargs_pack'],
    'eh.intrinsic': ['eh_allocate','eh_object_address','eh_raise','eh_search','eh_cleanup',
        'eh_catch_object','eh_begin_catch','eh_end_catch','eh_rethrow','eh_rethrow_current','eh_resume',
        'eh_retain','eh_release','eh_current','eh_current_owner','eh_owner_retain','eh_owner_release',
        'eh_owner_rethrow','eh_uncaught_exceptions','eh_set_terminate','eh_get_terminate',
        'eh_terminate','eh_forced_unwind'],
    'pointer.intrinsic': ['pointer_expose','pointer_recover'],
    'nonlocal': ['setjmp_capture','longjmp_restore'],
    'atomic_flag': ['atomic_flag_test','atomic_flag_test_and_set','atomic_flag_clear'],
    'completed_object': ['journal_begin','journal_detach','journal_adopt_child',
        'journal_claim_partial','journal_fail_partial','journal_publish_object','journal_claim_destroy'],
}


def strict_json(text):
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, 'LLVM_JSON_DUPLICATE_KEY')
            result[name] = value
        return result

    def nonfinite(_):
        require(False, 'LLVM_JSON_NONFINITE')

    return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)


def catalog_digest(value):
    require(type(value) is dict and 'digest' not in value, 'LLVM_CATALOG_SELF_DIGEST')
    canonical = json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False).encode('ascii')
    return hashlib.sha256(b'SMIR-HELPERS-V1\0' + canonical).hexdigest()


def catalog():
    value = strict_json((PORTABLE / 'schema/runtime/helpers-v1.json').read_text())
    names = [record['name'] for record in value['records']]
    require(len(names) == len(set(names)), 'LLVM_CATALOG_DUPLICATE_HELPER')
    return value, {record['name']: record for record in value['records']}


def instantiate(record, type_parameters, resolve_type=None, contract=None, *, journal_captures=None):
    """Return exact resolved logical signature from typeN catalog templates."""
    require(type(type_parameters) is list and len(type_parameters) == len(record['type_parameters']),
            'LLVM_HELPER_TYPE_ARITY')
    require(record['signature_cc'] == 'portable' and record['variadic'] is False,
            'LLVM_HELPER_CC')

    def resolve(name):
        if name.startswith('type'):
            index = int(name[4:])
            require(index < len(type_parameters), 'LLVM_HELPER_TYPE_INDEX')
            return copy.deepcopy(type_parameters[index])
        if name == 'code_ptr' and 'actual_code_ptr_signature_portable_fixed_void_noargs' in record.get('semantic_checks', []):
            return {'kind':'code_ptr','signature':{'kind':'function','cc':'portable','variadic':False,
                    'params':[],'results':[],'param_noundef':[],'result_noundef':[]}}
        return {'builtin': name}

    def element(value):
        reference=value['element']
        if type(reference) is dict and 'kind' in reference:
            return reference
        require(resolve_type is not None,'LLVM_HELPER_ELEMENT_RESOLVER')
        return resolve_type(reference)

    def floating(value):
        return value.get('kind') == 'float' and value.get('format') in (
            'binary16','bfloat16','binary32','binary64','binary128')

    def integer(value):
        return value.get('kind') == 'int' and type(value.get('bits')) is int and 1 <= value['bits'] <= 2**23

    def vector(value, predicate):
        return value.get('kind') == 'vector' and type(value.get('count')) is int and \
            1 <= value['count'] <= 65535 and predicate(element(value))

    for constraint, supplied in zip(record['type_parameters'], type_parameters):
        require(type(supplied) is dict, 'LLVM_HELPER_TYPE')
        if constraint == 'float':
            require(floating(supplied), 'LLVM_HELPER_FLOAT')
        elif constraint == 'floating_value':
            require(floating(supplied) or vector(supplied,floating),'LLVM_HELPER_FLOATING_VALUE')
        elif constraint in ('integer', 'int'):
            require(integer(supplied), 'LLVM_HELPER_INTEGER')
        elif constraint == 'integer_value':
            require(integer(supplied) or vector(supplied,integer),'LLVM_HELPER_INTEGER_VALUE')
        elif constraint == 'storage_value':
            require(supplied.get('kind') in ('int','raw','float','data_ptr','code_ptr','vector','array','struct'), 'LLVM_HELPER_STORAGE')
        elif constraint == 'pointer':
            require(supplied.get('kind') in ('data_ptr','code_ptr'), 'LLVM_HELPER_POINTER')
        else:
            require(False, 'LLVM_HELPER_UNKNOWN_CONSTRAINT')
    if 'integer_value' in record['type_parameters']:
        first, exponent=type_parameters
        require((first.get('kind') == exponent.get('kind') == 'vector'
                 and first['count'] == exponent['count'])
                or (first.get('kind') != 'vector' and exponent.get('kind') != 'vector'),
                'LLVM_HELPER_EXPONENT_LANES')
    if contract is not None:
        require(contract in record['contracts'],'LLVM_HELPER_CONTRACT')
        if contract == 'c_fenv' and record['policy'] == 'libm':
            require(all(value.get('kind') != 'vector' for value in type_parameters),
                    'LLVM_HELPER_SOURCE_LIBM_SCALAR')
    templates = [p for p in record['params'] if p['type'] == 'journal_captures']
    require(not any(p['type'] == 'journal_captures' for p in record['results']), 'LLVM_JOURNAL_TEMPLATE')
    if templates:
        selected_contract = contract if contract is not None else 'default'
        require(len(templates) == 1 and namespace_plan(record, selected_contract)['abi'] == 'journal'
                and templates[0]['noundef'] is False, 'LLVM_JOURNAL_TEMPLATE')
        require(type(journal_captures) is list, 'LLVM_JOURNAL_CAPTURE_METADATA')
        require(len(journal_captures) <= 65536, 'LLVM_JOURNAL_CAPTURE_RESOURCE')
        require(all(type(value) is dict and value.get('kind') not in (None, 'function')
                    for value in journal_captures), 'LLVM_JOURNAL_CAPTURE_TYPE')
    else:
        require(journal_captures is None, 'LLVM_JOURNAL_UNUSED_CAPTURES')
    params, noundef = [], []
    for parameter in record['params']:
        if parameter['type'] == 'journal_captures':
            params.extend(copy.deepcopy(journal_captures))
            noundef.extend([False] * len(journal_captures))
        else:
            params.append(resolve(parameter['type']))
            noundef.append(parameter['noundef'])
    return {'cc': 'portable', 'variadic': False,
            'params': params,
            'results': [resolve(p['type']) for p in record['results']],
            'param_noundef': noundef,
            'result_noundef': [p['noundef'] for p in record['results']]}


def journal_capture_types(program, resolve_nominal, resolve_execution):
    """Read ACTUALLY admitted ordered ABI formals, never infer from numeric IDs.

    Resolvers must belong to the SAME immutable admitted RootContext/ABI graph.
    This template reader grants no journal/factory/runtime authority. O(P) calls
    and descriptor space excluding actual type-graph verification/copy work.
    """
    require(type(program) is dict and type(program.get('params')) is list,
            'LLVM_JOURNAL_CAPTURE_METADATA')
    require(len(program['params']) <= 65536, 'LLVM_JOURNAL_CAPTURE_RESOURCE')
    result = []
    for formal in program['params']:
        source = resolve_nominal(formal['type'])
        require(type(source) is dict and type(source.get('execution')) is dict
                and set(source['execution']) == {'some'}, 'LLVM_JOURNAL_CAPTURE_EXECUTION')
        value = resolve_execution(source['execution']['some'])
        require(type(value) is dict and value.get('kind') not in (None, 'function'),
                'LLVM_JOURNAL_CAPTURE_TYPE')
        result.append(copy.deepcopy(value))
    return result


def namespace_plan(record, contract):
    """Resolve only the closed catalog table names; entity admission is external."""
    require(contract in record['contracts'], 'LLVM_HELPER_CONTRACT')
    contracts = set(record['contracts'])
    abi, target = record.get('abi_namespace'), record.get('target_namespace')
    require(type(abi) is dict and set(abi) == contracts and type(target) is dict
            and set(target) == contracts, 'LLVM_HELPER_NAMESPACE_MAP')
    require(set(abi.values()) <= {'none','nominal','signature','bridge','journal','recipe',
                                 'storage_binding','optional_storage_binding'}
            and set(target.values()) <= {'none','nominal','signature','bridge','journal','recipe','tls','storage_layout'},
            'LLVM_HELPER_NAMESPACE')
    # R018 has required and optional contexts in one helper's closed contract
    # map. The old summary bool cannot determine per-contract admission.
    require(type(record['abi_required']) is bool, 'LLVM_HELPER_ABI_REQUIRED')
    return {'abi':abi[contract], 'target':target[contract]}


def bind_context(record, contract, abi, target, resolve):
    """resolve(namespace, ref) MUST obtain an actually admitted table record.

    This namespace adapter cannot establish ABI relation/lifetime authority.
    It deliberately never falls back to another table for a missing integer ID.
    """
    plan = namespace_plan(record,contract)
    result = {}
    for field, reference in [('abi',abi),('target',target)]:
        namespace=plan[field]
        optional = namespace == 'optional_storage_binding'
        if optional and reference is None:
            result[field]=None
        elif namespace == 'none':
            require(reference is None,'LLVM_HELPER_UNUSED_'+field.upper())
            result[field]=None
        else:
            require(reference is not None,'LLVM_HELPER_REQUIRED_'+field.upper())
            result[field]=resolve('storage_binding' if optional else namespace,reference)
            require(result[field] is not None,'LLVM_HELPER_ENTITY')
    return result


def core_bindings():
    schema = json.loads((PORTABLE / 'schema/execution/candidate.json').read_text())
    function_fields = dict(schema['records']['function']['fields'])
    require(function_fields.get('abi_signature') == 'opt:entity_ref' and 'nominal' not in function_fields,
            'LLVM_FUNCTION_ABI_NAMESPACE')
    operations = schema['records']['operation']['variants']
    terminators = schema['records']['terminator']['variants']
    for family, (ops, terms) in CORE.items():
        require(set(ops) <= operations.keys(), 'LLVM_CORE_OPERATION:' + family)
        require(set(terms) <= terminators.keys(), 'LLVM_CORE_TERMINATOR:' + family)
    for family, ops in ADDITIONAL_CORE.items():
        require(set(ops) <= operations.keys(), 'LLVM_CORE_OPERATION:' + family)
    for family, terms in ADDITIONAL_TERMINATORS.items():
        require(set(terms) <= terminators.keys(), 'LLVM_CORE_TERMINATOR:' + family)
    for stem, plan in constrained_math_bindings().items():
        require(set(plan['core']) <= operations.keys(),'LLVM_CONSTRAINED_CORE:'+stem)
    catalog_value, records = catalog()
    require('mode_only' in records['fenv_set']['contracts'],'LLVM_FENV_MODE_CONTRACT')
    context_namespaces={}
    for name, record in records.items():
        context_namespaces[name]={contract:namespace_plan(record,contract)
                                  for contract in record['contracts']}
    for family, names in EXPLICIT.items():
        require(set(names) <= records.keys(), 'LLVM_EXPLICIT_HELPER:' + family)
    return {'revision': 'llvm-candidate-bindings-v1',
            'core': {family: {'operations': ops, 'terminators': terms,
                             'helper_import_required': False}
                     for family, (ops, terms) in CORE.items()},
            'explicit_imports': EXPLICIT, 'math': math_bindings(),
            'constrained_math': constrained_math_bindings(),
            'additional_core': ADDITIONAL_CORE,
            'additional_terminators': ADDITIONAL_TERMINATORS,
            'catalog_digest': catalog_digest(catalog_value),
            'context_namespaces': context_namespaces,
            'function_abi_namespace': 'section10 call_signature via abi_signature; function_type separately resolves nominal_type',
            'environment_words': {'integer_bits':64,'environment_mask':0xC3F,'mode_mask':0xC00,
                'source_round_codes':{'nearest_even':0,'downward':0x400,'upward':0x800,'toward_zero':0xC00},
                'LLVM_FLT_ROUNDS':{'toward_zero':0,'nearest_even':1,'upward':2,'downward':3},
                'set_environment':'fenv_set/default','set_mode_rounding':'fenv_set/mode_only',
                'private_diagnostics_serialized':False},
            'catalog_artifact_sha256': hashlib.sha256((PORTABLE/'schema/runtime/helpers-v1.json').read_bytes()).hexdigest(),
            'site_artifact_sha256': hashlib.sha256((PORTABLE/'schema/abi/site.json').read_bytes()).hexdigest(),
            'site_identity': hashlib.sha256(json.dumps(json.loads((PORTABLE/'schema/abi/site.json').read_text()), sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'context': 'Explicit internal imports bind exact runtime_helper_options; direct core op attrs define profile semantics; no ambiguous helper name lookup.',
            'dependency_ref': 'self or dependency slot; dependency entity IDs are consumer declarations; deployment publishes complete SCC before execution'}


def math_bindings():
    """Exact generic FP intrinsic to core/helper plan; shape checked at pin."""
    from contracts import MATH
    aliases = {'fabs':'fp_abs', 'fmuladd':'fp_fma',
               'fptosi_sat':'fp_to_signed_sat', 'fptoui_sat':'fp_to_unsigned_sat',
               'fptrunc_round':'fp_convert'}
    compound = {
        'powi': {'helpers':[], 'core':['freeze','i_sub','i_and','i_lshr','icmp','cbranch','fp_mul','fp_div'],
                 'algorithm':'freeze exponent once before control use; unsigned abs modulo source width, square-and-multiply in source FP semantics, reciprocal for negative exponent; width1 special-case avoids overshift',
                 'precondition':'mandatory legalize before any LLVM optimization/LTO at this pin; preserve full exponent width'},
        'ldexp': {'helpers':['fp_ldexp'],'core':['sext','trunc','icmp','select'],
                  'integer_mapping':'helper generic integer template preserves full exponent; i32-only backend alternative requires signed saturation, never truncation'},
        'frexp': {'helpers':['fp_frexp'],'core':['trunc','sext'],
                  'integer_mapping':'helper i32 finite exponent, explicit signed extension/truncation to exact result width; NaN/Inf exponent choose concrete0 as pinned ConstantFolding'},
        'is_fpclass': {'helpers':[], 'core':['bitcast','i_and','i_lshr','icmp','select'],
                       'predicate':'ten-bit FPClassTest; bitwise NaN classification never raises invalid'},
    }
    _, records = catalog()
    result = {}
    for stem in sorted(MATH):
        if stem in compound:
            result[stem] = compound[stem]
        else:
            name = aliases.get(stem, 'fp_' + stem)
            require(name in records, 'LLVM_MATH_HELPER:' + name)
            result[stem] = {'helpers':[name], 'core':[], 'errno':'preserve for LLVM intrinsic',
                            'helper_contract':'llvm_default',
                            'options':'explicit source rounding/exceptions/predicate, no ambient host state'}
    for plan in result.values():
        require(set(plan['helpers']) <= records.keys(), 'LLVM_MATH_HELPER')
    return result


CONSTRAINED = set('''acos asin atan atan2 ceil cos cosh exp exp2 fadd fcmp fcmps
fdiv floor fma fmul fmuladd fpext fptosi fptoui fptrunc frem fsub ldexp llrint
llround log log10 log2 lrint lround maximum maxnum minimum minnum nearbyint pow
powi rint round roundeven sin sinh sitofp sqrt tan tanh trunc uitofp'''.split())


def constrained_math_bindings():
    core = {name:'fp_'+name[1:] for name in ('fadd','fsub','fmul','fdiv','frem')}
    core.update({'frem':'fp_frem','fma':'fp_fma','fmuladd':'fp_fma','sqrt':'fp_sqrt',
                 'fcmp':'fcmp','fcmps':'fcmp','fpext':'fpconvert','fptrunc':'fpconvert',
                 'fptosi':'fptosi','fptoui':'fptoui','sitofp':'sitofp','uitofp':'uitofp',
                 'maximum':'fp_maximum','minimum':'fp_minimum',
                 'maxnum':'fp_maxnum','minnum':'fp_minnum'})
    _, helpers=catalog()
    plans={}
    for stem in sorted(CONSTRAINED):
        plan={'source':'llvm.experimental.constrained.'+stem,
              'core':[core[stem]] if stem in core else [],
              'helpers':[] if stem in core else ['fp_'+stem],
              'helper_contract':'constrained' if stem not in core else None,
              'exceptions':'exact source metadata; flags+diagnostic before one source-op result commit',
              'rounding':'fixed by opcode' if stem in {'ceil','floor','trunc','round','roundeven','lround','llround'}
                         else 'exact source metadata if present; exact conversions/compare have no rounding effect',
              'vector':stem not in {'lrint','llrint','lround','llround'},
              'vector_frontier':'union executed lane flags before single diagnostic/result commit; no scalar helper prefix publication',
              'errno':'preserve'}
        if stem in {'fcmp','fcmps'}:
            plan['signaling']=stem=='fcmps'
        if stem=='powi':
            plan['exponent_bits']=32
            plan['legalization']='preserve constrained i32 intrinsic metadata through optimization, then helper; ordinary wide power has separate mandatory preopt expansion'
        for name in plan['helpers']:
            require(name in helpers,'LLVM_CONSTRAINED_HELPER:'+name)
        plans[stem]=plan
    return plans
