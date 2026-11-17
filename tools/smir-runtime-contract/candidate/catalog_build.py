#!/usr/bin/env python3
"""Exact compiler-internal helper contracts; no numeric public helper IDs."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / 'docs/specifications/smir/portable/schema/runtime/helpers-v1.json'
RECORDS = []

POLICIES = {
    'guarded_value': {
        'frontier': 'validate_and_pin_all_bytes_before_effect; publish complete typed result once',
        'shadow': 'bytes/poison/undef/pointer origins copied under same backing synchronization',
        'fault': 'fault leaves destination/result unchanged and retains original operation frontier',
        'lifetime': 'mapping/object generation checked; all virtual aliases share backing identity',
    },
    'atomic': {
        'frontier': 'one guarded byte+shadow+observed+success transaction, one ticket winner',
        'shadow': 'load/exchange preserve observed shadow; store/successful CAS copy desired shadow',
        'comparison': 'full_storage or admitted value_mask or llvm_precision; zero poison/undef compared bits per use',
        'arithmetic': 'integer modulo precision; poison significant input produces poisoned result; origin cleared except exchange',
        'order': 'success relaxed/consume/acquire/release/acq_rel/seq_cst; failure relaxed/consume/acquire/seq_cst independently',
        'progress': 'lock backed for every size; is_lock_free=false; process/shared backing broker domain',
        'width': 'any positive ABI storage size within configured resource quota, not restricted to powers of two or16B',
    },
    'bulk': {
        'frontier': 'validate/pin all spans before first effect; ticket records direction+committed bytes at chunk polls',
        'shadow': 'memcpy/memmove copy all shadow; memset transfers raw8 byte poison/undef, clears origins; defined byte clears shadow',
        'zero': 'original poison/undef length UB; defined zero length observes no pointer/value except separate argument attributes; memcpy identical spans or disjoint only',
        'commit': 'one final result frontier; never repeat already copied chunks; memmove chooses overlap-safe direction',
    },
    'allocation': {
        'frontier': 'publish object identity/address/generation only after full reservation succeeds',
        'lifetime': 'thread/activation stack or process heap owner; end/revoke closes admission and drains pins',
        'initial': 'uninitialized bytes have undef shadow; calloc defines zero; no host uninitialized bytes',
        'failure': 'heap allocation returns null and guest errno ENOMEM; stack resource failure precise resource trap',
    },
    'tls': {
        'frontier': 'stable per-thread module address; copy template/relocations before publishing initialization',
        'callbacks': 'publish suspended caller and drop runtime locks before guest initialization/destruction',
        'guard': 'uninitialized/initializing/initialized; same-thread recursion UB; abort retries block-static but namespace throw terminates',
        'raw': 'tls_address_raw returns preissued TLSbase+u64offset modulo2^64 with exactobject/gen/range, noinit/guestmemoryaccess/allocation/block/trap; everyoffset representable evenoutsidebounds, laterderefs check. LLVM usesoffset0; thread/moduleadmission reserves slots beforepublication.',
        'lease': 'TLS/initializer/destructor retains exact module generation until thread cleanup',
    },
    'fp': {
        'frontier': 'compute exact destination bits and raised flags; default LLVM operations do not alter guest fenv',
        'constrained': 'constrained/c_fenv merges sticky flags before enabled trap; result uncommitted on trap',
        'rounding': 'explicit nearest_even/nearest_away/toward_zero/upward/downward or dynamic thread rounding',
        'formats': 'binary16/bfloat16/binary32/binary64/binary128; no host long-double or default fenv substitution',
        'nan': 'execution candidate exact NaN/signaling/payload/rounding/conversion contract is authoritative',
    },
    'fenv': {
        'frontier': 'INT010rev2 thread-owned source rounding+six flags including explicit-only denorm; source traps0; private VM diagnostics separate IEEEfive',
        'raise': 'merge flags before enabled diagnostic trap; no result publication on trap',
        'migration': 'restore host environment and install thread guest environment explicitly at every boundary',
    },
    'varargs': {
        'frontier': 'ABI32B list/header, exact promoted nominal type, live thread/activation cookie and full bounds before cursor change',
        'copy': 'va_copy duplicates cursor; va_end invalidates; foreign lists require descriptor conversion',
        'failure': 'precise guest-UB diagnostic leaves cursor and destination unchanged',
    },
    'nonlocal': {
        'frontier': 'registry-bound logical snapshot with complete typed locals/shadow/allocations/journals/continuation',
        'jump': 'same process/thread/live activation/generation; zero i32 becomes1; validate cleanup before discarding frames',
        'cleanup': 'C++ invalid longjmp path is UB; admitted foreign/nonlocal recipes coordinate exact journal cleanup, never Rust unwind',
    },
    'eh': {
        'frontier': 'pure global handler search, then exactly-once reverse committed-subobject cleanup, then selected invoke edge',
        'identity': 'typed catches use admitted nominal/copy/base/qualification recipes; opaque leases only catch-all/rethrow',
        'ownership': 'exception owner module/object/type/code retained through exception_ptr/rethrow/catch destruction',
        'failure': 'noexcept/uncaught/cleanup-throw/forced-unwind policies follow admitted section10 actions',
        'private_E': 'opaque SSA only, no ordinary memory; source exception_ptr8B owner proxy to reserved readonly32B registry object, actual process/object/base/provenance/generation, not header bytes',
        'owner': 'current_owner null without ACTIVEcatch else retains once; null retain/release noop; lastrefs one outside-lock owner destructor ticket thenfree; failedconstruction never completeTdestructor',
        'rethrow': 'owner_rethrow void/raises creates fresh currentthread facade captured currentglobal handler; bare rethrow_current inherits ACTIVEcaught snapshot; nocatch invokes terminate, no normal result',
        'terminate': 'explicit selects activecaught snapshot elseglobal; implicit establishes causingcatch; logicaluncaught count; handler return/throw aborts nonrecursive; actual callable fixedportable void()',
    },
    'journal': {
        'frontier': 'ABI construction slots/elements/parents/dependencies and monotonic completion ordinal, one ticket per phase',
        'cleanup': 'only committed subobjects destroyed in reverse completion order; in-progress constructors own partial children',
        'resume': 'complete typed live checkpoint, no repeated constructor/destructor/adapter effect',
    },
    'call': {
        'frontier': 'validate module/signature/nominal/capability and publish suspended caller before any callback',
        'result': 'foreign RETURNED exposes target storage; conversion+required typed cleanup precede one portable normal commit',
        'suspend': 'retain stage, exact adapter frame, foreign CPU snapshot, journals and leases; no native-call replay',
    },
    'pointer': {
        'frontier': 'registry-issued data provenance/code token; numeric address alone confers no authority',
        'expose': 'record explicit address exposure; recover live authority only through admitted exposed object/generation/full origins; otherwise preserve non-dereferenceable numeric address',
        'pure_poison': 'pure expose/recover propagate poison; unknown/unexposed/dead inttoptr is not an eager fault; dereference/call sink validates authority',
    },
}


def helper(name, params, results, *, category, types=(), abi=False,
           contracts=('default',), effects=(), traps=(), cancel='before_commit',
           blocking='never', reentry='forbidden', guards=(), leases=()):
    RECORDS.append({
        'namespace': 'smir.internal.v1', 'name': name, 'version': 1,
        'type_parameters': list(types),
        'params': [{'name': field, 'type': kind, 'noundef': False}
                   for field, kind in params],
        'results': [{'type': kind, 'noundef': False} for kind in results],
        'abi_required': abi, 'contracts': list(contracts), 'policy': category,
        'effects': list(effects), 'traps': list(traps), 'cancellation': cancel,
        'blocking': blocking, 'reentry': reentry, 'guards': list(guards),
        'leases': list(leases), 'signature_cc': 'portable', 'variadic': False,
    })


MEM_TRAPS = ('null_address', 'range', 'alignment', 'unmapped', 'permission',
             'backing_failure', 'resource', 'invalid_provenance', 'ub_pointer_poison')
for name in ('load', 'store'):
    helper('memory_' + name, [('address', 'data_ptr')] +
           ([('value', 'type0')] if name == 'store' else []),
           ['type0'] if name == 'load' else [], category='guarded_value',
           types=['storage_value'], abi=True, contracts=('ordinary', 'volatile'),
           effects=('memory_read',) if name == 'load' else ('memory_write',),
           traps=MEM_TRAPS, guards=('entire_address_storage',), leases=('object',))
for name in ('copy', 'move', 'set'):
    helper('memory_' + name,
           [('destination', 'data_ptr'),
            ('byte', 'u8') if name == 'set' else ('source', 'data_ptr'), ('bytes', 'u64')],
           ['data_ptr'], category='bulk', contracts=('ordinary', 'volatile'),
           effects=('memory_read', 'memory_write'), traps=MEM_TRAPS + ('overlap',),
           cancel='defer_after_effect', guards=('all_source_destination_spans',), leases=('objects',))
for name, params, results in [
    ('heap_alloc', [('bytes', 'u64'), ('alignment', 'u64'), ('zero', 'i1')], ['data_ptr']),
    ('heap_realloc', [('old', 'data_ptr'), ('bytes', 'u64'), ('alignment', 'u64')], ['data_ptr']),
    ('heap_free', [('address', 'data_ptr')], []),
    ('stack_alloc', [('bytes', 'u64'), ('alignment', 'u64')], ['data_ptr']),
    ('stack_save', [], ['stack_mark']), ('stack_restore', [('mark', 'stack_mark')], []),
    ('lifetime_start', [('address', 'data_ptr'), ('bytes', 'u64')], []),
    ('lifetime_end', [('address', 'data_ptr'), ('bytes', 'u64')], []),
]:
    helper(name, params, results, category='allocation', effects=('allocation_lifetime',),
           traps=('resource', 'alignment', 'invalid_lifetime', 'wrong_activation', 'ub_invalid_free'),
           guards=('revoked_object_pins',), leases=('allocation_owner',))
for name, params, results in [
    ('tls_address', [('offset', 'u64')], ['data_ptr']),
    ('tls_initialize', [], []), ('tls_guard_acquire', [('guard', 'data_ptr')], ['i1']),
    ('tls_guard_release', [('guard', 'data_ptr')], []),
    ('tls_guard_abort', [('guard', 'data_ptr')], []),
    ('guard_acquire', [('guard', 'data_ptr')], ['i1']),
    ('guard_release', [('guard', 'data_ptr')], []), ('guard_abort', [('guard', 'data_ptr')], []),
    ('tls_destructor_register', [('code', 'code_ptr'), ('object', 'data_ptr')], []),
]:
    helper(name, params, results, category='tls', abi=True, effects=('tls_guard',),
           traps=('resource', 'invalid_tls_offset', 'ub_recursive_initialization', 'exception'),
           blocking='ready_wait' if name.endswith('acquire') else 'never',
           reentry='guest' if name == 'tls_initialize' else 'forbidden',
           cancel='defer_after_effect', guards=('guard_or_template_storage',), leases=('module_tls',))
for name, params, results in [
    ('atomic_load', [('address', 'data_ptr'), ('order', 'u32')], ['type0']),
    ('atomic_store', [('address', 'data_ptr'), ('value', 'type0'), ('order', 'u32')], []),
    ('atomic_exchange', [('address', 'data_ptr'), ('value', 'type0'), ('order', 'u32')], ['type0']),
    ('atomic_cmpxchg', [('address', 'data_ptr'), ('expected', 'type0'), ('desired', 'type0'),
                         ('success_order', 'u32'), ('failure_order', 'u32'), ('weak', 'i1')], ['type0', 'i1']),
]:
    helper(name, params, results, category='atomic', types=['storage_value'], abi=True,
           contracts=('full_storage', 'value_mask', 'llvm_precision'),
           effects=('atomic_memory',), traps=MEM_TRAPS + ('order', 'scope', 'comparison_mask'),
           guards=('one_alias_domain_bytes_and_shadow',), leases=('backing',))
for operation in ('add', 'sub', 'and', 'or', 'xor', 'nand', 'smin', 'smax', 'umin', 'umax'):
    helper('atomic_fetch_' + operation,
           [('address', 'data_ptr'), ('value', 'type0'), ('order', 'u32')], ['type0'],
           category='atomic', types=['integer'], abi=True, contracts=('llvm_precision',),
           effects=('atomic_memory',), traps=MEM_TRAPS + ('order', 'scope'),
           guards=('one_alias_domain_bytes_and_shadow',), leases=('backing',))
helper('atomic_fence', [('order', 'u32')], [], category='atomic',
       effects=('atomic_order',), traps=('order', 'scope'))
helper('atomic_is_lock_free', [('bytes', 'u64'), ('address', 'data_ptr')], ['i1'],
       category='atomic', contracts=('always_false',), traps=())
for operation, arity in [('add', 2), ('sub', 2), ('mul', 2), ('div', 2), ('fma', 3),
                          ('sqrt', 1), ('frem', 2), ('neg', 1), ('abs', 1), ('copysign', 2),
                          ('minimum', 2), ('maximum', 2), ('minnum', 2), ('maxnum', 2)]:
    helper('fp_' + operation, [('operand' + str(i), 'type0') for i in range(arity)], ['type0'],
           category='fp', types=['float'], contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags',), traps=('fp_enabled',))
for name, types, params, results in [
    ('fp_convert', ['float', 'float'], [('value', 'type0')], ['type1']),
    ('fp_to_signed', ['float', 'integer'], [('value', 'type0')], ['type1']),
    ('fp_to_unsigned', ['float', 'integer'], [('value', 'type0')], ['type1']),
    ('fp_from_signed', ['integer', 'float'], [('value', 'type0')], ['type1']),
    ('fp_from_unsigned', ['integer', 'float'], [('value', 'type0')], ['type1']),
    ('fp_compare', ['float'], [('left', 'type0'), ('right', 'type0')], ['i1']),
]:
    helper(name, params, results, category='fp', types=types,
           contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags',), traps=('fp_enabled',))
for name, params, results in [
    ('fenv_get', [], ['fenv']), ('fenv_set', [('environment', 'fenv')], []),
    ('fenv_test', [('mask', 'u32')], ['u32']), ('fenv_clear', [('mask', 'u32')], ['u32']),
    ('fenv_raise', [('mask', 'u32')], []),
]:
    helper(name, params, results, category='fenv', effects=('thread_fenv',),
           traps=('invalid_fenv', 'fp_enabled'))
for name, params, results, types in [
    ('va_start', [('list', 'data_ptr'), ('arena', 'data_ptr'), ('extent', 'u64')], [], []),
    ('va_arg', [('list', 'data_ptr')], ['type0'], ['storage_value']),
    ('va_copy', [('destination', 'data_ptr'), ('source', 'data_ptr')], [], []),
    ('va_end', [('list', 'data_ptr')], [], []),
    ('varargs_pack', [('arena', 'data_ptr'), ('values', 'data_ptr'), ('count', 'u64')], ['u64'], []),
]:
    helper(name, params, results, category='varargs', types=types, abi=True,
           effects=('varargs_cursor',), traps=MEM_TRAPS + ('ub_vararg_type', 'invalid_cookie'),
           guards=('list_and_arena',), leases=('thread_activation',))
for name, params, results in [
    ('setjmp_capture', [('buffer', 'data_ptr')], ['i32']),
    ('longjmp_restore', [('buffer', 'data_ptr'), ('value', 'i32')], []),
]:
    helper(name, params, results, category='nonlocal', abi=True,
           contracts=('setjmp', 'sigsetjmp'), effects=('nonlocal_control',),
           traps=('invalid_cookie', 'wrong_thread', 'dead_activation', 'ub_invalid_cleanup'),
           reentry='guest', cancel='defer_after_effect', leases=('snapshot_and_journal',))
for name, params, results in [
    ('eh_allocate', [('bytes', 'u64'), ('alignment', 'u64')], ['exception']),
    ('eh_raise', [('exception', 'exception')], []),
    ('eh_search', [('exception', 'exception'), ('journal', 'journal')], ['i1']),
    ('eh_cleanup', [('exception', 'exception'), ('journal', 'journal')], []),
    ('eh_begin_catch', [('exception', 'exception')], ['data_ptr']),
    ('eh_end_catch', [('exception', 'exception')], []),
    ('eh_rethrow', [('exception', 'exception')], []),
    ('eh_resume', [('exception', 'exception')], []),
    ('eh_retain', [('exception', 'exception')], ['exception']),
    ('eh_release', [('exception', 'exception')], []),
    ('eh_current', [], ['exception']),
    ('eh_forced_unwind', [('exception', 'exception')], []),
]:
    helper(name, params, results, category='eh', abi=True,
           effects=('exception_control_and_ownership',),
           traps=('invalid_exception', 'wrong_thread', 'stale_generation', 'terminate'),
           reentry='guest', cancel='defer_after_effect', leases=('exception_owner_and_frames',))
for name, params, results in [
    ('eh_object_address', [('exception','exception')], ['data_ptr']),
    ('eh_catch_object', [('exception','exception')], ['data_ptr']),
    ('eh_current_owner', [], ['data_ptr']),
    ('eh_owner_retain', [('owner','data_ptr')], []),
    ('eh_owner_release', [('owner','data_ptr')], []),
    ('eh_owner_rethrow', [('owner','data_ptr')], []),
    ('eh_uncaught_exceptions', [], ['i32']),
    ('eh_set_terminate', [('handler','code_ptr')], ['code_ptr']),
    ('eh_get_terminate', [], ['code_ptr']),
    ('eh_terminate', [], []),
    ('eh_rethrow_current', [], []),
]:
    helper(name,params,results,category='eh',effects=('exception_control_and_ownership',),
           traps=('invalid_exception','wrong_thread','stale_generation','resource','terminate'),
           reentry='guest' if name in {'eh_owner_release','eh_owner_rethrow','eh_terminate','eh_rethrow_current'} else 'forbidden',
           blocking='ready_wait' if name in {'eh_owner_release','eh_owner_rethrow','eh_terminate','eh_rethrow_current'} else 'never',
           cancel='defer_after_effect',leases=('process_payload_proxy_type_module_code',))
helper('journal_advance', [('journal', 'journal'), ('slot', 'u32'), ('element', 'u64')], [],
       category='journal', abi=True,
       contracts=('construct_begin', 'construct_commit', 'destroy_begin', 'destroy_commit',
                  'ownership_transfer', 'retain', 'release'), effects=('typed_cleanup_journal',),
       traps=('invalid_journal', 'wrong_thread', 'stale_generation', 'duplicate_effect', 'terminate'),
       reentry='guest', cancel='defer_after_effect', leases=('object_module_code_descriptor',))
helper('call_dispatch', [('target', 'code_ptr'), ('arguments', 'data_ptr'), ('results', 'data_ptr')], [],
       category='call', abi=True, contracts=('portable', 'foreign', 'callback'),
       effects=('call_and_conversion',), traps=('signature', 'capability', 'stale_generation', 'exception'),
       reentry='guest', blocking='ready_wait', cancel='defer_after_effect', leases=('transition_journals',))
helper('pointer_expose', [('pointer', 'type0')], ['u64'], category='pointer', types=['pointer'],
       effects=('provenance_exposure',), traps=('invalid_provenance',))
helper('pointer_recover', [('address', 'u64')], ['type0'], category='pointer', types=['pointer'],
       effects=('provenance_recovery',), traps=('malformed_provenance_metadata',))


# Flag is a distinct source type/progress class, not generic atomic<bool>.
POLICIES['atomic_flag'] = {
    'storage': 'one byte/alignment1; significant bit0; initialized false, remaining bits canonical zero',
    'progress': 'test/test_and_set/clear and hot lifetime guard are lock-free; no mutex/globalSC lock or dependence on paused guest worker',
    'order': 'same coherent process/shared-backing order as other atomics; SC may not become a separate flag-only total order',
    'lifetime': 'registered backing flag access class; aliases/foreign adapters use same atomic hot path; revocation prevents new admission without blocking flag operation',
    'lock_free': 'true for atomic_flag only; ordinary atomic<bool>/integer macros remain0',
}
for operation, params, results in [
    ('test', [('address', 'data_ptr'), ('order', 'u32')], ['i1']),
    ('test_and_set', [('address', 'data_ptr'), ('order', 'u32')], ['i1']),
    ('clear', [('address', 'data_ptr'), ('order', 'u32')], []),
]:
    helper('atomic_flag_' + operation, params, results, category='atomic_flag', abi=True,
           effects=('lock_free_flag',), traps=MEM_TRAPS + ('order',),
           guards=('lock_free_registered_flag_lifetime',), leases=('flag_backing',))
for operation in ('uinc_wrap', 'udec_wrap', 'usub_cond', 'usub_sat'):
    helper('atomic_fetch_' + operation,
           [('address', 'data_ptr'), ('value', 'type0'), ('order', 'u32')], ['type0'],
           category='atomic', types=['integer'], abi=True, contracts=('llvm_precision',),
           effects=('atomic_memory',), traps=MEM_TRAPS + ('order', 'scope'),
           guards=('one_alias_domain_bytes_and_shadow',), leases=('backing',))
for operation in ('fadd', 'fsub', 'fmax', 'fmin', 'fmaximum', 'fminimum',
                  'fmaximumnum', 'fminimumnum'):
    helper('atomic_fetch_' + operation,
           [('address', 'data_ptr'), ('value', 'type0'), ('order', 'u32')], ['type0'],
           category='atomic', types=['float'], abi=True,
           contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('atomic_memory', 'optional_fenv_flags'), traps=MEM_TRAPS + ('order', 'fp_enabled'),
           guards=('one_alias_domain_bytes_and_shadow',), leases=('backing',))
POLICIES['libm'] = {
    'finite': 'exact real mathematical function rounded once to destination binary format in selected rounding mode; stricter than approximate LLVM intrinsic bounds',
    'special': 'C23 domain/pole/signed-zero/infinity rules; first NaN quieted with payload/sign preserved; signaling NaN raises invalid',
    'sincospi': 'two results correctly rounded sin(pi*x),cos(pi*x) with exact mathematical pi*x argument reduction, never rounded pi multiplication',
    'errno': 'llvm_default/constrained preserve guest errno; c_fenv libm sets EDOM/ERANGE according to C source math-error contract',
    'fenv': 'llvm_default no environment changes; constrained/c_fenv merge flags before enabled trap, no result publication on trap',
    'powi': 'Full signed exponent width, exponent0 returns1 with no arithmetic; selected-bit multiply into1, shift magnitude right, square only when remaining nonzero; each executed multiply rounds destination, final reciprocal only negative; union only executed flags before single result frontier. This sequence overrides exact-real single-round finite policy for powi only.',
    'vector': 'c_fenv C libm is scalar only (no vector errno aggregation); floating_value scalar or fixed float vector; integer_value exponent has matched scalar/vector lane count; powi shares scalar integer exponent. Preserve lane poison, evaluate all defined lanes, union flags, diagnose once and publish complete result once; no source-visible prefix or compiler diagnostic-mask access.',
    'integer_round': 'lrint/llrint exact integer rounding selected mode, inexact only changed valid result; lround/llround nearest-away and never inexact; NaN/Inf/out-of-range returns concrete0 freeze refinement and invalid without inexact; flags merge once before result, never compound fptosi poison',
    'implementation': 'pure portable libm or software helper against this mathematical contract; host libm is not an implicit oracle',
}
for operation in ('acos', 'asin', 'atan', 'acosh', 'asinh', 'atanh', 'cos', 'sin', 'tan',
                  'cosh', 'sinh', 'tanh', 'exp', 'exp2', 'exp10', 'expm1', 'log', 'log2',
                  'log10', 'log1p', 'cbrt', 'erf', 'erfc', 'tgamma', 'lgamma', 'floor',
                  'ceil', 'trunc', 'round', 'roundeven', 'rint', 'nearbyint', 'logb',
                  'canonicalize'):
    helper('fp_' + operation, [('value', 'type0')], ['type0'], category='libm',
           types=['float'], contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags', 'optional_errno'), traps=('fp_enabled',))
for operation in ('atan2', 'pow', 'hypot', 'nextafter', 'remainder', 'fdim',
                  'minimumnum', 'maximumnum'):
    helper('fp_' + operation, [('left', 'type0'), ('right', 'type0')], ['type0'],
           category='libm', types=['float'], contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags', 'optional_errno'), traps=('fp_enabled',))
for operation in ('scalbn',):
    helper('fp_' + operation, [('value', 'type0'), ('exponent', 'i32')], ['type0'],
           category='libm', types=['float'], contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags', 'optional_errno'), traps=('fp_enabled',))
for operation in ('powi', 'ldexp', 'scalbln'):
    helper('fp_' + operation, [('value', 'type0'), ('exponent', 'type1')], ['type0'],
           category='libm', types=['float', 'integer'],
           contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags', 'optional_errno'), traps=('fp_enabled',))
for operation, results in [('frexp', ['type0', 'i32']), ('modf', ['type0', 'type0']),
                           ('sincos', ['type0', 'type0']), ('sincospi', ['type0', 'type0']), ('ilogb', ['i32'])]:
    helper('fp_' + operation, [('value', 'type0')], results, category='libm',
           types=['float'], contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags', 'optional_errno'), traps=('fp_enabled',))
for signedness in ('signed', 'unsigned'):
    helper('fp_to_' + signedness + '_sat', [('value', 'type0')], ['type1'], category='fp',
           types=['float', 'integer'], contracts=('llvm_default',), effects=(), traps=())

for operation in ('lrint', 'llrint', 'lround', 'llround'):
    helper('fp_' + operation, [('value', 'type0')], ['type1'], category='libm',
           types=['float', 'integer'], contracts=('llvm_default', 'constrained', 'c_fenv'),
           effects=('optional_fenv_flags', 'optional_errno'), traps=('fp_enabled',))

helper('tls_address_raw', [('offset', 'u64')], ['data_ptr'], category='tls',
       contracts=('default',), effects=(), traps=(), leases=('preissued_module_tls',))
for name, params, results in [
    ('journal_begin', [('object','data_ptr'),('captures','journal_captures')], ['journal']),
    ('journal_detach', [('journal','journal')], []),
    ('journal_adopt_child', [('journal','journal'),('slot','u32'),('element','u64'),('child','data_ptr')], []),
    ('journal_claim_partial', [('object','data_ptr')], ['journal']),
    ('journal_fail_partial', [('object','data_ptr'),('exception','exception')], ['journal']),
    ('journal_publish_object', [('journal', 'journal'), ('object', 'data_ptr')], []),
    ('journal_claim_destroy', [('object', 'data_ptr')], ['journal']),
]:
    helper(name, params, results, category='journal', abi=True,
           contracts=('construction','resume') if name=='journal_begin' else ('default',),
           effects=('typed_object_lifetime',), traps=('invalid_object', 'stale_generation',
           'wrong_program', 'duplicate_effect', 'resource'), blocking='ready_wait',
           guards=('exclusive_object_lifetime_metadata',), leases=('object_module_lifetime',))

for entry in RECORDS:
    name = entry['name']
    if name == 'fenv_set':
        entry['contracts'] = ['default', 'mode_only']
    if name == 'journal_advance':
        entry['reentry'] = 'forbidden'
        entry['blocking'] = 'ready_wait'
        entry['traps'] = ['invalid_journal', 'wrong_thread', 'stale_generation', 'duplicate_effect', 'resource', 'terminate']
    entry['completion'] = ('nonlocal' if name == 'longjmp_restore' else
        'terminal' if name == 'eh_terminate' else
        'raises' if name in {'eh_raise', 'eh_rethrow', 'eh_resume', 'eh_forced_unwind',
                            'eh_owner_rethrow','eh_rethrow_current'} else 'returns')
    if name in {'eh_get_terminate','eh_set_terminate'}:
        entry['semantic_checks'] = ['actual_code_ptr_signature_portable_fixed_void_noargs']
    if entry['policy'] == 'libm' and name not in {'fp_frexp', 'fp_ilogb', 'fp_lrint',
            'fp_llrint', 'fp_lround', 'fp_llround'}:
        entry['type_parameters'][0] = 'floating_value'
        if name in {'fp_ldexp', 'fp_scalbln'}:
            entry['type_parameters'][1] = 'integer_value'
    namespaces = {contract: ('nominal' if entry['abi_required'] else 'none')
                  for contract in entry['contracts']}
    targets = {contract: 'none' for contract in entry['contracts']}
    if name == 'call_dispatch':
        namespaces = {'portable': 'signature', 'foreign': 'bridge', 'callback': 'bridge'}
    elif name.startswith('journal_'):
        namespaces = {contract: 'journal' for contract in entry['contracts']}
    elif name == 'varargs_pack':
        namespaces = {contract: 'signature' for contract in entry['contracts']}
        targets = {contract: 'recipe' for contract in entry['contracts']}
    elif name == 'tls_destructor_register':
        namespaces = {contract: 'signature' for contract in entry['contracts']}
    elif name == 'tls_initialize':
        entry['abi_required'] = False
        namespaces = {contract: 'none' for contract in entry['contracts']}
    elif name.startswith('eh_') and name != 'eh_allocate':
        entry['abi_required'] = False
        namespaces = {contract: 'none' for contract in entry['contracts']}
    if name in {'tls_address', 'tls_initialize', 'tls_address_raw'}:
        targets = {contract: 'tls' for contract in entry['contracts']}
    if name in {'memory_load', 'memory_store'} or (name.startswith('atomic_') and
            entry['type_parameters']):
        namespaces = {contract: ('optional_storage_binding' if contract in
            {'ordinary', 'volatile', 'llvm_precision', 'llvm_default', 'constrained'}
            else 'storage_binding') for contract in entry['contracts']}
        targets = {contract: 'storage_layout' for contract in entry['contracts']}
    entry['abi_namespace'] = namespaces
    entry['target_namespace'] = targets


def document():
    return {'format': 'runtime_helper_catalog_v1', 'version': 1,
            'status': 'candidate_contract_not_production_implementation',
            'type_template_grammar': 'fixed u8/u32/u64/i1/i32/data_ptr/code_ptr/exception/fenv/stack_mark/journal; typeN binds exactly one admitted execution entity_ref',
            'order_input_domain': 'pinned Clang __ATOMIC constants0..5; consume refines acquire; no unknown upper bits',
            'signature_rules': 'exact params/results/noundef/portable cc/nonvariadic; no host ABI inference; ABI storage mask/extent checked separately',
            'policies': POLICIES, 'records': RECORDS}


if __name__ == '__main__':
    OUTPUT.write_text(json.dumps(document(), indent=2) + '\n')
