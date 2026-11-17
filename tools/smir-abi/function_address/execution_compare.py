"""Full execution-shape comparison over genuine API6 source-call views.

This unconsumed reference utility grants no source ABI compatibility, callable
permit, or executable admission. References keep their original owner context;
neither shape digests nor caller-supplied type resolvers are accepted.

The traversal computes rooted ordered bisimulation with memoized node PAIRS.
Let P be visited distinct pairs, E their outgoing paired edges, M the scalar
metadata visited, and S the charged cost of one complete source-view snapshot
check. Work is O(P + E + M + (P + E + 1)*S), not merely O(P + E): record() checks
the real roots before and after each query. Traversal storage is O(P + E + M)
logical metadata, in addition to the source factory's captured roots. Quotas
bound logical work, edges, copied payload bytes, and first-visit path depth;
they are not allocator-capacity or wall-clock bounds.

Trusted Python implementation/module mutation is outside the source-view
contract. The canonical loader and private-issued validator still reject
aliases, duck views, object.__new__ objects, and mismatched budget associations.
"""

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
_ERROR_NAME = '_rax_smir_call_comparison_errors_v1'
_VIEW_NAME = '_rax_smir_source_call_v1'
_ERROR_PATH = ROOT / 'tools/smir-abi/function_address/errors.py'
_VIEW_PATH = ROOT / 'tools/smir-format/execution/candidate/source_call_projection.py'

# Closed constructor fields, including all semantic descriptors. CodeAddress's
# accepted next-format shape is recorded here but cannot be issued by the current
# genuine factory/schema. No active CodeAddress test/admission is implied.
_FIELDS = {
    'int': ('bits',),
    'raw': ('bits',),
    'float': ('format',),
    'data_ptr': ('space',),
    'code_ptr': ('signature',),
    'code_address': (),
    'array': ('element', 'count'),
    'vector': ('element', 'count'),
    'struct': ('fields',),
    'function': ('params', 'results', 'variadic', 'param_noundef',
                 'result_noundef', 'cc'),
    'exception': (),
    'fenv': (),
    'stack_mark': (),
    'va_list': (),
    'journal': (),
}


def _errors():
    """Load only the already approved canonical error leaf, without aliases."""
    module = sys.modules.get(_ERROR_NAME)
    if module is not None:
        if (getattr(module, '__file__', None) is None or
                Path(module.__file__).resolve() != _ERROR_PATH or
                getattr(module, '_CANONICAL_INITIALIZED', False) is not True):
            raise RuntimeError('CALL_COMPARISON_MODULE_IDENTITY')
        return module
    specification = importlib.util.spec_from_file_location(_ERROR_NAME, _ERROR_PATH)
    module = importlib.util.module_from_spec(specification)
    sys.modules[_ERROR_NAME] = module
    try:
        specification.loader.exec_module(module)
        if getattr(module, '_CANONICAL_INITIALIZED', False) is not True:
            raise RuntimeError('CALL_COMPARISON_MODULE_IDENTITY')
    except BaseException:
        if sys.modules.get(_ERROR_NAME) is module:
            del sys.modules[_ERROR_NAME]
        raise
    return module


def _fail(kind, code, detail):
    raise _errors().CallComparisonError(kind, code, detail)


def _source_api():
    # Real view creation has already initialized this exact canonical module.
    # A missing module cannot contain a genuine issued input view.
    _errors()
    module = sys.modules.get(_VIEW_NAME)
    if (module is None or getattr(module, '__file__', None) is None or
            Path(module.__file__).resolve() != _VIEW_PATH or
            getattr(module, '_SOURCE_CALL_READY', False) is not True):
        _fail('semantic', 'ABI_CC_CONTEXT', 'canonical source-call module required')
    return module


def _validate_both(api, actual, expected, budget):
    api.validate_source_call_context(actual, budget=budget)
    api.validate_source_call_context(expected, budget=budget)


def _depth(budget, depth):
    if depth > budget.max_depth:
        # Both views have already validated the real S014 budget/class/module.
        module = sys.modules['_rax_smir_source_data_v1']
        raise module.SourceDataError('resource', 'SOURCE_DATA_RESOURCE',
                                     'execution comparison depth')


def _describe(record, budget):
    """Retain complete intrinsic metadata and ordered original child qrefs."""
    kind = record['kind']
    budget.work(len(kind) + 1)
    fields = _FIELDS.get(kind)
    if fields is None:
        _fail('unavailable', 'ABI_CC_TYPE_UNAVAILABLE', kind)
    # New fields on a valid future constructor must not be silently discarded.
    if (len(record) != len(fields) + 2 or
            any(name not in fields and name not in ('id', 'kind') for name in record)):
        _fail('unavailable', 'ABI_CC_TYPE_UNAVAILABLE', kind + ': descriptor fields')

    if kind in ('int', 'raw'):
        budget.charge(work=2, copied_bytes=24)
        return (kind, record['bits']), ()
    if kind in ('float', 'data_ptr'):
        text = record['format' if kind == 'float' else 'space']
        budget.charge(work=len(text) + 1, copied_bytes=24)
        return (kind, text), ()
    if kind == 'code_ptr':
        budget.charge(work=1, edges=1, copied_bytes=32)
        return (kind,), (record['signature'],)
    if kind in ('array', 'vector'):
        budget.charge(work=2, edges=1, copied_bytes=40)
        return (kind, record['count']), (record['element'],)
    if kind == 'struct':
        children = record['fields']
        budget.charge(work=len(children) + 1, copied_bytes=24)
        return (kind, len(children)), children
    if kind == 'function':
        params, results = record['params'], record['results']
        pn, rn = record['param_noundef'], record['result_noundef']
        cc, variadic = record['cc'], record['variadic']
        count = len(params) + len(results)
        budget.charge(work=count + len(pn) + len(rn) + len(cc) + 4,
                      edges=count, copied_bytes=64 + 8 * count)
        return (kind, cc, variadic, pn, rn, len(params), len(results)), params + results
    budget.charge(work=1, copied_bytes=16)
    return (kind,), ()


def same_execution_shape(actual_context, actual_ref, expected_context, expected_ref, *, budget):
    """Compare raw execution types in their own genuine contexts and one ledger.

    Return bool only after revalidating BOTH original snapshots. Semantic,
    unavailable and shared-budget/resource errors retain their exact exception
    identities; programming exceptions propagate. A false result is a genuine
    structural mismatch, never an error fallback. Inputs are not rewritten.
    """
    api = _source_api()
    _validate_both(api, actual_context, expected_context, budget)
    budget.charge(work=1, edges=1, copied_bytes=96)
    pending = [(actual_ref, expected_ref, 1)]
    seen = set()
    equal = True
    while pending:
        left_ref, right_ref, depth = pending.pop()
        left = actual_context.record('execution', left_ref, budget=budget)
        right = expected_context.record('execution', right_ref, budget=budget)
        budget.charge(work=2, copied_bytes=32)
        pair = left.local_reference['id'], right.local_reference['id']
        if pair in seen:
            # Closing a cycle/revisiting a pair is not a new graph descent.
            continue
        _depth(budget, depth)
        left_label, left_children = _describe(left.record, budget)
        right_label, right_children = _describe(right.record, budget)
        if left_label != right_label or len(left_children) != len(right_children):
            equal = False
            break
        budget.charge(work=1, edges=1, copied_bytes=64)
        seen.add(pair)
        for index in range(len(left_children) - 1, -1, -1):
            budget.charge(work=1, edges=1, copied_bytes=32)
            pending.append((left_children[index], right_children[index], depth + 1))
    _validate_both(api, actual_context, expected_context, budget)
    return equal
