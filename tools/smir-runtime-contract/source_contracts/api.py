"""Public finite static verifier and comparator on genuine original owners."""
from dataclasses import dataclass, field
from . import ContractToolError
from . import checker as C, identity as I

StaticConstraints = C.StaticConstraints


@dataclass(frozen=True)
class StaticComparison:
    result: bool
    function: int
    functions: tuple
    left: StaticConstraints
    right: StaticConstraints
    deferred: tuple
    binding: str = field(default='unbound', init=False)
    source_fact_authority: bool = field(default=False, init=False)
    runtime_authority: bool = field(default=False, init=False)
    active_v3_verified: bool = field(default=False, init=False)


def verify(owner, document, *, budget):
    return C.run(owner, document, budget=budget)


def compare(left_owner, left_document, right_owner, right_document, function, *, budget):
    if type(function) is not int or not 0 <= function < 2**32 - 1:
        raise ContractToolError('input', 'SCV_FUNCTION', 'function must be a non-sentinel u32')
    result, left, right, functions = I.compare(left_owner, left_document, right_owner,
                                             right_document, function, budget=budget,
                                             _details=True)
    count = len(left.deferred) + len(right.deferred) + 1
    budget.charge(work=count * max(1, count.bit_length()), edges=count,
                  copied_bytes=256 * count)
    deferred = tuple(sorted(set(left.deferred) | set(right.deferred) |
                            {'SCV_COMPARISON_FINITE_SUBSET'}))
    return StaticComparison(result, function, functions, left, right, deferred)


def _checked(value):
    return {name: [{'function': f, 'id': i} for f, i in getattr(value, field)]
            for name, field in [('bindings', 'checked_bindings'),
                                ('scope_values', 'checked_scope_values'),
                                ('exits', 'checked_exits')]}


def _side(value):
    return {'source': {'schema_digest': value.stamp.schema_digest.hex(),
                       'roots': [{'section': n, 'digest': digest.hex()}
                                 for n, digest in value.stamp.root_digests]},
            'checked': _checked(value)}


def flags():
    return dict(format='smir-source-contracts-static-report', revision=1,
                binding='unbound', source_fact_authority=False, runtime_authority=False,
                active_v3_verified=False)


def report(value, *, budget):
    """Precharged inspection output; private owner/stamp handles never escape."""
    sides = (value.left, value.right) if type(value) is StaticComparison else (value,)
    count = sum(len(x.stamp.root_digests) + len(x.checked_bindings) +
                len(x.checked_scope_values) + len(x.checked_exits) for x in sides)
    budget.charge(work=128 + 128 * count + 256 * len(value.deferred),
                  edges=128 + 16 * count + len(value.deferred),
                  copied_bytes=8192 + 1024 * count + 2048 * len(value.deferred))
    result = flags()
    if type(value) is StaticComparison:
        result.update(status='static-comparison', result=value.result, function=value.function,
                      functions=list(value.functions), left=_side(value.left), right=_side(value.right))
    else:
        result.update(status='conditional-static-constraints', **_side(value))
    result['deferred'] = list(value.deferred)
    return result
