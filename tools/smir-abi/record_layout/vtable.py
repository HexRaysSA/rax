"""INT033 absolute selected vtable components; no RTTI/code authority."""
from layout import require
from .model import Budget


def components(vptr, budget=None):
    """Map each explicitly ordered negative8B slot to its kind and value.

    O(L) time/space, precharged before derived allocation. This proves component
    shape/position, not final-overrider or source virtual-base identity.
    """
    budget = budget or Budget()
    order = vptr['component_order']
    values = {'vcall': vptr['vcall_offsets'], 'vbase': vptr['vbase_offsets']}
    length = len(order)
    require(length == sum(map(len, values.values())) and length <= ((1 << 63) // 8) - 2,
            'ABI_CC_VTABLE_COMPONENT_COUNT')
    budget.work(length)
    budget.reserve(128 * length)
    indices = {'vcall': 0, 'vbase': 0}
    result = {}
    for index, kind in enumerate(order):
        require(kind in values and indices[kind] < len(values[kind]), 'ABI_CC_VTABLE_COMPONENT_KIND')
        result[-8 * (2 + length - index)] = kind, values[kind][indices[kind]]
        indices[kind] += 1
    require(all(indices[kind] == len(value) for kind, value in values.items()),
            'ABI_CC_VTABLE_COMPONENT_COUNT')
    return result
