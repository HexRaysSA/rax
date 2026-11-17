"""Independent mathematical LLVM64 GEP flag witness; no guest memory access."""
from canonical import require, uint


def normalize_indices(steps, *, flags=()):
    """LLVM64 constant-index prefix, before runtime relocation construction.

    Returns (signed-i64 ordered offsets, known_poison). The caller retains all
    flags on each ordered pointer step and attaches inrange to the FINAL GEP
    result only. This does not discharge actual-base no-wrap/object promises.
    O(K) big-integer operations, O(K) result space; K source indices.
    """
    require(type(steps) is list and set(flags) <= {'nuw', 'nusw', 'inbounds'}, 'GEP_INPUT')
    mask = (1 << 64) - 1
    lo, hi, offset, poison, result = -(1 << 63), (1 << 63) - 1, 0, False, []
    for bits, width, stride in steps:
        require(type(width) is int and 1 <= width <= 65535, 'GEP_INDEX_WIDTH')
        require(type(bits) is int and 0 <= bits < 1 << width, 'GEP_INDEX')
        uint(stride, 64)
        signed = bits - (1 << width) if bits & (1 << (width - 1)) else bits
        narrowed = signed & mask
        index = narrowed - (1 << 64) if narrowed >> 63 else narrowed
        product = index * stride
        unsigned_product = narrowed * stride
        old_signed = offset - (1 << 64) if offset >> 63 else offset
        if {'nusw', 'inbounds'} & set(flags):
            poison |= width > 64 and signed != index
            poison |= not lo <= product <= hi
            poison |= not lo <= old_signed + product <= hi
        if 'nuw' in flags:
            poison |= width > 64 and bits != narrowed
            poison |= unsigned_product > mask
            poison |= offset + unsigned_product > mask
        delta = product & mask
        result.append(delta - (1 << 64) if delta >> 63 else delta)
        offset = (offset + delta) & mask
    return result, bool(poison)


def gep(base, steps, *, flags=(), allocation=None):
    """steps=(raw index bits, index width, allocation stride) in source order.

    allocation=(origin,max_extent) may describe a deallocated object: GEP
    inbounds does not require live allocation. Actual dereference is separate.
    Returns (address bits, deferred poison). O(number of indices), big-int cost.
    """
    uint(base, 64)
    require(type(steps) is list and set(flags) <= {'nuw', 'nusw', 'inbounds'}, 'GEP_INPUT')
    mask = (1 << 64) - 1
    signed_min, signed_max = -(1 << 63), (1 << 63) - 1
    address, offset, poison = base, 0, False
    all_zero = True
    if allocation is not None:
        require(type(allocation) is tuple and len(allocation) == 2, 'GEP_ALLOCATION')
        origin, extent = allocation
        uint(origin, 64)
        uint(extent, 64)
        require(origin + extent <= mask, 'GEP_ALLOCATION')
    for bits, width, stride in steps:
        require(type(width) is int and 1 <= width <= 65535, 'GEP_INDEX_WIDTH')
        require(type(bits) is int and 0 <= bits < 1 << width, 'GEP_INDEX')
        uint(stride, 64)
        all_zero &= bits == 0
        narrowed = bits & mask
        signed_original = bits - (1 << width) if bits & (1 << (width - 1)) else bits
        signed_index = (narrowed - (1 << 64) if narrowed & (1 << 63) else narrowed) if width >= 64 else signed_original
        unsigned_index = (signed_index & mask) if width < 64 else narrowed
        signed_product, unsigned_product = signed_index * stride, unsigned_index * stride
        signed_offset = offset - (1 << 64) if offset & (1 << 63) else offset
        if 'nusw' in flags or 'inbounds' in flags:
            poison |= width > 64 and signed_original != signed_index
            poison |= not signed_min <= signed_product <= signed_max
            poison |= not signed_min <= signed_offset + signed_product <= signed_max
            poison |= not 0 <= address + signed_product <= mask
        if 'nuw' in flags:
            poison |= width > 64 and bits != narrowed
            poison |= unsigned_product > mask
            poison |= offset + unsigned_product > mask
            poison |= address + unsigned_product > mask
        address = (address + signed_product) & mask
        offset = (offset + signed_product) & mask
        if 'inbounds' in flags and bits != 0:
            poison |= allocation is None or not origin <= base <= origin + extent
        if 'inbounds' in flags and allocation is not None:
            poison |= not origin <= address <= origin + extent
    if 'inbounds' in flags and all_zero:
        # The pinned all-zero exception applies even to null/out-of-object base.
        poison = False
    return address, bool(poison)
