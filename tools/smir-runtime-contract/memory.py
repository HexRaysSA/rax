"""Access admission and order validation; not a production memory backend."""
from schema import alignment, require, validate

ORDERS = {'relaxed', 'acquire', 'release', 'acq_rel', 'seq_cst'}
CAS_FAILURES = {
    'relaxed': {'relaxed'},
    'acquire': {'relaxed', 'acquire'},
    'release': {'relaxed'},
    'acq_rel': {'relaxed', 'acquire'},
    'seq_cst': {'relaxed', 'acquire', 'seq_cst'},
}


def verify_access(access):
    validate(access, 'memory')
    kind = access['kind']
    width = access['width']
    order = access['order']
    failure = access['failure_order']
    require(alignment(access['alignment']), 'ACCESS_ALIGNMENT')
    if kind == 'fence':
        require(width == 0 and access['address'] == 0 and access['alignment'] == 1,
                'FENCE_OPERANDS')
        require(order in {'acquire', 'release', 'acq_rel', 'seq_cst'}, 'FENCE_ORDER')
        require(failure == 'none' and not access['volatile'], 'FENCE_FLAGS')
        return
    require(width > 0, 'ACCESS_WIDTH')
    require(width <= 1048576, 'ACCESS_LIMIT')
    require(access['address'] != 0, 'NULL_ADDRESS')
    require(access['address'] + width <= 2**64, 'ADDRESS_OVERFLOW')
    require(access['address'] % access['alignment'] == 0, 'MISALIGNED')
    if order == 'none':
        require(kind in {'load', 'store'} and failure == 'none', 'ORDINARY_KIND')
        return
    require(order in ORDERS, 'ATOMIC_ORDER')
    require(width in {1, 2, 4, 8, 16}, 'ATOMIC_WIDTH')
    require(access['alignment'] >= width and access['address'] % width == 0,
            'ATOMIC_ALIGNMENT')
    if kind == 'load':
        require(order in {'relaxed', 'acquire', 'seq_cst'}, 'LOAD_ORDER')
    elif kind == 'store':
        require(order in {'relaxed', 'release', 'seq_cst'}, 'STORE_ORDER')
    if kind == 'compare_exchange':
        require(failure in CAS_FAILURES[order], 'CAS_FAILURE_ORDER')
    else:
        require(failure == 'none', 'UNEXPECTED_FAILURE_ORDER')


def check_range(address, width, limit=2**64):
    """Mathematical range check; 2**64 is an exclusive endpoint, not a u64."""
    require(type(address) is int and type(width) is int, 'RANGE_TYPE')
    require(0 <= address < 2**64 and 0 < width <= 2**64, 'RANGE_DOMAIN')
    require(address != 0, 'NULL_ADDRESS')
    require(address + width <= limit, 'ADDRESS_OVERFLOW')
    return address, address + width


class ByteMemory:
    """Whole-access fault/alias reference semantics, not a threaded host backend.

    Lifetime/locking is modeled independently by MemoryLifetime and C++ witnesses.
    This model never holds guest-derived host pointers or executes guest code.
    """
    def __init__(self):
        self.backings = {}
        self.mappings = []

    def add_backing(self, identity, contents):
        require(identity not in self.backings, 'BACKING_EXISTS')
        require(type(contents) is bytes and len(contents) <= 16777216, 'BACKING_CONTENTS')
        self.backings[identity] = bytearray(contents)

    def map(self, address, length, backing, offset=0, permissions=3):
        start, end = check_range(address, length)
        require(backing in self.backings, 'BACKING_UNKNOWN')
        require(type(offset) is int and 0 <= offset and
                offset + length <= len(self.backings[backing]), 'BACKING_BOUNDS')
        require(type(permissions) is int and permissions & ~3 == 0, 'MAPPING_PERMISSIONS')
        require(all(end <= m[0] or m[1] <= start for m in self.mappings), 'MAPPING_OVERLAP')
        self.mappings.append((start, end, backing, offset, permissions))
        self.mappings.sort()

    def _spans(self, request, permission):
        cursor = request['address']
        end = cursor + request['width']
        spans = []
        for start, limit, backing, offset, permissions in self.mappings:
            if limit <= cursor:
                continue
            if start > cursor or cursor >= end:
                break
            require(permissions & permission == permission, 'MEMORY_PERMISSION', hex(cursor))
            size = min(end, limit) - cursor
            spans.append((backing, offset + cursor - start, size))
            cursor += size
        require(cursor == end, 'MEMORY_UNMAPPED', hex(cursor))
        return spans

    def load(self, request):
        verify_access(request)
        require(request['kind'] == 'load', 'MEMORY_KIND')
        spans = self._spans(request, 1)
        return b''.join(bytes(self.backings[backing][offset:offset + size])
                        for backing, offset, size in spans)

    def store(self, request, value):
        verify_access(request)
        require(request['kind'] == 'store', 'MEMORY_KIND')
        require(type(value) is bytes and len(value) == request['width'], 'MEMORY_VALUE')
        spans = self._spans(request, 2)
        staged = []
        at = 0
        for backing, offset, size in spans:
            staged.append((backing, offset, value[at:at + size]))
            at += size
        for backing, offset, contents in staged:
            self.backings[backing][offset:offset + len(contents)] = contents
