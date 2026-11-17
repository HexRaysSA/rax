"""The floating-point and atomic programs of the interpreter differential corpus.

`add(m, b)` and `add_atomics(m, b)` append them to the module `m`; `b` is the `build` module, whose
helpers author the records. Most programs return several results, one per
operation, so that each case checks a whole family at once.

All operations use the default environment: round to nearest with ties to
even, and no observable exception.
"""

DEFAULT = {'environment': 'default', 'rounding': 'nearest_even', 'exceptions': 'ignore'}
BITS = {'f32': 32, 'f64': 64, 'f128': 128}
PREDICATES = ['false', 'oeq', 'ogt', 'oge', 'olt', 'ole', 'one', 'ord',
              'ueq', 'ugt', 'uge', 'ult', 'ule', 'une', 'uno', 'true']


def add(m, b):
    def fp(name, value, kind, *operands):
        return {'op': 'fp_' + name, 'results': [b.decl(value, kind)], 'operands': list(operands),
                'mode': dict(DEFAULT)}

    def fcmp(value, predicate, left, right, signaling=False):
        return {'op': 'fcmp', 'results': [b.decl(value, 1)], 'operands': [left, right],
                'predicate': predicate, 'signaling': signaling, 'mode': dict(DEFAULT)}

    def cast(name, value, kind, operand):
        """sitofp, uitofp, fptosi, fptoui, their saturating forms and fpconvert."""
        return {'op': name, 'results': [b.decl(value, kind)], 'operands': [operand], 'mode': dict(DEFAULT)}

    def fconst(value, kind, bits):
        literal = {'kind': 'bits', 'value': bits.to_bytes(BITS[kind] // 8, 'little').hex()}
        return {'op': 'constant', 'results': [b.decl(value, kind)], 'operands': [], 'literal': literal}

    def family(identifier, name, kind, count, operations):
        """A function of `count` floats that returns one result per operation."""
        ops = [fp(operation, count + position, kind, *range(count))
               for position, operation in enumerate(operations)]
        results = list(range(count, count + len(operations)))
        m.function(identifier, name, [kind] * count, [kind] * len(operations),
                   [b.block(0, [], ops, b.ret(*results))], noundef=False)

    # binary128 has the same programs, numbered from 560.
    for offset, kind in ((0, 'f32'), (1, 'f64'), (60, 'f128')):
        width = BITS[kind]
        family(500 + offset, f'arith{width}', kind, 2, ['add', 'sub', 'mul', 'div', 'frem'])
        family(502 + offset, f'extrema{width}', kind, 2,
               ['minimum', 'maximum', 'minnum', 'maxnum', 'minimumnum', 'maximumnum', 'copysign'])
        family(504 + offset, f'unary{width}', kind, 1, ['neg', 'abs', 'sqrt'])
        family(506 + offset, f'fma{width}', kind, 3, ['fma'])

        # compare(a, b): every predicate, and two of them again as signaling
        # comparisons, which differ only in exceptions nothing observes.
        ops = [fcmp(2 + position, predicate, 0, 1) for position, predicate in enumerate(PREDICATES)]
        ops += [fcmp(18, 'olt', 0, 1, signaling=True), fcmp(19, 'une', 0, 1, signaling=True)]
        m.function(508 + offset, f'compare{width}', [kind, kind], [1] * 18,
                   [b.block(0, [], ops, b.ret(*range(2, 20)))], noundef=False)

        # to_integers(a): truncating conversions, where a value out of range
        # is poison, and saturating ones.
        targets = [('fptosi', 8), ('fptosi', 32), ('fptosi', 64), ('fptoui', 8), ('fptoui', 32),
                   ('fptoui', 64), ('fptoui', 1), ('fptosi', 1), ('fptosi_sat', 8), ('fptosi_sat', 32),
                   ('fptosi_sat', 64), ('fptoui_sat', 8), ('fptoui_sat', 32), ('fptoui_sat', 64)]
        ops = [cast(operation, 1 + position, bits, 0) for position, (operation, bits) in enumerate(targets)]
        m.function(510 + offset, f'to_integers{width}', [kind], [bits for _, bits in targets],
                   [b.block(0, [], ops, b.ret(*range(1, 1 + len(targets))))], noundef=False)

        # from_integer(x): the 64-bit value and its low 8 bits, as signed and
        # as unsigned.
        m.function(512 + offset, f'from_integer{width}', [64], [kind] * 4, [b.block(0, [], [
            cast('sitofp', 1, kind, 0), cast('uitofp', 2, kind, 0), b.simple('trunc', 3, 8, 0),
            cast('sitofp', 4, kind, 3), cast('uitofp', 5, kind, 3)], b.ret(1, 2, 4, 5))], noundef=False)

        # reinterpret(a): the bits as an integer, back as a float, and through
        # memory in both types.
        m.function(514 + offset, f'reinterpret{width}', [kind], [width, kind, width, kind], [b.block(0, [], [
            b.simple('bitcast', 1, width, 0), b.simple('bitcast', 2, kind, 1),
            b.const(3, 64, width // 8), m.alloca(4, 3, width // 8), b.store(4, 0, kind),
            b.load(5, width, 4), b.store(4, 1, width), b.load(6, kind, 4)], b.ret(1, 2, 5, 6))], noundef=False)

    # widen128(a) and narrow128(a): conversion to and from binary128.
    m.function(580, 'widen128', ['f64'], ['f128', 'f64', 'f32'], [b.block(0, [], [
        cast('fpconvert', 1, 'f128', 0), cast('fpconvert', 2, 'f64', 1), cast('fpconvert', 3, 'f32', 1)],
        b.ret(1, 2, 3))], noundef=False)
    m.function(581, 'narrow128', ['f128'], ['f64', 'f32', 'f128'], [b.block(0, [], [
        cast('fpconvert', 1, 'f64', 0), cast('fpconvert', 2, 'f32', 0), cast('fpconvert', 3, 'f128', 2)],
        b.ret(1, 2, 3))], noundef=False)

    # widen(a) and narrow(a): conversion between the formats.
    m.function(516, 'widen', ['f32'], ['f64', 'f32'], [b.block(0, [], [
        cast('fpconvert', 1, 'f64', 0), cast('fpconvert', 2, 'f32', 1)], b.ret(1, 2))], noundef=False)
    m.function(517, 'narrow', ['f64'], ['f32', 'f64'], [b.block(0, [], [
        cast('fpconvert', 1, 'f32', 0), cast('fpconvert', 2, 'f64', 1)], b.ret(1, 2))], noundef=False)

    # harmonic(n): the sum of 1/k for k from 1 to n & 31, in a loop with a
    # floating-point phi.
    m.function(518, 'harmonic', [32], ['f64'], [
        b.block(0, [], [b.const(1, 32, 31), b.binary('and', 2, 32, 0, 1), fconst(3, 'f64', 0),
                        fconst(4, 'f64', 0x3ff0000000000000), b.const(5, 32, 0), b.const(6, 32, 1)], b.jump(1)),
        b.block(1, [b.phi(7, 32, (0, 5), (2, 11)), b.phi(8, 'f64', (0, 3), (2, 14))],
                [b.icmp(9, 'eq', 7, 2)], b.branch(9, 3, 2)),
        b.block(2, [], [b.binary('add', 11, 32, 7, 6), cast('uitofp', 12, 'f64', 11),
                        fp('div', 13, 'f64', 4, 12), fp('add', 14, 'f64', 8, 13)], b.jump(1)),
        b.block(3, [], [], b.ret(8)),
    ], noundef=False)

    # clamp(a): selects on a comparison; the unordered case falls to zero.
    m.function(519, 'clamp', ['f32'], ['f32'], [b.block(0, [], [
        fconst(1, 'f32', 0), fconst(2, 'f32', 0x3f800000), fcmp(3, 'olt', 0, 1), fcmp(4, 'ogt', 0, 2),
        fcmp(5, 'uno', 0, 0), b.select(6, 'f32', 4, 2, 0), b.select(7, 'f32', 3, 1, 6),
        b.select(8, 'f32', 5, 1, 7)], b.ret(8))], noundef=False)

    # tainted(a): a conversion out of range is poison, and stays poison
    # through arithmetic, comparison and selection.
    m.function(520, 'tainted', ['f32'], ['f32', 1, 'f64'], [b.block(0, [], [
        cast('fptosi', 1, 8, 0), cast('sitofp', 2, 'f32', 1), fp('add', 3, 'f32', 2, 0),
        fcmp(4, 'oeq', 3, 3), special(b, 5, 'f64', 'undef'), fp('neg', 6, 'f64', 5)], b.ret(3, 4, 6))],
        noundef=False)


def special(b, value, kind, state):
    return {'op': 'constant', 'results': [b.decl(value, kind)], 'operands': [], 'literal': {'kind': state}}


def add_atomics(m, b):
    """Atomic accesses, which a single thread performs as plain ones."""
    def mode(order, failure='none'):
        return {'alignment': 4, 'volatile': False, 'order': order, 'failure_order': failure,
                'scope': 'process', 'elementwise': False}

    def atomic(name, results, operands, order, failure='none', **extra):
        record = {'op': name, 'results': results, 'operands': operands, **b.access(32)}
        record['mode'] = mode(order, failure)
        record.update(extra)
        return record

    # update(a, b): every read-modify-write action in turn on one cell that
    # starts as a; the results are the values each action found.
    actions = ['exchange', 'add', 'sub', 'and', 'nand', 'or', 'xor', 'min', 'max', 'umin', 'umax']
    ops = [b.const(2, 64, 4), m.alloca(3, 2, 4), atomic('atomic_store', [], [3, 0], 'seq_cst')]
    ops += [atomic('atomic_rmw', [b.decl(4 + position, 32)], [3, 1], 'seq_cst' if position % 2 else 'relaxed',
                   action=action) for position, action in enumerate(actions)]
    last = 4 + len(actions)
    ops += [atomic('atomic_load', [b.decl(last, 32)], [3], 'acquire'),
            {'op': 'fence', 'results': [], 'operands': [], 'order': 'seq_cst', 'scope': 'process'}]
    m.function(540, 'atomic_update', [32, 32], [32] * (len(actions) + 1),
               [b.block(0, [], ops, b.ret(*range(4, last + 1)))], noundef=False)

    # exchange(a, b): a compare-and-exchange that succeeds when a equals b,
    # then one against a cell that was never written, and one whose expected
    # value is poison: undef and poison bits compare as zero.
    m.function(541, 'atomic_exchange', [32, 32], [32, 1, 32, 32, 1, 32, 1, 32], [b.block(0, [], [
        b.const(2, 64, 4), m.alloca(3, 2, 4), b.store(3, 0, 32), b.const(4, 32, 0x5a5a),
        atomic('cmpxchg', [b.decl(5, 32), b.decl(6, 1)], [3, 1, 4], 'seq_cst', 'seq_cst', weak=False),
        b.load(7, 32, 3),
        m.alloca(8, 2, 4),
        atomic('cmpxchg', [b.decl(9, 32), b.decl(10, 1)], [8, 1, 4], 'acq_rel', 'relaxed', weak=True),
        special(b, 11, 32, 'poison'),
        atomic('cmpxchg', [b.decl(12, 32), b.decl(13, 1)], [3, 11, 0], 'release', 'relaxed', weak=False),
        b.load(14, 32, 3)], b.ret(5, 6, 7, 9, 10, 12, 13, 14))], noundef=False)

    # misaligned(x): an atomic access checks its alignment like any other.
    m.function(542, 'atomic_misaligned', [32], [32], [b.block(0, [], [
        b.const(1, 64, 8), m.alloca(2, 1, 4), b.const(3, 64, 1), b.offset(4, 2, 3),
        atomic('atomic_rmw', [b.decl(5, 32)], [4, 0], 'seq_cst', action='add')], b.ret(5))], noundef=False)
