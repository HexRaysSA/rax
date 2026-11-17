#!/usr/bin/env python3
"""Author the interpreter differential programs as editable ten-root JSON.

    python3 -B build.py            # rewrite programs.json
    python3 -B build.py --check    # fail if programs.json is out of date

The module starts from the repository's `add64.json` reference source, which
supplies valid ABI and manifest sections, and appends integer types, functions
and their symbols. `programs.smo` is `programs.json` assembled by
`tools/smir-format/smir.py assemble`.

The programs use integers of at most 64 bits, data pointers, the integer,
cast, compare, select, freeze and call operations, plain loads and stores,
pointer offsets and conversions, stack allocation and lifetime markers, and
`return`, `jump` and `cbranch`. The oracle is the Python reference Machine
driven by `../oracle.py`, which supplies the three runtime helpers.

The helper import records come from the reference suite's own constructor
(`test_candidate_bindings.add_import`), so their catalog digest and option
defaults are the ones the reference verifier expects.
"""
import copy
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = (ROOT / 'docs/specifications/smir/portable/conformance/envelope/candidate'
        / 'reference-execution/integers/add64.json')
INT = {1: 2001, 8: 2008, 16: 2016, 32: 2032, 64: 2064}
POINTER = 2090
# Memory layout identifiers, by integer width; POINTER_LAYOUT for pointers.
LAYOUT = {1: 2101, 8: 2108, 16: 2116, 32: 2132, 64: 2164}
POINTER_LAYOUT = 2190
# Import identifiers of the runtime helpers.
HELPERS = {'stack_alloc': 0, 'lifetime_start': 1, 'lifetime_end': 2}


def ref(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


def type_of(kind):
    """Type identifier of an integer width, or of the pointer type for 'ptr'."""
    return POINTER if kind == 'ptr' else INT[kind]


def decl(value, bits):
    return {'id': value, 'type': ref(type_of(bits))}


def null(value):
    return {'op': 'constant', 'results': [decl(value, 'ptr')], 'operands': [], 'literal': {'kind': 'zero'}}


def access(kind, alignment=None):
    """The storage and mode records of a plain load or store of `kind`."""
    size = 8 if kind == 'ptr' else (kind + 7) // 8
    layout = POINTER_LAYOUT if kind == 'ptr' else LAYOUT[kind]
    return {'storage': {'type': ref(type_of(kind)), 'layout': ref(layout), 'nominal': None,
                        'abi_binding': None, 'bytes': size},
            'mode': {'alignment': alignment or size, 'volatile': False, 'order': 'none',
                     'failure_order': 'none', 'scope': 'process', 'elementwise': False}}


def load(value, kind, pointer, alignment=None):
    return {'op': 'load', 'results': [decl(value, kind)], 'operands': [pointer], **access(kind, alignment)}


def store(pointer, value, kind, alignment=None):
    return {'op': 'store', 'results': [], 'operands': [pointer, value], **access(kind, alignment)}


def offset(value, pointer, delta, inbounds=False, check_base=False, nuw=False, nusw=False):
    return {'op': 'ptr_offset', 'results': [decl(value, 'ptr')], 'operands': [pointer, delta],
            'inbounds': inbounds, 'check_base': check_base, 'nuw': nuw, 'nusw': nusw, 'inrange': None}


def convert(name, value, kind, operand):
    """ptrtoint, ptrtoaddr and inttoptr."""
    return {'op': name, 'results': [decl(value, kind)], 'operands': [operand]}


def const(value, bits, number):
    literal = {'kind': 'bits', 'value': (number % (1 << bits)).to_bytes((bits + 7) // 8, 'little').hex()}
    return {'op': 'constant', 'results': [decl(value, bits)], 'operands': [], 'literal': literal}


def special(value, bits, kind):
    return {'op': 'constant', 'results': [decl(value, bits)], 'operands': [], 'literal': {'kind': kind}}


def binary(name, value, bits, left, right, *flags):
    # The format requires flags in sorted order without repeats.
    return {'op': 'i_' + name, 'results': [decl(value, bits)], 'operands': [left, right],
            'flags': sorted(set(flags))}


def unary(name, value, bits, operand, zero_is_poison=False):
    return {'op': 'i_' + name, 'results': [decl(value, bits)], 'operands': [operand],
            'zero_is_poison': zero_is_poison}


def icmp(value, predicate, left, right):
    return {'op': 'icmp', 'results': [decl(value, 1)], 'operands': [left, right], 'predicate': predicate}


def select(value, bits, condition, if_true, if_false):
    return {'op': 'select', 'results': [decl(value, bits)], 'operands': [condition, if_true, if_false]}


def simple(name, value, bits, operand):
    """copy, freeze, trunc, zext and sext: one operand, one result."""
    return {'op': name, 'results': [decl(value, bits)], 'operands': [operand]}


def phi(value, bits, *incoming):
    return {'result': decl(value, bits),
            'incoming': [{'predecessor': block, 'value': source} for block, source in incoming]}


def block(identifier, phis, ops, term):
    return {'id': identifier, 'phis': phis, 'ops': ops, 'term': term}


def ret(*values):
    return {'op': 'return', 'values': list(values)}


def jump(target):
    return {'op': 'jump', 'target': target}


def branch(condition, if_true, if_false):
    return {'op': 'cbranch', 'condition': condition, 'true': if_true, 'false': if_false}


class Module:
    def __init__(self):
        self.roots = json.loads(BASE.read_text())['sections']
        self.types = self.roots['1']['types']
        self.functions = self.roots['3']['functions']
        self.symbols = self.roots['2']['symbols']
        # The base module's function 1 takes a code address, which the Python
        # reference machine supports only with its source registry attached.
        # Nothing refers to that function, and the oracle runs without the
        # registry, so it is left out.
        self.functions[:] = [item for item in self.functions if item['id'] != 1]
        self.types.extend({'kind': 'int', 'id': identifier, 'bits': bits} for bits, identifier in INT.items())
        self.signatures = {}
        self.index = []
        self.types.append({'kind': 'data_ptr', 'id': POINTER, 'space': 'guest_data'})
        layouts = self.roots['1']['memory_layouts']
        for bits, identifier in LAYOUT.items():
            size = (bits + 7) // 8
            layouts.append({'id': identifier, 'type': ref(INT[bits]), 'size': size, 'alignment': size,
                            'access_bytes': size, 'fields': [], 'element': None, 'stride': 0})
        layouts.append({'id': POINTER_LAYOUT, 'type': ref(POINTER), 'size': 8, 'alignment': 8,
                        'access_bytes': 8, 'fields': [], 'element': None, 'stride': 0})
        layouts.sort(key=lambda item: item['id'])
        self.helper_signatures = {}
        self.add_helpers()

    def signature(self, params, results, noundef, param_noundef=True):
        key = (tuple(params), tuple(results), noundef, param_noundef)
        if key not in self.signatures:
            identifier = 2200 + len(self.signatures)
            self.signatures[key] = identifier
            self.types.append({
                'kind': 'function', 'id': identifier,
                'params': [ref(type_of(kind)) for kind in params],
                'results': [ref(type_of(kind)) for kind in results],
                'variadic': False, 'param_noundef': [param_noundef] * len(params),
                'result_noundef': [noundef] * len(results), 'cc': 'portable'})
        return self.signatures[key]

    def add_helpers(self):
        """Import the stack and lifetime helpers of the internal runtime."""
        sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
        from test_candidate_bindings import add_import
        shapes = {'stack_alloc': ([64, 64], ['ptr']), 'lifetime_start': (['ptr', 64], []),
                  'lifetime_end': (['ptr', 64], [])}
        for name, identifier in HELPERS.items():
            _, binding = add_import(name)
            binding = copy.deepcopy(binding)
            params, results = shapes[name]
            self.helper_signatures[name] = self.signature(params, results, False, param_noundef=False)
            binding.update(id=identifier, signature=ref(self.helper_signatures[name]))
            self.roots['6']['imports'].append(binding)

    def helper(self, name, results, operands, alignment=0):
        target = {'kind': 'import', 'import': ref(HELPERS[name]), 'signature': ref(self.helper_signatures[name])}
        return {'op': 'alloca' if name == 'stack_alloc' else name, 'results': results, 'operands': operands,
                'helper': target, 'binding': None, 'alignment': alignment}

    def alloca(self, value, size, alignment):
        """A stack object of `size` (a 64-bit value) bytes."""
        return self.helper('stack_alloc', [decl(value, 'ptr')], [size], alignment)

    def lifetime(self, start, pointer, size):
        return self.helper('lifetime_start' if start else 'lifetime_end', [], [pointer, size])

    def call(self, values, callee, operands):
        """A direct call to an earlier function; `values` are (id, bits) results."""
        entry = next(item for item in self.index if item['id'] == callee)
        return {'op': 'call', 'results': [decl(value, bits) for value, bits in values],
                'operands': list(operands),
                'target': {'kind': 'direct', 'function': ref(callee), 'signature': ref(entry['signature'])},
                'unwind': 'propagate', 'source_plan': None}

    def declare(self, identifier, name, params, results, noundef=True):
        """Reserve a function so that its own body can call it."""
        signature = self.signature(params, results, noundef)
        self.index.append({'id': identifier, 'name': name, 'params': list(params),
                           'results': list(results), 'signature': signature})
        return signature

    def define(self, identifier, blocks):
        entry = next(item for item in self.index if item['id'] == identifier)
        self.functions.append({
            'id': identifier, 'signature': ref(entry['signature']), 'abi_signature': None,
            'params': [decl(value, bits) for value, bits in enumerate(entry['params'])],
            'entry': blocks[0]['id'], 'escape': 'propagate', 'no_return': False, 'blocks': blocks})
        self.symbols.append({
            'id': identifier, 'namespace': 'example', 'name': 'program_' + entry['name'],
            'kind': 'function', 'source_linkage': 'none', 'binding': 'strong', 'visibility': 'default',
            'execution': ref(entry['signature']), 'nominal': None, 'abi_signature': None,
            'definition': {'some': {'kind': 'function', 'target': ref(identifier)}},
            'size': None, 'alignment': 1, 'comdat': None, 'fallback': None})

    def function(self, identifier, name, params, results, blocks, noundef=True):
        self.declare(identifier, name, params, results, noundef)
        self.define(identifier, blocks)


def build():
    m = Module()

    # gcd(a, b): Euclid's algorithm with a loop-carried pair.
    m.function(100, 'gcd', [64, 64], [64], [
        block(0, [], [const(4, 64, 0)], jump(1)),
        block(1, [phi(2, 64, (0, 0), (2, 3)), phi(3, 64, (0, 1), (2, 6))],
              [icmp(5, 'eq', 3, 4)], branch(5, 3, 2)),
        block(2, [], [binary('urem', 6, 64, 2, 3)], jump(1)),
        block(3, [], [], ret(2)),
    ])

    # collatz(n): number of steps to reach 1, choosing the next value by select.
    m.function(101, 'collatz', [64], [64], [
        block(0, [], [const(1, 64, 1), const(2, 64, 3), const(3, 64, 0)], jump(1)),
        block(1, [phi(4, 64, (0, 0), (2, 12)), phi(5, 64, (0, 3), (2, 13))],
              [icmp(6, 'ule', 4, 1)], branch(6, 3, 2)),
        block(2, [], [
            binary('and', 7, 64, 4, 1), icmp(8, 'ne', 7, 3), binary('lshr', 9, 64, 4, 1),
            binary('mul', 10, 64, 4, 2), binary('add', 11, 64, 10, 1),
            select(12, 64, 8, 11, 9), binary('add', 13, 64, 5, 1)], jump(1)),
        block(3, [], [], ret(5)),
    ])

    # fib(n): 32-bit counter, 64-bit accumulators.
    m.function(102, 'fib', [32], [64], [
        block(0, [], [const(1, 64, 0), const(2, 64, 1), const(3, 32, 0), const(4, 32, 1)], jump(1)),
        block(1, [phi(5, 64, (0, 1), (2, 6)), phi(6, 64, (0, 2), (2, 9)), phi(7, 32, (0, 3), (2, 10))],
              [icmp(8, 'eq', 7, 0)], branch(8, 3, 2)),
        block(2, [], [binary('add', 9, 64, 5, 6), binary('add', 10, 32, 7, 4)], jump(1)),
        block(3, [], [], ret(5)),
    ])

    # swap(n): two phis that read each other; only a simultaneous commit swaps.
    m.function(103, 'swap', [32], [32], [
        block(0, [], [const(1, 32, 1), const(2, 32, 2), const(3, 32, 0)], jump(1)),
        block(1, [phi(4, 32, (0, 1), (1, 5)), phi(5, 32, (0, 2), (1, 4)), phi(6, 32, (0, 3), (1, 7))],
              [binary('add', 7, 32, 6, 1), icmp(8, 'eq', 7, 0)], branch(8, 2, 1)),
        block(2, [], [], ret(4)),
    ])

    # fact(n): direct recursion; large n exhausts the frame limit.
    m.declare(104, 'fact', [64], [64])
    m.define(104, [
        block(0, [], [const(1, 64, 1), icmp(2, 'ule', 0, 1)], branch(2, 1, 2)),
        block(1, [], [], ret(1)),
        block(2, [], [binary('sub', 3, 64, 0, 1), m.call([(4, 64)], 104, [3]),
                      binary('mul', 5, 64, 0, 4)], ret(5)),
    ])

    def mix(identifier, name, bits, swap):
        ops = [const(2, bits, bits - 1), binary('and', 3, bits, 1, 2),
               binary('shl', 4, bits, 0, 3), binary('lshr', 5, bits, 0, 3), binary('ashr', 6, bits, 0, 3),
               binary('rotl', 7, bits, 0, 1), binary('rotr', 8, bits, 0, 1),
               unary('clz', 9, bits, 0), unary('ctz', 10, bits, 0), unary('popcount', 11, bits, 0),
               unary('abs', 12, bits, 0), unary('bitreverse', 13, bits, 0),
               binary('xor', 14, bits, 4, 5), binary('sub', 15, bits, 14, 6),
               binary('mul', 16, bits, 15, 7), binary('or', 17, bits, 16, 8),
               binary('add', 18, bits, 17, 9), binary('xor', 19, bits, 18, 10),
               binary('add', 20, bits, 19, 11), binary('mul', 21, bits, 20, 12),
               binary('xor', 22, bits, 21, 13)]
        last = 22
        if swap:
            ops += [unary('bswap', 23, bits, 0), binary('add', 24, bits, 22, 23)]
            last = 24
        m.function(identifier, name, [bits, bits], [bits], [block(0, [], ops, ret(last))])

    # Every non-faulting integer operation at three widths.
    mix(105, 'mix64', 64, True)
    mix(106, 'mix8', 8, False)
    mix(107, 'mix16', 16, True)

    # divide(x, y): all four divisions; faults on zero and on MIN / -1.
    m.function(108, 'divide', [64, 64], [64], [block(0, [], [
        binary('sdiv', 2, 64, 0, 1), binary('srem', 3, 64, 0, 1),
        binary('udiv', 4, 64, 0, 1), binary('urem', 5, 64, 0, 1),
        binary('mul', 6, 64, 2, 1), binary('add', 7, 64, 6, 3),
        binary('xor', 8, 64, 4, 5), binary('sub', 9, 64, 7, 8), binary('xor', 10, 64, 9, 2)], ret(10))])

    # casts(x): truncate, extend both ways and select on a one-bit truncation.
    m.function(109, 'casts', [64], [64], [block(0, [], [
        simple('trunc', 1, 8, 0), simple('sext', 2, 32, 1), simple('zext', 3, 16, 1),
        simple('sext', 4, 64, 2), simple('zext', 5, 64, 3), simple('trunc', 6, 1, 0),
        select(7, 64, 6, 4, 5), simple('trunc', 8, 32, 0), simple('zext', 9, 64, 8),
        binary('xor', 10, 64, 7, 9), simple('zext', 11, 64, 6), binary('add', 12, 64, 10, 11)], ret(12))])

    # flags(x, y): may return poison, which a non-noundef result allows.
    m.function(110, 'flags', [32, 32], [32], [block(0, [], [
        binary('add', 2, 32, 0, 1, 'nsw')], ret(2))], noundef=False)

    # frozen(x, y): poison from wrap flags is frozen to zero before use.
    m.function(111, 'frozen', [32, 32], [32], [block(0, [], [
        binary('add', 2, 32, 0, 1, 'nuw'), binary('mul', 3, 32, 0, 1, 'nsw'),
        binary('sub', 4, 32, 0, 1, 'nuw', 'nsw'), binary('shl', 5, 32, 0, 1, 'nuw'),
        simple('freeze', 6, 32, 2), simple('freeze', 7, 32, 3),
        simple('freeze', 8, 32, 4), simple('freeze', 9, 32, 5),
        binary('xor', 10, 32, 6, 7), binary('add', 11, 32, 10, 8), binary('xor', 12, 32, 11, 9)], ret(12))])

    # overshift(x, y): a shift by the width or more is poison; returning it
    # through a noundef result is undefined.
    m.function(112, 'overshift', [32, 32], [32], [block(0, [], [binary('lshr', 2, 32, 0, 1, 'exact')], ret(2))])

    # poison_branch(x, y): branching on a poison comparison is undefined.
    m.function(113, 'poison_branch', [32, 32], [32], [
        block(0, [], [binary('add', 2, 32, 0, 1, 'nsw'), icmp(3, 'slt', 2, 0)], branch(3, 1, 2)),
        block(1, [], [], ret(0)),
        block(2, [], [], ret(1)),
    ])

    # undef_use(x): each use of undef is zero; select forwards undef unchanged.
    m.function(114, 'undef_use', [32], [32], [block(0, [], [
        special(1, 32, 'undef'), special(2, 1, 'undef'), binary('add', 3, 32, 0, 1),
        select(4, 32, 2, 0, 3), const(5, 1, 1), select(6, 32, 5, 1, 0),
        simple('copy', 7, 32, 6), simple('freeze', 8, 32, 7), binary('add', 9, 32, 4, 8)], ret(9))])

    # undef_result(x): returns undef or poison unchanged, by parity of x.
    m.function(115, 'undef_result', [32], [32], [
        block(0, [], [simple('trunc', 1, 1, 0)], branch(1, 1, 2)),
        block(1, [], [special(2, 32, 'undef')], ret(2)),
        block(2, [], [special(3, 32, 'poison'), simple('copy', 4, 32, 3)], ret(4)),
    ], noundef=False)

    # spin(x): never terminates; bounded only by fuel.
    m.function(116, 'spin', [32], [32], [
        block(0, [], [const(1, 32, 1)], jump(1)),
        block(1, [phi(2, 32, (0, 0), (1, 3))], [binary('add', 3, 32, 2, 1)], jump(1)),
    ])

    # zero_poison(x): clz, ctz and abs with their poison flag, then frozen.
    m.function(117, 'zero_poison', [64], [64], [block(0, [], [
        unary('clz', 1, 64, 0, True), unary('ctz', 2, 64, 0, True), unary('abs', 3, 64, 0, True),
        simple('freeze', 4, 64, 1), simple('freeze', 5, 64, 2), simple('freeze', 6, 64, 3),
        binary('shl', 7, 64, 4, 5), binary('xor', 8, 64, 7, 6)], ret(8))])

    # diamond(x): two arms that merge through a phi, with signed comparisons.
    m.function(118, 'diamond', [32], [32], [
        block(0, [], [const(1, 32, 100), icmp(2, 'sgt', 0, 1)], branch(2, 1, 2)),
        block(1, [], [binary('sub', 3, 32, 0, 1)], jump(3)),
        block(2, [], [binary('sub', 4, 32, 1, 0), icmp(5, 'uge', 4, 1), simple('zext', 6, 32, 5),
                      binary('add', 7, 32, 4, 6)], jump(3)),
        block(3, [phi(8, 32, (1, 3), (2, 7))], [], ret(8)),
    ])

    # minmax(a, b): two results; sum_range calls it and uses both.
    m.function(119, 'minmax', [32, 32], [32, 32], [block(0, [], [
        icmp(2, 'slt', 0, 1), select(3, 32, 2, 0, 1), select(4, 32, 2, 1, 0)], ret(3, 4))])
    m.function(120, 'spread', [32, 32], [32], [block(0, [], [
        m.call([(2, 32), (3, 32)], 119, [0, 1]), binary('sub', 4, 32, 3, 2)], ret(4))])

    # compare(x, y): all ten predicates packed into one integer.
    predicates = ['eq', 'ne', 'ult', 'ule', 'ugt', 'uge', 'slt', 'sle', 'sgt', 'sge']
    ops, accumulator = [const(2, 32, 0), const(3, 32, 1)], 2
    value = 4
    for predicate in predicates:
        ops += [icmp(value, predicate, 0, 1), simple('zext', value + 1, 32, value),
                binary('shl', value + 2, 32, accumulator, 3), binary('or', value + 3, 32, value + 2, value + 1)]
        accumulator, value = value + 3, value + 4
    m.function(121, 'compare', [16, 16], [32], [block(0, [], ops, ret(accumulator))])

    memory_programs(m)
    # The format requires every table in increasing identifier order.
    m.types.sort(key=lambda item: item['id'])
    m.functions.sort(key=lambda item: item['id'])
    m.symbols.sort(key=lambda item: item['id'])
    m.index.sort(key=lambda item: item['id'])
    return {'sections': m.roots}, m.index


def memory_programs(m):
    """Stack objects, loads and stores, pointer arithmetic and each memory fault."""
    # stack_sum(n): fill a 16-element array on the stack, then sum it.
    m.function(130, 'stack_sum', [32], [64], [
        block(0, [], [const(1, 64, 128), m.alloca(2, 1, 8), const(3, 64, 0), const(4, 64, 1),
                      const(5, 64, 16), const(6, 64, 8), simple('zext', 7, 64, 0)], jump(1)),
        block(1, [phi(8, 64, (0, 3), (1, 12))], [
            binary('mul', 9, 64, 8, 6), offset(10, 2, 9, inbounds=True), binary('mul', 11, 64, 8, 7),
            store(10, 11, 64), binary('add', 12, 64, 8, 4), icmp(13, 'eq', 12, 5)], branch(13, 2, 1)),
        block(2, [], [], jump(3)),
        block(3, [phi(14, 64, (2, 3), (3, 18)), phi(15, 64, (2, 3), (3, 19))], [
            binary('mul', 16, 64, 14, 6), offset(17, 2, 16, inbounds=True), load(20, 64, 17),
            binary('add', 19, 64, 15, 20), binary('add', 18, 64, 14, 4), icmp(21, 'eq', 18, 5)],
              branch(21, 4, 3)),
        block(4, [], [], ret(19)),
    ])

    # swap_memory(a, b): exchange two stack slots through loads and stores.
    m.function(131, 'swap_memory', [64, 64], [64], [block(0, [], [
        const(2, 64, 8), m.alloca(3, 2, 8), m.alloca(4, 2, 8), store(3, 0, 64), store(4, 1, 64),
        load(5, 64, 3), load(6, 64, 4), store(3, 6, 64), store(4, 5, 64), load(7, 64, 3), load(8, 64, 4),
        const(9, 64, 3), binary('mul', 10, 64, 7, 9), binary('sub', 11, 64, 10, 8)], ret(11))])

    # narrow_wide(x): read one 64-bit store back at 8, 16 and 32 bits, patch a
    # byte in the middle and read the whole word again.
    m.function(132, 'narrow_wide', [64], [64], [block(0, [], [
        const(1, 64, 8), m.alloca(2, 1, 8), store(2, 0, 64), load(3, 8, 2),
        const(4, 64, 2), offset(5, 2, 4, inbounds=True), load(6, 16, 5),
        const(7, 64, 4), offset(8, 2, 7, inbounds=True), load(9, 32, 8),
        const(10, 64, 5), offset(11, 2, 10, inbounds=True), const(12, 8, 0xa5), store(11, 12, 8),
        load(13, 64, 2), simple('zext', 14, 64, 3), simple('zext', 15, 64, 6), simple('zext', 16, 64, 9),
        binary('add', 17, 64, 14, 15), binary('xor', 18, 64, 17, 16), binary('add', 19, 64, 18, 13)],
        ret(19))])

    # uninitialized(x): fresh stack memory is undef, which a load refines to zero.
    m.function(133, 'uninitialized', [32], [32], [block(0, [], [
        const(1, 64, 4), m.alloca(2, 1, 4), load(3, 32, 2), binary('add', 4, 32, 3, 0)], ret(4))])

    # poison_store(x, y): poison survives a store and a load.
    m.function(134, 'poison_store', [32, 32], [32], [block(0, [], [
        const(2, 64, 4), m.alloca(3, 2, 4), binary('add', 4, 32, 0, 1, 'nsw'), store(3, 4, 32),
        load(5, 32, 3)], ret(5))], noundef=False)

    # poison_byte(x, y): one byte of a stored poison value is poison; freeze it.
    m.function(135, 'poison_byte', [32, 32], [32], [block(0, [], [
        const(2, 64, 4), m.alloca(3, 2, 4), binary('add', 4, 32, 0, 1, 'nsw'), store(3, 4, 32),
        load(5, 8, 3), simple('freeze', 6, 8, 5), simple('zext', 7, 32, 6)], ret(7))])

    # out_of_bounds(x): a byte load at offset x of a four-byte object.
    m.function(136, 'out_of_bounds', [64], [32], [block(0, [], [
        const(1, 64, 4), m.alloca(2, 1, 4), const(3, 32, 0x01020304), store(2, 3, 32),
        offset(4, 2, 0), load(5, 8, 4), simple('zext', 6, 32, 5)], ret(6))])

    # inbounds(x): an inbounds offset outside the object is poison, not a trap.
    m.function(137, 'inbounds', [64], [64], [block(0, [], [
        const(1, 64, 8), m.alloca(2, 1, 8), offset(3, 2, 0, inbounds=True),
        convert('ptrtoaddr', 4, 64, 3), convert('ptrtoaddr', 5, 64, 2), binary('sub', 6, 64, 4, 5),
        simple('freeze', 7, 64, 6), const(8, 64, 0x1000), binary('add', 9, 64, 7, 8)], ret(9))])

    # addresses(x): the addresses three stack objects receive.
    m.function(138, 'addresses', [32], [64], [block(0, [], [
        const(1, 64, 4), m.alloca(2, 1, 4), const(3, 64, 16), m.alloca(4, 3, 16),
        const(5, 64, 1), m.alloca(6, 5, 1), convert('ptrtoaddr', 7, 64, 2),
        convert('ptrtoaddr', 8, 64, 4), convert('ptrtoaddr', 9, 64, 6),
        binary('shl', 10, 64, 8, 5), binary('xor', 11, 64, 7, 10), binary('add', 12, 64, 11, 9)],
        ret(12))])

    # lifetime(x): access after lifetime_end traps; a restarted lifetime is undef.
    m.function(139, 'lifetime', [32], [32], [
        block(0, [], [const(1, 64, 4), m.alloca(2, 1, 4), m.lifetime(True, 2, 1), store(2, 0, 32),
                      load(3, 32, 2), m.lifetime(False, 2, 1), simple('trunc', 4, 1, 0)], branch(4, 1, 2)),
        block(1, [], [load(5, 32, 2)], ret(5)),
        block(2, [], [m.lifetime(True, 2, 1), load(6, 32, 2), binary('add', 7, 32, 6, 3)], ret(7)),
    ])

    # misaligned(x): a four-byte load that requires four-byte alignment.
    m.function(140, 'misaligned', [64], [32], [block(0, [], [
        const(1, 64, 16), m.alloca(2, 1, 8), const(3, 64, 0x1122334455667788), store(2, 3, 64),
        const(4, 64, 7), binary('and', 5, 64, 0, 4), offset(6, 2, 5), load(7, 32, 6)], ret(7))])

    # pointer_roundtrip(x): a pointer stored and loaded whole still reaches its
    # object; the same address written as an integer does not.
    m.function(141, 'pointer_roundtrip', [64], [64], [
        block(0, [], [const(1, 64, 8), m.alloca(2, 1, 8), m.alloca(3, 1, 8), store(3, 2, 'ptr'),
                      load(4, 'ptr', 3), store(4, 0, 64), load(5, 64, 2), load(6, 64, 3),
                      store(3, 6, 64), load(7, 'ptr', 3), simple('trunc', 8, 1, 0)], branch(8, 1, 2)),
        block(1, [], [load(9, 64, 7)], ret(9)),
        block(2, [], [], ret(5)),
    ])

    # integer_roundtrip(x): ptrtoint exposes an object to inttoptr; ptrtoaddr
    # does not.
    m.function(142, 'integer_roundtrip', [64], [64], [
        block(0, [], [const(1, 64, 8), m.alloca(2, 1, 8), store(2, 0, 64), simple('trunc', 3, 1, 0)],
              branch(3, 1, 2)),
        block(1, [], [convert('ptrtoint', 4, 64, 2), convert('inttoptr', 5, 'ptr', 4), load(6, 64, 5)],
              ret(6)),
        block(2, [], [convert('ptrtoaddr', 7, 64, 2), convert('inttoptr', 8, 'ptr', 7), load(9, 64, 8)],
              ret(9)),
    ])

    # leak(v) returns the address of its own stack object; escape(x) tries to
    # use it after the activation has ended.
    m.function(150, 'leak', [32], [64], [block(0, [], [
        const(1, 64, 4), m.alloca(2, 1, 4), store(2, 0, 32), convert('ptrtoint', 3, 64, 2)], ret(3))])
    m.declare(143, 'escape', [32], [32])
    m.define(143, [block(0, [], [
        m.call([(1, 64)], 150, [0]), convert('inttoptr', 2, 'ptr', 1), load(3, 32, 2)], ret(3))])

    # grow(n) keeps 256 bytes of stack per activation; deep(n) recurses until
    # the live-memory limit the test sets (4 KiB) is reached.
    m.declare(151, 'grow', [32], [32])
    m.define(151, [
        block(0, [], [const(1, 64, 256), m.alloca(2, 1, 8), store(2, 0, 32), const(3, 32, 0),
                      icmp(4, 'eq', 0, 3)], branch(4, 1, 2)),
        block(1, [], [load(5, 32, 2)], ret(5)),
        block(2, [], [const(6, 32, 1), binary('sub', 7, 32, 0, 6), m.call([(8, 32)], 151, [7]),
                      load(9, 32, 2), binary('add', 10, 32, 8, 9)], ret(10)),
    ])
    m.declare(144, 'deep', [32], [32])
    m.define(144, [block(0, [], [
        const(1, 32, 31), binary('and', 2, 32, 0, 1), m.call([(3, 32)], 151, [2])], ret(3))])

    # null_access(x): loads through a null, an undef and a poison pointer.
    m.function(145, 'null_access', [32], [32], [
        block(0, [], [const(1, 32, 3), binary('and', 2, 32, 0, 1), const(3, 32, 0), icmp(4, 'eq', 2, 3)],
              branch(4, 1, 2)),
        block(1, [], [null(5), load(6, 32, 5)], ret(6)),
        block(2, [], [const(7, 32, 1), icmp(8, 'eq', 2, 7)], branch(8, 3, 4)),
        block(3, [], [special(9, 'ptr', 'undef'), load(10, 32, 9)], ret(10)),
        block(4, [], [const(11, 32, 2), icmp(12, 'eq', 2, 11)], branch(12, 5, 6)),
        block(5, [], [special(13, 'ptr', 'poison'), load(14, 32, 13)], ret(14)),
        block(6, [], [], ret(0)),
    ])


def main():
    document, index = build()
    text = json.dumps(document, indent=1, sort_keys=True) + '\n'
    listing = json.dumps(index, indent=1) + '\n'
    outputs = {HERE / 'programs.json': text, HERE / 'index.json': listing}
    if sys.argv[1:] == ['--check']:
        stale = [path.name for path, expected in outputs.items()
                 if not path.exists() or path.read_text() != expected]
        if stale:
            sys.exit('out of date; rerun build.py: ' + ', '.join(stale))
        return
    if sys.argv[1:]:
        sys.exit(__doc__)
    for path, expected in outputs.items():
        path.write_text(expected)


if __name__ == '__main__':
    main()
