#!/usr/bin/env python3
"""Author the interpreter differential programs as editable ten-root JSON.

    python3 -B build.py            # rewrite programs.json
    python3 -B build.py --check    # fail if programs.json is out of date

The module starts from the repository's `add64.json` reference source, which
supplies valid ABI and manifest sections, and appends integer types, functions
and their symbols. `programs.smo` is `programs.json` assembled by
`tools/smir-format/smir.py assemble`.

Every program stays inside what the Python reference CLI can run (integers of
at most 64 bits; the integer, cast, compare, select, freeze and call
operations; `return`, `jump` and `cbranch`), because that CLI is the oracle
the Rust interpreter is compared with.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = (ROOT / 'docs/specifications/smir/portable/conformance/envelope/candidate'
        / 'reference-execution/integers/add64.json')
INT = {1: 2001, 8: 2008, 16: 2016, 32: 2032, 64: 2064}


def ref(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


def decl(value, bits):
    return {'id': value, 'type': ref(INT[bits])}


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

    def signature(self, params, results, noundef):
        key = (tuple(params), tuple(results), noundef)
        if key not in self.signatures:
            identifier = 2100 + len(self.signatures)
            self.signatures[key] = identifier
            self.types.append({
                'kind': 'function', 'id': identifier,
                'params': [ref(INT[bits]) for bits in params],
                'results': [ref(INT[bits]) for bits in results],
                'variadic': False, 'param_noundef': [True] * len(params),
                'result_noundef': [noundef] * len(results), 'cc': 'portable'})
        return self.signatures[key]

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

    m.types.sort(key=lambda item: item['id'])
    return {'sections': m.roots}, m.index


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
