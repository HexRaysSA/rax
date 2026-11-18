#!/usr/bin/env python3
"""Author the modules that are linked, as editable ten-root JSON.

    python3 -B build_linked.py            # rewrite the linked-*.json files
    python3 -B build_linked.py --check    # fail if any is out of date

Three modules make a program:

- `linked-base.json`, known as `example:base` 1.2: functions over a counter
  of its own, and an initializer.
- `linked-shapes.json`, known as `example:shapes` 1.0: functions that call
  those of `base`, an initializer that does, and a function it hides.
- `linked-main.json`, the program: it calls both.

A module names another as a dependency, with a slot, and declares the
functions it calls of it; a call of one is a call whose function is a
reference to that slot and declaration instead of to the module itself. The
other files are modules that cannot be linked with these, each for one
reason. `../linking.rs` links and runs them; each `.smo` is its `.json`
assembled. None needs a capability.
"""
from pathlib import Path

import build
from build import Module, address_of, binary, block, const, decl, load, ref, ret, store

HERE = Path(__file__).resolve().parent


class Linked(Module):
    def __init__(self, name, minor=0):
        """A module known as `example:<name>` 1.<minor>, with nothing in it."""
        super().__init__()
        self.functions.clear()
        self.symbols.clear()
        self.manifest = self.roots['2']['manifest']
        self.manifest['key'] = {'namespace': 'example', 'name': name, 'abi_major': 1, 'abi_minor': minor}
        self.declared = {}

    def needs(self, slot, name, functions, minimum_minor=0, baseline=None):
        """Depend on `example:<name>` and declare functions of it: each a
        name with the kinds of its parameters and results."""
        declarations = []
        for position, (function, (params, results)) in enumerate(functions.items()):
            signature = self.signature(params, results, True)
            self.declared[slot, function] = (position, signature)
            declarations.append({
                'id': position, 'kind': 'function', 'symbol_kind': 'none', 'source_linkage': 'none',
                'namespace': 'example', 'name': function, 'execution': {'some': ref(signature)},
                'nominal': None, 'abi_signature': None, 'weak': False})
        self.manifest['dependencies'].append({
            'slot': slot,
            'key': {'namespace': 'example', 'name': name, 'abi_major': 1,
                    'abi_minor': minimum_minor if baseline is None else baseline},
            'minimum_minor': minimum_minor, 'maximum_minor': None, 'site': self.manifest['site'],
            'declarations': declarations})

    def outside(self, values, slot, function, operands):
        """A call of a declared function of a dependency; `values` are (id, bits) results."""
        position, signature = self.declared[slot, function]
        return {'op': 'call', 'results': [decl(value, bits) for value, bits in values],
                'operands': list(operands),
                'target': {'kind': 'direct', 'signature': ref(signature),
                           'function': {'module': {'kind': 'dependency', 'slot': slot}, 'id': position}},
                'unwind': 'propagate', 'source_plan': None}

    def export(self, identifier, name, params, results, blocks):
        """A function other modules may call, under exactly this name."""
        self.function(identifier, name, params, results, blocks, symbol=name)

    def hidden(self, identifier, name, params, results, blocks):
        """A function with a name that is the module's own: no other may call it."""
        self.export(identifier, name, params, results, blocks)
        self.symbols[-1]['visibility'] = 'hidden'

    def before(self, identifier, blocks):
        """A function that takes and returns nothing and runs before the program."""
        self.function(identifier, f'initialize_{identifier}', [], [], blocks, noundef=False)
        self.roots['2']['initializers'].append(
            {'function': ref(identifier), 'priority': 1, 'ordinal': len(self.roots['2']['initializers']),
             'association': None})

    def document(self):
        self.types.sort(key=lambda item: item['id'])
        self.roots['1']['memory_layouts'].sort(key=lambda item: item['id'])
        self.roots['6']['imports'].sort(key=lambda item: item['id'])
        self.functions.sort(key=lambda item: item['id'])
        self.symbols.sort(key=lambda item: item['id'])
        import json
        return json.dumps({'sections': self.roots}, indent=1, sort_keys=True) + '\n'


def base(minor=2):
    m = Linked('base', minor)
    m.data(400, 'counter', build.words(0, size=8))
    m.data(401, 'ready', build.words(0, size=8))
    # The initializer: until it has run, `ready_value` yields 0.
    m.before(310, [block(0, [], [address_of(0, 401), const(1, 64, 7), store(0, 1, 64)], ret())])
    # scale(x): three times x.
    m.export(300, 'scale', [32], [32], [block(0, [], [const(1, 32, 3), binary('mul', 2, 32, 0, 1)], ret(2))])
    # count(): how many times it has been called, this time included.
    m.export(301, 'count', [], [64], [block(0, [], [
        address_of(0, 400), load(1, 64, 0), const(2, 64, 1), binary('add', 3, 64, 1, 2), store(0, 3, 64)],
        ret(3))])
    # ready_value(): what the initializer stored.
    m.export(302, 'ready_value', [], [64], [block(0, [], [address_of(0, 401), load(1, 64, 0)], ret(1))])
    return m


def shapes():
    m = Linked('shapes')
    m.needs(0, 'base', {'scale': ([32], [32]), 'count': ([], [64]), 'ready_value': ([], [64])})
    m.data(400, 'stored', build.words(0, size=8))
    # Its initializer asks `base` for what `base`'s initializer stored, which
    # is there only if that ran first.
    m.before(310, [block(0, [], [
        m.outside([(0, 64)], 0, 'ready_value', []), const(1, 64, 1), binary('add', 2, 64, 0, 1),
        address_of(3, 400), store(3, 2, 64)], ret())])
    # area(w, h): scale(w) times h.
    m.export(300, 'area', [32, 32], [32], [block(0, [], [
        m.outside([(2, 32)], 0, 'scale', [0]), binary('mul', 3, 32, 2, 1)], ret(3))])
    # ticks(): counts twice in `base` and returns the second count.
    m.export(301, 'ticks', [], [64], [block(0, [], [
        m.outside([(0, 64)], 0, 'count', []), m.outside([(1, 64)], 0, 'count', [])], ret(1))])
    # stored_value(): what its initializer stored.
    m.export(302, 'stored_value', [], [64], [block(0, [], [address_of(0, 400), load(1, 64, 0)], ret(1))])
    # scale(x): a function of its own with the name of one of `base`, which
    # nobody calls: a hundred times x.
    m.export(303, 'scale', [32], [32], [block(0, [], [const(1, 32, 100), binary('mul', 2, 32, 0, 1)], ret(2))])
    # inner(x): x itself, for this module alone.
    m.hidden(304, 'inner', [32], [32], [block(0, [], [], ret(0))])
    return m


def main_module():
    m = Linked('main')
    m.needs(0, 'shapes', {'area': ([32, 32], [32]), 'ticks': ([], [64]), 'stored_value': ([], [64])})
    m.needs(1, 'base', {'scale': ([32], [32]), 'count': ([], [64])}, minimum_minor=1)
    # entry(x): area(x, 2) + scale(x), which is nine times x.
    m.export(300, 'entry', [32], [32], [block(0, [], [
        const(1, 32, 2), m.outside([(2, 32)], 0, 'area', [0, 1]), m.outside([(3, 32)], 1, 'scale', [0]),
        binary('add', 4, 32, 2, 3)], ret(4))])
    # counts(): `base` counts once for this module and twice for `shapes`,
    # in one counter: there is one `base`.
    m.export(301, 'counts', [], [64, 64], [block(0, [], [
        m.outside([(0, 64)], 1, 'count', []), m.outside([(1, 64)], 0, 'ticks', [])], ret(0, 1))])
    # order(): what the initializer of `shapes` found in `base`, plus one.
    m.export(302, 'order', [], [64], [block(0, [], [m.outside([(0, 64)], 0, 'stored_value', [])], ret(0))])
    return m


def unlinkable():
    """Modules that these cannot be linked with, each for one reason."""
    # A function `base` does not have.
    absent = Linked('absent')
    absent.needs(0, 'base', {'missing': ([32], [32])})
    absent.export(300, 'entry', [32], [32], [block(0, [], [absent.outside([(1, 32)], 0, 'missing', [0])],
                                                   ret(1))])
    # A function `base` has with another type.
    mistyped = Linked('mistyped')
    mistyped.needs(0, 'base', {'scale': ([64], [64])})
    mistyped.export(300, 'entry', [64], [64], [block(0, [], [mistyped.outside([(1, 64)], 0, 'scale', [0])],
                                                     ret(1))])
    # A function `shapes` keeps to itself.
    prying = Linked('prying')
    prying.needs(0, 'shapes', {'inner': ([32], [32])})
    prying.export(300, 'entry', [32], [32], [block(0, [], [prying.outside([(1, 32)], 0, 'inner', [0])], ret(1))])
    # A later `base` than there is.
    newer = Linked('newer')
    newer.needs(0, 'base', {'scale': ([32], [32])}, minimum_minor=3)
    newer.export(300, 'entry', [32], [32], [block(0, [], [newer.outside([(1, 32)], 0, 'scale', [0])], ret(1))])
    # Two modules that each need the other.
    left, right = Linked('left'), Linked('right')
    left.needs(0, 'right', {'back': ([32], [32])})
    left.export(300, 'forth', [32], [32], [block(0, [], [left.outside([(1, 32)], 0, 'back', [0])], ret(1))])
    right.needs(0, 'left', {'forth': ([32], [32])})
    right.export(300, 'back', [32], [32], [block(0, [], [right.outside([(1, 32)], 0, 'forth', [0])], ret(1))])
    # A program for another system than `base` is for.
    abroad = Linked('abroad')
    abroad.manifest['personality'] = 'darwin'
    abroad.needs(0, 'base', {'scale': ([32], [32])})
    abroad.export(300, 'entry', [32], [32], [block(0, [], [abroad.outside([(1, 32)], 0, 'scale', [0])], ret(1))])
    return {'absent': absent, 'mistyped': mistyped, 'prying': prying, 'newer': newer, 'left': left,
            'right': right, 'abroad': abroad}


def main():
    modules = {'base': base(), 'shapes': shapes(), 'main': main_module(), **unlinkable()}
    build.write({HERE / f'linked-{name}.json': module.document() for name, module in modules.items()}, __doc__)


if __name__ == '__main__':
    main()
