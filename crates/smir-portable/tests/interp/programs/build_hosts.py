#!/usr/bin/env python3
"""Author a module that imports functions of its host, as editable ten-root
JSON, and the descriptors a host registers those functions with.

    python3 -B build_hosts.py            # rewrite hosts.json, hosts-user.json and hosts.descriptors.json
    python3 -B build_hosts.py --check    # fail if any is out of date

A host function is an application's own, over integers and floats. The
module imports each by namespace, name and version and quotes the identity
of its descriptor: the record that says what the function takes and
returns, which the host registers the function with. `hosts.json` is such a
module, and `hosts.descriptors.json` has the bytes of each descriptor, in
hex, by the function's name; `../hosts.rs` and the host C interface's tests
are hosts that have the functions. `hosts.smo` is the module assembled. It
declares the capability `host_value`, as the format asks of a module with
such imports. `hosts-user.json` is a program that needs that module and
imports a host function itself.
"""
import hashlib
import json
from pathlib import Path
import sys

import build
from build import binary, block, const, decl, ref, ret, special, type_of
from build_linked import Linked

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[4] / 'tools/smir-format'))

import smir  # noqa: E402

# The functions: (namespace, name, version) and the kinds of what each takes
# and returns.
FUNCTIONS = {
    'add': (('app', 'add', 1), [32, 32], [32]),
    'tick': (('app', 'tick', 1), [], [64]),
    'scale': (('app.math', 'scale', 3), ['f64', 64], ['f64']),
}


class Hosted(Linked):
    def __init__(self, name):
        super().__init__(name)
        self.codec = smir.records().records
        self.descriptors = {}
        self.imported = {}
        self.roots['9']['capabilities'] = ['host_value']
        for position, (function, (key, params, results)) in enumerate(FUNCTIONS.items()):
            self.host(10 + position, function, key, params, results)

    def host(self, identifier, function, key, params, results):
        """Import a host function, with the descriptor that is made of its
        name and of the types of its signature."""
        signature = self.signature(params, results, False, False)
        types = {item['id']: item for item in self.types}
        # The descriptor's types are numbered by the function alone: those of
        # the parameters and then of the results from 0, each once, in the
        # order they are first met, and the function type after them. That
        # is how tools/smir-clang/smircc.py numbers them, so the descriptor
        # of a function is the same whoever imports it.
        numbers = {}
        for kind in params + results:
            numbers.setdefault(type_of(kind), len(numbers))
        root = {'payload_revision': 2, 'memory_layouts': [],
                'types': [dict(types[identifier], id=number) for identifier, number in numbers.items()]
                + [dict(types[signature], id=len(numbers),
                        params=[ref(numbers[type_of(kind)]) for kind in params],
                        results=[ref(numbers[type_of(kind)]) for kind in results])]}
        namespace, name, version = key
        record = self.codec.encode('runtime_host_descriptor', {
            'revision': 1, 'namespace': namespace, 'name': name, 'version': version,
            'types': self.codec.encode('execution_types', root).hex(), 'signature': len(numbers)})
        self.descriptors[function] = record.hex()
        self.roots['6']['imports'].append({
            'id': identifier, 'kind': 'host', 'namespace': namespace, 'name': name, 'version': version,
            'descriptor': hashlib.sha256(b'SMIR-HOST-V1\0' + record).hexdigest(),
            'signature': ref(signature), 'capability': 'host_value'})
        self.imported[function] = (identifier, signature)

    def asks(self, values, function, operands):
        """A call of a host function; `values` are (id, kind) results."""
        identifier, signature = self.imported[function]
        return {'op': 'call', 'results': [decl(value, kind) for value, kind in values],
                'operands': list(operands),
                'target': {'kind': 'import', 'import': ref(identifier), 'signature': ref(signature)},
                'unwind': 'propagate', 'source_plan': None}


def hosts():
    m = Hosted('hosts')
    # sum3(a, b, c): add(add(a, b), c), two calls of the host.
    m.export(300, 'sum3', [32, 32, 32], [32], [block(0, [], [
        m.asks([(3, 32)], 'add', [0, 1]), m.asks([(4, 32)], 'add', [3, 2])], ret(4))])
    # ticks(): the host's count, twice, and the two added.
    m.export(301, 'ticks', [], [64], [block(0, [], [
        m.asks([(0, 64)], 'tick', []), m.asks([(1, 64)], 'tick', []), binary('add', 2, 64, 0, 1)], ret(2))])
    # scaled(x, by): a float through the host and back.
    m.export(302, 'scaled', ['f64', 64], ['f64'], [block(0, [], [m.asks([(2, 'f64')], 'scale', [0, 1])],
                                                         ret(2))])
    # poisoned(): poison is nothing a host is given.
    m.export(303, 'poisoned', [], [32], [block(0, [], [
        special(0, 32, 'poison'), const(1, 32, 1), m.asks([(2, 32)], 'add', [0, 1])], ret(2))])
    # unspecified(): of an unspecified value the host gets zero.
    m.export(304, 'unspecified', [], [32], [block(0, [], [
        special(0, 32, 'undef'), const(1, 32, 5), m.asks([(2, 32)], 'add', [0, 1])], ret(2))])
    return m


def user():
    """A program that needs `hosts` and has host functions of its own: linked,
    the two modules' imports are one program's."""
    m = Hosted('hosts_user')
    m.needs(0, 'hosts', {'sum3': ([32, 32, 32], [32])})
    # both(a, b): add(a, b) by this module's import, plus sum3(a, b, 0) by
    # the other module's.
    m.export(300, 'both', [32, 32], [32], [block(0, [], [
        m.asks([(2, 32)], 'add', [0, 1]), const(3, 32, 0), m.outside([(4, 32)], 0, 'sum3', [0, 1, 3]),
        binary('add', 5, 32, 2, 4)], ret(5))])
    return m


def main():
    m = hosts()
    build.write({HERE / 'hosts.json': m.document(),
                 HERE / 'hosts-user.json': user().document(),
                 HERE / 'hosts.descriptors.json': json.dumps(m.descriptors, indent=1, sort_keys=True) + '\n'},
                __doc__)


if __name__ == '__main__':
    main()
