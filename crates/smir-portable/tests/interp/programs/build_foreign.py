#!/usr/bin/env python3
"""Author the modules that call foreign code, as editable ten-root JSON.

    python3 -B build_foreign.py            # rewrite foreign-x86_64.json and foreign-aarch64.json
    python3 -B build_foreign.py --check    # fail if either is out of date

Foreign code is machine code of another processor that the runtime runs
with a processor of its own making. A module does not hold it: it names a
native image by its SHA-256, and a byte range of it for each function it
has there. `../foreign/guest-*.elf` are such images (`../foreign/guest.json`
says what is in them), and each of these modules is for one of them:

- its manifest names the foreign processor;
- its ABI root has a second domain, of that processor, and for each
  function of the image a bridge to it: the function's native symbol, how
  the function unwinds, and the signature it is called with from portable
  code, `int(int)`;
- it imports each bridge (`kind` `foreign`), and has a function
  `call_NAME(x)` that calls the import and returns what comes back;
- it has two functions that the foreign code calls, `twice(x)`, which is
  2x, and `step(n)`, which is the foreign `down(n - 1)`. For each there is
  a bridge the other way, from the foreign domain to the portable one: its
  entry is a function of the image that the runtime takes over, where the
  foreign code goes to make the call, and its recipe for the arguments is
  one call of the portable function. The bridges of the foreign functions
  that call back say that they do (`callbacks` `owner_thread`).

The ABI root and the types are those of the reference fixture of
`tools/smir-abi/candidate_fixtures.py`, which has one such bridge; here
there is one for each function. The unwind rows are that fixture's and
describe no real prologue: no exception crosses these bridges, which say so
(`exceptions` `noexcept`). `../foreign.rs` runs the modules; each `.smo` is
its `.json` assembled.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys

import build

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path[:0] = [str(ROOT / 'tools/smir-format'), str(ROOT / 'tools/smir-abi')]

from candidate_fixtures import build as reference, step  # noqa: E402
from nominal import ref, some  # noqa: E402

SPEC = ROOT / 'docs/specifications/smir/portable'
# The functions of the image that are called, in the order of their bridges,
# and those of them whose bridges say that they call back. `quiet` calls
# back and its bridge does not say so.
NAMES = ('scale', 'count', 'fault', 'silent', 'stale', 'spin', 'apply', 'down', 'quiet', 'other', 'crooked')
CALLING = ('apply', 'down', 'other', 'crooked')
# The portable functions the image calls, each with the identifier of its
# bridge, which the image's wrappers put into their frames (`guest.c`).
CALLED = (('twice', 100), ('step', 101))
PERSONALITY, METADATA, FIRST_BRIDGE, FIRST_ENTRY = 101, 103, 110, 130
IMPORTS, FIRST_CALLED = 50, 20


def module(machine, guest):
    image, functions = guest['sha256'], guest['functions']
    document, evidence = reference()
    domain = document['domains'][1]
    domain.update(isa=machine)
    roots = {int(key): value for key, value in json.loads(
        (SPEC / 'conformance/execution/candidate/portable-identity.json').read_text())['sections'].items()}
    roots.setdefault(5, {'payload_revision': 2, 'relocations': [], 'constant_initializers': []})
    roots.setdefault(7, {'payload_revision': 1, 'segments': []})
    roots[9] = {'payload_revision': 1, 'capabilities': ['foreign'], 'requirements': [], 'limits': []}
    roots[10] = document
    roots[1]['types'] = deepcopy(evidence['execution_graph'])
    roots[1]['memory_layouts'] = sorted(deepcopy(list(evidence['memory_layouts'].values())),
                                        key=lambda item: item['id'])
    roots[2]['manifest'].update(foreign_isa=machine, personality=domain['personality'])
    roots[2]['manifest']['key']['name'] = f'foreign_{machine}'
    nominal = {item['id']: item for item in document['types']}
    symbols = roots[2]['symbols']

    def native(identifier, name, signature, execution, where):
        """The symbol of a function of the image: a byte range of it."""
        symbols.append({
            'id': identifier, 'namespace': 'fixture', 'name': name, 'kind': 'function',
            'source_linkage': 'cpp', 'binding': 'strong', 'visibility': 'hidden', 'execution': ref(execution),
            'nominal': {'some': signature}, 'abi_signature': None,
            'definition': {'some': {'kind': 'native', 'image': image, 'domain': domain['id'],
                                    'offset': where['offset'], 'size': where['size']}},
            'size': {'some': where['size']}, 'alignment': 16, 'comdat': None, 'fallback': None})

    def execution_of(signature, identifier):
        """The execution type of a native function type, under `identifier`."""
        elements = [nominal[item['id']] for item in nominal[signature['id']]['elements']]
        shapes = [None if item['kind'] == 'void' else deepcopy(item['execution']['some']) for item in elements]
        params, result = shapes[:-1], shapes[-1]
        roots[1]['types'].append({
            'id': identifier, 'kind': 'function', 'cc': 'portable', 'variadic': False, 'params': params,
            'results': [] if result is None else [result], 'param_noundef': [True] * len(params),
            'result_noundef': [] if result is None else [True]})
        return identifier

    entry_type = evidence['symbols']['100']['signature']
    personality_type = evidence['symbols']['101']['signature']
    entry_execution = execution_of(entry_type, 600)
    native(PERSONALITY, 'personality', personality_type, execution_of(personality_type, 601),
           functions['personality'])

    # The unwind metadata the fixture declares, as the bytes of a segment.
    data = bytes.fromhex(evidence['metadata'][str(METADATA)])
    roots[1]['types'] += [{'id': 603, 'kind': 'raw', 'bits': 8},
                          {'id': 604, 'kind': 'array', 'element': ref(603), 'count': len(data)}]
    symbols.append({
        'id': METADATA, 'namespace': 'fixture', 'name': 'declared_unwind_metadata', 'kind': 'data',
        'source_linkage': 'none', 'binding': 'strong', 'visibility': 'hidden', 'execution': ref(604),
        'nominal': None, 'abi_signature': None, 'definition': {'some': {'kind': 'data', 'segment': METADATA}},
        'size': {'some': len(data)}, 'alignment': 1, 'comdat': None, 'fallback': None})
    roots[4]['segments'] = [{
        'id': METADATA, 'layout': None, 'nominal': None, 'abi_binding': None, 'alignment': 1, 'mutable': False,
        'initial': data.hex(), 'poison': '00' * len(data), 'undef': '00' * len(data), 'zero_fill': 0,
        'zero_shadow': 'defined'}]

    # One bridge for each function, after the fixture's one.
    first_bridge, first_unwind = document['bridges'][0], document['unwind'][0]
    document['bridges'], document['unwind'] = [], []
    identity = roots[3]['functions'][0]
    called = next(item for item in document['signatures'] if item['id'] == first_bridge['signature'])
    for position, name in enumerate(NAMES):
        where = functions[f'bridge_{name}']
        native(FIRST_BRIDGE + position, f'bridge_{name}', entry_type, entry_execution, where)
        unwind = deepcopy(first_unwind)
        unwind.update(id=position, function=ref(FIRST_BRIDGE + position), code_size=where['size'])
        unwind['rows'][0]['end'] = unwind['regions'][0]['end'] = where['size']
        document['unwind'].append(unwind)
        document['bridges'].append(dict(
            first_bridge, id=position, entry=ref(FIRST_BRIDGE + position), unwind=position,
            callbacks='owner_thread' if name in CALLING else 'none',
            exceptions='noexcept', ownership='borrowed', identity='preserve', aliases='none'))
        roots[6]['imports'].append({'id': IMPORTS + position, 'kind': 'foreign', 'descriptor': ref(position),
                                    'signature': deepcopy(called['execution']), 'capability': 'foreign'})
        # call_NAME(x): what the foreign function makes of x.
        function = deepcopy(identity)
        function.update(id=1 + position, abi_signature=None)
        function['blocks'][0].update(
            ops=[{'op': 'call', 'results': [{'id': 1, 'type': deepcopy(function['params'][0]['type'])}],
                  'operands': [0],
                  'target': {'kind': 'import', 'import': ref(IMPORTS + position),
                             'signature': deepcopy(called['execution'])},
                  'unwind': 'propagate', 'source_plan': None}],
            term={'op': 'return', 'values': [1]})
        roots[3]['functions'].append(function)
        symbols.append({
            'id': 1 + position, 'namespace': 'example', 'name': f'call_{name}', 'kind': 'function',
            'source_linkage': 'none', 'binding': 'strong', 'visibility': 'default',
            'execution': deepcopy(identity['signature']), 'nominal': None, 'abi_signature': None,
            'definition': {'some': {'kind': 'function', 'target': ref(1 + position)}},
            'size': None, 'alignment': 1, 'comdat': None, 'fallback': None})

    # The functions the foreign code calls, and the bridge to each.
    value = deepcopy(identity['params'][0]['type'])
    integer = called['lowered_params'][0]['value_type']['id']
    bodies = {
        # twice(x): x + x.
        'twice': ([{'op': 'i_add', 'results': [{'id': 1, 'type': value}], 'operands': [0, 0], 'flags': []}], 1),
        # step(n): what the foreign `down` makes of n - 1.
        'step': ([{'op': 'constant', 'results': [{'id': 1, 'type': value}], 'operands': [],
                   'literal': {'kind': 'bits', 'value': '01000000'}},
                  {'op': 'i_sub', 'results': [{'id': 2, 'type': value}], 'operands': [0, 1], 'flags': []},
                  {'op': 'call', 'results': [{'id': 3, 'type': value}], 'operands': [2],
                   'target': {'kind': 'import', 'import': ref(IMPORTS + NAMES.index('down')),
                              'signature': deepcopy(called['execution'])},
                   'unwind': 'propagate', 'source_plan': None}], 3)}
    first_symbol = next(item for item in symbols if item['id'] == identity['id'])
    for position, (name, bridge) in enumerate(CALLED):
        target, entry = FIRST_CALLED + position, FIRST_ENTRY + position
        ops, result = bodies[name]
        function = deepcopy(identity)
        function['id'] = target
        function['blocks'][0].update(ops=ops, term={'op': 'return', 'values': [result]})
        roots[3]['functions'].append(function)
        # A function of C++, as the reference's is: it has the nominal type
        # a recipe needs of what it calls.
        symbols.append(dict(deepcopy(first_symbol), id=target, name=f'_Z{len(name)}{name}i', visibility='hidden',
                            definition={'some': {'kind': 'function', 'target': ref(target)}}))
        where = functions[f'callback_{name}']
        native(entry, f'callback_{name}', entry_type, entry_execution, where)
        unwind = deepcopy(first_unwind)
        unwind.update(id=len(NAMES) + position, function=ref(entry), code_size=where['size'])
        unwind['rows'][0]['end'] = unwind['regions'][0]['end'] = where['size']
        # An entry is a few bytes, fewer than the reference's function has
        # before its landing pad.
        unwind['regions'][0]['landing_offset'] = 0
        document['unwind'].append(unwind)
        document['recipes'].append({
            'id': 1 + position, 'domain': 0, 'params': [{'id': 0, 'type': ref(integer)}],
            'results': [ref(integer)], 'entry': 0,
            'steps': [step(0, 'call', [0], [(1, integer)], normal=1, callee=some(ref(target))),
                      step(1, 'return', [1])]})
        document['bridges'].append(dict(
            first_bridge, id=bridge, source=domain['id'], target=0, entry=ref(entry),
            unwind=len(NAMES) + position, arguments=1 + position, callbacks='none', exceptions='noexcept',
            ownership='borrowed', identity='preserve', aliases='none'))
    roots[3]['functions'].sort(key=lambda item: item['id'])
    roots[1]['types'].sort(key=lambda item: item['id'])
    roots[6]['imports'].sort(key=lambda item: item['id'])
    symbols.sort(key=lambda item: item['id'])
    return json.dumps({'sections': {str(key): roots[key] for key in sorted(roots)}}, indent=1, sort_keys=True) + '\n'


def main():
    guests = json.loads((HERE.parent / 'foreign/guest.json').read_text())
    build.write({HERE / f'foreign-{machine}.json': module(machine, guest) for machine, guest in guests.items()},
                __doc__)


if __name__ == '__main__':
    main()
