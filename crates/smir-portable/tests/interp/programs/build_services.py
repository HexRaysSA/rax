#!/usr/bin/env python3
"""Author the runtime service programs as editable ten-root JSON.

    python3 -B build_services.py            # rewrite services.json and lifecycle.json
    python3 -B build_services.py --check    # fail if either is out of date

`services.json` is a second module beside `programs.json`, built with the same helpers. It
imports the runtime services the interpreter performs (`file.read`,
`file.write`, `process.exit`, `process.abort`) and declares the capabilities
they need, so it cannot share a module with the differential programs: those
run with no capability granted, and the Python reference machine performs no
services. `../services.rs` runs these programs against a host that records
what they write. `services.smo` is `services.json` assembled.

`lifecycle.json` is a third module, with initializers and finalizers that each
write one letter, so that the order they run in shows in the output, and a
function that reads a clock.

`mapping.json` is a fourth, whose functions map memory, use it, change what
it permits and unmap it.
"""
import hashlib
import json
from pathlib import Path

import build
from build import (Module, address_of, binary, block, branch, bulk, const, decl, icmp, load, offset, ref,
                   ret, special, store)

HERE = Path(__file__).resolve().parent
CATALOG = build.ROOT / 'docs/specifications/smir/portable/schema/runtime/services-v1.json'
# Import identifiers; the stack and lifetime helpers are 0 to 2.
SERVICES = {'file.read': 3, 'file.write': 4, 'process.exit': 5, 'process.abort': 6, 'clock.now': 7,
            'thread.spawn': 8, 'thread.join': 9, 'thread.detach': 10, 'thread.yield': 11, 'thread.id': 12,
            'thread.exit': 13, 'sync.wait32': 14, 'sync.wake32': 15,
            'memory.map': 16, 'memory.unmap': 17, 'memory.protect': 18}
TEXT = b'hello\n'


def catalog_digest(catalog):
    """The identity a service import must quote for the catalog it uses."""
    canonical = json.dumps(catalog, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(b'SMIR-SERVICES-V1\0' + canonical.encode('ascii')).hexdigest()


class ServiceModule(Module):
    def __init__(self, services):
        """A module that imports `services` and declares the capabilities they need."""
        super().__init__()
        catalog = json.loads(CATALOG.read_text())
        rows = {row['name']: row for row in catalog['records']}
        kinds = {'u64': 64, 'u32': 32, 'i32': 32, 'data_ptr': 'ptr'}
        if 'thread.spawn' in services:
            # The one code pointer a service takes: a thread's entry.
            kinds['code_ptr'] = self.code_pointer(['ptr'], [64])[0]
        self.service_signatures = {}
        for name in services:
            identifier, row = SERVICES[name], rows[name]
            signature = self.signature([kinds[item['type']] for item in row['params']],
                                       [kinds[item['type']] for item in row['results']],
                                       False, param_noundef=False)
            self.service_signatures[name] = signature
            self.roots['6']['imports'].append({
                'id': identifier, 'kind': 'service', 'namespace': row['namespace'], 'name': name,
                'version': row['version'], 'catalog': catalog_digest(catalog), 'signature': ref(signature),
                'abi': None, 'capability': row['capability'], 'descriptor': None})
        self.roots['9']['capabilities'] = sorted({rows[name]['capability'] for name in services})

    def service(self, name, values, operands):
        """A call of a runtime service; `values` are (id, bits) results."""
        return {'op': 'call', 'results': [decl(value, bits) for value, bits in values],
                'operands': list(operands),
                'target': {'kind': 'import', 'import': ref(SERVICES[name]),
                           'signature': ref(self.service_signatures[name])},
                'unwind': 'propagate', 'source_plan': None}


def packed(value, status, count):
    """status * 65536 + count as a 32-bit value; uses identifiers value-3 to value."""
    return [build.simple('trunc', value - 3, 32, count), const(value - 2, 32, 16),
            binary('shl', value - 1, 32, status, value - 2), binary('or', value, 32, value - 1, value - 3)]


def programs(m):
    text = m.data(400, 'text', TEXT, mutable=False, alignment=1)
    assert text == 0

    # main(argc, argv): writes the first five bytes of argv[1] to standard
    # output and returns argc, plus 100 if argv[argc] is the null pointer.
    m.function(300, 'main', [32, 'ptr'], [32], [block(0, [], [
        const(2, 64, 8), offset(3, 1, 2), load(4, 'ptr', 3),
        const(5, 64, 1), const(6, 64, 5), m.service('file.write', [(7, 32), (8, 64)], [5, 4, 6]),
        build.simple('sext', 9, 64, 0), binary('mul', 10, 64, 9, 2), offset(11, 1, 10), load(12, 'ptr', 11),
        build.null(13), icmp(14, 'eq', 12, 13), build.simple('zext', 15, 32, 14), const(16, 32, 100),
        binary('mul', 17, 32, 15, 16), binary('add', 18, 32, 0, 17)], ret(18))], symbol='main')

    # write_text(handle, length): writes that many bytes of the constant text.
    m.function(301, 'write_text', [64, 64], [32], [block(0, [], [
        address_of(2, 400), m.service('file.write', [(3, 32), (4, 64)], [0, 2, 1]),
        *packed(8, 3, 4)], ret(8))])

    # write_null(length): a span at the null pointer.
    m.function(302, 'write_null', [64], [32], [block(0, [], [
        build.null(1), const(2, 64, 1), m.service('file.write', [(3, 32), (4, 64)], [2, 1, 0]),
        *packed(8, 3, 4)], ret(8))])

    # write_local(kind): writes four bytes of a stack object that holds
    # 0: defined bytes, 1: nothing yet (undef), 2: a poison byte.
    m.function(303, 'write_local', [32], [32], [
        block(0, [], [const(1, 64, 4), m.alloca(2, 1, 4), const(3, 32, 0), icmp(4, 'eq', 0, 3)], branch(4, 1, 2)),
        block(1, [], [const(5, 32, 0x64636261), store(2, 5, 32)], build.jump(4)),
        block(2, [], [const(6, 32, 2), icmp(7, 'eq', 0, 6)], branch(7, 3, 4)),
        block(3, [], [special(8, 8, 'poison'), const(9, 64, 2), offset(10, 2, 9), store(10, 8, 8),
                      const(18, 8, 0x78), store(2, 18, 8)], build.jump(4)),
        block(4, [], [const(11, 64, 1), m.service('file.write', [(12, 32), (13, 64)], [11, 2, 1]),
                      *packed(17, 12, 13)], ret(17)),
    ])

    # write_poison_handle(): the handle itself is poison.
    m.function(304, 'write_poison_handle', [], [32], [block(0, [], [
        special(0, 64, 'poison'), address_of(1, 400), const(2, 64, 1),
        m.service('file.write', [(3, 32), (4, 64)], [0, 1, 2])], ret(3))])

    # echo(length): reads up to that many bytes (of at most 16) from standard
    # input into a stack object and writes back what was read.
    m.function(305, 'echo', [64], [32], [block(0, [], [
        const(1, 64, 16), m.alloca(2, 1, 1), const(3, 64, 0),
        m.service('file.read', [(4, 32), (5, 64)], [3, 2, 0]),
        const(6, 64, 1), m.service('file.write', [(7, 32), (8, 64)], [6, 2, 5]),
        binary('or', 9, 32, 4, 7), *packed(13, 9, 8)], ret(13))])

    # read_from(handle): one byte, to show which handles can be read.
    m.function(306, 'read_from', [64], [32], [block(0, [], [
        const(1, 64, 1), m.alloca(2, 1, 1), m.service('file.read', [(3, 32), (4, 64)], [0, 2, 1]),
        *packed(8, 3, 4)], ret(8))])

    # read_into_text(): the destination is constant data.
    m.function(307, 'read_into_text', [], [32], [block(0, [], [
        address_of(0, 400), const(1, 64, 0), const(2, 64, 1),
        m.service('file.read', [(3, 32), (4, 64)], [1, 0, 2])], ret(3))])

    # quit(status, mode): never returns.
    m.function(308, 'quit', [32, 32], [32], [block(0, [], [
        m.service('process.exit', [], [0, 1])], {'op': 'unreachable'})])

    # give_up(): never returns.
    m.function(309, 'give_up', [], [32], [block(0, [], [
        m.service('process.abort', [], [])], {'op': 'unreachable'})])

    # flood(length): writes that many bytes of a 70,000 byte stack object
    # filled with 'x'. One call transfers at most 65,536.
    m.function(310, 'flood', [64], [32], [block(0, [], [
        const(1, 64, 70000), m.alloca(2, 1, 1), const(3, 8, 0x78), bulk('memset', 2, 3, 1),
        const(4, 64, 1), m.service('file.write', [(5, 32), (6, 64)], [4, 2, 0]),
        build.simple('trunc', 7, 32, 6)], ret(7))])


def lifecycle(m):
    letters = m.data(400, 'letters', b'abcdem', mutable=False, alignment=1)
    assert letters == 0

    def say(position):
        """Operations that write the letter at `position`; uses identifiers 10 to 15."""
        return [address_of(10, 400), const(11, 64, position), offset(12, 10, 11), const(13, 64, 1),
                m.service('file.write', [(14, 32), (15, 64)], [13, 12, 13])]

    # Five hooks, each writing its own letter.
    for position in range(5):
        m.function(320 + position, 'hook_' + 'abcde'[position], [], [],
                   [block(0, [], say(position), ret())], noundef=False)
    # Initializers run by ascending priority, then ordinal: c, b, a. The
    # ordinals of one list are distinct.
    m.roots['2']['initializers'] = [
        {'function': ref(320), 'priority': 2, 'ordinal': 2, 'association': None},
        {'function': ref(321), 'priority': 1, 'ordinal': 1, 'association': None},
        {'function': ref(322), 'priority': 1, 'ordinal': 0, 'association': None}]
    # Finalizers run in the reverse of that order: e, d.
    m.roots['2']['finalizers'] = [
        {'function': ref(323), 'priority': 1, 'ordinal': 0, 'association': None},
        {'function': ref(324), 'priority': 5, 'ordinal': 1, 'association': None}]

    m.function(300, 'main', [], [32], [block(0, [], say(5) + [const(0, 32, 7)], ret(0))], symbol='main')
    # quit(status, mode): writes its letter, then ends the program.
    m.function(301, 'quit', [32, 32], [32], [block(0, [], say(5) + [
        m.service('process.exit', [], [0, 1])], {'op': 'unreachable'})])
    # fail(): writes its letter, then traps.
    m.function(302, 'fail', [], [32], [block(0, [], say(5), build.trap('failed'))])
    # now(clock): the status and the reading of a clock.
    m.function(303, 'now', [32], [32, 64], [block(0, [], [
        m.service('clock.now', [(1, 32), (2, 64)], [0])], ret(1, 2))], noundef=False)


READ, WRITE = 1, 2
EINVAL_PROBE = 0x55


def mapping(m):
    def map_(first, size, alignment, permissions):
        """Map memory: the status is first+3 and the base first+4."""
        return [const(first, 64, size), const(first + 1, 64, alignment), const(first + 2, 32, permissions),
                m.service('memory.map', [(first + 3, 32), (first + 4, 'ptr')], [first, first + 1, first + 2])]

    def unmap(first, base, size):
        """Unmap: the status is first+1."""
        return [const(first, 64, size),
                m.service('memory.unmap', [(first + 1, 32), (first + 2, 64)], [base, first])]

    def protect(first, base, size, permissions):
        """Change permissions: the status is first+2."""
        return [const(first, 64, size), const(first + 1, 32, permissions),
                m.service('memory.protect', [(first + 2, 32), (first + 3, 64)], [base, first, first + 1])]

    # use(x): maps 4096 bytes, which are zero, writes x at the start and
    # reads it and the last eight bytes back, then unmaps. Returns the map
    # status, the sum of what it read, and the unmap status.
    m.function(300, 'use', [64], [32, 64, 32], [block(0, [], [
        *map_(10, 4096, 8, READ | WRITE), store(14, 0, 64), const(20, 64, 4088), offset(21, 14, 20),
        load(22, 64, 21), load(23, 64, 14), binary('add', 24, 64, 22, 23), *unmap(30, 14, 4096)],
        ret(13, 24, 31))])

    # after_unmap(): reads a mapping that is gone.
    m.function(301, 'after_unmap', [], [32], [block(0, [], [
        *map_(10, 16, 8, READ | WRITE), *unmap(20, 14, 16), load(30, 32, 14)], ret(30))])

    # A write to a mapping that may only be read, a read of one that may
    # only be written, and a read of one that permits nothing.
    m.function(302, 'write_read_only', [], [32], [block(0, [], [
        *map_(10, 16, 8, READ), load(20, 32, 14), const(21, 32, 1), store(14, 21, 32)], ret(20))])
    m.function(303, 'read_write_only', [], [32], [block(0, [], [
        *map_(10, 16, 8, WRITE), const(20, 32, 1), store(14, 20, 32), load(21, 32, 14)], ret(21))])
    m.function(304, 'read_no_access', [], [32], [block(0, [], [
        *map_(10, 16, 8, 0), load(20, 32, 14)], ret(20))])

    # protect(): writes 5, makes the mapping read-only and reads it, makes
    # it writable again and writes 6. Returns the two statuses and values.
    m.function(305, 'protect', [], [32, 32, 32, 32], [block(0, [], [
        *map_(10, 16, 8, READ | WRITE), const(20, 32, 5), store(14, 20, 32), *protect(21, 14, 16, READ),
        load(25, 32, 14), *protect(26, 14, 16, READ | WRITE), const(30, 32, 6), store(14, 30, 32),
        load(31, 32, 14)], ret(23, 25, 28, 31))])

    # sealed(): writes to a mapping after it was made read-only.
    m.function(306, 'sealed', [], [32], [block(0, [], [
        *map_(10, 16, 8, READ | WRITE), *protect(21, 14, 16, READ), const(30, 32, 6), store(14, 30, 32)],
        ret(23))])

    # refused(): the statuses of mapping nothing, of an alignment that is no
    # power of two, of an unknown permission, of unmapping part of a mapping,
    # of unmapping a stack object, of unmapping twice (the second), and of
    # protecting with an unknown permission.
    m.function(307, 'refused', [], [32] * 7, [block(0, [], [
        *map_(10, 0, 8, READ), *map_(20, 16, 3, READ), *map_(30, 16, 8, 4),
        *map_(40, 32, 8, READ | WRITE), *unmap(50, 44, 16),
        const(60, 64, 16), m.alloca(61, 60, 8), *unmap(62, 61, 16),
        *unmap(70, 44, 32), *unmap(73, 44, 32), *map_(80, 16, 8, READ), *protect(85, 84, 16, 7)],
        ret(13, 23, 33, 51, 63, 74, 87))])

    # too_much(bytes): the status of a mapping, and whether its base is null.
    m.function(308, 'too_much', [64], [32, 32], [block(0, [], [
        const(1, 64, 8), const(2, 32, READ | WRITE),
        m.service('memory.map', [(3, 32), (4, 'ptr')], [0, 1, 2]), build.null(5), icmp(6, 'eq', 4, 5),
        build.simple('zext', 7, 32, 6)], ret(3, 7))])

    # again(rounds): maps and unmaps a megabyte that many times; the memory
    # of each mapping is returned when it is unmapped.
    m.function(309, 'again', [32], [32], [
        block(0, [], [const(1, 32, 0), const(2, 32, 1)], build.jump(1)),
        block(1, [build.phi(3, 32, (0, 1), (2, 30)), build.phi(4, 32, (0, 1), (2, 31))],
              [icmp(5, 'eq', 3, 0)], branch(5, 3, 2)),
        block(2, [], [*map_(10, 1 << 20, 4096, READ | WRITE), *unmap(20, 14, 1 << 20),
                      binary('add', 30, 32, 3, 2), binary('or', 29, 32, 13, 21),
                      binary('or', 31, 32, 4, 29)], build.jump(1)),
        block(3, [], [], ret(4))])


def document(author, services):
    m = ServiceModule(services)
    # The module holds only what is authored here.
    m.functions.clear()
    m.symbols.clear()
    author(m)
    m.types.sort(key=lambda item: item['id'])
    m.roots['1']['memory_layouts'].sort(key=lambda item: item['id'])
    m.roots['6']['imports'].sort(key=lambda item: item['id'])
    m.functions.sort(key=lambda item: item['id'])
    m.symbols.sort(key=lambda item: item['id'])
    return json.dumps({'sections': m.roots}, indent=1, sort_keys=True) + '\n'


def main():
    transfers = ['file.read', 'file.write', 'process.exit', 'process.abort']
    build.write({HERE / 'services.json': document(programs, transfers),
                 HERE / 'lifecycle.json': document(lifecycle, ['file.write', 'process.exit', 'clock.now']),
                 HERE / 'mapping.json': document(mapping, ['memory.map', 'memory.unmap', 'memory.protect'])},
                __doc__)


if __name__ == '__main__':
    main()
