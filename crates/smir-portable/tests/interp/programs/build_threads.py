#!/usr/bin/env python3
"""Author the thread programs as editable ten-root JSON.

    python3 -B build_threads.py            # rewrite threads.json
    python3 -B build_threads.py --check    # fail if it is out of date

`threads.json` is a module whose functions start, join and detach threads and
wait on a word of memory, through the `thread` and `sync` services. Like the
other service modules it is not compared with the Python reference machine,
which has one thread and performs no services. `../threads.rs` runs these
programs; `threads.smo` is `threads.json` assembled.

Functions 300 and up are entered by the tests. Functions 310 to 319 are what
the threads they start run: each takes a pointer and returns a 64-bit result.
Functions 340 and up use the module's thread-local segment.
"""
import copy
from pathlib import Path

import build
from build import (address_of, binary, block, branch, code_address_of, const, decl, icmp, jump, load, offset,
                   phi, ref, ret, retype, simple, store, trap)
from build_services import ServiceModule, document

HERE = Path(__file__).resolve().parent
FOREVER = 2 ** 64 - 1
UNREACHABLE = {'op': 'unreachable'}
# The import that yields the address of the thread-local segment.
THREAD_LOCAL = 20


def thread_local(m, words):
    """Give the module one thread-local segment of 32-bit `words`, and return
    the operation that yields the calling thread's address of a byte of it."""
    from test_candidate_bindings import add_import
    _, binding = add_import('tls_address_raw', options={'target': {'some': ref(0)}})
    binding = copy.deepcopy(binding)
    signature = m.signature([64], ['ptr'], False, param_noundef=False)
    binding.update(id=THREAD_LOCAL, signature=ref(signature))
    m.roots['6']['imports'].append(binding)
    image = b''.join(word.to_bytes(4, 'little') for word in words)
    m.roots['7']['segments'].append({
        'storage': {'id': 0, 'layout': None, 'nominal': None, 'abi_binding': None, 'alignment': 4,
                    'mutable': True, 'initial': image.hex(), 'poison': bytes(len(image)).hex(),
                    'undef': bytes(len(image)).hex(), 'zero_fill': 0, 'zero_shadow': 'defined'},
        'initializers': [], 'destructors': [], 'initialization': 'static'})

    def address(value, offset):
        """The address `offset` (a 64-bit value) bytes into the segment."""
        return {'op': 'call', 'results': [decl(value, 'ptr')], 'operands': [offset],
                'target': {'kind': 'import', 'import': ref(THREAD_LOCAL), 'signature': ref(signature)},
                'unwind': 'propagate', 'source_plan': None}
    return address


def atomic(name, results, operands, **extra):
    """A sequentially consistent atomic access of a 32-bit word."""
    record = {'op': name, 'results': results, 'operands': operands, **build.access(32)}
    record['mode'] = {'alignment': 4, 'volatile': False, 'order': 'seq_cst', 'failure_order': 'none',
                      'scope': 'process', 'elementwise': False}
    record.update(extra)
    return record


def programs(m):
    entry, _, _ = m.code_pointer(['ptr'], [64])
    other, _, _ = m.code_pointer([32], [32])
    # A 32-bit word that threads share, four spare bytes, and a 64-bit count.
    cell = m.data(400, 'cell', [0] * 16)
    assert cell == 0

    def spawn(first, worker):
        """Start `worker` on the cell. Uses identifiers first to first+4: the
        cell's address is first+1, the status first+3 and the handle first+4."""
        return [code_address_of(first, entry, worker), address_of(first + 1, 400), const(first + 2, 64, 0),
                m.service('thread.spawn', [(first + 3, 32), (first + 4, 64)], [first, first + 1, first + 2])]

    def join(first, handle):
        """Join a thread: the status is `first` and the result first+1."""
        return m.service('thread.join', [(first, 32), (first + 1, 64)], [handle])

    def wait(first, address, expected, timeout):
        return m.service('sync.wait32', [(first, 32), (first + 1, 64)], [address, expected, timeout])

    def wake(first, address, count):
        return m.service('sync.wake32', [(first, 32), (first + 1, 64)], [address, count])

    # add_many(cell): adds one to the word, as many times as the count says,
    # and returns the count.
    m.function(310, 'add_many', ['ptr'], [64], [
        block(0, [], [const(1, 64, 8), offset(2, 0, 1), load(3, 64, 2), const(4, 64, 0), const(5, 32, 1),
                      const(6, 64, 1)], jump(1)),
        block(1, [phi(7, 64, (0, 4), (2, 10))], [icmp(8, 'eq', 7, 3)], branch(8, 3, 2)),
        block(2, [], [atomic('atomic_rmw', [decl(9, 32)], [0, 5], action='add'), binary('add', 10, 64, 7, 6)],
              jump(1)),
        block(3, [], [], ret(7))])

    # identify(cell): the thread's own identity.
    m.function(311, 'identify', ['ptr'], [64], [block(0, [], [
        m.service('thread.id', [(1, 32), (2, 64)], [])], ret(2))])

    # leave(cell): ends the thread with 77 from inside a call; never returns 5.
    m.function(313, 'leave_inner', [], [], [block(0, [], [
        const(0, 64, 77), m.service('thread.exit', [], [0])], UNREACHABLE)], noundef=False)
    m.function(312, 'leave', ['ptr'], [64], [block(0, [], [
        m.call([], 313, []), const(1, 64, 5)], ret(1))])

    # await_word(cell): waits until the word is not zero and returns it.
    m.function(314, 'await_word', ['ptr'], [64], [
        block(0, [], [const(1, 32, 0), const(2, 64, FOREVER)], jump(1)),
        block(1, [], [atomic('atomic_load', [decl(3, 32)], [0]), icmp(4, 'eq', 3, 1)], branch(4, 2, 3)),
        block(2, [], [wait(5, 0, 1, 2)], jump(1)),
        block(3, [], [simple('zext', 7, 64, 3)], ret(7))])

    # fail(cell): traps.
    m.function(315, 'fail', ['ptr'], [64], [block(0, [], [], trap('worker_failed'))])

    # quit(cell): ends the program with status 3.
    m.function(316, 'quit', ['ptr'], [64], [block(0, [], [
        const(1, 32, 3), const(2, 32, 0), m.service('process.exit', [], [1, 2])], UNREACHABLE)])

    # spin(cell): never ends.
    m.function(317, 'spin', ['ptr'], [64], [block(0, [], [], jump(1)), block(1, [], [], jump(1))])

    # sleep(cell): waits for a wake that never comes.
    m.function(318, 'sleep', ['ptr'], [64], [
        block(0, [], [const(1, 32, 0), const(2, 64, FOREVER)], jump(1)),
        block(1, [], [wait(3, 0, 1, 2)], jump(1))])

    # misshapen(x): not a thread's entry.
    m.function(319, 'misshapen', [32], [32], [block(0, [], [], ret(0))])

    # count(n): four threads each add one to the word n times. Returns the
    # word, the sum of the threads' results, and every status or'ed together.
    ops = [address_of(1, 400), const(2, 64, 8), offset(3, 1, 2), store(3, 0, 64)]
    for position in range(4):
        ops += spawn(10 + 10 * position, 310)
    ops += [join(50 + 2 * position, 14 + 10 * position) for position in range(4)]
    ops += [binary('add', 60, 64, 51, 53), binary('add', 61, 64, 60, 55), binary('add', 62, 64, 61, 57)]
    statuses = [13, 23, 33, 43, 50, 52, 54, 56]
    ops += [binary('or', 70, 32, statuses[0], statuses[1])]
    ops += [binary('or', 70 + position, 32, 69 + position, status)
            for position, status in enumerate(statuses[2:], start=1)]
    ops += [atomic('atomic_load', [decl(80, 32)], [1])]
    m.function(300, 'count', [64], [32, 64, 32], [block(0, [], ops, ret(80, 62, 76))])

    # identity(): its own identity, the handle of a thread it starts, and the
    # identity that thread reports.
    m.function(301, 'identity', [], [64, 64, 64], [block(0, [], [
        m.service('thread.id', [(0, 32), (1, 64)], []), *spawn(10, 311), join(20, 14)], ret(1, 14, 21))])

    # joins(): the status of a join, of a second join of the same thread, of a
    # join of the calling thread, and of a join of no thread.
    m.function(302, 'joins', [], [32] * 4, [block(0, [], [
        *spawn(10, 311), join(20, 14), join(22, 14), const(24, 64, 1), join(25, 24),
        const(27, 64, 999), join(28, 27)], ret(20, 22, 25, 28))])

    # detached(): the status of a detach, of a join after it, and of a second
    # detach.
    m.function(303, 'detached', [], [32] * 3, [block(0, [], [
        *spawn(10, 311), m.service('thread.detach', [(20, 32), (21, 64)], [14]), join(22, 14),
        m.service('thread.detach', [(24, 32), (25, 64)], [14])], ret(20, 22, 24))])

    # exit_value(): joins a thread that ends itself.
    m.function(304, 'exit_value', [], [32, 64], [block(0, [], [
        *spawn(10, 312), join(20, 14)], ret(20, 21))])

    # waits(): a wait for a value the word does not hold, a wait of no time,
    # a wait of a millisecond, and a wake of nobody; the three statuses and
    # how many were woken. The yield in between changes nothing.
    m.function(305, 'waits', [], [32, 32, 32, 64, 32], [block(0, [], [
        address_of(0, 400), const(1, 32, 1), const(2, 32, 0), const(3, 64, FOREVER), const(4, 64, 0),
        const(5, 64, 1_000_000), wait(6, 0, 1, 3), wait(8, 0, 2, 4), wait(10, 0, 2, 5), const(12, 32, 5),
        wake(13, 0, 12), m.service('thread.yield', [(15, 32), (16, 64)], [])], ret(6, 8, 10, 14, 15))])

    # handoff(): starts a thread that waits for the word, sets the word to 9,
    # wakes the thread and returns what it returned.
    m.function(306, 'handoff', [], [32, 64], [block(0, [], [
        *spawn(10, 314), const(20, 32, 9), atomic('atomic_store', [], [11, 20]), const(21, 32, 1),
        wake(22, 11, 21), join(24, 14)], ret(24, 25))])

    # rouse(): starts a thread that waits for the word and wakes it, as often
    # as it takes to find it waiting, while the word is still zero, so the
    # thread waits again. Then as handoff().
    m.function(327, 'rouse', [], [32, 64], [
        block(0, [], [*spawn(10, 314), const(20, 32, 1), const(24, 64, 1)], jump(1)),
        block(1, [], [wake(21, 11, 20), icmp(23, 'eq', 22, 24)], branch(23, 3, 2)),
        block(2, [], [m.service('thread.yield', [(25, 32), (26, 64)], [])], jump(1)),
        block(3, [], [const(27, 32, 9), atomic('atomic_store', [], [11, 27]), wake(28, 11, 20),
                      join(30, 14)], ret(30, 31))])

    # stuck(): the only thread waits for a wake.
    m.function(307, 'stuck', [], [32], [block(0, [], [
        address_of(0, 400), const(1, 32, 0), const(2, 64, FOREVER), wait(3, 0, 1, 2)], ret(3))])

    # One thread joins another, which sleeps, fails, ends the program, or
    # spins.
    for identifier, name, worker in [(308, 'join_sleeper', 318), (309, 'join_failing', 315),
                                     (320, 'join_quitting', 316), (326, 'join_spinner', 317)]:
        m.function(identifier, name, [], [32], [block(0, [], [*spawn(10, worker), join(20, 14)], ret(20))])

    # leave_spinner(): returns while a thread it started still runs.
    m.function(321, 'leave_spinner', [], [32], [block(0, [], spawn(10, 317), ret(13))])

    # bad_entry(): starts a thread at a function of the wrong shape.
    m.function(322, 'bad_entry', [], [32], [block(0, [], [
        code_address_of(0, other, 319), retype(1, entry, 0), address_of(2, 400), const(3, 64, 0),
        m.service('thread.spawn', [(4, 32), (5, 64)], [1, 2, 3])], ret(4))])

    # misaligned(): waits on an address that is not a multiple of four.
    m.function(323, 'misaligned', [], [32], [block(0, [], [
        address_of(0, 400), const(1, 64, 2), offset(2, 0, 1), const(3, 32, 0), const(4, 64, 0),
        wait(5, 2, 3, 4)], ret(5))])

    # outside(): wakes on the null pointer.
    m.function(324, 'outside', [], [32], [block(0, [], [
        build.null(0), const(1, 32, 1), wake(2, 0, 1)], ret(2))])

    # first_leaves(): the first thread ends itself.
    m.function(325, 'first_leaves', [], [32], [block(0, [], [
        const(0, 64, 5), m.service('thread.exit', [], [0])], UNREACHABLE)])

    # Thread-local storage: two words, 5 and 7, in every thread's copy.
    local = thread_local(m, [5, 7])

    # bump(cell): adds 100 to the thread's first word and returns the sum of
    # its two words.
    m.function(340, 'bump', ['ptr'], [64], [block(0, [], [
        const(1, 64, 0), local(2, 1), load(3, 32, 2), const(4, 32, 100), binary('add', 5, 32, 3, 4),
        store(2, 5, 32), const(6, 64, 4), local(7, 6), load(8, 32, 7), load(9, 32, 2),
        binary('add', 10, 32, 8, 9), simple('zext', 11, 64, 10)], ret(11))])

    # own_copies(): sets its own first word to 9, lets two threads bump
    # theirs, and returns what each returned and its own first word.
    m.function(341, 'own_copies', [], [64, 64, 32], [block(0, [], [
        const(0, 64, 0), local(1, 0), const(2, 32, 9), store(1, 2, 32),
        *spawn(10, 340), *spawn(20, 340), join(30, 14), join(32, 24), load(34, 32, 1)], ret(31, 33, 34))])

    # lend(cell): leaves the address of its thread-local word in the cell.
    m.function(342, 'lend', ['ptr'], [64], [block(0, [], [
        const(1, 64, 0), local(2, 1), const(3, 64, 8), offset(4, 0, 3), store(4, 2, 'ptr')], ret(1))])

    # outlived(): reads through the address a thread that has ended left.
    m.function(343, 'outlived', [], [32], [block(0, [], [
        *spawn(10, 342), join(20, 14), const(22, 64, 8), offset(23, 11, 22), load(24, 'ptr', 23),
        load(25, 32, 24)], ret(25))])

    # beyond(): an address past the end of the segment is computed but
    # cannot be used.
    m.function(344, 'beyond', [], [32], [block(0, [], [
        const(0, 64, 8), local(1, 0), load(2, 32, 1)], ret(2))])


    # concurrency(): how many threads the runtime says run at one time.
    m.function(345, 'concurrency', [], [32, 64], [block(0, [], [
        m.service('thread.concurrency', [(0, 32), (1, 64)], [])], ret(0, 1))])


def main():
    services = ['process.exit', 'thread.spawn', 'thread.join', 'thread.detach', 'thread.yield', 'thread.id',
                'thread.exit', 'sync.wait32', 'sync.wake32', 'thread.concurrency']
    build.write({HERE / 'threads.json': document(programs, services)}, __doc__)


if __name__ == '__main__':
    main()
