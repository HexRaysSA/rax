#!/usr/bin/env python3
"""Author a module whose functions give out and take pointers, as editable
ten-root JSON.

    python3 -B build_handles.py            # rewrite handles.json
    python3 -B build_handles.py --check    # fail if it is out of date

A library hands its user pointers that the user hands back: an object it
made, a part of one, nothing. `handles.json` is such a library, for the
tests of what a host may do with a pointer it was given
(`../instances.rs`, and the host C interface's tests): `handles.smo` is it
assembled. Its only import is the helper that allocates on the stack.
"""
from pathlib import Path

import build
from build import address_of, block, const, convert, load, null, ret, store
from build_linked import Linked

HERE = Path(__file__).resolve().parent


def handles():
    m = Linked('handles')
    # Two words, the first of which says 5 from the start.
    m.data(400, 'store', build.words(5, 0, size=8))
    # open(): the store.
    m.export(300, 'open', [], ['ptr'], [block(0, [], [address_of(0, 400)], ret(0))])
    # put(where, value) and get(where): one word through a pointer.
    m.export(301, 'put', ['ptr', 64], [], [block(0, [], [store(0, 1, 64)], ret())])
    m.export(302, 'get', ['ptr'], [64], [block(0, [], [load(1, 64, 0)], ret(1))])
    # nothing(): the null pointer.
    m.export(303, 'nothing', [], ['ptr'], [block(0, [], [null(0)], ret(0))])
    # local(): the address of an object that ends with the call.
    m.export(304, 'local', [], ['ptr'], [block(0, [], [const(0, 64, 8), m.alloca(1, 0, 8)], ret(1))])
    # forged(): an address that is of no object.
    m.export(305, 'forged', [], ['ptr'], [block(0, [], [
        const(0, 64, 4096), convert('inttoptr', 1, 'ptr', 0)], ret(1))])
    return m


def main():
    build.write({HERE / 'handles.json': handles().document()}, __doc__)


if __name__ == '__main__':
    main()
