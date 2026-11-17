#!/usr/bin/env python3
"""Inspect, pack and evaluate isolated verified integer-core draft modules."""
import argparse
import json
from pathlib import Path
import sys

from codec import encode_sections
from common import Limits, Reject, require
from evaluate import run
from verify import verify


def load(path, limits=Limits()):
    raw = Path(path).read_bytes()
    require(len(raw) <= limits.max_bytes, 'limit', 'JSON bytes')

    def unique(pairs):
        document = {}
        for name, value in pairs:
            require(name not in document, 'shape', 'duplicate JSON key')
            document[name] = value
        return document

    def no_constant(value):
        raise Reject('shape', f'non-JSON numeric constant {value}')

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise Reject('shape', 'JSON syntax, text encoding or nesting') from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['verify', 'run', 'pack'])
    parser.add_argument('module', type=Path)
    parser.add_argument('--entry', type=int, default=0)
    parser.add_argument('--argument', action='append', default=[])
    parser.add_argument('--fuel', type=int, default=100_000)
    parser.add_argument('--types', type=Path)
    parser.add_argument('--functions', type=Path)
    args = parser.parse_args()
    try:
        document = verify(load(args.module))
        if args.action == 'verify':
            print('OK integer_core_draft_v1; reference-only, no production admission')
        elif args.action == 'run':
            print(json.dumps(run(document, args.entry, args.argument, fuel=args.fuel), sort_keys=True))
        else:
            require(args.types is not None and args.functions is not None, 'argument', 'two output paths')
            require(args.types.resolve() != args.functions.resolve()
                    and args.types.resolve() != args.module.resolve()
                    and args.functions.resolve() != args.module.resolve(), 'argument', 'distinct output paths')
            # Do not overwrite either existing output or the source module.
            require(not args.types.exists() and not args.functions.exists(), 'argument', 'outputs exist')
            types, functions = encode_sections(document)
            with args.types.open('xb') as output:
                output.write(types)
            with args.functions.open('xb') as output:
                output.write(functions)
            print('WROTE draft section payloads; not an executable envelope')
        return 0
    except (Reject, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
