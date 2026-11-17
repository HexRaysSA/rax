#!/usr/bin/env python3
"""Assemble/disassemble canonical SMIR records and run explicit reference checks."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
import codec

MAX_SOURCE_BYTES = 64 * 1024 * 1024


def source_json(payload):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise codec.RecordError('SOURCE-DUPLICATE-KEY')
            result[name] = value
        return result
    codec.RecordCodec._require(type(payload) is bytes and len(payload) <= MAX_SOURCE_BYTES,
                               'SOURCE-LIMIT')
    try:
        text = payload.decode('utf-8')
    except UnicodeDecodeError as error:
        raise codec.RecordError('SOURCE-UTF8') from error
    # Bound allocation before json.loads, including Python implementations whose
    # JSON parser uses an explicit stack rather than the Python recursion limit.
    depth, quoted, escaped = 0, False, False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            codec.RecordCodec._require(depth <= 128, 'SOURCE-JSON-DEPTH')
        elif byte in (93, 125):
            depth -= 1
    try:
        # Passing text disables json.loads' UTF-16/32 byte auto-detection: the
        # lexical depth check and the JSON decoder must see the same encoding.
        return json.loads(text, object_pairs_hook=pairs)
    except RecursionError as error:
        raise codec.RecordError('SOURCE-JSON-DEPTH') from error


def records():
    root = Path(__file__).resolve().parents[2]
    schema = root / 'docs/specifications/smir/portable/schema'
    return codec.CandidateCodec({name: source_json((schema / name / 'candidate.json').read_bytes())
                                 for name in ('execution', 'runtime', 'abi')})


def assemble(document):
    """Representations only: no ABI, SSA, runtime or execution authority."""
    codec.RecordCodec._require(type(document) is dict and document.keys() in
                               ({'sections'}, {'sections', 'metadata'}), 'SOURCE-FIELDS')
    sections = document['sections']
    codec.RecordCodec._require(type(sections) is dict and
                               sections.keys() == {str(number) for number in range(1, 11)}, 'SOURCE-ROOTS')
    roots = {int(number): value for number, value in sections.items()}
    manifest = roots[2]['manifest']
    codec.RecordCodec._require(manifest['kind'] in {'object', 'image'}, 'SOURCE-MODULE-KIND')
    entry = manifest['entry']
    codec.RecordCodec._require(entry is None or entry['some']['module'] == {'kind': 'self'}, 'SOURCE-ENTRY')
    metadata = document.get('metadata', [])
    codec.RecordCodec._require(type(metadata) is list and all(type(item) is dict and
                               item.keys() == {'kind', 'required', 'hex'} for item in metadata),
                               'SOURCE-METADATA')
    return records().encode(roots, kind={'object': 1, 'image': 2}[manifest['kind']],
                            entry=codec.NO_ENTRY if entry is None else entry['some']['id'], metadata=metadata)


def disassemble(payload):
    decoded = records().decode(payload)
    manifest = decoded.roots[2]['manifest']
    codec.RecordCodec._require(decoded.envelope['kind'] == {'object': 1, 'image': 2}[manifest['kind']],
                               'SOURCE-HEADER-KIND')
    entry = manifest['entry']
    codec.RecordCodec._require(entry is None or entry['some']['module'] == {'kind': 'self'}, 'SOURCE-ENTRY')
    codec.RecordCodec._require(decoded.envelope['entry'] ==
                               (codec.NO_ENTRY if entry is None else entry['some']['id']), 'SOURCE-HEADER-ENTRY')
    document = {'sections': {str(key): value for key, value in decoded.roots.items()}}
    metadata = [item for item in decoded.envelope['sections'] if item['kind'] >= 0x8000]
    if metadata:
        document['metadata'] = metadata
    return document


def main():
    # Existing reference commands retain their own exact argument/error contract.
    if len(sys.argv) > 1 and sys.argv[1] in {'run', 'verify'}:
        sys.argv[1] = {'run': 'run-candidate-reference', 'verify': 'verify-candidate-reference'}[sys.argv[1]]
        return codec.main()
    parser = argparse.ArgumentParser(description=__doc__, epilog=
        'Reference commands: smir.py run OBJECT --entry-function ID --reference-policy POLICY '
        '[--argument-bits HEX]; smir.py verify OBJECT [--capability NAME].')
    parser.add_argument('operation', choices=('assemble', 'disassemble'))
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if (args.input.resolve() == args.output.resolve() or
                args.output.exists() and args.input.samefile(args.output)):
            parser.error('input and output must be different files')
        limit = MAX_SOURCE_BYTES if args.operation == 'assemble' else codec.DEFAULT_MAX_BYTES
        with args.input.open('rb') as source:
            payload = source.read(limit + 1)
        codec.RecordCodec._require(len(payload) <= limit, 'SOURCE-LIMIT')
        result = (assemble(source_json(payload)) if args.operation == 'assemble' else
                  (json.dumps(disassemble(payload), indent=2) + '\n').encode())
        # Publish a completed output by rename. An alias introduced after the
        # identity check must not let truncation alter the input's inode.
        descriptor, name = tempfile.mkstemp(prefix='.smir-output-', dir=args.output.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as destination:
                destination.write(result)
            temporary.replace(args.output)
        finally:
            temporary.unlink(missing_ok=True)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    main()
