#!/usr/bin/env python3
"""Compile C files to one portable SMIR object.

    python3 -B smircc.py [-O1|-O2|...] [-I DIR]... [-D MACRO]... -o OUTPUT.smo INPUT.c...

Builds the smir-clang driver if needed, compiles the inputs and links them
into one module fragment, merges the fragment into `template.json` and
assembles the result. Also writes
OUTPUT.smo.index.json, which lists each function's identifier and the bit
widths of its parameters and results, for callers that enter by name.

`template.json` supplies the sections the emitter does not produce yet: the
module manifest, the ABI contract root with its site record and one portable
domain, and empty TLS, exception and capability roots. The import root is
filled with the internal runtime helpers the functions call (stack allocation
and lifetime markers); the data and relocation roots with the program's
global variables. It is the repository's `generic-functions/int64` conformance module
with its function and symbol removed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / 'tools/smir-format')]

import build  # noqa: E402


class CompileError(Exception):
    pass


def reference(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


HELPER_CATALOG = ROOT / 'docs/specifications/smir/portable/schema/runtime/helpers-v1.json'
# Option values of a helper import that takes no options.
HELPER_OPTIONS = {'alignment': 1, 'scope': 'process', 'order': 'none', 'failure_order': 'none',
                  'weak': False, 'comparison': 'none', 'mask': '', 'rounding': 'none',
                  'exceptions': 'none', 'predicate': 'none', 'target': None, 'flags': []}


def helper_catalog_digest():
    """The identity an internal helper import must quote for the catalog it uses."""
    catalog = json.loads(HELPER_CATALOG.read_text())
    canonical = json.dumps(catalog, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(b'SMIR-HELPERS-V1\0' + canonical.encode('ascii')).hexdigest()


def bind_helpers(fragment):
    """Import records for the helpers a fragment names, and the names resolved in place."""
    digest = helper_catalog_digest()
    identifiers = {helper['name']: position for position, helper in enumerate(fragment['helpers'])}
    for function in fragment['functions']:
        for block in function['blocks']:
            for operation in block['ops']:
                if 'helper' in operation:
                    operation['helper']['import'] = reference(identifiers[operation['helper']['import']])
    return [{'id': identifiers[helper['name']], 'kind': 'internal', 'namespace': 'smir.internal.v1',
             'name': helper['name'], 'version': 1, 'catalog': digest,
             'signature': reference(helper['signature']), 'abi': None, 'types': [],
             'contract': 'default', 'options': dict(HELPER_OPTIONS)}
            for helper in fragment['helpers']]


def merge(fragment, name):
    """The complete ten-root document for a fragment."""
    document = json.loads((HERE / 'template.json').read_text())
    sections = document['sections']
    layouts = sections['1']['memory_layouts']
    if {item['id'] for item in layouts} & {item['id'] for item in fragment['layouts']}:
        raise CompileError('memory layout identifiers collide with the template')
    layouts.extend(fragment['layouts'])
    layouts.sort(key=lambda item: item['id'])
    sections['6']['imports'] = bind_helpers(fragment)
    sections['4']['segments'] = [{
        'id': position, 'layout': None, 'nominal': None, 'abi_binding': None,
        'alignment': segment['alignment'], 'mutable': segment['mutable'], 'initial': segment['initial'],
        'poison': segment['poison'], 'undef': segment['undef'], 'zero_fill': segment['zero_fill'],
        'zero_shadow': 'defined',
    } for position, segment in enumerate(fragment['segments'])]
    sections['5']['relocations'] = [{
        'source_kind': 'data', 'source': relocation['segment'], 'offset': relocation['offset'],
        'width': (relocation['integer_bits'] + 7) // 8 or 8, 'integer_bits': relocation['integer_bits'],
        'kind': relocation['kind'], 'target': reference(relocation['target']),
        'addend': relocation['addend'], 'derivation': [], 'check_base': False, 'flags': [],
        'inrange': None,
    } for relocation in sorted(fragment['relocations'], key=lambda item: (item['segment'], item['offset']))]
    types = sections['1']['types']
    used = {item['id'] for item in types}
    for item in fragment['types']:
        if item['id'] in used:
            raise CompileError(f'type identifier {item["id"]} collides with the template')
    types.extend(fragment['types'])
    types.sort(key=lambda item: item['id'])
    sections['3']['functions'] = fragment['functions']
    sections['2']['symbols'] = [{
        'id': symbol['function'], 'namespace': 'c', 'name': symbol['name'], 'kind': 'function',
        'source_linkage': 'none', 'binding': symbol['binding'], 'visibility': symbol['visibility'],
        'execution': reference(symbol['signature']), 'nominal': None, 'abi_signature': None,
        'definition': {'some': {'kind': 'function', 'target': reference(symbol['function'])}},
        'size': None, 'alignment': 1, 'comdat': None, 'fallback': None,
    } for symbol in fragment['symbols']] + [{
        'id': segment['symbol'], 'namespace': 'c', 'name': segment['name'], 'kind': 'data',
        'source_linkage': 'none', 'binding': segment['binding'], 'visibility': segment['visibility'],
        'execution': reference(segment['type']), 'nominal': None, 'abi_signature': None,
        'definition': {'some': {'kind': 'data', 'segment': position}},
        'size': {'some': segment['size']}, 'alignment': segment['alignment'], 'comdat': None,
        'fallback': None,
    } for position, segment in enumerate(fragment['segments'])]
    sections['2']['manifest']['key']['name'] = name
    return document


def module_name(path):
    """A module name token derived from the output file name."""
    name = re.sub(r'[^a-z0-9_]', '_', Path(path).name.split('.')[0].lower())
    return (name if re.match(r'[a-z]', name) else 'm_' + name)[:63]


def compile_file(source, output, arguments=(), llvm=None):
    """Compile one source to the object `output`; return the entry index."""
    return compile_files([source], output, arguments, llvm)


def compile_files(sources, output, arguments=(), llvm=None):
    """Compile and link `sources` to the object `output`; return the entry index."""
    import smir
    driver = build.build(llvm)
    resource = sorted((Path(llvm or build.default_llvm()) / 'build/lib/clang').iterdir())[-1]
    with tempfile.TemporaryDirectory(prefix='smircc-') as scratch:
        fragment_path = Path(scratch) / 'fragment.json'
        run = subprocess.run([str(driver), *arguments, '--resource-dir', str(resource),
                              '-o', str(fragment_path), *map(str, sources)], capture_output=True, text=True)
        if run.returncode != 0:
            raise CompileError(run.stderr.strip() or f'smir-clang exited with status {run.returncode}')
        fragment = json.loads(fragment_path.read_text())
    payload = smir.assemble(merge(fragment, module_name(output)))
    output = Path(output)
    output.write_bytes(payload)
    Path(str(output) + '.index.json').write_text(json.dumps(fragment['index'], indent=1) + '\n')
    return fragment['index']


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('sources', type=Path, nargs='+')
    parser.add_argument('-o', dest='output', type=Path, required=True)
    parser.add_argument('--llvm', type=Path)
    arguments, driver_arguments = parser.parse_known_args()
    try:
        compile_files(arguments.sources, arguments.output, driver_arguments, arguments.llvm)
    except (CompileError, build.BuildError, ValueError, KeyError) as error:
        sys.exit(f'smircc.py: {error}')


if __name__ == '__main__':
    main()
