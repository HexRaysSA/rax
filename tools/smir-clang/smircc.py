#!/usr/bin/env python3
"""Compile one C file to a portable SMIR object.

    python3 -B smircc.py [-O1|-O2|...] [-I DIR]... [-D MACRO]... -o OUTPUT.smo INPUT.c

Builds the smir-clang driver if needed, compiles INPUT.c to a module fragment,
merges the fragment into `template.json` and assembles the result. Also writes
OUTPUT.smo.index.json, which lists each function's identifier and the bit
widths of its parameters and results, for callers that enter by name.

`template.json` supplies the sections the emitter does not produce yet: the
module manifest, the ABI contract root with its site record and one portable
domain, and empty data, relocation, import, TLS, exception and capability
roots. It is the repository's `generic-functions/int64` conformance module
with its function and symbol removed.
"""
import argparse
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


def merge(fragment, name):
    """The complete ten-root document for a fragment."""
    document = json.loads((HERE / 'template.json').read_text())
    sections = document['sections']
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
    } for symbol in fragment['symbols']]
    sections['2']['manifest']['key']['name'] = name
    return document


def module_name(path):
    """A module name token derived from the output file name."""
    name = re.sub(r'[^a-z0-9_]', '_', Path(path).name.split('.')[0].lower())
    return (name if re.match(r'[a-z]', name) else 'm_' + name)[:63]


def compile_file(source, output, arguments=(), llvm=None):
    """Compile `source` to the object `output`; return the entry index."""
    import smir
    driver = build.build(llvm)
    resource = sorted((Path(llvm or build.default_llvm()) / 'build/lib/clang').iterdir())[-1]
    with tempfile.TemporaryDirectory(prefix='smircc-') as scratch:
        fragment_path = Path(scratch) / 'fragment.json'
        run = subprocess.run([str(driver), *arguments, '--resource-dir', str(resource),
                              '-o', str(fragment_path), str(source)], capture_output=True, text=True)
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
    parser.add_argument('source', type=Path)
    parser.add_argument('-o', dest='output', type=Path, required=True)
    parser.add_argument('--llvm', type=Path)
    arguments, driver_arguments = parser.parse_known_args()
    try:
        compile_file(arguments.source, arguments.output, driver_arguments, arguments.llvm)
    except (CompileError, build.BuildError, ValueError, KeyError) as error:
        sys.exit(f'smircc.py: {error}')


if __name__ == '__main__':
    main()
