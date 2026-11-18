#!/usr/bin/env python3
"""Compile C and C++ files to one portable SMIR object, or to a bitcode library.

    python3 -B smircc.py [-O1|-O2|...] [-I DIR]... [-D MACRO]... [--library LIB.bc]...
                         [--hosted] -o OUTPUT.smo INPUT...
    python3 -B smircc.py -c [OPTIONS] -o LIB.bc INPUT...

Builds the smir-clang driver if needed, compiles the inputs and links them
into one module fragment, merges the fragment into `template.json` and
assembles the result. With `-c` the linked inputs are written as an LLVM
bitcode library instead, for `--library` in a later link. Also writes
OUTPUT.smo.index.json, which lists each function's identifier and the bit
widths of its parameters and results, for callers that enter by name.

`template.json` supplies the sections the emitter does not produce yet: the
module manifest, the ABI contract root with its site record and one portable
domain, and empty TLS and exception roots. The import root is filled with the
internal runtime helpers the functions call (stack allocation and lifetime
markers) and the runtime services they call, whose capabilities go in the
capability root; the data and relocation roots with the program's
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


def object_limits():
    """How large an object may be: as large as `smir-run` accepts. The format's
    own defaults are sized for hand-written modules; a program linked with
    the C++ library's stream classes is some tens of megabytes."""
    import codec
    return codec.RecordLimits(max_bytes=128 << 20, max_nodes=50_000_000, max_list=4_000_000,
                              max_string=16 << 20)


def reference(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


INCLUDE = HERE / 'include'
HELPER_CATALOG = ROOT / 'docs/specifications/smir/portable/schema/runtime/helpers-v1.json'
SERVICE_CATALOG = ROOT / 'docs/specifications/smir/portable/schema/runtime/services-v1.json'
# Option values of a helper import that takes no options.
HELPER_OPTIONS = {'alignment': 1, 'scope': 'process', 'order': 'none', 'failure_order': 'none',
                  'weak': False, 'comparison': 'none', 'mask': '', 'rounding': 'none',
                  'exceptions': 'none', 'predicate': 'none', 'target': None, 'flags': []}


def catalog_digest(catalog, domain):
    """The identity an import must quote for the catalog it uses."""
    canonical = json.dumps(catalog, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(domain + canonical.encode('ascii')).hexdigest()


def bind_imports(fragment):
    """Import records for the helpers and services a fragment names.

    The names in the fragment's operations are resolved in place to import
    identifiers: the helpers first, then the services. Also returns the
    capabilities the services need, sorted.
    """
    helpers = {helper['name']: position for position, helper in enumerate(fragment['helpers'])}
    services = {service['name']: len(helpers) + position
                for position, service in enumerate(fragment['services'])}
    # One import of the thread-local address helper for each thread-local
    # segment a function names, as "tls:" and the segment's position.
    called = sorted({operation['target']['import']
                     for function in fragment['functions'] for block in function['blocks']
                     for operation in block['ops']
                     if operation.get('target', {}).get('kind') == 'import'
                     and operation['target']['import'].startswith('tls:')},
                    key=lambda name: int(name[4:]))
    thread_local = {name: len(helpers) + len(services) + position for position, name in enumerate(called)}
    for function in fragment['functions']:
        for block in function['blocks']:
            for operation in block['ops']:
                if 'helper' in operation:
                    operation['helper']['import'] = reference(helpers[operation['helper']['import']])
                target = operation.get('target')
                if target and target['kind'] == 'import':
                    target['import'] = reference({**services, **thread_local}[target['import']])
    digest = catalog_digest(json.loads(HELPER_CATALOG.read_text()), b'SMIR-HELPERS-V1\0')
    imports = [{'id': helpers[helper['name']], 'kind': 'internal', 'namespace': 'smir.internal.v1',
                'name': helper['name'], 'version': 1, 'catalog': digest,
                'signature': reference(helper['signature']), 'abi': None, 'types': [],
                'contract': 'default', 'options': dict(HELPER_OPTIONS)}
               for helper in fragment['helpers']]
    imports += [{'id': identifier, 'kind': 'internal', 'namespace': 'smir.internal.v1',
                 'name': 'tls_address_raw', 'version': 1, 'catalog': digest,
                 'signature': reference(fragment['thread_local_signature']), 'abi': None, 'types': [],
                 'contract': 'default',
                 'options': dict(HELPER_OPTIONS, target={'some': reference(int(name[4:]))})}
                for name, identifier in thread_local.items()]
    if not services:
        return imports, []
    catalog = json.loads(SERVICE_CATALOG.read_text())
    digest = catalog_digest(catalog, b'SMIR-SERVICES-V1\0')
    rows = {row['name']: row for row in catalog['records']}
    for service in fragment['services']:
        row = rows[service['name']]
        imports.append({'id': services[service['name']], 'kind': 'service', 'namespace': row['namespace'],
                        'name': row['name'], 'version': row['version'], 'catalog': digest,
                        'signature': reference(service['signature']), 'abi': None,
                        'capability': row['capability'], 'descriptor': None})
    # The format wants imports in identifier order.
    imports.sort(key=lambda item: item['id'])
    return imports, sorted({rows[service['name']]['capability'] for service in fragment['services']})


def merge(fragment, name):
    """The complete ten-root document for a fragment."""
    document = json.loads((HERE / 'template.json').read_text())
    sections = document['sections']
    layouts = sections['1']['memory_layouts']
    if {item['id'] for item in layouts} & {item['id'] for item in fragment['layouts']}:
        raise CompileError('memory layout identifiers collide with the template')
    layouts.extend(fragment['layouts'])
    layouts.sort(key=lambda item: item['id'])
    sections['6']['imports'], sections['9']['capabilities'] = bind_imports(fragment)
    sections['4']['segments'] = [{
        'id': position, 'layout': None, 'nominal': None, 'abi_binding': None,
        'alignment': segment['alignment'], 'mutable': segment['mutable'], 'initial': segment['initial'],
        'poison': segment['poison'], 'undef': segment['undef'], 'zero_fill': segment['zero_fill'],
        'zero_shadow': 'defined',
    } for position, segment in enumerate(fragment['segments'])]
    sections['7']['segments'] = [{
        'storage': {
            'id': position, 'layout': None, 'nominal': None, 'abi_binding': None,
            'alignment': segment['alignment'], 'mutable': segment['mutable'], 'initial': segment['initial'],
            'poison': segment['poison'], 'undef': segment['undef'], 'zero_fill': segment['zero_fill'],
            'zero_shadow': 'defined'},
        'initializers': [], 'destructors': [], 'initialization': 'static',
    } for position, segment in enumerate(fragment['thread_local'])]
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
    } for position, segment in enumerate(fragment['segments'])] + [{
        'id': segment['symbol'], 'namespace': 'c', 'name': segment['name'], 'kind': 'tls',
        'source_linkage': 'none', 'binding': segment['binding'], 'visibility': segment['visibility'],
        'execution': reference(segment['type']), 'nominal': None, 'abi_signature': None,
        'definition': {'some': {'kind': 'tls', 'segment': position}},
        'size': {'some': segment['size']}, 'alignment': segment['alignment'], 'comdat': None,
        'fallback': None,
    } for position, segment in enumerate(fragment['thread_local'])]
    sections['2']['symbols'].sort(key=lambda item: item['id'])
    # Functions to run before and after the program, in the order given.
    for side in ('initializers', 'finalizers'):
        sections['2'][side] = [{'function': reference(entry['function']), 'priority': entry['priority'],
                                'ordinal': position, 'association': None}
                               for position, entry in enumerate(fragment[side])]
    sections['2']['manifest']['key']['name'] = name
    return document


def module_name(path):
    """A module name token derived from the output file name."""
    name = re.sub(r'[^a-z0-9_]', '_', Path(path).name.split('.')[0].lower())
    return (name if re.match(r'[a-z]', name) else 'm_' + name)[:63]


def compile_file(source, output, arguments=(), llvm=None):
    """Compile one source to the object `output`; return the entry index."""
    return compile_files([source], output, arguments, llvm)


def drive(arguments, llvm=None):
    """Run the driver with the include path, resource directory and service catalog in place."""
    driver = build.build(llvm)
    resource = sorted((Path(llvm or build.default_llvm()) / 'build/lib/clang').iterdir())[-1]
    run = subprocess.run([str(driver), '-I', str(INCLUDE), '--resource-dir', str(resource),
                          '--services', str(SERVICE_CATALOG), *map(str, arguments)], capture_output=True, text=True)
    if run.returncode != 0:
        raise CompileError(run.stderr.strip() or f'smir-clang exited with status {run.returncode}')


def compile_library(sources, output, arguments=(), llvm=None):
    """Compile and link `sources` to the LLVM bitcode library `output`.

    A library may refer to what it does not define. A later link takes from
    it only the definitions the program needs.
    """
    drive([*arguments, '-c', '-o', output, *sources], llvm)


def compile_files(sources, output, arguments=(), llvm=None, libraries=(), hosted=False):
    """Compile and link `sources` to the object `output`; return the entry index.

    A source may be C, C++ or LLVM bitcode. `libraries` are bitcode libraries
    from `compile_library`. With `hosted`, the program is compiled against
    the C library's headers and linked with it; the library is built first
    if it is not there (see sysroot/build_libc.py).
    """
    import smir
    arguments, libraries = list(arguments), list(libraries)
    if hosted:
        sys.path.insert(0, str(HERE / 'sysroot'))
        import build_libc
        sys.path.pop(0)
        sysroot = build_libc.build(llvm)
        arguments += ['--hosted']
        # The C++ library's headers come before the C library's, some of
        # which they wrap. They are only on the path when there is C++.
        if any(Path(source).suffix in ('.cc', '.cpp', '.cxx') for source in sources):
            # C++ with a library has exceptions, as the library does.
            arguments += ['-fexceptions', '-fcxx-exceptions', '-nostdinc++', '-isystem', sysroot / 'include/c++/v1']
            libraries.append(sysroot / 'lib/libc++.bc')
        arguments += ['-isystem', sysroot / 'include']
        libraries.append(sysroot / 'lib/libc.bc')
    with tempfile.TemporaryDirectory(prefix='smircc-') as scratch:
        fragment_path = Path(scratch) / 'fragment.json'
        linked = [item for library in libraries for item in ('--library', library)]
        drive([*arguments, *linked, '-o', fragment_path, *sources], llvm)
        fragment = json.loads(fragment_path.read_text())
    payload = smir.assemble(merge(fragment, module_name(output)), object_limits())
    output = Path(output)
    output.write_bytes(payload)
    Path(str(output) + '.index.json').write_text(json.dumps(fragment['index'], indent=1) + '\n')
    return fragment['index']


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('sources', type=Path, nargs='+')
    parser.add_argument('-o', dest='output', type=Path, required=True)
    parser.add_argument('--llvm', type=Path)
    parser.add_argument('-c', dest='library', action='store_true')
    parser.add_argument('--hosted', action='store_true', help='compile against and link the C library')
    arguments, driver_arguments = parser.parse_known_args()
    try:
        if arguments.library:
            compile_library(arguments.sources, arguments.output, driver_arguments, arguments.llvm)
        else:
            compile_files(arguments.sources, arguments.output, driver_arguments, arguments.llvm,
                          hosted=arguments.hosted)
    except (CompileError, build.BuildError, ValueError, KeyError) as error:
        sys.exit(f'smircc.py: {error}')


if __name__ == '__main__':
    main()
