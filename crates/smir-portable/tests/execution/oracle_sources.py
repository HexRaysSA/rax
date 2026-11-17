"""Conservative read-only input inventory for independent fixture generators.

Some imported owner modules load catalogs, schemas or fixture data dynamically.
Hash their complete declared reference input trees rather than assume that a
Python module list captures those data dependencies. Inclusion is not evidence
that every file or semantic branch was executed.
"""
import hashlib
from pathlib import Path
import sys


def input_sources(repository, explicit=()):
    paths = {Path(p).resolve() for p in explicit}
    for module in list(sys.modules.values()):
        filename = getattr(module, '__file__', None)
        if filename and Path(filename).resolve().is_relative_to(repository):
            paths.add(Path(filename).resolve())
    for relative in input_roots():
        for path in (repository / relative).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path.name != '.DS_Store':
                paths.add(path.resolve())
    paths.add(repository / 'tools/smir-format/codec.py')
    return {str(p.relative_to(repository)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


def interpreter_identity():
    executable = Path(sys.executable).resolve()
    return dict(path=str(executable), version=sys.version,
        sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), optimize=sys.flags.optimize)


def input_roots():
    return ['tools/smir-format/execution', 'tools/smir-runtime-contract',
        'tools/smir-abi', 'docs/specifications/smir/portable/schema/execution',
        'docs/specifications/smir/portable/schema/runtime',
        'docs/specifications/smir/portable/schema/abi',
        'docs/specifications/smir/portable/conformance/execution',
        'docs/specifications/smir/portable/conformance/runtime',
        'docs/specifications/smir/portable/conformance/abi']
