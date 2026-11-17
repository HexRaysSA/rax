#!/usr/bin/env python3
"""Build the isolated AST-only witness from existing pinned static libraries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

TOOL = Path(__file__).resolve().parent
REPOSITORY = TOOL.parents[2]
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def command(argv, *, timeout=60, env=None):
    return subprocess.run([str(arg) for arg in argv], capture_output=True,
                          text=True, timeout=timeout, env=env)


def build(llvm, output):
    llvm = llvm.resolve()
    output = output.resolve()
    if output.is_relative_to(REPOSITORY) or output.is_relative_to(llvm):
        raise ValueError('build output must be outside both source checkouts')
    output.mkdir(parents=True, exist_ok=False)
    head = command(['git', '-C', llvm, 'rev-parse', 'HEAD'])
    if head.returncode or head.stdout.strip() != PIN:
        raise ValueError('LLVM source pin mismatch')
    compiler = llvm / 'build/bin/clang++'
    version = command([compiler, '--version'])
    if version.returncode or PIN not in version.stdout:
        raise ValueError('actual compiler does not report the selected source pin')
    include = [llvm / path for path in ('clang/include', 'build/tools/clang/include',
                                       'llvm/include', 'build/include')]
    argv = [compiler, '-std=c++17', '-fno-rtti', '-fno-exceptions']
    if os.uname().sysname == 'Darwin':
        sdk = command(['/usr/bin/xcrun', '--show-sdk-path'])
        if sdk.returncode:
            raise ValueError('SDK query failed: ' + sdk.stderr)
        argv += ['-isysroot', sdk.stdout.strip()]
    argv += ['-I' + str(path) for path in include]
    compile_options = list(argv)
    sources = [TOOL / name for name in ('producer.cpp', 'types.cpp', 'layout.cpp', 'construction.cpp',
                                       'lifetime_programs.cpp')]
    libraries = sorted((llvm / 'build/lib').glob('libclang*.a'))
    if not libraries:
        raise ValueError('matching static Clang libraries unavailable; no silent skip')
    flags = command([llvm / 'build/bin/llvm-config', '--ldflags', '--libs', '--system-libs'])
    if flags.returncode:
        raise ValueError('llvm-config failed: ' + flags.stderr)
    binary = output / 'record-input-witness'
    argv += sources + libraries + shlex.split(flags.stdout)
    if os.uname().sysname == 'Darwin':
        argv += ['-L/opt/homebrew/opt/zstd/lib', '-Wl,-rpath,' + str(llvm / 'build/lib')]
    argv += ['-o', binary]
    (output / 'argv.json').write_text(json.dumps([str(arg) for arg in argv], indent=2) + '\n')
    # The shared library was observed ABI-stale relative to this checkout. Use
    # one static Clang set, never fill missing symbols with a mixed shared build.
    llvm_files = command([llvm / 'build/bin/llvm-config', '--libfiles'])
    if llvm_files.returncode:
        raise ValueError('LLVM library provenance query failed: ' + llvm_files.stderr)
    dependencies = set()
    for source in sources:
        dependency = command(compile_options + ['-MM', '-MT', 'smir_input', source])
        if dependency.returncode:
            raise ValueError('compiler dependency query failed: ' + dependency.stderr)
        tokens = shlex.split(dependency.stdout.replace('\\\n', ''))
        if not tokens or tokens[0] != 'smir_input:':
            raise ValueError('unexpected compiler dependency output')
        dependencies.update(Path(path).resolve() for path in tokens[1:])
    inputs = sorted(set(sources + [TOOL / 'producer.hpp', Path(__file__).resolve(),
                                  compiler.resolve(), llvm / 'build/bin/llvm-config'] + libraries +
                        [Path(path) for path in shlex.split(llvm_files.stdout)]) | dependencies)
    before = [dict(path=str(path), sha256=digest(path)) for path in inputs]
    temporary = output / 'tmp'
    temporary.mkdir()
    environment = dict(os.environ, TMPDIR=str(temporary))
    result = command(argv, env=environment)
    (output / 'build.stdout').write_text(result.stdout)
    (output / 'build.stderr').write_text(result.stderr)
    after = [dict(path=str(path), sha256=digest(path)) for path in inputs]
    if before != after:
        raise ValueError('compiler inputs changed during build')
    receipt = dict(scope='Native AST-only tool build, no source-program/backend execution',
                   compiler=dict(path=str(compiler.resolve()), sha256=digest(compiler),
                                 version=version.stdout), input_hashes=before,
                   argv=[str(arg) for arg in argv], exit=result.returncode,
                   provenance_scope='Compiler, non-system transitive headers, existing static Clang/LLVM libraries; system SDK headers are not attested',
                   library_selection='existing static Clang libraries; shared library ABI mismatch excluded')
    if result.returncode == 0:
        receipt['binary'] = dict(path=str(binary), sha256=digest(binary))
    (output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if result.returncode:
        raise ValueError('AST witness build failed: ' + result.stderr)
    return binary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.llvm, args.out))
