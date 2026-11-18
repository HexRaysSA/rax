#!/usr/bin/env python3
"""Build the smir-clang driver against the pinned LLVM checkout.

    python3 -B build.py [--llvm DIR] [--output DIR] [--optimize]

The LLVM checkout is not modified. The driver links the checkout's static
Clang and LLVM libraries, with one exception: a copy of libclangBasic from
which Targets.cpp.o is removed, so that portable_target.h supplies the only
target factory. Prints the path of the built binary.

--llvm defaults to $SMIR_LLVM_ROOT, then to the llvm-project directory beside
this repository. --output defaults to crates/smir-portable/target/smir-clang,
which is ignored by git. The build is skipped when the binary is newer than
every source file here.
"""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
SOURCES = ['driver.cpp', 'emit.cpp', 'emit_abi.cpp', 'emit_atomic.cpp', 'emit_calls.cpp', 'emit_code.cpp',
           'emit_float.cpp', 'emit_memory.cpp', 'exceptions.cpp', 'jumps.cpp', 'program.cpp']
HEADERS = ['emit.h', 'emitter.h', 'portable_target.h', 'program.h']


class BuildError(Exception):
    pass


def default_llvm():
    return Path(os.environ.get('SMIR_LLVM_ROOT') or ROOT.parent / 'llvm-project')


def default_output():
    return ROOT / 'crates/smir-portable/target/smir-clang'


def run(arguments, **options):
    try:
        return subprocess.run([str(item) for item in arguments], check=True, capture_output=True,
                              text=True, **options).stdout
    except FileNotFoundError as error:
        raise BuildError(f'cannot run {arguments[0]}: {error}') from error
    except subprocess.CalledProcessError as error:
        raise BuildError(f'{arguments[0]} failed:\n{error.stderr[-4000:]}') from error


def build(llvm=None, output=None, optimize=False):
    llvm = Path(llvm or default_llvm()).resolve()
    output = Path(output or default_output()).resolve()
    binary = output / 'smir-clang'
    inputs = [HERE / name for name in SOURCES + HEADERS] + [Path(__file__).resolve()]
    if binary.exists() and all(binary.stat().st_mtime > item.stat().st_mtime for item in inputs):
        return binary
    compiler = llvm / 'build/bin/clang++'
    if not compiler.exists():
        raise BuildError(f'no pinned compiler at {compiler}; set SMIR_LLVM_ROOT or pass --llvm')
    # The checkout's other tools were built from older revisions; the compiler
    # and the libraries linked here must be the pinned one.
    if PIN not in run([compiler, '--version']):
        raise BuildError(f'{compiler} was not built from LLVM {PIN}')
    libraries = sorted((llvm / 'build/lib').glob('libclang*.a'))
    if not libraries:
        raise BuildError(f'no static Clang libraries under {llvm / "build/lib"}')
    output.mkdir(parents=True, exist_ok=True)
    original = llvm / 'build/lib/libclangBasic.a'
    filtered = output / 'libclangBasic-portable.a'
    shutil.copyfile(original, filtered)
    archiver = llvm / 'build/bin/llvm-ar'
    if run([archiver, 't', filtered]).splitlines().count('Targets.cpp.o') != 1:
        raise BuildError('libclangBasic.a does not contain exactly one Targets.cpp.o')
    run([archiver, 'd', filtered, 'Targets.cpp.o'])
    command = [compiler, '-std=c++17', '-fno-rtti', '-fno-exceptions', '-Wall', '-Wextra',
               '-Wno-unused-parameter']
    command += ['-O2', '-DNDEBUG'] if optimize else ['-O0']
    if sys.platform == 'darwin':
        command += ['-isysroot', run(['/usr/bin/xcrun', '--show-sdk-path']).strip()]
    command += ['-I' + str(llvm / item)
                for item in ('clang/include', 'build/tools/clang/include', 'llvm/include', 'build/include')]
    command += [HERE / name for name in SOURCES]
    command += [filtered if item == original else item for item in libraries]
    command += shlex.split(run([llvm / 'build/bin/llvm-config', '--ldflags', '--libs', '--system-libs']))
    if sys.platform == 'darwin':
        command += ['-L/opt/homebrew/opt/zstd/lib', '-Wl,-rpath,' + str(llvm / 'build/lib')]
    temporary = output / 'smir-clang.partial'
    run(command + ['-o', temporary], timeout=600)
    temporary.replace(binary)
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--llvm', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--optimize', action='store_true')
    arguments = parser.parse_args()
    try:
        print(build(arguments.llvm, arguments.output, arguments.optimize))
    except BuildError as error:
        sys.exit(f'build.py: {error}')


if __name__ == '__main__':
    main()
