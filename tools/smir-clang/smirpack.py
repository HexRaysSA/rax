#!/usr/bin/env python3
"""Make an executable that carries its runtime and its program.

    python3 -B smirpack.py OBJECT -o EXECUTABLE

OBJECT is a portable SMIR object, as `smircc.py` writes it. EXECUTABLE is a
program of this machine: the system's linker links the launcher and the
runtime's static library (`crates/smir-portable-capi`), with the object in a
section of its own, behind a locator that says where it is and what its
SHA-256 is. Started, the executable finds the object in its own file and runs
it; see `launcher/launcher.c` for what the program is given.

The steps, and why in this order:

1. `smir-pack --section` verifies the object and writes the section: a
   locator that does not yet say where the object is, and the object.
2. The C compiler links launcher, runtime and section.
3. `smir-pack --seal` writes into the locator where the section ended up.
4. The file is signed again, ad hoc, since step 3 changed it: macOS runs no
   program whose signature does not cover what is in it.
5. `smir-pack --show` finds the object in the finished file, as the runtime
   will when the file is started.

So far this is done for Mach-O, which is to say on macOS.
"""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = ROOT / 'crates/smir-portable'
INTERFACE = ROOT / 'crates/smir-portable-capi'
CONTRACT = ROOT / 'tools/smir-runtime-contract/include'


class PackError(Exception):
    pass


def run(command, what):
    done = subprocess.run([str(item) for item in command], capture_output=True, text=True)
    if done.returncode != 0:
        raise PackError(f'{what} failed:\n{(done.stdout + done.stderr).strip()[-3000:]}')
    return done.stdout


def cargo(crate, *arguments):
    run(['cargo', 'build', '--offline', '--locked', '--manifest-path', crate / 'Cargo.toml', *arguments],
        f'building {crate.name}')
    return crate / 'target/debug'


def tools():
    """Build what packing needs; returns `smir-pack` and the runtime's static library."""
    packer = cargo(RUNTIME, '--bin', 'smir-pack') / 'smir-pack'
    library = cargo(INTERFACE) / 'librax_smir_portable_capi.a'
    return packer, library


def pack(object_path, output):
    """Link `object_path` into the executable `output`."""
    if platform.system() != 'Darwin':
        raise PackError('executables are made for Mach-O only so far, on macOS')
    packer, library = tools()
    compiler = os.environ.get('CC', 'cc')
    with tempfile.TemporaryDirectory(prefix='smirpack-') as scratch:
        section = Path(scratch) / 'section.bin'
        run([packer, object_path, '--section', '-o', section], 'verifying the object')
        run([compiler, '-O1', '-o', output, INTERFACE / 'launcher/launcher.c',
             '-I', INTERFACE / 'include', '-I', CONTRACT, library, '-lSystem', '-lc', '-lm',
             # The object's section, in a segment of its own that is mapped
             # for reading and never for anything else.
             f'-Wl,-sectcreate,__SMIR,__module,{section}', '-Wl,-segprot,__SMIR,r,r'],
            'linking the executable')
    run([packer, '--seal', output], 'sealing the locator')
    run(['codesign', '--force', '--sign', '-', output], 'signing the executable')
    return run([packer, '--show', output], 'finding the object in the executable').strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('object', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    arguments = parser.parse_args()
    try:
        print(pack(arguments.object, arguments.output))
    except PackError as error:
        sys.exit(f'smirpack.py: {error}')


if __name__ == '__main__':
    main()
