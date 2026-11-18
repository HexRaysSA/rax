#!/usr/bin/env python3
"""Make an executable of a program: one that carries its runtime, or one
that finds a runtime installed on the machine.

    python3 -B smirpack.py OBJECT [--library MODULE.smo]... -o EXECUTABLE
    python3 -B smirpack.py OBJECT [--library MODULE.smo]... --installed [--runtime PATH]
                           [--runtime-identity HEX] [--runtime-revision N] -o EXECUTABLE

OBJECT is a portable SMIR object, as `smircc.py` writes it. EXECUTABLE is a
program of this machine: the system's linker links the launcher and the
runtime's static library (`crates/smir-portable-capi`), with the object in a
section of its own, behind a locator that says where it is and what its
SHA-256 is. Started, the executable finds the object in its own file and runs
it; see `launcher/launcher.c` for what the program is given.

An object that was compiled with `smircc.py --needs` calls functions of other
modules. Each `--library` is the object of one of them; it goes into the
executable as it is, in a section beside the program's, and the launcher
links the modules when the executable starts, as `smir-run --library` does.

With `--installed` the runtime's static library is left out, and the entry is
`launcher/bootstrap.c` instead: started, the executable loads the runtime's
shared library from the path it was built with (`--runtime`), or else from
`../lib/rax/` beside itself, or else from where the system's installation
record says; makes sure that runtime has the interface it was built against
(and, if asked, the identity and revision); and runs the program with it.
Such an executable is some tens of kilobytes and its program.

The steps, and why in this order:

1. `smir-pack --section` verifies the object, and that it links with the
   libraries if there are any, and writes the section: a locator that does
   not yet say where the object is, and the object.
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
# As many as the launcher looks for (MOST_LIBRARIES in launch.c).
MOST_LIBRARIES = 64
# The runtime's shared library, as the bootstrap looks for it.
RUNTIME_NAME = 'librax_smir_portable_capi.dylib' if platform.system() == 'Darwin' else 'librax_smir_portable_capi.so'


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


def runtime_library():
    """Build the runtime and return its shared library, which is what is
    installed for the executables that do not carry it."""
    return cargo(INTERFACE) / RUNTIME_NAME


class Installed:
    """An executable that carries its program and not its runtime, and how
    it finds one that is installed (see `launcher/bootstrap.c`).

    `runtime` is the absolute path of the runtime's shared library, if the
    executable is to use that one and no other. Without it the runtime is
    looked for beside the executable, at `../lib/rax/` and the library's
    name from the executable's directory, and then where the installation
    record says, a file whose first line is the path; `record` is another
    place for that record than the system's. `identity` is the
    implementation identity the runtime must have, as 64 hexadecimal digits,
    and `revision` the least revision.
    """

    def __init__(self, runtime=None, record=None, identity=None, revision=0):
        self.definitions = [f'-DRAX_RUNTIME_REVISION={int(revision)}']
        for name, value in (('RAX_RUNTIME_PATH', runtime), ('RAX_INSTALLATION_RECORD', record),
                            ('RAX_RUNTIME_IDENTITY', identity)):
            if value is None:
                continue
            value = str(value)
            if name == 'RAX_RUNTIME_IDENTITY':
                if len(value) != 64 or set(value) - set('0123456789abcdef'):
                    raise PackError('a runtime identity is 64 hexadecimal digits in lower case')
            elif not value.startswith('/') or set(value) & set('"\\\n'):
                raise PackError(f'{value!r} is not an absolute path that can be built in')
            self.definitions.append(f'-D{name}="{value}"')


def pack(object_path, output, libraries=(), installed=None):
    """Link `object_path` into the executable `output`, and with it the
    objects of the modules it is linked with when it is loaded. The
    executable carries its runtime unless `installed`, an `Installed`, says
    how it finds one."""
    if platform.system() != 'Darwin':
        raise PackError('executables are made for Mach-O only so far, on macOS')
    if len(libraries) > MOST_LIBRARIES:
        raise PackError(f'an executable holds at most {MOST_LIBRARIES} modules beside its program')
    packer, library = tools()
    compiler = os.environ.get('CC', 'cc')
    launcher = INTERFACE / 'launcher'
    # The entry and the runtime it uses: one linked in, or one to be found.
    entry = ([launcher / 'launcher.c', library, '-lSystem', '-lc', '-lm'] if installed is None else
             [launcher / 'bootstrap.c', *installed.definitions])
    with tempfile.TemporaryDirectory(prefix='smirpack-') as scratch:
        section = Path(scratch) / 'section.bin'
        needed = [item for path in libraries for item in ('--library', path)]
        run([packer, object_path, '--section', *needed, '-o', section], 'verifying the object')
        run([compiler, '-O1', '-o', output, launcher / 'launch.c', *entry,
             '-I', INTERFACE / 'include', '-I', CONTRACT,
             # The object's section, in a segment of its own that is mapped
             # for reading and never for anything else.
             f'-Wl,-sectcreate,__SMIR,__module,{section}', '-Wl,-segprot,__SMIR,r,r',
             # And each module it needs, as it is, in a section beside it,
             # where the launcher looks for them by these names.
             *(f'-Wl,-sectcreate,__SMIR,__needs{position},{Path(path).resolve()}'
               for position, path in enumerate(libraries))],
            'linking the executable')
    run([packer, '--seal', output], 'sealing the locator')
    run(['codesign', '--force', '--sign', '-', output], 'signing the executable')
    return run([packer, '--show', output], 'finding the object in the executable').strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('object', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    parser.add_argument('--library', type=Path, action='append', default=[], metavar='MODULE.smo',
                        help='a module the object is linked with when it is loaded')
    parser.add_argument('--installed', action='store_true',
                        help='leave the runtime out: the executable finds one that is installed')
    parser.add_argument('--runtime', metavar='PATH',
                        help='with --installed: the absolute path of the one runtime to use')
    parser.add_argument('--runtime-identity', metavar='HEX',
                        help='with --installed: the implementation identity the runtime must have')
    parser.add_argument('--runtime-revision', type=int, default=0, metavar='N',
                        help='with --installed: the least revision of the runtime')
    parser.add_argument('--installation-record', metavar='PATH',
                        help='with --installed: where the installation record is, if not where the system has it')
    arguments = parser.parse_args()
    chosen = (arguments.runtime, arguments.installation_record, arguments.runtime_identity)
    if not arguments.installed and (any(chosen) or arguments.runtime_revision):
        parser.error('which runtime to find is said with --installed only')
    try:
        installed = Installed(*chosen, arguments.runtime_revision) if arguments.installed else None
        print(pack(arguments.object, arguments.output, arguments.library, installed))
    except PackError as error:
        sys.exit(f'smirpack.py: {error}')


if __name__ == '__main__':
    main()
