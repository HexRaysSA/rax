"""Build the isolated pinned LLVM IRReader witness; no TargetMachine or emitter."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
COMPILER_SHA256 = '192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7'


class BuildError(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise BuildError(detail)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def output(command):
    return subprocess.check_output([str(value) for value in command], text=True, timeout=60)


def build(llvm, destination):
    llvm = Path(llvm).resolve()
    destination = Path(destination).resolve()
    need(not destination.is_relative_to(PROJECT) and not destination.is_relative_to(llvm),
         'program-space outputs must be outside both source checkouts')
    need(not destination.exists(), 'fresh build output required')
    head = output(['git', '-C', llvm, 'rev-parse', 'HEAD']).strip()
    compiler = llvm / 'build/bin/clang++'
    config = llvm / 'build/bin/llvm-config'
    version = output([compiler, '--version'])
    need(head == PIN and PIN in version and digest(compiler) == COMPILER_SHA256,
         'actual pinned compiler/source required')
    config_version = output([config, '--version']).strip()
    need(config_version.startswith('24.0.0'), 'pinned LLVM24 library configuration required')
    flags = shlex.split(output([config, '--cxxflags']))
    source = HERE / 'program_space_reader.cpp'
    need(source.is_file(), 'native reader source missing')
    extra_inputs = []
    extra_links = []
    if sys.platform == 'darwin':
        sdk = Path(output(['/usr/bin/xcrun', '--show-sdk-path']).strip())
        need(sdk.is_dir(), 'SDK missing')
        flags += ['-isysroot', str(sdk)]
        extra_inputs += [sdk / 'SDKSettings.json', llvm / 'build/lib/libc++.1.dylib',
                         llvm / 'build/lib/libc++abi.1.dylib',
                         Path('/opt/homebrew/opt/zstd/lib/libzstd.1.dylib')]
        extra_links += ['-L/opt/homebrew/opt/zstd/lib', '-Wl,-rpath,' + str(llvm / 'build/lib')]
    components = ['core', 'irreader', 'asmparser', 'support']
    libraries = [Path(value).resolve() for value in shlex.split(
        output([config, '--link-static', '--libfiles', *components]))]
    need(bool(libraries), 'LLVM static libraries missing')
    links = shlex.split(output([config, '--ldflags', '--system-libs']))
    dependencies = shlex.split(output([compiler, *flags, '-MM', '-MT', 'reader', source])
                               .replace('\\\n', ''))
    need(bool(dependencies) and dependencies[0] == 'reader:', 'dependency grammar')
    inputs = {Path(value).resolve() for value in dependencies[1:]}
    inputs.update(path.resolve() for path in libraries + extra_inputs +
                  [source, Path(__file__), compiler, config, llvm / 'build/CMakeCache.txt'])
    before = {str(path): digest(path) for path in sorted(inputs)}
    destination.mkdir(parents=True, exist_ok=False)
    scratch = destination / 'clang-tmp'
    scratch.mkdir()
    binary = destination / 'program-space-oracle'
    command = [str(compiler), *flags, str(source), *map(str, libraries), *links,
               *extra_links, '-o', str(binary)]
    timed_out = False
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180,
                                env=dict(os.environ, TMPDIR=str(scratch)))
        exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        exit_code = None
        stdout = error.stdout or b''
        stderr = error.stderr or b''
        stdout = stdout.decode(errors='replace') if isinstance(stdout, bytes) else stdout
        stderr = stderr.decode(errors='replace') if isinstance(stderr, bytes) else stderr
    (destination / 'build.stdout').write_text(stdout)
    (destination / 'build.stderr').write_text(stderr)
    drift = [path for path, sha in before.items() if digest(path) != sha]
    head_after = output(['git', '-C', llvm, 'rev-parse', 'HEAD']).strip()
    receipt = dict(format='llvm-program-space-reference-build-v1',
                   command=command, exit=exit_code, timed_out=timed_out,
                   input_hashes=before, drift=drift, compiler_version=version,
                   llvm_pin=head, llvm_head_after=head_after,
                   config_version=config_version,
                   native_host=output([config, '--host-target']).strip(),
                   source=str(source), builder=str(Path(__file__).resolve()),
                   scope='Actual reference-build static IRReader/verifier. No TargetMachine, optimizer, emitter, source/ABI/runtime admission or full LLVM/OS rebuild attestation. Supplied library-source relationship is an explicit assumption; exact artifacts are guarded.')
    if exit_code == 0:
        receipt['binary'] = dict(path=str(binary), sha256=digest(binary))
    (destination / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    need(not drift and head_after == PIN, 'build inputs/source HEAD changed')
    need(exit_code == 0, 'actual native build failed: ' + stderr[-4096:])
    print('program-space native build PASS', len(before), str(binary), flush=True)
    return binary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--llvm', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    build(arguments.llvm, arguments.output)
