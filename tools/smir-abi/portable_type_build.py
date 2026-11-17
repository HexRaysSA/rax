"""Real pinned native build; every guard remains active under Python -O."""
from pathlib import Path
import hashlib, json, os, shlex, subprocess, sys
HERE = Path(__file__).resolve().parent
from portable_type_paths import foundation
import portable_type_paths
PROJECT = foundation()
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
COMPILER = '192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7'

class BuildError(ValueError):

    def __init__(self, code, detail=''):
        self.code = code
        super().__init__(code + ': ' + detail)

def need(value, code, detail=''):
    if not value:
        raise BuildError(code, detail)

def digest(p):
    h = hashlib.sha256()
    try:
        with Path(p).open('rb') as f:
            for data in iter(lambda: f.read(1 << 20), b''):
                h.update(data)
    except OSError as e:
        raise BuildError('CEW_BUILD_INPUT', str(e)) from e
    return h.hexdigest()

def check(args):
    try:
        return subprocess.check_output([str(x) for x in args], text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise BuildError('CEW_BUILD_COMMAND', str(e)) from e

def build(llvm, output, optimize=False):
    llvm = Path(llvm).resolve()
    output = Path(output).resolve()
    need(not output.is_relative_to(PROJECT) and (not output.is_relative_to(llvm)), 'CEW_BUILD_OUTPUT', 'output must be outside source checkouts')
    need(not output.exists(), 'CEW_BUILD_OUTPUT', 'output already exists')
    need(check(['git', '-C', llvm, 'rev-parse', 'HEAD']).strip() == PIN, 'CEW_BUILD_PIN', 'LLVM source pin')
    cc = llvm / 'build/bin/clang++'
    need(digest(cc) == COMPILER, 'CEW_BUILD_COMPILER', 'actual compiler hash')
    version = check([cc, '--version'])
    need(PIN in version, 'CEW_BUILD_COMPILER', 'actual compiler version')
    libraries = sorted((llvm / 'build/lib').glob('libclang*.a'))
    need(bool(libraries), 'CEW_BUILD_LIBRARIES', 'no pinned static Clang libraries')
    flags = [str(cc), '-std=c++17', '-fno-rtti', '-fno-exceptions']
    flags += ['-O2','-DNDEBUG'] if optimize else ['-O0']
    sdk = None
    if sys.platform == 'darwin':
        sdk = Path(check(['/usr/bin/xcrun', '--show-sdk-path']).strip())
        need(sdk.is_dir(), 'CEW_BUILD_SDK', 'SDK path')
        flags += ['-isysroot', str(sdk)]
    flags += ['-I' + str(llvm / x) for x in ['clang/include', 'build/tools/clang/include', 'llvm/include', 'build/include']]
    cpp = HERE / 'portable_type_frontend.cpp'
    need(cpp.is_file(), 'CEW_BUILD_INPUT', 'native source')
    raw = check(flags + ['-MM', '-MT', 'source_event', cpp])
    words = shlex.split(raw.replace('\\\n', ''))
    need(bool(words) and words[0] == 'source_event:', 'CEW_BUILD_DEPENDENCIES', 'compiler dependency grammar')
    headers = [Path(x).resolve() for x in words[1:]]
    need(bool(headers), 'CEW_BUILD_DEPENDENCIES', 'empty source dependency set')
    config = llvm / 'build/bin/llvm-config'
    links = shlex.split(check([config, '--ldflags', '--libs', '--system-libs']))
    llvmfiles = [Path(x).resolve() for x in shlex.split(check([config, '--libfiles']))]
    need(bool(llvmfiles), 'CEW_BUILD_LIBRARIES', 'empty LLVM library set')
    binary = output / 'portable-type-bootstrap'
    filtered = output / 'libclangBasic-portable.a'
    original_basic = llvm / 'build/lib/libclangBasic.a'
    argv = flags + [str(cpp)] + [str(filtered if x == original_basic else x) for x in libraries] + links
    if sys.platform == 'darwin':
        argv += ['-L/opt/homebrew/opt/zstd/lib', '-Wl,-rpath,' + str(llvm / 'build/lib')]
    argv += ['-o', str(binary)]
    ar = llvm / 'build/bin/llvm-ar'
    inputs = set(headers + libraries + llvmfiles + [cpp, cc.resolve(), config, ar.resolve(), Path(__file__).resolve(), Path(portable_type_paths.__file__).resolve()])
    if sdk and (sdk / 'SDKSettings.json').is_file():
        inputs.add(sdk / 'SDKSettings.json')
    inputs.update([llvm / 'build/lib/libc++.1.0.dylib', llvm / 'build/lib/libc++abi.1.0.dylib', Path('/opt/homebrew/Cellar/zstd/1.5.7_1/lib/libzstd.1.5.7.dylib')])
    before = {str(x.resolve()): digest(x) for x in sorted(inputs)}
    output.mkdir(exist_ok=False)
    import shutil
    shutil.copyfile(original_basic, filtered)
    need(check([ar,'t',original_basic]).splitlines().count('Targets.cpp.o')==1,'PT_BUILD_ARCHIVE_OBJECT')
    subprocess.run([str(ar), 'd', str(filtered), 'Targets.cpp.o'], check=True)
    need('Targets.cpp.o' not in check([ar,'t',filtered]).splitlines(),'PT_BUILD_ARCHIVE_OBJECT')
    before[str(filtered)]=digest(filtered)
    tmp = output / 'clang-tmp'
    tmp.mkdir()
    print('actual native compile inputs', len(before), flush=True)
    run = subprocess.run(argv, capture_output=True, text=True, timeout=180, env=dict(os.environ, TMPDIR=str(tmp)))
    (output / 'build.stdout').write_text(run.stdout)
    (output / 'build.stderr').write_text(run.stderr)
    drift = [p for p, h in before.items() if digest(p) != h]
    receipt = dict(format='draft-portable-type-target-bootstrap-build', llvm_pin=PIN, compiler=dict(path=str(cc.resolve()), sha256=digest(cc), version=version), command=argv, exit=run.returncode, input_hashes=before, drift=drift, native_optimization='O2_NDEBUG' if optimize else 'O0', scope='Actual out-of-tree portable TargetInfo/frontend compilation; original archive preserved and filtered copy/archiver/compiler/non-system headers/static libraries/SDKsettings guarded, not full OS/SDK/shared-library attestation or clean LLVM rebuild')
    if run.returncode == 0:
        receipt['binary'] = dict(path=str(binary), sha256=digest(binary))
    (output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    need(not drift, 'CEW_BUILD_DRIFT', repr(drift))
    need(run.returncode == 0, 'CEW_NATIVE_BUILD_FAILED', run.stderr[-4096:])
    print(str(binary), flush=True)
    return binary
if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--llvm', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--optimize',action='store_true')
    a = p.parse_args()
    build(a.llvm, a.output,a.optimize)
