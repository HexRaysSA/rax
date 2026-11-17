"""Controlled native-host termination context oracle; never SMIR execution."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

from canonical import require

OBSERVATIONS = []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def observe(compiler, source):
    compiler, source = Path(compiler), Path(source)
    sdk = subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True).strip()
    headers = Path(sdk) / 'usr/include/c++/v1'
    options = [str(compiler), '-std=c++23', '-nostdinc++', '-isystem', str(headers), '-isysroot', sdk]
    with tempfile.TemporaryDirectory(prefix='termination-context-') as temporary:
        directory = Path(temporary)
        dependency_file, binary = directory/'dependencies.d', directory/'probe'
        preflight = [*options, '-M', '-MT', 'smir_termination', '-MF', str(dependency_file), str(source)]
        subprocess.run(preflight, capture_output=True, text=True, check=True)
        dependencies = shlex.split(dependency_file.read_text().split(':', 1)[1].replace('\\\n', ''))
        require(len(dependencies) <= 4096, 'TERMINATION_HEADER_QUOTA')
        paths = sorted(set(dependencies))
        before = [{'path':p, 'sha256':sha(p)} for p in paths]
        compiler_before = sha(compiler)
        command = [*options, str(source), '-o', str(binary)]
        build = subprocess.run(command, capture_output=True, text=True, check=True)
        cases = []
        expected = {'unhandled':(0,1,1,73), 'noexcept':(0,1,1,73),
                    'catch_copy':(1,1,2,73), 'rethrow_empty':(0,0,0,73),
                    'terminate_in_catch':(0,1,1,73), 'bare_rethrow_after_change':(0,1,1,73),
                    'owner_rethrow_after_change':(0,1,1,74)}
        for case, (count, current, kind, exit_code) in expected.items():
            result = subprocess.run([str(binary),case], capture_output=True, text=True, timeout=10)
            require(result.returncode == exit_code and not result.stderr and result.stdout.strip() ==
                    f'case={case} uncaught={count} current={current} kind={kind}',
                    'TERMINATION_CONTEXT_MISMATCH')
            cases.append({'case':case,'returncode':result.returncode,'stdout':result.stdout.strip()})
        after = [{'path':p,'sha256':sha(p)} for p in paths]
        require(before == after and compiler_before == sha(compiler), 'TERMINATION_INPUT_DRIFT')
        report = {'scope':'native Darwin arm64 host context oracle',
                  'compiler':str(compiler),'compiler_sha256':compiler_before,
                  'compiler_version':subprocess.check_output([str(compiler),'--version'],text=True).strip(),
                  'sdk':sdk,'headers_before':before,'headers_after':after,'inputs_stable':True,
                  'dependency_command':preflight,'compile_command':command,'compile_stderr':build.stderr,
                  'binary_sha256':sha(binary),
                  'linked_images':subprocess.check_output(['/usr/bin/otool','-L',str(binary)],text=True),
                  'cases':cases,'limits':'Explicit Apple SDK headers and system runtime, not pinned LLVM libc++abi build/SMIR/JIT/foreign qualification. Dynamic system runtime binary hash unknown (shared cache).'}
    OBSERVATIONS.append(report)
    return report


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(observe('/Users/int/dev/llvm-project/build/bin/clang++',
        root/'docs/specifications/smir/portable/conformance/llvm/termination-context.cpp'),indent=2))
