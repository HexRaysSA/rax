"""Build immutable native query-key probes using the existing compiler adapter."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

ROOT = Path('C:/Windows/Temp/assist-native-rax-20261010/src-display-candidate1').resolve()
OUT = Path(__file__).resolve().parent
assert OUT.is_relative_to(ROOT / 'target')
TMP = OUT / 'tmp'
TMP.mkdir(exist_ok=True)
state = {'pid': os.getpid(), 'state': 'running', 'kernel': list(sys.getwindowsversion()), 'rows': []}

def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def save():
    p = OUT / 'receipt.json'
    p.write_text(json.dumps(state, indent=2))

try:
    helper = ROOT / 'docs/specifications/windows/native-exception-entry-profile/run-v2.py'
    assert digest(helper) == '391b84e6c0477abc27ca6d20c41a37078f2074fe34d4b2620a3ec8ec34df30ba'
    spec = importlib.util.spec_from_file_location('compiler_adapter', helper)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    source = OUT / 'probe-v3.cpp'
    state.update(controller_sha256=digest(__file__), source_sha256=digest(source), python_sha256=digest(sys.executable), compiler_adapter_sha256=digest(helper))
    save()
    env_snapshot = ROOT / 'target/win32u-validation-recovery-v2/transfer/mutant-native-compiler-env-epoch4.json'
    for label, arch in [('arm64', 'arm64'), ('x64', 'x64'), ('x86', 'x86'), ('x86-laa', 'x86')]:
        work = OUT / label
        work.mkdir(exist_ok=False)
        env, compiler = adapter.compiler_environment(arch, env_snapshot, TMP)
        exe = work / 'native-query-key-v3.exe'
        command = [str(compiler), '/nologo', '/std:c++17', '/EHsc', '/utf-8', '/MT', str(source), '/Fo' + str(work / 'probe.obj'), '/Fd' + str(work / 'compile.pdb'), '/Fe' + str(exe), '/link', '/PDB:' + str(work / 'link.pdb')]
        if label == 'x86-laa':
            command.append('/LARGEADDRESSAWARE')
        if label == 'x86':
            command.append('/LARGEADDRESSAWARE:NO')
        build = subprocess.run(command, capture_output=True, env=env, cwd=work, timeout=120)
        (work / 'build.log').write_bytes(build.stdout + build.stderr)
        row = dict(label=label, command=command, compiler_sha256=digest(compiler), source_before_sha256=digest(source), build_returncode=build.returncode)
        state['rows'].append(row)
        save()
        assert build.returncode == 0
        row['exe_before_sha256'] = digest(exe)
        save()
        with (work / 'stdout.jsonl').open('wb') as stdout, (work / 'stderr.log').open('wb') as stderr:
            run = subprocess.run([str(exe)], stdout=stdout, stderr=stderr, env=env, cwd=work, timeout=60)
        row.update(run_returncode=run.returncode, exe_after_sha256=digest(exe), source_after_sha256=digest(source), stdout_sha256=digest(work / 'stdout.jsonl'), stderr_sha256=digest(work / 'stderr.log'))
        observations = [json.loads(line) for line in (work / 'stdout.jsonl').read_text().splitlines()]
        row['machine'] = observations[0]
        row['observations'] = len(observations)
        save()
        assert run.returncode == 0
        assert row['exe_before_sha256'] == row['exe_after_sha256']
        assert row['source_before_sha256'] == row['source_after_sha256'] == state['source_sha256']
    state['state'] = 'complete'
except BaseException:
    state['state'] = 'failed'
    state['error'] = traceback.format_exc()
finally:
    save()
