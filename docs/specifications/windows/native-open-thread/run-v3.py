"""Capture NtOpenThread caller ordering and grants on the three Windows ABIs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--compiler-env', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parents[3].resolve()
    output = args.output.resolve()
    assert output.is_relative_to(root)
    output.mkdir()
    source = folder / 'probe-v2.c'
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location('profile', root / 'docs/specifications/windows/native-exception-entry-profile/run-v2.py')
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    result = {'pid': os.getpid(), 'build': os.sys.getwindowsversion().build, 'source_sha256': digest, 'cases': [], 'binaries': {}, 'state': 'running'}
    receipt = output / 'receipt.json'
    def save():
        receipt.write_text(json.dumps(result, indent=2))
    save()
    try:
        for arch in ['arm64', 'x86', 'x64']:
            build = output / arch
            build.mkdir()
            env, compiler = profile.compiler_environment(arch, args.compiler_env, build)
            binary = build / 'probe.exe'
            with (build / 'build.log').open('wb') as log:
                subprocess.run([str(compiler), '/nologo', '/O1', '/MD', 'advapi32.lib', str(source), '/Fe:' + str(binary)], cwd=build, env=env, stdout=log, stderr=log, check=True)
            binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
            result['binaries'][arch] = binary_hash
            for case in range(148, 240):
                child = subprocess.run([str(binary), str(case)], cwd=build, env=env, capture_output=True, timeout=15)
                entry = {'arch': arch, 'case': case, 'exit_code': child.returncode, 'stdout': child.stdout.decode('utf-8', errors='replace'), 'stderr': child.stderr.decode('utf-8', errors='replace')}
                if child.returncode == 0:
                    entry['observation'] = json.loads(entry['stdout'])
                result['cases'].append(entry)
                save()
                assert child.returncode == 0, entry
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
        assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
        result['state'] = 'finished'
    except BaseException:
        result.update(state='failed', error=traceback.format_exc())
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
