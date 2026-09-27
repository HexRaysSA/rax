#!/usr/bin/env bash
# Observed failures of final inputs under the preserved pre-feature RAX CLI.
set -euo pipefail
fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
baseline_cli="${1:?Usage: bash baseline.sh /absolute/path/to/preserved/rax-user}"
python3 - "$fixture_dir" "$baseline_cli" <<'PY'
import hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile, tomllib
root = pathlib.Path(sys.argv[1])
cli = pathlib.Path(sys.argv[2]).resolve(strict=True)
sha = lambda data: hashlib.sha256(data).hexdigest()
expected_cli = '422d7a6a0178c1a3a249c109f1138ed71e2b1ec5ffd1377573b1dcfa2f31c93f'
assert sha(cli.read_bytes()) == expected_cli, 'Not the preserved source baseline CLI'
manifest_bytes = (root / 'manifest.toml').read_bytes()
manifest = tomllib.loads(manifest_bytes.decode())
receipt = {
    'schema': 1, 'purpose': 'Observed pre-feature RAX onexit failures; no native oracle.',
    'source_baseline': '3efe07a63ab935815d84ea4a48958282672a9059',
    'executable': str(cli), 'executable_sha256': expected_cli,
    'fixture_manifest_sha256': sha(manifest_bytes), 'seed': 1,
    'arena_bytes': 67108864, 'watchdog_seconds': 30,
    'environment': {'RAX_NO_JIT': '1'}, 'dependencies': [], 'runs': [],
}
for fixture in manifest['fixture']:
    if fixture['role'] == 'dependency':
        assert sha((root / fixture['path']).read_bytes()) == fixture['sha256']
        receipt['dependencies'].append({key: fixture[key] for key in
            ('path', 'arch', 'binding', 'sha256', 'bytes')})
environment = os.environ.copy()
environment['RAX_NO_JIT'] = '1'
for fixture in manifest['fixture']:
    if fixture['role'] != 'executable': continue
    image = root / fixture['path']
    assert sha(image.read_bytes()) == fixture['sha256']
    for slice_instructions in (1, 4096):
        with tempfile.TemporaryDirectory(prefix='rax-crt-onexit-baseline-') as directory:
            copied = pathlib.Path(directory) / image.name
            shutil.copyfile(image, copied)
            dependency = None
            if fixture['program'] == 'terminal':
                dependency = image.parent / 'onexit.dll'
                copied_dll = pathlib.Path(directory) / 'onexit.dll'
                shutil.copyfile(dependency, copied_dll)
            arguments = [str(cli), '--os', 'windows', '--memory', '64M', '--drive',
                         f'C={directory}', '--cwd', 'C:\\', '--slice', str(slice_instructions),
                         '--seed', '1', '--clear-env', str(copied)]
            result = subprocess.run(arguments, env=environment, capture_output=True,
                                    text=True, timeout=30, check=False)
            assert sha(copied.read_bytes()) == fixture['sha256'], 'Copied input mutated'
            expected_names = [image.name]
            if dependency:
                assert copied_dll.read_bytes() == dependency.read_bytes(), 'Copied dependency mutated'
                expected_names.append('onexit.dll')
            assert sorted(path.name for path in pathlib.Path(directory).iterdir()) == sorted(expected_names)
        match = re.search(r'unimplemented Windows export: ([^!\n]+)!([^ ]+) at ', result.stderr)
        assert result.returncode == 125 and match, (
            fixture['path'], slice_instructions, result.returncode, result.stderr)
        receipt['runs'].append({
            'path': fixture['path'], 'arch': fixture['arch'], 'binding': fixture['binding'],
            'program': fixture['program'], 'input_sha256': fixture['sha256'],
            'slice_instructions': slice_instructions, 'arguments': arguments[1:],
            'shell_exit': result.returncode, 'status': None,
            'failure_class': 'unimplemented Windows export',
            'missing_dll': match.group(1), 'missing_export': match.group(2),
            'stdout': result.stdout, 'stderr': result.stderr,
            'dependencies': [{'path': str(dependency.relative_to(root)),
                              'sha256': sha(dependency.read_bytes())}] if dependency else [],
        })
assert len(receipt['runs']) == 72
assert len(receipt['dependencies']) == 6
(root / 'baseline.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('72 observed onexit-export failures; no timeout/native oracle.')
PY
