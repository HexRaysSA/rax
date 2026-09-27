#!/usr/bin/env bash
# Observed final-input failures under the preserved pre-feature CLI only.
set -euo pipefail
fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
baseline_cli="${1:?Usage: bash baseline.sh /absolute/path/to/preserved/rax-user}"
python3 - "$fixture_dir" "$baseline_cli" <<'PY'
import hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile, tomllib
root = pathlib.Path(sys.argv[1])
cli = pathlib.Path(sys.argv[2]).resolve(strict=True)
sha = lambda data: hashlib.sha256(data).hexdigest()
expected_cli = '55a60784315e0e7eff45b5ba4b793f1f225424bb7583f1c95653135a70e89b93'
assert sha(cli.read_bytes()) == expected_cli, 'Not the preserved pre-feature CLI'
manifest_bytes = (root / 'manifest.toml').read_bytes()
manifest = tomllib.loads(manifest_bytes.decode())
receipt = {
    'schema': 1, 'purpose': 'Observed pre-feature CRT stdio failures; no native oracle.',
    'source_baseline': '9b73397628567e675f129ecf38896ee50f601576',
    'executable': str(cli), 'executable_sha256': expected_cli,
    'fixture_manifest_sha256': sha(manifest_bytes), 'seed': 1,
    'arena_bytes': 67108864, 'watchdog_seconds': 30,
    'environment': {'RAX_NO_JIT': '1'}, 'runs': [], 'ordinary_runs': [],
}
environment = os.environ.copy(); environment['RAX_NO_JIT'] = '1'
inputs = {'translation': {'text.dat': b'a\r\nb\rx\r\nYZ\x1aQ',
                          'edge.dat': b'a' * 255 + b'\r\n' + b'b' * 512 + b'Z'},
          'repair': {'read.dat': bytes((7 * i + 3) % 256 for i in range(768))}}
outputs = {'streams': (), 'bytes': ('bytes.dat',), 'descriptors': ('descriptor.dat',),
           'translation': ('translate.dat', 'default.dat', 'control.dat'), 'repair': ('repair.dat',),
           'buffering': ('line.dat', 'flush.dat'), 'errors': (), 'main': (), 'wmain': ()}
for fixture in manifest['fixture']:
    image = root / fixture['path']
    assert sha(image.read_bytes()) == fixture['sha256']
    ordinary = fixture['role'] == 'ordinary-startup-observation'
    for slice_instructions in (1, 4096):
        with tempfile.TemporaryDirectory(prefix='rax-crt-stdio-baseline-') as directory:
            directory = pathlib.Path(directory)
            copied = directory / image.name; shutil.copyfile(image, copied)
            source_inputs = inputs.get(fixture['program'], {})
            for name, data in source_inputs.items(): (directory / name).write_bytes(data)
            arguments = [str(cli), '--os', 'windows', '--memory', '64M', '--drive',
                         f'C={directory}', '--cwd', 'C:\\', '--slice', str(slice_instructions),
                         '--seed', '1', '--clear-env', str(copied)]
            timed_out = False
            try:
                result = subprocess.run(arguments, env=environment, capture_output=True,
                                        timeout=30, check=False)
                returncode, stdout, stderr_bytes = result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired as failure:
                assert ordinary, 'Semantic probe baseline timed out'
                timed_out = True
                returncode, stdout, stderr_bytes = None, failure.stdout or b'', failure.stderr or b''
            assert copied.read_bytes() == image.read_bytes(), 'Copied PE mutated'
            for name, data in source_inputs.items(): assert (directory / name).read_bytes() == data
            allowed = {image.name, *source_inputs, *outputs[fixture['program']]}
            assert {path.name for path in directory.iterdir()} <= allowed, 'Unexpected guest-created file'
            effects = {name: (directory / name).read_bytes().hex()
                       for name in outputs[fixture['program']] if (directory / name).exists()}
        stderr = stderr_bytes.decode('utf-8', errors='replace')
        match = re.search(r'unimplemented Windows export: ([^!\n]+)!([^ ]+) at ', stderr)
        assert timed_out or (returncode == 125 and match), (
            fixture['path'], slice_instructions, returncode, stderr)
        observation = {
            'path': fixture['path'], 'arch': fixture['arch'], 'binding': fixture['binding'],
            'program': fixture['program'], 'input_sha256': fixture['sha256'],
            'slice_instructions': slice_instructions, 'arguments': arguments[1:],
            'shell_exit': returncode, 'status': None, 'timed_out': timed_out,
            'failure_class': 'watchdog timeout' if timed_out else 'unimplemented Windows export',
            'missing_dll': match.group(1) if match else None,
            'missing_export': match.group(2) if match else None,
            'stdout_hex': stdout.hex(), 'stderr_hex': stderr_bytes.hex(),
            'stdout': stdout.decode('utf-8', errors='replace'), 'stderr': stderr,
            'inputs': {name: sha(data) for name, data in source_inputs.items()},
            'output_hex': effects,
        }
        receipt['ordinary_runs' if ordinary else 'runs'].append(observation)
assert len(receipt['runs']) == 120 and len(receipt['ordinary_runs']) == 12
(root / 'baseline.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('120 semantic export failures; 12 genuine ordinary-startup observations; native oracle unknown.')
PY
