#!/usr/bin/env bash
# Record actual old-RAX failures, not native Windows behavior. No Cargo/build.
set -euo pipefail
fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
baseline_cli="${1:?Usage: bash baseline.sh /absolute/path/to/preserved/rax-user}"
python3 - "$fixture_dir" "$baseline_cli" <<'PY'
import hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile, tomllib
root = pathlib.Path(sys.argv[1])
cli = pathlib.Path(sys.argv[2]).resolve(strict=True)
sha = lambda data: hashlib.sha256(data).hexdigest()
expected_cli = '8ab3fbeafd5f8cf379fcdf0f826ffd89eb573a3db00c97558df151c278253fc5'
assert sha(cli.read_bytes()) == expected_cli, 'Not the preserved source baseline executable'
manifest_bytes = (root / 'manifest.toml').read_bytes()
manifest = tomllib.loads(manifest_bytes.decode())
receipt = {
    'schema': 1,
    'purpose': 'Observed pre-feature RAX constructor import failures; no native Windows oracle.',
    'source_baseline': 'b7498e58030bc0317cfa96845b509c9335c8fb30',
    'executable': str(cli), 'executable_sha256': expected_cli,
    'fixture_manifest_sha256': sha(manifest_bytes),
    'seed': 1, 'arena_bytes': 67108864, 'watchdog_seconds': 30,
    'environment': {'RAX_NO_JIT': '1'}, 'runs': [],
}
environment = os.environ.copy()
environment['RAX_NO_JIT'] = '1'
for fixture in manifest['fixture']:
    image = root / fixture['path']
    assert sha(image.read_bytes()) == fixture['sha256']
    for slice_instructions in (1, 4096):
        with tempfile.TemporaryDirectory(prefix='rax-crt-init-baseline-') as directory:
            copied_image = pathlib.Path(directory) / image.name
            shutil.copyfile(image, copied_image)
            arguments = [str(cli), '--os', 'windows', '--memory', '64M', '--drive',
                         f'C={directory}', '--cwd', 'C:\\', '--slice', str(slice_instructions),
                         '--seed', '1', str(copied_image)]
            result = subprocess.run(arguments, env=environment, capture_output=True,
                                    text=True, timeout=30, check=False)
            assert sha(copied_image.read_bytes()) == fixture['sha256'], 'Copied input mutated'
        missing_export = '_initterm_e' if image.stem == 'errors' else '_initterm'
        assert result.returncode == 125 and 'unimplemented Windows export:' in result.stderr \
            and f'!{missing_export} at ' in result.stderr, (
            fixture['path'], slice_instructions, result.returncode, result.stderr)
        receipt['runs'].append({
            'path': fixture['path'], 'arch': fixture['arch'], 'binding': fixture['binding'],
            'input_sha256': fixture['sha256'], 'slice_instructions': slice_instructions,
            'arguments': arguments[1:], 'shell_exit': result.returncode,
            'status': None, 'failure_class': 'unimplemented Windows export',
            'missing_export': missing_export,
            'stdout': result.stdout, 'stderr': result.stderr,
        })
assert len(receipt['runs']) == 68
(root / 'baseline.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('68 observed constructor-import failures; no timeout or native oracle.')
PY
