#!/usr/bin/env bash
# Record old-RAX failures of final inputs; no Cargo/native Windows invocation.
set -euo pipefail
fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
baseline_cli="${1:?Usage: bash baseline.sh /absolute/path/to/preserved/rax-user}"
python3 - "$fixture_dir" "$baseline_cli" <<'PY'
import hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile, tomllib
root = pathlib.Path(sys.argv[1])
cli = pathlib.Path(sys.argv[2]).resolve(strict=True)
sha = lambda data: hashlib.sha256(data).hexdigest()
expected_cli = 'cb2fe8e1dc750165233922cf2712dac132cb42e127baf799d47322ac09d1f3ce'
assert sha(cli.read_bytes()) == expected_cli, 'Not the preserved source baseline executable'
manifest_bytes = (root / 'manifest.toml').read_bytes()
manifest = tomllib.loads(manifest_bytes.decode())
lines = {
    'arguments': r'"C:\Program Files\probe.exe" "" "ab\"c" a\\\b d"e f"g "café" ＂x y＂',
    'environment': 'probe environment',
    'wildcards': r'probe *.txt "*.txt" *.* sub\?.bin absent*.q ??.dat',
    'newmode': 'probe', 'modes': 'probe one two', 'isolation': 'probe one two',
}
files = {'alpha.txt': b'alpha', 'beta.txt': b'beta', 'README': b'extensionless',
         'aa.dat': b'aa', 'bb.dat': b'bb', 'sub/q.bin': b'q', 'sub/qq.bin': b'qq'}
receipt = {
    'schema': 1, 'purpose': 'Observed pre-feature RAX argv/environment failures; no native oracle.',
    'source_baseline': '0753ca1c0b769da93d24390d1f24c4aad070b9d2',
    'executable': str(cli), 'executable_sha256': expected_cli,
    'fixture_manifest_sha256': sha(manifest_bytes), 'seed': 1,
    'arena_bytes': 67108864, 'watchdog_seconds': 30,
    'environment': {'RAX_NO_JIT': '1'},
    'wildcard_inputs': [{'path': name, 'bytes': len(data), 'sha256': sha(data)}
                        for name, data in files.items()], 'runs': [],
}
environment = os.environ.copy()
environment['RAX_NO_JIT'] = '1'
for fixture in manifest['fixture']:
    image = root / fixture['path']
    assert sha(image.read_bytes()) == fixture['sha256']
    scenarios = ('populated', 'empty') if fixture['program'] == 'environment' else ('default',)
    for scenario in scenarios:
        raw_line = 'probe empty' if scenario == 'empty' else lines[fixture['program']]
        for slice_instructions in (1, 4096):
            with tempfile.TemporaryDirectory(prefix='rax-crt-startup-baseline-') as directory:
                copied_image = pathlib.Path(directory) / image.name
                shutil.copyfile(image, copied_image)
                if fixture['program'] == 'wildcards':
                    work = pathlib.Path(directory) / 'work'
                    (work / 'sub').mkdir(parents=True)
                    for name, data in files.items(): (work / name).write_bytes(data)
                cwd = 'C:\\work' if fixture['program'] == 'wildcards' else 'C:\\'
                arguments = [str(cli), '--os', 'windows', '--memory', '64M', '--drive',
                             f'C={directory}', '--cwd', cwd, '--slice', str(slice_instructions),
                             '--seed', '1', '--clear-env', '--command-line', raw_line]
                if scenario == 'populated':
                    for value in ('Alpha=one', 'Beta=two', 'Mixed=café', 'alpha=last', 'EMPTY='):
                        arguments.extend(('-E', value))
                arguments.append(str(copied_image))
                result = subprocess.run(arguments, env=environment, capture_output=True,
                                        text=True, timeout=30, check=False)
                assert sha(copied_image.read_bytes()) == fixture['sha256'], 'Copied input mutated'
                if fixture['program'] == 'wildcards':
                    for name, data in files.items(): assert (work / name).read_bytes() == data
            match = re.search(r'unimplemented Windows export: ([^!\n]+)!([^ ]+) at ', result.stderr)
            assert result.returncode == 125 and match, (
                fixture['path'], scenario, slice_instructions, result.returncode, result.stderr)
            receipt['runs'].append({
                'path': fixture['path'], 'arch': fixture['arch'], 'binding': fixture['binding'],
                'program': fixture['program'], 'scenario': scenario,
                'input_sha256': fixture['sha256'], 'slice_instructions': slice_instructions,
                'raw_command_line': raw_line, 'arguments': arguments[1:],
                'shell_exit': result.returncode, 'status': None,
                'failure_class': 'unimplemented Windows export',
                'missing_dll': match.group(1), 'missing_export': match.group(2),
                'stdout': result.stdout, 'stderr': result.stderr,
            })
assert len(receipt['runs']) == 108
(root / 'baseline.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n')
print('108 observed startup-import failures; no timeout/native oracle.')
PY
