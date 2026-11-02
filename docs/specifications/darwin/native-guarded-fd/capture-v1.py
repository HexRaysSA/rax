"""Capture guarded-descriptor controls in a new in-tree acquisition directory."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    source = Path(__file__).resolve().with_name('probe-v1.c')
    root = source.parents[4]
    out = arguments.output.resolve()
    assert sys.platform == 'darwin'
    assert root in out.parents and not out.exists()
    out.mkdir(parents=True)
    (out / '.owner').write_text('native-guarded-fd-v1-20261102\n')
    temporary = out / 'tmp'
    temporary.mkdir()
    environment = os.environ.copy()
    environment.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary))
    compiler = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
    cases = [('positive', attributes, flags) for attributes in range(32) if attributes & 2]
    cases.extend(('open', attributes, flags) for attributes in [0, 1, 4, 8, 16, 32, 34, 0xffffffff])
    cases.extend((mode, 31, value) for mode in ['open', 'zero-guard', 'null-guard', 'bad-guard'] for value in [flags, flags & ~os.O_CLOEXEC])
    cases.append(('bad-fd', 31, flags))
    receipt = {'state': 'running', 'host': platform.platform(), 'source_sha256': sha(source), 'compiler': compiler, 'sdk': sdk, 'architectures': []}
    for architecture in ['arm64', 'x86_64']:
        image = out / ('guarded-fd-' + architecture)
        command = [compiler, '-isysroot', sdk, '-arch', architecture, '-std=c11', '-O0', '-Wall', '-Wextra', str(source), '-o', str(image)]
        with (out / ('build-' + architecture + '.log')).open('xb') as log:
            subprocess.run(command, cwd=root, env=environment, stdout=log, stderr=log, check=True)
        identity = sha(image)
        records = []
        for index, (mode, attributes, open_flags) in enumerate(cases):
            data = out / (architecture + '-' + str(index) + '.data')
            command = [str(image), mode, str(data), str(attributes), str(open_flags)]
            begin = time.monotonic()
            result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True, timeout=10, check=True)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            assert rows and not any(row.get('missing_native_symbol') for row in rows)
            record = {'case': index, 'mode': mode, 'guard_flags': attributes, 'open_flags': open_flags, 'argv': command, 'exit_code': result.returncode, 'seconds': time.monotonic() - begin, 'records': rows, 'stderr': result.stderr}
            if data.exists():
                record['file_after'] = {'bytes': data.stat().st_size, 'sha256': sha(data)}
            records.append(record)
        assert sha(image) == identity
        output = out / ('records-' + architecture + '-v1.json')
        output.write_text(json.dumps({'architecture': architecture, 'image_sha256': identity, 'cases': records}, indent=2) + '\n')
        receipt['architectures'].append({'architecture': architecture, 'cases': len(records), 'image_sha256': identity, 'records_sha256': sha(output)})
    assert sha(source) == receipt['source_sha256']
    receipt.update(state='finished', exit_code=0, scope='Positive descriptor operations and nonfatal validation cases only; x86-64 execution on ARM64 is through Rosetta.')
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
