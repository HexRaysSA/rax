"""Acquire descriptor policy and synchronous guard exceptions on native macOS."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    source = Path(__file__).resolve().with_name('policy-probe-v2.c')
    root = source.parents[4]
    out = arguments.output.resolve()
    assert sys.platform == 'darwin'
    assert root in out.parents and not out.exists()
    out.mkdir(parents=True)
    (out / '.owner').write_text('native-guarded-fd-policy-v2-20261102\n')
    temporary = out / 'tmp'
    temporary.mkdir()
    environment = os.environ.copy()
    environment.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary))
    compiler = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    operations = ['close', 'dup', 'dev-fd', 'write', 'pwrite', 'writev',
                  'close-wrong', 'write-wrong', 'fork', 'fork-after-clear',
                  'exec-after-clear', 'fileport', 'socket-transfer', 'kqueue',
                  'change-wrong', 'change-replace']
    cases = [(operation, attributes, 0) for attributes in [2, 3, 18, 31]
             for operation in operations]
    cases.extend(('fcntl-dup', attributes, command)
                 for attributes in [2, 3, 18, 31] for command in [0, 67, 115])
    cases.extend(('setfd', attributes, flags)
                 for attributes in [2, 3, 18, 31] for flags in [0, 1, 2, 3])
    cases.extend(('change-remove', attributes, flags)
                 for attributes in [2, 3, 18, 31] for flags in [0, 1, 2, 3])
    cases.extend(('write', attributes, 1) for attributes in [2, 18])
    cases.extend((operation, 2, 0) for operation in
                 ['plain-guarded-close', 'plain-guarded-write', 'plain-change-add'])
    receipt = {'state': 'running', 'host': platform.platform(),
               'kernel': list(os.uname()), 'source_sha256': sha(source),
               'compiler': compiler, 'sdk': sdk, 'architectures': []}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    for architecture in ['arm64', 'x86_64']:
        image = out / ('policy-' + architecture)
        command = [compiler, '-isysroot', sdk, '-arch', architecture,
                   '-std=c11', '-O0', '-Wall', '-Wextra', str(source), '-o', str(image)]
        with (out / ('build-' + architecture + '.log')).open('xb') as log:
            subprocess.run(command, cwd=root, env=environment, stdout=log,
                           stderr=log, check=True)
        identity = sha(image)
        records = []
        for index, (operation, attributes, argument) in enumerate(cases):
            data = out / (architecture + '-' + str(index) + '.data')
            command = [str(image), operation, str(data), str(attributes), str(argument)]
            begin = time.monotonic()
            result = subprocess.run(command, cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=15)
            (out / (architecture + '-' + str(index) + '.stdout')).write_text(result.stdout)
            (out / (architecture + '-' + str(index) + '.stderr')).write_text(result.stderr)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            assert rows and rows[0] == {'kind': 'guard-handler', 'status': 0}
            assert result.returncode in [0, -signal.SIGKILL], (command, result)
            guards = [row for row in rows if row['kind'] == 'guard-exception']
            # Synchronous delivery can be absent, including on Rosetta, even
            # when the registered handler succeeds and the process is killed.
            # Preserve that absence; SIGKILL alone does not prove guard codes.
            assert not guards or result.returncode == -signal.SIGKILL, (command, result)
            for guard in guards:
                descriptor = next(row['result'] for row in rows if row['kind'] == 'open')
                code = int(guard['code'], 16)
                assert guard['message_id'] == 2405 and guard['message_bytes'] == 84
                assert guard['descriptors'] == 2 and guard['exception'] == 12 and guard['count'] == 2
                assert code >> 61 == 2 and code & 0xffffffff == descriptor
                assert guard['subcode'] == '0x1122334455667788'
            record = {'case': index, 'operation': operation, 'guard_flags': attributes,
                      'argument': argument, 'argv': command, 'exit_code': result.returncode,
                      'seconds': time.monotonic() - begin, 'records': rows,
                      'stderr': result.stderr,
                      'synchronous_guard_observed': bool(guards)}
            if data.exists():
                record['file_after'] = {'bytes': data.stat().st_size, 'sha256': sha(data)}
            records.append(record)
            (out / (architecture + '-' + str(index) + '.json')).write_text(json.dumps(record, indent=2) + '\n')
            progress = out / 'progress.json'
            progress.write_text(json.dumps({'architecture': architecture,
                                           'completed': len(records), 'total': len(cases)}) + '\n')
        assert sha(image) == identity
        output = out / ('policy-records-' + architecture + '-v2.json')
        output.write_text(json.dumps({'architecture': architecture,
                                     'image_sha256': identity, 'cases': records}, indent=2) + '\n')
        receipt['architectures'].append({'architecture': architecture, 'cases': len(records),
                                        'image_sha256': identity, 'records_sha256': sha(output),
                                        'killed_cases': sum(row['exit_code'] < 0 for row in records),
                                        'synchronous_guard_cases': sum(row['synchronous_guard_observed'] for row in records)})
    assert sha(source) == receipt['source_sha256']
    receipt.update(state='finished', exit_code=0,
                   scope='Native descriptor policy and synchronous EXC_GUARD controls; x86-64 executes through Rosetta on this ARM64 host.')
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
