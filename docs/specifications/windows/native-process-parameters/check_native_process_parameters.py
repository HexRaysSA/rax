#!/usr/bin/env python3
"""Replay required native originals and independent process-parameter layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import re

if not __debug__:
    raise SystemExit("Replay requires Python assertions enabled")
HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--rax-root', type=Path, default=HERE.parents[3])
args = parser.parse_args()

def verify_manifest(name, key='name'):
    records = json.loads((HERE / name).read_text())
    assert records, name
    for record in records:
        data = (HERE / record[key]).read_bytes()
        assert len(data) == record['bytes'], record[key]
        assert hashlib.sha256(data).hexdigest().lower() == record['sha256'].lower(), record[key]
    return records

verify_manifest('sources.json', 'file')
verify_manifest('native-process-parameters-hashes.json')
verify_manifest('native-open-partition-trace-hashes.json')
verify_manifest('native-partition-descriptor-watch-hashes.json')
verify_manifest('windows-recovered-artifacts-hashes.json')
verify_manifest('final-evidence-hashes.json')
source_records = json.loads((HERE / 'source-hashes.json').read_text())
assert len(source_records) == 3, 'required implementation source set'
for record in source_records:
    data = (args.rax_root / record['file']).read_bytes()
    assert len(data) == record['bytes'], record['file']
    assert hashlib.sha256(data).hexdigest().lower() == record['sha256'].lower(), record['file']

header = (HERE / 'phnt-ntrtl.h').read_text()
source = (HERE / 'native-process-parameters-probe.cpp').read_text()
for tag in ['CURDIR', 'RTL_DRIVE_LETTER_CURDIR', 'RTL_USER_PROCESS_PARAMETERS']:
    start = header.index('typedef struct _' + tag + '\n')
    end = header.index(';', header.index('} ', start)) + 1
    declaration = header[start:end]
    for name in ['RTL_USER_PROCESS_PARAMETERS', 'RTL_DRIVE_LETTER_CURDIR', 'CURDIR']:
        declaration = declaration.replace(name, 'ABI_' + name)
    declaration = declaration.replace('    STRING DosPath;', '    ANSI_STRING DosPath;')
    assert declaration in source, tag

count = 0
for arch in ['arm64', 'x86', 'x86-laa', 'x64']:
    text = (HERE / f'native-process-parameters-probe-{arch}.log').read_text()
    match = re.search(r'parameter-layout width=(\d+) size=(\d+) redirection=(\d+) heap-partition=(\d+) cpu-masks=(\d+) cpu-count=(\d+) thread-maximum=(\d+) heap-memory-type=(\d+)', text)
    assert match, arch
    layout = tuple(map(int, match.groups()))
    expected = (8, 0x448, 0x410, 0x420, 0x430, 0x438, 0x43C, 0x440) if arch in ['arm64', 'x64'] else (4, 0x2C4, 0x2A4, 0x2AC, 0x2B4, 0x2B8, 0x2BC, 0x2C0)
    assert layout == expected, (arch, layout)
    raw = re.search(r'^parameters bytes=(\d+) hex=([0-9A-F]+)$', text, re.M)
    assert raw, arch
    data = bytes.fromhex(raw[2])
    assert len(data) == int(raw[1]) == layout[1], arch
    assert not any(data[layout[2]:]), (arch, 'nonzero default modern tail')
    maximum, length = (int.from_bytes(data[i:i+4], 'little') for i in [0, 4])
    assert maximum >= length >= layout[1], (arch, maximum, length)
    assert 'create width=' + str(layout[0]) + ' ok=1 error=0' in text, arch
    assert 'cleanup terminate=1 error=0 wait=00000000' in text, arch
    assert not re.search(r'^read .* ok=0 ', text, re.M), arch
    count += 1

before = (HERE / 'native-open-partition-trace-output.log').read_text()
assert 'partition name length=67 buffer=0x70005c00700070' in before
assert 'native NTDLL service NtOpenPartition (0x131)' in before
watch = (HERE / 'native-partition-descriptor-watch-output.log').read_text()
assert 'watch-change turn=12649 PC=0x1800d483c' in watch
assert 'watch-history turn=12647' in watch and 'offset: Imm(1056)' in watch
assert 'watch-history turn=12648' in watch and 'mnemonic: STR' in watch
assert 'bytes=[43, 00, 3a, 00, 5c, 00, 61, 00, 70, 00, 70, 00, 5c, 00, 70, 00' in watch
print(f'PASS: {count} native layouts/default tails; pinned declarations; original bad-descriptor/write trace')

post = (HERE / 'native-parameters-recovered-trace-output.log').read_text()
assert 'service=0x131 ' not in post and 'NtOpenPartition' not in post
assert 'terminal turn=13286 Complete(Internal("native NTDLL service NtQuerySystemInformationEx (0x16e)' in post
for turn in [11315, 11397, 11542]:
    assert f'kernel-after turn={turn} service=0x78 PC=0x1800017c4 X0=0x0' in post
ordinary = (HERE / 'native-parameters-recovered-ordinary-processes.log').read_text()
assert ordinary.count('exited with status 0xc0000005 (STATUS_ACCESS_VIOLATION)') == 4
artifacts = [json.loads(line) for line in (HERE / 'native-parameters-recovered-artifacts.jsonl').read_text().splitlines()]
core = [x for x in artifacts if x.get('reason') == 'compiler-artifact' and x['target']['name'] == 'rax' and '/capi/' not in x['manifest_path'].replace('\\', '/')]
assert len(core) == 1 and any(name.endswith('librax-e6c413934cad3a8f.rlib') for name in core[0]['filenames'])
assert any(x.get('reason') == 'build-finished' and x.get('success') is True for x in artifacts)
archive = (HERE / 'windows-rebuilt-archive-inspection.log').read_text()
assert archive.count('STRUCTURAL MEMBER WALK PASSED') == 2 and 'INVALID MEMBER' not in archive
for name, summary in [
    ('macos-parameters-final-full-macos.log', '7558 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out'),
    ('linux-native-parameters-final-full.log', '7551 passed; 1 failed; 2 ignored; 0 measured; 0 filtered out'),
    ('native-parameters-resumed-full.log', '6947 passed; 5 failed; 2 ignored; 0 measured; 0 filtered out'),
    ('macos-parameters-final-integration-macos.log', '544 passed; 0 failed'),
    ('linux-native-parameters-resumed-integration.log', '544 passed; 0 failed'),
    ('native-parameters-resumed-integration.log', '4 passed; 0 failed'),
]:
    assert summary in (HERE / name).read_text(), name
print('PASS: exact current source bytes; owning artifact identity; corrected continuation; explicit full-suite limits')
