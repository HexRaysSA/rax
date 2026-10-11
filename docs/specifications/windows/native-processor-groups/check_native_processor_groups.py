#!/usr/bin/env python3
"""Replay original processor-group observations and recorded validation."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

if not __debug__:
    raise SystemExit('Python optimization disables replay assertions; use normal Python')

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fields(line):
    parts = [part.split('=', 1) for part in line.split()]
    require(all(len(pair) == 2 for pair in parts), f'malformed observation: {line}')
    keys = [pair[0] for pair in parts]
    require(len(keys) == len(set(keys)), 'duplicate native field key')
    return dict(parts)


def record(width, processors=8):
    size = 72 + width
    data = bytearray(size)
    data[:4] = (4).to_bytes(4, 'little')
    data[4:8] = size.to_bytes(4, 'little')
    data[8:12] = bytes([1, 0, 1, 0])
    data[32:34] = bytes([processors, processors])
    data[72:] = ((1 << processors) - 1).to_bytes(width, 'little')
    return bytes(data)


def native_profile(arch):
    width = 4 if arch.startswith('x86') else 8
    text = (HERE / f'native-topology-probe-{arch}.log').read_text()
    lines = text.splitlines()
    require(lines[-1] == 'complete cases=371', f'{arch}: incomplete oracle')
    profile = fields(next(line for line in lines if line.startswith('profile '))[8:])
    require(profile == {'width': str(width), 'page': '4096', 'processor-count': '8', 'processor-mask': 'FF'}, f'{arch}: different native profile')
    layout = fields(next(line for line in lines if line.startswith('layout '))[7:])
    require(layout == {'sdk-size': str(72 + width), 'group-size': str(64 + width), 'group-info-size': str(40 + width), 'group-offset': '8', 'info-offset': '24', 'mask-offset': '40'}, f'{arch}: SDK layout differs')
    rows = [fields(line) for line in lines if line.startswith('case=')]
    require(len(rows) == 371 and [int(row['case']) for row in rows] == list(range(371)), f'{arch}: ordinal coverage')
    require(all(row['exception'] == '00000000' for row in rows), f'{arch}: external SEH exception')
    for row in rows:
        require(int(row['width']) == width, f'{arch}: caller width')
        data = bytes.fromhex(row['output'])
        require(len(data) == int(row['output-captured-bytes']), f'{arch}: snapshot extent')
        # returned-read alone does not mean all four bytes were readable.
        require(0 <= int(row['returned-captured-bytes']) <= 4, f'{arch}: returned snapshot extent')
    group = next(row for row in rows if row['label'] == 'relationship' and row['relationship'] == '4')
    native = record(width)
    require(group['status'] == '00000000' and bytes.fromhex(group['output']) == native + b'\xA5' * (96 - len(native)), f'{arch}: native group fields/suffix')
    require(group['returned'] == f'{len(native):08X}' and group['returned-captured-bytes'] == '4', f'{arch}: native returned length')
    for row in rows:
        label = row['label']
        if label == 'input-extra-span':
            expected = 'C000000D' if int(row['input-bytes']) < 4 else '00000000'
            require(row['status'] == expected, f'{arch}: unused input span')
        if label in ['output-field-boundary', 'output-field-readonly']:
            prefix = int(row['offset'])
            expected = bytearray(b'\xA5' * prefix)
            if width == 4:
                status = '00000000' if prefix >= 76 else 'C0000005'
                if prefix >= 76:
                    expected[:76] = native
                else:
                    if prefix >= 12: expected[8:12] = bytes([1, 0, 1, 0])
                    if prefix >= 28: expected[12:28] = bytes(16)
                    if prefix >= 32: expected[28:32] = bytes(4)
                    if prefix >= 33: expected[32] = 8
                    if prefix >= 34: expected[33] = 8
            else:
                status = '80000002' if prefix % 4 else 'C0000005'
            require(row['status'] == status, f'{arch}: boundary status at {prefix}')
            require(bytes.fromhex(row['output'])[:prefix] == expected, f'{arch}: partial fields at {prefix}')
        if label == 'returned-cross-page':
            prefix = int(row['offset'])
            require(row['status'] == ('00000000' if prefix == 4 else 'C0000005'), f'{arch}: crossing length store')
            expected = native if width == 4 or prefix == 4 else b'\xA5' * len(native)
            require(bytes.fromhex(row['output'])[:len(native)] == expected, f'{arch}: output/returned fault order')
    guards = [fields(line[12:]) for line in lines if line.startswith('range-guard ')]
    require(len(guards) == (0 if width == 4 else 3), f'{arch}: upper guard coverage')
    for role, row in enumerate(guards):
        require(row == {'role': str(role), 'width': '8', 'status': '80000001' if role == 2 else 'C0000005', 'exception': '00000000', 'guard': '0' if role == 2 else '256'}, f'{arch}: upper guard ordering')
    return len(rows) + len(guards)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rax-root', type=Path, default=HERE.parents[3])
    args = parser.parse_args()
    manifest = json.loads((HERE / 'evidence-hashes.json').read_text())
    names = set()
    for item in manifest:
        name = item['name']
        require(name not in names and Path(name).name == name, 'nonlocal/duplicate manifest input')
        names.add(name)
        data = (HERE / name).read_bytes()
        require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'].lower(), f'original differs: {name}')
    for item in json.loads((HERE / 'source-hashes-reviewed.json').read_text()):
        data = (args.rax_root / item['path']).read_bytes()
        require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'].lower(), f'source differs: {item["path"]}')
    ref = args.rax_root / 'docs/specifications/windows/native-processor-features'
    for name, sha in [('phnt-ntexapi.h', '0510ac40fa1690cd73bed8afe3ed602aaa7bb6870ab95ea9aaba36ce1f4c3d53'), ('phnt-LICENSE', 'ad2ab542c56c606e4c19d66a7f3cdcd3ef83beffb638e7c3893b22c7a6a6c0df')]:
        require(hashlib.sha256((ref / name).read_bytes()).hexdigest() == sha, f'pinned primary reference differs: {name}')
    header = (ref / 'phnt-ntexapi.h').read_text()
    require('SystemLogicalProcessorAndGroupInformation,' in header and re.search(r'NtQuerySystemInformationEx\([^;]+PULONG ReturnLength\s*\);', header), 'primary query definition missing')
    enum = header.split('typedef enum _SYSTEM_INFORMATION_CLASS', 1)[1].split('} SYSTEM_INFORMATION_CLASS;', 1)[0]
    enum = re.sub(r'/\*.*?\*/|//[^\n]*', '', enum, flags=re.S)
    value = -1
    identities = {}
    for line in enum.splitlines():
        match = re.match(r'\s*(System\w+)\s*(?:=\s*(\d+))?\s*,?', line)
        if match:
            value = int(match[2]) if match[2] else value + 1
            identities[match[1]] = value
    require(identities['SystemLogicalProcessorAndGroupInformation'] == 107, 'primary class identity differs')
    require(sum(native_profile(arch) for arch in ['arm64', 'x86', 'x64', 'x86-laa']) == 1490, 'native observation count')
    baseline = (HERE / 'macos-group-baseline.log').read_text()
    require('NtQuerySystemInformationEx (0x16e)' in baseline and 'is not implemented' in baseline and '0 passed; 1 failed' in baseline, 'behavioral baseline differs')
    before = (HERE / 'native-topology-before-trace-output.log').read_text()
    require('raw=Ok([04, 00, 00, 00])' in before and '13286' in before, 'owning relationship capture differs')
    require((HERE / 'native-topology-before-trace.rs').read_bytes() == (HERE / 'native-topology-after-trace.rs').read_bytes(), 'continuation source changed')
    after = (HERE / 'native-topology-after-trace-output.log').read_text()
    require('kernel-after turn=13286 service=0x16e PC=0x180002724 X0=0x0' in after, 'owning group query did not succeed')
    require('terminal turn=33364' in after and 'NtQuerySystemInformation class 197' in after, 'owning next frontier differs')
    ordinary = (HERE / 'native-topology-after-ordinary-processes.log').read_text()
    require(ordinary.count('STATUS_ACCESS_VIOLATION') == 4 and ordinary.count('opened modules=') == 4, 'ordinary startup limit differs')
    artifacts = [json.loads(line) for line in (HERE / 'native-topology-after-artifacts.jsonl').read_text().splitlines()]
    core = [item for item in artifacts if item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'rax' and not item['manifest_path'].replace('\\', '/').endswith('/capi/Cargo.toml')]
    require(len(core) == 1 and core[0]['features'] == [], 'owning core artifact/features differ')
    require(any(name.endswith('librax-e6c413934cad3a8f.rlib') for name in core[0]['filenames']), 'owning linked artifact identity differs')
    archive = (HERE / 'native-reviewed-archive-inspection.log').read_text()
    require(archive.count('STRUCTURAL MEMBER WALK PASSED') == 2 and '4673' in archive and '260' in archive and 'INVALID' not in archive and 'OUTSIDE' not in archive, 'owning archive structure differs')
    validation = json.loads((HERE / 'validation.json').read_text())
    for gate in validation['gates']:
        log = (HERE / gate['log']).read_text()
        require(gate['required'] in log, f'gate evidence absent: {gate["log"]}')
    print(f'Processor groups: {len(manifest)} original inputs, 5 source hashes, 1490 native observations and recorded gates verified')


if __name__ == '__main__':
    main()
