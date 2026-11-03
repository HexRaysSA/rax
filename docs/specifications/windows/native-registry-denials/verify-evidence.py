#!/usr/bin/env python3
"""Check fixed-subject native receipts, including every partial output byte."""
from pathlib import Path
import hashlib
import json
import re
import struct

BASE = Path(__file__).resolve().parent
PARENT = (r'\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion'
          r'\Image File Execution Options')
NAMES = ['DefenderAgentScan.exe', 'cmd.exe',
         r'DefenderAgentScan.exe\rax-missing-child-20261103',
         r'cmd.exe\rax-missing-child-20261103', 'defenderagentscan.EXE\\',
         r'DefenderAgentScan.exe\\rax-missing-child-20261103']
LENGTHS = [0, 15, 16, 55, 56, 57, 63, 64, 65, 128, 4096]
OPEN = re.compile(r'open route=(\d+) row=(\d+) access=([0-9A-F]{8}) '
                  r'status=([0-9A-F]{8}) handle=(\d+) query=([0-9A-F]{8}) '
                  r'returned=(\d+) granted=([0-9A-F]{8}) path=(.*)')
ENUM = re.compile(r'enum class=(\d+) length=(\d+) poison=([0-9A-F]{2}) '
                  r'status=([0-9A-F]{8}) returned=(\d+) bytes=([0-9A-F]*)')


def verify(receipt, source, masks, schema):
    assert receipt['schema'] == schema
    assert receipt['exit_code'] == 0 and receipt['stderr'] == ''
    assert receipt['native_validation_jobs_restarted'] is False
    assert receipt['new_subject_control'] is True
    assert receipt['source_sha256'] == hashlib.sha256(source).hexdigest()
    stdout = receipt['stdout']
    assert receipt['stdout_sha256'] == hashlib.sha256(stdout.encode()).hexdigest()
    assert receipt['ntdll_sha256'] == 'e9943254a04813ede84d84b1be5fb4f41537d103d2771449db56a80cf6f301fd'
    assert int(receipt['pid']) > 0 and int(receipt['creation']) > 0
    lines = stdout.splitlines()
    assert lines[0] == 'parent status=00000000 opened=1'
    opens, enumerations, child = {}, {}, None
    for line in lines[1:-1]:
        if match := OPEN.fullmatch(line):
            route, row, access, status, handle, query, returned, grant, path = match.groups()
            route, row, access = int(route), int(row), int(access, 16)
            assert route in (0, 1) and row in range(6) and access in masks
            assert path == (PARENT + '\\' if route == 0 else '') + NAMES[row]
            assert status == ('C0000022' if row in (0, 4) else 'C0000034')
            assert (handle, query, returned, grant) == ('0', 'FFFFFFFF', '0', '00000000')
            key = route, row, access
            assert key not in opens
            opens[key] = True
        elif match := ENUM.fullmatch(line):
            information, length, poison, status, returned, raw = match.groups()
            information, length, poison, returned = (int(information), int(length),
                                                     int(poison, 16), int(returned))
            assert information in range(3) and length in LENGTHS and poison in (0xA5, 0x5A)
            key = information, length, poison
            assert key not in enumerations
            enumerations[key] = status, returned, bytes.fromhex(raw)
        else:
            match = re.fullmatch(r'child index=(\d+) name=DefenderAgentScan.exe last_write=([0-9A-F]{16})', line)
            assert match and child is None, line
            child = int(match[1]), int(match[2], 16)
    assert len(opens) == 2 * 6 * len(masks)
    assert len(enumerations) == 3 * len(LENGTHS) * 2
    assert child is not None
    last_write = child[1]
    name = NAMES[0].encode('utf-16le')
    payloads = [struct.pack('<QII', last_write, 0, len(name)) + name,
                struct.pack('<QIIII', last_write, 0, 0xFFFFFFFF, 0, len(name)) + name,
                struct.pack('<Q9I', last_write, 0, 0xFFFFFFFF, 0, 0, 0, 0, 1, 34, 8)]
    headers = [16, 24, 44]
    for (information, length, poison), (status, returned, actual) in enumerations.items():
        payload, header = payloads[information], headers[information]
        assert returned == len(payload)
        expected = bytearray([poison] * length)
        if length < header:
            expected_status = 'C0000023'
        else:
            copied = min(length, len(payload))
            expected[:copied] = payload[:copied]
            if copied < len(payload) and (copied - header) % 2:
                expected[copied - 1] = 0
            expected_status = '00000000' if length >= len(payload) else '80000005'
        assert status == expected_status and actual == expected, (information, length, poison)
    assert lines[-1] == (f'finished open_calls={1 + len(opens)} enum_calls=66 opened=1 closed=1')
    return len(opens), len(enumerations)


def main():
    cases = [
        ('native-open-enumeration-arm64-v1.json', 'native-ifeo-denials-v1.cpp',
         [0, 1, 8, 9, 0x20000, 0x20019, 0x02000000], 'assist-native-registry-denials-v45'),
        ('native-security-masks-arm64-v2.json', 'native-ifeo-denials-security-v2.cpp',
         [0x01000000, 0x01000001, 0x01000008, 0x01000009, 0x01020000, 0x01020019,
          0x03000000, 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0xFFFFFFFF,
          0x04000000], 'assist-native-registry-denials-v46'),
    ]
    for receipt, source, masks, schema in cases:
        actual = verify(json.loads((BASE / receipt).read_text()),
                        (BASE / source).read_bytes(), masks, schema)
        print(f'{receipt}: {actual[0]} opens, {actual[1]} enumeration cases verified')
    manifest_bytes = (BASE / 'native-rust-build-source-v1.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    receipt = json.loads((BASE / 'native-rust-arm64-v1.json').read_text())
    assert receipt['schema'] == 'rax-registry-denials-tests-v1'
    assert receipt['original_native_jobs_restarted'] is False
    assert 'error' not in receipt and 'prior_receipt' not in receipt
    assert receipt['source_manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
    assert receipt['image_sha256'] == manifest['artifact']['sha256']
    assert receipt['subject'] == json.loads((BASE / cases[0][0]).read_text())['subject']
    assert receipt['ntdll_sha256'] == json.loads((BASE / cases[0][0]).read_text())['ntdll_sha256']
    root = BASE.parents[3]
    for path, expected in manifest['owned_sources'].items():
        assert path.startswith('src/') and '..' not in Path(path).parts
        assert hashlib.sha256((root / path).read_bytes()).hexdigest() == expected, path
    groups = [('registry::installed::ifeo::tests', 4),
              ('registry::captured_tree::tests', 3), ('registry_tests::denials', 2)]
    assert len(receipt['tests']) == len(groups)
    for result, (name, count) in zip(receipt['tests'], groups):
        assert result['arguments'] == name + ' --test-threads=1 --nocapture'
        assert result['exit_code'] == 0 and result['stderr'].strip() == ''
        assert int(result['pid']) > 0 and int(result['creation']) > 0
        assert f'test result: ok. {count} passed; 0 failed; 0 ignored;' in result['stdout']
        assert len(re.findall(r'^test .* \.\.\. ok$', result['stdout'], re.M)) == count
    print('Native Rust: 4 capture-adapter, 3 snapshot and 2 entered-service tests verified')


if __name__ == '__main__':
    main()
