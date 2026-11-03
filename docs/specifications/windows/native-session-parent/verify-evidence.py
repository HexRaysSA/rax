from pathlib import Path
import hashlib
import json
import re

BASE = Path(__file__).resolve().parent
DLL = 'e9943254a04813ede84d84b1be5fb4f41537d103d2771449db56a80cf6f301fd'


def provenance(receipt, source, build, schema):
    assert receipt['schema'] == schema and receipt['exit_code'] == 0
    assert receipt['stderr'] == '' and 'error' not in receipt
    assert receipt['native_validation_jobs_restarted'] is False
    assert receipt['new_subject_control'] is True
    assert receipt['source_sha256'] == hashlib.sha256(source).hexdigest() == build['source_sha256']
    assert receipt['image_sha256'] == build['image_sha256']
    assert receipt['stdout_sha256'] == hashlib.sha256(receipt['stdout'].encode()).hexdigest()
    assert receipt['ntdll_sha256'] == DLL
    assert int(receipt['pid']) > 0 and int(receipt['creation']) > 0


def fields(line):
    return dict(part.split('=', 1) for part in line.split()[1:])


def number(row, key, base=16):
    return int(row[key], base)


def directories(receipt):
    lines = receipt['stdout'].splitlines()
    assert lines[0] == 'session=1 paths=10 masks=8'
    paths = ['\\', '\\KnownDlls', '\\KnownDlls32', '\\KnownDllsChpe32', '\\Windows',
             '\\BaseNamedObjects', '\\Sessions', '\\Sessions\\1',
             '\\Sessions\\1\\BaseNamedObjects', '\\Sessions\\1\\Windows']
    ceilings = [0x20003] * 10
    ceilings[5], ceilings[7], ceilings[8] = 0x2000F, 2, 0xF000F
    masks = [0, 1, 2, 3, 0x20000, 0x02000000, 0x01000000, 0x03000000]
    opened, basic, enumerated = {}, {}, {}
    for line in lines[1:-1]:
        row = fields(line)
        path, access = number(row, 'path', 10), number(row, 'access')
        assert path in range(10) and access in masks
        key = path, access
        success = access != 0 and access not in (0x01000000, 0x03000000) and (
            access == 0x02000000 or access & ~ceilings[path] == 0)
        if line.startswith('open '):
            expected = 0 if success else (0xC0000061 if access & 0x01000000 else 0xC0000022)
            assert row['name'] == paths[path]
            assert number(row, 'status') == expected
            assert number(row, 'handle', 10) == int(success)
            assert key not in opened
            opened[key] = success
        elif line.startswith('basic '):
            assert success and key not in basic
            assert number(row, 'status') == 0 and number(row, 'returned', 10) == 56
            assert number(row, 'granted') == (ceilings[path] if access == 0x02000000 else access)
            basic[key] = number(row, 'granted')
        else:
            assert line.startswith('enum ') and success and key in basic
            poison = number(row, 'poison')
            assert poison in (0xA5, 0x5A) and (*key, poison) not in enumerated
            assert number(row, 'guard', 10) == 1
            if basic[key] & 1:
                assert number(row, 'status') == 0
                assert 32 <= number(row, 'returned', 10) <= 131072
                assert number(row, 'context', 10) == 1
                assert number(row, 'name_units', 10) > 0 and number(row, 'kind_units', 10) > 0
            else:
                assert number(row, 'status') == 0xC0000022
                assert number(row, 'returned', 10) == 0xFEE1DEAD
                assert number(row, 'context', 10) == 0
                assert number(row, 'name_units', 10) == number(row, 'kind_units', 10) == 0
            enumerated[*key, poison] = True
    assert len(opened) == 80 and sum(opened.values()) == len(basic) == 47
    assert len(enumerated) == 94
    assert lines[-1] == 'finished opened=47 closed=47 enum_calls=94'


def children(receipt):
    lines = receipt['stdout'].splitlines()
    assert lines[0] == 'parent session=1 name=\\Sessions\\1'
    opens, metadata, identities = {}, {}, {}
    for line in lines[1:-1]:
        row = fields(line)
        kind, child = number(row, 'kind', 10), number(row, 'row', 10)
        flags, access = number(row, 'flags'), number(row, 'access')
        assert kind in (0, 1) and child in range(5)
        assert flags in (0, 0x40, 0x100, 0x140) and access in (0, 1, 0x02000000)
        key = kind, child, flags, access
        if child == 4:
            status = 0xC0000034
        elif kind == 1:
            status = 0xC0000024
        elif flags & 0x100:
            status = 0xC000000D
        elif access == 0:
            status = 0xC0000022
        else:
            status = 0
        if line.startswith('open '):
            assert key not in opens
            assert number(row, 'status') == status and number(row, 'handle', 10) == int(status == 0)
            opens[key] = status
        elif line.startswith('metadata '):
            assert status == 0 and key not in metadata
            assert number(row, 'basic') == 0 and number(row, 'returned', 10) == 56
            ceiling = 0xF000F if child in (0, 1) else 0x20003
            assert number(row, 'granted') == (ceiling if access == 0x02000000 else access)
            assert row['type'] == 'Directory'
            assert row['name'] == ('\\Sessions\\1\\BaseNamedObjects' if child in (0, 1)
                                   else '\\Sessions\\1\\Windows')
            metadata[key] = True
        else:
            assert line.startswith('identity ') and status == 0 and key not in identities
            assert number(row, 'open') == number(row, 'compare') == 0
            identities[key] = True
    assert len(opens) == 120 and len(metadata) == len(identities) == 16
    assert set(metadata) == set(identities) == {key for key, status in opens.items() if status == 0}
    assert lines[-1] == 'finished cases=120 comparisons=16 opened=33 closed=33'


def main():
    specs = [('native-receipt-v1.json', 'native-directory-access-v1.cpp', 'native-build-v1.json',
              'assist-native-namespace-access-v1', directories),
             ('native-receipt-v2.json', 'native-session-children-v2.cpp', 'native-child-build-v2.json',
              'assist-native-session-children-v2', children)]
    receipts = []
    for receipt, source, build, schema, verify in specs:
        data = json.loads((BASE / receipt).read_text())
        provenance(data, (BASE / source).read_bytes(), json.loads((BASE / build).read_text()), schema)
        verify(data)
        receipts.append(data)
    assert receipts[0]['subject'] == receipts[1]['subject']
    manifest_bytes = (BASE / 'native-rust-source-v1.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    runtime = json.loads((BASE / 'native-rust-arm64-v1.json').read_text())
    assert runtime['schema'] == 'rax-namespace-tests-v1'
    assert 'error' not in runtime and 'prior_receipt' not in runtime
    assert runtime['original_native_jobs_restarted'] is False
    assert runtime['subject'] == receipts[0]['subject']
    assert runtime['ntdll_sha256'] == DLL
    assert runtime['source_manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
    assert runtime['image_sha256'] == manifest['artifact']['sha256']
    root = BASE.parents[3]
    for path, expected in manifest['owned_sources'].items():
        if path.startswith('src/'):
            assert '..' not in Path(path).parts
            assert hashlib.sha256((root / path).read_bytes()).hexdigest() == expected, path
    groups = [('object_namespace::installed::session_parent::tests', 3),
              ('object_namespace::traverse_only_tests::', 2),
              ('directory_open_tests::partial_session::', 1)]
    assert len(runtime['tests']) == len(groups)
    for result, (name, count) in zip(runtime['tests'], groups):
        assert result['arguments'] == name + ' --test-threads=1 --nocapture'
        assert result['exit_code'] == 0 and result['stderr'].strip() == ''
        assert int(result['pid']) > 0 and int(result['creation']) > 0
        assert f'{count} passed; 0 failed; 0 ignored;' in result['stdout']
        assert len(re.findall(r'^test .* \.\.\. ok$', result['stdout'], re.M)) == count
    startup_manifest_bytes = (BASE / 'native-startup-source-v1.json').read_bytes()
    startup_manifest = json.loads(startup_manifest_bytes)
    startup = json.loads((BASE / 'native-startup-arm64-v1.json').read_text())
    assert startup['schema'] == 'rax-namespace-startup-v1'
    assert 'error' not in startup and 'prior_receipt' not in startup
    assert startup['original_native_jobs_restarted'] is False
    assert startup['subject'] == receipts[0]['subject']
    assert startup['ntdll_sha256'] == DLL
    assert startup['source_manifest_sha256'] == hashlib.sha256(startup_manifest_bytes).hexdigest()
    assert startup['image_sha256'] == startup_manifest['artifact']['sha256']
    assert startup_manifest['source_frame_sha256'] == manifest['source_frame_sha256']
    assert {p: h for p, h in startup_manifest['owned_sources'].items() if p.startswith('src/')} == \
        {p: h for p, h in manifest['owned_sources'].items() if p.startswith('src/')}
    assert hashlib.sha256((BASE / 'startup-control.rs').read_bytes()).hexdigest() == \
        startup_manifest['artifact']['source_sha256']
    assert len(startup['tests']) == 1
    attempt = startup['tests'][0]
    assert int(attempt['pid']) > 0 and int(attempt['creation']) > 0
    assert attempt['exit_code'] == 0 and attempt['stderr'].strip() == ''
    assert attempt['arguments'] == r'C:\WINDOWS\System32\cmd.exe 268435456 0'
    output = attempt['stdout']
    assert output.startswith('configuration file_backed_spawn=true arena_bytes=268435456 seed=0 ')
    for module in ['cmd.exe', 'ntdll.dll', 'kernel32.dll', 'KernelBase.dll', 'ucrtbase.dll']:
        assert len(re.findall(r'^module name=' + re.escape(module) + r' base=', output, re.M)) == 1
    terminal = re.findall(r'^TERMINAL .*$', output, re.M)
    assert len(terminal) == 1
    terminal = terminal[0]
    assert 'sample=33504 instruction_budget_bound=2144320 active_exception_seen=false ' in terminal
    assert (33504 + 1) * 64 == 2144320
    assert 'status=Complete(Internal(' in terminal
    assert 'NtSecureConnectPort requires a matched selected guest server and owned shared views' in terminal
    assert 'DIAGNOSTIC_INSTRUCTION_LIMIT' not in output
    print('Verified 80 directory opens/94 enumerations and 120 child opens/16 identity pairs; zero-right existing-directory opens deny in both controls.')
    print('Verified 6 native Rust tests: 3 capture-adapter, 2 model, 1 entered-service.')
    print('Verified installed CMD construction and guest entry; terminal NtSecureConnectPort Internal error, not CMD success.')


if __name__ == '__main__':
    main()
