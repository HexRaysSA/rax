from pathlib import Path
import hashlib
import json
import re

BASE = Path(__file__).resolve().parent
DLL = 'e9943254a04813ede84d84b1be5fb4f41537d103d2771449db56a80cf6f301fd'


def load(name):
    return json.loads((BASE / name).read_text())


def fields(line):
    return dict(item.split('=', 1) for item in line.split()[1:])


def rows(text, prefix, key):
    result = {}
    for line in text.splitlines():
        if line.startswith(prefix):
            row = fields(line)
            assert row[key] not in result
            result[row[key]] = row
    return result


def word(data, at):
    return int.from_bytes(data[at:at + 8], 'little')


def provenance(name, source, build, schema):
    receipt, compiled = load(name), load(build)
    assert receipt['schema'] == schema and receipt['exit_code'] == 0
    assert receipt['stderr'] == '' and 'error' not in receipt and 'prior_receipt' not in receipt
    assert receipt['native_validation_jobs_restarted'] is False
    assert receipt['new_subject_control'] is True
    assert int(receipt['pid']) > 0 and int(receipt['creation']) > 0
    assert receipt['source_sha256'] == compiled['source_sha256']
    assert receipt['source_sha256'] == hashlib.sha256((BASE / source).read_bytes()).hexdigest()
    assert receipt['image_sha256'] == compiled['image_sha256']
    assert receipt['stdout_sha256'] == hashlib.sha256(receipt['stdout'].encode()).hexdigest()
    assert receipt['ntdll_sha256'] == DLL
    return receipt


def main():
    profile = load('profile-v1.json')
    assert profile['schema'] == 'rax-native-arm64-current-session-csr-v1'
    meta = provenance('native-receipt-v1.json', 'native-session-csr-v1.cpp',
                      'native-build-v1.json', 'assist-native-session-csr-v1')
    first = provenance('native-first-receipt-v1.json', 'native-first-csr-session-v1.cpp',
                       'native-first-build-v1.json', 'assist-native-first-session-csr-v1')
    wow = provenance('native-wow64-receipt-v2.json', 'native-wow64-first-session-v1.cpp',
                     'native-wow64-build-v1.json', 'assist-native-wow64-session-csr-v1')
    assert meta['subject'] == first['subject'] == wow['subject'] == profile['subject']
    assert profile['ntdll_sha256'] == DLL
    observed = fields(meta['stdout'].splitlines()[0])
    assert int(observed['pointer_bytes']) == 8
    assert int(observed['session']) == int(observed['peb_session']) == profile['session'] == 1
    assert [int(x) for x in observed['kernel'].split('.')] == profile['kernel'] == [10, 0, 29698]
    assert int(observed['server'], 16) == profile['server_base']
    assert int(observed['offset'], 16) == profile['statics_offset'] == 0x750
    assert int(observed['csr_pid']) == profile['server_pid']
    assert int(observed['statics'], 16) - int(observed['local'], 16) == 0x750
    output = rows(meta['stdout'], 'bytes ', 'name')
    prefix = bytes.fromhex(output['peb-shared-prefix']['hex'])
    assert prefix.hex().upper() == profile['selected_prefix_hex'] and len(prefix) == 128
    assert word(prefix, 40) == word(prefix, 48) == profile['server_base']
    assert 'selected-section prefix_equal=1 server_words_equal=1' in meta['stdout']
    for name in ['peb-shared', 'selected-shared']:
        regions = [fields(line) for line in meta['stdout'].splitlines()
                   if line.startswith('region name=' + name + ' ')]
        assert [(int(r['offset']), int(r['size']), int(r['state'], 16),
                 int(r['protection'], 16), int(r['type'], 16)) for r in regions] == [
                     (0, 20480, 0x1000, 2, 0x40000), (20480, 1028096, 0x2000, 0, 0x40000)]
    assert profile['initialized_repeat_status'] == 0xC0000041
    assert 'connect status=C0000041 handle=0 maximum_message=0 information_bytes=48' in meta['stdout']
    for name in ['client', 'remote', 'information']:
        assert output[name + '-before']['hex'] == output[name + '-after']['hex']
    counts = [fields(line) for line in meta['stdout'].splitlines() if line.startswith('owned-handles ')]
    assert len(counts) == 1 and counts[0]['before'] == counts[0]['after']
    assert 'user-client status=00000000 inside=0 csr_pid=' + str(profile['server_pid']) in meta['stdout']
    user = bytes.fromhex(output['user-information']['hex'])
    assert len(user) == 584 and word(user, 24) == 32
    extents = rows(meta['stdout'], 'extent ', 'name')
    assert int(extents['user-handles']['base'], 16) == word(user, 16)
    assert int(extents['user-shared']['base'], 16) == word(user, 40)
    assert int(extents['user-handles']['size']) == 1 << 21
    assert int(extents['user-shared']['size']) == 32768
    assert word(user, 8) == word(user, 40) + 0x1040
    for name in ['user-handles', 'user-shared']:
        regions = [fields(line) for line in meta['stdout'].splitlines()
                   if line.startswith('region name=' + name + ' ')]
        assert len(regions) == (2 if name == 'user-handles' else 1)
        assert int(regions[0]['state'], 16) == 0x1000 and int(regions[0]['protection'], 16) == 2
        assert all(int(row['type'], 16) == 0x40000 for row in regions)
        assert int(regions[0]['offset']) == 0 and int(regions[0]['size']) == 32768
        if name == 'user-handles':
            assert int(regions[1]['state'], 16) == 0x2000
            assert int(regions[1]['offset']) == 32768
            assert int(regions[1]['size']) == (1 << 21) - 32768
            assert int(regions[1]['protection'], 16) == 0
    for at in [8, 16, 32, 40, 56, 88, 104, 168, 184, 200, 216, 232, 248, 280, 296, 312, 552, 568]:
        pointer = word(user, at)
        assert pointer == 0 or any(word(user, base) <= pointer < word(user, base) + 32768
                                   for base in [16, 40])

    capture = rows(first['stdout'], 'dump ', 'name')
    for row in capture.values():
        assert row['ok'] == '1' and row['error'] == '0'
        assert int(row['requested']) == int(row['got']) == len(bytes.fromhex(row['hex']))
    for key, label in [
        ('qos_hex', 'security-qos'), ('sid_hex', 'required-server-sid'),
        ('client_before_hex', 'client-view-before'), ('client_after_hex', 'client-view-after'),
        ('remote_before_hex', 'server-view-before'), ('remote_after_hex', 'server-view-after'),
        ('information_before_hex', 'connection-before'), ('information_after_hex', 'connection-after'),
    ]:
        assert profile[key] == capture[label]['hex']
    port = bytes.fromhex(capture['port-name-utf16']['hex'])
    assert port.decode('utf-16le') == profile['port'] == r'\Sessions\1\Windows\ApiPort'
    header = bytes.fromhex(capture['port-name-header']['hex'])
    assert len(header) == 16 and int.from_bytes(header[:2], 'little') == len(port)
    assert int.from_bytes(header[2:4], 'little') >= len(port)
    assert profile['qos_hex'] == '000000000200000001010000'
    assert profile['sid_hex'] == '010100000000000512000000'
    before, after = (bytes.fromhex(profile[key]) for key in ['client_before_hex', 'client_after_hex'])
    assert len(before) == len(after) == 48 and before[:32] == after[:32]
    assert word(before, 24) == 65536 and before[32:] == bytes(16)
    assert word(after, 32) != word(after, 40)
    assert all(word(after, at) != 0 and word(after, at) % 65536 == 0 for at in [32, 40])
    before, after = (bytes.fromhex(profile[key]) for key in
                      ['information_before_hex', 'information_after_hex'])
    assert len(before) == len(after) == 48 and before[:32] == bytes(32)
    assert word(before, 32) == 1 and after[24:] == before[24:]
    assert [word(after, at) for at in [0, 8, 16, 24]] == [
        profile['server_base'], profile['server_base'] + 0x750, profile['server_pid'], 0]
    assert profile['remote_after_hex'] == '00' * 24
    assert int.from_bytes(bytes.fromhex(capture['max-message-after']['hex']), 'little') == \
        profile['maximum_message'] == 952
    assert int.from_bytes(bytes.fromhex(capture['connection-length-after']['hex']), 'little') == \
        profile['information_bytes'] == 48
    assert profile['native_first_status'] == 0 and profile['native_child_exit'] == 41
    assert 'return ordinal=0 status=00000000' in first['stdout']
    assert first['stdout'].splitlines()[-1] == 'complete captured=1 calls=1 exit=41'
    assert sum(line.startswith('entry ') for line in first['stdout'].splitlines()) == 1

    build, projected = load('native-wow64-build-v1.json'), profile['wow64']
    assert wow['child_image_sha256'] == build['child']['sha256']
    assert build['child']['source_sha256'] == hashlib.sha256(
        (BASE / 'native-wow64-child-v1.cpp').read_bytes()).hexdigest()
    assert build['child']['machine'] == 0x14C and build['parent']['machine'] == 0xAA64
    assert wow['wow64_ntdll_sha256'] == projected['ntdll32_sha256']
    text = wow['stdout']
    assert 'CREATE status=00000000 state=6 chpe=0' in text
    assert 'SESSION native=1 wow=1 process=1' in text
    root = next(fields(line) for line in text.splitlines() if line.startswith('ROOT '))
    assert bytes.fromhex(root['hex']).decode('utf-16le') == projected['directory'] == r'\Sessions\1\Windows'
    assert int(root['units']) == 19
    data = rows(text, 'DATA ', 'label')
    for key, label in [('buffer_before_hex', 'before-buffer'), ('buffer_after_hex', 'after-buffer'),
                       ('inside_before_hex', 'before-inside'), ('inside_after_hex', 'after-inside')]:
        assert data[label]['ok'] == '1' and projected[key] == data[label]['hex']
    assert projected['buffer_before_hex'] == projected['buffer_after_hex']
    assert projected['inside_after_hex'] == '00' and projected['status'] == 0
    assert 'server=1 ' in text and 'bytes=8 ' in text
    assert 'RETURN ordinal=0 status=00000000' in text and 'HANDLE_DELTA added=1 removed=0' in text
    assert 'access=001F0001' in text and 'type=ALPC Port' in text
    assert 'machine=014C ret-bytes=20' in text
    entry_sp = int(re.search(r'^ENTRY .*sp=([0-9A-F]+)', text, re.M)[1], 16)
    return_sp = int(re.search(r'^RETURN .*sp=([0-9A-F]+)', text, re.M)[1], 16)
    assert return_sp - entry_sp == 4 + projected['ret_bytes'] == 24
    assert projected['native_handle_delta'] == 1
    assert projected['controller_stopped_child_after_return'] == 70
    assert text.splitlines()[-1] == 'DONE installed=1 entered=1 returned=1 base-calls=1 pending=0 exit=70'
    manifest_bytes = (BASE / 'native-rust-source-v1.json').read_bytes()
    manifest, runtime = json.loads(manifest_bytes), load('native-rust-arm64-v1.json')
    assert runtime['schema'] == 'rax-csr-session-tests-v2' and 'error' not in runtime
    assert runtime['subject'] == profile['subject'] and runtime['ntdll_sha256'] == DLL
    assert runtime['original_native_jobs_restarted'] is False
    assert runtime['source_manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
    assert runtime['image_sha256'] == manifest['artifact']['sha256']
    root = BASE.parents[3]
    for path, expected in manifest['owned_sources'].items():
        if path.startswith('src/') or path.endswith('/native-arm64-session-csr/profile-v1.json'):
            assert '..' not in Path(path).parts
            assert hashlib.sha256((root / path).read_bytes()).hexdigest() == expected, path
    assert len(runtime['tests']) == 6
    for index, (result, count) in enumerate(zip(runtime['tests'], [3, 2, 2, 1, 1, 43])):
        assert result['exit_code'] == 0
        assert int(result['pid']) > 0 and int(result['creation']) > 0
        assert f'{count} passed; 0 failed; 0 ignored;' in result['stdout']
        assert len(re.findall(r'^test .* \.\.\. ok$', result['stdout'], re.M)) == count
        expected_stderr = ('Validated installed ARM64 NtCreateSection/NtSecureConnectPort/NtClose '
                           'with matched native CSR metadata') if index == 3 else ''
        assert result['stderr'].strip() == expected_stderr
    startup_bytes = (BASE / 'native-startup-source-v1.json').read_bytes()
    startup_manifest, startup = json.loads(startup_bytes), load('native-startup-arm64-v1.json')
    assert startup['schema'] == 'rax-csr-session-startup-v2' and 'error' not in startup
    assert startup['subject'] == profile['subject'] and startup['ntdll_sha256'] == DLL
    assert startup['original_native_jobs_restarted'] is False
    assert startup['source_manifest_sha256'] == hashlib.sha256(startup_bytes).hexdigest()
    assert startup['image_sha256'] == startup_manifest['artifact']['sha256']
    assert startup_manifest['source_frame_sha256'] == manifest['source_frame_sha256']
    assert hashlib.sha256((BASE / 'startup-control.rs').read_bytes()).hexdigest() == \
        startup_manifest['artifact']['source_sha256']
    assert len(startup['tests']) == 1
    attempt = startup['tests'][0]
    assert attempt['exit_code'] == 0 and attempt['stderr'] == ''
    assert int(attempt['pid']) > 0 and int(attempt['creation']) > 0
    output = attempt['stdout']
    assert output.startswith('configuration file_backed_spawn=true arena_bytes=268435456 seed=0 ')
    for module in ['cmd.exe', 'ntdll.dll', 'kernel32.dll', 'KernelBase.dll', 'ucrtbase.dll']:
        assert len(re.findall(r'^module name=' + re.escape(module) + r' base=', output, re.M)) == 1
    terminal = [line for line in output.splitlines() if line.startswith('TERMINAL ')]
    assert len(terminal) == 1 and 'sample=68671 instruction_budget_bound=4395008' in terminal[0]
    assert (68671 + 1) * 64 == 4395008
    assert 'status=Complete(Internal(' in terminal[0] and 'NtAlpcSendWaitReceivePort' in terminal[0]
    assert 'unmeasured CSR message/profile' in terminal[0]
    assert 'DIAGNOSTIC_INSTRUCTION_LIMIT' not in output
    capi_bytes = (BASE / 'native-capi-source-v1.json').read_bytes()
    capi_manifest, capi = json.loads(capi_bytes), load('native-capi-system-v1.json')
    assert capi['schema'] == 'rax-csr-session-capi-v2' and 'error' not in capi
    assert capi['subject'] == 'S-1-5-18' and capi['ntdll_sha256'] == DLL
    assert capi['original_native_jobs_restarted'] is False
    assert capi['source_manifest_sha256'] == hashlib.sha256(capi_bytes).hexdigest()
    assert capi['image_sha256'] == capi_manifest['artifact']['sha256']
    for path, expected in capi_manifest['owned_sources'].items():
        if path.startswith(('src/', 'capi/src/')) or path.endswith('/native-arm64-session-csr/profile-v1.json'):
            assert '..' not in Path(path).parts
            assert hashlib.sha256((root / path).read_bytes()).hexdigest() == expected, path
    assert len(capi['tests']) == 1
    result = capi['tests'][0]
    assert result['arguments'] == '--test-threads=2'
    assert result['exit_code'] == 0 and result['stderr'].strip() == ''
    assert '243 passed; 0 failed; 0 ignored;' in result['stdout']
    assert len(re.findall(r'^test .* \.\.\. ok$', result['stdout'], re.M)) == 243
    for name in ['process_supplied_dll_array_loads_real_imports_all_abis',
                 'process_captures_real_crt_stdout_and_stderr_after_exit_all_abis']:
        assert f'test tests::process::{name} ... ok' in result['stdout']
    assets = load('capi-fixture-membership-v1.json')
    assert assets['count'] == len(assets['assets']) == 21
    for path, identity in assets['assets'].items():
        assert path.startswith('tests/fixtures/user/windows/') and '..' not in Path(path).parts
        data = (root / path).read_bytes()
        assert len(data) == identity['bytes'] and hashlib.sha256(data).hexdigest() == identity['sha256']
    before = load('native-capi-before-fixtures-v1.json')
    assert before['subject'] == 'S-1-5-18' and len(before['tests']) == 1
    assert before['tests'][0]['exit_code'] == 101
    assert '241 passed; 2 failed; 0 ignored;' in before['tests'][0]['stdout']
    assert 'The system cannot find the path specified.' in before['tests'][0]['stdout']
    print('Verified session1 metadata/USER views, ARM64 first connection, and pure-x86 BASE bridge.')
    print('ARM64 child naturally exits41; x86 controller stops only its owned child70 after the return.')
    print('Verified 52 native Rust case-runs/45 unique cases; installed CMD advances to a later ALPC message.')
    print('CMD terminal is Internal, not success; wrapper exit0 records the failure.')
    print('Verified 243 native Windows C API cases under SYSTEM; ordinary-user CSR evidence remains separate.')


if __name__ == '__main__':
    main()
