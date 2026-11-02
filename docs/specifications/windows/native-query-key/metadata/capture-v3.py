from pathlib import Path
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import traceback
import zipfile

root = Path.cwd().resolve()
out = root / 'target/nls-custom-locale-query-native-c-v1'
assert (out / '.owner').read_text() == 'nls-custom-locale-query-native-c-v1-20261102\n'
assert out.resolve().is_relative_to(root) and not out.is_symlink()
receipt = {'pid': os.getpid(), 'state': 'checking inputs', 'commands': [], 'reports': [], 'failures': []}
sequence = 0
manifest = {}
k = ctypes.WinDLL('kernel32', use_last_error=True)
k.GetProcessTimes.argtypes = [w.HANDLE, *[ctypes.POINTER(w.FILETIME)] * 4]
k.QueryDosDeviceW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
k.QueryDosDeviceW.restype = w.DWORD

def birth(handle):
    times = [w.FILETIME() for _ in range(4)]
    assert k.GetProcessTimes(handle, *[ctypes.byref(x) for x in times])
    return str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()

def save():
    global sequence
    sequence += 1
    (out / ('progress-metadata-guards-v3-%04d.json' % sequence)).write_text(json.dumps(receipt, indent=2) + '\n')

def verify():
    for name, digest in manifest.items():
        path = out / name
        assert path.resolve().is_relative_to(out) and not path.is_symlink()
        assert sha(path) == digest, name

def run(name, argv, env, allowed=(0,)):
    label = 'metadata-guards-v3-' + name
    begin = time.monotonic()
    with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
        child = subprocess.Popen(argv, cwd=out, env=env, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, creationflags=0x08000000)
        receipt.update(state=name, child_pid=child.pid, child_creation_filetime=birth(w.HANDLE(int(child._handle))))
        save()
        code = child.wait()
    receipt['commands'].append({'name': name, 'argv': argv, 'exit_code': code, 'seconds': time.monotonic() - begin})
    save()
    assert code in allowed, (name, code)
    return out / (label + '.stdout')

def identity(label, image, phase, env):
    path = run(label + '-identity-' + phase, [str(image), '--identity'], env)
    q = json.loads(path.read_text())
    assert q['kind'] == 'identity' and q['schema'] == 'rax-native-key-metadata-guards-v3'
    assert q['kernel'] == [10, 0, 29698] and q['native_machine'] == 0xAA64
    assert q['pointer_bytes'] == (4 if label == 'x86' else 8)
    assert q['process_machine'] == (0x14C if label == 'x86' else 0)
    mapped = bytes.fromhex(q['mapped_provider_utf16']).decode('utf-16-le')
    device = ctypes.create_unicode_buffer(32768)
    assert k.QueryDosDeviceW('C:', device, 32768)
    prefix = device.value
    assert mapped.casefold().startswith((prefix + '\\').casefold()), mapped
    backing = Path('C:' + mapped[len(prefix):])
    data = backing.read_bytes()
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[:2] == b'MZ' and data[offset:offset + 4] == b'PE\0\0'
    q.update(backing_file=str(backing), provider_bytes=len(data), provider_sha256=hashlib.sha256(data).hexdigest(),
             provider_pe_machine=struct.unpack_from('<H', data, offset + 4)[0],
             provider_identity_source='GetMappedFileNameW at the actual NtQueryKey address')
    assert q['provider_pe_machine'] == (0x14C if label == 'x86' else 0xAA64)
    return q

save()
try:
    manifest = json.loads((out / 'source-hashes-metadata-guards-v3.json').read_text())
    verify()
    settings = root / 'target/win32u-validation-recovery-v2/transfer/mutant-native-compiler-env-epoch4.json'
    assert sha(settings) == 'e6ca43bcdcbd3067b5de05d051259d4d3abf0bfa5283a98daac14fd508a05fad'
    values = {key.upper(): value for key, value in json.loads(settings.read_text(encoding='utf-8-sig')).items()}
    env = os.environ.copy()
    env.update(values)
    cmake = Path(values['VCTOOLSINSTALLDIR']).parents[3] / 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
    assert sha(cmake) == '6fb7b634091690510a9f5612237fe2816f5a401ffd6cc91f9e248ff47d11e96a'
    temporary = out / 'tmp'
    assert temporary.resolve().is_relative_to(out)
    env.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary), SystemTemp=str(temporary),
               CCACHE_DISABLE='1', SCCACHE_DISABLE='1')
    ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
    receipt['kernel'] = list(sys.getwindowsversion().platform_version)
    for label, architecture, machine in [('arm64', 'ARM64', 0xAA64), ('x64', 'x64', 0x8664), ('x86', 'Win32', 0x14C)]:
        build = out / ('build-' + label)
        assert build.resolve().is_relative_to(out)
        run(label + '-configure', [str(cmake), '-S', str(out / 'source'), '-B', str(build), '-A', architecture], env)
        run(label + '-build', [str(cmake), '--build', str(build), '--config', 'Release', '--', '/nr:false', '/m:1'], env)
        paths = (build / 'probe-paths-Release.txt').read_text().splitlines()
        assert len(paths) == 1
        image = Path(paths[0]).resolve()
        assert image.is_relative_to(build)
        data = image.read_bytes()
        offset = struct.unpack_from('<I', data, 0x3C)[0]
        assert data[:2] == b'MZ' and data[offset:offset + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', data, offset + 4)[0] == machine
        copy = out / 'artifacts' / ('native-key-metadata-guards-v3-' + label + '.exe')
        with copy.open('xb') as f:
            f.write(data)
        expected_image_hash = sha(copy)
        before = identity(label, copy, 'before', env)
        receipt['active_identity'] = {'architecture': label, 'provider_before': before, 'image_sha256': expected_image_hash}; save()
        stdout = run(label + '-cases', [str(copy)], env, allowed=(0, 25))
        counts = {}
        controls = {}
        first = last = None
        snapshots = []
        with stdout.open('rb') as stream:
            for line in stream:
                q = json.loads(line)
                if first is None:
                    assert q['kind'] == 'host'
                    first = q
                    continue
                if q['kind'] == 'handle_snapshot':
                    assert q['phase'] in ['initial','before','after'] and q['status'] == 0 and not q.get('bounds_error')
                    assert q['count'] == len(q['entries']) and all(not e.get('bounds_error') for e in q['entries'])
                    snapshots.append(q)
                    continue
                if q['kind'] == 'finished':
                    assert last is None
                    last = q
                    continue
                assert last is None and q['kind'] == 'case'
                index = sum(counts.values())
                assert q['index'] == index and 0 <= q['class'] <= 10
                assert 0 <= q['output'] < 14 and 0 <= q['returned'] < 13
                assert len(bytes.fromhex(q['bytes'])) == 256 and len(bytes.fromhex(q['returned_bytes'])) == 8
                assert len(q['protections']) == 4
                counts[q['class']] = counts.get(q['class'], 0) + 1
                if index % 6010 >= 6006:
                    assert q['output'] == q['returned'] == 0 and q['length'] == 256
                    controls.setdefault(q['class'], []).append(q)
        assert first is not None and last is not None
        for field in ['pointer_bytes', 'process_machine', 'native_machine', 'kernel',
                      'provider_utf16', 'mapped_provider_utf16']:
            assert first[field] == before[field], (label, field)
        assert counts == {information_class: 6010 for information_class in range(11)}, counts
        assert last['records'] == 66110
        assert [q['phase'] for q in snapshots] == ['initial','before','after']
        assert last['handles_before'] == snapshots[1]['public_count'] and last['handles_after'] == snapshots[2]['public_count']
        lifetime_unchanged = last['handles_before'] == last['handles_after']
        if not lifetime_unchanged:
            receipt['failures'].append({'architecture':label,'gate':'strict process handle equality','before':last['handles_before'],'after':last['handles_after']})
        for information_class, rows in controls.items():
            assert len(rows) == 4 and [r['poison'] for r in rows] == [165, 165, 90, 90]
            if information_class > 8:
                assert all(r['status'] == 0xC000000D and r['exception'] == 0 for r in rows)
            else:
                assert all(r['status'] == r['exception'] == 0 for r in rows)
                lengths = [int.from_bytes(bytes.fromhex(r['returned_bytes'])[:4], 'little') for r in rows]
                assert len(set(lengths)) == 1 and 4 <= lengths[0] <= 256
                records = [bytes.fromhex(r['bytes'])[:lengths[0]] for r in rows]
                assert len(set(records)) == 1, (information_class, 'native full record changed or contains undefined bytes')
        after = identity(label, copy, 'after', env)
        assert before == after
        assert sha(copy) == sha(image) == expected_image_hash
        verify()
        receipt['reports'].append({'architecture': label, 'pe_machine': machine,
            'image_bytes': len(data), 'image_sha256': expected_image_hash,
            'provider_before': before, 'provider_after': after,
            'records': 66110, 'warmup_records': 66110, 'class_counts': counts,
            'stdout_path': str(stdout), 'stdout_sha256': sha(stdout),
            'handles_before': last['handles_before'], 'handles_after': last['handles_after'],
            'stable_full_records': True, 'handle_snapshots': snapshots, 'strict_handle_equality': lifetime_unchanged})
        save()
    receipt.update(state='finished' if not receipt['failures'] else 'failed', exit_code=1 if receipt['failures'] else 0, inputs_unchanged=True)
except BaseException:
    receipt.update(state='failed', exit_code=1, error=traceback.format_exc())
finally:
    save()
    (out / 'receipt-metadata-guards-v3.json').write_text(json.dumps(receipt, indent=2) + '\n')
    files = {name: out / name for name in manifest}
    for path in out.iterdir():
        if path.is_file() and (path.name.startswith(('metadata-guards-v3-', 'progress-metadata-guards-v3-')) or
                             path.name in ['.owner', 'receipt-metadata-guards-v3.json', 'source-hashes-metadata-guards-v3.json',
                                           'launch-metadata-guards-v3.json', 'source-before-metadata-guards-v3.zip']):
            files[path.name] = path
    for path in (out / 'artifacts').glob('native-key-metadata-guards-v3-*.exe'):
        files[path.relative_to(out).as_posix()] = path
    for report in receipt['reports']:
        provider = Path(report['provider_before']['backing_file'])
        assert sha(provider) == report['provider_before']['provider_sha256']
        files['providers/' + report['architecture'] + '-ntdll.dll'] = provider
    if receipt.get('active_identity'):
        active = receipt['active_identity']
        provider = Path(active['provider_before']['backing_file'])
        assert sha(provider) == active['provider_before']['provider_sha256']
        files['providers/' + active['architecture'] + '-ntdll.dll'] = provider
    archive = out / 'metadata-guards-only-v3.zip'
    inventory = {name: {'bytes': path.stat().st_size, 'sha256': sha(path)} for name, path in files.items()}
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as z:
        for name, path in files.items():
            z.write(path, name)
        z.writestr('archive-manifest.json', json.dumps(inventory, sort_keys=True))
    with zipfile.ZipFile(archive) as z:
        for name, expected in inventory.items():
            h = hashlib.sha256()
            size = 0
            with z.open(name) as stream:
                for block in iter(lambda: stream.read(1 << 20), b''):
                    h.update(block)
                    size += len(block)
            assert size == expected['bytes'] and h.hexdigest() == expected['sha256']
    result = {'path': str(archive), 'bytes': archive.stat().st_size, 'sha256': sha(archive),
              'payloads': len(inventory), 'state': 'verified', 'validation_exit_code': receipt['exit_code']}
    (out / 'metadata-guards-only-v3.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
raise SystemExit(receipt['exit_code'])
