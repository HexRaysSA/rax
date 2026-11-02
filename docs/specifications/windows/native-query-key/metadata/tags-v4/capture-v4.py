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
receipt = {'pid': os.getpid(), 'state': 'checking inputs', 'commands': [], 'reports': []}
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
    (out / ('progress-metadata-tags-v4-%04d.json' % sequence)).write_text(json.dumps(receipt, indent=2) + '\n')

def verify():
    for name, digest in manifest.items():
        path = out / name
        assert path.resolve().is_relative_to(out) and not path.is_symlink()
        assert sha(path) == digest, name

def run(name, argv, env):
    label = 'metadata-tags-v4-' + name
    begin = time.monotonic()
    with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
        child = subprocess.Popen(argv, cwd=out, env=env, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, creationflags=0x08000000)
        receipt.update(state=name, child_pid=child.pid, child_creation_filetime=birth(w.HANDLE(int(child._handle))))
        save()
        code = child.wait()
    receipt['commands'].append({'name': name, 'argv': argv, 'exit_code': code, 'seconds': time.monotonic() - begin})
    save()
    assert code == 0, (name, code)
    return out / (label + '.stdout')

def identity(label, image, phase, env):
    path = run(label + '-identity-' + phase, [str(image), '--identity'], env)
    q = json.loads(path.read_text())
    assert q['kind'] == 'identity' and q['schema'] == 'rax-native-key-metadata-tags-v4'
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
    manifest = json.loads((out / 'source-hashes-metadata-tags-v4.json').read_text())
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
    for label, architecture, machine in [('arm64','ARM64',0xAA64),('x64','x64',0x8664),('x86','Win32',0x14C)]:
        build=out/('build-'+label)
        run(label+'-configure',[str(cmake),'-S',str(out/'source'),'-B',str(build),'-A',architecture],env)
        run(label+'-build',[str(cmake),'--build',str(build),'--config','Release','--','/nr:false','/m:1'],env)
        image=Path((build/'probe-paths-Release.txt').read_text().strip()).resolve();assert image.is_relative_to(build)
        data=image.read_bytes();offset=struct.unpack_from('<I',data,0x3c)[0];assert data[:2]==b'MZ' and data[offset:offset+4]==b'PE\0\0' and struct.unpack_from('<H',data,offset+4)[0]==machine
        copy=out/'artifacts'/('native-key-metadata-tags-v4-'+label+'.exe')
        with copy.open('xb') as f:f.write(data)
        before=identity(label,copy,'before',env)
        receipt['active_identity']={'architecture':label,'provider_before':before,'image_sha256':sha(copy)};save()
        stdout=run(label+'-tags',[str(copy),'--tag-records'],env)
        rows=[json.loads(line) for line in stdout.read_text().splitlines()]
        assert rows[0]['kind']=='host' and rows[1]['kind']=='setter' and rows[1]['mapped_provider_utf16']==before['mapped_provider_utf16']
        assert rows[-1]=={'kind':'tags_finished','inputs':8,'before_queries':9,'after_queries':72}
        originals={q['class']:q for q in rows if q['kind']=='tags_before'};assert set(originals)==set(range(9))
        mutations=[q for q in rows if q['kind']=='tags_after'];assert len(mutations)==72
        inputs=[0,1,0x400,0x600,0xffff,0x10000,0x12345678,0xffffffff]
        changed=[]
        for q in mutations:
            assert q['input'] in inputs and q['set_status']==q['status']==0
            assert q['required']==originals[q['class']]['required']
            if q['class']==7:assert bytes.fromhex(q['bytes'])==(q['input']&0xffff).to_bytes(4,'little')
            elif q['bytes']!=originals[q['class']]['bytes']:changed.append(q)
        after=identity(label,copy,'after',env);assert before==after and sha(copy)==sha(image)==receipt['active_identity']['image_sha256'];verify()
        receipt['reports'].append({'architecture':label,'image_sha256':sha(copy),'image_bytes':len(data),'provider_before':before,'provider_after':after,'setter_provider_matches_query':True,'queries':81,'mutations':8,'other_changed_records':changed})
        save()
    receipt.update(state='finished',exit_code=0,inputs_unchanged=True)
except BaseException:
    receipt.update(state='failed',exit_code=1,error=traceback.format_exc())
finally:
    save()
    (out/'receipt-metadata-tags-v4.json').write_text(json.dumps(receipt,indent=2)+'\n')
    files={name:out/name for name in manifest}
    for path in out.iterdir():
        if path.is_file() and (path.name.startswith(('metadata-tags-v4-','progress-metadata-tags-v4-')) or path.name in ['.owner','receipt-metadata-tags-v4.json','source-hashes-metadata-tags-v4.json','launch-metadata-tags-v4.json','source-before-metadata-tags-v4.zip']):files[path.name]=path
    for path in (out/'artifacts').glob('native-key-metadata-tags-v4-*.exe'):files[path.relative_to(out).as_posix()]=path
    identities={r['architecture']:r['provider_before'] for r in receipt['reports']}
    if receipt.get('active_identity'):identities[receipt['active_identity']['architecture']]=receipt['active_identity']['provider_before']
    for label,q in identities.items():
        provider=Path(q['backing_file']);assert sha(provider)==q['provider_sha256'];files['providers/'+label+'-ntdll.dll']=provider
    archive=out/'metadata-tags-only-v4.zip';inventory={name:{'bytes':path.stat().st_size,'sha256':sha(path)} for name,path in files.items()}
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
        for name,path in files.items():z.write(path,name)
        z.writestr('archive-manifest.json',json.dumps(inventory,sort_keys=True))
    with zipfile.ZipFile(archive) as z:
        for name,item in inventory.items():
            data=z.read(name);assert len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256']
    result={'path':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),'payloads':len(inventory),'state':'verified','validation_exit_code':receipt['exit_code']}
    (out/'metadata-tags-only-v4.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
raise SystemExit(receipt['exit_code'])
