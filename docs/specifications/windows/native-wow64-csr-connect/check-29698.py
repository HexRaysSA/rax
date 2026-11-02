"""Cross-check fresh native evidence against the preserved native controls."""
from pathlib import Path
import base64
import hashlib
import json
import re
import zipfile
import sys

base = Path(__file__).resolve().parent
root = base.parents[3]
old = base


def fields(line):
    return dict(re.findall(r'([\w-]+)=([^\s]+)',line))


def project(raw):
    lines=raw.decode().splitlines()
    assert 'exit=70' in lines[-1]
    assert any('machine=014C ret-bytes=20' in line for line in lines if line.startswith('INSTALLED '))
    result=[]
    step=None
    for line in lines:
        row=fields(line)
        if line.startswith('RETURN '):
            assert step is None
            step={'ordinal':int(row['ordinal']),'status':row['status'],'new_handles':[],'new_mappings':[]}
        elif line.startswith('HANDLE_NEW '):
            assert step is not None and row['duplicate']=='1' and row['query']=='00000000'
            kind=re.search(r' type=(.*?)(?= name-query=|$)',line).group(1)
            name=re.search(r' name=(.*?)(?= section-query=|$)',line)
            step['new_handles'].append({'access':row['access'],'type':kind,'name':name.group(1) if name else None})
        elif line.startswith('MAPPED_NEW '):
            assert step is not None
            step['new_mappings'].append({'bytes':int(row['bytes']),'state':int(row['state'],16),'protect':int(row['protect'],16),'type':int(row['type'],16)})
        elif line.startswith('PEB_DELTA '):
            assert step is not None
            before,after=map(int,row['handles'].split(':'))
            step.update(handles_before=before,handles_after=after,changed64=int(row['changed64']),changed32=int(row['changed32']))
            assert len(step['new_handles'])==after-before
            result.append(step)
            step=None
    assert step is None and result
    return {'terminal':lines[-1],'steps':result}


if len(sys.argv) == 1:
    payload = (base/'profile-29698-v1.json').read_bytes()
    assert hashlib.sha256(payload).hexdigest() == '4053990c745a36d2736deec49093dbe6723e5b1a411287ddd54b2e509b03c0b4'
    data = json.loads(payload)
    assert data['kernel'] == [10,0,29698] and data['native_machine'] == 0xAA64 and data['session'] == 0
    for name,identity in data['sources'].items():
        if name == 'CMakeLists.txt':
            continue  # Infrastructure source is verified by the optional archive path.
        path = root/'tests/fixtures/user/windows/native_exception_entry/bin/x86/fault.exe' if name == 'fault.exe' else base/name
        raw = path.read_bytes()
        assert len(raw) == identity['bytes'] and hashlib.sha256(raw).hexdigest() == identity['sha256'],name
    assert sum(len(group['samples'])for group in data['groups']) == 31
    assert sum(len(sample['steps'])for group in data['groups']for sample in group['samples']) == 38
    assert data['original_native_exit'] == 0 and sum(sample['rows']for sample in data['family']) == 336
    print('Verified frozen sources and SHA-bound projection: 31 fresh/retry cases, 38 returns, 336 repeated calls. Raw archive not checked.')
    raise SystemExit(0)
assert len(sys.argv) == 2, 'usage: check-29698.py [native-archive.zip]'

# First prove that the parser reproduces every preserved typed old step.
for version in (8,9):
    typed=json.loads((old/('initial-29695-v%d.json'%version)).read_text())
    raw=json.loads((old/('initial-raw-v%d.json'%version)).read_text())
    for sample in typed['samples']:
        text=base64.b64decode(raw['logs'][sample['mode']+'.log'],validate=True)
        parsed=project(text)
        assert parsed['steps']==sample['steps'] and parsed['terminal']==sample['terminal'],sample['mode']

archive=Path(sys.argv[1])
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='60a3deccd08004edcb3b19259f37ee0d7a0088b458b9494707d5a47135057c5b'
with zipfile.ZipFile(archive) as z:
    identities=json.loads(z.read('archive-manifest.json'))
    assert z.testzip() is None and len(identities)==403
    for name,identity in identities.items():
        raw=z.read(name)
        assert len(raw)==identity['bytes'] and hashlib.sha256(raw).hexdigest()==identity['sha256']
    receipt=json.loads(z.read('native/receipt.json'))
    assert receipt['state']=='finished' and receipt['inputs_unchanged'] and receipt['kernel'][:3]==[10,0,29698]
    assert receipt['original_native_exit']==0 and all(item['exit_code']==0 for item in receipt['commands'])
    assert hashlib.sha256(z.read('native/source/fault.exe')).hexdigest()=='4a0f28a1fba11a97b7498f6bf5b231d32c124ce15d2bcb90084816e342c09544'
    groups=[]
    for version in (8,9):
        previous=json.loads((old/('initial-29695-v%d.json'%version)).read_text())
        samples=[]
        for sample in previous['samples']:
            mode=sample['mode']
            raw=z.read('native/v%d-%s.log'%(version,mode))
            parsed=project(raw)
            assert parsed['terminal']==sample['terminal']
            assert len(sample['steps']) == len(parsed['steps'])
            for before,after in zip(sample['steps'],parsed['steps']):
                # ASLR can change the count of nonzero pointer bytes; only the
                # publication/nonpublication observation is architecture policy.
                for key in ('ordinal','status','new_handles','new_mappings'):
                    assert before[key]==after[key],(version,mode,key)
                assert before['handles_after']-before['handles_before']==after['handles_after']-after['handles_before']
                for key in ('changed64','changed32'):
                    assert bool(before[key])==bool(after[key]),(version,mode,key)
            samples.append({'mode':mode,'stdout_sha256':hashlib.sha256(raw).hexdigest(),**parsed})
        groups.append({'version':version,'case_count':len(samples),'return_count':sum(len(s['steps'])for s in samples),'samples':samples})
    family=[]
    old_family=json.loads((old/'family-raw-v2.json').read_text())
    expected=None
    for mode in ('default','enabled','disabled'):
        raw=z.read('native/family/'+mode+'.log')
        text=raw.decode()
        assert 'KERNEL major=10 minor=0 build=29698' in text and text.splitlines()[-1]=='DONE calls=112'
        rows=[fields(line)for line in text.splitlines() if line.startswith('CASE ')]
        prior=base64.b64decode(old_family['logs'][mode+'.log'],validate=True).decode()
        assert rows==[fields(line)for line in prior.splitlines() if line.startswith('CASE ')]
        assert len(rows)==112
        if expected is not None:assert rows==expected
        expected=rows
        family.append({'mode':mode,'rows':len(rows),'stdout_sha256':hashlib.sha256(raw).hexdigest()})
    result={'schema':'rax-native-wow64-csr-29698-v1','kernel':[10,0,29698],'native_machine':0xAA64,'session':0,'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'original_native_exit':0,'fresh_cases':31,'fresh_returns':38,'family_calls':336,'sources':receipt['sources'],'images':receipt['images'],'providers':receipt['providers'],'groups':groups,'family':family,'comparison':'Exact status, new handle grants/types/names, mapped geometry, per-step handle deltas, publication state and all 336 repeated-call semantic rows match prior controls. Pointer addresses and the number of changed pointer bytes are retained in raw logs, without interpreting ASLR bytes as policy.'}
sys.stdout.write(json.dumps(result,indent=2)+'\n')
