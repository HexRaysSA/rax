#!/usr/bin/env python3
"""Independent byte/fault replay of selected class55 observations."""
import argparse
import hashlib
import json
import re
from pathlib import Path

if not __debug__:
    raise SystemExit('Python optimization disables replay assertions')
HERE = Path(__file__).resolve().parent
OK, SHORT, AV, ALIGN, GUARD = '00000000','C0000004','C0000005','80000002','80000001'


def fields(line):
    pairs=[item.split('=',1) for item in line.split()]
    assert all(len(p)==2 for p in pairs) and len(set(p[0] for p in pairs))==len(pairs)
    return dict(pairs)


def replay(row,width,state):
    length,mode,offset=(int(row[k]) for k in ['bytes','mode','offset'])
    out,ret=state['out'],state['ret']
    def output_fault():
        if mode==2 or mode==13 and offset%4 or mode in [9,10] and offset%4:
            return ALIGN
        if mode in [1,5,15,16,17,19,20]:
            return AV
        if state['og']:
            state['og']=0
            return GUARD
        if row['label'] in ['huge-length','huge-fault'] or mode in [9,10] and offset<length:
            return AV
        return None
    def return_fault():
        if mode in [4,7,15,18] or mode==11 and offset<4:
            return AV
        if state['rg']:
            state['rg']=0
            return GUARD
        return None
    def write_return(value):
        if mode==3:return None
        fault=return_fault()
        if fault:return fault
        data=value.to_bytes(4,'little')
        if mode==12:out[offset:offset+4]=data
        elif mode==11:state['crossret']=data
        else:
            start=offset if mode==14 else 0
            ret[start:start+4]=data
        return None
    def execute():
        if length:
            fault=output_fault()
            if fault:return fault
        if width==8 and mode!=3:
            fault=return_fault()
            if fault:return fault
        if length<4:
            return (write_return(4) or SHORT) if width==8 else SHORT
        out[:4]=bytes(4)
        if length>=24:
            out[8:24]=bytes([255])+bytes(15)
        return write_return((20 if width==4 else 24) if length>=24 else 4) or OK
    status=execute()
    assert row['status']==status,(row['case'],row,status)
    assert (int(row['output-guard']),int(row['returned-guard']))==(state['og'],state['rg']),row
    if mode in [1,2,15,16,17,20] or state['og']:output=b''
    elif mode in [9,10]:output=bytes(out[:min(offset,2048)])
    else:output=bytes(out[:2048])
    if mode in [3,4,15] or state['rg']:returned=b''
    elif mode==12:returned=bytes(out[offset:offset+2048])
    elif mode==11:returned=(state['crossret']+b'\xA5'*2048)[:offset]
    else:
        start=offset if mode==14 else 0
        returned=bytes(ret[start:start+2048])
    backing=b'' if state['rg'] else bytes(ret[:2048])
    for name,data in [('output',output),('returned',returned),('backing',backing)]:
        assert int(row[name+'-captured'])==len(data) and bytes.fromhex(row[name])==data,(row['case'],name)


def profile(arch):
    width=4 if arch.startswith('x86') else 8
    lines=(HERE/('native-numa-map-probe-'+arch+'.log')).read_text().splitlines()
    assert lines[0]==f'profile width={width} page=4096 class=55' and lines[-1]=='complete cases=395'
    rows=[fields(line) for line in lines if line.startswith('case=')]
    assert len(rows)==395 and [int(x['case']) for x in rows]==list(range(395))
    assert all(x['exception']==OK and int(x['width'])==width for x in rows)
    state=None
    for row in rows:
        if row['repeat']=='0':
            mode=int(row['mode'])
            state={'out':bytearray(b'\xA5'*4096),'ret':bytearray(b'\xA5'*4096),
                   'og':256 if mode in [6,18] else 0,'rg':256 if mode in [8,17,19] else 0,'crossret':b'\xA5'*4}
        replay(row,width,state)
    guards=[fields(x[12:]) for x in lines if x.startswith('range-guard ')]
    assert guards==([dict(role='0',width='8',status=AV,exception=OK,guard='256'),dict(role='1',width='8',status=GUARD,exception=OK,guard='0')] if width==8 else [])
    return len(rows)+len(guards)



def verify_records(names, sources):
    records=json.loads((HERE/'validation.json').read_text())
    gates=records['gates']
    assert len(gates)==22 and len({(x['host'],x['gate']) for x in gates})==22
    for gate in gates:
        assert gate['path'] in names
        log=(HERE/gate['path']).read_text()
        for summary in gate.get('expected-summaries',[]):assert summary in log,gate
        if gate.get('build-success'):assert 'Finished `dev`' in log,gate
        if 'required-marker' in gate:assert gate['required-marker'] in log,gate
    for host,path in [('linux','linux-final-full.log'),('windows','native-numa-final-full.log')]:
        log=(HERE/path).read_text()
        section=log[log.rfind('failures:'):].split('test result:',1)[0]
        failures=[x.strip() for x in section.splitlines()[1:] if x.strip()]
        assert failures==records['known-full-suite-failures'][host]
    for metadata in ['native-gate-hashes.json','native-owning-log-hashes.json','owning-cpp-helper-hashes.json']:
        for row in json.loads((HERE/metadata).read_text()):
            assert row['path'] in names
            data=(HERE/row['path']).read_bytes()
            assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
    for path,count in [('linux-owning-cpp.log',184),('assist-native-numa-owned-cpp.log',182)]:
        log=(HERE/path).read_text()
        for marker in [f'process tool: {count} checks passed','RAX process: 162 checks passed',
                       'canonical discovery and explicit RAX-disabled refusal passed','2/2 passed','PASS']:
            assert marker in log,(path,marker)
    archive=json.loads((HERE/'native-owning-archive-hashes.json').read_text())
    assert archive['core-features']==[] and archive['sources']==sources
    assert len(archive['archives'])==2 and all(x['structural-member-walk']=='pass' for x in archive['archives'])
    assert [x['members'] for x in archive['archives']]==[4673,260]
    artifacts=[json.loads(x) for x in (HERE/'native-numa-after-artifacts.jsonl').read_text().splitlines()]
    core=[x for x in artifacts if x.get('reason')=='compiler-artifact' and x['target']['name']=='rax'
          and not x['manifest_path'].endswith('capi\\Cargo.toml')]
    assert len(core)==1 and core[0]['fresh'] and core[0]['features']==[]
    assert archive['archives'][1]['path'] in core[0]['filenames']
    assert (HERE/'native-numa-before-trace.rs').read_bytes()==(HERE/'native-numa-after-trace.rs').read_bytes()
    before=(HERE/'native-numa-before-trace-output.log').read_text()
    after=(HERE/'native-numa-after-trace-output.log').read_text()
    assert 'terminal turn=33566' in before and 'NtQuerySystemInformation class 55' in before
    assert 'kernel-after turn=33566 service=0x36 PC=0x1800013a4 X0=0x0' in after
    assert 'terminal turn=40500' in after and 'NtQuerySystemInformationEx class 107 relationship 6' in after
    ordinary=(HERE/'native-numa-after-ordinary-processes.log').read_text()
    assert ordinary.count('program ')==4 and ordinary.count('run reason=4 exit=3221225477')==4
    trace=(HERE/'native-numa-after-production-trace-output.log').read_text()
    assert 'ProcessHeap=Ok(65536)' in trace and 'first exception appears at turn=1459' in trace
    assert 'original exception context PC=0x180026528 SP=0xabf9c0' in trace
    assert 'terminal turn=1500 Complete(Exited(3221225477))' in trace
    for turn,pc in [(1456,'0x180026520'),(1457,'0x180026524'),(1458,'0x180026528')]:
        line=next(x for x in trace.splitlines() if x.startswith(f'first-fault-history turn={turn} '))
        assert f'PC={pc}' in line
        regs=line.split(' registers=[',1)[1].split(']',1)[0].split(', ')
        assert int(regs[19],16)==0x10000
        if turn>1456:assert int(regs[8],16)==0x80006
    observer=(HERE/'native-numa-after-production-trace.rs').read_text()
    assert hashlib.sha256(observer.encode()).hexdigest()=='75d006334ffed51536d5d5b1c314c6b21b1e2e4f873add8db1b4e519874635f0'
    assert all(x not in observer for x in ['state_mut(', 'set_pc(', 'LdrInitializeThunk', 'RegContext::capture'])
    runtime=json.loads((HERE/'native-current-runtime-hashes.json').read_text())
    assert len(runtime)==3 and runtime[-1]['sha256']=='d76e8c7f2cbd744628a5cccda5bec0c346a1aca8f8a35408bd2c9d5ff87667bd'
    assert runtime[0]['sha256']=='502d4678206c8fd564972a3f82bfe63fe1a451cb5a6804ac0a9823b65fcbb61f'
    assert runtime[1]['sha256']=='ffd2b7ff39889c5599c8a8451eef5c852acee9101da5ce5a6def8b8e60a6627e'
    print('Recorded22 gates, current owning artifacts, paired loader and ordinary first fault verified')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-root',type=Path,default=HERE.parents[3])
    args=parser.parse_args()
    manifest=json.loads((HERE/'evidence-hashes.json').read_text())['files']
    names=set()
    for row in manifest:
        name=row['path']
        assert Path(name).name==name and name not in names
        names.add(name)
        data=(HERE/name).read_bytes()
        assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],name
    assert {'README.md','validation.json','check_native_numa_map.py','source-hashes-reviewed.json',
            'native-probe-hashes-reviewed.json','wow64-wrapper-provenance.json','wow64-pdb-identity.txt',
            'native-owning-archive-hashes.json','native-current-runtime-hashes.json'}<=names
    sources=json.loads((HERE/'source-hashes-reviewed.json').read_text())
    assert len(sources)==4
    for row in sources:
        data=(args.source_root/row['path']).read_bytes()
        assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],row['path']
    ref=args.source_root/'docs/specifications/windows/native-processor-features'
    for name,sha in [('phnt-ntexapi.h','0510ac40fa1690cd73bed8afe3ed602aaa7bb6870ab95ea9aaba36ce1f4c3d53'),
                     ('phnt-LICENSE','ad2ab542c56c606e4c19d66a7f3cdcd3ef83beffb638e7c3893b22c7a6a6c0df')]:
        assert hashlib.sha256((ref/name).read_bytes()).hexdigest()==sha
    header=(ref/'phnt-ntexapi.h').read_text()
    enum=header.split('typedef enum _SYSTEM_INFORMATION_CLASS',1)[1].split('} SYSTEM_INFORMATION_CLASS;',1)[0]
    enum=re.sub(r'/\*.*?\*/|//[^\n]*','',enum,flags=re.S)
    value,identities=-1,{}
    for line in enum.splitlines():
        match=re.match(r'\s*(System\w+)\s*(?:=\s*(\d+))?\s*,?',line)
        if match:
            value=int(match[2]) if match[2] else value+1
            identities[match[1]]=value
    assert identities['SystemNumaProcessorMap']==55
    for definition in ['ULONG HighestNodeNumber;', 'ULONG Reserved;',
                       'GROUP_AFFINITY ActiveProcessorsGroupAffinity[MAXIMUM_NODE_COUNT];',
                       'ULONGLONG Pad[MAXIMUM_NODE_COUNT * 2];']:
        assert definition in header
    assert hashlib.sha256((HERE/'native-numa-map-probe.cpp').read_bytes()).hexdigest()=='fa16b0705e866fb9bcb7a2d4fd363b716bfa40d0622170dd48519c2abd0323f7'
    metadata=json.loads((HERE/'native-probe-hashes-reviewed.json').read_text())
    for arch,machine,laa in [('arm64','0xaa64',True),('x64','0x8664',True),('x86','0x14c',False),('x86-laa','0x14c',True)]:
        prefix='native-numa-map-probe-'+arch
        for suffix in ['.log','-build.log']:
            data=(HERE/(prefix+suffix)).read_bytes();row=metadata[prefix+suffix]
            assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
        row=metadata[prefix+'.exe']
        assert row['pe-machine']==machine and row['large-address-aware']==laa
    provenance=json.loads((HERE/'wow64-wrapper-provenance.json').read_text())
    assert (provenance['age'],provenance['pdb-info-age'],provenance['pdb-dbi-age'])==(1,3,1)
    assert provenance['guid']=='1f6db1e7-82ec-0d6e-7fdc-18da3d1f62db' and provenance['class55-case-rva']=='0x1A3A4'
    assert provenance['conversion-mask']=='low32(mask64) | high32(mask64)' and provenance['converted-record-bytes']==12
    identity=(HERE/'wow64-pdb-identity.txt').read_text()
    assert re.search(r'PdbStream:\s*Age:\s*3',identity) and re.search(r'DbiStream:.*?Age:\s*1',identity,re.S)
    assert '{1F6DB1E7-82EC-0D6E-7FDC-18DA3D1F62DB}' in identity
    assert '0 passed; 7 failed' in (HERE/'macos-before-portable.log').read_text()
    assert '7 passed; 1 failed' in (HERE/'macos-after-portable.log').read_text()
    assert '8 passed; 0 failed' in (HERE/'macos-final-portable.log').read_text()
    verify_records(names,sources)
    total=sum(profile(p) for p in ['arm64','x64','x86','x86-laa'])
    assert total==1584
    print('NUMA map: all 1584 native statuses, bytes, aliases and guard states verified')

if __name__=='__main__':main()
