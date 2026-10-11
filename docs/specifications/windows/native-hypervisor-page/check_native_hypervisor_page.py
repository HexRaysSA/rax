#!/usr/bin/env python3
"""Replay original class197 observations independently of the guest query."""
import argparse
import hashlib
import json
import re
from pathlib import Path

if not __debug__:
    raise SystemExit('Python optimization disables replay assertions; use normal Python')
HERE = Path(__file__).resolve().parent
OK, SHORT, AV, ALIGN, GUARD, OOM = ('00000000', 'C0000004', 'C0000005', '80000002', '80000001', 'C0000017')


def fields(line):
    pairs = [x.split('=', 1) for x in line.split()]
    assert all(len(x) == 2 for x in pairs), line
    assert len({x[0] for x in pairs}) == len(pairs), line
    return dict(pairs)


def replay(row, width, state):
    length, mode, offset = (int(row[x]) for x in ('bytes', 'mode', 'offset'))
    label = row['label']
    out, ret = state['out'], state['ret']

    def output_fault(native):
        if native:
            if mode == 2 or mode == 13 and offset % 4 or mode in (9, 10) and offset % 4:
                return ALIGN
            if label == 'huge-length' or mode == 20:
                return AV
        if mode in (1, 2, 5, 15, 16, 17, 19, 20) or mode in (9, 10) and offset < (length if native else width):
            return AV
        if state['og']:
            state['og'] = 0
            return GUARD
        return None

    def return_fault():
        if mode in (4, 7, 15, 18) or mode == 11 and offset < 4:
            return AV
        if state['rg']:
            state['rg'] = 0
            return GUARD
        return None

    def write_return(value):
        if mode == 3:
            return None
        error = return_fault()
        if error:
            return error
        data = value.to_bytes(4, 'little')
        if mode == 12:
            out[offset:offset+4] = data
        elif mode == 11:
            state['crossret'] = data
        else:
            start = offset if mode == 14 else 0
            ret[start:start+4] = data
        return None

    def execute():
        if width == 8:
            if length:
                error = output_fault(True)
                if error:
                    return error
            if mode != 3:
                error = return_fault()
                if error:
                    return error
        elif mode in (1, 15, 17) and length:
            return write_return(0xFFFFFFFC) or AV
        elif length and (label in ('huge-length', 'wow64-huge-fault') or
                         label == 'wow64-capture-size' and length >= 0x7FFFFFE0):
            # Only the explicitly captured values are tested here. There is no
            # inferred host allocation threshold between16 MiB and these rows.
            return OOM
        if length < width:
            return write_return(width) or SHORT
        if width == 4:
            error = output_fault(False)
            if error:
                return error
        out[:width] = bytes(width)
        return write_return(width) or OK

    status = execute()
    assert row['status'] == status, (row['case'], width, row, status)
    assert int(row['output-guard']) == state['og'], row
    assert int(row['returned-guard']) == state['rg'], row
    if mode in (1, 2, 15, 16, 17, 20) or state['og']:
        output = b''
    elif mode in (9, 10):
        output = bytes(out[:min(offset, 32)])
    else:
        output = bytes(out[:32])
    if mode in (3, 4, 15) or state['rg']:
        returned = b''
    elif mode == 12:
        returned = bytes(out[offset:offset+32])
    elif mode == 11:
        returned = (state['crossret'] + b'\xA5' * 32)[:offset]
    else:
        start = offset if mode == 14 else 0
        returned = bytes(ret[start:start+32])
    backing = b'' if state['rg'] else bytes(ret[:32])
    for name, data in [('output', output), ('returned', returned), ('backing', backing)]:
        assert int(row[name+'-captured']) == len(data), (row, name, len(data))
        assert bytes.fromhex(row[name]) == data, (row, name, data.hex())


def native_profile(profile):
    width = 4 if profile.startswith('x86') else 8
    count = 239 if width == 4 else 210
    lines = (HERE / ('native-hypervisor-page-probe-'+profile+'.log')).read_text().splitlines()
    assert lines[0] == f'profile width={width} page=4096 class=197'
    assert lines[-1] == f'complete cases={count}'
    rows = [fields(x) for x in lines if x.startswith('case=')]
    assert len(rows) == count
    assert [int(x['case']) for x in rows] == list(range(count))
    assert all(x['exception'] == '00000000' and int(x['width']) == width for x in rows)
    state = None
    for row in rows:
        if row['repeat'] == '0':
            mode = int(row['mode'])
            state = {'out':bytearray(b'\xA5'*64), 'ret':bytearray(b'\xA5'*64),
                     'og':256 if mode in (6,18) else 0,
                     'rg':256 if mode in (8,17,19) else 0,
                     'crossret':b'\xA5'*4}
        replay(row, width, state)
    guards = [fields(x[12:]) for x in lines if x.startswith('range-guard ')]
    if width == 8:
        assert guards == [dict(role='0',width='8',status=AV,exception=OK,guard='256'),
                          dict(role='1',width='8',status=GUARD,exception=OK,guard='0')]
    else:
        assert not guards
    return count + len(guards)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=HERE.parents[3])
    args = parser.parse_args()
    manifest = json.loads((HERE / 'evidence-hashes.json').read_text())['files']
    names = set()
    for row in manifest:
        name = row['path']
        assert Path(name).name == name and name not in names, name
        names.add(name)
        data = (HERE/name).read_bytes()
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], name
    required = {'README.md', 'check_native_hypervisor_page.py', 'validation.json',
                'source-hashes-reviewed.json', 'native-probe-hashes-reviewed.json',
                'native-owning-archive-hashes.json', 'wow64-wrapper-provenance.json',
                'wow64-pdb-identity.txt', 'native-current-runtime-hashes.json'}
    assert required <= names and 'evidence-hashes.json' not in names
    sources = json.loads((HERE/'source-hashes-reviewed.json').read_text())
    assert len(sources) == 4
    for row in sources:
        data = (args.source_root/row['path']).read_bytes()
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], row['path']
    ref = args.source_root/'docs/specifications/windows/native-processor-features'
    for name, sha in [('phnt-ntexapi.h', '0510ac40fa1690cd73bed8afe3ed602aaa7bb6870ab95ea9aaba36ce1f4c3d53'),
                      ('phnt-LICENSE', 'ad2ab542c56c606e4c19d66a7f3cdcd3ef83beffb638e7c3893b22c7a6a6c0df')]:
        assert hashlib.sha256((ref/name).read_bytes()).hexdigest() == sha, name
    header = (ref/'phnt-ntexapi.h').read_text()
    enum = header.split('typedef enum _SYSTEM_INFORMATION_CLASS', 1)[1].split('} SYSTEM_INFORMATION_CLASS;', 1)[0]
    enum = re.sub(r'/\*.*?\*/|//[^\n]*', '', enum, flags=re.S)
    value, identities = -1, {}
    for line in enum.splitlines():
        match = re.match(r'\s*(System\w+)\s*(?:=\s*(\d+))?\s*,?', line)
        if match:
            value = int(match[2]) if match[2] else value+1
            identities[match[1]] = value
    assert identities['SystemHypervisorSharedPageInformation'] == 197
    declarations = re.sub(r'/\*.*?\*/|//[^\n]*', '', header, flags=re.S)
    assert re.search(r'_SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION\s*\{\s*PSYSTEM_HYPERVISOR_USER_SHARED_DATA\s+HypervisorSharedUserVa;', declarations)
    assert hashlib.sha256((HERE/'native-hypervisor-page-probe.cpp').read_bytes()).hexdigest() == '61ce0759f8e2f6f3fdb072a251ddf6686cc7a8947489b3486dc2c43a2ccdda68'
    producers = json.loads((HERE/'native-probe-hashes-reviewed.json').read_text())
    for profile, machine, laa in [('arm64','0xaa64',True),('x64','0x8664',True),('x86','0x14c',False),('x86-laa','0x14c',True)]:
        prefix = 'native-hypervisor-page-probe-'+profile
        for suffix in ['.log', '-build.log']:
            data = (HERE/(prefix+suffix)).read_bytes()
            row = producers[prefix+suffix]
            assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
        row = producers[prefix+'.exe']
        assert row['pe-machine'] == machine and row['large-address-aware'] == laa
    provenance = json.loads((HERE/'wow64-wrapper-provenance.json').read_text())
    assert (provenance['age'], provenance['pdb-info-age'], provenance['pdb-dbi-age'], provenance['pdb-dbi-flags']) == (1,3,1,2)
    assert provenance['guid'] == '1f6db1e7-82ec-0d6e-7fdc-18da3d1f62db'
    assert provenance['native-capture-bytes'] == 'align_up(u64(length)+4,16)' and provenance['heap-link-node-bytes'] == 16
    identity = (HERE/'wow64-pdb-identity.txt').read_text()
    assert re.search(r'PdbStream:\s*Age:\s*3', identity) and re.search(r'DbiStream:.*?Age:\s*1', identity, re.S)
    assert '{1F6DB1E7-82EC-0D6E-7FDC-18DA3D1F62DB}' in identity
    total = sum(native_profile(p) for p in ['arm64','x64','x86','x86-laa'])
    assert total == 902
    assert '0 passed; 9 failed' in (HERE/'macos-before-portable.log').read_text()
    assert '10 passed; 0 failed' in (HERE/'macos-final-portable.log').read_text()
    assert '10 passed; 1 failed' in (HERE/'macos-budget-reviewed-portable.log').read_text()
    assert '11 passed; 0 failed' in (HERE/'macos-budget-final-portable.log').read_text()
    assert (HERE/'native-hypervisor-before-trace.rs').read_bytes() == (HERE/'native-hypervisor-after-trace.rs').read_bytes()
    before = (HERE/'native-hypervisor-before-trace-output.log').read_text()
    after = (HERE/'native-hypervisor-after-trace-output.log').read_text()
    assert 'terminal turn=33364' in before and 'NtQuerySystemInformation class 197' in before
    assert 'kernel-after turn=33364 service=0x36 PC=0x1800013a4 X0=0x0' in after
    assert 'terminal turn=33566' in after and 'NtQuerySystemInformation class 55' in after
    ordinary = (HERE/'native-hypervisor-after-ordinary-processes.log').read_text()
    assert ordinary.count('STATUS_ACCESS_VIOLATION') == 4 and ordinary.count('opened modules=') == 4
    artifacts = [json.loads(line) for line in (HERE/'native-hypervisor-after-artifacts.jsonl').read_text().splitlines()]
    core = [x for x in artifacts if x.get('reason') == 'compiler-artifact' and x['target']['name'] == 'rax' and not x['manifest_path'].replace('\\','/').endswith('/capi/Cargo.toml')]
    assert len(core) == 1 and core[0]['features'] == []
    archives = json.loads((HERE/'native-owning-archive-hashes.json').read_text())
    assert archives['core-features'] == [] and archives['sources'] == sources
    assert len(archives['archives']) == 2
    assert [x['members'] for x in archives['archives']] == [4673,260]
    assert all(x['structural-member-walk'] == 'pass' for x in archives['archives'])
    assert archives['archives'][1]['path'] in core[0]['filenames']
    validation = json.loads((HERE/'validation.json').read_text())
    assert len(validation['gates']) == 22
    for gate in validation['gates']:
        log = (HERE/gate['path']).read_text()
        for summary in gate.get('expected-summaries', []):
            assert summary in log, gate['path']
        if gate.get('build-success'):
            assert 'Finished `dev`' in log, gate['path']
        if 'required-marker' in gate:
            assert gate['required-marker'] in log, gate['path']
    for host, failures in validation['known-full-suite-failures'].items():
        gate = next(x for x in validation['gates'] if x['host'] == host and x['gate'] == 'full')
        log = (HERE/gate['path']).read_text()
        assert all(name in log for name in failures)
        assert len(failures) == (1 if host == 'linux' else 5)
    for path, count in [('linux-owning-cpp.log',184),('assist-native-hypervisor-owned-cpp.log',182)]:
        log = (HERE/path).read_text()
        for marker in [f'process tool: {count} checks passed', '162 checks passed', 'explicit RAX-disabled refusal passed',
                       'header API = 1.11', '2/2 passed', 'PASS']:
            assert marker in log, (path,marker)
    assert '100% tests passed out of 7' in (HERE/'macos-owning-ctest.log').read_text()
    print(f'Hypervisor page: {len(names)} original inputs, four compiled source hashes, 902 native observations and 22 recorded gates verified')


if __name__ == '__main__':
    main()
