#!/usr/bin/env python3
"""Verify original NUMA captures, frozen sources, owning archives and recorded gates."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from native_replay import fields, profile, require

HERE = Path(__file__).resolve().parent


def rows(path):
    return json.loads(path.read_text())


def hashed(path, item):
    data = path.read_bytes()
    require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'].lower(), 'byte identity ' + str(path))


def main():
    require(not sys.flags.optimize, 'optimized validation rejected')
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=HERE.parents[3])
    args = parser.parse_args()
    required = {'native-numa-node-probe-x86-laa.log', 'native-numa-node-before-ordinary-processes.log', 'native-numa-node-probe-x86.log', 'native-numa-node-after-artifacts.jsonl', 'native-owning-archive-hashes.json', 'macos-red-baseline.log', 'linux-final-capi.log', 'README.md', 'task-baseline.json', 'run-owning-linux.py', 'native-numa-node-after-production-trace-build.log', 'native-numa-node-probe-arm64.ps1', 'linux-owning-cpp.log', 'macos-final-targeted-macos.log', 'macos-red-extended-baseline.log', 'native-numa-node-probe-x64-build.log', 'native-numa-node-isolated-clock.log', 'assist-native-numa-node-owned-cpp.log', 'native-numa-node-after-artifacts-stderr.log', 'macos-final-all-targets-macos.log', 'capture-native-identities.py', 'macos-final-capi-macos.log', 'task-contract.md', 'native-numa-node-final-full.log', 'native-numa-node-isolated-clock.ps1', 'macos-owning-build.log', 'native-numa-node-final.ps1', 'native-numa-node-final-integration.log', 'macos-final-integration-macos.log', 'native-numa-node-before-production-trace.rs', 'native-numa-node-probe-x64.ps1', 'native-owning-log-hashes.json', 'native-numa-node-probe-x86-laa.ps1', 'linux-isolated-timeout.log', 'source-hashes-reviewed.json', 'owning-cpp-helper-hashes.json', 'native-numa-node-final-all-targets.log', 'run-macos.py', 'macos-owning-ctest.log', 'gate-recording-provenance.json', 'replay-negative-checks.json', 'native-numa-node-after-production-trace.rs', 'native-executable-identities.json', 'native-numa-node-final-targeted.log', 'native-numa-node-probe-x64.log', 'startup-sources-preserved.json', 'linux-final-all-targets.log', 'capture-status.json', 'linux-final-integration.log', 'windows-final-driver.log', 'run-linux.py', 'native-numa-node-probe-arm64-build.log', 'assist-native-numa-node-owned-shipping.log', 'native-numa-node-probe-x86-laa-build.log', 'assist-cpp-build.py', 'macos-first-targeted.log', 'owning-linux-cpp-build.py', 'native-gate-hashes.json', 'wow-conversion-boundary-observations.json', 'validation.json', 'native-numa-node-probe-arm64.log', 'inspect-owning-archives.py', 'native-numa-node-after-ordinary-processes.log', 'linux-final-targeted.log', 'check_native_numa_node.py', 'native-numa-node-probe-x86-build.log', 'curate.py', 'capture-identities.json', 'macos-final-full-macos.log', 'linux-final-full.log', 'assist-native-numa-node-owned.ps1', 'native-numa-node-probe-x86.ps1', 'native-numa-node-final-capi.log', 'primary-contracts.md', 'native-process-probe.cpp', 'native-numa-node-before-production-trace-output.log', 'native-numa-node-probe.cpp', 'before-owning-archive-hashes.json', 'windows-isolated-clock-driver.log', 'wow64-wrapper-provenance.json', 'native-numa-node-after-production-trace-output.log', 'native_replay.py', 'linux-owning-shipping.log'}
    manifest = rows(HERE / 'evidence-hashes.json')
    names = {item['path'] for item in manifest}
    require(len(names) == len(manifest) and names == required, 'complete mandatory manifest')
    for item in manifest:
        require(Path(item['path']).name == item['path'], 'nonlocal manifest path')
        hashed(HERE / item['path'], item)
    owned = rows(HERE / 'source-hashes-reviewed.json')
    preserved = rows(HERE / 'startup-sources-preserved.json')
    require(len(owned) == 4 and len(preserved) == 8, 'source surface count')
    for item in owned + preserved:
        hashed(args.source_root / item['path'], item)
    ref = args.source_root / 'docs/specifications/windows/native-processor-features'
    for name, sha in [('phnt-ntexapi.h', '0510ac40fa1690cd73bed8afe3ed602aaa7bb6870ab95ea9aaba36ce1f4c3d53'),
                      ('phnt-LICENSE', 'ad2ab542c56c606e4c19d66a7f3cdcd3ef83beffb638e7c3893b22c7a6a6c0df')]:
        require(hashlib.sha256((ref / name).read_bytes()).hexdigest() == sha, 'pinned primary reference ' + name)
    header = (ref / 'phnt-ntexapi.h').read_text()
    require('SystemLogicalProcessorAndGroupInformation,' in header and re.search(r'NtQuerySystemInformationEx\([^;]+PULONG ReturnLength\s*\);', header), 'primary six-argument signature')
    enum = header.split('typedef enum _SYSTEM_INFORMATION_CLASS', 1)[1].split('} SYSTEM_INFORMATION_CLASS;', 1)[0]
    enum = re.sub(r'/\*.*?\*/|//[^\n]*', '', enum, flags=re.S)
    value, classes = -1, {}
    for line in enum.splitlines():
        match = re.match(r'\s*(System\w+)\s*(?:=\s*(\d+))?\s*,?', line)
        if match:
            value = int(match[2]) if match[2] else value + 1
            classes[match[1]] = value
    require(classes['SystemLogicalProcessorAndGroupInformation'] == 107, 'class identity')
    counts = [profile(HERE, arch) for arch in ('arm64', 'x64', 'x86', 'x86-laa')]
    require(sum(x[0] for x in counts) == 1402 and sum(x[1] for x in counts) == 1346, 'original/replay observation coverage')
    captures = rows(HERE / 'capture-identities.json')
    require(len(captures) == 4 and {x['profile'] for x in captures} == {'arm64','x64','x86','x86-laa'}, 'capture identities')
    for item in captures: hashed(HERE / item['path'], item)
    identity = rows(HERE / 'native-executable-identities.json')
    require(len(identity['sources']) == 1, 'native producer count')
    producer = identity['sources'][0]
    hashed(HERE / 'native-numa-node-probe.cpp', producer)
    require(producer['sha256'] == '69a0fb52fc44e4cf44ec21d357e57f7906d4d4f575643545992ed889fd40552f', 'native producer identity')
    exes = identity['executables']
    require(len(exes) == 4 and {x['arch'] for x in exes} == {'arm64','x64','x86','x86-laa'}, 'compiled native profiles')
    for item in exes:
        machine = '0xaa64' if item['arch']=='arm64' else '0x8664' if item['arch']=='x64' else '0x14c'
        require(item['machine'] == machine and item['large-address-aware'] == (item['arch'] != 'x86'), 'native executable machine/LAA')
    wrapper = rows(HERE / 'wow64-wrapper-provenance.json')
    require(wrapper['guid'] == '1f6db1e7-82ec-0d6e-7fdc-18da3d1f62db' and wrapper['age'] == wrapper['pdb-dbi-age'] == 1 and wrapper['pdb-info-age'] == 3, 'matching PDB identity/ages')
    require(wrapper['converter-symbol'] == 'whNT32ThunkSystemLogicalProcessorInformationEx' and wrapper['numa-body-rva'] == '0x9CA8', 'selected native converter')
    offsets = [(x['offset'],x['bytes']) for x in wrapper['ordered-stores']]
    require(offsets == [(8,4),(12,16),(28,2),(30,2),(32,8),(40,4),(36,2),(32,4),(0,8),('ReturnLength',4)], 'native store order')
    for filename, relationship in [('macos-red-baseline.log',1),('macos-red-extended-baseline.log',6)]:
        text = (HERE / filename).read_text()
        require(f'class 107 relationship {relationship}' in text and '0 passed; 1 failed' in text, 'observed missing baseline')
    require((HERE / 'native-numa-node-before-production-trace.rs').read_bytes() == (HERE / 'native-numa-node-after-production-trace.rs').read_bytes(), 'ordinary observer changed')
    before = (HERE / 'native-numa-node-before-production-trace-output.log').read_text()
    require('terminal turn=40500' in before and 'class 107 relationship 6' in before, 'production baseline frontier')
    after = (HERE / 'native-numa-node-after-production-trace-output.log').read_text()
    require('kernel-after turn=40500 service=0x16e PC=0x180002724 X0=0xc0000004' in after and 'kernel-after turn=41325 service=0x16e PC=0x180002724 X0=0x0' in after and 'terminal turn=42051' in after and 'NtCreateIoCompletion (0xb2)' in after and 'exception-before' not in after, 'production continuation evidence')
    ordinary = (HERE / 'native-numa-node-after-ordinary-processes.log').read_text()
    require(ordinary.count('run reason=5 exit=0') == 4 and ordinary.count('diagnostic="emulator failure: native NTDLL service NtCreateIoCompletion (0xb2)') == 4, 'ordinary programs outcome identity')
    artifact_rows = [json.loads(line) for line in (HERE / 'native-numa-node-after-artifacts.jsonl').read_text().splitlines()]
    core = [x for x in artifact_rows if x.get('reason') == 'compiler-artifact' and x['target']['name'] == 'rax' and not x['manifest_path'].replace('\\','/').endswith('/capi/Cargo.toml')]
    require(len(core) == 1 and core[0]['features'] == [], 'current owning empty-feature core')
    archives = rows(HERE / 'native-owning-archive-hashes.json')
    require(archives['core-features'] == [] and archives['sources'] == owned + preserved, 'native source/feature identity')
    require(len(archives['archives']) == 2 and all(x['members']>0 and x['structural-member-walk']=='pass' for x in archives['archives']), 'complete owning archive walks')
    require(any(x['path'] in core[0]['filenames'] for x in archives['archives']), 'inspected current artifact')
    helpers = rows(HERE / 'owning-cpp-helper-hashes.json')
    require(archives['helpers'] == helpers[:2], 'actual native owning C++ helpers')
    for item in helpers: hashed(HERE / item['path'], item)
    validation = rows(HERE / 'validation.json')
    gates = validation['gates']
    require(len(gates) == 23 and len({(x['host'],x['gate']) for x in gates}) == 23, 'required gate selection')
    for gate in gates:
        require(gate['path'] in names, 'missing gate input')
        text = (HERE / gate['path']).read_text()
        for marker in gate.get('expected-summaries',[]) + gate.get('required-markers',[]):
            require(marker in text, 'recorded gate marker ' + gate['path'])
    failures = validation['full-suite-failures']
    prior_failures = ['smir::lower::aarch64::tests::bit::'+suffix for suffix in
       ['lowers_bzhi_x_imm_index_at_width_with_flags_sets_carry','lowers_bzhi_x_two_imms_all_ones_with_flags_as_movn_sets_carry',
        'lowers_bzhi_x_two_imms_with_flags_sets_carry','lowers_bzhi_x_with_flags_and_low_byte_index_guards']]
    prior_failures += ['smir::lower::aarch64::tests::vector::lowers_vector_fp16_arithmetic_runtime']
    require(failures == {'macos': [], 'linux': ['user::linux::tests::uring::timeout::a_multishot_timeout_reports_each_expiry'], 'windows': sorted(prior_failures + ['user::clock::tests::native_thread_clock_excludes_another_threads_work'])}, 'exact full-suite failure boundaries')
    negatives = rows(HERE / 'replay-negative-checks.json')
    require(len(negatives)==4 and {x['probe'] for x in negatives}==
            {'missing-manifest-entry','changed-original','independent-status-replay','optimized-validation'} and
            all(x['exit'] != 0 for x in negatives), 'recorded rejection probes')
    print(f'NUMA node: {len(manifest)} inputs, 4 owned/8 preserved source hashes, 1402 original/1346 replayed observations, 23 recorded gates verified')


if __name__ == '__main__':
    main()
