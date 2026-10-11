"""Explicit owned artifact selection; full build logs stay in task storage."""
from pathlib import Path
import hashlib
import json
import re
import shutil

HERE = Path(__file__).resolve().parent
DEST = Path('/Users/int/hexrays/kvasir/vendor/rax/docs/specifications/windows/native-numa-node')


def hashrow(path, name=None):
    data = path.read_bytes()
    return {'path': name or path.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    files = ['README.md', 'task-contract.md', 'primary-contracts.md', 'task-baseline.json', 'source-hashes-reviewed.json', 'startup-sources-preserved.json', 'capture-identities.json', 'capture-status.json', 'native-executable-identities.json', 'wow64-wrapper-provenance.json', 'wow-conversion-boundary-observations.json', 'capture-native-identities.py', 'native-numa-node-probe.cpp', 'macos-red-baseline.log', 'macos-red-extended-baseline.log', 'macos-first-targeted.log', 'native-numa-node-before-production-trace.rs', 'native-numa-node-before-production-trace-output.log', 'native-numa-node-before-ordinary-processes.log', 'before-owning-archive-hashes.json', 'native-numa-node-after-production-trace.rs', 'native-numa-node-after-production-trace-output.log', 'native-numa-node-after-production-trace-build.log', 'native-numa-node-after-ordinary-processes.log', 'native-numa-node-after-artifacts.jsonl', 'native-numa-node-after-artifacts-stderr.log', 'native-owning-archive-hashes.json', 'native-owning-log-hashes.json', 'native-gate-hashes.json', 'windows-final-driver.log', 'run-macos.py', 'run-linux.py', 'run-owning-linux.py', 'native-numa-node-final.ps1', 'assist-native-numa-node-owned.ps1', 'inspect-owning-archives.py', 'assist-cpp-build.py', 'native-process-probe.cpp', 'owning-linux-cpp-build.py', 'owning-cpp-helper-hashes.json', 'native_replay.py', 'check_native_numa_node.py', 'curate.py', 'replay-negative-checks.json', 'native-numa-node-probe-arm64.ps1', 'native-numa-node-probe-arm64.log', 'native-numa-node-probe-arm64-build.log', 'native-numa-node-probe-x64.ps1', 'native-numa-node-probe-x64.log', 'native-numa-node-probe-x64-build.log', 'native-numa-node-probe-x86.ps1', 'native-numa-node-probe-x86.log', 'native-numa-node-probe-x86-build.log', 'native-numa-node-probe-x86-laa.ps1', 'native-numa-node-probe-x86-laa.log', 'native-numa-node-probe-x86-laa-build.log']
    files += ['native-numa-node-isolated-clock.ps1', 'windows-isolated-clock-driver.log']
    for name in files:
        shutil.copyfile(HERE / name, DEST / name)
    gates, recorded = [], []
    for host in ('macos', 'linux', 'windows'):
        for gate in ('targeted', 'full', 'capi', 'all-targets', 'integration'):
            name = ('macos-final-' + gate + '-macos.log' if host == 'macos' else
                    'linux-final-' + gate + '.log' if host == 'linux' else
                    'native-numa-node-final-' + gate + '.log')
            text = (HERE / name).read_text()
            row = {'host': host, 'gate': gate, 'path': name,
                   'expected-summaries': re.findall(r'test result: .*', text)}
            if gate == 'all-targets':
                if 'Finished `dev`' not in text:
                    raise ValueError('missing all-targets success ' + name)
                row['required-markers'] = ['Finished `dev`']
            gates.append(row)
            # Keep exact selected status/failure/count lines and bounded build
            # metadata. Original full log SHA/length remain explicit provenance.
            if gate == 'full':
                lines = text.splitlines()
                chosen = [line for line in lines if line.startswith(('    Finished', '     Running', 'running ', 'test result:', 'test ')) and
                          (not line.startswith('test ') or line.startswith('test result:') or ' ... FAILED' in line or 'numa_node_tests::' in line)]
                chosen.extend(line for line in lines if line.startswith('    smir::') or line.startswith('error: test failed'))
                output = '\n'.join(chosen) + '\n'
            else:
                output = text
            if gate == 'full':
                (DEST / name).write_text(output)
            else:
                shutil.copyfile(HERE / name, DEST / name)
            recorded.append({'recorded': hashrow(DEST / name), 'original': hashrow(HERE / name), 'full-log-retained-in-task-storage': True})
    owning = [('macos', 'owning-build', 'macos-owning-build.log', ['Built target assist_idalib_cli', 'Static text scan: 1 artifacts, 0 failures']),
              ('macos', 'owning-ctest', 'macos-owning-ctest.log', ['100% tests passed out of 7']),
              ('linux', 'owning-shipping', 'linux-owning-shipping.log', ['Finished `dev`']),
              ('linux', 'owning-cpp', 'linux-owning-cpp.log', ['PASS', 'RAX process: 162 checks passed', 'embedded rax_version = 1.11.0']),
              ('windows', 'owning-shipping', 'assist-native-numa-node-owned-shipping.log', ['Finished `dev`']),
              ('windows', 'owning-cpp', 'assist-native-numa-node-owned-cpp.log', ['PASS', 'RAX process: 162 checks passed', 'embedded rax_version = 1.11.0'])]
    for host, gate, name, markers in owning:
        text = (HERE / name).read_text()
        if not all(x in text for x in markers):
            raise ValueError('owning gate incomplete ' + name)
        shutil.copyfile(HERE / name, DEST / name)
        gates.append({'host': host, 'gate': gate, 'path': name, 'required-markers': markers})
    name = 'linux-isolated-timeout.log'
    text = (HERE / name).read_text()
    if 'test result: ok. 1 passed; 0 failed' not in text:
        raise ValueError('isolated timeout check incomplete')
    shutil.copyfile(HERE / name, DEST / name)
    gates.append({'host': 'linux', 'gate': 'isolated-timeout', 'path': name,
                  'required-markers': ['a_multishot_timeout_reports_each_expiry ... ok',
                                       'test result: ok. 1 passed; 0 failed']})
    name = 'native-numa-node-isolated-clock.log'
    text = (HERE / name).read_text()
    if 'test result: ok. 1 passed; 0 failed' not in text:
        raise ValueError('isolated native clock check incomplete')
    shutil.copyfile(HERE / name, DEST / name)
    gates.append({'host': 'windows', 'gate': 'isolated-clock', 'path': name,
                  'required-markers': ['native_thread_clock_excludes_another_threads_work ... ok',
                                       'test result: ok. 1 passed; 0 failed']})
    failures = {}
    for host in ('macos', 'linux', 'windows'):
        name = next(x['path'] for x in gates if x['host'] == host and x['gate'] == 'full')
        failures[host] = sorted(set(re.findall(r'test ([\w:]+) \.\.\. FAILED', (DEST / name).read_text())))
    (DEST / 'validation.json').write_text(json.dumps({'gates': gates, 'full-suite-failures': failures,
        'compiled-root': '125715f13b78fd696cb10dd5b767beee29fc3af9',
        'cpp-compiled-source-base': 'c4cb8f6a0dd7c0d068d2defd411599fba9e32b7e'}, indent=2) + '\n')
    (DEST / 'gate-recording-provenance.json').write_text(json.dumps(recorded, indent=2) + '\n')
    manifest = [hashrow(f) for f in sorted(DEST.iterdir()) if f.is_file() and f.name != 'evidence-hashes.json']
    (DEST / 'evidence-hashes.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('curated', len(manifest) + 1, 'artifacts;', sum(x['bytes'] for x in manifest), 'bytes')


if __name__ == '__main__':
    main()
