"""Explicit owned artifact selection; full build logs stay in task storage."""
from pathlib import Path
import hashlib
import json
import re
import shutil

HERE = Path(__file__).resolve().parent
DEST = Path('/Users/int/hexrays/kvasir/vendor/rax/docs/specifications/windows/native-bootstrap')


def hashrow(path, name=None):
    data = path.read_bytes()
    return {'path': name or path.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    files = ['README.md', 'assumptions-and-scope.md', 'primary-contracts.md',
             'primary-identities.json', 'baseline.json', 'source-hashes-reviewed.json',
             'native-startup-observations.json', 'native-startup-teb-log-hashes.json',
             'native-loader-entry-observations.json', 'selected-entry-contracts.json',
             'ntdll-fault-provenance.json', 'ntdll-pdb-identity.txt',
             'native-producer-executable-identities.json', 'before-owning-archive-hashes.json',
             'native-owning-archive-hashes.json', 'native-owning-log-hashes.json',
             'native-gate-hashes.json', 'windows-final-driver.log',
             'native-startup-initial-probe.cpp', 'native-startup-probe.cpp',
             'native-loader-entry-probe.cpp', 'native-loader-entry-before-cleanup.cpp',
             'native-loader-entry-before-cleanup-arm64.log',
             'native-loader-entry-before-cleanup-arm64-build.log',
             'baseline-ldr-overlay.json', 'baseline-thread-overlay.json',
             'reviewed-loader-ldr.rs', 'reviewed-process-thread.rs',
             'macos-before-private-loader-test.log', 'macos-before-private-tls-test.log',
             'macos-initial-targeted.log', 'macos-after-loader-targeted.log',
             'native-bootstrap-before-production-trace.rs',
             'native-bootstrap-before-production-trace-output.log',
             'native-bootstrap-before-production-trace-build.log',
             'native-bootstrap-after-production-trace.rs',
             'native-bootstrap-after-production-trace-output.log',
             'native-bootstrap-after-production-trace-build.log',
             'native-bootstrap-after-ordinary-processes.log',
             'native-bootstrap-after-artifacts.jsonl',
             'native-bootstrap-after-artifacts-stderr.log',
             'native-cold-loader-before-trace.rs', 'native-cold-loader-before.ps1',
             'native-cold-loader-before-trace-output.log',
             'native-cold-loader-before-trace-build.log',
             'run-macos.py', 'run-linux.py', 'run-owning-linux.py',
             'native-bootstrap-final.ps1', 'assist-native-bootstrap-owned.ps1',
             'inspect-owning-archives.py', 'assist-cpp-build.py',
             'native-process-probe.cpp', 'owning-linux-cpp-build.py',
             'owning-cpp-helper-hashes.json', 'check_native_bootstrap.py', 'curate.py',
             'replay-negative-checks.json']
    for arch in ('arm64', 'x64', 'x86'):
        for prefix in ('native-startup-probe', 'native-startup-teb-probe', 'native-loader-entry-probe'):
            files.extend(f'{prefix}-{arch}{suffix}' for suffix in ('.ps1', '.log', '-build.log'))
    for name in files:
        shutil.copyfile(HERE / name, DEST / name)
    gates, recorded = [], []
    for host in ('macos', 'linux', 'windows'):
        for gate in ('targeted', 'full', 'capi', 'all-targets', 'integration'):
            name = ('macos-final-' + gate + '-macos.log' if host == 'macos' else
                    'linux-final-' + gate + '.log' if host == 'linux' else
                    'native-bootstrap-final-' + gate + '.log')
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
                          (not line.startswith('test ') or line.startswith('test result:') or ' ... FAILED' in line or 'native_start::' in line)]
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
              ('windows', 'owning-shipping', 'assist-native-bootstrap-owned-shipping.log', ['Finished `dev`']),
              ('windows', 'owning-cpp', 'assist-native-bootstrap-owned-cpp.log', ['PASS', 'RAX process: 162 checks passed', 'embedded rax_version = 1.11.0'])]
    for host, gate, name, markers in owning:
        text = (HERE / name).read_text()
        if not all(x in text for x in markers):
            raise ValueError('owning gate incomplete ' + name)
        shutil.copyfile(HERE / name, DEST / name)
        gates.append({'host': host, 'gate': gate, 'path': name, 'required-markers': markers})
    failures = {}
    for host in ('macos', 'linux', 'windows'):
        name = next(x['path'] for x in gates if x['host'] == host and x['gate'] == 'full')
        failures[host] = sorted(set(re.findall(r'test ([\w:]+) \.\.\. FAILED', (DEST / name).read_text())))
    (DEST / 'validation.json').write_text(json.dumps({'gates': gates, 'full-suite-failures': failures,
        'compiled-root': 'fcf698e3f626572742ddbf761ffdcc1105246787',
        'cpp-compiled-source-base': 'c4cb8f6a0dd7c0d068d2defd411599fba9e32b7e'}, indent=2) + '\n')
    (DEST / 'gate-recording-provenance.json').write_text(json.dumps(recorded, indent=2) + '\n')
    manifest = [hashrow(f) for f in sorted(DEST.iterdir()) if f.is_file() and f.name != 'evidence-hashes.json']
    (DEST / 'evidence-hashes.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('curated', len(manifest) + 1, 'artifacts;', sum(x['bytes'] for x in manifest), 'bytes')


if __name__ == '__main__':
    main()
