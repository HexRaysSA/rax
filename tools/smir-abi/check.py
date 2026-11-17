#!/usr/bin/env python3
"""Run focused ABI checks and write content-bound evidence outside the checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

from witness import compiler, run

ROOT = Path(__file__).resolve().parents[2]
OWNED = [ROOT / 'docs/specifications/smir/portable/03-abi.md',
         ROOT / 'docs/specifications/smir/portable/07-foreign-domains.md']
TREES = ['docs/specifications/smir/portable/schema/abi',
         'docs/specifications/smir/portable/conformance/abi', 'tools/smir-abi']


def dependencies():
    paths=[ROOT/'tools/smir-format/codec.py']
    # The actual ten-root source-data boundary imports SEM/R implementations.
    # Conservatively bind those shared reference modules and active grammars.
    for tree in ('tools/smir-format/execution', 'tools/smir-runtime-contract'):
        paths.extend(path for path in (ROOT / tree).rglob('*.py')
                     if '__pycache__' not in path.parts)
    for tree in ('docs/specifications/smir/portable/schema/execution',
                 'docs/specifications/smir/portable/schema/runtime'):
        paths.extend((ROOT / tree).rglob('*.json'))
    paths.append(ROOT / 'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json')
    for manifest in ('sources.json','candidate-sources.json'):
        document=json.loads((ROOT/'docs/specifications/smir/portable/schema/abi'/manifest).read_text())
        for source in document if isinstance(document,list) else document['sources']:
            relative=source['archive_path'] if 'archive_path' in source else 'references/'+source['path']
            paths.append(ROOT/'docs/specifications/smir/portable'/relative)
    return {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(set(paths))}


def hashes():
    paths = OWNED + [path for tree in TREES for path in (ROOT / tree).rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error('output must be outside the checkout')
    output.mkdir(parents=True, exist_ok=True)
    before = hashes()
    dependencies_before=dependencies()
    canonical = ('function_address.test_execution_compare', 'function_address.test_model')
    test_modules = sorted('.'.join(path.relative_to(ROOT / 'tools/smir-abi').with_suffix('').parts)
                          for path in (ROOT / 'tools/smir-abi').rglob('test_*.py'))
    groups = [dict(name='legacy-and-independent-oracles', cwd=ROOT / 'tools/smir-abi',
                   modules=[name for name in test_modules if name not in canonical]),
              dict(name='genuine-canonical-source-calls', cwd=ROOT / 'tools/smir-abi',
                   modules=list(canonical))]
    argv = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SMIR_ABI_TMP=str(output))
    runs = []
    for group in groups:
        command = [sys.executable, '-B', '-m', 'unittest', *group['modules'], '-v']
        result = subprocess.run(command, cwd=group['cwd'], env=env, capture_output=True, text=True)
        runs.append(dict(name=group['name'], argv=command, cwd=str(group['cwd']),
                         exit_code=result.returncode, log=result.stdout + result.stderr))
        argv.append(command)
    log = ''.join('GROUP ' + run['name'] + '\n' + run['log'] for run in runs)
    exit_code = next((run['exit_code'] for run in runs if run['exit_code'] != 0), 0)
    (output / 'tests.log').write_text(log)
    counts = re.findall(r'Ran (\d+) tests?', log)
    tests = sum(map(int, counts))
    complete_groups = len(counts) == len(groups) and all(int(count) > 0 for count in counts)
    skipped = sum(1 for line in log.splitlines() if ' ... skipped ' in line)
    failed = sum(1 for line in log.splitlines() if line.startswith(('FAIL:', 'ERROR:')))
    clang, version = compiler()
    witness = None
    witness_error = None
    if exit_code == 0 and tests > 0 and complete_groups:
        try:
            witness = run(output / 'compiler')
            (output / 'compiler-witness.json').write_text(json.dumps(witness, indent=2) + '\n')
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            witness_error = str(error)
    after = hashes()
    dependencies_after=dependencies()
    cxx=env.get('CXX','/usr/bin/clang++' if sys.platform=='darwin' else 'clang++')
    cxx_path=shutil.which(cxx)
    cxx_version=subprocess.check_output([cxx,'--version'],text=True)
    header_delta=subprocess.check_output(['git','-C','/Users/int/dev/llvm-project','diff',
        '36763294ef639d8a6a4379d81da653dda1c20686','--name-only','--','libcxx/include'],text=True).splitlines()
    passed = (exit_code == 0 and tests > 0 and complete_groups and skipped == failed == 0 and
              before == after and dependencies_before==dependencies_after and not header_delta and witness is not None)
    receipt = {
        'revision': 'abi-validation-receipt-candidate-v3', 'passed': passed,
        'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'argv': argv, 'cwd': str(ROOT),
        'test_groups': [{key: value for key, value in run.items() if key != 'log'} for run in runs],
        'environment': {'PYTHONDONTWRITEBYTECODE': '1', 'SMIR_ABI_TMP': str(output),
                        'python': sys.version, 'host': platform.platform(),
                        'compiler': clang, 'compiler_version': version,
                        'compiler_sha256': hashlib.sha256(Path(clang).read_bytes()).hexdigest(),
                        'native_cxx':cxx_path,'native_cxx_version':cxx_version,
                        'native_cxx_sha256':hashlib.sha256(Path(cxx_path).read_bytes()).hexdigest(),
                        'llvm_header_delta_from_pin':header_delta},
        'tests': {'run': tests, 'failed': failed, 'skipped': skipped,
                  'successful_run': tests if passed else None, 'exit_code': exit_code},
        'tests_log_sha256': hashlib.sha256(log.encode()).hexdigest(),
        'artifacts': after, 'files_changed_during_check': before != after,
        'dependencies':dependencies_after,'dependencies_changed_during_check':dependencies_before!=dependencies_after,
        'witness_error': witness_error,
        'scope': ['independent C object equations', 'pinned existing-target layout compilation',
                  'three independent ordered decoders', 'source/execution/storage/capture verification',
                  'synthetic native domain/type/layout/unwind evidence validation',
                  'sequential construction/object-lifetime/varargs/fenv protocols',
                  'native host C++ cleanup/catch/exception_ptr/flag/object lifetime witnesses'],
        'not_proven': ['SMIR frontend', 'SMIR guest interpretation or JIT', 'parallel RAX runtime',
                       'generated bridges', 'DWARF/SEH unwind', 'compiler freeze'],
    }
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f"ABI focused checks: {tests} tests; {failed} failures; {skipped} skips; "
          f"{'PASS' if passed else 'FAIL'}")
    if not passed:
        print(log, file=sys.stderr)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
