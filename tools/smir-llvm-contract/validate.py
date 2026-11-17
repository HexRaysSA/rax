#!/usr/bin/env python3
"""Run focused witnesses and bind observations to artifact/tool hashes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNED = [
    ROOT / 'docs/specifications/smir/portable/09-llvm.md',
    ROOT / 'docs/specifications/smir/portable/llvm',
    ROOT / 'docs/specifications/smir/portable/conformance/llvm',
    ROOT / 'tools/smir-llvm-contract',
]
INPUTS = [
    ROOT / 'docs/specifications/smir/portable/schema/execution/candidate.json',
    ROOT / 'docs/specifications/smir/portable/schema/runtime/helpers-v1.json',
    ROOT / 'docs/specifications/smir/portable/schema/runtime/candidate.json',
    ROOT / 'docs/specifications/smir/portable/schema/abi/candidate.json',
    ROOT / 'docs/specifications/smir/portable/schema/abi/site.json',
    ROOT / 'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json',
    ROOT / 'tools/smir-format/codec.py',
    *[ROOT / 'tools/smir-format/execution' / name for name in
      ('test_candidate.py','test_candidate_context.py','test_candidate_initializers.py',
       'test_candidate_memory.py','test_candidate_storage_join.py')],
    ROOT / 'tools/smir-format/execution/test_candidate_weak_initializers.py',
    ROOT / 'tools/smir-format/execution/test_candidate_journal_factory.py',
    ROOT / 'tools/smir-format/execution/test_candidate_eh_bindings.py',
    ROOT / 'tools/smir-format/execution/common.py',
    *[ROOT / 'tools/smir-format/execution/candidate' / name
      for name in ('__init__.py','bindings.py','context.py','fenv.py','fp.py','initializers.py','live.py','layouts.py','machine.py','memory.py','schema_build.py',
                   'operations.py','pure.py','raw.py','ranges.py','type_system.py','values.py','verify.py','wire.py')],
    *[ROOT / 'tools/smir-format/execution' / name
      for name in ('evaluate.py','floating.py','verify.py')],
    *[ROOT / 'docs/specifications/smir/portable/schema/execution' / name
      for name in ('records.json','exceptions.json','types.json')],
    *[ROOT / 'tools/smir-runtime-contract/candidate' / name
      for name in ('__init__.py','comdat.py','errors.py','helpers.py','wire.py','initialization.py',
                   'lifetimes.py','linking.py','partials.py','relocations.py','requirements.py','reservations.py',
                   'selection.py','services.py','startup.py')],
    ROOT / 'docs/specifications/smir/portable/conformance/abi/candidate/complete.json',
    *[ROOT / 'tools/smir-abi' / name for name in ('nominal.py','graph_identity.py','layout.py','c_boundary.py','call_interfaces.py',
        'candidate.py','candidate_codec.py','construction.py','contract_json.py','namespaces.py',
        'native_contract.py','site_config.py','storage_binding.py')],
    ROOT / 'tools/smir-abi/execution_shapes.py',
    ROOT / 'tools/smir-abi/function_address/errors.py',
    ROOT / 'tools/smir-format/execution/candidate/source_call_projection.py',
    ROOT / 'tools/smir-format/execution/candidate/source_registry_projection.py',
    ROOT / 'tools/smir-runtime-contract/source_roles/__init__.py',
    *[ROOT / 'tools/smir-abi/record_layout' / name
      for name in ('__init__.py','checked.py','model.py','vtable.py')],
    *[ROOT / 'tools/smir-abi/source_roles' / name for name in ('__init__.py','model.py','builder.py')],
]


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def snapshot(roots):
    result = []
    for root in roots:
        paths = [root] if root.is_file() else sorted(root.rglob('*'))
        for path in paths:
            if path.is_file() and '__pycache__' not in path.parts:
                result.append(dict(path=str(path.relative_to(ROOT)), sha256=sha(path), bytes=path.stat().st_size))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    # Keep generated Python caches out of a shared checkout and hash only the
    # actual owned source/fixtures, never test outputs in coordination storage.
    sys.dont_write_bytecode = True
    owned_before, inputs_before = snapshot(OWNED), snapshot(INPUTS)
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tools/smir-llvm-contract'), pattern='test_*.py')
    for name in ('record_layout', 'source_roles'):
        directory = ROOT / 'tools/smir-llvm-contract' / name
        suite.addTests(unittest.TestLoader().discover(str(directory), pattern='test_*.py',
                                                      top_level_dir=str(directory)))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    llvm = Path(os.environ.get('SMIR_LLVM_ROOT', '/Users/int/dev/llvm-project'))
    binary_root = Path(os.environ.get('SMIR_LLVM_BIN', str(llvm / 'build/bin')))
    binaries = []
    for name in ('clang', 'clang++', 'opt', 'llvm-tblgen'):
        path = binary_root / name
        version = subprocess.run([str(path), '--version'], capture_output=True, text=True, check=True)
        binaries.append(dict(path=str(path), realpath=str(path.resolve()),
                             sha256=sha(path), version=version.stdout.strip()))
    artifacts, inputs_after = snapshot(OWNED), snapshot(INPUTS)
    watched = {entry['path'] for entry in owned_before + inputs_before}
    consumed_modules = sorted({str(Path(module.__file__).resolve().relative_to(ROOT))
        for module in sys.modules.values()
        if isinstance(getattr(module, '__file__', None), str)
        and Path(module.__file__).resolve().is_relative_to(ROOT)
        and Path(module.__file__).suffix == '.py'})
    unwatched_modules = sorted(set(consumed_modules) - watched)
    stable = owned_before == artifacts and inputs_before == inputs_after and not unwatched_modules
    passed = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
    receipt = dict(
        revision='llvm-local-witness-receipt-v2',
        observed_at=datetime.now(timezone.utc).isoformat(),
        argv=[sys.executable, '-B', str(Path(__file__).resolve()), '--receipt', str(args.receipt)],
        cwd=str(ROOT),
        rax_head=subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        llvm_head=subprocess.check_output(['git', '-C', str(llvm), 'rev-parse', 'HEAD'], text=True).strip(),
        host=dict(system=platform.system(), machine=platform.machine(), python=sys.version,
                  sdk=subprocess.check_output(['/usr/bin/xcrun','--show-sdk-path'],text=True).strip()
                      if sys.platform=='darwin' else None),
        tests=dict(run=result.testsRun, passed=passed, failures=len(result.failures),
                   errors=len(result.errors), skipped=len(result.skipped)),
        limitations=['No portable SMIR execution or LLVM emission',
                     'opt is an independently identified subset oracle; not pinned LLVM24',
                     'Existing x86-64 Clang ABI subset, not SMIR TargetInfo',
                     'Finite deterministic undef/freeze refinements, not universal proof',
                     'Native host execution covers LLVM-only power, controlled-primitives source and C-provider/C++-consumer probes; no native guest/JIT qualification',
                     'Stage W source function-address/AST/IR witnesses do not prove portable origins, ISO character-copy legality or helper execution',
                     'No hosted sysroot, foreign EH or six-host qualification',
                     'Actual component witness admits SEM roots before projection and independently normalizes runtime bytes; not whole-module admission or LLVM emission'],
        compiler_freeze_passed=False, tools=binaries, artifacts=artifacts,
        native_termination_observations=__import__('termination_witness').OBSERVATIONS,
        native_coroutine_observations=__import__('coroutine_host').OBSERVATIONS,
        source_function_address_observations=__import__('test_fnaddr').OBSERVATIONS,
        source_inputs_stable=stable, inputs_before=inputs_before, inputs_after=inputs_after,
        consumed_python_modules=consumed_modules, unwatched_python_modules=unwatched_modules,
        owned_before=owned_before,
    )
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt['tests'], sort_keys=True))
    return 0 if result.wasSuccessful() and stable else 1


if __name__ == '__main__':
    sys.exit(main())
