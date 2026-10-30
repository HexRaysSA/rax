"""Run the actual signed native RAX ARM64 state-transfer consumer on Apple Silicon."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import struct
import subprocess
import sys
import time
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(directory):
    words = []
    for mode in [0, 4, 5]:
        for current in [0, 1, 0x1111222233334444, (1 << 64) - 1]:
            first = current if mode in [0, 4] else 0x5555666677778888
            second = current if mode == 5 else 0x9999AAAABBBBCCCC
            words.extend([mode, current, current, first, second])
    assert (directory / 'rows.bin').read_bytes() == struct.pack('<60Q', *words)
    assert (directory / 'admission.bin').read_bytes() == struct.pack(
        '<3Q', 0, 1, 0x1234
    )
    assert (directory / 'before.txt').read_bytes() == (
        directory / 'after.txt'
    ).read_bytes()
    text = (directory / 'admission.txt').read_text()
    assert text.startswith('Err(') and 'EL0t' in text
    return dict(
        native_cases=12,
        register_observation_bytes=480,
        admission_observation_bytes=24,
        nonmutating_mode_rejections=1,
        failed=0,
    )


def run_probe(a, temporary):
    root, out = a.repo.resolve(), a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'manifest.json').unlink(missing_ok=True)
    sources = [
        'src/backend/hvf/arm64.rs',
        'src/backend/hvf/arm64_state.rs',
        'src/backend/hvf/arm64_stack.rs',
        'src/backend/hvf/arm64_worker.rs',
        'src/backend/hvf/arm64_bindings.rs',
        'src/backend/hvf/arm64_checkpoint.rs',
        'src/backend/hvf/arm64_checkpoint_api.rs',
        'src/backend/hvf/arm64_context_format.rs',
        'src/backend/hvf/arm64_restore.rs',
        'src/backend/hvf/arm64_vm_checkpoint.rs',
        'src/backend/checkpoint.rs',
        'src/backend/mod.rs',
        'src/vm/vcpu/mod.rs',
        'tools/hvf/arm64_state_native_guest.rs',
        'tools/hvf/arm64_native_state_probe.py',
    ]
    before = {n: sha(root / n) for n in sources}
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(a.target_dir), CARGO_BUILD_JOBS='1')
    commands = []

    def run(name, args, timeout=60):
        start = time.monotonic()
        result = subprocess.run(
            args, cwd=root, env=env, capture_output=True, timeout=timeout
        )
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        commands.append(
            dict(
                name=name,
                args=args,
                code=result.returncode,
                seconds=time.monotonic() - start,
            )
        )
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert result.returncode == 0, (name, result.stderr[-4000:])
        return result

    library = run(
        'library',
        [
            'cargo',
            '+stable',
            'build',
            '--locked',
            '--offline',
            '--no-default-features',
            '--features',
            'x86_64-suite,smir-jit,hvf',
            '--message-format=json',
            '--lib',
        ],
        600,
    )
    artifacts = []
    for line in library.stdout.splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row['target']['name'] == 'rax':
            artifacts.extend(Path(name) for name in row['filenames'] if name.endswith('.rlib'))
    assert len(artifacts) == 1, artifacts
    archive = artifacts[0]
    library_sha256 = sha(archive)
    executable = temporary / 'native-state'
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/hvf/arm64_state_native_guest.rs'),
            '--extern',
            'rax=' + str(archive),
            '-L',
            'dependency=' + str(a.target_dir / 'debug/deps'),
            '-o',
            str(executable),
        ],
    )
    (out / 'entitlements.plist').write_bytes(
        plistlib.dumps({'com.apple.security.hypervisor': True})
    )
    run(
        'sign',
        [
            'codesign',
            '--force',
            '--sign',
            '-',
            '--entitlements',
            str(out / 'entitlements.plist'),
            str(executable),
        ],
    )
    run('verify-sign', ['codesign', '--verify', '--strict', str(executable)])
    run('native', [str(executable), str(out)], 20)
    report = verify(out)
    probes = []
    for name, count in [('rows.bin', 60), ('admission.bin', 3)]:
        path = out / name
        original = path.read_bytes()
        for word in range(count):
            mutant = bytearray(original)
            mutant[word * 8] ^= 1
            path.write_bytes(mutant)
            try:
                try:
                    verify(out)
                except AssertionError:
                    pass
                else:
                    raise RuntimeError(f'Native verifier accepted {name} word {word}')
            finally:
                path.write_bytes(original)
            probes.append(
                dict(
                    file=name,
                    word=word,
                    rejected=True,
                    mutant_sha256=hashlib.sha256(mutant).hexdigest(),
                )
            )
    assert len(probes) == 63 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=63, rejected=63, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in sources}
    assert sha(archive) == library_sha256
    artifacts = [
        'rows.bin',
        'admission.bin',
        'before.txt',
        'after.txt',
        'admission.txt',
        'entitlements.plist',
        'fault-injection.json',
        'commands.json',
    ]
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='native_rax_arm64_sp_transfer_and_mode_admission_match',
                report=report,
                commands=commands,
                source_sha256=before,
                library_sha256=library_sha256,
                linked_library=str(archive),
                native_executable_sha256=sha(executable),
                linked_artifacts_unchanged=True,
                host_machine=platform.machine(),
                artifacts={n: sha(out / n) for n in artifacts},
                scope='Actual signed public native RAX register API backed by a permanent SDK owner;12cases and one nonmutating invalid-mode rejection. Bare register access intentionally permits an unconfigured/unmapped VM. No complete private-state,SDK-failure rollback,worker migration,native retirement-budget or Intel/KVM proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    a = p.parse_args()
    if sys.platform != 'darwin' or platform.machine() not in ['arm64', 'aarch64']:
        print(
            'Native ARM64 HVF state validation requires Apple Silicon macOS.',
            file=sys.stderr,
        )
        raise SystemExit(77)
    temporary_path = None
    try:
        with tempfile.TemporaryDirectory(prefix='rax-arm64-state-') as name:
            temporary_path = Path(name)
            run_probe(a, temporary_path)
    finally:
        a.work_dir.mkdir(parents=True, exist_ok=True)
        (a.work_dir / 'cleanup.json').write_text(json.dumps({
            'temporary_directory': str(temporary_path),
            'removed': temporary_path is not None and not temporary_path.exists(),
            'copied_library_archives': 0,
        }, indent=2) + '\n')


if __name__ == '__main__':
    main()
