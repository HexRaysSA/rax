"""Validate native RAX ARM64 MMIO transactions on Apple Silicon."""

import argparse
import hashlib
import json
import os
import platform
import plistlib
import struct
import subprocess
import sys
import time
import tempfile
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected():
    rows = bytearray()
    base, seed = 0x40000000, 0x1122334455667788
    configs = [
        (1, 0, 0),
        (1, 1, 0),
        (1, 1, 1),
        (2, 0, 0),
        (2, 1, 0),
        (2, 1, 1),
        (4, 0, 0),
        (4, 1, 1),
        (8, 0, 1),
    ]
    for case, (size, signed, wide) in enumerate(configs):
        modulus = 256**size
        sign = modulus // 2
        for destination, rt in enumerate([0, 31]):
            pc = base + (case * 2 + destination) * 16
            for pattern, value in enumerate(
                [0, 1, modulus - 1, sign, sign - 1, 0x8877665544332211 % modulus]
            ):
                result = value - modulus if signed and value >= sign else value
                result %= 2 ** (64 if wide else 32)
                for stage in range(7):
                    kind = 1 if stage in [0, 2, 4] else 2 if stage == 6 else 0
                    rows.extend(
                        struct.pack(
                            '<12Q',
                            case,
                            rt,
                            pattern,
                            stage,
                            kind,
                            0x09000000 if kind == 1 else 0,
                            size if kind == 1 else 0,
                            result if stage >= 5 and rt == 0 else seed,
                            99 if stage == 6 else 0,
                            0x200 if stage == 6 else pc + 4,
                            0x4003C5 if stage == 6 else 0x3C5,
                            base + 0x3FF0,
                        )
                    )
    for stage in range(8, 13):
        kind = 1 if stage == 9 else 2 if stage == 12 else 0
        rows.extend(
            struct.pack(
                '<12Q',
                99,
                0,
                0,
                stage,
                kind,
                0x09000000 if kind == 1 else 0,
                8 if kind == 1 else 0,
                seed if stage < 10 else 0xAABBCCDDEEFF0011,
                99 if stage == 12 else 0,
                0x200 if stage == 12 else base + 16 * 16 + 4,
                0x4003C5 if stage == 12 else 0x3C5,
                base + 0x3FF0,
            )
        )
    assert len(rows) == 73056
    return bytes(rows)


def verify(directory):
    actual, want = (directory / 'rows.bin').read_bytes(), expected()
    if actual != want:
        for i, (got, gold) in enumerate(
            zip(struct.iter_unpack('<12Q', actual), struct.iter_unpack('<12Q', want))
        ):
            assert got == gold, (i, got, gold)
        assert actual == want, (len(actual), len(want))
    assert (directory / 'admission.txt').read_text().startswith('Err(')
    return {
        'native_load_cases': 108,
        'load_configurations': 9,
        'destination_registers': 2,
        'data_patterns': 6,
        'observations': 761,
        'observation_bytes': 73056,
        'incomplete_reply_attempts': 216,
        'repeated_pending_exits': 216,
        'state_replacement_cases': 1,
        'failed': 0,
    }


def run_probe(a, temporary):
    root, out = a.repo.resolve(), a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'manifest.json').unlink(missing_ok=True)
    sources = [
        'src/backend/hvf/arm64.rs',
        'src/backend/hvf/arm64_mmio.rs',
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
        'src/backend/hvf/mod.rs',
        'tools/hvf/arm64_mmio_native_guest.rs',
        'tools/hvf/arm64_mmio_native_probe.py',
    ]
    before = {n: sha(root / n) for n in sources}
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(a.target_dir), CARGO_BUILD_JOBS='1')
    commands = []

    def run(name, args, timeout=60):
        start = time.monotonic()
        r = subprocess.run(
            args, cwd=root, env=env, capture_output=True, check=False, timeout=timeout
        )
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        commands.append(
            {
                'name': name,
                'args': args,
                'code': r.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert r.returncode == 0, (name, r.stderr[-4000:])
        return r

    instructions = [
        ('ldrb', 'w'),
        ('ldrsb', 'w'),
        ('ldrsb', 'x'),
        ('ldrh', 'w'),
        ('ldrsh', 'w'),
        ('ldrsh', 'x'),
        ('ldr', 'w'),
        ('ldrsw', 'x'),
        ('ldr', 'x'),
    ]
    assembly = '.text\n.global _start\n_start:\n'
    for mnemonic, width in instructions:
        for rt in ['0', 'zr']:
            assembly += f' {mnemonic} {width}{rt}, [x1]\n mov x10, #99\n brk #0\n nop\n'
    (out / 'guest.s').write_text(assembly)
    run(
        'assemble',
        [
            str(a.llvm_bin / 'llvm-mc'),
            '-triple=aarch64-none-elf',
            '-filetype=obj',
            str(out / 'guest.s'),
            '-o',
            str(out / 'guest.o'),
        ],
    )
    run(
        'link',
        [
            str(a.llvm_bin / 'ld.lld'),
            '-m',
            'aarch64elf',
            '-Ttext=0x40000000',
            '--entry=_start',
            str(out / 'guest.o'),
            '-o',
            str(out / 'guest.elf'),
        ],
    )
    run(
        'extract',
        [
            str(a.llvm_bin / 'llvm-objcopy'),
            '-O',
            'binary',
            '--only-section=.text',
            str(out / 'guest.elf'),
            str(out / 'guest.bin'),
        ],
    )
    assert (out / 'guest.bin').stat().st_size == 288
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
    artifacts = {}
    for line in library.stdout.splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row['target']['name'] in [
            'rax',
            'vm_memory',
        ]:
            for name in row['filenames']:
                if name.endswith('.rlib'):
                    artifacts[row['target']['name']] = Path(name)
    assert set(artifacts) == {'rax', 'vm_memory'}
    storage = [
        {'name': name, 'source': str(path), 'sha256': sha(path)}
        for name, path in artifacts.items()
    ]
    (out / 'producer-storage.json').write_text(json.dumps(storage, indent=2) + '\n')
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/hvf/arm64_mmio_native_guest.rs'),
            '--extern',
            'rax=' + str(artifacts['rax']),
            '--extern',
            'vm_memory=' + str(artifacts['vm_memory']),
            '-L',
            'dependency=' + str(a.target_dir / 'debug/deps'),
            '-o',
            str(temporary / 'native-mmio'),
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
            str(temporary / 'native-mmio'),
        ],
    )
    run('verify-sign', ['codesign', '--verify', '--strict', str(temporary / 'native-mmio')])
    run('native', [str(temporary / 'native-mmio'), str(out)], 30)
    report = verify(out)
    assert before == {n: sha(root / n) for n in sources}
    names = [
        'rows.bin',
        'admission.txt',
        'guest.s',
        'guest.o',
        'guest.elf',
        'guest.bin',
        'entitlements.plist',
        'producer-storage.json',
    ]
    (out / 'manifest.json').write_text(
        json.dumps(
            {
                'result': 'native_rax_arm64_mmio_transactions_match',
                'report': report,
                'commands': commands,
                'source_sha256': before,
                'library_sha256': {
                    n: sha(path) for n, path in artifacts.items()
                },
                'native_executable_sha256': sha(temporary / 'native-mmio'),
                'linked_artifacts_unchanged': all(sha(artifacts[row['name']]) == row['sha256'] for row in storage),
                'host_machine': platform.machine(),
                'artifacts': {n: sha(out / n) for n in names},
                'scope': 'Actual signed public RAX ARM64 backend/VCpu API backed by a permanent SDK owner, with a fresh native VM/CPU cohort for each independent case. Complete scalar replies, incomplete-reply re-entry and state-replacement cancellation only. SDK register-write failure is not fault-injected; native budgets, checkpoint completeness, worker migration and physical Intel/KVM remain unverified.',
            },
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
    p.add_argument('--llvm-bin', type=Path, required=True)
    a = p.parse_args()
    if sys.platform != 'darwin' or platform.machine() not in ['arm64', 'aarch64']:
        print(
            'Native ARM64 HVF validation requires Apple Silicon macOS.', file=sys.stderr
        )
        raise SystemExit(77)
    temporary_path = None
    try:
        with tempfile.TemporaryDirectory(prefix='rax-arm64-mmio-') as name:
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
