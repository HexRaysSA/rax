"""Independent bigint model of fixed-frequency clock phase across u64 wraps."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time

MASK = (1 << 64) - 1


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def expected(*, predecessor=False):
    words = []
    for rv32 in [0, 1]:
        for devices in [0, 1]:
            for identity in [0, 1, 2, 3, 255, (1 << 32) - 1]:
                words.extend(
                    [rv32, devices, identity, 0 if predecessor else identity, 4100, 1]
                )
    return struct.pack('<144Q', *words)


def verify(directory):
    assert (directory / 'trace.bin').read_bytes() == expected()
    for bits in [32, 64]:
        for count in [1, 2, 4]:
            assert sorted(
                (directory / f'qemu-{bits}-{count}.stdout').read_bytes()
            ) == list(range(48, 48 + count))
    return dict(
        widths=2,
        adapter_modes=2,
        observations=24,
        observation_bytes=1152,
        qemu_runs=6,
        qemu_harts=14,
        failed=0,
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    p.add_argument('--llvm-bin', type=Path)
    a = p.parse_args()
    root = a.repo.resolve()
    out = a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = [
        'src/isa/riscv/cpu.rs',
        'src/isa/riscv/cpu/identity.rs',
        'src/backend/emulator/riscv/cpu.rs',
        'tests/suites/backend/riscv_hartid.rs',
        'tools/execution/riscv_hartid_guest.rs',
        'tools/execution/riscv_hartid_oracle.py',
        'tools/execution/riscv_hartid_reference.s',
    ]
    before = {n: sha(root / n) for n in names}
    e = os.environ.copy()
    e.update(
        CARGO_TARGET_DIR=str(a.target_dir),
        CARGO_BUILD_JOBS='1',
        CARGO_MANIFEST_DIR=str(root),
    )
    commands = []

    def run(name, args, timeout):
        start = time.monotonic()
        r = subprocess.run(args, cwd=root, env=e, capture_output=True, timeout=timeout)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        commands.append(
            dict(
                name=name,
                args=args,
                code=r.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert r.returncode == 0, (name, r.stderr[-4000:])
        return r

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
            '--bin',
            'rax',
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
    for name, path in artifacts.items():
        shutil.copyfile(path, out / ('lib' + name + '.rlib'))
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/execution/riscv_hartid_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '--extern',
            'vm_memory=' + str(out / 'libvm_memory.rlib'),
            '-L',
            'dependency=' + str(a.target_dir / 'debug/deps'),
            '-o',
            str(out / 'publish'),
        ],
        60,
    )
    run('publish', [str(out / 'publish'), str(out / 'trace.bin')], 60)

    def tool(name):
        found = a.llvm_bin / name if a.llvm_bin else shutil.which(name)
        assert found and Path(found).is_file(), (
            f'Required LLVM tool unavailable: {name}'
        )
        return str(found)

    run('llvm-version', [tool('llvm-mc'), '--version'], 20)
    for bits in [32, 64]:
        qemu = shutil.which(f'qemu-system-riscv{bits}')
        assert qemu, f'Required machine-mode reference missing: qemu-system-riscv{bits}'
        run(f'qemu-{bits}-version', [qemu, '--version'], 20)
        for count in [1, 2, 4]:
            tag = f'{bits}-{count}'
            asm, obj, elf = [
                out / ('reference-' + tag + suffix) for suffix in ['.s', '.o', '.elf']
            ]
            asm.write_text(
                f'.equ NHARTS,{count}\n'
                + (root / 'tools/execution/riscv_hartid_reference.s').read_text()
            )
            run(
                'assemble-' + tag,
                [
                    tool('llvm-mc'),
                    f'-triple=riscv{bits}',
                    '-mattr=+m,+a,+f,+d,+c,+zicsr',
                    '-filetype=obj',
                    str(asm),
                    '-o',
                    str(obj),
                ],
                20,
            )
            run(
                'link-' + tag,
                [
                    tool('ld.lld'),
                    '-m',
                    f'elf{bits}lriscv',
                    '-Ttext=0x80000000',
                    '--entry=_start',
                    str(obj),
                    '-o',
                    str(elf),
                ],
                20,
            )
            run(
                'qemu-' + tag,
                [
                    qemu,
                    '-M',
                    'virt',
                    '-smp',
                    str(count),
                    '-m',
                    '128M',
                    '-bios',
                    'none',
                    '-kernel',
                    str(elf),
                    '-nographic',
                    '-monitor',
                    'none',
                    '-serial',
                    'stdio',
                ],
                20,
            )

    report = verify(out)
    original = (out / 'trace.bin').read_bytes()
    indices = list(range(24 * 6))
    assert len(set(indices)) == 144
    probes = []
    for word in indices:
        mutant = bytearray(original)
        mutant[word * 8] ^= 1
        (out / 'trace.bin').write_bytes(mutant)
        try:
            try:
                verify(out)
            except AssertionError:
                pass
            else:
                raise RuntimeError(f'Verifier accepted mutated word{word}')
        finally:
            (out / 'trace.bin').write_bytes(original)
        probes.append(
            dict(
                word=word,
                rejected=True,
                mutant_sha256=hashlib.sha256(mutant).hexdigest(),
            )
        )
    assert len(probes) == 144 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=144, rejected=144, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_configured_riscv_hart_id_observations_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                artifacts={
                    n: sha(out / n)
                    for n in ['trace.bin', 'fault-injection.json']
                    + [
                        f'qemu-{bits}-{count}.stdout'
                        for bits in [32, 64]
                        for count in [1, 2, 4]
                    ]
                    + [
                        f'reference-{bits}-{count}.elf'
                        for bits in [32, 64]
                        for count in [1, 2, 4]
                    ]
                },
                scope='Actual RV32/RV64 configured machine/embedded hart CSR reads;24 observations/1152 bytes;independent machine-mode QEMU32/64 at1/2/4harts,14 complete identity bytes with raw order retained. No RAX SMP scheduler,interrupt-controller,boot or native RISC-V hardware proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
