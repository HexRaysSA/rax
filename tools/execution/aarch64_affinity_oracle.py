"""Independent byte-field model of guest-visible configured AArch64 affinity."""

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
    for system in [0, 1]:
        for identity in [0, 1, 255, 256, 0xFFFF, 0xFFFFFF, 0x1000000, 0xFFFFFFFF]:
            fields = identity.to_bytes(4, 'little')
            affinity = 0x80000000 | sum(
                fields[i] << shift for i, shift in enumerate([0, 8, 16, 32])
            )
            words.extend(
                [system, identity, 0x80000000 if predecessor else affinity, 4100, 1]
            )
    return struct.pack('<80Q', *words)


def verify(directory):
    assert (directory / 'trace.bin').read_bytes() == expected()
    return dict(
        adapter_modes=2,
        observations=16,
        observation_bytes=640,
        affinity_levels=4,
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
        'src/isa/arm/aarch64/cpu/mod.rs',
        'src/isa/arm/aarch64/cpu/identity.rs',
        'src/isa/arm/aarch64/cpu/state.rs',
        'src/backend/emulator/aarch64.rs',
        'src/backend/hvf/arm64.rs',
        'tests/suites/backend/aarch64_affinity.rs',
        'tools/execution/aarch64_affinity_guest.rs',
        'tools/execution/aarch64_affinity_oracle.py',
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
            str(root / 'tools/execution/aarch64_affinity_guest.rs'),
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

    report = verify(out)
    original = (out / 'trace.bin').read_bytes()
    indices = list(range(16 * 5))
    assert len(set(indices)) == 80
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
    assert len(probes) == 80 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=80, rejected=80, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_configured_aarch64_affinity_observations_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                artifacts={
                    n: sha(out / n) for n in ['trace.bin', 'fault-injection.json']
                },
                scope='Actual configured AArch64 machine/micro guest MRS reads;16 observations/640 bytes;independent byte-field affinity model.No RAX multi-vCPU scheduling,shared GIC/PSCI,startup,Linux SMP or native high-affinity admission proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
