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


def expected():
    words = []
    for system in [0, 1]:
        for n in range(1, 1001):
            words.extend(
                [system, n, 1, n, 4096 + 4 * (n % 4), (n + 3) // 4, (n + 2) // 4]
            )
        total = 0
        for budget in [0, 1, 2, 999, 1000, 1001]:
            total += budget
            words.extend(
                [
                    system,
                    budget,
                    budget,
                    total,
                    4096 + 4 * (total % 4),
                    (total + 3) // 4,
                    (total + 2) // 4,
                ]
            )
    return struct.pack('<14084Q', *words)


def verify(directory):
    assert (directory / 'trace.bin').read_bytes() == expected()
    return dict(
        adapter_modes=2,
        observations=2012,
        observation_bytes=112672,
        retired_units=8006,
        failed=0,
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    a = p.parse_args()
    root = a.repo.resolve()
    out = a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = [
        'src/backend/emulator/aarch64.rs',
        'src/backend/emulator/aarch64_step.rs',
        'src/isa/arm/aarch64/cpu/system_step.rs',
        'src/isa/arm/aarch64/cpu/system_step_tests.rs',
        'tests/suites/backend/aarch64_step_jit.rs',
        'tools/execution/aarch64_step_jit_guest.rs',
        'tools/execution/aarch64_step_jit_oracle.py',
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
            str(root / 'tools/execution/aarch64_step_jit_guest.rs'),
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
    indices = (
        list(range(7))
        + [255 * 7 + i for i in range(7)]
        + [1005 * 7 + i for i in range(7)]
        + [1006 * 7 + i for i in range(7)]
        + [1261 * 7 + i for i in range(7)]
        + [2011 * 7 + i for i in range(7)]
    )
    assert len(set(indices)) == 42
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
    assert len(probes) == 42 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=42, rejected=42, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_exact_aarch64_step_observations_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                artifacts={
                    n: sha(out / n) for n in ['trace.bin', 'fault-injection.json']
                },
                scope='Actual full-machine and diagnostic AArch64 adapter stepping across the JIT promotion threshold:2012 observation rows,112672 exact bytes,8006 retired units;independent instruction-count/PC/register model;cached-region native boundary additionally requires its owning library test;no native hypervisor/SMP/full-clock proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
