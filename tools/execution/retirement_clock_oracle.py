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
    widths = [1, 4, 4, 2, 4, 4, 8, 8, 8, 8, 8, 8]
    for kind, width in enumerate(widths):
        total = 0
        for budget in [0, 1, 2, 999, 1000, 1001]:
            total += budget
            words.extend(
                [
                    kind,
                    budget,
                    budget,
                    4096 + total * width,
                    total,
                    total // 3,
                    total % 3,
                ]
            )
    words.extend(range(1000))
    return struct.pack('<' + str(len(words)) + 'Q', *words)


def verify(directory):
    assert (directory / 'trace.bin').read_bytes() == expected()
    return dict(
        profiles=12,
        calls=72,
        retired_units=36036,
        observation_bytes=12032,
        within_quantum_reads=1000,
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
        'src/vm/timing.rs',
        'src/vm/timing/context.rs',
        'src/vm/vcpu/budget.rs',
        'tests/suites/backend/retirement_clock.rs',
        'tools/execution/retirement_clock_guest.rs',
        'tools/execution/retirement_clock_oracle.py',
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
            str(root / 'tools/execution/retirement_clock_guest.rs'),
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
    indices = list(range(72 * 7)) + [72 * 7 + i * 61 for i in range(16)]
    assert len(set(indices)) == 520
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
    assert len(probes) == 520 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=520, rejected=520, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_budget_clock_observations_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                artifacts={
                    n: sha(out / n) for n in ['trace.bin', 'fault-injection.json']
                },
                scope='12 actual backend profiles,72 budget results,12032 observation bytes,1000 within-quantum clock reads;independent integer model;direct stepping and unbounded runs retain clock ownership;no coordinator/native/SMP/replay proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
