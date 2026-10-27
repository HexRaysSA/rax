"""Independent exact retirement/PC model for twelve real stepping profiles."""

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


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def verify(directory):
    raw = (directory / 'rows.bin').read_bytes()
    widths = [1, 4, 4, 2, 4, 4] + [8] * 6
    expected = []
    for plane, width in enumerate(widths):
        total = 0
        for budget in [0, 1, 999, 1000, 1001]:
            total += budget
            expected.extend([plane, budget, budget, total, 0x1000 + total * width])
    assert raw == struct.pack('<300Q', *expected)
    return dict(
        profiles=12, calls=60, retired_units=36012, exact_result_bytes=2400, failed=0
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
        'src/vm/vcpu/mod.rs',
        'src/vm/vcpu/budget.rs',
        'tests/suites/backend/retirement_budget.rs',
        'tools/execution/budget_guest.rs',
        'tools/execution/budget_oracle.py',
    ]
    before = {n: sha(root / n) for n in names}
    env = os.environ.copy()
    env['CARGO_MANIFEST_DIR'] = str(root)
    env['CARGO_TARGET_DIR'] = str(a.target_dir)
    env['CARGO_BUILD_JOBS'] = '1'
    commands = []

    def run(name, args, timeout):
        start = time.monotonic()
        r = subprocess.run(
            args, cwd=root, env=env, capture_output=True, timeout=timeout
        )
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

    r = run(
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
            '--lib',
            '--message-format=json',
        ],
        600,
    )
    artifacts = {}
    for line in r.stdout.splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row['target']['name'] in [
            'rax',
            'vm_memory',
        ]:
            for path in row['filenames']:
                if path.endswith('.rlib'):
                    artifacts[row['target']['name']] = Path(path)
    assert set(artifacts) == {'rax', 'vm_memory'}
    for name, path in artifacts.items():
        shutil.copyfile(path, out / ('lib' + name + '.rlib'))
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/execution/budget_guest.rs'),
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
    run('publish', [str(out / 'publish'), str(out / 'rows.bin')], 60)
    report = verify(out)
    original = (out / 'rows.bin').read_bytes()
    faults = []
    for word in range(300):
        mutant = bytearray(original)
        mutant[8 * word] ^= 1
        (out / 'rows.bin').write_bytes(mutant)
        try:
            try:
                verify(out)
            except AssertionError:
                pass
            else:
                raise RuntimeError('Verifier accepted corrupted word ' + str(word))
        finally:
            (out / 'rows.bin').write_bytes(original)
        faults.append(
            dict(
                word=word,
                rejected=True,
                mutant_sha256=hashlib.sha256(mutant).hexdigest(),
            )
        )
    assert verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=300, rejected=300, failed=0, probes=faults), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_exact_budget_and_pc_rows_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                output_sha256=sha(out / 'rows.bin'),
                fault_injection_sha256=sha(out / 'fault-injection.json'),
                scope='Actual flat instruction/packet execution on x86,A64,A32,CortexM,RV,Hexagon,eBPF andSBPFV0..V4;no native/SMP/coordinator/replay proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
