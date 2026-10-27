"""Independent required-clock wire and continued-context state model."""

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


def values(index):
    if index == 0:
        return 0, 0, 97, 0, 37
    if index == 4:
        return 1, 2, MASK, MASK, MASK
    return 1, index - 1, 97, 0x123456789ABCDEF0, 37


def verify(directory):
    rows = []
    for index in range(5):
        path = directory / f'clock-{index}.rxc'
        raw = path.read_bytes()
        assert raw[:16] == b'RAXCKPT\0' + struct.pack('<I', 8) + b'RXS8'
        count = struct.unpack_from('<I', raw, 16)[0]
        assert count == 7
        at = 20
        parts = {}
        order = []
        clock_at = None
        for _ in range(count):
            assert at + 16 <= len(raw)
            kind, schema, n = struct.unpack_from('<IIQ', raw, at)
            assert kind not in parts and schema == (2 if kind == 1 else 1)
            at += 16
            assert n <= len(raw) - at
            parts[kind] = raw[at : at + n]
            order.append(kind)
            if kind == 12:
                clock_at = at
            at += n
        assert at == len(raw) and order == [1, 2, 3, 4, 5, 12, 6]
        mode, phase, nanos, units, ticks = values(index)
        wanted = b'RAXCLK01' + struct.pack(
            '<Q4B3Q', 3_000_000_000, mode, phase, 1, 0, nanos, units, ticks
        )
        assert len(wanted) == 44 and parts[12] == wanted
        instruction_count, elapsed, memory = struct.unpack('<3Q', parts[2])
        assert (instruction_count, elapsed, memory) == (17, nanos, 4096)
        runtime = directory / f'clock-{index}.runtime'
        if mode == 0:
            expected = struct.pack('<2Q', ticks, 1)
        else:
            expected = struct.pack(
                '<5Q',
                (nanos + (phase + 1) // 3) & MASK,
                (units + 1) & MASK,
                (phase + 1) % 3,
                ticks,
                1,
            )
        assert runtime.read_bytes() == expected
        rows.append(
            dict(
                index=index,
                clock_offset=clock_at,
                artifacts={p.name: sha(p) for p in [path, runtime]},
            )
        )
    return dict(
        files=5, sections=35, clock_record_bytes=220, live_state_bytes=176, failed=0
    ), rows


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
        'src/vm/snapshot.rs',
        'src/vm/snapshot/clock.rs',
        'src/vm/snapshot/bundle.rs',
        'src/vm/snapshot/codec.rs',
        'src/vm/timing/context.rs',
        'src/vm/timing/retired.rs',
        'src/vm/runtime.rs',
        'src/config/runtime.rs',
        'tests/suites/vm/checkpoint_clock.rs',
        'tools/execution/checkpoint_clock_guest.rs',
        'tools/execution/checkpoint_clock_oracle.py',
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

    run(
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
            '--bin',
            'rax',
        ],
        600,
    )
    shutil.copyfile(a.target_dir / 'debug/librax.rlib', out / 'librax.rlib')
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/execution/checkpoint_clock_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '-L',
            'dependency=' + str(a.target_dir / 'debug/deps'),
            '-o',
            str(out / 'publish'),
        ],
        60,
    )
    run('publish', [str(out / 'publish'), str(out)], 60)
    report, cases = verify(out)
    probes = []
    for case in cases:
        index = case['index']
        path = out / f'clock-{index}.rxc'
        original = path.read_bytes()
        for offset in [0, 8, 16, 17, 18, 19, 20, 28, 36, 43]:
            mutant = bytearray(original)
            mutant[case['clock_offset'] + offset] ^= 1
            probes.append((path, f'clock-field-{offset}', original, bytes(mutant)))
        path = out / f'clock-{index}.runtime'
        original = path.read_bytes()
        for offset in range(0, len(original), 8):
            mutant = bytearray(original)
            mutant[offset] ^= 1
            probes.append((path, f'live-word-{offset // 8}', original, bytes(mutant)))
    receipts = []
    for path, label, original, mutant in probes:
        path.write_bytes(mutant)
        try:
            try:
                verify(out)
            except AssertionError:
                pass
            else:
                raise RuntimeError(f'Verifier accepted {path.name}/{label}')
        finally:
            path.write_bytes(original)
        receipts.append(
            dict(
                artifact=path.name,
                label=label,
                rejected=True,
                mutant_sha256=hashlib.sha256(mutant).hexdigest(),
            )
        )
    assert len(receipts) == 72 and verify(out)[0] == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=72, rejected=72, failed=0, probes=receipts), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_clock_wire_and_continued_state_bytes_match',
                report=report,
                cases=cases,
                commands=commands,
                source_sha256=before,
                library_sha256=sha(out / 'librax.rlib'),
                fault_injection_sha256=sha(out / 'fault-injection.json'),
                scope='Five actual clock files:220fixed wire bytes and176live continuation/notification bytes;all phases/fullwidth state;no deterministic coordinator/native/replay proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
