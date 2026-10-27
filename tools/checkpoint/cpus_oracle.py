"""Independent full fixed-width x86 register/base-private CPU-set model."""

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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def word(cpu, lane):
    return 0x0102030405060708 ^ (cpu << 48) ^ (lane + 1)


def expected(cpu):
    # 32GPRs,RIP/RFLAGS,then272vector/mask/MMX words;fixed arrays have no counts.
    registers = (
        [word(cpu, i) for i in range(32)]
        + [0x1000 + cpu * 4, 2 + (cpu & 1)]
        + [word(cpu, i) for i in range(32, 304)]
    )
    assert len(registers) == 306
    # Eight23-byte segments,two10-byte tables,nineteen64-bit system/MSR/debug fields.
    state = (
        struct.pack('<I', 0)
        + struct.pack('<306Q', *registers)
        + bytes(8 * 23 + 2 * 10 + 19 * 8)
    )
    fpu = struct.pack('<HHHQQH', 0x37F, 0, 0, 0x11110000 + cpu, 0x22220000 + cpu, 0x123)
    fpu += (
        b''.join(struct.pack('<Q', word(cpu, i)) + b'\xff\xff' for i in range(296, 304))
        + b'\0'
    )
    lazy = struct.pack('<BQQQB', 0, 0, 0, 0, 4)
    private = (
        fpu
        + lazy
        + struct.pack(
            '<QQIQQQIIBB',
            0x33000000 + cpu * 0x1000,
            cpu * 3,
            cpu * 17,
            1,
            0x0007040600070406,
            0x40,
            cpu * 0x10203,
            0x1F80 | (cpu & 0x3F),
            int(bool(cpu & 1)),
            int(bool(cpu & 2)),
        )
    )
    assert len(state) == 2808 and len(private) == 185
    runtime = struct.pack(
        '<5Q',
        word(cpu, 0),
        0x1000 + cpu * 4,
        0x33000000 + cpu * 0x1000,
        cpu * 0x10203,
        0x1F80 | (cpu & 0x3F),
    )
    return state, private, runtime


def verify(directory):
    rows = []
    payload_bytes = 0
    for count in [1, 2, 4]:
        path = directory / f'cpus-{count}.rxc'
        raw = path.read_bytes()
        assert raw[:16] == b'RAXCKPT\0' + struct.pack('<I', 8) + b'RXS8'
        total = struct.unpack_from('<I', raw, 16)[0]
        assert total == 8
        at, parts, order = 20, {}, []
        for _ in range(total):
            kind, schema, length = struct.unpack_from('<IIQ', raw, at)
            assert kind not in parts and schema == (2 if kind == 1 else 1)
            at += 16
            assert length <= len(raw) - at
            parts[kind] = raw[at : at + length]
            order.append(kind)
            at += length
        assert at == len(raw) and order == [1, 2, 3, 4, 5, 11, 7, 6]
        assert parts[3] == expected(0)[0] and parts[4] == expected(0)[1]
        data = parts[11]
        assert data[:12] == b'RAXCPU01' + struct.pack('<I', count)
        at = 12 + 16 * count
        for cpu in range(count):
            state, private, _ = expected(cpu)
            sizes = struct.unpack_from('<QQ', data, 12 + cpu * 16)
            assert sizes == (len(state), len(private))
            assert data[at : at + len(state)] == state
            at += len(state)
            assert data[at : at + len(private)] == private
            at += len(private)
            payload_bytes += len(state) + len(private)
        assert at == len(data)
        runtime = directory / f'cpus-{count}.runtime'
        assert runtime.read_bytes() == b''.join(expected(i)[2] for i in range(count))
        rows.append(
            dict(cpus=count, artifacts={p.name: sha(p) for p in [path, runtime]})
        )
    assert (directory / 'publish.stdout').read_text().splitlines() == [
        '1\t1',
        '2\t2',
        '4\t4',
    ]
    return dict(
        files=3,
        sections=24,
        cpus=7,
        complete_cpu_payload_bytes=payload_bytes,
        live_runtime_marker_bytes=7 * 40,
        failed=0,
    ), rows


def fault_injection(directory):
    """Prove exact byte comparisons observe each payload and live marker field."""
    scratch = directory / 'fault-injection'
    scratch.mkdir(exist_ok=True)
    names = [
        f'cpus-{n}.{suffix}' for n in [1, 2, 4] for suffix in ['rxc', 'runtime']
    ] + ['publish.stdout']
    baseline = {name: (directory / name).read_bytes() for name in names}
    for name, raw in baseline.items():
        (scratch / name).write_bytes(raw)
    probes = []
    for count in [1, 2, 4]:
        name = f'cpus-{count}.rxc'
        raw = baseline[name]
        at = 20
        while True:
            kind, schema, size = struct.unpack_from('<IIQ', raw, at)
            if kind == 11:
                break
            at += 16 + size
        payload = at + 16
        offsets = [
            ('section-count', 16),
            ('schema', at + 4),
            ('tag', payload),
            ('count', payload + 8),
        ]
        record = payload + 12 + 16 * count
        for cpu in range(count):
            state, private = struct.unpack_from('<QQ', raw, payload + 12 + 16 * cpu)
            for label, size in [('state', state), ('private', private)]:
                offsets.extend(
                    [
                        (f'cpu{cpu}-{label}-first', record),
                        (f'cpu{cpu}-{label}-last', record + size - 1),
                    ]
                )
                record += size
        probes.extend((name, label, offset) for label, offset in offsets)
        probes.extend(
            (f'cpus-{count}.runtime', f'cpu{cpu}-live{field}', 40 * cpu + 8 * field)
            for cpu in range(count)
            for field in range(5)
        )
    receipts = []
    for name, label, offset in probes:
        original = baseline[name]
        mutant = bytearray(original)
        mutant[offset] ^= 1
        path = scratch / name
        path.write_bytes(mutant)
        try:
            try:
                verify(scratch)
            except AssertionError:
                pass
            else:
                raise RuntimeError(
                    f'Independent verifier accepted mutated {name}/{label}'
                )
        finally:
            path.write_bytes(original)
        receipts.append(
            dict(
                artifact=name,
                label=label,
                offset=offset,
                mutation='xor1',
                mutant_sha256=hashlib.sha256(mutant).hexdigest(),
                rejected=True,
            )
        )
    assert len(receipts) == 75
    assert all((scratch / name).read_bytes() == raw for name, raw in baseline.items())
    assert verify(scratch)[0] == verify(directory)[0]
    result = dict(
        cases=len(receipts),
        rejected=len(receipts),
        failed=0,
        probes=receipts,
        scope='Single-bit probes at both ends of every CPU public/private payload, each live marker word, and each CPU-section framing field;all baseline artifacts restored and reverified.',
    )
    (directory / 'fault-injection.json').write_text(json.dumps(result, indent=2) + '\n')
    return dict(
        cases=len(receipts),
        rejected=len(receipts),
        failed=0,
        manifest_sha256=sha(directory / 'fault-injection.json'),
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    a = p.parse_args()
    root, out = a.repo.resolve(), a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [
        'src/vm/snapshot.rs',
        'src/vm/snapshot/cpus.rs',
        'src/vm/snapshot/bundle.rs',
        'src/vm/snapshot/codec.rs',
        'src/vm/runtime.rs',
        'tests/suites/vm/checkpoint_cpus.rs',
        'tools/checkpoint/cpus_guest.rs',
        'tools/checkpoint/cpus_oracle.py',
    ]
    before = {n: sha(root / n) for n in sources}
    library = out / 'librax.rlib'
    shutil.copyfile(a.target_dir / 'debug/librax.rlib', library)
    env = os.environ.copy()
    env['CARGO_MANIFEST_DIR'] = str(root)
    commands = []
    for name, command in [
        (
            'build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(root / 'tools/checkpoint/cpus_guest.rs'),
                '--extern',
                'rax=' + str(library),
                '-L',
                'dependency=' + str(a.target_dir / 'debug/deps'),
                '-o',
                str(out / 'publish'),
            ],
        ),
        ('publish', [str(out / 'publish'), str(out)]),
    ]:
        start = time.monotonic()
        r = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=60)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        commands.append(
            dict(
                name=name,
                args=command,
                code=r.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert r.returncode == 0, (name, r.stderr[-3000:])
    report, cases = verify(out)
    faults = fault_injection(out)
    assert before == {n: sha(root / n) for n in sources}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_ordered_cpu_payloads_and_live_markers_match',
                report=report,
                cases=cases,
                fault_injection=faults,
                commands=commands,
                source_sha256=before,
                library_sha256=sha(library),
                scope='Every serialized public/base-private byte for7x86 CPU contexts plus280live marker bytes;all data-modeled independently.No instruction/native/fullprivate/SMPexecution claim.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
