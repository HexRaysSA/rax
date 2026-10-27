"""Independent full backing/projection/ELF comparison and actual CLI execution."""

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

RAM = 128 * 1024**2
REQUESTED = RAM + 1
ALLOCATED = RAM + 4096
PHYSICAL = ALLOCATED + 4 * 1024**3


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def segments(raw):
    assert raw[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<H', raw, 18)[0] == 243
    at = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    assert size == 56
    result = []
    for index in range(count):
        kind, flags, offset, virtual, physical, files, mem, align = struct.unpack_from(
            '<IIQQQQQQ', raw, at + index * size
        )
        if kind != 1:
            continue
        assert files <= mem and offset + files <= len(raw)
        start = physical or virtual
        assert 0 <= start < start + mem <= PHYSICAL
        result.append((start, raw[offset : offset + files], mem))
    assert len(result) == 2 and [r[0] for r in result] == [0x80000000, 0x80001000]
    return result


def check_stream(frame, size, expected, zstd, directory, name):
    path = directory / (name + '.zst')
    path.write_bytes(frame)
    digest = hashlib.sha256()
    total = 0
    with (directory / (name + '-zstd.stderr')).open('wb') as stderr:
        child = subprocess.Popen(
            [zstd, '-d', '-q', '-c', str(path)], stdout=subprocess.PIPE, stderr=stderr
        )
        try:
            while chunk := child.stdout.read(1024 * 1024):
                assert total + len(chunk) <= size, (name, 'excess output', total)
                wanted = bytearray(len(chunk))
                for start, data, _ in expected:
                    low, high = (
                        max(total, start),
                        min(total + len(chunk), start + len(data)),
                    )
                    if low < high:
                        wanted[low - total : high - total] = data[
                            low - start : high - start
                        ]
                assert chunk == wanted, (
                    name,
                    'unexpected byte range',
                    total,
                    len(chunk),
                )
                digest.update(chunk)
                total += len(chunk)
            assert child.wait(timeout=30) == 0 and total == size, (name, total, size)
        finally:
            child.stdout.close()
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
    return dict(bytes=total, sha256=digest.hexdigest(), frame_sha256=sha(path))


def verify(directory, root, zstd):
    raw = (directory / 'console.rxc').read_bytes()
    assert raw[:16] == b'RAXCKPT\0' + struct.pack('<I', 8) + b'RXS8'
    count = struct.unpack_from('<I', raw, 16)[0]
    assert count == 9
    at, parts, order = 20, {}, []
    for _ in range(count):
        kind, schema, length = struct.unpack_from('<IIQ', raw, at)
        assert kind not in parts and schema == (2 if kind == 1 else 1)
        at += 16
        assert length <= len(raw) - at
        parts[kind] = raw[at : at + length]
        order.append(kind)
        at += length
    assert at == len(raw) and order == [1, 2, 3, 4, 5, 12, 11, 10, 6]
    cpus = parts[11]
    assert cpus[:12] == b'RAXCPU01' + struct.pack('<I', 1)
    cpu_bytes, emulator_bytes = struct.unpack_from('<QQ', cpus, 12)
    assert len(cpus) == 28 + cpu_bytes + emulator_bytes
    assert cpus[28 : 28 + cpu_bytes] == parts[3]
    assert cpus[28 + cpu_bytes :] == parts[4]
    instruction_count, elapsed, memory = struct.unpack('<QQQ', parts[2])
    clock = parts[12]
    assert len(clock) == 44 and clock[:8] == b'RAXCLK01'
    assert struct.unpack_from('<Q', clock, 8)[0] == 3_000_000_000
    assert clock[16:20] == bytes(4)
    assert struct.unpack_from('<3Q', clock, 20) == (elapsed, 0, 0)

    assert instruction_count == 0 and memory == ALLOCATED
    physical = parts[10]
    assert physical[:12] == b'RAXRAM01' + struct.pack('<I', 1)
    start, length, digest, compressed = struct.unpack_from('<QQ32sQ', physical, 12)
    assert start == 0 and length == PHYSICAL and len(physical) == 68 + compressed
    elf = root / 'tests/fixtures/checkpoint/resume-riscv.elf'
    loads = segments(elf.read_bytes())
    actual = check_stream(physical[68:], PHYSICAL, loads, zstd, directory, 'physical')
    assert actual['sha256'] == digest.hex()
    projection = check_stream(parts[6], ALLOCATED, [], zstd, directory, 'projection')
    kernel = Path((directory / 'kernel-path.txt').read_text())
    assert kernel.is_absolute() and not kernel.exists()
    assert (directory / 'publish.stdout').read_text().splitlines() == [
        f'{REQUESTED}\t{ALLOCATED}\t{PHYSICAL}'
    ]
    return dict(
        files=1,
        sections=9,
        regions=1,
        physical_bytes=PHYSICAL,
        projection_bytes=ALLOCATED,
        elf_segments=2,
        missing_kernel_paths=1,
        guest_uart_markers=1,
        guest_shutdown_events=1,
        failed=0,
    ), dict(
        physical=actual,
        projection=projection,
        elf_sha256=sha(elf),
        elf_segments=[
            dict(
                start=s,
                bytes=len(d),
                mapped_bytes=n,
                sha256=hashlib.sha256(d).hexdigest(),
            )
            for s, d, n in loads
        ],
        recorded_elapsed_nanos=elapsed,
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
        'src/config/runtime.rs',
        'src/vm/snapshot/cpus.rs',
        'src/vm/snapshot/clock.rs',
        'src/vm/timing/context.rs',
        'src/vm/timing/retired.rs',
        'src/vm/snapshot/bundle.rs',
        'src/vm/snapshot/codec.rs',
        'src/vm/runtime.rs',
        'src/vm/runtime/pci_state.rs',
        'src/cli/mod.rs',
        'tests/suites/vm/checkpoint_resume.rs',
        'tools/checkpoint/resume_guest.rs',
        'tools/checkpoint/resume_oracle.py',
        'tests/fixtures/checkpoint/resume-riscv.s',
        'tests/fixtures/checkpoint/resume-riscv.ld',
        'tests/fixtures/checkpoint/resume-riscv.elf',
    ]
    before = {n: sha(root / n) for n in sources}
    library = out / 'librax.rlib'
    shutil.copyfile(a.target_dir / 'debug/librax.rlib', library)
    binary = a.target_dir / 'debug/rax'
    assert binary.is_file()
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
                str(root / 'tools/checkpoint/resume_guest.rs'),
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
        result = subprocess.run(
            command, cwd=root, env=env, capture_output=True, timeout=120
        )
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        commands.append(
            dict(
                name=name,
                args=command,
                code=result.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert result.returncode == 0, (name, result.stderr[-3000:])
    env['RUST_LOG'] = 'info'
    cmd = [
        str(binary),
        '--checkpoint',
        str(out / 'console.rxc'),
        '--backend',
        'emulator',
    ]
    start = time.monotonic()
    with (
        (out / 'cli.stdout').open('wb') as stdout,
        (out / 'cli.stderr').open('wb') as stderr,
    ):
        child = subprocess.Popen(
            cmd, cwd=root, env=env, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr
        )
        try:
            code = child.wait(timeout=120)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            child.stdin.close()
    commands.append(
        dict(
            name='cli',
            args=cmd,
            code=code,
            seconds=time.monotonic() - start,
            stdin='Owned pipe writer held open until exit;EOF cannot cause the accepted shutdown.',
        )
    )
    combined = (out / 'cli.stdout').read_bytes() + (out / 'cli.stderr').read_bytes()
    assert (
        code == 0
        and combined.count(b'RAX\n') == 1
        and combined.count(b'vCPU shutdown') == 1
    ), combined[-6000:]
    zstd = shutil.which('zstd')
    assert zstd
    report, comparison = verify(out, root, zstd)
    assert before == {n: sha(root / n) for n in sources}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_file_resume_bytes_and_guest_execution_match',
                report=report,
                comparison=comparison,
                commands=commands,
                source_sha256=before,
                library_sha256=sha(library),
                binary_sha256=sha(binary),
                artifacts={
                    n: sha(out / n)
                    for n in [
                        'console.rxc',
                        'kernel-path.txt',
                        'cli.stdout',
                        'cli.stderr',
                        'publish.stdout',
                        'publish.stderr',
                    ]
                },
                scope='Actual console file,independent system-zstd comparison of every mapped/projection byte against ELF segments/zero backing,and CLI UART+HTIF shutdown after missing original kernel.No Linux/native/fullSMP claim.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
