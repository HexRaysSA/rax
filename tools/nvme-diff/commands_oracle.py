#!/usr/bin/env python3
"""Execute optional NVM commands through independent QEMU PCI/queue guests.

All input SQEs, guest code, raw completions, output buffers, media and capability
words are retained. Comparison uses current production sources. Raw capability
and DNR differences are reported separately from shared data behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time

CASES = [
    'compare-prp',
    'compare-mismatch',
    'compare-sgl',
    'zeroes',
    'zeroes-deallocate',
    'dataset-ranges',
    'dataset-advisory',
    'dataset-256',
    'dataset-sgl',
    'invalid-namespace',
    'range-errors',
    'combined-operations',
    'dataset-page-aligned',
    'dataset-mixed-alignment',
    'dataset-256-page-aligned',
    'dataset-sgl-page-aligned',
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def initial_disk():
    return bytes((i * 17 ^ (i >> 9)) & 255 for i in range(16384))


def command(op, lba=0, blocks=1, first=0, second=0, mode=0, control=0, nsid=1):
    raw = bytearray(64)
    raw[0], raw[1] = op, mode << 6
    struct.pack_into('<I', raw, 4, nsid)
    struct.pack_into('<QQ', raw, 24, first, second)
    struct.pack_into('<III', raw, 40, lba & 0xFFFFFFFF, lba >> 32, blocks - 1 | control)
    return raw


def dataset(entries, address, mode=0, attributes=4):
    raw = b''.join(
        struct.pack('<IIQ', i, count, lba) for i, (lba, count) in enumerate(entries)
    )
    sqe = command(9, first=address, second=len(raw) if mode else 0, mode=mode)
    struct.pack_into('<II', sqe, 40, len(entries) - 1, attributes)
    return sqe, raw


def make_input(index):
    disk = initial_disk()
    writes = []
    output = []
    expected = []
    commands = []

    def put(address, raw):
        assert len(raw) % 4 == 0
        writes.extend(
            (address + offset, struct.unpack_from('<I', raw, offset)[0])
            for offset in range(0, len(raw), 4)
        )

    def add(sqe, status=0):
        commands.append(sqe)
        expected.append(status)

    def read_media():
        add(command(2, blocks=32, first=0x02010003, second=16384, mode=1))
        output.append((0x02010003, 16384))

    if index in [0, 1]:
        data = bytearray(disk[512 : 512 + 4096])
        if index == 1:
            data[-1] ^= 1
        put(0x02000004, data[:4092])
        put(0x02002000, data[4092:])
        add(
            command(5, lba=1, blocks=8, first=0x02000004, second=0x02002000),
            0x285 if index == 1 else 0,
        )
    elif index == 2:
        put(0x02000003, disk[:512])
        add(command(5, first=0x02000003, second=512, mode=1, control=7 << 26))
    elif index in [3, 4]:
        lba, blocks = (3, 2) if index == 3 else (31, 1)
        flags = 0 if index == 3 else (1 << 25) | (1 << 29) | (3 << 30)
        add(
            command(
                8, lba, blocks, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, control=flags
            )
        )
        read_media()
    elif index == 5:
        sqe, raw = dataset(
            [(3, 2), (5, 1), (3, 1), (0xFFFFFFFFFFFFFFFF, 1), (32, 1), (0, 0)],
            0x02000004,
        )
        put(0x02000004, raw)
        add(sqe)
        read_media()
    elif index == 6:
        for attributes in range(4):
            sqe, _ = dataset([(0, 1)], 0xFFFFFFFFFFFFFFFF, attributes=attributes)
            add(sqe)
        read_media()
    elif index == 7:
        entries = [(1, 1)] * 256
        entries[-1] = (30, 1)
        sqe, raw = dataset(entries, 0x02000FFC)
        struct.pack_into('<Q', sqe, 32, 0x02002000)
        put(0x02000FFC, raw[:4])
        put(0x02002000, raw[4:])
        add(sqe)
        read_media()
    elif index == 8:
        sqe, raw = dataset([(2, 2), (31, 1)], 0x02000003, mode=2, attributes=7)
        put(0x02000003, raw)
        add(sqe)
        read_media()
    elif index == 9:
        for op, nsid in [(5, 2), (8, 0), (9, 0xFFFFFFFF)]:
            add(command(op, first=0xFFFFFFFFFFFFFFFF, nsid=nsid), 0x0B)
        add(command(0, nsid=0xFFFFFFFF))
        read_media()
    elif index == 10:
        add(command(8, lba=31, blocks=2), 0x80)
        add(command(5, lba=32), 0x80)
        read_media()
    elif index == 11:
        put(0x02000000, disk[7 * 512 : 8 * 512])
        add(command(5, lba=7, first=0x02000000))
        add(command(8, lba=7))
        put(0x02004000, bytes(512))
        add(command(5, lba=7, first=0x02004000))
        sqe, raw = dataset([(10, 2)], 0x02008000)
        put(0x02008000, raw)
        add(sqe)
        read_media()
    elif index == 12:
        sqe, raw = dataset([(0, 8), (16, 8)], 0x02000004)
        put(0x02000004, raw)
        add(sqe)
        read_media()
    elif index == 13:
        sqe, raw = dataset([(0, 8), (9, 1), (16, 8)], 0x02000004)
        put(0x02000004, raw)
        add(sqe)
        read_media()
    elif index == 14:
        entries = [(0, 8)] * 256
        entries[-1] = (24, 8)
        sqe, raw = dataset(entries, 0x02000FFC)
        struct.pack_into('<Q', sqe, 32, 0x02002000)
        put(0x02000FFC, raw[:4])
        put(0x02002000, raw[4:])
        add(sqe)
        read_media()
    elif index == 15:
        sqe, raw = dataset([(8, 8), (24, 8)], 0x02000003, mode=2, attributes=7)
        put(0x02000003, raw)
        add(sqe)
        read_media()
    else:
        raise ValueError(index)
    for slot, sqe in enumerate(commands):
        struct.pack_into('<H', sqe, 2, 0x6000 + slot)
    header = struct.pack('<III', len(commands), len(writes), len(output))
    raw = header + b''.join(commands)
    raw += b''.join(struct.pack('<II', a, b) for a, b in writes + output)
    return raw, expected, output


def media_contract(index):
    # Primary command effects; DSM choices remain optional per logical block.
    zeroes = {3: {3, 4}, 4: {31}, 11: {7}}.get(index, set())
    optional = {
        5: {3, 4, 5},
        7: {1, 30},
        8: {2, 3, 31},
        11: {10, 11},
        12: set(range(0, 8)) | set(range(16, 24)),
        13: set(range(0, 8)) | {9} | set(range(16, 24)),
        14: set(range(0, 8)) | set(range(24, 32)),
        15: set(range(8, 16)) | set(range(24, 32)),
    }.get(index, set())
    return zeroes, optional


def validate_reference_media(index, media):
    initial = initial_disk()
    mandatory, advisory = media_contract(index)
    assert len(media) == len(initial)
    for block in range(32):
        got = media[block * 512 : (block + 1) * 512]
        original = initial[block * 512 : (block + 1) * 512]
        if block in mandatory:
            assert got == bytes(512), (index, block, 'mandatory Write Zeroes')
        elif block in advisory:
            assert got in (original, bytes(512)), (
                index,
                block,
                'advisory block integrity',
            )
        else:
            assert got == original, (index, block, 'unrequested block changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--repo', type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--discard', choices=['ignore', 'unmap'], default='unmap')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--target-dir', type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    here = Path(__file__).resolve().parent
    if not (repo / 'src/devices/nvme/nvm.rs').is_file():
        raise ValueError('--repo must name a checkout with the NVM command module')
    if not args.reference_only and here.parents[1] != repo:
        raise ValueError('Run the tool from the selected checkout')
    if not args.reference_only and (
        args.target_dir is None
        or not (args.target_dir.resolve() / 'debug/librax.rlib').is_file()
    ):
        raise ValueError('--target-dir must contain a built debug/librax.rlib')
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    marker = out / '.rax-nvme-commands'
    if any(out.iterdir()) and (
        not marker.is_file() or marker.read_text() != 'version=1\n'
    ):
        raise ValueError('Use an empty or owned version1 evidence directory')
    marker.write_text('version=1\n')
    sources = [
        'src/devices/nvme.rs',
        'src/devices/nvme/nvm.rs',
        'src/devices/nvme/prp.rs',
        'src/devices/nvme/sgl.rs',
        'tests/suites/devices/nvme_prp.rs',
        'tests/suites/devices/nvme_commands.rs',
    ]
    bound = {n: sha(repo / n) for n in sources}
    manifest = dict(
        version=1,
        cases=len(CASES),
        product_source_sha256=bound,
        tool_sha256=sha(Path(__file__)),
        guest_source_sha256=sha(here / 'commands_guest.s'),
        commands=[],
        cases_completed=[],
        scope=__doc__,
        reference_drive_discard=args.discard,
    )

    def run(name, command, cwd=out, expected=0):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            manifest['commands'].append(dict(name=name, args=command, code='timeout'))
            (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            raise RuntimeError(name + ' timed out; no passing result') from None
        (cwd / (name + '.stdout')).write_bytes(result.stdout)
        (cwd / (name + '.stderr')).write_bytes(result.stderr)
        manifest['commands'].append(
            dict(
                name=name,
                args=command,
                code=result.returncode,
                seconds=time.monotonic() - start,
            )
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        if result.returncode != expected:
            raise RuntimeError(
                f'{name} returned {result.returncode}; diagnostics retained'
            )

    run('qemu-version', [args.qemu, '--version'])
    llvm = args.llvm_bin.resolve()
    run('llvm-version', [str(llvm / 'llvm-mc'), '--version'])
    for index, name in enumerate(CASES):
        case = out / f'case-{index}'
        case.mkdir(exist_ok=True)
        raw, expected, output = make_input(index)
        (case / 'input.bin').write_bytes(raw)
        (case / 'initial.raw').write_bytes(initial_disk())
        (case / 'disk.raw').write_bytes(initial_disk())
        shutil.copyfile(here / 'commands_guest.s', case / 'guest.s')
        (case / 'link.ld').write_text(
            'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n'
        )
        run(
            'assemble',
            [
                str(llvm / 'llvm-mc'),
                '-triple=i386-none-elf',
                '-filetype=obj',
                'guest.s',
                '-o',
                'guest.o',
            ],
            case,
        )
        run(
            'link',
            [
                str(llvm / 'ld.lld'),
                '-m',
                'elf_i386',
                '-T',
                'link.ld',
                'guest.o',
                '-o',
                'guest.elf',
            ],
            case,
        )
        run(
            'qemu',
            [
                args.qemu,
                '-machine',
                'pc',
                '-cpu',
                'max',
                '-accel',
                'tcg,thread=single',
                '-m',
                '128M',
                '-nodefaults',
                '-display',
                'none',
                '-monitor',
                'none',
                '-serial',
                'none',
                '-debugcon',
                'file:' + str(case / 'records.bin'),
                '-drive',
                f'if=none,id=disk,format=raw,discard={args.discard},file='
                + str(case / 'disk.raw'),
                '-device',
                'nvme,drive=disk,serial=RAXNVCMD,mdts=9',
                '-device',
                'isa-debug-exit,iobase=0xf4,iosize=0x04',
                '-no-reboot',
                '-kernel',
                str(case / 'guest.elf'),
            ],
            case,
            33,
        )
        records = (case / 'records.bin').read_bytes()
        count = len(expected)
        payload = sum(length for _, length in output)
        assert records[:8] == b'RAXNVCM2' and records[8:20] == raw[:12]
        assert records[-8:] == b'NVCMDONE' and len(records) == 40 + count * 16 + payload
        capability, sgls, nn = struct.unpack_from('<III', records, 20)
        assert capability & 0x0D == 0x0D and sgls & 3 == 1
        cqes = []
        for slot, status in enumerate(expected):
            cqe = records[32 + 16 * slot : 48 + 16 * slot]
            head, sqid, cid, sf = struct.unpack('<HHHH', cqe[8:])
            assert (head, sqid, cid, sf & 1) == (slot + 1, 1, 0x6000 + slot, 1)
            if index == 9 and slot == 0:
                assert nn >= 2, (
                    'Reference NSID2 must be an inactive in-range identifier'
                )
                status = 2
            assert (sf >> 1) & ~0x4000 == status, (index, slot, cqe.hex(), status)
            cqes.append(cqe.hex())
        validate_reference_media(index, (case / 'disk.raw').read_bytes())
        if output:
            assert len(output) == 1 and payload == 16384
            assert records[32 + count * 16 : -8] == (case / 'disk.raw').read_bytes()
        manifest['cases_completed'].append(
            dict(
                index=index,
                name=name,
                io_commands=count,
                payload_bytes=payload,
                raw_capability_word=capability,
                raw_sgls=sgls,
                raw_max_namespace_id=nn,
                completions=cqes,
                artifact_sha256={
                    n: sha(case / n)
                    for n in [
                        'input.bin',
                        'initial.raw',
                        'guest.s',
                        'guest.elf',
                        'records.bin',
                        'disk.raw',
                    ]
                },
            )
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    manifest['result'] = 'reference_complete'
    if not args.reference_only:
        if args.target_dir is None:
            raise ValueError('--target-dir must contain a built debug/librax.rlib')
        library = args.target_dir.resolve() / 'debug/librax.rlib'
        before = sha(library)
        shutil.copyfile(library, out / 'librax.rlib')
        assert before == sha(library) == sha(out / 'librax.rlib')
        manifest['rax_library_sha256'] = before
        flags = [
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '-L',
            'dependency=' + str(library.parent / 'deps'),
        ]
        run(
            'owning-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                '--test',
                str(repo / 'tests/suites/devices/nvme_commands.rs'),
                *flags,
                '-o',
                str(out / 'owning'),
            ],
        )
        run('owning', [str(out / 'owning'), '--test-threads=4'])
        assert (
            '49 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
            in (out / 'owning.stdout').read_text()
        )
        comparison = here / 'commands_compare.rs'
        manifest['comparison_source_sha256'] = sha(comparison)
        run(
            'comparison-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(comparison),
                *flags,
                '-o',
                str(out / 'compare'),
            ],
        )
        run('comparison', [str(out / 'compare'), str(out)])
        report = json.loads((out / 'comparison.stdout').read_text())
        assert report['cases'] == len(CASES) and report['failed'] == 0
        manifest['report'] = report
        manifest['result'] = (
            'shared_command_contract_verified_with_advisory_and_profile_differences'
        )
    assert bound == {n: sha(repo / n) for n in bound}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(
        json.dumps(
            dict(cases=len(manifest['cases_completed']), result=manifest['result'])
        )
    )


if __name__ == '__main__':
    main()
