#!/usr/bin/env python3
"""Execute actual NVMe PRP DMA through a bare-metal PCI/queue guest in QEMU.

Each case starts a fresh device and private raw disk, reads the initial media,
writes0x5a through the same PRPs, clears the buffers and reads back. Every byte
and all three I/O completion records are retained;no RAX-generated reference.
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
    (9, 0, 0),
    (24, 4, 8),
    (4088, 4092, 4080),
    (4096, 4092, 4088),
    (17, 0, 0),
    (16, 4092, 4088),
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_input(blocks, first_offset, list_offset):
    total = blocks * 512
    first = 0x02000000 + first_offset
    length = min(total, 4096 - first_offset)
    segments = [(first, length)]
    left = total - length
    index = 1
    while left:
        length = min(left, 4096)
        segments.append((0x02000000 + index * 8192, length))
        left -= length
        index += 1
    entries = []
    second = 0
    if len(segments) == 2:
        second = segments[1][0]
    elif len(segments) > 2:
        second = 0x01800000 + list_offset
        cursor = second
        next_list = 0x01810000
        at = 1
        while at < len(segments):
            capacity = (4096 - cursor % 4096) // 8
            count = min(len(segments) - at, capacity)
            chained = len(segments) - at > capacity
            if chained:
                count -= 1
            entries.extend((cursor + 8 * n, segments[at + n][0]) for n in range(count))
            at += count
            if chained:
                entries.append((cursor + 8 * count, next_list))
                cursor = next_list
                next_list += 4096
    header = struct.pack('<IIIII', total, first, second, len(segments), len(entries))
    return header + b''.join(struct.pack('<II', a, n) for a, n in segments + entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--repo', type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--target-dir', type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    if not (repo / 'src/devices/nvme.rs').is_file():
        raise ValueError('--repo must name a RAX checkout')
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    marker = out / '.rax-nvme-prp'
    if any(out.iterdir()) and (
        not marker.is_file() or marker.read_text() != 'version=1\n'
    ):
        raise ValueError('Use an empty or owned version1 directory')
    marker.write_text('version=1\n')
    here = Path(__file__).resolve().parent
    if not args.reference_only and here.parents[1].resolve() != repo:
        raise ValueError('Run the comparison tool from the selected --repo checkout')
    if not args.reference_only and (
        args.target_dir is None
        or not (args.target_dir.resolve() / 'debug/librax.rlib').is_file()
    ):
        raise ValueError(
            '--target-dir must contain a built debug/librax.rlib;run cargo build --lib first'
        )
    bound = {
        name: sha(repo / name)
        for name in [
            'src/devices/nvme.rs',
            'src/devices/nvme/prp.rs',
            'tests/suites/devices/nvme_prp.rs',
        ]
    }
    manifest = {
        'product_source_sha256': bound,
        'version': 1,
        'cases': len(CASES),
        'tool_sha256': sha(Path(__file__)),
        'guest_source_sha256': sha(here / 'prp_guest.s'),
        'commands': [],
        'cases_completed': [],
        'scope': __doc__,
        'guest_ram_bytes': 128 << 20,
        'reference_limit': 'QEMU mdts9 permits2MiB commands;host IOV_MAX1024 rejects mdts0 or10. Local primary-contract tests independently cover32MiB.',
    }

    def run(name, command, cwd=out, expected=0):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            manifest['commands'].append(
                {
                    'name': name,
                    'args': command,
                    'code': 'timeout',
                    'seconds': time.monotonic() - start,
                }
            )
            (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            raise RuntimeError(name + ' timed out;no passing result') from None
        (cwd / (name + '.stdout')).write_bytes(result.stdout)
        (cwd / (name + '.stderr')).write_bytes(result.stderr)
        manifest['commands'].append(
            {
                'name': name,
                'args': command,
                'code': result.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        if result.returncode != expected:
            raise RuntimeError(
                name + f' returned{result.returncode};retained raw diagnostics'
            )

    run('qemu-version', [args.qemu, '--version'])
    run('nvme-options', [args.qemu, '-device', 'nvme,help'])
    llvm = args.llvm_bin.resolve()
    run('llvm-version', [str(llvm / 'llvm-mc'), '--version'])
    for index, (blocks, first, list_offset) in enumerate(CASES):
        case = out / f'case-{index}'
        case.mkdir(exist_ok=True)
        (case / 'input.bin').write_bytes(make_input(blocks, first, list_offset))
        shutil.copyfile(here / 'prp_guest.s', case / 'guest.s')
        (case / 'link.ld').write_text(
            'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n'
        )
        total = blocks * 512
        initial = bytes((i * 17 ^ (i >> 9)) & 255 for i in range(total))
        (case / 'disk.raw').write_bytes(initial)
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
                'if=none,id=prpdisk,format=raw,file=' + str(case / 'disk.raw'),
                '-device',
                'nvme,drive=prpdisk,serial=RAXPRPTEST,mdts=9',
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
        header = (case / 'input.bin').read_bytes()[:20]
        assert records[:8] == b'RAXNVPR1' and records[8:28] == header
        assert len(records) == 84 + total * 2 and records[-8:] == b'NVPRDONE', (
            index,
            len(records),
            total,
        )
        at = 28
        completion = []
        for slot in range(3):
            cqe = records[at : at + 16]
            at += 16
            head, sqid, cid, status = struct.unpack('<HHHH', cqe[8:16])
            assert (head, sqid, cid, status) == (slot + 1, 1, 0x73A5, 1), (
                index,
                slot,
                cqe.hex(),
            )
            completion.append(cqe.hex())
            if slot == 0:
                assert records[at : at + total] == initial
                at += total
            if slot == 2:
                assert records[at : at + total] == b'\x5a' * total
                at += total
        assert at == len(records) - 8
        assert (case / 'disk.raw').read_bytes() == b'\x5a' * total
        manifest['cases_completed'].append(
            {
                'index': index,
                'blocks': blocks,
                'first_offset': first,
                'list_offset': list_offset,
                'bytes_compared': 2 * total,
                'completions': completion,
                'artifact_sha256': {
                    name: sha(case / name)
                    for name in [
                        'input.bin',
                        'guest.s',
                        'guest.elf',
                        'records.bin',
                        'disk.raw',
                    ]
                },
            }
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    manifest['result'] = 'reference_complete'
    if not args.reference_only:
        if args.target_dir is None:
            raise ValueError('--target-dir required for product comparison')
        # The comparator executes the exact production device through the same
        # public queue interface;its expected payloads are these actual bytes.
        library = args.target_dir.resolve() / 'debug/librax.rlib'
        before_library = sha(library)
        shutil.copyfile(library, out / 'librax.rlib')
        assert before_library == sha(library) == sha(out / 'librax.rlib'), (
            'Helper library changed while captured'
        )
        manifest['rax_library_sha256'] = before_library
        manifest['comparison_source_sha256'] = sha(here / 'prp_compare.rs')
        run(
            'owning-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                '--test',
                str(repo / 'tests/suites/devices/nvme_prp.rs'),
                '--extern',
                'rax=' + str(out / 'librax.rlib'),
                '-L',
                'dependency=' + str(library.parent / 'deps'),
                '-o',
                str(out / 'owning'),
            ],
        )
        run('owning', [str(out / 'owning'), '--test-threads=4'])
        assert (
            '32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
            in (out / 'owning.stdout').read_text()
        )
        run(
            'comparison-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(here / 'prp_compare.rs'),
                '--extern',
                'rax=' + str(out / 'librax.rlib'),
                '-L',
                'dependency=' + str(library.parent / 'deps'),
                '-o',
                str(out / 'compare'),
            ],
        )
        run('comparison', [str(out / 'compare'), str(out)])
        report = json.loads((out / 'comparison.stdout').read_text())
        assert report['cases'] == 6 and report['failed'] == 0
        manifest['report'] = report
        manifest['result'] = 'reference_and_product_match'
    assert bound == {name: sha(repo / name) for name in bound}, (
        'Product changed during reference/product comparison'
    )
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(
        json.dumps(
            {'cases': len(manifest['cases_completed']), 'result': manifest['result']}
        )
    )


if __name__ == '__main__':
    main()
