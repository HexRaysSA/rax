#!/usr/bin/env python3
"""Execute actual NVMe SGL DMA through a bare-metal PCI/queue guest in QEMU.

Each case starts a fresh device and private raw disk, reads the initial media,
writes0x5a through the same SGLs, clears the buffers and reads back. Every byte
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
    "direct-unaligned",
    "oversized",
    "last-segment",
    "two-segments",
    "null-entries",
    "three-segments",
    "unused-metadata-mode",
    "metadata-mode-chain",
    "512-byte-extents",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def descriptor(address, length, kind=0):
    return struct.pack('<QI3xB', address, length, kind << 4)


def make_input(index):
    a, b, c = 0x01800000, 0x01801000, 0x01802000
    x, y, z = 0x02000003, 0x02002001, 0x02004007
    nodes = {}
    psdt = 1
    if index == 0:
        total, root, data = 512, descriptor(x, 512), [(x, 512)]
    elif index == 1:
        total, root, data = 512, descriptor(x, 4096), [(x, 512)]
    elif index == 2:
        total, root, data = 1024, descriptor(a, 16, 3), [(x, 1024)]
        nodes[a] = descriptor(x, 1024)
    elif index in [3, 7]:
        total, root, data = 1024, descriptor(a, 32, 2), [(x, 333), (y, 691)]
        nodes[a] = descriptor(x, 333) + descriptor(b, 48, 3)
        nodes[b] = descriptor(0, 0) + descriptor(y, 691) + descriptor(0, 0)
        if index == 7:
            psdt = 2
    elif index == 4:
        total, root, data = 512, descriptor(a, 48, 3), [(x, 512)]
        nodes[a] = descriptor(0, 0) + descriptor(x, 512) + descriptor(0, 0)
    elif index == 5:
        total, root, data = 512, descriptor(a, 32, 2), [(x, 128), (y, 129), (z, 255)]
        nodes[a] = descriptor(x, 128) + descriptor(b, 48, 2)
        nodes[b] = descriptor(0, 0) + descriptor(y, 129) + descriptor(c, 16, 3)
        nodes[c] = descriptor(z, 255)
    elif index == 6:
        total, root, data, psdt = 512, descriptor(x, 512), [(x, 512)], 2
    elif index == 8:
        total, root = 512, descriptor(a, 8192, 3)
        data = [(x + 2 * n, 1) for n in range(512)]
        nodes[a] = b''.join(descriptor(address, length) for address, length in data)
    else:
        raise ValueError(index)
    writes = [
        (address + offset, struct.unpack('<I', raw[offset : offset + 4])[0])
        for address, raw in nodes.items()
        for offset in range(0, len(raw), 4)
    ]
    header = (
        struct.pack('<II', total, psdt)
        + root
        + struct.pack('<II', len(data), len(writes))
    )
    return header + b''.join(
        struct.pack('<II', address, value) for address, value in data + writes
    )


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
    marker = out / '.rax-nvme-sgl'
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
            'src/devices/nvme/nvm.rs',
            'src/devices/nvme/prp.rs',
            'src/devices/nvme/sgl.rs',
            'tests/suites/devices/nvme_prp.rs',
            'tests/suites/devices/nvme_sgl.rs',
        ]
    }
    manifest = {
        'product_source_sha256': bound,
        'version': 1,
        'cases': len(CASES),
        'tool_sha256': sha(Path(__file__)),
        'guest_source_sha256': sha(here / 'sgl_guest.s'),
        'commands': [],
        'cases_completed': [],
        'scope': __doc__,
        'reference_capability_projection': {
            'qemu_raw': 0x80001,
            'rax_primary': 0x40001,
            'common_basic_byte_granular': 1,
            'difference': 'QEMU advertises metadata-SGL support;RAX advertises excess-length support. Actual transfer records do not certify full capability equivalence.',
        },
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
    for index in range(len(CASES)):
        case = out / f'case-{index}'
        case.mkdir(exist_ok=True)
        (case / 'input.bin').write_bytes(make_input(index))
        shutil.copyfile(here / 'sgl_guest.s', case / 'guest.s')
        (case / 'link.ld').write_text(
            'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n'
        )
        total = struct.unpack_from('<I', (case / 'input.bin').read_bytes())[0]
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
                'nvme,drive=prpdisk,serial=RAXSGLTEST,mdts=9',
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
        header = (case / 'input.bin').read_bytes()[:32]
        assert records[:8] == b'RAXNVSG1' and records[8:40] == header
        assert len(records) == 100 + total * 2 and records[-8:] == b'NVSGDONE', (
            index,
            len(records),
            total,
        )
        reference_sgls = struct.unpack_from('<I', records, 40)[0]
        assert reference_sgls & 3 == 1, (
            'Reference lacks byte-granular basic SGL support'
        )
        # Preserve full capability differences:QEMU advertises metadata SGLs
        # but not excess length;its actual oversized-descriptor result is
        # retained separately from the RAX primary-source capability contract.
        at = 44
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
                'name': CASES[index],
                'total_bytes': total,
                'reference_sgls': reference_sgls,
                'rax_sgls_primary': 0x40001,
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
        manifest['comparison_source_sha256'] = sha(here / 'sgl_compare.rs')
        run(
            'owning-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                '--test',
                str(repo / 'tests/suites/devices/nvme_sgl.rs'),
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
            '50 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
            in (out / 'owning.stdout').read_text()
        )
        run(
            'comparison-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(here / 'sgl_compare.rs'),
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
        assert report['cases'] == 9 and report['failed'] == 0
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
