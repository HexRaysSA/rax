#!/usr/bin/env python3
"""Execute actual scalar IN instructions and compare complete RAX/flags records.

This is TCG instruction/fallthrough evidence, not native Intel VMX exit delivery.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--module', type=Path)
    args = parser.parse_args()
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    owner = out / '.rax-hvf-port-io'
    if any(out.iterdir()) and (not owner.is_file() or owner.read_text() != 'version=1\n'):
        raise ValueError('Use an empty or owned version1 directory')
    owner.write_text('version=1\n')
    module = (args.module or args.repo / 'src/backend/hvf/port_io.rs').resolve()
    guest = Path(__file__).with_name('port_io_guest.s')
    values = [0, 0xffffffffffffffff, 0x123456789abcdef0, 0x8000000000000000, 0x00000000ffffffff, 0xfedcba9876543210]
    cases = [(width, form, old) for width in [1, 2, 4] for form in [0, 1] for old in values]
    (out / 'cases.bin').write_bytes(b''.join(struct.pack('<IIQ', *case) for case in cases))
    (out / 'guest.s').write_text(guest.read_text().replace('@CASE_COUNT@', str(len(cases))))
    (out / 'link.ld').write_text('ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n')
    # Include the actual product module; its fallible access trait is exercised,
    # including fault preservation and success commit order, on the same records.
    rust = '#[path=MODULE] mod port_io;\nfn word(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}\nfn quad(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}\nfn main(){let a:Vec<_>=std::env::args().collect();let c=std::fs::read(&a[1]).unwrap();let r=std::fs::read(&a[2]).unwrap();let n=c.len()/16;\n assert_eq!(c.len()%16,0);assert_eq!(r.len(),20+n*24);assert_eq!(&r[..8],b"RAXIO001");assert_eq!(word(&r,8)as usize,n);assert_eq!(&r[12+n*24..],b"IO_DONE!");\n let(mut failed,mut flags_failed,mut preserved_upper_cases)=(0,0,0);\n for(i,c)in c.chunks_exact(16).enumerate(){let width=word(c,0)as u8;let old=quad(c,8);let raw=&r[12+i*24..12+(i+1)*24];let actual=quad(raw,0);let bytes=actual.to_le_bytes();\n if width<4 {preserved_upper_cases+=1};let predicted=port_io::input_value(old,width,&bytes[..width as usize]).unwrap();if predicted!=actual{failed+=1;eprintln!("case{i}:width{width},old{old:x},predicted{predicted:x},actual{actual:x}");}\n if quad(raw,8)!=quad(raw,16){flags_failed+=1;}\n }\n println!("{{\\"cases\\":{n},\\"preserved_upper_cases\\":{preserved_upper_cases},\\"failed\\":{failed},\\"flags_failed\\":{flags_failed}}}");if failed!=0||flags_failed!=0{std::process::exit(1)}\n}\n'.replace('MODULE',json.dumps(str(module)))
    (out / 'compare.rs').write_text(rust)
    manifest = {'version': 1, 'cases': len(cases), 'tool_sha256': sha(Path(__file__)),
                'comparison_masks': {}, 'guest_source_sha256': sha(guest), 'module_sha256': sha(module),
                'commands': [], 'scope': 'Thirty-six actual CPL0 IN AL/AX/EAX executions in long mode, DX/immediate port encoding and6 prior RAX patterns; complete RAX and before/after flags compared. Lower input bytes are captured reference values, not assumed device constants. TCG, not native VMX.'}
    def run(name, command, expected=0):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=out, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=60)
        except subprocess.TimeoutExpired:
            manifest['commands'].append({'name': name, 'args': command, 'code': 'timeout',
                                         'seconds': time.monotonic() - start})
            (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            raise RuntimeError(f'{name} exceeded60s; no passing result') from None
        (out / (name + '.stdout')).write_text(result.stdout)
        (out / (name + '.stderr')).write_text(result.stderr)
        manifest['commands'].append({'name': name, 'args': command, 'code': result.returncode,
                                     'seconds': time.monotonic() - start})
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        if expected is not None and result.returncode != expected:
            raise RuntimeError(f'{name}: code{result.returncode}; see retained diagnostics')
        return result
    llvm = args.llvm_bin.resolve()
    run('qemu-version', [args.qemu, '--version'])
    run('llvm-version', [str(llvm / 'llvm-mc'), '--version'])
    run('rust-version', ['rustc', '+stable', '-vV'])
    run('assemble', [str(llvm / 'llvm-mc'), '-triple=i386-none-elf', '-filetype=obj', 'guest.s', '-o', 'guest.o'])
    run('link', [str(llvm / 'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld', 'guest.o', '-o', 'guest.elf'])
    run('qemu', [args.qemu, '-machine', 'pc', '-cpu', 'Haswell-noTSX', '-accel', 'tcg,thread=single', '-m', '64M', '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none', '-debugcon', 'file:' + str(out / 'results.bin'), '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-no-reboot', '-kernel', str(out / 'guest.elf')], 33)
    run('compare-build', ['rustc', '+stable', '--edition=2024', 'compare.rs', '-o', 'compare'])
    result = run('compare', [str(out / 'compare'), str(out / 'cases.bin'), str(out / 'results.bin')], expected=None)
    assert result.returncode in (0, 1)
    report = json.loads(result.stdout)
    assert report['cases'] == 36 and report['preserved_upper_cases'] == 24, report
    assert result.returncode == int(report['failed'] != 0 or report['flags_failed'] != 0)
    assert sha(module) == manifest['module_sha256']
    manifest['artifact_sha256'] = {name: sha(out / name) for name in ['cases.bin', 'results.bin', 'guest.s', 'guest.elf', 'compare.rs']}
    manifest['report'] = report
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(report))
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
