#!/usr/bin/env python3
"""Execute prefixed CPUID with actual #DB records across legacy code-size boundaries.

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
    parser.add_argument('--qemu', default='qemu-system-i386')
    parser.add_argument('--module', type=Path)
    args = parser.parse_args()
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    owner = out / '.rax-hvf-sync_exit'
    if any(out.iterdir()) and (not owner.is_file() or owner.read_text() != 'version=1\n'):
        raise ValueError('Use an empty or owned version1 directory')
    owner.write_text('version=1\n')
    module = (args.module or args.repo / 'src/backend/hvf/sync_exit.rs').resolve()
    guest = Path(__file__).with_name('sync_exit_guest.s')
    cases = [(selector, end - length, end, length)
             for selector in [8, 24] for end in [0x100, 0x10000] for length in [2, 3, 15]]
    (out / 'cases.bin').write_bytes(b''.join(struct.pack('<IIII', *case) for case in cases))
    (out / 'guest.s').write_text(guest.read_text().replace('@CASE_COUNT@', str(len(cases))))
    (out / 'link.ld').write_text('ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n')
    # Include the actual product module; its fallible access trait is exercised,
    # including fault preservation and success commit order, on the same records.
    rust = '#[path=' + json.dumps(str(module)) + '] mod sync_exit;\n' + r'''
fn word(b:&[u8],i:usize)->u32 {u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn main() {
 let args:Vec<_>=std::env::args().collect();let cases=std::fs::read(&args[1]).unwrap();let raw=std::fs::read(&args[2]).unwrap();let n=cases.len()/16;
 assert_eq!(cases.len()%16,0);assert_eq!(raw.len(),20+n*12);assert_eq!(&raw[..8],b"RAXIP001");assert_eq!(word(&raw,8) as usize,n);assert_eq!(&raw[12+n*12..],b"IP_DONE!");
 let mut failed=0;let mut reference_failed=0;let mut decode16=0;
 for (index,c) in cases.chunks_exact(16).enumerate() {
  let selector=word(c,0);let start=u64::from(word(c,4));let end=word(c,8);let length=u64::from(word(c,12));let cs_access=if selector==24 {decode16+=1;0x809b}else{0xc09b};
  let bits=sync_exit::code_width(0,cs_access);let predicted=sync_exit::next_ip(start,length,bits).unwrap();let r=&raw[12+index*12..12+(index+1)*12];let observed=(word(r,0),word(r,4)&0xffff,word(r,8));
  if observed!=(end,selector,2) {reference_failed+=1;}
  if predicted!=u64::from(observed.0) {failed+=1;eprintln!("case{index}:selector={selector:x} start={start:x} length={length} bits={bits} predicted={predicted:x} actual={observed:?}");}
 }
 println!("{{\"cases\":{n},\"decode16_cases\":{decode16},\"failed\":{failed},\"reference_failed\":{reference_failed}}}");if failed!=0 || reference_failed!=0 {std::process::exit(1)}
}
'''
    (out / 'compare.rs').write_text(rust)
    manifest = {'version': 1, 'cases': len(cases), 'tool_sha256': sha(Path(__file__)),
                'comparison_masks': {'saved_cs_selector': 'low16 only; full32 EIP compared; raw stack padding retained'}, 'guest_source_sha256': sha(guest), 'module_sha256': sha(module),
                'commands': [], 'scope': 'Twelve CPL0 CPUID executions with actual debug traps in16/32-bit decoding, lengths2/3/15 and64KiB boundary crossing. Non64 EIP is32-bit. Not native VMX.'}
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
    assert report['cases'] == 12 and report['decode16_cases'] == 6, report
    assert result.returncode == int(report['failed'] != 0 or report['reference_failed'] != 0)
    assert sha(module) == manifest['module_sha256']
    manifest['artifact_sha256'] = {name: sha(out / name) for name in ['cases.bin', 'results.bin', 'guest.s', 'guest.elf', 'compare.rs']}
    manifest['report'] = report
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(report))
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
