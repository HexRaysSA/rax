#!/usr/bin/env python3
"""Execute STI followed by CPUID/HLT with a proven pending PIT/PIC interrupt.

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
    parser.add_argument('--event-module', type=Path)
    args = parser.parse_args()
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    owner = out / '.rax-hvf-interrupt-shadow'
    if any(out.iterdir()) and (not owner.is_file() or owner.read_text() != 'version=1\n'):
        raise ValueError('Use an empty or owned version1 directory')
    owner.write_text('version=1\n')
    module = (args.module or args.repo / 'src/backend/hvf/interrupt_shadow.rs').resolve()
    guest = Path(__file__).with_name('interrupt_shadow_guest.s')
    cases = [(0, n) for n in [2, 3, 15]] + [(1, n) for n in [1, 2, 15]]
    (out / 'cases.bin').write_bytes(b''.join(struct.pack('<II', *case) for case in cases))
    (out / 'guest.s').write_text(guest.read_text().replace('@CASE_COUNT@', str(len(cases))))
    (out / 'link.ld').write_text('ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n')
    # Include the actual product module; its fallible access trait is exercised,
    # including fault preservation and success commit order, on the same records.
    event_module = (args.event_module or args.repo / 'src/backend/hvf/event_injection.rs').resolve()
    rust = '#[path=MODULE] mod interrupt_shadow;\n#[path=EVENT] mod event_injection;\nuse interrupt_shadow::Access;\nstruct Host {state:u64,ip:u64}\nimpl Access for Host {\n type Error=();fn interruptibility(&mut self)->Result<u64,()>{Ok(self.state)}\n fn advance_ip(&mut self)->Result<(),()>{self.ip+=1;Ok(())}\n fn write_interruptibility(&mut self,v:u64)->Result<(),()>{self.state=v;Ok(())}\n}\nimpl event_injection::Access for Host {\n type Error=();fn entry_information(&mut self)->Result<u64,()>{Ok(0)}\n fn rflags(&mut self)->Result<u64,()>{Ok(0x202)}\n fn interruptibility(&mut self)->Result<u64,()>{Ok(self.state)}\n fn write_entry_information(&mut self,_:u64)->Result<(),()>{Ok(())}\n}\nfn word(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}\nfn main(){\n let a:Vec<_>=std::env::args().collect();let c=std::fs::read(&a[1]).unwrap();let r=std::fs::read(&a[2]).unwrap();let n=c.len()/8;\n assert_eq!(c.len()%8,0);assert_eq!(r.len(),20+n*8);assert_eq!(&r[..8],b"RAXSH001");assert_eq!(word(&r,8)as usize,n);assert_eq!(&r[12+n*8..],b"SH_DONE!");\n let(mut failed,mut reference_failed,mut hlt)=(0,0,0);\n for(i,c)in c.chunks_exact(8).enumerate(){let kind=word(c,0);let len=word(c,4);if kind==1{hlt+=1};let observed=word(&r,12+i*8);let count=word(&r,16+i*8);if observed!=0x200001+len||count!=1{reference_failed+=1;}\n let mut h=Host{state:1,ip:0};interrupt_shadow::complete(&mut h).unwrap();if h.ip!=1||!event_injection::available(&mut h,event_injection::Event::Interrupt(0x20)).unwrap(){failed+=1;}\n }\n println!("{{\\"cases\\":{n},\\"hlt_cases\\":{hlt},\\"failed\\":{failed},\\"reference_failed\\":{reference_failed}}}");if failed!=0||reference_failed!=0{std::process::exit(1)}\n}\n'.replace('MODULE', json.dumps(str(module))).replace('EVENT', json.dumps(str(event_module)))
    (out / 'compare.rs').write_text(rust)
    manifest = {'version': 1, 'cases': len(cases), 'tool_sha256': sha(Path(__file__)),
                'comparison_masks': {}, 'event_module_sha256': sha(event_module), 'guest_source_sha256': sha(guest), 'module_sha256': sha(module),
                'commands': [], 'scope': 'Six CPL0 STI;CPUID/HLT cases with PIC IRR IRQ0 verified pending before STI; full saved EIP and interrupt count. TCG direct instructions, not native VMX.'}
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
    assert report['cases'] == 6 and report['hlt_cases'] == 3, report
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
