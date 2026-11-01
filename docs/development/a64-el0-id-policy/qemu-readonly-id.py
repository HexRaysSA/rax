#!/usr/bin/env python3
"""Independent EL1 read-only ID-write oracle; no RAX import or invocation."""
import argparse,hashlib,json,os,pathlib,re,shutil,subprocess,tempfile

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--output',type=pathlib.Path,required=True);parser.add_argument('--llvm-bin',type=pathlib.Path,default=pathlib.Path('/Users/int/local/bin'));parser.add_argument('--qemu',default=shutil.which('qemu-system-aarch64'));args=parser.parse_args();here=pathlib.Path(__file__).resolve().parent
 result=dict(passed=False,scope='QEMU whole-CPU EL1 Undefined/read-only controls; no physical hardware or per-field isolation claim',source_sha256={n:hashlib.sha256((here/n).read_bytes()).hexdigest() for n in ['qemu-readonly-id.s','qemu-readonly-id.py']},records=[],cases=[])
 def run(argv,cwd):
  r=subprocess.run(argv,cwd=cwd,capture_output=True,text=True);result['records'].append(dict(argv=argv,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));assert r.returncode==0,result['records'][-1];return r.stdout
 try:
  with tempfile.TemporaryDirectory(prefix='rax-id-readonly-',dir=os.environ.get('TMPDIR')) as temporary:
   work=pathlib.Path(temporary);result['qemu_version']=run([args.qemu,'--version'],work);result['llvm_version']=run([str(args.llvm_bin/'llvm-mc'),'--version'],work)
   run([str(args.llvm_bin/'llvm-mc'),'-triple=aarch64-none-elf','-filetype=obj',str(here/'qemu-readonly-id.s'),'-o','guest.o'],work)
   run([str(args.llvm_bin/'ld.lld'),'-Ttext=0x40080000','-e','_start','guest.o','-o','guest.elf'],work)
   run([str(args.llvm_bin/'llvm-objcopy'),'-O','binary','guest.elf','guest.bin'],work)
   result['binary_sha256']=hashlib.sha256((work/'guest.bin').read_bytes()).hexdigest()
   for model in ['cortex-a53','max']:
    output=run([args.qemu,'-M','virt,virtualization=on','-cpu',model,'-m','64M','-display','none','-monitor','none','-serial','stdio','-semihosting-config','enable=on,target=native','-kernel','guest.bin'],work)
    values=[int(line,16) for line in output.splitlines() if re.fullmatch('[0-9a-f]{8}',line)]
    case=dict(model=model,values=values);result['cases'].append(case)
    assert len(values)==15 and values[0]!=0 and values[0]==values[1],case
    assert values[2:5]==[4,10,0x1234],case
    assert values[5:]==[1<<25]*10,case
   result['passed']=True
 finally:args.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(dict(passed=True,cases=result['cases'])))
if __name__=='__main__':main()
