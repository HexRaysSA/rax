from pathlib import Path
import sys, json, subprocess, hashlib, os, time
revision=int(sys.argv[1])
n=Path('/tmp/rax-kvm-native-entry-ixif9sv1')
b=n/'observations'/f'cpu-context-contract-v{revision}'
p=b/'source'; p.mkdir(parents=True,exist_ok=False)
payload=json.loads((n/'observations'/f'cpu-context-payload-v{revision}.json').read_text())
for name,value in payload['files'].items():
 f=p/name; f.parent.mkdir(parents=True,exist_ok=True); f.write_text(value)
assert all(hashlib.sha256((p/name).read_bytes()).hexdigest()==sha for name,sha in payload['sha256'].items())
args=json.loads((n/'observations/cpu-context-contract-v2/build-argv.json').read_text())
args[args.index('rax_kvm_cpu_context_v2')]=f'rax_kvm_cpu_context_v{revision}'
args[args.index('--emit=dep-info,link')]='--emit=link'
args[args.index('-o')+1]=str(b/'native-probe')
(b/'build-argv.json').write_text(json.dumps(args,indent=2)+'\n')
(b/'driver.py').write_bytes(Path(__file__).read_bytes())
reports=[]
if (p/'helpers/nested-image-v5.c').exists():
 cc=['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-c',str(p/'helpers/nested-image-v5.c'),'-o',str(b/'nested-helper.o')]
 with (b/'cc.log').open('x') as log: code=subprocess.run(cc,cwd=p,stdout=log,stderr=subprocess.STDOUT).returncode
 reports.append(dict(label='cc',exit_code=code,argv=cc))
 print('CC',code,flush=True)
 if code:
  print((b/'cc.log').read_text(),flush=True)
  raise SystemExit(code)
 args.extend(['-C','link-arg='+str(b/'nested-helper.o')])
 (b/'build-argv.json').write_text(json.dumps(args,indent=2)+'\n')
for label,argv in [('build',args),('clippy',[str(Path(args[0]).with_name('clippy-driver')), *[('--emit=metadata' if arg=='--emit=link' else str(b/'clippy.rmeta') if arg==str(b/'native-probe') else arg) for arg in args[1:]]]),('run',[str(b/'native-probe')])]:
 start=time.monotonic()
 with (b/f'{label}.log').open('x') as log:
  child=subprocess.Popen(argv,cwd=p,stdout=log,stderr=subprocess.STDOUT)
  print(json.dumps(dict(event='start',label=label,pid=child.pid)),flush=True)
  code=child.wait()
 report=dict(label=label,exit_code=code,seconds=time.monotonic()-start,argv=argv)
 reports.append(report);(b/f'{label}.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(dict(label=label,exit_code=code)),flush=True)
 for line in (b/f'{label}.log').read_text().splitlines():
  try:
   v=json.loads(line)
   if v.get('level')=='error': print(v.get('rendered',v['message']),flush=True)
  except Exception:print(line,flush=True)
 if code:break
(b/'result.json').write_text(json.dumps(dict(commands=reports,source_sha256=payload['sha256'],complete_native_producer=False),indent=2)+'\n')
