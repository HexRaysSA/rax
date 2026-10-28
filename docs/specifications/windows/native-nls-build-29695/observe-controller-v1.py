from pathlib import Path
import hashlib,importlib.util,json,os,subprocess,sys,time,traceback
R=Path('C:/Windows/Temp/assist-native-rax-20261010/src-display-candidate1')
O=R/'target/native-nls-29695-observe-v1'
s={'pid':os.getpid(),'created_epoch_seconds':time.time(),'kernel':list(sys.getwindowsversion()),'state':'checking','commands':[],'samples':[]}
def save():(O/'receipt.json').write_text(json.dumps(s,indent=2))
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(argv,env,cwd,label):
 start=time.monotonic()
 with (O/(label+'.log')).open('wb') as log:
  child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log);s.update(state=label,child_pid=child.pid);save();code=child.wait()
 s['commands'].append({'argv':argv,'exit_code':code,'seconds':time.monotonic()-start});save();return code
save()
try:
 assert sys.getwindowsversion().build==29695
 helper=R/'docs/specifications/windows/native-exception-entry-profile/run-v2.py';sources={n:O/(n+'.cpp') for n in ['leaf','mui','initialize','protect']};before={str(p):digest(p) for p in [*sources.values(),O/'driver.py',helper]};s['inputs_sha256']=before;save()
 spec=importlib.util.spec_from_file_location('profile',helper);profile=importlib.util.module_from_spec(spec);spec.loader.exec_module(profile)
 for arch in ['arm64','x64','x86','x86-laa']:
  target='x86' if arch=='x86-laa' else arch
  kinds=['leaf','mui']+(['initialize','protect'] if target!='x86' else [])
  for kind in kinds:
   label=arch+'-'+kind;build=O/label;build.mkdir();tmp=build/'tmp';tmp.mkdir()
   env,compiler=profile.compiler_environment(target,str(R/'target/win32u-validation-recovery-v2/transfer/mutant-native-compiler-env-epoch4.json'),tmp);compiler=Path(compiler);compiler_hash=digest(compiler);exe=build/(label+'.exe')
   argv=[str(compiler),'/nologo','/std:c++20','/MT','/EHsc','/utf-8','/W4','/WX',str(sources[kind]),'psapi.lib','/Fe:'+str(exe),'/Fo:'+str(build/'probe.obj')]
   if arch=='x86-laa':argv+=['/link','/LARGEADDRESSAWARE']
   assert run(argv,env,build,label+'-compile')==0
   exe_hash=digest(exe);code=run([str(exe)],env,build,label+'-observe');text=(O/(label+'-observe.log')).read_text();row={'arch':arch,'kind':kind,'source_sha256':digest(sources[kind]),'compiler_sha256':compiler_hash,'binary_sha256':exe_hash,'binary_bytes':exe.stat().st_size,'stdout_sha256':digest(O/(label+'-observe.log')),'exit_code':code,'terminal':text.splitlines()[-1] if text.splitlines() else ''}
   if (build/'mui.bin').exists():row['payload']={'bytes':(build/'mui.bin').stat().st_size,'sha256':digest(build/'mui.bin')}
   assert digest(exe)==exe_hash and digest(compiler)==compiler_hash and all(digest(p)==h for p,h in before.items());row['inputs_unchanged']=True;s['samples'].append(row);save();assert code==0
 s.update(state='finished',exit_code=0)
except BaseException:s.update(state='failed',exit_code=1,error=traceback.format_exc())
finally:save()
