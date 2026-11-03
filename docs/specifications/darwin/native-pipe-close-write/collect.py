from pathlib import Path
import os,subprocess,json,hashlib,time,platform,traceback
root=Path(__file__).resolve().parents[4];source_dir=Path(__file__).resolve().parent
import sys
if platform.system() != 'Darwin': raise SystemExit('native collector requires macOS; verify.py works on all hosts')
if len(sys.argv) != 2: raise SystemExit('usage: python3 collect.py <fresh in-repository build directory>')
build=Path(sys.argv[1]).resolve()
assert build.is_relative_to(root.resolve()) and build != root.resolve(), 'build directory must be inside this worktree'
q=build
assert not build.exists();build.mkdir(parents=True);(build/'.owner').write_text('darwin-pipe-close-signal-v1\n');(build/'tmp').mkdir()
env=dict(os.environ,TMPDIR=str(build/'tmp'),TMP=str(build/'tmp'),TEMP=str(build/'tmp'),CCACHE_DISABLE='1',SCCACHE_DISABLE='1')
state={'state':'building','pid':os.getpid(),'host':list(platform.uname()),'builds':[],'cases':[],'original_jobs_restarted':False};receipt=q/'native-signal-v1.json'
def save():receipt.write_text(json.dumps(state,indent=2)+'\n')
try:
 src=source_dir/'native-pipe-close-signal-v1.c';state['source_sha256']=hashlib.sha256(src.read_bytes()).hexdigest()
 for arch in ['arm64','x86_64']:
  image=build/('native-pipe-close-signal-'+arch+'-v1');args=['/usr/bin/clang','-arch',arch,'-std=c11','-O0','-Wall','-Wextra','-I',str(root/'docs/specifications/darwin/native-guarded-fd'),str(src),'-o',str(image)]
  p=subprocess.run(args,cwd=root,env=env,capture_output=True,text=True);state['builds'].append({'architecture':arch,'argv':args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr});save();assert p.returncode==0,p.stderr
  ih=hashlib.sha256(image.read_bytes()).hexdigest();state['builds'][-1]['image_sha256']=ih;save()
  for vector in [0,1]:
   for kind in ['pipe','fifo']:
    for suppress in [0,1]:
     path=build/f'{arch}-{vector}-{kind}-{suppress}.fifo';args=[str(image),str(vector),'1','0',kind,str(path),str(suppress)];start=time.monotonic();p=subprocess.run(args,cwd=root,env=env,capture_output=True,text=True,timeout=15)
     row={'architecture':arch,'vector':bool(vector),'kind':kind,'suppress_sigpipe':bool(suppress),'argv':args,'image_sha256':ih,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'seconds':time.monotonic()-start};state['cases'].append(row);save();assert p.returncode==0,row
     lines=[json.loads(l) for l in p.stdout.splitlines()];results={r['kind']:r for r in lines};assert results['writer-was-blocked']['result']==1
     expected_signals=int(kind=='pipe' and suppress==0);assert results['observed-sigpipe']['result']==expected_signals,row
     assert results['write-result']['result']==(-1 if kind=='pipe' else 1),row
     if kind=='pipe':assert results['write-result']['errno']==32,row
     assert not path.exists()
  assert hashlib.sha256(image.read_bytes()).hexdigest()==ih
 state.update(state='qualified',exit_code=0,case_count=len(state['cases']))
except BaseException:state.update(state='failed',exit_code=1,error=traceback.format_exc())
finally:save()
print(state['state'],len(state['cases']),flush=True);raise SystemExit(state['exit_code'])
