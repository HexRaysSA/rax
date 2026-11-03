from pathlib import Path
import hashlib,json,os,subprocess
r=Path('/work');out=r/'.task-evidence/darwin-timed-record-locks-v1';tmp=r/'target/qualified-v1/tmp/darwin-timed-lock-linux-baseline-v2';tmp.mkdir();(tmp/'.owner').write_text('darwin-timed-record-locks-v1-linux-baseline'+chr(10));env=dict(os.environ,TMPDIR=str(tmp),TMP=str(tmp),TEMP=str(tmp));results=[]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for part in iter(lambda:f.read(1048576),b''):h.update(part)
 return h.hexdigest()
for label,path,expected,pattern in [('before-timed-locks-fifo', 'target/qualified-v1/x86_64-unknown-linux-gnu/debug/deps/rax-cd68278a9635a54f', '1deb556716e1bfb3041a67e7c41f9ee6fe8f12bccae8358a7952bfd896ba7d27', 'user::darwin::process::fifo_lifetime_tests::'), ('current-pipe', 'target/qualified-v1/x86_64-unknown-linux-gnu/debug/deps/rax-9af1d7ee0e3bc159', '2ee5b36ce2d56eaf45eafdb3692b90f569f84aebb0704eace38141ba3cffc4fc', 'user::darwin::process::pipe_drain_tests::'), ('current-continuation', 'target/qualified-v1/x86_64-unknown-linux-gnu/debug/deps/rax-9af1d7ee0e3bc159', '2ee5b36ce2d56eaf45eafdb3692b90f569f84aebb0704eace38141ba3cffc4fc', 'user::darwin::process::continuation_tests::')]:
 image=r/path;assert sha(image)==expected
 p=subprocess.run([str(image),pattern,'--test-threads=1','--nocapture'],cwd=r,env=env,capture_output=True,text=True);row={'label':label,'image_sha256':expected,'filter':pattern,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr};results.append(row);(out/'linux-baseline-comparison-progress-v2.json').write_text(json.dumps({'results':results},indent=2)+chr(10));print(label,p.returncode,p.stdout.split('test result:')[-1][-180:])
(out/'linux-baseline-comparison-v2.json').write_text(json.dumps({'results':results,'cpu_execution':'Docker amd64 translation on ARM64; not physical Intel execution'},indent=2)+chr(10))
