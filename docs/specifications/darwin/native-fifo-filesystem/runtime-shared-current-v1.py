from pathlib import Path
import hashlib,json,os,platform,subprocess
root=Path('/work');out=root/'.task-evidence/darwin-timed-record-locks-v1';image=root/'target/qualified-v1/x86_64-unknown-linux-gnu/debug/deps/rax-9af1d7ee0e3bc159'
assert hashlib.sha256(image.read_bytes()).hexdigest()=='2ee5b36ce2d56eaf45eafdb3692b90f569f84aebb0704eace38141ba3cffc4fc'
tmp=root/'target/qualified-v1/tmp/darwin-timed-lock-linux-v2';tmp.mkdir();(tmp/'.owner').write_text('darwin-timed-record-locks-v1-linux'+chr(10))
env=dict(os.environ,TMPDIR=str(tmp),TMP=str(tmp),TEMP=str(tmp));rows=[]
for name,count in [('timed_lock_tests::',7),('fifo_lifetime_tests::',10),('pipe_drain_tests::',1),('continuation_tests::',7)]:
 p=subprocess.run([str(image),'user::darwin::process::'+name,'--test-threads=1','--nocapture'],env=env,cwd=root,text=True,capture_output=True)
 row={'filter':name,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr};rows.append(row)
 (out/'linux-runtime-progress-v2.json').write_text(json.dumps({'results':rows,'image_sha256':'2ee5b36ce2d56eaf45eafdb3692b90f569f84aebb0704eace38141ba3cffc4fc'},indent=2)+chr(10))
 assert p.returncode==0 and f'{count} passed; 0 failed; 0 ignored;'in p.stdout,row
assert hashlib.sha256(image.read_bytes()).hexdigest()=='2ee5b36ce2d56eaf45eafdb3692b90f569f84aebb0704eace38141ba3cffc4fc'
(out/'linux-runtime-v2.json').write_text(json.dumps({'results':rows,'image_sha256':'2ee5b36ce2d56eaf45eafdb3692b90f569f84aebb0704eace38141ba3cffc4fc','machine':platform.machine(),'system':platform.system(),'container_architecture':'amd64','docker_daemon_architecture':'aarch64','cpu_execution':'Docker x86-64 translation on AArch64; not physical x86 qualification'},indent=2)+chr(10))
print('Linux owning checks passed:25')
