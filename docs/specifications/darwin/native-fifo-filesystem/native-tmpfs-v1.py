from pathlib import Path
import os,fcntl,ctypes,json,platform,errno
r=Path('/work');out=r/'.task-evidence/linux-fifo-entry-v1';tmp=r/'target/qualified-v1/tmp/linux-fifo-entry-native-v3';tmp.mkdir(exist_ok=True);(tmp/'.owner').write_text('linux-fifo-entry-v1'+chr(10));p=tmp/'named';os.mkfifo(p,0o600);reader=os.open(p,os.O_RDONLY|os.O_NONBLOCK);writer=os.open(p,os.O_WRONLY|os.O_NONBLOCK);fcntl.fcntl(reader,fcntl.F_SETFL,0);a,b=os.pipe();libc=ctypes.CDLL(None,use_errno=True);libc.fstatfs.argtypes=[ctypes.c_int,ctypes.c_void_p];libc.fstatfs.restype=ctypes.c_int;rows=[]
def observe(label,fd):
 row={'kind':label,'fd':fd};raw=(ctypes.c_long*32)();ctypes.set_errno(0);result=libc.fstatfs(fd,ctypes.byref(raw));row.update(fstatfs_result=result,fs_errno=ctypes.get_errno(),fs_magic=hex(raw[0]))
 for name,fn in [('stat',lambda:os.fstat(fd)),('proc_fd',lambda:os.readlink('/proc/self/fd/'+str(fd))),('flags',lambda:fcntl.fcntl(fd,fcntl.F_GETFL))]:
  try:
   x=fn();row[name]=({'mode':oct(x.st_mode),'dev':x.st_dev,'inode':x.st_ino,'links':x.st_nlink}if name=='stat'else x)
  except OSError as e:row[name+'_error']={'errno':e.errno,'message':str(e)}
 rows.append(row)

try:
 observe('named-linked',reader);p.unlink();observe('named-unlinked',reader);observe('anonymous-reader',a);observe('anonymous-writer',b)
finally:
 for fd in [reader,writer,a,b]:os.close(fd)
 if p.exists():p.unlink()
result={'system':list(platform.uname()),'records':rows,'container_architecture':'amd64','docker_daemon_architecture':'aarch64','cpu_execution':'Docker x86-64 translation on ARM64; not physical Intel qualification'};(out/'native-classification-v3.json').write_text(json.dumps(result,indent=2)+chr(10));print(json.dumps(result))
