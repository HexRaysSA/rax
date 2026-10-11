from pathlib import Path
import hashlib
root=Path(r"C:\Windows\Temp\assist-native-rax-20261010\target\debug")
paths=[root/"assist_rs.lib",*sorted((root/"deps").glob("*rax-e6c413934cad3a8f.rlib"))]
for p in paths:
 print("archive",p,flush=True)
 h=hashlib.sha256()
 with p.open("rb") as f:
  for block in iter(lambda:f.read(1048576),b""):h.update(block)
 print("size",p.stat().st_size,"sha256",h.hexdigest(),flush=True)
 with p.open("rb") as f:
  print("magic",repr(f.read(8)),flush=True)
  count=0
  while f.tell()<p.stat().st_size:
   offset=f.tell();header=f.read(60)
   if len(header)!=60 or header[58:60]!=b"`\n":
    print("INVALID MEMBER",offset,repr(header),flush=True);break
   try:size=int(header[48:58])
   except ValueError:
    print("INVALID SIZE",offset,repr(header),flush=True);break
   end=f.tell()+size+(size&1)
   if end>p.stat().st_size:
    print("MEMBER OUTSIDE FILE",offset,size,end,flush=True);break
   f.seek(end);count+=1
  else:print("STRUCTURAL MEMBER WALK PASSED",count,flush=True)
