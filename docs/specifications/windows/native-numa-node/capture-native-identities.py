from pathlib import Path
import hashlib,json,struct
base=Path(r'C:\Windows\Temp\assist-native-rax-20261010')
items=[]
for arch in ['arm64','x64','x86','x86-laa']:
 path=base/('native-numa-node-probe-'+arch+'.exe');data=path.read_bytes();pe=struct.unpack_from('<I',data,60)[0]
 if data[:2]!=b'MZ' or data[pe:pe+4]!=b'PE\0\0':raise RuntimeError('not PE')
 machine,sections,stamp,_,_,opt,flags=struct.unpack_from('<HHIIIHH',data,pe+4)
 items.append({'arch':arch,'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'machine':hex(machine),'characteristics':hex(flags),'large-address-aware':bool(flags&32)})
source=base/'native-numa-node-probe.cpp';data=source.read_bytes()
result={'sources':[{'path':str(source),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}],'executables':items}
Path(r'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154\native-numa-node-executable-identities.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
