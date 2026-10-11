import json,hashlib,struct
from pathlib import Path
root=Path(r'C:\Windows\Temp\assist-native-rax-20261010');share=Path(r'C:\Mac\Home\Downloads\assist-native-allocate-ex-transfer-20261010-2154');rows={}
for name in ['native-numa-map-probe-arm64.log', 'native-numa-map-probe-arm64-build.log', 'native-numa-map-probe-x64.log', 'native-numa-map-probe-x64-build.log', 'native-numa-map-probe-x86.log', 'native-numa-map-probe-x86-build.log', 'native-numa-map-probe-x86-laa.log', 'native-numa-map-probe-x86-laa-build.log']:
 data=(root/name).read_bytes();(share/name).write_bytes(data);rows[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
for arch in ['arm64','x64','x86','x86-laa']:
 name='native-numa-map-probe-'+arch+'.exe';d=(root/name).read_bytes();pe=struct.unpack_from('<I',d,60)[0];rows[name]={'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest(),'pe-machine':hex(struct.unpack_from('<H',d,pe+4)[0]),'large-address-aware':bool(struct.unpack_from('<H',d,pe+22)[0]&32)}
print(json.dumps(rows))