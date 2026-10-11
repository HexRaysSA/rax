from pathlib import Path
import hashlib,json
root=Path(r'C:\Windows\Temp\assist-native-rax-20261010')
artifacts=[json.loads(x) for x in (root/'native-hypervisor-after-artifacts.jsonl').read_text().splitlines()]
core=[x for x in artifacts if x.get('reason')=='compiler-artifact' and x['target']['name']=='rax' and not x['manifest_path'].replace('\\','/').endswith('/capi/Cargo.toml')]
assert len(core)==1 and core[0]['features']==[]
paths=[root/'target/debug/assist_rs.lib',Path(next(p for p in core[0]['filenames'] if p.endswith('.rlib')))]
rows=[]
for path in paths:
 size=path.stat().st_size;h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 with path.open('rb') as f:
  assert f.read(8)==b'!<arch>\n';count=0
  while f.tell()<size:
   header=f.read(60);assert len(header)==60 and header[58:60]==b'`\n'
   member=int(header[48:58]);end=f.tell()+member+(member&1);assert end<=size
   f.seek(end);count+=1
  assert f.tell()==size
 rows.append({'path':str(path),'bytes':size,'sha256':h.hexdigest(),'members':count,'structural-member-walk':'pass'})
sources=[]
for x in [{'path': 'src/user/windows/dll/native/query.rs', 'bytes': 9961, 'sha256': '027a8c4873c27b07009f91ea274efca48723c696361e1eec98fb136bad40828b'}, {'path': 'src/user/windows/process/sched/tests/services_tests.rs', 'bytes': 45351, 'sha256': 'e79defc012117f5d72b4a05f35d7168ca438ec297cdd4dd757a0697334a6a0c7'}, {'path': 'src/user/windows/process/sched/tests/services_tests/hypervisor_page_tests.rs', 'bytes': 20252, 'sha256': '95d40c7addc4cfb32f422701e3a53d7b2c8bc09074831fffdd119a6434ccd7d7'}, {'path': 'src/user/windows/process/sched/tests/services_tests/hypervisor_page_leaf_tests.rs', 'bytes': 4563, 'sha256': '511785f1fd5bc15f4e22408f06c3c76877127bdaadbb6f936b366d28c68c3008'}]:
 data=(root/'src'/x['path']).read_bytes();assert len(data)==x['bytes'] and hashlib.sha256(data).hexdigest()==x['sha256'];sources.append(x)
print(json.dumps({'archives':rows,'core-features':core[0]['features'],'sources':sources}))
