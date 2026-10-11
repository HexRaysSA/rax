from pathlib import Path
import hashlib,json
root=Path(r'C:\Windows\Temp\assist-native-rax-20261010')
artifacts=[json.loads(x) for x in (root/'native-numa-after-artifacts.jsonl').read_text().splitlines()]
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
for x in [{'path': 'src/user/windows/dll/native/query.rs', 'bytes': 11373, 'sha256': '6898b058b6e635e550e5237f3236baddbc1190a4a21609073223d9e479298d39'}, {'path': 'src/user/windows/process/sched/tests/services_tests.rs', 'bytes': 45417, 'sha256': '5089f53ae34603f2305c9dfb59e246fa5a872ed072c9bc26a5cf9968aaa09144'}, {'path': 'src/user/windows/process/sched/tests/services_tests/numa_map_tests.rs', 'bytes': 16475, 'sha256': '8d856cd0711a3b89535cea04b5498ae9fc6c6628aaae2700b96e32d20819c7b2'}, {'path': 'src/user/windows/process/sched/tests/services_tests/numa_map_leaf_tests.rs', 'bytes': 4484, 'sha256': '16370e294a2d5829246b236dd247a22ff96d0134bbd55abcbbd646cbb17e7c23'}]:
 data=(root/'src'/x['path']).read_bytes();assert len(data)==x['bytes'] and hashlib.sha256(data).hexdigest()==x['sha256'];sources.append(x)
print(json.dumps({'archives':rows,'core-features':core[0]['features'],'sources':sources}))
