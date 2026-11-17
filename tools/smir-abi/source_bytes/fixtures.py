"""Source-authored epoch controls; independent Rust decoder consumes the bytes."""
from pathlib import Path
from copy import deepcopy
import hashlib,importlib.util,json,sys
ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'docs/specifications/smir/portable/conformance/abi/source-bytes'
def projection_fixture():
 sys.path[:0]=[str(ROOT/'tools'/p)for p in ('smir-format/execution','smir-runtime-contract','smir-abi','smir-format')]
 from candidate.context import RootContext
 from function_address.fixtures import ordinary,source,layout,seal
 from nominal import ref as q
 from record_layout.materialization import _api
 from site_config import site_record,identity
 roots=ordinary();roots[10].update(site=site_record(platform_source_abi_revision=2),identity=identity(platform_source_abi_revision=2));roots[2]['manifest']['site']=roots[10]['identity']
 for domain in roots[10]['domains']:
  if domain['isa']=='portable':domain['abi_identity']=roots[10]['identity']
 roots[1]['types'] += [dict(id=5000,kind='raw',bits=8),dict(id=5001,kind='int',bits=8)]
 roots[1]['memory_layouts'] += [dict(id=i,type=q(t),size=1,access_bytes=1,alignment=1,fields=[],element=None,stride=0)for i,t in[(5100,5000),(5101,5001)]]
 t=source(5000,'scalar',entity='unsigned char',bits=8,execution=5000,layout_id=5000,representation='value',flags=['complete','trivial_copy','trivial_destroy']);roots[10]['types'].append(t);roots[10]['layouts'].append(layout(5000,1,1));seal(roots)
 owner=RootContext(roots);b=_api().SourceQueryBudget(max_work=10**20,max_edges=10**20,max_copied_bytes=10**20,max_depth=128);stamp=owner.prepare_source_data(budget=b);dg=dict(stamp.root_digests)
 descriptor=dict(format='abi-source-byte-projection',revision=1,context=0,module_root=dg[2].hex(),abi_root=dg[10].hex(),types=[dict(nominal=q(5000),category='unsigned_char',execution=q(5000),declaration=None)])
 return owner,descriptor,b

def build():
 recipe=ROOT/'crates/smir-portable/tests/abi/ordinary_pointer_fixtures.py'
 spec=importlib.util.spec_from_file_location('_epoch_pointer_recipe',recipe)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 from site_config import site_record,identity
 roots=module.pointer_object(['int*'],'int*')
 roots[10]['site']=site_record(platform_source_abi_revision=2)
 roots[10]['identity']=identity(platform_source_abi_revision=2)
 for domain in roots[10]['domains']:
  if domain['isa']=='portable':domain['abi_identity']=roots[10]['identity']
 roots[2]['manifest']['site']=roots[10]['identity']
 module.seal(roots)
 return roots,module.CandidateCodec(module.SCHEMAS).encode(roots)
def main():
 roots,data=build();OUT.mkdir(parents=True,exist_ok=True)
 outputs={'epoch2-byte-free.smo':data,'epoch2-byte-free.source.json':(json.dumps({'sections':roots},sort_keys=True,indent=2)+'\n').encode()}
 owner,descriptor,b=projection_fixture()
 def encoded(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 outputs['unsigned-char-original-roots.json']=encoded({'sections':owner.sections})
 outputs['unsigned-char-projection.json']=encoded(descriptor)
 for failure in ('omitted-table','wrong-category','duplicate','nonlocal-context','wrong-root'):
  rejected=deepcopy(descriptor)
  if failure=='omitted-table':rejected['types']=[]
  elif failure=='wrong-category':rejected['types'][0]['category']='char'
  elif failure=='duplicate':rejected['types']*=2
  elif failure=='nonlocal-context':rejected['context']=1
  else:rejected['abi_root']='0'*64
  outputs['reject-'+failure+'.json']=encoded(rejected)
 for name,content in outputs.items():
  path=OUT/name
  if '--check'in sys.argv:
   if path.read_bytes()!=content:raise RuntimeError('fixture changed '+name)
  else:path.write_bytes(content)
 print(json.dumps({name:hashlib.sha256(content).hexdigest()for name,content in outputs.items()},sort_keys=True))
if __name__=='__main__':main()
