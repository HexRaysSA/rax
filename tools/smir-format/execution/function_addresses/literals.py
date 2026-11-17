"""Authored CodeAddress bit-literal cases; no registration or authority oracle."""
from copy import deepcopy
from pathlib import Path
import hashlib,importlib.util,json,sys
ROOT=Path(__file__).resolve().parents[4]
FOLDER=ROOT/'docs/specifications/smir/portable/conformance/execution/function-addresses/literal-values'
if __name__=='__main__':sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
from candidate.function_address_contract import local_roots,source_roots,observe
from candidate.type_system import ref
from test_candidate import operation,decl


def cases():
    result=[]
    def add(name,typ,source,expected):
        roots=local_roots()
        roots[0]['types'].append(dict(id=305,kind='struct',fields=[ref(300),ref(301)]))
        roots[1]['functions'][0]['blocks'][0]['ops'].append(operation('constant',[decl(31,typ)],literal=source))
        result.append(dict(id=name,scope='execution-local',sections=dict(zip((1,3,8),roots)),expected=expected,rust_expected=expected))
    bits=lambda n:dict(kind='bits',value=n.to_bytes(8,'little').hex())
    for n in [0,1,2,2**64-1]:add('bits-'+str(n),300,bits(n),'ok')
    add('vector-recursion',301,dict(kind='aggregate',elements=[bits(1),bits(2**64-1)]),'ok')
    add('struct-vector-recursion',305,dict(kind='aggregate',elements=[bits(2),dict(kind='aggregate',elements=[bits(0),bits(2**64-1)])]),'ok')
    add('reject-data-pointer',7,bits(2),'literal_pointer')
    add('reject-typed-code-pointer',302,bits(2),'literal_pointer')
    add('reject-short-width',300,dict(kind='bits',value='00'*7),'constant')
    add('reject-long-width',300,dict(kind='bits',value='00'*9),'constant')
    return result


def codec():
    name='_rax_codeaddress_literal_fixture_codec'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'tools/smir-format/codec.py');m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m)
    schemas={n:json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())for n in ['execution','abi','runtime']}
    return sys.modules[name].CandidateCodec(schemas)


def product():
    c=codec();encoded=[];base=source_roots()
    for row in cases():
        if observe(row)!=row['expected']:raise RuntimeError('authored expectation mismatch: '+row['id'])
        sections={**deepcopy(base),**deepcopy(row['sections'])};sections[2]['symbols']=[]
        raw=c.encode(sections)
        encoded.append(dict(id=row['id'],scope=row['scope'],expected=row['expected'],rust_expected=row['rust_expected'],encoded_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest()))
    return (json.dumps(dict(format='codeaddress-literal-static-fixtures',revision=1,contract='S-PROD016REV7/P1-CODEADDRESS-LITERAL-CONSISTENCY-01',scope='Authored local execution type/body checks only; enclosing ABI/source/production admission not asserted. All CodeAddress literals originless.',cases=encoded),indent=2)+'\n').encode()


if __name__=='__main__':
    if sys.argv[1:]not in([],['--check']):raise SystemExit('usage: literals.py [--check]')
    raw=product();path=FOLDER/'cases.json'
    if '--check'in sys.argv:
        if path.read_bytes()!=raw:raise SystemExit('literal fixture drift')
    else:path.write_bytes(raw)
    print(json.dumps(dict(cases=10,files=1,bytes=len(raw),checked='--check'in sys.argv)))
