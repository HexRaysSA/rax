"""Author only the new UNBOUND flow corpus; --check never writes."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':sys.path.insert(0,str(ROOT/'tools/smir-format/execution'))
from source_value_flow.fixtures import FOLDER, FN, RAW, NOMINAL, codec, document, encoded, ref


def product():
    modules={};assertions={};cases=[]
    for name,profile,count in [('loop','loop',0),('seeds','seeds',0),('literal','literal',0),
                               ('max-id','max-id',0),('boundary4096','chain',4095)]:
        roots,assertion=document(profile,count)
        wire=codec().encode(roots)
        modules[name]=dict(encoded_hex=wire.hex(),bytes=len(wire),sha256=hashlib.sha256(wire).hexdigest())
        assertions[name]=assertion
        cases.append(dict(id='accept-'+name,module=name,assertion=assertion,expected='ok'))
    empty=dict(format='source-value-flow-assertion',revision=1,function=ref(0),flows=[],nominals=[],seeds=[])
    cases.append(dict(id='accept-no-source-byte-definitions',module='literal',assertion=empty,expected='ok'))
    def reject(name,code,change,module='loop'):
        a=deepcopy(assertions[module]);change(a)
        cases.append(dict(id='reject-'+name,module=module,assertion=a,expected=code))
    reject('unknown-field','FLOW_SHAPE',lambda a:a.update(authority=True))
    reject('bool-version','FLOW_SHAPE',lambda a:a.update(revision=True))
    reject('float-version','FLOW_JSON',lambda a:a.update(revision=1.0))
    reject('unknown-flow-kind','FLOW_SHAPE',lambda a:a['flows'][0].update(kind='issuer'))
    reject('bool-value','FLOW_SHAPE',lambda a:a['flows'][0].update(result=True))
    reject('sentinel','FLOW_SHAPE',lambda a:a['flows'][0].update(result=4294967295))
    reject('negative-id','FLOW_SHAPE',lambda a:a['flows'][0].update(result=-1))
    reject('foreign-function','FLOW_SHAPE',lambda a:a['function'].update(module=dict(kind='dependency',slot=0)))
    reject('missing-function','FLOW_REFERENCE',lambda a:a['function'].update(id=999))
    reject('omitted-edge','FLOW_PHI',lambda a:a['flows'][0]['incoming'].pop())
    reject('reordered-edge-vector','FLOW_PHI',lambda a:a['flows'][0]['incoming'].reverse())
    reject('repeated-predecessor','FLOW_PHI',lambda a:a['flows'][0]['incoming'][1].update(predecessor=0))
    reject('wrong-predecessor','FLOW_PHI',lambda a:a['flows'][0]['incoming'][1].update(predecessor=99))
    reject('wrong-incoming-value','FLOW_PHI',lambda a:a['flows'][0]['incoming'][0].update(value=1))
    reject('missing-unused-definition','FLOW_COVERAGE',lambda a:a['seeds'].pop())
    reject('missing-nominal','FLOW_COVERAGE',lambda a:a['nominals'].pop())
    reject('extra-nominal','FLOW_COVERAGE',lambda a:a['nominals'].append(dict(value=999,nominal=ref(NOMINAL))))
    reject('wrong-nominal-projection','FLOW_NOMINAL',lambda a:a['nominals'][0].update(nominal=ref(0)))
    reject('wrong-phi-nominal','FLOW_NOMINAL',lambda a:a['flows'][0].update(nominal=ref(999)))
    reject('duplicate-flow','FLOW_COVERAGE',lambda a:a['flows'].insert(1,deepcopy(a['flows'][0])))
    reject('unsorted-flow','FLOW_COVERAGE',lambda a:a['flows'].reverse())
    reject('wrong-block','FLOW_COORDINATE',lambda a:a['flows'][2].update(block=0))
    reject('wrong-operation','FLOW_COORDINATE',lambda a:a['flows'][2].update(operation=1))
    reject('wrong-noop-input','FLOW_OPCODE',lambda a:a['flows'][2].update(input=11))
    reject('swapped-select-arms','FLOW_OPCODE',lambda a:a['flows'][3].update(true_value=11,false_value=13))
    reject('wrong-select-condition','FLOW_OPCODE',lambda a:a['flows'][3].update(condition=2))
    reject('wrong-freeze-input','FLOW_OPCODE',lambda a:a['flows'][4].update(input=11))
    reject('duplicate-seed-flow','FLOW_COVERAGE',lambda a:a['seeds'].insert(2,dict(value=13,kind='literal')))
    # Duplicate producer above is validly sorted but its asserted literal is not
    # a literal; the seed/opcode check deliberately precedes cross-kind joining.
    cases[-1]['expected']='FLOW_SEED'
    reject('parameter-as-literal','FLOW_SEED',lambda a:a['seeds'][0].update(kind='literal'))
    def disguised_freeze(a):
        a['flows'][4]=dict(kind='noop',block=1,operation=4,input=14,result=17,
                          input_nominal=ref(NOMINAL),result_nominal=ref(NOMINAL))
    reject('freeze-as-copy','FLOW_OPCODE',disguised_freeze)
    def numeric_noop(a):
        a['seeds'].pop()
        a['flows'].insert(0,dict(kind='noop',block=0,operation=2,input=1,result=2,
                               input_nominal=ref(NOMINAL),result_nominal=ref(NOMINAL)))
    reject('numeric-as-noop','FLOW_TYPE',numeric_noop,'seeds')
    reject('numeric-seed-as-literal','FLOW_SEED',lambda a:a['seeds'][1].update(kind='literal'),'seeds')
    reject('flow-vector-limit','FLOW_SHAPE',lambda a:a.update(flows=[deepcopy(a['flows'][0])for _ in range(4097)]))
    return dict(format='source-value-flow-unbound-fixtures',revision=1,
                source_facts_issued=False,source_admission_passed=False,runtime_permission=False,
                modules=modules,cases=cases)


def bytes_product():
    return (json.dumps(product(),indent=2)+'\n').encode('ascii')


if __name__=='__main__':
    if sys.argv[1:]not in ([],['--check']):raise SystemExit('usage: generate.py [--check]')
    raw=bytes_product();path=FOLDER/'cases.json'
    if '--check'in sys.argv:
        if path.read_bytes()!=raw:raise SystemExit('SourceValueFlow corpus drift')
    else:
        FOLDER.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    data=json.loads(raw)
    print(json.dumps(dict(checked='--check'in sys.argv,modules=len(data['modules']),cases=len(data['cases']),bytes=len(raw))))
