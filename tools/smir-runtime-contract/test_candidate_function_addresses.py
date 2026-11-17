"""Independent actual graph checks and closed address-publication boundary."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SCRIPT=r'''
import json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'tools/smir-format'))
from codec import CandidateCodec
spec=root/'docs/specifications/smir/portable'
codec=CandidateCodec({n:json.loads((spec/'schema'/n/'candidate.json').read_text()) for n in ('execution','runtime','abi')})
sys.path.insert(0,str(root/'tools/smir-format/execution'))
from candidate.context import RootContext
from candidate.bindings import runtime_package_module
L=runtime_package_module('linking')
folder=root/'crates/smir-portable/tests/metadata/function-address-fixtures'
cases=json.loads((folder/'manifest.json').read_text())['cases']
results={}
for name,case in cases.items():
    roots=codec.decode((folder/(name+'.smo')).read_bytes()).roots
    try:
        actual=RootContext(roots);actual.verify_abi()
        def absent(*args):raise RuntimeError('unexpected external comparison')
        context=L.Context(site=roots[10]['identity'],execution=actual.execution,
            nominal=lambda r:actual.abi_entity('nominal',r),function=actual.function,
            symbol=actual.runtime_symbol,execution_equal=actual.types.equal,
            nominal_compatible=actual.abi_graph.boundary_compatible,storage_layout=actual.memory_layout,
            symbol_body=absent,symbol_identity=absent,abi_entity=actual.abi_entity,
            target_entity=actual.target_entity,native_symbol=actual.native_symbol,
            nominal_layout=actual.source_layout,grants=frozenset({'memory'}),
            signature_compatible=actual.abi_graph.signature_compatible,source_compatible=actual.source_compatible)
        L.validate({n:roots[n] for n in L.ROOTS},context)
    except ValueError as error:
        results[name]={'code':getattr(error,'code',str(error))}
    else: results[name]={'code':None}
print(json.dumps(results))
'''


class FunctionAddressTests(unittest.TestCase):
    def test_independent_actual_graph_static_contract(self):
        command=[sys.executable,'-B']+(['-O'] if sys.flags.optimize else [])
        completed=subprocess.run(command+['-c',SCRIPT,str(ROOT)],capture_output=True,text=True)
        self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
        results=json.loads(completed.stdout)
        folder=ROOT/'crates/smir-portable/tests/metadata/function-address-fixtures'
        cases=json.loads((folder/'manifest.json').read_text())['cases']
        self.assertEqual(len(results),29)
        for name,case in cases.items():
            with self.subTest(case=name):
                if case['expected']=='semantic':self.assertIsNotNone(results[name]['code'])
                else:self.assertIsNone(results[name]['code'],results[name])

    def test_runtime_address_patch_cannot_use_dict_resolver_or_publish(self):
        # Package bootstrap does not import SEM's canonical candidate namespace.
        from test_candidate_contract import ref
        from runtime_candidate.relocations import Registry
        from runtime_candidate.requirements import RuntimeUnavailable
        image={'bytes':bytearray(b'\xa5'*8),'poison':bytearray(8),'undef':bytearray(8),'origins':[]}
        registry=Registry({('data',0):image},{'owner':1});before=deepcopy(registry.images);revision=registry.revision
        record={'source_kind':'data','source':0,'offset':0,'width':8,'integer_bits':0,
            'kind':'code_address','target':ref(0),'addend':0,'derivation':[],
            'check_base':False,'flags':[],'inrange':None}
        def forbidden(reference):raise AssertionError('loose resolver used as address issuer')
        with self.assertRaises(RuntimeUnavailable) as caught:registry.prepare([record],forbidden)
        self.assertEqual(caught.exception.code,'code_address_unavailable')
        self.assertEqual(caught.exception.kind,'unavailable')
        self.assertEqual(registry.images,before)
        self.assertEqual(registry.revision,revision)
        self.assertEqual(registry.exposed,set());self.assertEqual(registry.exposed_code,set())


if __name__=='__main__':unittest.main()
