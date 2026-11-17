"""Exact CodeAddress literal bits and real reference/registry rejection controls."""
from copy import deepcopy
import hashlib,json,sys,unittest,subprocess
from pathlib import Path
from common import Reject
from candidate.type_system import Types,ref
from candidate.values import Value,Pointer,literal,freeze,validate
from candidate.function_address_contract import local_roots
from candidate.verify import verify
from candidate.machine import Machine
from test_candidate import operation,decl
from test_candidate_memory import scalar,storage,MODE
from function_addresses import literals
ROOT=Path(__file__).resolve().parents[3]
VALUES=(0,1,2,2**64-1)


def bits(n):return dict(kind='bits',value=n.to_bytes(8,'little').hex())

def value_machine(n,from_bits=False):
    roots=local_roots();roots[0]['memory_layouts']=[scalar(0,300,8,alignment=8)]
    roots[0]['types'][15]['results']=[ref(300)]
    ops=([operation('constant',[decl(0,4)],literal=bits(n)),operation('bitcast',[decl(1,300)],[0])]if from_bits else[operation('constant',[decl(0,300)],literal=bits(n)),operation('copy',[decl(1,300)],[0])])
    ops.append(operation('icmp',[decl(2,0)],[1,1],predicate='eq'))
    fn=roots[1]['functions'][0];fn['blocks'][0]['ops']=ops;fn['blocks'][0]['term']={'op':'return','values':[1]}
    return Machine(verify(*roots))


class CodeAddressLiteralTests(unittest.TestCase):
    def assert_originless(self,value,n):
        p=value.data
        self.assertEqual(value.state,'concrete');self.assertEqual(p.address,n);self.assertEqual(p.domain,'code_address')
        self.assertIsNone(p.origin);self.assertEqual(p.generation,0);self.assertIsNone(p.permit);self.assertIsNone(p.authority);self.assertIsNone(p.lineage)

    def test_actual_literal_constructor_all_boundary_bits(self):
        types=Types(local_roots()[0])
        for n in VALUES:
            with self.subTest(bits=n):
                types.literal(ref(300),bits(n));v=literal(types,ref(300),bits(n));validate(types,v);self.assert_originless(v,n)

    def test_real_machine_copy_equality_store_reload_no_registration(self):
        for n in VALUES:
            with self.subTest(bits=n):
                machine=value_machine(n);machine.start(0,[]);out=machine.run();self.assertEqual(out['kind'],'return');v=out['values'][0];self.assert_originless(v,n)
                p=machine.memory.allocate(8,8);spec=storage(300,0,8);mode={**MODE,'alignment':8}
                machine.memory.store(p,v,spec,mode);read=machine.memory.load(p,spec,mode);self.assert_originless(read,n);self.assertEqual(read,v)
                self.assertIsNone(machine._source_runtime);self.assertEqual(machine.code_pointers,{});self.assertEqual(machine.exposed_code,set());self.assertEqual(machine.memory.exposed,set())

    def test_existing_raw_from_bits_materialization_equal_to_literal(self):
        # Actual raw64 constant -> bitcast CodeAddress is the existing pure
        # bit-only path. This does not claim LLVM helper registration/emission.
        for n in VALUES:
            a=value_machine(n);b=value_machine(n,True);a.start(0,[]);b.start(0,[])
            x=a.run()['values'][0];y=b.run()['values'][0];self.assertEqual(x,y);self.assert_originless(y,n)
            self.assertEqual(b.exposed_code,set());self.assertEqual(b.memory.exposed,set())

    def test_vector_struct_recursion_and_static_corpus(self):
        path=literals.FOLDER/'cases.json';d=json.loads(path.read_bytes());self.assertEqual(len(d['cases']),10);codec=literals.codec()
        from candidate.function_address_contract import observe
        logical={c['id']:c for c in literals.cases()}
        for c in d['cases']:
            wire=bytes.fromhex(c['encoded_hex']);self.assertEqual(hashlib.sha256(wire).hexdigest(),c['sha256']);self.assertEqual(codec.encode(codec.decode(wire).roots),wire)
            self.assertEqual(observe(logical[c['id']]),c['expected'])
        for name in ['vector-recursion','struct-vector-recursion']:
            c=logical[name];t=Types(c['sections'][1]);op=c['sections'][3]['functions'][0]['blocks'][0]['ops'][-1];r=op['results'][0]['type'];t.literal(r,op['literal']);validate(t,literal(t,r,op['literal']))

    def test_other_pointer_policies_and_wrong_width_unchanged(self):
        t=Types(local_roots()[0])
        for typ in [7,302]:
            t.literal(ref(typ),bits(0))
            for n in VALUES[1:]:
                with self.subTest(type=typ,bits=n),self.assertRaisesRegex(Reject,'literal_pointer'):t.literal(ref(typ),bits(n))
        for size in [0,7,9]:
            with self.subTest(bytes=size),self.assertRaisesRegex(Reject,'constant'):t.literal(ref(300),dict(kind='bits',value='00'*size))

    def test_zero_poison_undef_and_freeze_keep_no_authority(self):
        t=Types(local_roots()[0])
        for kind in ['zero','poison','undef']:
            src=dict(kind=kind);t.literal(ref(300),src);v=literal(t,ref(300),src);self.assert_originless(freeze(t,v),0)

    def test_literal_equal_real_issued_target_still_fails_bind_before_call(self):
        command=[sys.executable,'-B']+(['-O']if sys.flags.optimize else[])+[str(Path(__file__).resolve()),'--registry-witness']
        child=subprocess.run(command,capture_output=True,text=True,timeout=60)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(json.loads(child.stdout),dict(actual_registry_bind='code_address_invalid',issued_bits=2,literal_originless=True,permits=0,entries=0,optimize=sys.flags.optimize))

    def _actual_registry_witness(self):
        # Build the complete real source module before admission. The actual
        # registry chooses the target bits; equality is checked, never assumed.
        sys.path.insert(0,str(ROOT/'tools/smir-runtime-contract'))
        from source_roles.test_code_addresses import R,budget,policy
        from generate_service_type_fixtures import complete_identity,prepare_abi2_nonrecord_source
        from candidate.context import RootContext
        roots=complete_identity();roots[1]['types'] += [dict(id=900,kind='code_address'),dict(id=901,kind='code_ptr',signature=ref(12))]
        main=deepcopy(roots[3]['functions'][0]);main['id']=1
        main['blocks'][0]['ops']=[operation('constant',[decl(20,900)],literal=bits(2)),operation('code_bind',[decl(21,901)],[20],plan=ref(0)),operation('call',[decl(22,17)],[0],target=dict(kind='indirect',value=21,signature=ref(12)),unwind='propagate',source_plan={'some':ref(0)})]
        main['blocks'][0]['term']={'op':'return','values':[22]};roots[3]['functions'].append(main);prepare_abi2_nonrecord_source(roots)
        owner=RootContext(roots);owner.verify_abi();checked=owner.verify_execution();ledger=budget();source=owner.source_registry_context(budget=ledger)
        registry=R.CodeRegistry(budget=ledger,policy=policy());machine=Machine(checked);machine.attach_source_registry(registry,source,budget=ledger)
        runtime=machine._source_runtime;target=registry.resolve(runtime['deployment'],runtime['owner'],'function',ref(0),budget=ledger);issued=registry.address(target,budget=ledger)
        self.assertEqual(issued.bits,2);self.assertIsNotNone(issued.target);self.assertEqual(registry._permits,[])
        machine.start(1,[Value(ref(17),'concrete',42)]);out=machine.run();self.assertEqual((out['kind'],out['reason']),('trap','code_address_invalid'))
        frame=machine.stack[-1];self.assert_originless(frame.values[20],issued.bits);self.assertNotIn(21,frame.values);self.assertNotIn(22,frame.values)
        self.assertEqual(registry._permits,[]);self.assertEqual(registry._entries,[]);self.assertEqual(machine.memory.effects,[])
        return dict(actual_registry_bind='code_address_invalid',issued_bits=issued.bits,literal_originless=True,permits=len(registry._permits),entries=len(registry._entries),optimize=sys.flags.optimize)

    def test_codeaddress_indirect_call_stays_statically_invalid(self):
        roots=local_roots();roots[1]['functions'][0]['blocks'][0]['ops'] += [operation('constant',[decl(31,300)],literal=bits(2)),operation('call',[decl(32,2)],[],target=dict(kind='indirect',value=31,signature=ref(15)),unwind='propagate')]
        with self.assertRaisesRegex(Reject,'call_indirect_signature'):verify(*roots)


if __name__=='__main__':
    if sys.argv[1:]==['--registry-witness']:
        print(json.dumps(CodeAddressLiteralTests()._actual_registry_witness(),sort_keys=True))
    else:unittest.main(verbosity=2)
