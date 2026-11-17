"""Actual independent native/per-bit versus Core span/Machine controls."""
from copy import deepcopy
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import reference as R
from oracle import actual_witness, encoded_cases, budget, compare_raw
from code_address_bytes import contract as core
from candidate.raw import Raw, Span, concat, overwrite
from candidate.values import Value, Pointer, from_raw, raw_bits
from candidate.memory import GuestFault
from candidate.type_system import ref

HERE = Path(__file__).resolve().parent
BINARY = Path(os.environ['RAW8_REFERENCE_BINARY']).resolve()
RECEIPT = Path(os.environ['RAW8_REFERENCE_RECEIPT']).resolve()
ARTIFACTS = Path(os.environ['RAW8_REFERENCE_ARTIFACTS'])
FIXTURES = json.loads((HERE / 'fixtures.json').read_bytes())
ARTIFACTS.mkdir(exist_ok=False)


class Helpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner, cls.source, cls.core_budget, cls.registry, cls.machine = core.make_machine(encoded_cases()[1]['relay'])
        cls.types = cls.machine.types

    def setUp(self):
        self.ledger = budget()
        self.session = R.ReferenceSession(BINARY, RECEIPT, budget=self.ledger, max_events=256)

    def image(self, raw):
        return self.session.capture_raw(raw, budget=self.ledger)

    def native(self, operation, arguments):
        return self.session.result(self.session.evaluate(operation, arguments, budget=self.ledger), budget=self.ledger)

    def test_from_integer_exact_states_and_origin_stripping(self):
        for row in FIXTURES['numeric']:
            with self.subTest(row=row):
                expected = raw_bits(self.types, Value(ref(2), row['state'], row['bits'] if row['state'] == 'concrete' else None))
                result = self.native('from_int8', dict(row))
                compare_raw(self.session, result, expected)
                self.assertEqual(result['origins'], [])
                self.assertEqual(int(result['poison'], 16), 255 if row['state'] == 'poison' else 0)
                self.assertEqual(int(result['undef'], 16), 255 if row['state'] == 'undef' else 0)

    def test_poison_undef_freeze_and_observe_math_partitions(self):
        for row in FIXTURES['masks']:
            with self.subTest(row=row):
                raw = Raw(8, row['bits'], row['poison'], (), row['undef'])
                frozen = self.native('freeze8', {'value': self.image(raw)})
                self.assertEqual(int(frozen['bits'], 16), row['bits'] & ~(row['poison'] | row['undef']) & 255)
                self.assertEqual((int(frozen['poison'], 16), int(frozen['undef'], 16)), (0, 0))
                compare_raw(self.session, frozen, raw.freeze())
                observed = self.native('observe8', {'value': self.image(raw)})
                actual = from_raw(self.types, ref(2), raw)
                self.assertEqual(observed, dict(state=actual.state, bits=actual.data if actual.state == 'concrete' else 0))
                self.assertEqual(observed['state'], 'poison' if row['poison'] else 'concrete')

    def test_genuine_inrange_fragment_traps_zero_numeric_and_poison_precedence(self):
        from candidate.memory import Memory
        memory = Memory(self.types, self.machine.dependencies)
        original = memory.allocate(8, 1)
        pointer = memory.offset(original, 0, True, False, False, {'lower': 0, 'upper': 8})
        raw = Raw.pointer(pointer).slice(0, 8)
        self.assertEqual(raw.bits, 0)
        with self.assertRaises(GuestFault) as actual:
            from_raw(self.types, ref(2), raw)
        with self.assertRaises(R.HelperError) as native:
            self.native('observe8', {'value': self.image(raw)})
        self.assertEqual((native.exception.kind, native.exception.code), ('trap', actual.exception.code))
        poisoned = Raw(8, 0, 128, (Span(0, 7, pointer, 0),))
        result = self.native('observe8', {'value': self.image(poisoned)})
        self.assertEqual(result, dict(state='poison', bits=0))
        self.assertEqual(from_raw(self.types, ref(2), poisoned).state, 'poison')
        frozen = self.native('freeze8', {'value': self.image(poisoned)})
        self.assertEqual(frozen['origins'][0]['length'], 7)

    def test_plain_and_masked_memory_updates_match_actual_core(self):
        from candidate.memory import Memory
        for mask in FIXTURES['write_masks']:
            memory = Memory(self.types, self.machine.dependencies)
            pointer = memory.allocate(1, 1)
            other = memory.allocate(1, 1)
            old = Raw.pointer(pointer).slice(0, 8)
            new = Raw.pointer(other).slice(0, 8)
            memory.raw_store(pointer, old)
            record = self.session.capture_memory(memory, pointer, budget=self.ledger)
            access = self.session.capture_pointer(pointer, budget=self.ledger)
            result = self.native('store8', dict(memory=record, pointer=access, value=self.image(new), mask=mask))
            expected = old
            for bit in range(8):
                if mask >> bit & 1:
                    expected = overwrite(expected, bit, new.slice(bit, 1))
            memory.raw_store(pointer, expected)
            actual = self.session._ref(self.session.capture_memory(memory, pointer, budget=self.ledger), 'memory')
            self.assertEqual(result, actual)
            loaded = self.native('load8', dict(memory=self.session.capture_memory(memory, pointer, budget=self.ledger), pointer=access))
            compare_raw(self.session, loaded, memory.raw_load(pointer, 1))

    def test_actual_memory_guards_reject_without_partial_core_write(self):
        from candidate.memory import Memory
        for case in ('readonly', 'bounds', 'inactive', 'retired', 'wrong-origin', 'originless', 'inrange'):
            with self.subTest(case=case):
                memory = Memory(self.types, self.machine.dependencies)
                base = memory.allocate(1, 1, mutable=case != 'readonly')
                pointer = base
                if case == 'bounds':
                    pointer = memory.offset(base, 1, True, False, False)
                elif case == 'inactive':
                    memory.objects[base.origin]['active'][0] = False
                elif case == 'retired':
                    memory.objects[base.origin]['live'] = False
                elif case == 'wrong-origin':
                    foreign = Memory(self.types, self.machine.dependencies)
                    foreign.allocate(1, 1)
                    pointer = foreign.allocate(1, 1)
                elif case == 'originless':
                    pointer = memory.integer_pointer(base.address)
                elif case == 'inrange':
                    pointer = memory.offset(base, 0, True, False, False, {'lower': 1, 'upper': 1})
                before = list(memory.objects[base.origin]['bytes'])
                with self.assertRaises(GuestFault) as actual:
                    memory.guard(pointer, 1, write=True)
                with self.assertRaises(R.HelperError) as native:
                    self.native('store8', dict(memory=self.session.capture_memory(memory, base, budget=self.ledger),
                        pointer=self.session.capture_pointer(pointer, budget=self.ledger), value=self.image(Raw.integer(8, 42)), mask=255))
                self.assertEqual(native.exception.code, actual.exception.code)
                self.assertEqual(memory.objects[base.origin]['bytes'], before)

    def test_wrong_owner_event_and_budget_are_real_reference_rejections(self):
        other_budget = budget()
        other = R.ReferenceSession(BINARY, RECEIPT, budget=other_budget, max_events=2)
        value = self.image(Raw.integer(8, 42))
        before = other.native_calls
        with self.assertRaises(R.HelperError) as wrong:
            other.evaluate('freeze8', {'value': value}, budget=other_budget)
        self.assertEqual(wrong.exception.code, 'RAW_REFERENCE_HANDLE')
        self.assertEqual(other.native_calls, before)
        with self.assertRaises(R.HelperError) as wrong:
            self.session.evaluate('freeze8', {'value': value}, budget=other_budget)
        self.assertEqual(wrong.exception.code, 'RAW_REFERENCE_BUDGET')
        event = self.session.evaluate('freeze8', {'value': value}, budget=self.ledger)
        with self.assertRaises(R.HelperError):
            other.result(event, budget=other_budget)
        forged = R.ReferenceEvent(self.session, event.serial, event.epoch, event.payload, event.token)
        with self.assertRaises(R.HelperError):
            self.session.result(forged, budget=self.ledger)
        ref_clone = R.ReferenceRef(value.owner, value.serial, value.kind, value.record, value.token)
        with self.assertRaises(R.HelperError):
            self.session.evaluate('freeze8', {'value': ref_clone}, budget=self.ledger)
        self.assertIs(type(value.record), bytes)
        self.session.expire()
        with self.assertRaises(R.HelperError):
            self.session.result(event, budget=self.ledger)

    def test_actual_equal_pointer_distinct_authorities_keep_first_original(self):
        from test_candidate import operation,decl
        roots=core.build_document('producer')
        producer=next(f for f in roots[3]['functions']if f['id']==3)
        producer['blocks'][0]['ops'].insert(1,operation('address_of',[decl(22,900)],symbol=ref(0)))
        wire=core.codec().encode(roots)
        owner,source,ledger,registry,machine=core.make_machine(wire)
        machine.start(3,[]);out=machine.run(fuel=3)
        self.assertEqual(out['kind'],'resource')
        frame=machine.stack[-1];a,b=frame.values[20].data,frame.values[22].data
        self.assertEqual(a,b)
        self.assertIsNot(a.authority,b.authority)
        lanes=[Raw.pointer(a if i<4 else b).slice(i*8,8)for i in range(8)]
        result=self.native('join_code64',{'values':tuple(self.image(x)for x in lanes)})
        actual=from_raw(self.types,ref(900),concat(lanes))
        original=self.session.pointers[result['origin']-1]
        self.assertIs(original,a)
        self.assertIs(actual.data.authority,a.authority)
        self.assertIs(original.authority,a.authority)
        owner.assert_snapshot()

    def test_ranges_limit_empty_intersection_and_partial_poison_join(self):
        from candidate.memory import Memory
        memory=Memory(self.types,self.machine.dependencies);base=memory.allocate(8,1)
        whole=memory.offset(base,0,True,False,False,{'lower':-base.address,'upper':(1<<64)-base.address})
        point=memory.offset(base,0,True,False,False,{'lower':0,'upper':0})
        empty=memory.offset(point,0,True,False,False,{'lower':1,'upper':1})
        for pointer in (whole,empty):
            raw=Raw.pointer(pointer);lanes=[raw.slice(8*i,8)for i in range(8)]
            result=self.native('join_code64',{'values':tuple(self.image(x)for x in lanes)})
            actual=from_raw(self.types,ref(900),raw)
            self.assertIsNone(result['origin'])
            self.assertEqual(result['range'],self.session.bounds(actual.data.access_range))
            with self.assertRaises(R.HelperError)as caught:self.native('observe8',{'value':self.image(lanes[0])})
            self.assertEqual(caught.exception.code,'ub_inrange_address_conversion')
        lanes=[Raw.integer(8,i)for i in range(8)];lanes[3]=Raw.integer(8,0,poison=1)
        result=self.native('join_code64',{'values':tuple(self.image(x)for x in lanes)})
        actual=from_raw(self.types,ref(900),concat(lanes))
        self.assertEqual((result['state'],actual.state),('poison','poison'))
        self.assertIsNone(result['origin'])
        compare_raw(self.session,result['raw'],concat(lanes))

    def test_operation_specific_response_and_raw_results_domain(self):
        actual=R.child
        def corrupt(*args,**kw):
            status,out,err=actual(*args,**kw);response=R.strict_json(out)
            response['result']={'width':8,'bits':'0000000000000000','poison':'0000000000000000','undef':'0000000000000000','origins':[]}
            return status,R.canonical(response),err
        with mock.patch.object(R,'child',corrupt),self.assertRaises(R.HelperError):
            self.native('observe8',{'value':self.image(Raw.integer(8,0))})
        self.assertEqual(len(self.session.events),0)
        event=self.session.evaluate('observe8',{'value':self.image(Raw.integer(8,0))},budget=self.ledger)
        with self.assertRaises(R.HelperError):self.session.raw_results(event,budget=self.ledger)
        lanes=tuple(self.image(Raw.integer(8,0))for _ in range(8))
        event=self.session.evaluate('join_code64',{'values':lanes},budget=self.ledger)
        with self.assertRaises(R.HelperError):self.session.raw_results(event,budget=self.ledger)

    def test_original_configuration_and_bound_cannot_be_rebound(self):
        original = self.session.budget
        for name, value in [('budget',budget()),('max_events',65536),('attempts',0),('serial',0),
                            ('binary',Path('/invalid')),('receipt',Path('/invalid')),('epoch',0),
                            ('_original_budget',budget()),('_max_events',65536),('_attempts',0),('_binary',Path('/invalid'))]:
            with self.subTest(name=name),self.assertRaises(AttributeError):
                setattr(self.session,name,value)
        self.assertIs(self.session.budget,original)
        self.assertEqual((self.session.max_events,self.session.native_calls),(256,0))
        with self.assertRaises(TypeError):self.session.events[1]=object()
        with self.assertRaises(TypeError):self.session.refs[1]=object()
        self.assertIs(type(self.session.pointers),tuple)

    def test_exact_foundation_override_no_fallback_and_foreign_candidate(self):
        # Missing override is a negative only in an actual off-layout module.
        # An installed module must instead discover its known foundation.
        off_layout = ARTIFACTS / 'off-layout-import'
        off_layout.mkdir()
        shutil.copyfile(HERE / 'reference.py', off_layout / 'reference.py')
        installed_root = ARTIFACTS / 'installed-default-foundation'
        installed_tools = installed_root / 'tools'
        installed_tools.mkdir(parents=True)
        for name in ('smir-format', 'smir-runtime-contract'):
            (installed_tools / name).symlink_to(R.PROJECT / 'tools' / name, target_is_directory=True)
        installed = installed_tools / 'smir-llvm-contract/raw8-helper-reference'
        installed.mkdir(parents=True)
        shutil.copyfile(HERE / 'reference.py', installed / 'reference.py')
        copies = [off_layout / 'reference.py', installed / 'reference.py']
        original_digest = R.hashlib.sha256((HERE / 'reference.py').read_bytes()).hexdigest()
        guards = [{'path': str(path.resolve()),
                   'sha256': R.hashlib.sha256(path.read_bytes()).hexdigest()}
                  for path in copies]
        self.assertTrue(all(row['sha256'] == original_digest for row in guards))

        env = dict(os.environ)
        env.pop('SMIR_RAW8_REFERENCE_PROJECT', None)
        env['PYTHONPYCACHEPREFIX'] = str(ARTIFACTS / 'off-layout-foundation-cache')
        missing_command = [sys.executable, '-B', '-c',
                           'import sys;sys.path.insert(0,' + repr(str(off_layout)) + ');import reference']
        missing = subprocess.run(missing_command, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('RAW_REFERENCE_FOUNDATION', missing.stderr)

        env['PYTHONPYCACHEPREFIX'] = str(ARTIFACTS / 'installed-foundation-cache')
        positive_code = ('import json,sys;sys.path.insert(0,' + repr(str(installed)) + ');'
                         'import reference as R;'
                         'api=R.source_api();'
                         'print(json.dumps({"foundation":str(R.PROJECT),'
                         '"source_api":str(R.Path(api.__file__).resolve()),"optimize":sys.flags.optimize}))')
        positive = subprocess.run([sys.executable, '-B', '-c', positive_code], env=env,
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        observed = json.loads(positive.stdout)
        self.assertEqual(observed, {'foundation': str(installed_root.resolve()),
                                   'source_api': str((R.PROJECT / 'tools/smir-runtime-contract/source_roles/source_data.py').resolve()),
                                   'optimize': sys.flags.optimize})

        env['SMIR_RAW8_REFERENCE_PROJECT'] = 'relative/path'
        env['PYTHONPYCACHEPREFIX'] = str(ARTIFACTS / 'relative-foundation-cache')
        command = [sys.executable, '-B', '-c',
                   'import sys;sys.path.insert(0,' + repr(str(HERE)) + ');import reference']
        relative = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(relative.returncode, 0)
        self.assertIn('RAW_REFERENCE_FOUNDATION', relative.stderr)

        env['SMIR_RAW8_REFERENCE_PROJECT'] = str(R.PROJECT)
        env['PYTHONPYCACHEPREFIX'] = str(ARTIFACTS / 'foreign-foundation-cache')
        foreign_code = ('import sys;sys.path.insert(0,' + repr(str(R.PROJECT / 'tools/smir-abi')) + ');'
                        'import candidate;sys.path.insert(0,' + repr(str(HERE)) + ');import reference')
        foreign = subprocess.run([sys.executable, '-B', '-c', foreign_code], env=env,
                                 capture_output=True, text=True, timeout=30)
        self.assertNotEqual(foreign.returncode, 0)
        self.assertIn('RAW_REFERENCE_FOREIGN_CANDIDATE', foreign.stderr)
        for row in guards:
            self.assertEqual(R.hashlib.sha256(Path(row['path']).read_bytes()).hexdigest(), row['sha256'])
        (ARTIFACTS / 'foundation-import-results.json').write_text(json.dumps({
            'source_guards': guards,
            'positive': observed,
            'cases': [{'case': name, 'exit': row.returncode, 'stderr': row.stderr}
                      for name, row in [('off-layout-missing', missing), ('installed-default', positive),
                                        ('relative', relative), ('actual-ABI-candidate', foreign)]]}, indent=2) + '\n')

    def test_real_growth_and_original_resource_keep_bounded_unbuffered_guard(self):
        schema=ARTIFACTS/'growth-schema.json';schema.write_bytes(R.SCHEMA_PATH.read_bytes())
        captured=schema.stat().st_size;rows=[];saved=[];actual_child=R.child;scan=R.bounded_digest;open_file=Path.open
        class Reader:
            def __init__(self,file,row):self.file,self.row=file,row
            def __enter__(self):self.file.__enter__();return self
            def __exit__(self,*args):return self.file.__exit__(*args)
            def read(self,count):
                value=self.file.read(count);self.row['reads'].append((count,len(value),self.file.tell()));return value
        def traced(path,size):
            if path!=schema:return scan(path,size)
            row={'size':size,'reads':[]};rows.append(row)
            def opened(path,*args,**kw):
                import io
                file=open_file(path,*args,**kw)
                if path==schema:
                    row['raw']=isinstance(file,io.FileIO);return Reader(file,row)
                return file
            with mock.patch.object(Path,'open',opened):return scan(path,size)
        with mock.patch.object(R,'SCHEMA_PATH',schema):
            ledger=budget();session=R.ReferenceSession(BINARY,RECEIPT,budget=ledger,max_events=2)
            def grow_and_exhaust(*args,**kw):
                result=actual_child(*args,**kw)
                with schema.open('ab',buffering=0)as file:file.write(b' '*(1<<20))
                try:ledger.charge(copied_bytes=10**14)
                except R.source_api().SourceDataError as error:saved.append((error,error.kind,error.code,error.detail));raise
                return result
            with mock.patch.object(R,'child',grow_and_exhaust),mock.patch.object(R,'bounded_digest',traced),self.assertRaises(R.HelperError)as caught:
                session.evaluate('from_int8',{'state':'concrete','bits':42},budget=ledger)
        original,kind,code,detail=saved[0]
        self.assertEqual(caught.exception.code,'RAW_REFERENCE_CHANGED')
        self.assertIs(caught.exception.__cause__,original)
        self.assertEqual((original.kind,original.code,original.detail),(kind,code,detail))
        self.assertEqual((session.native_calls,session.serial,len(session.events)),(1,0,0))
        for row in rows:
            self.assertTrue(row['raw'])
            self.assertEqual(row['size'],captured)
            self.assertLessEqual(sum(n for n,_,_ in row['reads']),captured+1)
            self.assertLessEqual(sum(n for _,n,_ in row['reads']),captured+1)
            self.assertTrue(all(pos<=captured+1 for _,_,pos in row['reads']))
        (ARTIFACTS/'growth-read-traces.json').write_text(json.dumps(rows,indent=2)+'\n')

    def test_zero_and_exact_one_less_canonical_budget_dimensions(self):
        api = R.source_api()
        with self.assertRaises(api.SourceDataError) as caught:
            R.ReferenceSession(BINARY, RECEIPT, budget=api.SourceQueryBudget(max_work=0,max_edges=0,max_copied_bytes=0,max_depth=1), max_events=1)
        self.assertEqual((caught.exception.kind, caught.exception.code), ('resource', 'SOURCE_DATA_RESOURCE'))
        def sequence(ledger):
            s = R.ReferenceSession(BINARY, RECEIPT, budget=ledger, max_events=1)
            v = s.capture_raw(Raw.integer(8, 42), budget=ledger)
            return s.result(s.evaluate('freeze8', {'value': v}, budget=ledger), budget=ledger)
        base = budget(); expected = sequence(base)
        limits = dict(max_work=base._used_work,max_edges=base._used_edges,max_copied_bytes=base._used_copied_bytes,max_depth=128)
        self.assertEqual(sequence(api.SourceQueryBudget(**limits)), expected)
        original_charge = api.SourceQueryBudget.charge
        for key in ('max_work','max_edges','max_copied_bytes'):
            smaller=dict(limits);smaller[key]-=1;saved=[]
            def watch(ledger, **counts):
                try:return original_charge(ledger, **counts)
                except api.SourceDataError as error:saved.append(error);raise
            with mock.patch.object(api.SourceQueryBudget,'charge',watch), self.assertRaises(api.SourceDataError) as caught:
                sequence(api.SourceQueryBudget(**smaller))
            self.assertIs(caught.exception,saved[-1])

    def test_attempt_capacity_failure_never_publishes_event(self):
        s=R.ReferenceSession(BINARY,RECEIPT,budget=self.ledger,max_events=1)
        s.evaluate('from_int8',{'state':'concrete','bits':42},budget=self.ledger)
        with self.assertRaises(R.HelperError) as caught:
            s.evaluate('from_int8',{'state':'concrete','bits':43},budget=self.ledger)
        self.assertEqual((caught.exception.kind,len(s.events),s.native_calls),('resource',1,1))

    def test_closed_schema_bool_float_duplicate_depth_and_invalid_origin(self):
        for data in (b'{"x":1,"x":2}',b'{"x":1.0}',b'{"x":NaN}'):
            with self.assertRaises(R.HelperError):R.strict_json(data)
        for args in ({'state':'concrete','bits':True},{'state':'concrete','bits':256},{'state':'concrete','bits':0,'extra':0}):
            before=self.session.native_calls
            with self.assertRaises(R.HelperError):self.session.evaluate('from_int8',args,budget=self.ledger)
            self.assertEqual(self.session.native_calls,before)
        q={'format':'smir-raw8-helper-request','revision':1,'operation':'freeze8','origins':[],
           'arguments':{'value':{'width':8,'bits':'0000000000000000','poison':'0000000000000000','undef':'0000000000000000',
                               'origins':[{'offset':0,'length':8,'origin':1,'source':0}]}}}
        status,out,err=R.child([str(BINARY)],R.canonical(q))
        self.assertEqual(status,2)
        self.assertEqual(R.strict_json(out)['code'],'RAW_INPUT')
        status,out,err=R.child([str(BINARY)],b'['*40+b']'*40)
        self.assertEqual((status,R.strict_json(out)['code']),(2,'RAW_RESOURCE'))

    def test_native_canonical_integer_protocol_rejects_actual_root_counters(self):
        request={'format':'smir-raw8-helper-request','revision':1,'operation':'from_int8','origins':[],
                 'arguments':{'state':'concrete','bits':42}}
        positive=R.canonical(request)
        status,out,err=R.child([str(BINARY)],positive)
        self.assertEqual((status,R.strict_json(out)['result']['bits']),(0,'000000000000002a'))
        bad=[positive.replace(b'"bits":42',b'"bits":42,"bits":43'),
             positive.replace(b'"bits":42',b'"bits":42,"b\\u0069ts":43'),
             positive.replace(b'"revision":1',b'"revision":1.0'),
             positive.replace(b'"bits":42',b'"bits":42.0'),
             positive.replace(b'"bits":42',b'"bits":4.2e1'),
             positive+b'\n',json.dumps(request).encode()]
        rows=[]
        for raw in bad:
            status,out,err=R.child([str(BINARY)],raw);row=R.strict_json(out)
            self.assertEqual((status,row['status']),(2,'rejected'))
            rows.append({'input':raw.decode(),'exit':status,'response':row})
        (ARTIFACTS/'native-grammar-rejections.json').write_text(json.dumps(rows,indent=2)+'\n')

    def test_native_timeout_is_actual_child_failure(self):
        with mock.patch.object(R,'TIMEOUT',0),self.assertRaises(R.HelperError) as caught:
            self.native('from_int8',{'state':'concrete','bits':0})
        self.assertEqual(caught.exception.kind,'resource')


class ActualMachine(unittest.TestCase):
    def test_fresh_genuine_issued_address_all_ten_profiles(self):
        rows=[]
        for profile in encoded_cases()[1]:
            with self.subTest(profile=profile):
                row=actual_witness(profile,BINARY,RECEIPT);rows.append(row)
                self.assertEqual(row['optimize'],sys.flags.optimize)
                self.assertGreater(row['native_calls'],0)
                self.assertFalse(row['source_fact_authority'])
                if profile=='relay':
                    self.assertEqual((row['return_value'],row['helper_entries'],row['helper_returns'],row['stores'],row['loads'],row['permits'],row['entries']),(42,8,8,8,9,1,1))
                else:self.assertEqual((row['permits'],row['entries']),(0,0))
        (ARTIFACTS/'actual-machine-profiles.json').write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    report={'tests':result.testsRun,'fail':len(result.failures),'error':len(result.errors),'skip':len(result.skipped),'optimize':sys.flags.optimize}
    (ARTIFACTS/'tests-result.json').write_text(json.dumps(report,indent=2)+'\n')
    if not result.wasSuccessful():raise SystemExit(1)
