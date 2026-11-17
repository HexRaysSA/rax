"""Genuine ABI-verified type contexts for unconsumed pure value data."""
from copy import copy, deepcopy
import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import weakref

ROOT = Path(__file__).resolve().parents[2]
EXECUTION = ROOT / 'tools/smir-format/execution'
# Discovery imports the runtime candidate package while descending directories.
# Runtime tests use their separate runtime_candidate alias. Reserve candidate
# for the actual execution context, as the existing source-role tests do.
for _name, _module in tuple(sys.modules.items()):
    _file = getattr(_module, '__file__', None)
    if (_name == 'candidate' or _name.startswith('candidate.')) and _file and \
            ROOT / 'tools/smir-runtime-contract/candidate' in Path(_file).parents:
        del sys.modules[_name]
sys.path.insert(0, str(EXECUTION))
sys.path.insert(1, str(ROOT / 'tools/smir-format'))
from candidate.context import RootContext, source_call_api
from candidate.source_data_projection import source_api
from candidate.type_system import ref

CALL = source_call_api()
SD = source_api()
NAME = '_rax_smir_code_values_v1'
PATH = ROOT / 'tools/smir-runtime-contract/source_roles/code_values.py'
if NAME not in sys.modules:
    spec = importlib.util.spec_from_file_location(NAME, PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[NAME] = module
    spec.loader.exec_module(module)
M = sys.modules[NAME]
FIXTURE = ROOT / 'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json'
VECTORS = ROOT / 'docs/specifications/smir/portable/conformance/runtime/code-values-vectors.json'
WIDTHS = (1, 8, 32, 64, 128, 65536, 2**23)


def ledger(**changes):
    policy = dict(max_work=10**9, max_edges=10**9, max_copied_bytes=10**9, max_depth=128)
    policy.update(changes)
    return SD.SourceQueryBudget(**policy)


def document():
    result = {int(n): r for n, r in json.loads(FIXTURE.read_bytes())['sections'].items()}
    for i, width in enumerate(WIDTHS):
        result[1]['types'].append(dict(id=1000+i, kind='int', bits=width))
    rows = []
    for i, width in enumerate(WIDTHS):
        rows.append(dict(id=i, kind='type', symbol_kind='none', source_linkage='none',
                         namespace='pure', name='integer_'+str(width),
                         execution={'some': ref(1000+i)}, nominal=None, abi_signature=None, weak=False))
    result[2]['manifest']['dependencies'] = [dict(slot=0,
        key=dict(namespace='pure', name='provider', abi_major=1, abi_minor=0),
        minimum_minor=0, maximum_minor=None, site=result[10]['identity'], declarations=rows)]
    return result


def actual(budget=None):
    budget = ledger() if budget is None else budget
    context = RootContext(document())
    context.verify_abi()
    return context, context.source_call_context(budget=budget), budget


def vector_document():
    return {'format': 'pure-code-values-v1', 'scope': 'data only; no target or authority',
            'source_sha256': hashlib.sha256(PATH.read_bytes()).hexdigest(),
            'fixture_sha256': hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            'integer_cases': [{'width': width, 'self_id': 1000+i, 'dependency_slot': 0,
                               'dependency_id': i, 'boundaries': ['zero','max','overflow','negative','bool'],
                               'states': ['concrete','poison','undef']} for i,width in enumerate(WIDTHS)],
            'address_cases': [{'state':'concrete','bits_hex':format(bits,'016x')}
                              for bits in (0, 2, 2**64-1)] + [{'state':'poison'},{'state':'undef'}]}


class CodeValuesTests(unittest.TestCase):
    def setUp(self):
        self.context, self.view, self.budget = actual()

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(M.CodeValueError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_all_actual_widths_self_and_original_dependency(self):
        for i,width in enumerate(WIDTHS):
            # Maximum-width type uses zero here; bounded max patterns below use
            # the independently supported 65536-bit wide type.
            values = (0, 1) if width == 2**23 else (0, (1 << width)-1)
            for value in values:
                for reference in (ref(1000+i), ref(i,0)):
                    with self.subTest(width=width,value_bits=value.bit_length(),dependency='slot'in reference['module']):
                        result = M.integer(value,self.view,reference,budget=self.budget)
                        self.assertEqual((result.width,result.state,result.bits(budget=self.budget)),(width,'concrete',value))
                        self.assertIs(result.context,self.view)
                        self.assertEqual(result.reference['module']['kind'],reference['module']['kind'])
                        self.assertEqual(result.local_reference['id'],1000+i)

    def test_unsigned_boundaries_bool_and_overflow(self):
        for i,width in enumerate(WIDTHS):
            for bad in (-1, True, False, 1.0, '1', None, 1 << width):
                with self.subTest(width=width,bad_type=type(bad).__name__):
                    self.error('CODE_VALUE_INTEGER_RANGE',M.integer,bad,self.view,ref(1000+i),budget=self.budget)

    def test_poison_undef_never_project_fake_bits(self):
        for factory,state in ((M.integer_poison,'poison'),(M.integer_undef,'undef')):
            result=factory(self.view,ref(1000),budget=self.budget)
            self.assertEqual(result.state,state)
            self.assertIs(M.validate_integer(result,budget=self.budget),result)
            self.error('CODE_VALUE_NONCONCRETE',result.bits,budget=self.budget)
        for factory,state in ((M.poison,'poison'),(M.undef,'undef')):
            result=factory(budget=self.budget)
            self.assertEqual((result.width,result.state),(64,state))
            self.error('CODE_VALUE_NONCONCRETE',result.bits,budget=self.budget)

    def test_originless_address_boundaries_have_no_claim_fields(self):
        for bits in (0,2,2**64-1):
            result=M.originless(bits,budget=self.budget)
            self.assertEqual(result.bits(budget=self.budget),bits)
            self.assertEqual((result.width,result.state),(64,'concrete'))
            for forbidden in ('origin','authority','permit','target','generation','activation'):
                self.assertFalse(hasattr(result,forbidden))
        self.assertEqual(M.null(budget=self.budget).bits(budget=self.budget),0)
        for bad in (-1,2**64,True,False,1.0,None):
            self.error('CODE_VALUE_ADDRESS_RANGE',M.originless,bad,budget=self.budget)
        with self.assertRaises(TypeError):
            M.originless(2,budget=self.budget,authority=True)

    def test_wrong_execution_kind_or_namespace_preserves_errors(self):
        for identifier in (3,4,7,12,200):
            self.error('CODE_VALUE_INTEGER_TYPE',M.integer,0,self.view,ref(identifier),budget=self.budget)
        for reference in (ref(9999),ref(0,1),{'module':{'kind':'self'},'id':True}):
            with self.assertRaises(sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError):
                M.integer(0,self.view,reference,budget=self.budget)

    def test_wrong_budget_context_and_noncanonical_budget(self):
        result=M.integer(1,self.view,ref(1000),budget=self.budget)
        with self.assertRaises(sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError):
            M.integer(0,self.view,ref(1000),budget=ledger())
        self.error('CODE_VALUE_BUDGET_CONTEXT',result.bits,budget=ledger())
        class FakeBudget:
            def charge(self,**kw):
                raise RuntimeError('duck called')
        class SubBudget(SD.SourceQueryBudget):
            pass
        for bad in (None,FakeBudget(),object.__new__(SD.SourceQueryBudget),
                    SubBudget(max_work=1,max_edges=1,max_copied_bytes=1,max_depth=1)):
            with self.assertRaises(SD.SourceDataError) as caught:
                M.originless(0,budget=bad)
            self.assertEqual(caught.exception.code,'SOURCE_DATA_BUDGET')

    def test_other_context_has_own_types_and_values_not_interchangeable(self):
        _,other,other_budget=actual()
        a=M.integer(1,self.view,ref(1000),budget=self.budget)
        b=M.integer(1,other,ref(1000),budget=other_budget)
        self.assertIsNot(a.context,b.context)
        self.assertIsNot(a,b)
        self.error('CODE_VALUE_BUDGET_CONTEXT',M.validate_integer,a,budget=other_budget)
        self.assertEqual(b.bits(budget=other_budget),1)

    def test_fake_view_subclass_duck_and_object_new_reject(self):
        class Duck:
            def record(self,*args,**kwargs):
                raise RuntimeError('duck invoked')
        class Sub(CALL.SourceCallContext):
            pass
        for fake in (Duck(),object.__new__(CALL.SourceCallContext),object.__new__(Sub)):
            with self.assertRaises(sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError):
                M.integer(0,fake,ref(1000),budget=self.budget)

    def test_immutable_identity_no_ctor_reinit_delete_or_forged_copy(self):
        value=M.integer(1,self.view,ref(1000),budget=self.budget)
        self.assertIs(copy(value),value)
        self.assertIs(deepcopy(value),value)
        for cls in (M.IntegerLane,M.AddressLane):
            self.error('CODE_VALUE_CONSTRUCTOR',cls,authority=True)
            self.error('CODE_VALUE_IDENTITY',M.validate_address,object.__new__(cls),budget=self.budget)
        self.error('CODE_VALUE_CONSTRUCTOR',value.__init__)
        with self.assertRaises(AttributeError):
            value._record=()
        with self.assertRaises(AttributeError):
            del value._record
        forged=object.__new__(M.IntegerLane)
        object.__setattr__(forged,'_record',value._record)
        self.error('CODE_VALUE_IDENTITY',M.validate_integer,forged,budget=self.budget)
        self.error('CODE_VALUE_KIND',M.validate_address,value,budget=self.budget)

    def test_root_mutation_before_and_after_issue_rejects(self):
        value=M.integer(1,self.view,ref(1000),budget=self.budget)
        self.context.sections[1]['types'][0]['bits']=31
        for action in (lambda:M.integer(0,self.view,ref(1000),budget=self.budget),
                       lambda:value.bits(budget=self.budget)):
            with self.assertRaises(SD.SourceDataError) as caught:
                action()
            self.assertEqual(caught.exception.code,'context_snapshot_changed')

    def test_schema_mutation_rejected_unchanged_error_identity(self):
        value=M.integer(0,self.view,ref(1000),budget=self.budget)
        projection=self.view._projection
        changed=deepcopy(projection.SCHEMA['records']['type'])
        changed['variants']['int'].append(['extra','u32'])
        with patch.dict(projection.SCHEMA['records'],{'type':changed}):
            with self.assertRaises(SD.SourceDataError) as caught:
                value.bits(budget=self.budget)
            self.assertEqual(caught.exception.code,'SOURCE_DATA_SCHEMA')
        sentinel=sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError('resource','TEST_LIMIT','x')
        with patch.object(CALL,'validate_source_call_context',side_effect=sentinel):
            # Replacing the canonical validator itself is a module-identity error.
            self.error('CODE_VALUE_MODULE_IDENTITY',M.integer,0,self.view,ref(1000),budget=self.budget)

    def test_zero_and_cumulative_quota_no_reset(self):
        self.error('CODE_VALUE_INTEGER_RANGE',M.integer,-1,self.view,ref(1000),budget=self.budget)
        for dimension in ('max_work','max_edges','max_copied_bytes'):
            with self.assertRaises(SD.SourceDataError):
                M.originless(0,budget=ledger(**{dimension:0}))
        budget=ledger(max_work=32,max_edges=8,max_copied_bytes=256)
        M.originless(0,budget=budget)
        M.originless(2,budget=budget)
        used=(budget._used_work,budget._used_edges,budget._used_copied_bytes)
        with self.assertRaises(SD.SourceDataError):
            M.originless(4,budget=budget)
        self.assertEqual((budget._used_work,budget._used_edges,budget._used_copied_bytes),used)
        with self.assertRaises(SD.SourceDataError):
            budget.__init__(max_work=999,max_edges=999,max_copied_bytes=999,max_depth=1)

    def test_weak_issuance_does_not_permanently_pin_context(self):
        context,view,budget=actual()
        value=M.integer(1,view,ref(1000),budget=budget)
        weak_context,weak_view=weakref.ref(context),weakref.ref(view)
        identity=id(value)
        del context,view
        gc.collect()
        self.assertIsNotNone(weak_context())
        self.assertIsNotNone(weak_view())
        del value
        gc.collect()
        self.assertIsNone(weak_context())
        self.assertIsNone(weak_view())
        self.assertNotIn(identity,M._ISSUED)

    def test_exact_source_error_instances_propagate(self):
        failure=SD.SourceDataError('resource','SOURCE_DATA_RESOURCE','injected refusal')
        with patch.object(SD.SourceQueryBudget,'charge',side_effect=failure):
            with self.assertRaises(SD.SourceDataError) as caught:
                M.originless(0,budget=self.budget)
            self.assertIs(caught.exception,failure)
        cls=sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError
        failure=cls('resource','ABI_CC_GRAPH_LIMIT','injected read refusal')
        with patch.object(CALL.SourceCallContext,'record',side_effect=failure):
            with self.assertRaises(cls) as caught:
                M.integer(0,self.view,ref(1000),budget=self.budget)
            self.assertIs(caught.exception,failure)

    def test_typed_integer_cumulative_and_wide_reservations(self):
        used=self.budget._used_work,self.budget._used_copied_bytes
        measured=M.integer(0,self.view,ref(1000),budget=self.budget)
        cost_work=self.budget._used_work-used[0]
        cost_bytes=self.budget._used_copied_bytes-used[1]
        budget=ledger(max_work=used[0]+cost_work)
        view=self.context.source_call_context(budget=budget)
        value=M.integer(0,view,ref(1000),budget=budget)
        issued=set(M._ISSUED)
        with self.assertRaises(SD.SourceDataError):
            M.integer(0,view,ref(1000),budget=budget)
        self.assertEqual(set(M._ISSUED),issued)
        self.assertEqual(budget._used_work,budget.max_work)
        budget=ledger(max_copied_bytes=used[1]+cost_bytes)
        view=self.context.source_call_context(budget=budget)
        issued=set(M._ISSUED)
        with self.assertRaises(SD.SourceDataError) as caught:
            M.integer(0,view,ref(1006),budget=budget)
        self.assertEqual(caught.exception.code,'SOURCE_DATA_RESOURCE')
        self.assertEqual(set(M._ISSUED),issued)
        self.assertLessEqual(budget._used_copied_bytes,budget.max_copied_bytes)

    def test_canonical_module_path_and_validator_identity(self):
        replacement=types.SimpleNamespace(__file__='/tmp/wrong.py')
        with patch.dict(sys.modules,{'_rax_smir_source_call_v1':replacement}):
            self.error('CODE_VALUE_MODULE_IDENTITY',M.integer,0,self.view,ref(1000),budget=self.budget)
        spec=importlib.util.spec_from_file_location('_wrong_code_values_alias',PATH)
        alias=importlib.util.module_from_spec(spec)
        with self.assertRaisesRegex(ImportError,'CODE_VALUE_MODULE_IDENTITY'):
            spec.loader.exec_module(alias)

    def test_vector_reproduction_and_execution(self):
        expected=vector_document()
        self.assertEqual(json.loads(VECTORS.read_bytes()),expected)
        for case in expected['integer_cases']:
            value=M.integer(0,self.view,ref(case['self_id']),budget=self.budget)
            self.assertEqual(value.width,case['width'])
        for case in expected['address_cases']:
            value=(M.originless(int(case['bits_hex'],16),budget=self.budget) if case['state']=='concrete'
                   else getattr(M,case['state'])(budget=self.budget))
            self.assertEqual(value.state,case['state'])


if __name__=='__main__':
    unittest.main()
