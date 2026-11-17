"""Full ABI source graphs plus independent static role and owner checks."""
from copy import deepcopy
import unittest
from candidate import verify
from layout import ABIError
from nominal import NominalGraph,ref,some
from .builder import build_builtin_states,SOURCE_KEYS,EXECUTION_KEYS
from .fixtures import sample,checked_context
from .model import SourceRoles


class SourceRoleTests(unittest.TestCase):
    def admitted(self):
        doc,parts=sample();context,shapes=checked_context(doc,parts['execution_graph'])
        verify(doc,context)
        graph=NominalGraph(doc,'main')
        return doc,parts,SourceRoles(graph,lambda owner,r:shapes.describe(r)),shapes

    def test_all17_actual_source_role_controls(self):
        doc,parts,roles,shapes=self.admitted()
        cases={name:ref(108) for name in ('tls_address','tls_guard_acquire','tls_guard_release','tls_guard_abort',
            'guard_acquire','guard_release','guard_abort')}
        cases.update({name:ref(107) for name in ('atomic_flag_test','atomic_flag_test_and_set','atomic_flag_clear')})
        cases.update({name:parts['va_list'] for name in ('va_start','va_copy','va_end')})
        cases.update({name:parts['jmp_buf'] for name in ('setjmp_capture','longjmp_restore')})
        cases.update(va_arg=ref(101),eh_allocate=ref(101))
        self.assertEqual(len(cases),17)
        for name,reference in cases.items():
            extra={'target':('main',reference)} if name=='tls_address' else {'type0':('main',ref(201))} if name=='va_arg' else {}
            result=roles.check(name,reference,**extra)
            self.assertFalse(result['runtime_or_production_authority'])

    def test_flag_wrong_source_kind_and_source_type0(self):
        doc,parts,roles,_=self.admitted()
        for name in ('atomic_flag_test','atomic_flag_test_and_set','atomic_flag_clear'):
            with self.assertRaisesRegex(ABIError,'ABI_SOURCE_FLAG_KIND'):roles.check(name,ref(101))
        with self.assertRaisesRegex(ABIError,'ABI_SOURCE_VARARG_TYPE0'):
            roles.check('va_arg',ref(101),type0=('main',ref(202)))

    def test_builtin_wrong_state_unused_metadata_rejected_by_actual_abi(self):
        doc,parts,_,_=self.admitted()
        state=next(t for t in doc['types'] if t['id']==103)
        state['record_input']['some']['fields'][0]['name']=some('wrong')
        next(l for l in doc['layouts'] if l['id']==103)['fields'][0]['name']='wrong'
        from candidate_fixtures import seal
        seal(doc);context,_=checked_context(doc,parts['execution_graph'])
        with self.assertRaisesRegex(ABIError,'ABI_CC_BUILTIN_STATE'):verify(doc,context)

    def test_wrapper_cannot_be_substituted_by_same_size_state(self):
        _,parts,roles,_=self.admitted()
        for name in ('va_start','va_copy','va_end','setjmp_capture','longjmp_restore'):
            with self.assertRaisesRegex(ABIError,'ABI_CC_BUILTIN_STATE'):
                roles.check(name,parts['va_state'] if name.startswith('va_') else parts['jmp_state'])

    def test_original_dependency_owner_and_equal_numeric_collision(self):
        doc,parts,_,shapes=self.admitted();provider=deepcopy(doc)
        graph=NominalGraph(doc,'main',{'provider':provider},bindings={
            'main':{7:{'module':'provider','types':{101:105}}}})
        roles=SourceRoles(graph,lambda owner,r:shapes.describe(r))
        original=ref(101,7)
        result=roles.check('va_start',original)
        self.assertEqual(result['original_nominal'],original)
        self.assertEqual(result['resolved_source_owner'],'provider')
        with self.assertRaisesRegex(ABIError,'ABI_CC_BUILTIN_STATE'):roles.check('va_start',ref(101))

    def test_reference_to_incomplete_has_real8B_cell(self):
        doc,_,roles,_=self.admitted()
        self.assertIsNone(next(t for t in doc['types'] if t['id']==109)['layout'])
        self.assertEqual(next(l for l in doc['layouts'] if l['id']==108)['size'],8)
        for name in ('guard_acquire','tls_guard_acquire'):
            roles.check(name,ref(108))
        with self.assertRaisesRegex(ABIError,'ABI_SOURCE_PAYLOAD_TYPE'):roles.check('eh_allocate',ref(108))

    def test_builder_explicit_ids_namespaces_and_input_preservation(self):
        source=dict(zip(SOURCE_KEYS,range(6)));execution=dict(zip(EXECUTION_KEYS,range(5)))
        before=deepcopy((source,execution));parts=build_builtin_states(source_ids=source,execution_ids=execution,domain_id=0)
        self.assertEqual((source,execution),before)
        self.assertEqual([l['id'] for l in parts['layouts']],list(range(6)))
        self.assertTrue(all(t['identity']['definition']=='0'*64 for t in parts['types']))
        for wrong in ({},dict(source,extra=9),dict(source,uint32=True),dict(source,uint32=0xffffffff),dict(source,uint32=1)):
            with self.assertRaisesRegex(ABIError,'ABI_SOURCE_BUILDER_IDS'):
                build_builtin_states(source_ids=wrong,execution_ids=execution,domain_id=19)

    def test_qualified_global_state_is_valid_but_helper_role_is_unqualified(self):
        for qualifier in ('const','volatile'):
            doc,parts,_,_=self.admitted()
            before=NominalGraph(doc,'main').fingerprint(ref(103))
            next(t for t in doc['types'] if t['id']==103)['qualifiers']=[qualifier]
            from candidate_fixtures import seal
            seal(doc);context,shapes=checked_context(doc,parts['execution_graph'])
            verify(doc,context)
            self.assertNotEqual(before,NominalGraph(doc,'main').fingerprint(ref(103)))
            roles=SourceRoles(NominalGraph(doc,'main'),lambda owner,r:shapes.describe(r))
            with self.assertRaisesRegex(ABIError,'ABI_CC_BUILTIN_STATE'):
                roles.check('va_start',parts['va_list'])

    def test_global_outer_cv_exception_never_erases_nested_qualifiers(self):
        for identifier,qualifier in ((102,'const'),(103,'restrict')):
            doc,parts,_,_=self.admitted()
            next(t for t in doc['types'] if t['id']==identifier)['qualifiers']=[qualifier]
            from candidate_fixtures import seal
            seal(doc);context,_=checked_context(doc,parts['execution_graph'])
            with self.assertRaisesRegex(ABIError,'ABI_CC_BUILTIN_STATE'):
                verify(doc,context)
