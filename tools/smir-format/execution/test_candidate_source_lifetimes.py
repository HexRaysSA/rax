"""Authored conditional protocol fixtures; never actual CPP runtime issuers."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from candidate.source_data_projection import source_api
from candidate.source_lifetimes import ContractError, Verifier, preflight, shape, verify, SCHEMA

FIXTURES = Path(__file__).resolve().parents[3] / 'docs/specifications/smir/portable/conformance/execution/source-lifetimes'


def qref(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


def external(namespace, identifier, context='c'):
    return {'context': context, 'namespace': namespace, 'reference': qref(identifier)}


def ledger(**changes):
    limits = dict(max_work=10**9, max_edges=10**9, max_copied_bytes=10**9, max_depth=128)
    limits.update(changes)
    return source_api().SourceQueryBudget(**limits)


def base():
    binding = dict(id='caller', function=external('Function', 0), value=0,
                   source_class=external('Nominal', 12), source_path=external('CppSourcePath', 0),
                   role='complete', origin={'kind': 'returned_result',
                       'call': {'kind': 'op', 'block': 0, 'index': 0}, 'plan': external('CallSignature', 0)})
    creation = deepcopy(binding)
    creation.update(id='creator', function=external('Function', 1), origin={'kind': 'created', 'site': 50})
    programs = [dict(id=name, program=external('Journal', identifier), source_class=external('Nominal', 12),
                     view=view, coverage=external('CppCoverage', identifier))
                for name, identifier, view in [('complete', 0, 'complete'), ('nv', 1, 'nonvirtual')]]
    ends = [dict(id=0, binding='caller', location={'kind': 'pre_op', 'block': 0, 'index': 1},
                 reason='scope_end', stage='ordinary_end',
                 effect={'kind': 'destructor_preentry', 'call_site': 10, 'plan': external('CallSignature', 0)}),
            dict(id=1, binding='caller', location={'kind': 'normal_post', 'block': 0, 'index': 2},
                 reason='scope_end', stage='destructive_retire',
                 effect={'kind': 'cleanup_complete', 'program': 'complete'}),
            dict(id=2, binding='caller', location={'kind': 'pre_op', 'block': 0, 'index': 3},
                 reason='scope_end', stage='ordinary_end', effect={'kind': 'trivial_end'}),
            dict(id=3, binding='caller', location={'kind': 'normal_post', 'block': 0, 'index': 4},
                 reason='reuse', stage='ordinary_end', effect={'kind': 'reuse_commit'}),
            dict(id=4, binding='caller', location={'kind': 'normal_post', 'block': 0, 'index': 5},
                 reason='storage_release', stage='ordinary_end', effect={'kind': 'deallocation_commit'}),
            dict(id=5, binding='caller', location={'kind': 'normal_post', 'block': 0, 'index': 6},
                 reason='scope_end', stage='failed_construction_retire',
                 effect={'kind': 'cleanup_complete', 'program': 'complete'})]
    exits = []
    for identifier, helper in enumerate(['normal.no_journal', 'normal.with_journal', 'unwind.no_journal',
                                        'unwind.with_journal', 'outward_unwind.no_journal', 'outward_unwind.with_journal']):
        mode = helper.split('.')[0]
        location = {'kind': 'return_exit', 'block': 0} if mode == 'normal' else {
            'kind': 'unwind_exit', 'block': 0, 'call_index': None}
        exits.append(dict(id=identifier, function=external('Function', 0), scope=10, subject='physical',
                          location=location, helper=helper, scope_value=100,
                          journal=101 if helper.endswith('with_journal') else None,
                          exception=102 if mode == 'unwind' else None))
    contract = dict(format='draft-source-lifetime-contract', revision=1, binding='unbound',
        contexts=[dict(id='c', source_unit='11' * 32, abi_source='22' * 32, execution_source='33' * 32)],
        program_requirements=programs, object_bindings=[binding, creation], end_sites=ends,
        implicit_sets=[dict(id='implicit', binding='creator', source_class=external('Nominal', 12),
                            selection='recursive_eligible_subobjects', union_selection='explicit_source_selection')],
        scope_exits=exits)
    cells = [dict(id='root', parent=None, repeat=1, role='root', implicit_eligible=True, union_selected=None),
             dict(id='v', parent='root', repeat=1, role='virtual_base', implicit_eligible=True, union_selected=None),
             dict(id='m', parent='root', repeat=1, role='member', implicit_eligible=True, union_selected=None)]
    obj = dict(id='object', binding='creator', allocation='storage', allocation_generation=1,
               object_generation=1, offset=0, state='constructing', complete_owner='object', parent=None,
               parent_cell=None, claim=None, implicit_set=None)
    alias = dict(id='pointer', binding='caller', object='object', generation=1, allocation_generation=1,
                 owner='frame', owner_generation=1)
    view = dict(id='view', object='object', generation=1, program='complete', owner='frame', scope_generation=1,
                mode='construct', state='live', journal='j0', exception=None, cleanup_receipt=None)
    scope = dict(id='scope', declaration=10, value=100, view='view', object='object', owner='frame', generation=1,
                 pending=None, exception=None, subject='physical', state='open')
    initial = dict(allocations=[dict(id='storage', generation=1, address=4096, size=64)], objects=[obj],
                   aliases=[alias], views=[view], scopes=[scope],
                   cells=[dict(owner='object', generation=1, cell='root', completed=0, ordinal=0),
                          dict(owner='object', generation=1, cell='v', completed=1, ordinal=1),
                          dict(owner='object', generation=1, cell='m', completed=1, ordinal=2)],
                   frames=[dict(id='frame', context='c', function=external('Function', 0), generation=1, thread='thread')])
    witness = dict(format='unbound-source-lifetime-protocol-witness', binding='unbound', cell_models=cells,
                   program_models=[dict(program='complete', extent_bytes=16, coverage=['v', 'm']),
                                   dict(program='nv', extent_bytes=12, coverage=['m'])], initial=initial, actions=[])
    return dict(contract=contract, witness=witness)


def action(kind, **fields):
    return dict(kind=kind, **fields)


def exit_action(site=0, journal=None, exception=None, propagation=None):
    return action('scope_exit', scope='scope', generation=1, exit_site=site,
                  journal=journal, exception=exception, propagation=propagation)


def simple_alive():
    document = base()
    state = document['witness']['initial']
    state['objects'][0]['state'] = 'alive'
    state['views'] = []
    state['scopes'] = []
    return document


def failure():
    document = base()
    child = dict(id='nv_view', object='object', generation=1, program='nv', owner='frame', scope_generation=2,
                 mode='partial_cleanup', state='live', journal='nv_j1', exception='E', cleanup_receipt=None)
    document['witness']['actions'] = [
        action('delegate', ticket='ticket', parent='view', child=child),
        action('cleanup', view='nv_view', journal='nv_j1', cell='m', count=1),
        action('finish_cleanup', view='nv_view', journal='nv_j1', exception='E', receipt='nv_failed'),
        action('rejoin', ticket='ticket', outcome='unwind', receipt='nv_failed', exception='E'),
        action('fail_partial', view='view', old_journal='j0', new_journal='j1', exception='E', failed_ticket='ticket'),
        action('cleanup', view='view', journal='j1', cell='v', count=1),
        action('finish_cleanup', view='view', journal='j1', exception='E', receipt='complete_failed'),
        exit_action(2, exception='E'),
        action('end_object', alias='pointer', owner='frame', end_site=5, next_allocation_generation=None)]
    return document


def cases():
    result = []
    def add(name, document, code=None, kind='semantic'):
        result.append(dict(name=name, expected={'kind': 'static'} if code is None else {'kind': kind, 'code': code},
                           document=document))
    document = base()
    document['witness']['actions'] = [action('publish', view='view', journal='j0', receipt='published'),
                                      exit_action(), action('frame_exit', frame='frame')]
    add('publication_scope_exit_does_not_end_object', document)
    add('nv_failure_preserves_virtual_then_parent_cleans', failure())
    document = failure()
    document['witness']['actions'] = document['witness']['actions'][:3]
    add('nv_failed_clear_keeps_parent_current_j_and_virtual', document)
    for old, expected in [('j0', 'SL_STALE_JOURNAL'), ('nv_j1', 'SL_STALE_JOURNAL')]:
        document = failure()
        document['witness']['actions'][5]['journal'] = old
        add('parent_cleanup_rejects_' + old, document, expected)
    document = failure()
    document['witness']['actions'].insert(4, deepcopy(document['witness']['actions'][3]))
    add('duplicate_rejoin', document, 'SL_REJOIN_REPLAY')
    document = failure()
    document['witness']['actions'][4]['exception'] = 'different_E'
    add('same_type_wrong_exception', document, 'SL_FAILED_CHILD')
    document = failure()
    document['contract']['program_requirements'][1]['source_class'] = external('Nominal', 999)
    add('delegated_program_wrong_source_class', document, 'SL_VIEW_CLASS')
    document = failure()
    document['witness']['actions'][0]['child']['scope_generation'] = 0
    add('delegated_scope_generation_zero', document, 'SL_GENERATION')
    document = failure()
    document['contract']['contexts'].append(dict(id='foreign', source_unit='44' * 32,
        abi_source='55' * 32, execution_source='66' * 32))
    document['witness']['initial']['frames'].append(dict(id='foreign_frame', context='foreign',
        function=external('Function', 0, 'foreign'), generation=1, thread='another_thread'))
    document['witness']['actions'][0]['child']['owner'] = 'foreign_frame'
    add('delegated_owner_wrong_original_context', document, 'SL_CONTEXT')
    document = base()
    document['witness']['actions'] = [action('cleanup', view='view', journal='j0', cell='v', count=1)]
    document['witness']['initial']['views'][0]['mode'] = 'partial_cleanup'
    add('cleanup_must_reverse_completion', document, 'SL_CLEANUP_ORDER')
    document = base()
    document['witness']['initial']['views'][0]['program'] = 'nv'
    document['witness']['actions'] = [action('publish', view='view', journal='j0', receipt='fake_root')]
    add('nv_cannot_publish_complete_root', document, 'SL_VIEW_PUBLICATION')
    document = base()
    document['witness']['program_models'][1]['coverage'].append('v')
    add('nv_cannot_own_virtual_base', document, 'SL_NV_VIRTUAL_COVERAGE')
    document = base()
    document['witness']['program_models'][1]['extent_bytes'] = 0
    add('zero_nv_explicit_unavailable', document, 'SL_ZERO_NV_VIEW')
    document = simple_alive()
    document['witness']['actions'] = [action('assign', alias='pointer', owner='frame'),
        action('claim_destroy', alias='pointer', end_site=0, claim='claim', owner='frame', preflight='rejected'),
        action('assign', alias='pointer', owner='frame'),
        action('claim_destroy', alias='pointer', end_site=0, claim='claim', owner='frame', preflight='accepted'),
        action('trap', code='source_trap')]
    add('preflight_refusal_preserves_alive_then_claim_trap_never_resurrects', document)
    document = simple_alive()
    claim = action('claim_destroy', alias='pointer', end_site=0, claim='claim', owner='frame', preflight='accepted')
    document['witness']['actions'] = [claim, deepcopy(claim)]
    add('destruction_claim_once', document, 'SL_CLAIM_REPLAY')
    document = simple_alive()
    document['witness']['initial']['aliases'][0]['generation'] = 0
    document['witness']['actions'] = [action('assign', alias='pointer', owner='frame')]
    add('stale_object_alias', document, 'SL_STALE_ALIAS')
    document = simple_alive()
    document['witness']['initial']['aliases'][0]['allocation_generation'] = 2
    document['witness']['actions'] = [action('assign', alias='pointer', owner='frame')]
    add('stale_allocation_alias', document, 'SL_STALE_ALIAS')
    document = simple_alive()
    document['witness']['initial']['frames'].append(dict(id='recursive', context='c', function=external('Function', 0),
                                                        generation=2, thread='thread'))
    document['witness']['actions'] = [action('assign', alias='pointer', owner='recursive')]
    add('same_function_same_ssa_wrong_activation', document, 'SL_ALIAS_ACTIVATION')
    document = simple_alive()
    document['witness']['initial']['aliases'][0]['owner_generation'] = 2
    document['witness']['actions'] = [action('assign', alias='pointer', owner='frame')]
    add('stale_observing_activation', document, 'SL_ALIAS_ACTIVATION')
    document = simple_alive()
    document['witness']['actions'] = [action('end_object', alias='pointer', owner='frame', end_site=2,
                                           next_allocation_generation=None)]
    add('outside_creation_frame_trivial_end', document)
    document = simple_alive()
    document['witness']['actions'] = [action('end_object', alias='pointer', owner='frame', end_site=4,
                                           next_allocation_generation=2)]
    add('storage_release_separately_increments_allocation_generation', document)
    document = simple_alive()
    document['witness']['actions'] = [action('end_object', alias='pointer', owner='frame', end_site=4,
                                           next_allocation_generation=1)]
    add('storage_release_cannot_keep_generation', document, 'SL_ALLOCATION_GENERATION')
    for proof in ['fresh_result', 'transparent_replacement', 'launder']:
        document = simple_alive()
        new = deepcopy(document['witness']['initial']['objects'][0])
        new.update(id='replacement', complete_owner='replacement', object_generation=2, binding='replacement_binding')
        binding = deepcopy(document['contract']['object_bindings'][0])
        binding.update(id='replacement_binding', value=1,
                       origin={'kind': 'created', 'site': 99} if proof == 'fresh_result' else
                              {'kind': proof, 'site': 99, 'previous_value': 0})
        document['contract']['object_bindings'].append(binding)
        alias = deepcopy(document['witness']['initial']['aliases'][0])
        alias.update(id='new_pointer', object='replacement', generation=2, binding='replacement_binding')
        document['witness']['actions'] = [action('end_object', alias='pointer', owner='frame', end_site=3,
                                                next_allocation_generation=None),
            action('replace_object', old_alias='pointer', owner='frame', new_object=new, new_alias=alias,
                   rebind_aliases=['pointer'] if proof == 'transparent_replacement' else [], source_proof=proof),
            action('assign', alias='new_pointer', owner='frame')]
        add('reuse_' + proof + '_new_generation', document)
        if proof != 'transparent_replacement':
            document = deepcopy(document)
            document['witness']['actions'].append(action('assign', alias='pointer', owner='frame'))
            add('old_alias_stale_after_' + proof, document, 'SL_STALE_ALIAS')
    document = simple_alive()
    document['witness']['initial']['objects'][0]['implicit_set'] = 'implicit'
    document['witness']['cell_models'][2]['implicit_eligible'] = False
    document['witness']['cell_models'].append(dict(id='inside_nonimplicit', parent='m', repeat=1,
        role='member', implicit_eligible=True, union_selected=None))
    document['witness']['initial']['cells'][2].update(completed=0, ordinal=0)
    add('implicit_parent_does_not_create_nonimplicit_member_or_descendant', document)
    document = deepcopy(document)
    document['witness']['cell_models'][2]['repeat'] = 10**12
    add('huge_array_remains_symbolic_nonimplicit_elements_absent', document)
    document = deepcopy(document)
    document['witness']['cell_models'][2]['repeat'] = 0
    add('zero_elements_create_no_cell_instances', document)
    document = base()
    document['witness']['cell_models'][1]['parent'] = 'm'
    document['witness']['cell_models'][2]['parent'] = 'v'
    add('cell_parent_cycle', document, 'SL_CELL_CYCLE')
    document = base()
    document['witness']['cell_models'][2]['repeat'] = 2**64 - 1
    document['witness']['cell_models'].append(dict(id='overflow', parent='m', repeat=2, role='element',
                                                 implicit_eligible=True, union_selected=None))
    add('symbolic_count_overflow', document, 'SL_CELL_COUNT')
    for site, mode in enumerate(['normal.no_journal', 'normal.with_journal', 'unwind.no_journal',
                                 'unwind.with_journal', 'outward_unwind.no_journal', 'outward_unwind.with_journal']):
        document = base()
        document['witness']['actions'] = []
        add('literal_exit_declaration_' + mode, document)
    document = base()
    document['contract']['scope_exits'][4]['location'] = {'kind': 'pre_op', 'block': 0, 'index': 0}
    add('outward_none_not_handler_pre', document, 'SL_EXIT_LOCATOR')
    document = base()
    document['contract']['scope_exits'][0]['journal'] = 101
    add('no_journal_mode_cannot_hide_j', document, 'SL_EXIT_JOURNAL')
    document = base()
    document['contract']['scope_exits'][2]['exception'] = 100
    add('scope_and_exception_not_same_ssa', document, 'SL_EXIT_SSA_TYPE')
    document = failure()
    document['witness']['actions'][-2]['generation'] = 2
    add('stale_source_scope_generation', document, 'SL_SCOPE_GENERATION')
    document = base()
    document['witness']['actions'] = [action('nonlocal_exit', owner='frame')]
    add('nonlocal_cannot_skip_live_journal', document, 'SL_NONLOCAL_CLEANUP')
    document = simple_alive()
    document['witness']['actions'] = [action('frontier', id='front', owner='frame', generation=1, candidates=[20, 10]),
        action('select', frontier='front', index=0, ticket='effect'), action('suspend', frontier='front'),
        action('resume', frontier='front', owner='frame', generation=1),
        action('commit_event', frontier='front', ticket='effect'),
        action('select', frontier='front', index=1, ticket='next'),
        action('commit_event', frontier='front', ticket='next')]
    add('frontier_resume_preserves_static_vector_cursor', document)
    document = deepcopy(document)
    document['witness']['actions'].insert(5, action('commit_event', frontier='front', ticket='effect'))
    add('completed_effect_cannot_replay', document, 'SL_EFFECT_REPLAY')
    document = simple_alive()
    document['witness']['actions'] = [action('frontier', id='front', owner='frame', generation=1, candidates=[20]),
        action('select', frontier='front', index=0, ticket='effect'), action('cancel', frontier='front'),
        action('finish_cancel', frontier='front')]
    add('cancel_waits_for_original_pending_effect', document, 'SL_CANCEL_PENDING')
    document = base()
    document['contract']['program_requirements'][0]['program']['namespace'] = 'Function'
    add('namespace_not_numeric_id', document, 'SL_NAMESPACE')
    document = base()
    document['contract']['end_sites'][0]['id'] = True
    add('bool_not_id', document, 'SL_SHAPE')
    document = base()
    document['witness']['runtime_authority'] = True
    add('unbound_witness_cannot_request_runtime_authority', document, 'SL_SHAPE')
    document = simple_alive()
    view = deepcopy(base()['witness']['initial']['views'][0])
    view.update(mode='destroy', state='unbound', journal=None)
    document['witness']['initial']['views'] = [view]
    document['witness']['actions'] = [
        action('claim_destroy', alias='pointer', end_site=0, claim='claim', owner='frame', preflight='accepted'),
        action('bind_destroy', view='view', claim='claim', journal='destroy_j'),
        action('cleanup', view='view', journal='destroy_j', cell='m', count=1),
        action('cleanup', view='view', journal='destroy_j', cell='v', count=1),
        action('complete_view', view='view', journal='destroy_j', receipt='destroyed'),
        action('end_object', alias='pointer', owner='frame', end_site=1, next_allocation_generation=None)]
    add('destruction_claim_bind_reverse_cleanup_then_retirement', document)
    duplicate = deepcopy(document)
    duplicate['witness']['actions'].insert(2, action('end_object', alias='pointer', owner='frame',
                                                   end_site=0, next_allocation_generation=None))
    add('ordinary_end_cannot_claim_again_at_retirement', duplicate, 'SL_END_DUPLICATE_CLAIM')
    premature = deepcopy(document)
    premature['witness']['actions'] = premature['witness']['actions'][:2] + [premature['witness']['actions'][-1]]
    add('retirement_requires_original_completion', premature, 'SL_END_RECEIPT')
    wrong_owner = deepcopy(document)
    wrong_owner['witness']['initial']['frames'].append(dict(id='recursive', context='c',
        function=external('Function', 0), generation=2, thread='thread'))
    wrong_owner['witness']['initial']['views'][0]['owner'] = 'recursive'
    add('claim_binding_cannot_change_activation', wrong_owner, 'SL_CLAIM')
    document = failure()
    document['witness']['actions'] = document['witness']['actions'][:1] + [
        action('complete_view', view='nv_view', journal='nv_j1', receipt='fake_normal')]
    add('partial_failure_cannot_complete_normally', document, 'SL_VIEW_OUTCOME')
    document = base()
    document['witness']['initial']['views'][0]['program'] = 'nv'
    document['witness']['initial']['cells'][2].update(completed=0, ordinal=0)
    document['witness']['actions'] = [action('complete_view', view='view', journal='j0', receipt='incomplete')]
    add('nv_construct_completion_checks_original_cells', document, 'SL_INITIALIZATION_INCOMPLETE')
    document = failure()
    document['witness']['actions'] = document['witness']['actions'][:1] + [
        action('publish', view='view', journal='j0', receipt='parent_too_soon')]
    add('parent_publication_waits_for_child_rejoin', document, 'SL_PENDING_CHILD')
    document = failure()
    document['witness']['actions'][-2] = exit_action(3, journal='j0', exception='E')
    add('scope_projection_cannot_use_consumed_j0', document, 'SL_STALE_JOURNAL')
    document = base()
    document['witness']['actions'] = [exit_action(1, journal='j0')]
    add('normal_with_j_requires_unimplemented_actual_outcome_adapter', document,
        'SL_EXIT_NORMAL_JOURNAL_OUTCOME', 'unavailable')
    for site, outward in [(2, False), (4, True)]:
        document = simple_alive()
        scope = deepcopy(base()['witness']['initial']['scopes'][0])
        scope.update(view=None, object=None, pending='original_failed_call', exception='original_E')
        document['witness']['initial']['scopes'] = [scope]
        document['witness']['actions'] = [exit_action(site, exception=None if outward else 'original_E',
            propagation='original_E' if outward else None), action('nonlocal_exit', owner='frame')]
        add('physical_failure_before_j_' + str(site), document)
    document = base()
    document['witness']['initial']['objects'][0]['implicit_set'] = 'implicit'
    document['witness']['cell_models'][2].update(role='union_member', union_selected=None)
    add('implicit_union_requires_actual_selection', document, 'SL_IMPLICIT_UNION_SELECTION', 'unavailable')
    document = deepcopy(document)
    document['witness']['cell_models'][1].update(role='union_member', union_selected=True)
    document['witness']['cell_models'][2]['union_selected'] = True
    add('implicit_union_cannot_create_two_arms', document, 'SL_UNION_SELECTION')
    document = simple_alive()
    document['witness']['actions'] = [action('frontier', id='front', owner='frame', generation=1, candidates=[20]),
        action('cancel', frontier='front'), action('finish_cancel', frontier='front')]
    add('cancellation_finishes_only_without_pending_cleanup', document)
    document = deepcopy(document)
    document['witness']['actions'].append(action('select', frontier='front', index=0, ticket='after_cancel'))
    add('cancelled_frontier_cannot_restart', document, 'SL_FRONTIER_CURSOR')
    document = base()
    document['witness']['actions'] = [action('frontier', id='front', owner='frame', generation=1, candidates=[]),
        action('cancel', frontier='front'), action('finish_cancel', frontier='front')]
    add('cancel_cannot_skip_live_journal', document, 'SL_CANCEL_CLEANUP')
    document = simple_alive()
    document['witness']['actions'] = [action('trap', code='exact_trap'), action('assign', alias='pointer', owner='frame')]
    add('trap_has_no_continuation', document, 'SL_AFTER_TRAP')
    document = base()
    document['contract']['program_requirements'][1]['program'] = external('Journal', 0)
    add('complete_nv_cannot_alias_original_program', document, 'SL_PROGRAM_IDENTITY')
    document = simple_alive()
    document['witness']['actions'] = [action('frontier', id='front', owner='frame', generation=1, candidates=[20]),
        action('select', frontier='front', index=0, ticket='pending'), action('frame_exit', frame='frame')]
    add('activation_exit_cannot_drop_pending_frontier', document, 'SL_FRONTIER_EXIT')
    document = deepcopy(document)
    document['witness']['actions'][-1] = action('nonlocal_exit', owner='frame')
    add('nonlocal_exit_cannot_drop_pending_frontier', document, 'SL_FRONTIER_EXIT')
    return result


class SourceLifetimeTests(unittest.TestCase):
    def test_authored_fixtures(self):
        stored = json.loads((FIXTURES / 'cases.json').read_text())
        self.assertEqual(stored['format'], 'authored-source-lifetime-cases')
        self.assertGreaterEqual(len(stored['cases']), 65)
        self.assertEqual(stored['cases'], cases())
        for case in stored['cases']:
            with self.subTest(case=case['name']):
                expected = case['expected']
                if expected['kind'] == 'static':
                    result = verify(case['document'], budget=ledger())
                    self.assertFalse(result.runtime_authority)
                    self.assertFalse(result.source_fact_authority)
                    self.assertEqual(result.binding, 'unbound')
                else:
                    with self.assertRaises(ContractError) as caught:
                        verify(case['document'], budget=ledger())
                    self.assertEqual(caught.exception.code, expected['code'])
                    self.assertEqual(caught.exception.kind, expected['kind'])

    def checked_model(self, document):
        budget = ledger()
        preflight(document, budget)
        schema = json.loads(SCHEMA.read_text())
        shape(schema, document, schema['$defs'], budget)
        return Verifier(document, budget)

    def test_two_objects_same_cell_template_have_independent_completion(self):
        document = failure()
        state = document['witness']['initial']
        other = deepcopy(state['objects'][0])
        other.update(id='unrelated', offset=32, complete_owner='unrelated')
        state['objects'].append(other)
        for cell in list(state['cells']):
            second = deepcopy(cell)
            second['owner'] = 'unrelated'
            state['cells'].append(second)
        model = self.checked_model(document)
        result = model.run()
        self.assertFalse(result.runtime_authority)
        self.assertEqual(model.cells['object', 'v']['completed'], 0)
        self.assertEqual(model.cells['unrelated', 'v']['completed'], 1)
        self.assertEqual(model.cells['unrelated', 'm']['completed'], 1)
        self.assertEqual(model.objects['unrelated']['state'], 'constructing')

    def test_base_nonvirtual_retirement_preserves_complete_owner_virtual_cells(self):
        document = simple_alive()
        state, contract = document['witness']['initial'], document['contract']
        binding = deepcopy(contract['object_bindings'][0])
        binding.update(id='base_binding', value=3, source_class=external('Nominal', 13), role='base')
        contract['object_bindings'].append(binding)
        contract['program_requirements'][1]['source_class'] = external('Nominal', 13)
        base_object = deepcopy(state['objects'][0])
        base_object.update(id='base_object', binding='base_binding', parent='object', parent_cell='v')
        state['objects'].append(base_object)
        pointer = deepcopy(state['aliases'][0])
        pointer.update(id='base_pointer', binding='base_binding', object='base_object')
        state['aliases'].append(pointer)
        view = deepcopy(base()['witness']['initial']['views'][0])
        view.update(object='base_object', program='nv', mode='destroy', state='unbound', journal=None)
        state['views'] = [view]
        for identifier in [0, 1]:
            end = deepcopy(contract['end_sites'][identifier])
            end.update(id=10 + identifier, binding='base_binding')
            if identifier == 1:
                end['effect']['program'] = 'nv'
            contract['end_sites'].append(end)
        document['witness']['actions'] = [
            action('claim_destroy', alias='base_pointer', end_site=10, claim='base_claim', owner='frame', preflight='accepted'),
            action('bind_destroy', view='view', claim='base_claim', journal='base_j'),
            action('cleanup', view='view', journal='base_j', cell='m', count=1),
            action('complete_view', view='view', journal='base_j', receipt='base_finished'),
            action('end_object', alias='base_pointer', owner='frame', end_site=11, next_allocation_generation=None)]
        model = self.checked_model(document)
        self.assertFalse(model.run().runtime_authority)
        self.assertEqual(model.objects['base_object']['state'], 'ended')
        self.assertEqual(model.objects['object']['state'], 'alive')
        self.assertEqual(model.cells['object', 'v']['completed'], 1)
        self.assertEqual(model.cells['object', 'm']['completed'], 0)

    def test_implicit_set_and_huge_extent_are_symbolic(self):
        document = next(c['document'] for c in cases() if c['name'].startswith('huge_array'))
        result = verify(document, budget=ledger(max_work=1000000))
        created = dict(result.implicit_created[0][1])
        self.assertEqual(created['root'], 1)
        self.assertEqual(created['m'], 0)
        self.assertEqual(created['inside_nonimplicit'], 0)
        self.assertLess(len(created), 10)

    def test_schema_resources_wrong_ledger_cycles_and_immutability(self):
        for policy in [dict(max_work=0), dict(max_edges=0), dict(max_copied_bytes=0)]:
            with self.assertRaises(source_api().SourceDataError):
                verify(base(), budget=ledger(**policy))
        with self.assertRaises(ContractError):
            verify(base(), budget=object())
        cyclic = base()
        cyclic['witness']['actions'].append(cyclic)
        with self.assertRaisesRegex(ContractError, 'SL_INPUT_CYCLE'):
            verify(cyclic, budget=ledger())
        result = verify(base(), budget=ledger())
        with self.assertRaises(FrozenInstanceError):
            result.runtime_authority = True


if __name__ == '__main__':
    unittest.main()
