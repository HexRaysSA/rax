"""Observable EH selectors, local handler identity and admitted ABI RTTI keys."""
from copy import deepcopy
import json
import os
import subprocess
import sys
import unittest

from common import ROOT, Reject, SPEC
from candidate.context import RootContext
from candidate.machine import Machine
from candidate.type_system import ref
from candidate.values import Value
from candidate.verify import verify
from test_candidate import block, decl, operation
from test_candidate_context import roots
from test_candidate_eh_bindings import function, signature
from candidate_fixtures import declared_abi_source, seal_declared_abi


def package(handler_id=42, selector=7):
    candidate = roots()
    candidate[1]['types'].append(signature(302, [7], [17]))
    invoke = {'op': 'invoke', 'target': {'kind': 'direct', 'function': ref(2), 'signature': ref(302)},
        'operands': [0], 'normal': {'target': 1, 'results': [decl(1, 17)]},
        'unwind': {'target': 2, 'exception': decl(2, 7)}, 'region': 0}
    candidate[3]['functions'] += [function(1, 302, [decl(0, 7)], [block(0, [], invoke),
        block(1, [], {'op': 'return', 'values': [1]}),
        block(2, [operation('landingpad', [decl(3, 17)], [2], region=0)], {'op': 'return', 'values': [3]})]),
        function(2, 302, [decl(0, 7)], [block(0, [], {'op': 'throw', 'exception': 0, 'region': None})])]
    candidate[8]['functions'] = [{'function': 1, 'actions': [], 'regions': [
        {'id': 0, 'parent': None, 'blocks': [0], 'exit_actions': [], 'escape': 'continue', 'handlers': [
            {'id': handler_id, 'selector': selector, 'kind': 'typed', 'nominal': {'some': ref(1)},
             'entry': 2, 'cleanup_actions': [], 'catch_copy': None}]}]}]
    return candidate


def admit(candidate):
    context = RootContext(candidate)
    context.verify_abi()
    context.verify_execution()
    return context


def nested(candidate, nominal, selector=7):
    regions = candidate[8]['functions'][0]['regions']
    second = deepcopy(regions[0])
    second.update(id=1, parent={'some': 0})
    second['handlers'][0].update(id=73, nominal={'some': nominal}, selector=selector)
    regions.append(second)
    candidate[3]['functions'][1]['blocks'][0]['term']['region'] = 1
    return second


def add_invalid_root_types(candidate):
    # The owner's actual producer runs with its own imports in another process.
    script = 'import json;from candidate_fixtures import build;print(json.dumps(build(all_kinds=True)))'
    document, evidence = json.loads(subprocess.check_output([sys.executable, '-c', script],
        cwd=ROOT / 'tools/smir-abi', env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, text=True))
    by_id = {item['id']: item for item in document['types']}
    layouts = {item['id']: item for item in document['layouts']}
    selected = {item['kind']: item['id'] for item in document['types']
                if item['domain'] == 0 and item['kind'] in {'void', 'reference', 'array'}}
    selected['function'] = 12
    wanted, pending = {1, 12}, list(selected.values())
    while pending:
        identity = pending.pop()
        if identity in wanted:
            continue
        wanted.add(identity)
        item = by_id[identity]
        pending += [child['id'] for child in item['elements'] if child['id'] not in wanted]
        if item['layout'] is not None:
            layout = layouts[item['layout']['some']]
            pending += [field['type']['id'] for field in layout['fields'] if field['type']['id'] not in wanted]
    candidate[10]['types'] = [item for item in document['types'] if item['id'] in wanted]
    layout_ids = {item['layout']['some'] for item in candidate[10]['types'] if item['layout'] is not None}
    candidate[10]['layouts'] = [item for item in document['layouts'] if item['id'] in layout_ids]
    candidate[1]['types'] = evidence['execution_graph'] + [signature(302, [7], [17])]
    candidate[1]['types'].sort(key=lambda item: item['id'])
    candidate[1]['memory_layouts'] = list(evidence['memory_layouts'].values())
    return selected


class CandidateSelectorTests(unittest.TestCase):
    def test_admitted_top_cv_equivalence_preserves_pointee_cv_distinction(self):
        candidate = package()
        const = deepcopy(candidate[10]['types'][0])
        const.update(id=100, qualifiers=['const'], layout={'some': 100})
        layout = deepcopy(candidate[10]['layouts'][0])
        layout.update(id=100, type=ref(100))
        candidate[10]['types'].append(const)
        candidate[10]['layouts'].append(layout)
        candidate[10] = seal_declared_abi(candidate[10])
        second = nested(candidate, ref(100))
        admit(candidate)  # int and const int share the RTTI selector.
        actual, _ = declared_abi_source()
        for identifier, pointee in [(101, 1), (102, 100)]:
            pointer = deepcopy(next(item for item in actual['types'] if item['id'] == 4))
            pointer.update(id=identifier, elements=[ref(pointee)], layout={'some': identifier})
            geometry = deepcopy(next(item for item in actual['layouts'] if item['id'] == 4))
            geometry.update(id=identifier, type=ref(identifier))
            candidate[10]['types'].append(pointer)
            candidate[10]['layouts'].append(geometry)
        candidate[10] = seal_declared_abi(candidate[10])
        candidate[8]['functions'][0]['regions'][0]['handlers'][0]['nominal'] = {'some': ref(101)}
        second['handlers'][0]['nominal'] = {'some': ref(102)}
        with self.assertRaisesRegex(Reject, 'handler_selector_type'):
            admit(candidate)  # int* and const int* are distinct despite data_ptr execution.
        second['handlers'][0]['selector'] = 8
        admit(candidate)

    def test_consumer_nominal_alias_uses_verified_expected_type_not_private_id(self):
        candidate = package()
        candidate[2]['manifest']['dependencies'] = [{'slot': 0,
            'key': {'namespace': 'example', 'name': 'types', 'abi_major': 1, 'abi_minor': 0},
            'minimum_minor': 0, 'maximum_minor': None, 'site': candidate[10]['identity'], 'declarations': [
                {'id': 9, 'kind': 'nominal', 'symbol_kind': 'none', 'source_linkage': 'none', 'namespace': 'example', 'name': 'int_type',
                 'execution': None, 'nominal': {'some': ref(1)}, 'abi_signature': None, 'weak': False}]}]
        second = nested(candidate, ref(9, 0))
        context = admit(candidate)
        self.assertTrue(context.component_result()['requires_runtime_link_admission'])
        second['handlers'][0]['selector'] = 8
        with self.assertRaisesRegex(Reject, 'handler_selector_type'):
            admit(candidate)

    def test_local_handler_rename_preserves_selector_but_selector_change_is_observable(self):
        for identity, selector in [(42, 7), (73, 7), (42, 8)]:
            context = admit(package(identity, selector))
            machine = Machine(context.execution_checked)
            exception = machine.handle(ref(7), {'nominal': ('self', 1)})
            machine.start(1, [exception])
            self.assertEqual(machine.run()['values'][0].data, selector)
            self.assertEqual(machine.selected_handlers[1], identity)

    def test_repeated_types_across_regions_and_missing_admitted_comparator(self):
        candidate = package()
        eh = candidate[8]['functions'][0]
        second = deepcopy(eh['regions'][0])
        second.update(id=1, parent={'some': 0})
        second['handlers'][0]['id'] = 73
        eh['regions'].append(second)
        candidate[3]['functions'][1]['blocks'][0]['term']['region'] = 1
        context = admit(candidate)
        dependencies = deepcopy(context.execution_checked.dependencies)
        dependencies.nominal_equal = None
        with self.assertRaisesRegex(Reject, 'handler_nominal_comparator'):
            verify(context.sections[1], context.sections[3], context.sections[8], dependencies)
        second['handlers'][0]['selector'] = 8
        with self.assertRaisesRegex(Reject, 'handler_selector_type'):
            admit(candidate)
        second['handlers'][0].update(selector=7, kind='catch_all', nominal=None)
        with self.assertRaisesRegex(Reject, 'handler_selector_type'):
            admit(candidate)
        second['handlers'][0]['selector'] = 8
        admit(candidate)

    def test_single_invalid_rtti_root_rejects_after_actual_abi_verification(self):
        candidate = package()
        invalid = add_invalid_root_types(candidate)
        for kind, identifier in invalid.items():
            with self.subTest(kind=kind):
                candidate[8]['functions'][0]['regions'][0]['handlers'][0]['nominal'] = {'some': ref(identifier)}
                context = RootContext(candidate)
                context.verify_abi()  # Establishes that the negative is catch normalization.
                with self.assertRaisesRegex(Reject, 'handler_nominal_type.*ABI_CC_CATCH_NORMALIZATION'):
                    context.verify_execution()

    def test_selector_range_and_cleanup_zero(self):
        for selector in [0, 2**31, 2**32 - 1]:
            with self.assertRaisesRegex(Reject, 'handler_selector_range'):
                admit(package(selector=selector))
        candidate = package()
        fn = candidate[3]['functions'][1]
        fn['blocks'] = [block(0, [operation('landingpad', [decl(3, 17)], [0], region=0)],
                              {'op': 'return', 'values': [3]})]
        candidate[3]['functions'].pop()  # This pure cleanup selector view has no invoke.
        candidate[8]['functions'][0]['regions'][0]['handlers'] = []
        context = admit(candidate)
        machine = Machine(context.execution_checked)
        exception = machine.handle(ref(7), {'nominal': ('self', 1)})
        machine.start(1, [exception])
        self.assertEqual(machine.run()['values'][0].data, 0)


if __name__ == '__main__':
    unittest.main()
