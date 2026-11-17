"""Draft scalar Raw8 atomic reference witnesses, not parallel qualification."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path
import sys
import unittest

from atomic_bytes.contract import FAILURE, MODE, SUCCESS, cases, observe, roots
from atomic_bytes.generate import FOLDER, codec, product
from candidate.context import RootContext
from candidate.function_address_contract import source_roots
from candidate.machine import Machine
from candidate.memory import GuestFault
from candidate.raw import Raw, Span, concat
from candidate.type_system import ref
from candidate.values import Pointer, Value
from candidate.verify import verify
from common import Reject
from test_candidate import block, decl, operation

ROOT = Path(__file__).resolve().parents[3]


def start(machine, values):
    machine.start(0, values)
    return machine.run()


def raw_value(raw):
    return Value(ref(17), 'concrete', raw)


def pointer_value(pointer):
    return Value(ref(7), 'concrete', pointer)


def shadows(machine):
    """Both spans refer to actual independent guest allocation generations."""
    a = machine.memory.allocate(1, 1)
    b = machine.memory.allocate(1, 1)
    old = Raw(8, 1, 0x80, (Span(0, 4, a, 16),), 0x40)
    desired = Raw(8, 1, 0x10, (Span(0, 4, b, 16),), 0x20)
    return a, b, old, desired


def cas_writeback(weak=False):
    document = roots('cmpxchg', weak=weak)
    document[0]['types'][15].update(params=[ref(7), ref(7), ref(17)],
        results=[ref(0)], param_noundef=[False]*3, result_noundef=[False])
    fn = document[1]['functions'][0]
    fn['params'] = [decl(0, 7), decl(1, 7), decl(2, 17)]
    storage = deepcopy(fn['blocks'][0]['ops'][0]['storage'])
    fn['blocks'] = [block(0, [
        operation('load', [decl(3, 17)], [1], storage=storage,
                  mode=dict(MODE, order='none')),
        operation('cmpxchg', [decl(4, 17), decl(5, 0)], [0, 3, 2],
                  storage=storage, mode=dict(MODE, failure_order='relaxed'), weak=weak)],
        dict(op='cbranch', condition=5, true=1, false=2)),
        block(1, [], dict(op='return', values=[5])),
        block(2, [operation('store', [], [1, 4], storage=storage,
                           mode=dict(MODE, order='none'))], dict(op='return', values=[5]))]
    return Machine(verify(*document))


def original_bound_numeric(action='add'):
    """Actual full original ABI and body verification, under the existing site.

    This validates a separately declared Int8 physical binding for a Raw8 source
    nominal; it does not claim new epoch2 source-expression classification.
    """
    document = source_roots()
    document[1]['types'] += [dict(id=2200, kind='raw', bits=8),
        dict(id=2201, kind='int', bits=8), dict(id=2202, kind='data_ptr', space='guest_data'),
        dict(id=2203, kind='function', params=[ref(2202), ref(2200)], results=[ref(2200)],
             param_noundef=[False, False], result_noundef=[False], cc='portable', variadic=False)]
    for layout, typ in ((2200, 2200), (2201, 2201)):
        document[1]['memory_layouts'].append(dict(id=layout, type=ref(typ), size=1,
            access_bytes=1, alignment=1, fields=[], element=None, stride=0))
    nominal = dict(id=2200, domain=0,
        identity=dict(language='cpp23', linkage='builtin', entity='unsigned char',
                      definition='0'*64, library=None, unit=None),
        kind='scalar', qualifiers=[], bits=8, signed=False, elements=[], extent=None,
        representation='value', execution={'some': ref(2200)}, layout={'some': 2200},
        flags=['complete', 'trivial_copy', 'trivial_destroy'], methods=[], enumerators=[], record_input=None)
    document[10]['types'].append(nominal)
    document[10]['layouts'].append(dict(id=2200, type=ref(2200), size=1, align=1,
        data_size=1, nonvirtual_size=1, nonvirtual_align=1, fields=[], bases=[], vptrs=[]))
    for binding, layout in ((2200, 2200), (2201, 2201)):
        document[10]['storage_bindings'].append(dict(id=binding, nominal=ref(2200),
            execution_layout=ref(layout), kind='object_bytes', view_offset_bits=0,
            view_width_bits=8, required_alignment=1, access_bytes=1,
            fragments=[dict(source_path=[], source_offset_bits=0, execution_offset_bits=0,
                            width_bits=8, role='value')]))
    local = roots(action, numeric=True)[1]['functions'][0]
    remap = {1: 2201, 7: 2202, 17: 2200, 15: 2203}
    def mapped(value):
        if isinstance(value, dict):
            if set(value) == {'module', 'id'} and value['module'] == {'kind': 'self'}:
                return ref(remap.get(value['id'], value['id']))
            return {k: mapped(v) for k, v in value.items()}
        return [mapped(v) for v in value] if isinstance(value, list) else value
    fn = mapped(local)
    fn['id'] = 1
    atom = fn['blocks'][0]['ops'][1]
    atom['storage'].update(layout=ref(2201), nominal={'some': ref(2200)},
                           abi_binding={'some': ref(2201)})
    document[3]['functions'].append(fn)
    for table in ('types', 'memory_layouts'):
        document[1][table].sort(key=lambda row: row['id'])
    for table in ('types', 'layouts', 'storage_bindings'):
        document[10][table].sort(key=lambda row: row['id'])
    sys.path.insert(0, str(ROOT/'tools/smir-abi'))
    try:
        module = importlib.import_module('nominal')
        if Path(module.__file__).resolve() != (ROOT/'tools/smir-abi/nominal.py').resolve():
            raise RuntimeError('unexpected nominal implementation')
        nominal['identity']['definition'] = module.NominalGraph(document[10], 'atomic-byte').fingerprint(ref(2200))
    finally:
        sys.path.pop(0)
    context = RootContext(document)
    context.verify_abi()
    admitted = context.verify_execution()
    return context, Machine(admitted), atom


class ScalarRaw8AtomicTests(unittest.TestCase):
    def test_independent_corpus_static_boundaries_and_canonical_bytes(self):
        authored = cases()
        self.assertEqual(len(authored), 67)
        self.assertEqual(sum(row['expected'] == 'ok' for row in authored), 48)
        for row in authored:
            with self.subTest(case=row['id']):
                self.assertEqual(observe(row['roots']), row['expected'])
        raw = (FOLDER/'cases.json').read_bytes()
        self.assertEqual(product(), raw)
        encoder = codec()
        for row in json.loads(raw)['cases']:
            wire = bytes.fromhex(row['encoded_hex'])
            self.assertEqual(hashlib.sha256(wire).hexdigest(), row['sha256'])
            decoded = encoder.decode(wire)
            self.assertEqual(encoder.encode(decoded.roots), wire)

    def test_exchange_returns_actual_old_and_stores_distinct_desired_shadow(self):
        for order in SUCCESS:
            for volatile in (False, True):
                document = roots(order=order)
                document[1]['functions'][0]['blocks'][0]['ops'][0]['mode']['volatile'] = volatile
                machine = Machine(verify(*document))
                target = machine.memory.allocate(1, 1)
                a, b, old, desired = shadows(machine)
                self.assertNotEqual(a.origin, b.origin)
                self.assertEqual(old.bits, desired.bits)
                machine.memory.raw_store(target, old)
                outcome = start(machine, [pointer_value(target), raw_value(desired)])
                self.assertEqual(outcome['values'][0], raw_value(old))
                self.assertEqual(machine.memory.raw_load(target, 1), desired)
                self.assertEqual(machine.memory.effects, [('atomic_rmw', order, 'none', volatile)])
                self.assertEqual(machine.memory.exposed, set())

    def test_eight_actual_exchanges_reconstruct_only_ordered_single_origin(self):
        for mixed in (False, True):
            document = roots()
            fn = document[1]['functions'][0]
            params = [7]*8+[17]*8
            document[0]['types'][15].update(params=[ref(t) for t in params], param_noundef=[False]*16)
            fn['params'] = [decl(i, t) for i, t in enumerate(params)]
            template = fn['blocks'][0]['ops'][0]
            fn['blocks'][0]['ops'] = [dict(deepcopy(template), results=[decl(100+i, 17)], operands=[i, 8+i]) for i in range(8)]
            fn['blocks'][0]['term']['values'] = [107]
            machine = Machine(verify(*document))
            target = machine.memory.allocate(8, 1)
            first = machine.memory.allocate(1, 1)
            second = machine.memory.allocate(1, 1)
            raw = Raw.pointer(first)
            parts = [Raw.pointer(second if mixed and i == 7 else first).slice(8*i, 8) for i in range(8)]
            machine.memory.raw_store(target, Raw.integer(64, 0))
            arguments = [pointer_value(replace(target, address=target.address+i)) for i in range(8)]
            arguments += [raw_value(part) for part in parts]
            self.assertEqual(start(machine, arguments)['kind'], 'return')
            recovered = machine.memory.raw_load(target, 8)
            self.assertEqual(recovered.bits, raw.bits)
            self.assertEqual(recovered.as_pointer()['identity'], None if mixed else first.origin)
            self.assertEqual(len(machine.memory.effects), 8)
            if not mixed:
                machine.memory.end_lifetime(first)
                with self.assertRaisesRegex(GuestFault, 'memory_lifetime'):
                    machine.memory.guard(first, 1)

    def test_all_fifteen_cas_pairs_and_weak_strong_preserve_actual_origins(self):
        for order in SUCCESS:
            for failure in FAILURE:
                for weak in (False, True):
                    for matched in (False, True):
                        machine = Machine(verify(*roots('cmpxchg', order=order, failure=failure, weak=weak)))
                        target = machine.memory.allocate(1, 1)
                        _, b, old, desired = shadows(machine)
                        expected = Raw(8, 1 if matched else 2, 0, (), 0)
                        machine.memory.raw_store(target, old)
                        machine.start(0, [pointer_value(target), raw_value(expected), raw_value(desired)])
                        self.assertEqual(machine.run(fuel=2)['kind'], 'resource')
                        frame = machine.stack[-1]
                        self.assertEqual(frame.values[10], raw_value(old))
                        self.assertEqual(frame.values[11].data, int(matched))
                        self.assertEqual(machine.memory.raw_load(target, 1), desired if matched else old)
                        self.assertEqual(machine.memory.effects, [('cmpxchg', order, failure, False)])
                        self.assertEqual(machine.run()['values'][0], raw_value(old))
                        self.assertEqual(len(machine.memory.effects), 1)

    def test_cas_comparison_refines_masks_only_without_transplanting_expected_origin(self):
        machine = Machine(verify(*roots('cmpxchg')))
        target = machine.memory.allocate(1, 1)
        _, b, old, desired = shadows(machine)
        separate_expected = machine.memory.allocate(1, 1)
        expected = Raw(8, 0xc1, 0x80, (Span(0, 4, separate_expected, 16),), 0x40)
        machine.memory.raw_store(target, old)
        self.assertEqual(start(machine, [pointer_value(target), raw_value(expected), raw_value(desired)])['values'][0], raw_value(old))
        actual = machine.memory.raw_load(target, 1)
        self.assertEqual(actual, desired)
        self.assertEqual(actual.origins[0].pointer.origin, b.origin)
        self.assertNotEqual(actual.origins[0].pointer.origin, expected.origins[0].pointer.origin)

    def test_write_intent_bounds_alignment_lifetime_fault_before_atomic_read(self):
        for kind in ('exchange', 'cmpxchg'):
            for fault in ('memory_permission', 'memory_bounds', 'memory_alignment', 'memory_lifetime', 'ub_inrange_access'):
                document = roots(kind)
                if fault == 'memory_alignment':
                    document[1]['functions'][0]['blocks'][0]['ops'][0]['mode']['alignment'] = 2
                machine = Machine(verify(*document))
                base = machine.memory.allocate(2, 1)
                pointer = replace(base, address=base.address+(2 if fault == 'memory_bounds' else 1 if fault == 'memory_alignment' else 0))
                if fault == 'ub_inrange_access':
                    pointer = machine.memory.offset(base, 0, False, False, False,
                                                    inrange={'lower': 0, 'upper': 0})
                machine.memory.raw_store(base, Raw.integer(16, 0x2211))
                if fault == 'memory_permission':
                    machine.memory.objects[base.origin]['mutable'] = False
                if fault == 'memory_lifetime':
                    machine.memory.end_lifetime(base)
                before = list(machine.memory.objects[base.origin]['bytes'])
                reads, load = [], machine.memory.load
                def observed(*args):
                    reads.append(1)
                    return load(*args)
                machine.memory.load = observed
                args = [pointer_value(pointer), raw_value(Raw.integer(8, 0x11))]
                if kind == 'cmpxchg':
                    args.append(raw_value(Raw.integer(8, 0x33)))
                self.assertEqual(start(machine, args)['reason'], fault)
                self.assertEqual(reads, [])
                self.assertEqual(machine.memory.effects, [])
                self.assertEqual(machine.memory.objects[base.origin]['bytes'], before)

    def test_failure_writeback_has_distinct_committed_frontier_and_no_fuel_replay(self):
        machine = cas_writeback(weak=True)
        target, expected = machine.memory.allocate(1, 1), machine.memory.allocate(1, 1)
        _, _, old, desired = shadows(machine)
        machine.memory.raw_store(target, old)
        machine.memory.raw_store(expected, Raw.integer(8, 2))
        machine.start(0, [pointer_value(target), pointer_value(expected), raw_value(desired)])
        self.assertEqual(machine.run(fuel=3)['kind'], 'resource')
        self.assertEqual(machine.stack[-1].position, 2)
        self.assertEqual(machine.stack[-1].values[4], raw_value(old))
        self.assertEqual(machine.memory.raw_load(expected, 1), Raw.integer(8, 2))
        self.assertEqual(machine.run(fuel=2)['kind'], 'resource')
        self.assertEqual((machine.stack[-1].block, machine.stack[-1].position), (2, 0))
        self.assertEqual(machine.run()['values'][0].data, 0)
        self.assertEqual(machine.memory.raw_load(expected, 1), old)
        self.assertEqual(sum(row[0] == 'cmpxchg' for row in machine.memory.effects), 1)
        self.assertEqual(sum(row[0] == 'store' for row in machine.memory.effects), 1)

    def test_postcommit_writeback_fault_retains_atomic_effect_but_has_no_resume_api(self):
        machine = cas_writeback()
        target, expected = machine.memory.allocate(1, 1), machine.memory.allocate(1, 1)
        _, _, old, desired = shadows(machine)
        machine.memory.raw_store(target, old)
        machine.memory.raw_store(expected, Raw.integer(8, 2))
        machine.memory.objects[expected.origin]['mutable'] = False
        fault = start(machine, [pointer_value(target), pointer_value(expected), raw_value(desired)])
        self.assertEqual((fault['reason'], fault['block'], fault['operation']), ('memory_permission', 2, 0))
        self.assertEqual(machine.stack[-1].values[4], raw_value(old))
        self.assertEqual(machine.memory.raw_load(expected, 1), Raw.integer(8, 2))
        effects = list(machine.memory.effects)
        self.assertEqual(sum(row[0] == 'cmpxchg' for row in effects), 1)
        self.assertEqual(machine.run(), fault)
        self.assertEqual(machine.memory.effects, effects)

    def test_success_does_not_write_expected_and_allows_actual_alias(self):
        for alias in (False, True):
            machine = cas_writeback()
            target = machine.memory.allocate(1, 1)
            expected = target if alias else machine.memory.allocate(1, 1)
            _, _, old, desired = shadows(machine)
            machine.memory.raw_store(target, old)
            machine.memory.raw_store(expected, old)
            outcome = start(machine, [pointer_value(target), pointer_value(expected), raw_value(desired)])
            self.assertEqual(outcome['values'][0].data, 1)
            self.assertEqual(machine.memory.raw_load(expected, 1), desired if alias else old)
            self.assertFalse(any(row[0] == 'store' for row in machine.memory.effects))

    def test_numeric_rmw_checked_original_binding_discards_both_old_and_new_origins(self):
        for action, argument, result in [('add', 0, 1), ('sub', 0, 1), ('and', 255, 1), ('or', 0, 1), ('xor', 0, 1)]:
            context, machine, atom = original_bound_numeric(action)
            self.assertTrue(context.abi_checked)
            self.assertIsNotNone(context.execution_checked)
            self.assertEqual(context.abi_graph.value_mask(ref(2200)), b'\xff')
            self.assertEqual(atom['storage']['abi_binding'], {'some': ref(2201)})
            target = machine.memory.allocate(1, 1)
            pointee = machine.memory.allocate(1, 1)
            old = Raw.pointer(pointee).slice(16, 8)
            machine.memory.raw_store(target, old)
            argument_raw = Raw.pointer(pointee).slice(24, 8) if argument == 0 else Raw.integer(8, argument)
            machine.start(1, [Value(ref(2202), 'concrete', target), Value(ref(2200), 'concrete', argument_raw)])
            self.assertEqual(machine.run()['values'][0].data, Raw.integer(8, 1))
            self.assertEqual(machine.memory.raw_load(target, 1), Raw.integer(8, result))
            self.assertEqual(machine.memory.exposed, set())
            self.assertEqual(sum(row[0] == 'atomic_rmw' for row in machine.memory.effects), 1)

    def test_numeric_add_sub_wrap_without_signed_overflow_poison(self):
        for action, address, old_bits, new_bits in [('add', 0x100ff, 255, 0), ('sub', 0x20000, 0, 255)]:
            _, machine, _ = original_bound_numeric(action)
            target = machine.memory.allocate(1, 1)
            machine.memory.next_address = address
            pointee = machine.memory.allocate(1, 1)
            old = Raw.pointer(pointee).slice(0, 8)
            self.assertEqual(old.bits, old_bits)
            self.assertTrue(old.origins)
            machine.memory.raw_store(target, old)
            machine.start(1, [Value(ref(2202), 'concrete', target),
                              Value(ref(2200), 'concrete', Raw.integer(8, 1))])
            self.assertEqual(machine.run()['values'][0].data, Raw.integer(8, old_bits))
            self.assertEqual(machine.memory.raw_load(target, 1), Raw.integer(8, new_bits))

    def test_numeric_storage_rejects_raw_binding_reuse_and_raw_result(self):
        context, _, _ = original_bound_numeric()
        for change, expected in [
            (lambda node: node['storage'].update(abi_binding={'some': ref(2200)}), 'storage_binding_match'),
            (lambda node: node['results'][0].update(type=ref(2200)), 'operand_type')]:
            bad = deepcopy(context.sections)
            change(bad[3]['functions'][1]['blocks'][0]['ops'][1])
            owner = RootContext(bad)
            owner.verify_abi()
            with self.assertRaises(Reject) as caught:
                owner.verify_execution()
            self.assertEqual(caught.exception.code, expected)


if __name__ == '__main__':
    unittest.main()
