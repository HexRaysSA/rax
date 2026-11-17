#!/usr/bin/env python3
"""Authoritative ordered runtime candidate record declarations (INT-008/009)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / 'docs/specifications/smir/portable/schema/runtime/candidate.json'
RECORDS = {}


def record(name, fields):
    RECORDS[name] = {'fields': [list(field) for field in fields]}


def variant(name, variants, discriminator='kind'):
    RECORDS[name] = {'discriminator': discriminator,
                     'variants': {tag: [list(field) for field in fields]
                                  for tag, fields in variants.items()}}


variant('module_ref', {'self': [], 'dependency': [('slot', 'u32')]})
record('entity_ref', [('module', 'module_ref'), ('id', 'u32')])
record('linkage_key', [('namespace', 'utf8'), ('name', 'utf8'),
                       ('abi_major', 'u32'), ('abi_minor', 'u32')])
record('external_declaration', [
    ('id', 'u32'), ('kind', 'token'), ('symbol_kind', 'token'), ('source_linkage', 'token'), ('namespace', 'utf8'), ('name', 'utf8'),
    ('execution', 'opt:entity_ref'), ('nominal', 'opt:entity_ref'), ('abi_signature', 'opt:entity_ref'), ('weak', 'bool')])
record('dependency', [
    ('slot', 'u32'), ('key', 'linkage_key'), ('minimum_minor', 'u32'),
    ('maximum_minor', 'opt:u32'), ('site', 'digest32'),
    ('declarations', 'vec:external_declaration')])
record('runtime_export', [
    ('id', 'u32'), ('kind', 'token'), ('source_linkage', 'token'), ('namespace', 'utf8'), ('name', 'utf8'),
    ('target', 'entity_ref'), ('execution', 'opt:entity_ref'), ('nominal', 'opt:entity_ref'), ('abi_signature', 'opt:entity_ref')])
record('module_manifest', [
    ('identity', 'digest32'), ('key', 'linkage_key'), ('kind', 'token'),
    ('entry', 'opt:entity_ref'), ('site', 'digest32'), ('personality', 'token'),
    ('foreign_isa', 'token'), ('dependencies', 'vec:dependency'),
    ('exports', 'vec:runtime_export')])
variant('definition', {
    'function': [('target', 'entity_ref')], 'data': [('segment', 'u32')],
    'tls': [('segment', 'u32')], 'import': [('import', 'u32')],
    'alias': [('target', 'entity_ref')], 'common': [('size', 'u64'), ('alignment', 'u64')],
    'native': [('image', 'digest32'), ('domain', 'u32'), ('offset', 'u64'), ('size', 'u64')]})
record('runtime_symbol', [
    ('id', 'u32'), ('namespace', 'utf8'), ('name', 'utf8'), ('kind', 'token'), ('source_linkage', 'token'),
    ('binding', 'token'), ('visibility', 'token'), ('execution', 'entity_ref'),
    ('nominal', 'opt:entity_ref'), ('abi_signature', 'opt:entity_ref'), ('definition', 'opt:definition'),
    ('size', 'opt:u64'), ('alignment', 'u64'), ('comdat', 'opt:u32'),
    ('fallback', 'opt:entity_ref')])
record('runtime_comdat', [
    ('id', 'u32'), ('namespace', 'utf8'), ('name', 'utf8'), ('selection', 'token'),
    ('key_symbol', 'u32'), ('members', 'vec:u32')])
record('runtime_init', [('function', 'entity_ref'), ('priority', 'u32'), ('ordinal', 'u32'),
                        ('association', 'opt:entity_ref')])
record('runtime_symbols', [
    ('payload_revision', 'u32'), ('manifest', 'module_manifest'),
    ('symbols', 'vec:runtime_symbol'), ('comdats', 'vec:runtime_comdat'),
    ('initializers', 'vec:runtime_init'), ('finalizers', 'vec:runtime_init')])
record('runtime_segment', [
    ('id', 'u32'), ('layout', 'opt:entity_ref'), ('nominal', 'opt:entity_ref'),
    ('abi_binding', 'opt:entity_ref'), ('alignment', 'u64'),
    ('mutable', 'bool'), ('initial', 'hex'), ('poison', 'hex'), ('undef', 'hex'),
    ('zero_fill', 'u64'), ('zero_shadow', 'token')])
record('runtime_data', [('payload_revision', 'u32'), ('segments', 'vec:runtime_segment')])
record('runtime_gep_step', [('offset','i64'), ('check_base','bool'), ('flags','vec:token'), ('inrange','opt:access_range')])
record('runtime_relocation', [
    ('source_kind', 'token'), ('source', 'u32'), ('offset', 'u64'), ('width', 'u32'),
    ('integer_bits','u32'), ('kind', 'token'), ('target', 'entity_ref'), ('addend', 'i64'),
    ('derivation','vec:runtime_gep_step'), ('check_base','bool'), ('flags','vec:token'), ('inrange','opt:access_range')])
record('runtime_constant_initializer', [('id','u32'),('source_kind','token'),('source','u32'),
    ('offset','u64'),('layout','entity_ref'),('function','entity_ref'),('association','opt:entity_ref')])
record('runtime_relocations', [('payload_revision', 'u32'),
    ('relocations', 'vec:runtime_relocation'), ('constant_initializers','vec:runtime_constant_initializer')])
record('runtime_helper_options', [
    ('alignment', 'u64'), ('scope', 'token'), ('order', 'token'),
    ('failure_order', 'token'), ('weak', 'bool'), ('comparison', 'token'),
    ('mask', 'hex'), ('rounding', 'token'), ('exceptions', 'token'),
    ('predicate', 'token'), ('target', 'opt:entity_ref'), ('flags', 'vec:token')])
record('runtime_host_descriptor', [('revision', 'u32'), ('namespace', 'utf8'), ('name', 'utf8'),
                                   ('version', 'u32'), ('types', 'hex'), ('signature', 'u32')])
variant('runtime_import', {
    'host': [('id', 'u32'), ('namespace', 'utf8'), ('name', 'utf8'), ('version', 'u32'),
             ('descriptor', 'digest32'), ('signature', 'entity_ref'), ('capability', 'token')],
    'internal': [('id', 'u32'), ('namespace', 'utf8'), ('name', 'token'),
                 ('version', 'u32'), ('catalog', 'digest32'), ('signature', 'entity_ref'),
                 ('abi', 'opt:entity_ref'), ('types', 'vec:entity_ref'), ('contract', 'token'),
                 ('options', 'runtime_helper_options')],
    'service': [('id', 'u32'), ('namespace', 'utf8'), ('name', 'utf8'),
                ('version', 'u32'), ('catalog', 'digest32'), ('signature', 'entity_ref'),
                ('abi', 'opt:entity_ref'), ('capability', 'token'),
                ('descriptor', 'opt:entity_ref')],
    'foreign': [('id', 'u32'), ('descriptor', 'entity_ref'), ('signature', 'entity_ref'),
                ('capability', 'token')]})
record('runtime_imports', [('payload_revision', 'u32'), ('imports', 'vec:runtime_import')])
record('runtime_tls_segment', [
    ('storage', 'runtime_segment'), ('initializers', 'vec:entity_ref'),
    ('destructors', 'vec:entity_ref'), ('initialization', 'token')])
record('runtime_tls', [('payload_revision', 'u32'), ('segments', 'vec:runtime_tls_segment')])
record('runtime_limit', [('name', 'token'), ('value', 'u64')])
record('runtime_requirement', [('kind', 'token'), ('name', 'utf8'), ('version', 'u32')])
record('runtime_capabilities', [
    ('payload_revision', 'u32'), ('capabilities', 'vec:token'),
    ('requirements', 'vec:runtime_requirement'), ('limits', 'vec:runtime_limit')])
record('artifact_binding', [('key', 'linkage_key'), ('artifact', 'digest32')])
variant('entity_binding', {
    'export': [('entity_kind', 'token'), ('declaration', 'u32'), ('export', 'u32')],
    'weak_null': [('entity_kind', 'token'), ('declaration', 'u32')]})
record('dependency_binding', [('source', 'digest32'), ('slot', 'u32'),
                              ('target', 'digest32'), ('entities', 'vec:entity_binding')])
record('runtime_deployment', [('payload_revision', 'u32'),
                              ('modules', 'vec:artifact_binding'),
                              ('edges', 'vec:dependency_binding')])
# Live-state roots below are internal transfer protocols, not compiler file authority.
record('runtime_position', [('block', 'u32'), ('operation', 'u32'),
                            ('predecessor', 'opt:u32')])
record('runtime_pointer', [('id', 'u64'), ('address', 'u64'), ('object', 'u64'),
                           ('generation', 'u64'), ('domain', 'token'), ('exposed', 'bool')])
record('runtime_origin', [('bit', 'u64'), ('pointer', 'u64'), ('source_bit', 'u8')])
record('runtime_transfer', [('type', 'entity_ref'), ('bits', 'hex'), ('poison', 'hex'),
                            ('undef', 'hex'), ('origins', 'vec:execution_origin_span')])
record('runtime_local', [('id', 'u32'), ('value', 'execution_live_value')])
record('runtime_allocation', [('object', 'u64'), ('generation', 'u64'),
                              ('address', 'u64'), ('extent', 'u64'), ('alignment', 'u64'),
                              ('kind', 'token'), ('lifetime', 'token'),
                              ('created_sequence', 'u64'), ('layout', 'opt:entity_ref')])
record('runtime_continuation', [('activation', 'u64'), ('position', 'runtime_position'),
                                ('results', 'vec:u32')])
record('runtime_ticket', [
    ('id', 'u64'), ('state', 'token'), ('helper', 'opt:entity_ref'),
    ('before', 'runtime_position'), ('normal', 'opt:runtime_position'),
    ('unwind', 'opt:runtime_position'), ('committed_bytes', 'u64'),
    ('direction', 'token'), ('results', 'vec:runtime_local'),
    ('exception', 'opt:u64'), ('cancellation', 'token')])
record('runtime_frame', [
    ('activation', 'u64'), ('module', 'digest32'), ('generation', 'u64'),
    ('binding_generation', 'u64'), ('function', 'u32'), ('position', 'runtime_position'),
    ('status', 'token'), ('locals', 'vec:runtime_local'),
    ('allocations', 'vec:runtime_allocation'), ('normal', 'opt:runtime_continuation'),
    ('unwind', 'opt:runtime_continuation'), ('ticket', 'opt:runtime_ticket'),
    ('journals', 'vec:u64'), ('bridge', 'opt:u64'), ('exception', 'opt:u64'),
    ('progress', 'opt:execution_progress'), ('unwind_state', 'opt:u64')])
record('runtime_fenv', [('rounding', 'token'), ('flags', 'u32'), ('traps', 'u32')])
record('runtime_thread_state', [
    ('payload_revision', 'u32'), ('process', 'u64'), ('thread', 'u64'),
    ('worker', 'opt:u64'), ('epoch', 'u64'), ('memory_generation', 'u64'),
    ('journal_sequence', 'u64'),
    ('errno', 'i32'), ('fenv', 'runtime_fenv'), ('diagnostic_policy', 'u32'),
    ('frames', 'vec:runtime_frame')])
# These records are ABI022 exact ordered snapshots, not serialized authority.
ABI_SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/abi/candidate.json'
ABI_RECORDS = json.loads(ABI_SCHEMA.read_text())['records']
for source, target in [('journal_parent', 'runtime_journal_parent'),
                       ('journal_entry', 'runtime_journal_entry'),
                       ('cleanup_state', 'runtime_cleanup_state')]:
    aliases = {'qref': 'entity_ref', 'journal_parent': 'runtime_journal_parent',
               'journal_entry': 'runtime_journal_entry'}
    def mapped(kind):
        return ':'.join(aliases.get(part, part) for part in kind.split(':'))
    record(target, [(name, mapped(kind)) for name, kind in ABI_RECORDS[source]['fields']])
record('runtime_journal_count', [('slot', 'u32'), ('count', 'u64')])
record('runtime_captured_parameter', [('parameter', 'u32'), ('value', 'execution_live_value')])
variant('runtime_journal_seed', {'object':[('certificate','u64'),('revision','u64')],
    'partial':[('builder','u64'),('revision','u64')]})
record('runtime_journal_owner', [('thread','u64'),('activation','u64'),('generation','u64'),('instance','u64')])
record('runtime_subobject_owner', [('kind','token'),('id','u64'),('slot','u32'),('element','u64')])
record('runtime_live_subobject', [('slot', 'u32'), ('element', 'u64'), ('lifetime', 'u64'),
                                 ('ordinal', 'u64'), ('child', 'opt:u64')])
record('runtime_object_lifetime', [('id', 'u64'), ('revision', 'u64'), ('module', 'digest32'),
    ('module_generation', 'u64'), ('object', 'u64'), ('object_generation', 'u64'),
    ('address', 'u64'), ('program', 'entity_ref'), ('counts', 'vec:runtime_journal_count'),
    ('captures','vec:runtime_captured_parameter'),
    ('subobjects', 'vec:runtime_live_subobject'), ('phase', 'token'), ('claim', 'opt:runtime_journal_owner'),
    ('owner','opt:runtime_subobject_owner'),
    ('leases', 'vec:u64')])
record('runtime_partial_object', [('id','u64'),('revision','u64'),('module','digest32'),('module_generation','u64'),
    ('object','u64'),('object_generation','u64'),('address','u64'),('program','entity_ref'),
    ('captures','vec:runtime_captured_parameter'),('counts','vec:runtime_journal_count'),
    ('completed','vec:runtime_live_subobject'),('current','vec:runtime_live_subobject'),
    ('phase','token'),('claim','opt:runtime_journal_owner'),('leases','vec:u64')])
record('runtime_qualified_journal', [
    ('id', 'u64'), ('module', 'digest32'), ('module_generation', 'u64'),
    ('object', 'u64'), ('object_generation', 'u64'), ('object_address', 'u64'),
    ('program', 'entity_ref'), ('seed', 'opt:runtime_journal_seed'), ('state', 'runtime_cleanup_state'),
    ('event_sequences', 'vec:u64'),
    ('captures', 'vec:runtime_captured_parameter'), ('counts', 'vec:runtime_journal_count'),
    ('leases', 'vec:u64')])
record('runtime_native_context', [
    ('isa', 'token'), ('profile', 'token'), ('integer', 'hex'), ('vector', 'hex'),
    ('control', 'hex'), ('x87', 'hex'), ('tls', 'hex'), ('code_object', 'u64'),
    ('code_generation', 'u64'), ('pc', 'u64'), ('stack_object', 'u64'),
    ('stack_generation', 'u64'), ('unwind_row', 'u32'), ('opaque_extension', 'hex')])
record('runtime_result_values', [('values', 'vec:execution_live_value')])
record('runtime_bridge_state', [
    ('id', 'u64'), ('thread', 'u64'), ('activation', 'u64'), ('generation', 'u64'),
    ('descriptor', 'entity_ref'), ('stage', 'token'), ('normal', 'runtime_continuation'),
    ('unwind', 'runtime_continuation'), ('target', 'runtime_transfer'),
    ('source', 'opt:runtime_result_values'), ('source_journal', 'u64'), ('target_journal', 'u64'),
    ('adapter_frame', 'opt:runtime_frame'), ('cpu', 'opt:runtime_native_context'),
    ('suspension', 'u64'),
    ('foreign_entries', 'u32'), ('normal_publications', 'u32'),
    ('exception', 'opt:u64'), ('leases', 'vec:u64'), ('cancellation', 'token')])
record('runtime_nonlocal_state', [
    ('id', 'u64'), ('process', 'u64'), ('thread', 'u64'), ('activation', 'u64'),
    ('generation', 'u64'), ('position', 'runtime_position'), ('result', 'u32'),
    ('frames', 'vec:runtime_frame'), ('journals', 'vec:u64'),
    ('signal_mask', 'opt:hex'), ('leases', 'vec:u64')])
record('runtime_captured_parameter', [('parameter', 'u32'), ('value', 'execution_live_value')])
record('runtime_action_state', [('id', 'u32'), ('program', 'entity_ref'), ('recipe', 'entity_ref'),
                               ('journal', 'u64'), ('captures', 'vec:runtime_captured_parameter'),
                               ('phase', 'token'), ('ticket', 'u64')])
record('runtime_unwind_state', [
    ('id', 'u64'), ('thread', 'u64'), ('activation', 'u64'), ('generation', 'u64'),
    ('exception', 'u64'), ('phase', 'token'), ('before', 'runtime_position'),
    ('unwind', 'runtime_continuation'), ('handler', 'opt:entity_ref'),
    ('actions', 'vec:runtime_action_state'), ('next_action', 'u32'),
    ('adapter', 'opt:runtime_frame'), ('suspension', 'u64'), ('leases', 'vec:u64')])
record('runtime_environment_entry', [('name', 'utf8'), ('value', 'utf8')])
record('runtime_spawn_spec', [('revision', 'u32'), ('artifact', 'digest32'),
                              ('arguments', 'vec:utf8'), ('environment', 'vec:runtime_environment_entry'),
                              ('working_directory', 'utf8'), ('inherit', 'vec:u64')])
record('runtime_locator', [('offset','u64'), ('length','u64'), ('sha256','digest32')])
record('runtime_selection', [('abi_major','u32'), ('minimum_minor','u32'), ('minimum_revision','u32'),
    ('implementation','opt:digest32'), ('profile','u32'), ('helpers','digest32'),
    ('services','digest32'), ('baseline','digest32')])
record('runtime_launch', [('revision','u32'), ('launch','token'), ('carrier','token'),
    ('bootstrap_arch','token'), ('personality','token'), ('foreign_isa','token'),
    ('artifact','digest32'), ('entry','entity_ref'), ('locator','opt:runtime_locator'),
    ('runtime','runtime_selection'), ('required_capabilities','vec:token'), ('modules','vec:digest32')])
record('runtime_live_state', [
    ('payload_revision', 'u32'), ('thread', 'runtime_thread_state'),
    ('journals', 'vec:runtime_qualified_journal'), ('lifetimes', 'vec:runtime_object_lifetime'),
    ('partial_objects','vec:runtime_partial_object'), ('bridges', 'vec:runtime_bridge_state'),
    ('nonlocals', 'vec:runtime_nonlocal_state'), ('unwinds', 'vec:runtime_unwind_state')])

EXECUTION_SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/execution/candidate.json'
SHARED_RECORDS = ('access_range', 'absolute_range', 'execution_live_value', 'execution_live_payload',
                  'execution_origin_span', 'execution_progress')
for shared_name in SHARED_RECORDS:
    RECORDS[shared_name] = json.loads(EXECUTION_SCHEMA.read_text())['records'][shared_name]

ROOTS = {2: 'runtime_symbols', 4: 'runtime_data', 5: 'runtime_relocations',
         6: 'runtime_imports', 7: 'runtime_tls', 9: 'runtime_capabilities'}


def document():
    return {'format': 'ordered_records_candidate_v1',
            'status': 'accepted_common_refs_payload_contract_draft',
            'roots': {str(k): v for k, v in ROOTS.items()},
            'live_roots': ['runtime_deployment', 'runtime_live_state'], 'records': RECORDS}


if __name__ == '__main__':
    OUTPUT.write_text(json.dumps(document(), indent=2) + '\n')
