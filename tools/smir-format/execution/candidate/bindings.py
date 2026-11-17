"""Actual section6 helper catalog admission, with exact metadata namespaces."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from common import Reject, require
from candidate.type_system import key
from candidate.wire import SCHEMA, encode

ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'


def documents():
    return (json.loads((SPEC / 'schema/runtime/candidate.json').read_text()),
            json.loads((SPEC / 'schema/runtime/helpers-v1.json').read_text()))


def catalog_digest(catalog):
    canonical = json.dumps(catalog, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                           allow_nan=False).encode('ascii')
    return hashlib.sha256(b'SMIR-HELPERS-V1\0' + canonical).hexdigest()


def runtime_package_module(component):
    """Load owner reference package without shadowing this candidate package."""
    name = 'rax_runtime_candidate_contract'
    if name not in sys.modules:
        directory = ROOT / 'tools/smir-runtime-contract/candidate'
        specification = importlib.util.spec_from_file_location(name, directory / '__init__.py',
                                                              submodule_search_locations=[str(directory)])
        module = importlib.util.module_from_spec(specification)
        sys.modules[name] = module
        specification.loader.exec_module(module)
    return __import__(name + '.' + component, fromlist=['instantiate'])


def validate(binding, types, dependencies):
    runtime, _ = documents()
    records = dict(SCHEMA['records'])
    for name, record in runtime['records'].items():
        require(name not in records or records[name] == record, 'shared_schema_conflict', name)
        records[name] = record
    encode('runtime_import', binding, records=records)
    signature = types.get(binding['signature'])
    require(signature['kind'] == 'function' and signature['cc'] == 'portable', 'helper_signature')
    if binding['kind'] == 'host':
        from candidate.host import validate as validate_host
        return validate_host(binding, types, dependencies.host_descriptors, records)
    namespaces = {'nominal': dependencies.nominals, 'signature': dependencies.abi_signatures,
                  'bridge': dependencies.bridges, 'journal': dependencies.cleanup_programs,
                  'recipe': dependencies.actions, 'storage_binding': dependencies.storage_bindings,
                  'tls': dependencies.tls, 'storage_layout': dependencies.layouts}

    def resolve(namespace, reference):
        require(namespace in namespaces and key(reference) in namespaces[namespace], 'helper_namespace_reference', namespace)
        if namespace == 'tls':
            result = namespaces[namespace][key(reference)]
            if hasattr(result, 'metadata'):
                result.metadata()  # Preserve provider-owned namespace and issued binding.
                return result
        result = dict(namespaces[namespace][key(reference)])
        if namespace == 'storage_binding':
            require(result['kind'] != 'allocation', 'helper_allocation_not_value')
        if namespace == 'storage_binding' and key(reference) in dependencies.abi_masks:
            result['comparison_mask'] = dependencies.abi_masks[key(reference)]
        return result

    def source_signature(reference):
        descriptor = resolve('signature', reference)
        nominal = resolve('nominal', descriptor['function_type'])
        execution = nominal['execution']
        require(execution is not None and types.equal(binding['signature'], execution['some']), 'import_abi_signature')

    if binding['kind'] == 'foreign':
        require(binding['descriptor']['module']['kind'] == 'self', 'foreign_bridge_self')
        bridge = resolve('bridge', binding['descriptor'])
        reference = {'module': binding['descriptor']['module'], 'id': bridge['signature']}
        source_signature(reference)
        return None  # Native endpoint evidence and capabilities are runtime/ABI admission.
    helpers = runtime_package_module('helpers' if binding['kind'] == 'internal' else 'services')
    try:
        if binding['kind'] == 'service':
            template = helpers.instantiate(binding, types.resolve, resolve)
            return template
        options = {}
        if helpers.helper(binding['name'])['abi_namespace'][binding['contract']] == 'nominal':
            options['source_layout'] = dependencies.source_layout
            options['source_compatible'] = dependencies.source_compatible
        if any(parameter['type'] == 'journal_captures' for parameter in helpers.helper(binding['name'])['params']):
            require(binding['abi'] is not None and binding['abi']['some']['module']['kind'] == 'self',
                    'journal_capture_program')
            program = resolve('journal', binding['abi']['some'])
            captures = []
            for formal in program['params']:
                nominal = resolve('nominal', formal['type'])
                require(nominal['execution'] is not None, 'journal_capture_execution')
                captures.append(types.resolve(nominal['execution']['some']))
            options['journal_captures'] = captures  # [] is an actual zero-formal program, not missing evidence.
        template = helpers.instantiate(binding, types.resolve, resolve, resolve, **options)
    except ValueError as error:
        if isinstance(error, Reject):
            raise
        raise Reject('runtime_helper_contract', str(error)) from error
    namespace = template['abi_namespace'][binding['contract']]
    target_namespace = template['target_namespace'][binding['contract']]
    if target_namespace == 'storage_layout':
        layout_ref = binding['options']['target']['some']
        layout = resolve('storage_layout', layout_ref)
        require(binding['types'] and types.equal(layout['type'], binding['types'][0]), 'helper_storage_type')
        abi = binding['abi']
        if abi is not None:
            require(namespace in {'storage_binding', 'optional_storage_binding'}, 'helper_storage_namespace')
            correspondence = resolve('storage_binding', abi['some'])
            require(correspondence['execution_layout'] == layout_ref
                    and correspondence['access_bytes'] == layout['access_bytes']
                    and binding['options']['alignment'] >= correspondence['required_alignment'],
                    'helper_storage_binding')
    return template
