"""Derive semantic context from actual candidate sections, never producer callbacks."""
from copy import deepcopy
from collections.abc import Mapping
from dataclasses import dataclass, field
import importlib.util
import hashlib
from pathlib import Path
import sys

from common import require
from candidate.layouts import Layouts
from candidate.operations import Dependencies, optional
from candidate.type_system import Types, key, ref, unique
from candidate.verify import verify
from candidate.wire import SCHEMA, encode

ROOT = Path(__file__).resolve().parents[4]
ROOT_NAMES = {1: 'execution_types', 2: 'runtime_symbols', 3: 'execution_functions',
              4: 'runtime_data', 5: 'runtime_relocations', 6: 'runtime_imports', 7: 'runtime_tls',
              8: 'execution_exceptions', 9: 'runtime_capabilities', 10: 'abi_contract'}
_REGISTRY_VERIFICATION_KEY = object()


def source_registry_api():
    """Canonical draft data-view implementation; no runtime fact constructors."""
    call = source_call_api()  # Loads the one shared error identity first.
    name = '_rax_smir_source_registry_v1'
    path = (ROOT / 'tools/smir-format/execution/candidate/source_registry_projection.py').resolve()
    module = sys.modules.get(name)
    if module is not None:
        if (getattr(module, '__file__', None) is None or Path(module.__file__).resolve() != path or
                getattr(module, '_SOURCE_REGISTRY_READY', False) is not True):
            call._error('SOURCE_REGISTRY_CONTEXT', 'canonical registry module identity')
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        if getattr(module, '_SOURCE_REGISTRY_READY', False) is not True:
            call._error('SOURCE_REGISTRY_CONTEXT', 'registry module initialization')
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def source_call_api():
    """One exact reference-view identity; no generic package-name fallback."""
    def load(name, path, ready):
        if name in sys.modules:
            module = sys.modules[name]
            if getattr(module, '__file__', None) is None or Path(module.__file__).resolve() != path:
                raise RuntimeError('SOURCE_CALL_MODULE_IDENTITY: ' + name)
            if not ready(module):
                raise RuntimeError('SOURCE_CALL_MODULE_INITIALIZATION: ' + name)
            return module
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
            if not ready(module):
                raise RuntimeError('SOURCE_CALL_MODULE_INITIALIZATION: ' + name)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
        return module

    errors = load('_rax_smir_call_comparison_errors_v1',
                  (ROOT / 'tools/smir-abi/function_address/errors.py').resolve(),
                  lambda module: getattr(module, '_CANONICAL_INITIALIZED', False) is True)
    name = '_rax_smir_source_call_v1'
    path = (ROOT / 'tools/smir-format/execution/candidate/source_call_projection.py').resolve()
    if name in sys.modules and (getattr(sys.modules[name], '__file__', None) is None or
                               Path(sys.modules[name].__file__).resolve() != path):
        raise errors.CallComparisonError('semantic', 'ABI_CC_CONTEXT', 'source-call module path')
    return load(name, path, lambda module: getattr(module, '_SOURCE_CALL_READY', False) is True)


@dataclass(frozen=True)
class TlsTarget(Mapping):
    """Issued metadata view; provider SELF references keep their original owner."""
    registry: object
    binding: object
    consumer: object
    reference: dict

    def metadata(self):
        self.consumer.assert_snapshot()
        return self.registry.metadata_external(self.binding, self.consumer, self.reference)

    @property
    def provider_context(self):
        return self.metadata()['provider_context']

    @property
    def module_generation(self):
        return self.metadata()['module_generation']

    def __getitem__(self, name):
        return self.metadata()['segment'][name]

    def __iter__(self):
        return iter(self.metadata()['segment'])

    def __len__(self):
        return len(self.metadata()['segment'])

    def __deepcopy__(self, memo):
        # Never clone the private issued binding, Condition, or owner context.
        return self


def records():
    import json
    merged = dict(SCHEMA['records'])
    for owner in ['runtime', 'abi']:
        document = json.loads((ROOT / f'docs/specifications/smir/portable/schema/{owner}/candidate.json').read_text())
        for name, record in document['records'].items():
            require(name not in merged or merged[name] == record, 'root_schema_conflict', name)
            merged[name] = record
    return merged


@dataclass(frozen=True)
class IndependentEvidence:
    """Trusted admission inputs checked against actual foreign declarations.

    These records must come from registered metadata producers/independent image
    inspection under the caller's admission policy. Reading the same section10
    declaration back as its own evidence is not an evidence producer. No booleans
    or resolver callbacks in file data can substitute for these registry inputs.
    """
    native_types: dict
    native_unwind: dict
    native_symbols: dict = field(default_factory=dict)
    native_domains: dict = field(default_factory=dict)
    native_layouts: dict = field(default_factory=dict)
    native_personalities: dict = field(default_factory=dict)
    host_descriptors: dict = field(default_factory=dict)


class RootContext:
    def __init__(self, sections, independent=None, *, budget=None):
        is_v3 = sections.get(3, {}).get('payload_revision') == 3
        if is_v3:
            require(independent is None or type(independent) is IndependentEvidence and
                    all(type(value) is dict and not value for value in vars(independent).values()),
                    'V3_FACTORY_PROFILE')
            from . import root3_context as V3
            before_v3_hashes = V3.root_hashes(sections, budget)
        require(set(sections) >= {1, 2, 3, 4, 6, 8, 10}, 'section_context_missing')
        self.sections = deepcopy(sections)
        if is_v3:
            V3.bind(self, budget)
        merged = records()
        self._root_hashes = {}
        for section, root in ROOT_NAMES.items():
            if section not in self.sections:
                continue
            self._root_hashes[section] = (before_v3_hashes[section] if is_v3 else
                hashlib.sha256(encode(root, self.sections[section], records=merged)).digest())
            expected_revision = 3 if section == 10 or section == 3 and is_v3 else 2 if section in {1, 2, 3, 5} else 1
            require(self.sections[section]['payload_revision'] == expected_revision, 'root_revision')
        self.abi = self.sections[10]
        # Preserve ABI validation/diagnostic priority: indexing does not admit domains.
        self.nominal_domains = {}
        for domain in self.abi['domains']:
            self.nominal_domains.setdefault(domain['id'], []).append(domain)
        self.nominals = {('self', identifier): item for identifier, item in unique(self.abi['types']).items()}
        self.signatures = {('self', identifier): item for identifier, item in unique(self.abi['signatures']).items()}
        self.recipes = {('self', identifier): item for identifier, item in unique(self.abi['recipes']).items()}
        self.programs = {('self', identifier): item for identifier, item in unique(self.abi['journals']).items()}
        self.storage_bindings = {('self', identifier): item for identifier, item in unique(self.abi['storage_bindings']).items()}
        self.bridges = {('self', identifier): item for identifier, item in unique(self.abi['bridges']).items()}
        self.symbols = {('self', identifier): item for identifier, item in unique(self.sections[2]['symbols']).items()}
        self.imports = {('self', identifier): item for identifier, item in unique(self.sections[6]['imports']).items()}
        self.functions = {('self', identifier): item for identifier, item in unique(self.sections[3]['functions']).items()}
        tls_segments = self.sections.get(7, {'segments': []})['segments']
        tls_ids = [item['storage']['id'] for item in tls_segments]
        require(tls_ids == sorted(set(tls_ids)), 'tls_definition_order')
        self.tls_segments = {('self', item['storage']['id']): item for item in tls_segments}
        self.dependencies = unique(self.sections[2]['manifest']['dependencies'], 'slot')
        self.declarations = {}
        self.symbol_declarations = {}
        local_types = {item['id']: item for item in self.sections[1]['types']}
        external_types, external_functions = {}, {}
        for slot, dependency in self.dependencies.items():
            for declaration_id, declaration in unique(dependency['declarations']).items():
                require((declaration['symbol_kind'] in {'function', 'data', 'tls', 'import', 'function_address'}
                         if declaration['kind'] == 'symbol' else declaration['symbol_kind'] == 'none'),
                        'declaration_symbol_kind')
                identity = 'dependency', slot, declaration_id
                self.declarations[identity] = declaration
                expected = optional(declaration['execution'])
                if expected is not None:
                    require(expected['module']['kind'] == 'self' and expected['id'] in local_types, 'declaration_execution')
                    if declaration['kind'] == 'type':
                        external_types[identity] = local_types[expected['id']]
                    elif declaration['kind'] == 'function':
                        external_functions[identity] = expected
                nominal = optional(declaration['nominal'])
                if nominal is not None:
                    require(nominal['module']['kind'] == 'self' and key(nominal) in self.nominals, 'declaration_nominal')
                    if declaration['kind'] == 'nominal':
                        self.nominals[identity] = self.nominals[key(nominal)]
                plan = optional(declaration['abi_signature'])
                if plan is not None and (declaration['kind'] == 'function' or
                        declaration['kind'] == 'symbol' and declaration['symbol_kind'] in {'function', 'import'}):
                    require(plan['module']['kind'] == 'self' and key(plan) in self.signatures,
                            'declaration_abi_signature')
                    self.signatures[identity] = self.signatures[key(plan)]
        self.types = (Types(self.sections[1], external_types, budget=budget) if is_v3 else
                      Types(self.sections[1], external_types))
        for identity, declaration in self.declarations.items():
            if declaration['kind'] not in {'symbol', 'function'}:
                continue
            expected = optional(declaration['execution'])
            nominal = optional(declaration['nominal'])
            source = None if nominal is None else self.nominals[key(nominal)]
            storage_kind = 'function' if declaration['kind'] == 'function' else declaration['symbol_kind']
            function = storage_kind in {'function', 'import'}
            if storage_kind == 'function_address':
                require(expected is not None and self.types.get(expected)['kind'] == 'code_address'
                        and source is not None and source['kind'] == 'function'
                        and declaration['abi_signature'] is None, 'declaration_function_address')
            elif function:
                require(expected is not None and self.types.get(expected)['kind'] == 'function', 'declaration_function_signature')
            else:
                require(expected is not None or source is not None and source['kind'] != 'function', 'declaration_object_view')
                require(expected is None or self.types.get(expected)['kind'] != 'function', 'declaration_symbol_kind')
            self.symbol_declarations[identity] = {'kind': storage_kind,
                'execution': expected, 'nominal': declaration['nominal'], 'abi_signature': declaration['abi_signature'],
                'definition': None,
                'declaration': True, 'native_only': source is not None and 'native' in source['flags']}
        self.layouts = (Layouts(self.sections[1], self.types, budget=budget) if is_v3 else
                        Layouts(self.sections[1], self.types))
        require(independent is None or isinstance(independent, IndependentEvidence), 'independent_evidence_type')
        self.evidence = deepcopy(independent) if independent is not None else IndependentEvidence({}, {})
        self.abi_checked = False
        self.abi_masks = {}
        self.execution_checked = None
        self.external_tls = {}
        # Source-data preparation is explicit and caller-budgeted; old consumers
        # acquire no new eager snapshot/hash/copy work.
        self._source_stamp = None
        self._source_budget = None
        if type(self) is RootContext:
            source_registry_api()._constructed(self, _REGISTRY_VERIFICATION_KEY)

    @classmethod
    def from_module(cls, encoded, *, budget, independent=None):
        from . import root3_context as V3
        require(cls is RootContext, 'V3_OWNER_CLASS')
        decoded = V3.codec().decode_module(encoded, budget=budget)
        require(decoded.roots[3]['payload_revision'] == 3, 'V3_EXPECTED_REVISION3')
        return cls(decoded.roots, independent, budget=budget)

    @property
    def source_stamp(self):
        return self._source_stamp

    def prepare_source_data(self, *, budget):
        from .source_data_projection import prepare
        return prepare(self, budget=budget)

    def source_data(self, symbol, offset, length, *, budget):
        from .source_data_projection import query
        return query(self, symbol, offset, length, budget=budget)

    def source_call_context(self, *, budget):
        return source_call_api()._issue(self, budget=budget)

    def source_registry_context(self, *, budget):
        return source_registry_api()._issue(self, budget=budget)

    def assert_snapshot(self):
        if self.sections[3]['payload_revision'] == 3:
            from . import root3_context as V3
            require(V3.root_hashes(self.sections, V3.owner_budget(self)) == self._root_hashes,
                    'context_snapshot_changed')
            return
        merged = records()
        for section in self._root_hashes:
            root = ROOT_NAMES[section]
            require(hashlib.sha256(encode(root, self.sections[section], records=merged)).digest() ==
                    self._root_hashes[section], 'context_snapshot_changed')

    def execution(self, reference):
        return self.types.resolve(reference)

    def _source_nominal_reference(self, reference):
        """Resolve an original key through its actual consumer expectation.

        DEP aliases retain a separate future provider obligation. Their expected
        SELF graph is not the selected provider's private layout or live grant.
        """
        self.assert_snapshot()
        require(self.abi_checked, 'abi_before_execution_binding')
        require(key(reference) in self.nominals, 'abi_namespace_reference', 'nominal')
        return ref(self.nominals[key(reference)]['id'])

    def source_layout(self, reference):
        mapped = self._source_nominal_reference(reference)
        return deepcopy(self.abi_graph.layout(mapped))

    def source_compatible(self, left, right):
        mapped_left = self._source_nominal_reference(left)
        mapped_right = self._source_nominal_reference(right)
        return self.abi_graph.compatible(mapped_left, mapped_right, ignore_top_cv=True)

    def function(self, reference):
        """Actual local definition. Dependency declarations are not definitions.

        Deployment binder resolves a consumer declaration to a provider export
        and queries that provider context using its own self target reference.
        """
        require(key(reference) in self.functions, 'function_definition_reference')
        return deepcopy(self.functions[key(reference)])

    def runtime_symbol(self, reference):
        require(key(reference) in self.symbols, 'symbol_definition_reference')
        return deepcopy(self.symbols[key(reference)])

    def abi_entity(self, namespace, reference):
        if namespace == 'nominal_domain':
            # The reference identifies a nominal, never a provider-private domain.
            # DEP nominals already alias their actual local expectation records.
            require(key(reference) in self.nominals, 'abi_namespace_reference', namespace)
            domains = self.nominal_domains.get(self.nominals[key(reference)]['domain'], [])
            require(len(domains) == 1, 'abi_namespace_reference', namespace)
            return deepcopy(domains[0])
        tables = {'nominal': self.nominals, 'signature': self.signatures, 'recipe': self.recipes,
                  'journal': self.programs, 'bridge': self.bridges, 'storage_binding': self.storage_bindings}
        require(namespace in tables and key(reference) in tables[namespace], 'abi_namespace_reference', namespace)
        result = deepcopy(tables[namespace][key(reference)])
        if namespace == 'storage_binding' and key(reference) in self.abi_masks:
            result['comparison_mask'] = self.abi_masks[key(reference)]
        return result

    def target_entity(self, namespace, reference):
        if namespace == 'storage_layout':
            return self.memory_layout(reference)
        if namespace == 'tls':
            self.assert_snapshot()
            if reference['module']['kind'] == 'dependency':
                require(key(reference) in self.external_tls, 'tls_external_unbound')
                target = self.external_tls[key(reference)]
                target.metadata()  # Current private binding/generation, not a file assertion.
                return target
            require(key(reference) in self.tls_segments, 'tls_definition_reference')
            return deepcopy(self.tls_segments[key(reference)])
        return self.abi_entity(namespace, reference)

    def install_external_tls(self, mapping):
        """Stage issued bindings after ABI and before all-module execution checks."""
        require(self.abi_checked and self.execution_checked is None, 'tls_binding_stage')
        from candidate.bindings import runtime_package_module
        registry_type = runtime_package_module('tls').Registry
        installed = {}
        for identity, pair in mapping.items():
            require(type(identity) is tuple and len(identity) == 2 and all(type(n) is int and 0 <= n < 2**32
                    for n in identity), 'tls_binding_reference')
            reference = ref(identity[1], identity[0])
            declaration = self.declarations.get(key(reference))
            require(declaration is not None and declaration['kind'] == 'symbol'
                    and declaration['symbol_kind'] == 'tls', 'tls_binding_declaration')
            require(type(pair) is tuple and len(pair) == 2 and isinstance(pair[0], registry_type),
                    'tls_binding_registry')
            target = TlsTarget(pair[0], pair[1], self, reference)
            metadata = target.metadata()
            require(isinstance(metadata['provider_context'], RootContext)
                    and metadata['provider_context'].abi_checked, 'tls_binding_provider')
            installed[key(reference)] = target
        self.external_tls = installed

    def abi_execution(self, reference):
        """ABI shape view: child identities, not producer numeric type IDs.

        Runtime helper signature matching consumes execution() with real refs;
        ABI binding consumes this independently recomputed normalized view.
        """
        result = self.execution(reference)
        kind = result['kind']
        if kind in {'array', 'vector'}:
            result['element_identity'] = self.types.digest(result['element'])
        elif kind == 'code_ptr':
            result['signature_identity'] = self.types.digest(result['signature'])
        elif kind == 'struct':
            result['fields'] = [self.types.digest(child) for child in result['fields']]
        elif kind == 'function':
            for name in ['params', 'results']:
                result[name] = [self.types.digest(child) for child in result[name]]
        return result

    def memory_layout(self, reference):
        result = deepcopy(self.layouts.get(reference))
        result['identity'] = self.layouts.digest(reference)
        return result

    def nominal(self, reference):
        require(key(reference) in self.nominals, 'nominal_context_reference')
        return deepcopy(self.nominals[key(reference)])

    def nominal_layout(self, reference):
        require(self.abi_checked, 'abi_before_layout_evidence')
        return deepcopy(self.abi_graph.layout(reference))

    def symbol(self, reference):
        require(key(reference) in self.symbols, 'symbol_context_reference')
        symbol = deepcopy(self.symbols[key(reference)])
        nominal = optional(symbol['nominal'])
        require(nominal is not None and key(nominal) in self.nominals, 'symbol_nominal_evidence')
        source_type = self.nominals[key(nominal)]
        symbol['signature'] = nominal if source_type['kind'] == 'function' else None
        symbol['execution_signature'] = self.execution(symbol['execution'])
        symbol['domain'] = source_type['domain']
        domain = next(item for item in self.abi['domains'] if item['id'] == symbol['domain'])
        if domain['isa'] != 'portable':
            definition = optional(symbol['definition'])
            require(definition is not None and definition['kind'] == 'native', 'native_symbol_definition')
            symbol.update(self.native_symbol(reference, definition))
        return symbol

    def native_symbol(self, reference, definition):
        """Consume R028rev3 independent registered-image entry facts.

        The trusted factory must have inspected loaded guest bytes, profile,
        actual compiler type graph and boundaries. File data never fills this
        map or certifies itself; this adapter only checks their exact binding.
        """
        require(key(reference) in self.symbols and definition['kind'] == 'native', 'native_symbol_definition')
        require(key(reference) in self.evidence.native_symbols, 'native_symbol_evidence')
        facts = deepcopy(self.evidence.native_symbols[key(reference)])
        fields = {'image', 'domain', 'offset', 'code_size', 'guest_address', 'profile', 'native_cc', 'signature',
                  'code_generation', 'code_sha256', 'permissions', 'entry_boundary', 'execution_identity', 'bridge_abi'}
        require(set(facts) == fields, 'native_symbol_fact_shape')
        for field in ['domain', 'offset', 'code_size', 'guest_address', 'code_generation']:
            encode('u32' if field == 'domain' else 'u64', facts[field])
        for field in ['image', 'code_sha256', 'execution_identity']:
            encode('digest32', facts[field])
        for field in ['profile', 'native_cc', 'bridge_abi', 'permissions']:
            encode('token', facts[field])
        encode('entity_ref', facts['signature'])
        encode('bool', facts['entry_boundary'])
        declared = self.symbols[key(reference)]
        nominal = optional(declared['nominal'])
        require(nominal is not None and key(nominal) in self.nominals, 'native_symbol_nominal')
        domain = next((item for item in self.abi['domains'] if item['id'] == definition['domain']), None)
        require(domain is not None and domain['isa'] != 'portable'
                and self.nominals[key(nominal)]['domain'] == definition['domain'], 'native_definition_domain')
        require(facts['image'] == definition['image'] and facts['domain'] == definition['domain']
                and facts['offset'] == definition['offset'] and facts['code_size'] == definition['size'] > 0
                and facts['signature'] == nominal, 'native_symbol_fact_binding')
        require(type(facts['guest_address']) is int and 0 < facts['guest_address'] < 2**64
                and facts['guest_address'] + facts['code_size'] <= 2**64 - 1
                and type(facts['code_generation']) is int and 0 < facts['code_generation'] < 2**64
                and facts['permissions'] == 'rx' and facts['entry_boundary'] is True, 'native_symbol_code_range')
        conventions = {'sysv_amd64': ('x86_64', 'sysv64_frame'), 'win64': ('x86_64', 'win64_frame'),
                       'aapcs64': ('aarch64', 'aapcs64_frame'), 'aapcs64_darwin': ('aarch64', 'aapcs64_frame'),
                       'aapcs64_windows': ('aarch64', 'aapcs64_frame')}
        require(facts['native_cc'] in conventions and conventions[facts['native_cc']][0] == domain['isa']
                and facts['bridge_abi'] in {'none', conventions[facts['native_cc']][1]}, 'native_symbol_calling_convention')
        from candidate.wire import HEX
        require(type(facts['code_sha256']) is str and len(facts['code_sha256']) == 64
                and HEX.fullmatch(facts['code_sha256']) is not None
                and facts['execution_identity'] == self.types.digest(declared['execution']), 'native_symbol_execution_evidence')
        return facts

    def metadata(self, reference):
        require(key(reference) in self.symbols, 'metadata_symbol')
        symbol = self.symbols[key(reference)]
        definition = optional(symbol['definition'])
        require(definition is not None and definition['kind'] == 'data', 'metadata_definition')
        # Runtime data record names are schema-owned; no executable host pointer
        # or producer-provided arbitrary callback is a metadata source.
        objects = unique(self.sections[4]['segments'])
        require(definition['segment'] in objects, 'metadata_data_reference')
        item = objects[definition['segment']]
        initial, poison, undef = [bytes.fromhex(item[field]) for field in ['initial', 'poison', 'undef']]
        extent = len(initial) + item['zero_fill']
        require(extent <= 8 * 1024 * 1024, 'reference_resource', 'metadata bytes')
        require(len(initial) == len(poison) == len(undef) and not item['mutable'] and not any(poison)
                and not any(undef) and (item['zero_fill'] == 0 or item['zero_shadow'] == 'defined'),
                'metadata_initialized_readonly_bytes')
        require(optional(symbol['size']) == extent, 'metadata_symbol_extent')
        return initial + bytes(item['zero_fill'])

    def verify_abi(self, modules=None, bindings=None, families=None):
        if self.sections[3]['payload_revision'] == 3:
            from . import root3_context as V3
            require(modules is None and bindings is None and families is None, 'V3_FACTORY_PROFILE')
            source_registry_api()._invalidate(self, _REGISTRY_VERIFICATION_KEY, 'abi')
            V3.reserve_factory(self, V3.owner_budget(self))
        if type(self) is RootContext:
            source_registry_api()._invalidate(self, _REGISTRY_VERIFICATION_KEY, 'abi')
        self.assert_snapshot()
        abi_tools = ROOT / 'tools/smir-abi'
        module_name = 'rax_abi_candidate_contract'
        specification = importlib.util.spec_from_file_location(module_name, abi_tools / 'candidate.py')
        module = importlib.util.module_from_spec(specification)
        sys.modules[module_name] = module
        sys.path.insert(0, str(abi_tools))
        try:
            specification.loader.exec_module(module)
            # Exposed graph callbacks remain usable after this temporary import
            # path is removed. Their lazy dependencies are part of the actual
            # ABI implementation, never replaced by a permissive comparator.
            for dependency in ['c_boundary', 'call_interfaces']:
                importlib.import_module(dependency)
            family = self.sections[2]['manifest']['key']
            owner = family['namespace'] + ':' + family['name'] + ':' + str(family['abi_major'])
            # These are this consumer's local expectations, not provider
            # selection. An explicitly empty owner table is deliberately strict.
            nominal_expectations = {owner: {}}
            for dependency in self.sections[2]['manifest']['dependencies']:
                for declaration in dependency['declarations']:
                    if declaration['kind'] != 'nominal':
                        continue
                    expected = optional(declaration['nominal'])
                    if expected is not None:
                        require(expected['module']['kind'] == 'self' and
                                key(expected) in self.nominals, 'declaration_nominal')
                        nominal_expectations[owner][dependency['slot'], declaration['id']] = expected['id']
            factory_options = {}
            if self.sections[3]['payload_revision'] == 3:
                require('factory_budget' in module.Context.__dataclass_fields__,
                        'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
                factory_options['factory_budget'] = V3.owner_budget(self)
            context = module.Context(owner, self.abi_execution, self.symbol, self.metadata,
                                     modules or {}, bindings or {},
                                     lambda reference: deepcopy(self.evidence.native_types[key(reference)]),
                                     lambda reference: deepcopy(self.evidence.native_unwind[key(reference)]),
                                     families or {owner: (family['namespace'], family['name'], family['abi_major'])},
                                     self.memory_layout,
                                     native_domains=deepcopy(self.evidence.native_domains),
                                     native_layout=lambda reference: deepcopy(self.evidence.native_layouts[key(reference)]),
                                     native_personality=lambda reference: deepcopy(self.evidence.native_personalities[key(reference)]),
                                     source_data=self.source_data, source_stamp=self.source_stamp,
                                     source_budget=self._source_budget,
                                     nominal_expectations=nominal_expectations, **factory_options)
            result = module.verify(self.abi, context)
            graph_options = {'budget': V3.owner_budget(self)} if self.sections[3]['payload_revision'] == 3 else {}
            graph = module.NominalGraph(self.abi, owner, modules or {}, bindings or {}, context.families,
                                       nominal_expectations=nominal_expectations, **graph_options)
            self.abi_graph = graph
            for identity, binding in self.storage_bindings.items():
                if binding['kind'] == 'allocation':
                    continue  # Whole representation, never a source logical value mask.
                mask = int.from_bytes(graph.value_mask(binding['nominal']), 'little')
                mask = (mask >> binding['view_offset_bits']) & ((1 << binding['view_width_bits']) - 1)
                self.abi_masks[identity] = mask.to_bytes(binding['access_bytes'], 'little')
        finally:
            sys.path.pop(0)
        self.abi_checked = True
        if type(self) is RootContext:
            source_registry_api()._verified_abi(self, _REGISTRY_VERIFICATION_KEY)
        return result

    def verify_candidate_body(self, *, budget):
        from . import root3_context as V3
        from .verify import _verify_v3_body
        require(self.sections[3]['payload_revision'] == 3, 'V3_EXPECTED_REVISION3')
        V3.owner_budget(self, budget)
        V3.require_abi(self)
        source_registry_api()._invalidate(self, _REGISTRY_VERIFICATION_KEY, 'execution')
        stamp = RootContext.prepare_source_data(self, budget=budget)
        V3.reserve_factory(self, budget)
        working = RootContext(self.sections, budget=budget)
        working.verify_abi()
        # Match the original execution dependency construction on this complete
        # original-v3 clone. Snapshot charges precede allocation; callbacks retain
        # the actual checked graph and its original ledger.
        from . import factory_meter as M
        M.snapshot_bound(working.symbols, budget)
        M.snapshot_bound(working.symbol_declarations, budget)
        symbols = {**deepcopy(working.symbols), **deepcopy(working.symbol_declarations)}
        graph = deepcopy(working.abi_graph)
        M.collection(budget, len(working.nominals))
        nominal_aliases = {identity: ref(item['id']) for identity, item in working.nominals.items()}

        def nominal_equal(left, right):
            M.lookup(budget, len(nominal_aliases))
            require(key(left) in nominal_aliases and key(right) in nominal_aliases,
                    'handler_nominal_reference')
            return graph.catch_compatible(nominal_aliases[key(left)], nominal_aliases[key(right)])

        M.collection(budget, len(working.declarations))
        functions = {identity: optional(declaration['execution'])
                     for identity, declaration in working.declarations.items()
                     if declaration['kind'] == 'function' and declaration['execution'] is not None}
        M.collection(budget, len(working.tls_segments) + len(working.external_tls))
        deps = Dependencies(functions=functions, imports=working.imports, layouts=working.layouts.items,
            nominals=working.nominals, actions=working.recipes, symbols=symbols,
            cleanup_programs=working.programs, storage_bindings=working.storage_bindings,
            abi_signatures=working.signatures, bridges=working.bridges, abi_masks=working.abi_masks,
            host_descriptors=working.evidence.host_descriptors,
            tls={**working.tls_segments, **working.external_tls}, nominal_equal=nominal_equal,
            source_layout=working.source_layout, source_compatible=working.source_compatible)
        from candidate.bindings import validate
        for imported in M.iter_rows(budget, working.imports.values()):
            M.internal_helper(imported, deps, budget)
            validate(imported, working.types, deps)
        result = _verify_v3_body(working.sections[1], working.sections[3], working.sections[8],
                                 deps, budget=budget)
        from . import source_observer
        observers = source_observer.collect(result.functions_root, budget=budget)
        deferred = ('V3_SOURCE_SEMANTICS_INCOMPLETE',)
        if observers:
            deferred += ('V3_OBSERVER_SOURCE_CONSTRAINTS_REQUIRED',)
        require(RootContext.prepare_source_data(self, budget=budget) is stamp, 'V3_SOURCE_CHANGED')
        return V3.V3BodyChecks(self, stamp, result, deferred, observers)

    def verify_source_constraints(self, *, budget):
        from . import root3_context as V3
        V3.owner_budget(self, budget)
        carrier = dict(format='draft-source-alias-compiler-constraints', revision=4,
            draft_sha256='28db5402d408528b02aac917c53bf94f98ffe7d4b0fe49760dd3b0015cc1c029',
            contract=V3.codec().raw_contract(self.sections[3]['source_contract'], budget=budget),
            proposed_operations=[])
        return V3.source_contracts().verify(self, carrier, budget=budget)

    def verify_execution(self):
        require(self.sections[3]['payload_revision'] != 3, 'V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE')
        if type(self) is RootContext:
            source_registry_api()._invalidate(self, _REGISTRY_VERIFICATION_KEY, 'execution')
        self.assert_snapshot()
        require(self.abi_checked, 'abi_before_execution_binding')
        functions = {}
        for identity, declaration in self.declarations.items():
            if declaration['kind'] == 'function' and declaration['execution'] is not None:
                functions[identity] = optional(declaration['execution'])
        symbols = {**deepcopy(self.symbols), **deepcopy(self.symbol_declarations)}
        graph = deepcopy(self.abi_graph)
        nominal_aliases = {identity: ref(item['id']) for identity, item in self.nominals.items()}

        def nominal_equal(left, right):
            require(key(left) in nominal_aliases and key(right) in nominal_aliases, 'handler_nominal_reference')
            return graph.catch_compatible(nominal_aliases[key(left)], nominal_aliases[key(right)])

        dependencies = Dependencies(functions=functions, imports=self.imports, layouts=self.layouts.items,
                                    nominals=self.nominals, actions=self.recipes, symbols=symbols,
                                    cleanup_programs=self.programs, storage_bindings=self.storage_bindings,
                                    abi_signatures=self.signatures, bridges=self.bridges,
                                    abi_masks=self.abi_masks, host_descriptors=self.evidence.host_descriptors,
                                    tls={**self.tls_segments, **self.external_tls}, nominal_equal=nominal_equal,
                                    source_layout=self.source_layout, source_compatible=self.source_compatible)
        from candidate.bindings import validate
        for imported in self.imports.values():
            validate(imported, self.types, dependencies)
        self.execution_checked = verify(self.sections[1], self.sections[3], self.sections[8], dependencies,
                                        {identity: item for identity, item in self.types.items.items() if identity[0] != 'self'})
        if type(self) is RootContext:
            source_registry_api()._verified_execution(self, _REGISTRY_VERIFICATION_KEY)
        return self.execution_checked

    def component_result(self):
        self.assert_snapshot()
        require(self.abi_checked and self.execution_checked is not None, 'component_not_verified')
        return {'kind': 'verified_execution_declarations', 'requires_runtime_link_admission': True,
                'dependency_slots': sorted(self.dependencies), 'functions': len(self.sections[3]['functions']),
                'types': len(self.sections[1]['types']), 'layouts': len(self.sections[1]['memory_layouts'])}
