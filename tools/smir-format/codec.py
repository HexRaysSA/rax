#!/usr/bin/env python3
"""Independent SMIR codecs and explicitly bounded reference execution."""
import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct

MAGIC = b'SMIR\r\n\x1a\n'
HEADER = struct.Struct('<8sHHHHIIQQII')
RECORD = struct.Struct('<HHIQQ')
NO_ENTRY = 0xffffffff
DEFAULT_MAX_BYTES = 1 << 30


class DecodeError(ValueError):
    def __init__(self, number):
        super().__init__(f'SMIR-E{number:03}')


class RecordError(ValueError):
    """Symbolic INT-008 draft error; not a published framing diagnostic."""


@dataclass(frozen=True)
class RecordLimits:
    max_bytes: int = 16 * 1024 * 1024
    max_nodes: int = 1_000_000
    max_depth: int = 64
    max_list: int = 65_536
    max_string: int = 1024 * 1024


class RecordCodec:
    """INT-008 ordered-record prototype, entirely separate from execution.

    Record definitions contain either ordered ``fields`` or token-tagged
    ``variants`` plus ``discriminator``. bytes uses Python bytes, hex uses paired
    lowercase hexadecimal, and digest32 uses exactly 64 lowercase hex digits.
    opt:T is None or exactly {'some': value}, preserving nested option states.
    Those last two are logical JSON representations of raw wire bytes.

    Work is O(schema size + payload bytes + visited values); storage is bounded
    by max_bytes/max_nodes/max_depth. This checks representation, not type/CFG,
    ABI identity, capability admission, or any guest execution prerequisite.
    """

    TOKEN = re.compile(r'[a-z][a-z0-9_]{0,62}\Z')
    INTEGERS = {f'{prefix}{bits}': (bits // 8, prefix == 'i')
                for prefix in ('u', 'i') for bits in (8, 16, 32, 64)}
    PRIMITIVES = set(INTEGERS) | {'bool', 'bytes', 'hex', 'utf8', 'token', 'digest32'}

    def __init__(self, records, limits=RecordLimits()):
        self.records = records
        self.limits = limits
        self._require(isinstance(limits, RecordLimits), 'WIRE-CONFIG')
        self._require(all(type(value) is int and value >= 0
                          for value in vars(limits).values()), 'WIRE-CONFIG')
        self._require(limits.max_depth <= 128, 'WIRE-CONFIG')
        self._require(type(records) is dict and records, 'WIRE-SCHEMA')
        for name, record in records.items():
            self._require(type(name) is str and self.TOKEN.fullmatch(name), 'WIRE-SCHEMA')
            self._require(name not in self.PRIMITIVES and type(record) is dict, 'WIRE-SCHEMA')
            if set(record) == {'fields'}:
                self._audit_fields(record['fields'])
            else:
                self._require(set(record) == {'discriminator', 'variants'}, 'WIRE-SCHEMA')
                discriminator = record['discriminator']
                self._require(type(discriminator) is str and self.TOKEN.fullmatch(discriminator),
                              'WIRE-SCHEMA')
                self._require(type(record['variants']) is dict and record['variants'], 'WIRE-SCHEMA')
                for tag, fields in record['variants'].items():
                    self._require(type(tag) is str and self.TOKEN.fullmatch(tag), 'WIRE-SCHEMA')
                    self._audit_fields(fields, discriminator)
        self.records = copy.deepcopy(records)

    @staticmethod
    def _require(condition, code):
        if not condition:
            raise RecordError(code)

    def _kind(self, kind):
        self._require(type(kind) is str, 'WIRE-SCHEMA')
        for _ in range(129):
            if kind.startswith(('vec:', 'opt:')):
                kind = kind[4:]
            else:
                self._require(kind in self.PRIMITIVES or kind in self.records, 'WIRE-SCHEMA')
                return
        raise RecordError('WIRE-SCHEMA')

    def _audit_fields(self, fields, discriminator=None):
        self._require(type(fields) is list, 'WIRE-SCHEMA')
        names = {discriminator} if discriminator is not None else set()
        for field in fields:
            self._require(type(field) is list and len(field) == 2, 'WIRE-SCHEMA')
            name, kind = field
            self._require(type(name) is str and self.TOKEN.fullmatch(name) and name not in names,
                          'WIRE-SCHEMA')
            names.add(name)
            self._kind(kind)

    def _layout(self, kind, value):
        record = self.records[kind]
        discriminator = record.get('discriminator')
        if discriminator is None:
            fields = record['fields']
        else:
            tag = value.get(discriminator)
            self._require(type(tag) is str and tag in record['variants'], 'WIRE-TAG')
            fields = record['variants'][tag]
        expected = {name for name, _ in fields}
        if discriminator is not None:
            expected.add(discriminator)
        self._require(value.keys() == expected, 'WIRE-TYPE')
        return fields, discriminator

    def _budget(self):
        nodes = 0

        def visit(depth):
            nonlocal nodes
            nodes += 1
            self._require(depth <= self.limits.max_depth and nodes <= self.limits.max_nodes,
                          'WIRE-LIMIT')

        return visit

    def encode(self, kind, value):
        self._kind(kind)
        output = bytearray()
        visit = self._budget()

        def append(data):
            self._require(len(data) <= self.limits.max_bytes - len(output), 'WIRE-LIMIT')
            output.extend(data)

        def emit(kind, value, depth):
            visit(depth)
            if kind.startswith('vec:'):
                self._require(type(value) is list, 'WIRE-TYPE')
                self._require(len(value) <= min(self.limits.max_list, 0xffffffff), 'WIRE-LIMIT')
                append(len(value).to_bytes(4, 'little'))
                for item in value:
                    emit(kind[4:], item, depth + 1)
            elif kind.startswith('opt:'):
                append(bytes([int(value is not None)]))
                if value is not None:
                    self._require(type(value) is dict and value.keys() == {'some'}, 'WIRE-TYPE')
                    emit(kind[4:], value['some'], depth + 1)
            elif kind in self.INTEGERS:
                size, signed = self.INTEGERS[kind]
                self._require(type(value) is int, 'WIRE-TYPE')
                minimum = -(1 << (size * 8 - 1)) if signed else 0
                maximum = (1 << (size * 8 - int(signed))) - 1
                self._require(minimum <= value <= maximum, 'WIRE-RANGE')
                append(value.to_bytes(size, 'little', signed=signed))
            elif kind == 'bool':
                self._require(type(value) is bool, 'WIRE-TYPE')
                append(bytes([int(value)]))
            elif kind in {'bytes', 'hex', 'digest32'}:
                if kind == 'bytes':
                    self._require(type(value) is bytes, 'WIRE-TYPE')
                    raw = value
                else:
                    self._require(type(value) is str and len(value) % 2 == 0
                                  and re.fullmatch(r'[0-9a-f]*', value), 'WIRE-TYPE')
                    self._require(len(value) // 2 <= self.limits.max_bytes, 'WIRE-LIMIT')
                    raw = bytes.fromhex(value)
                if kind == 'digest32':
                    self._require(len(raw) == 32, 'WIRE-RANGE')
                else:
                    self._require(len(raw) <= 0xffffffff, 'WIRE-LIMIT')
                    append(len(raw).to_bytes(4, 'little'))
                append(raw)
            elif kind in {'utf8', 'token'}:
                self._require(type(value) is str, 'WIRE-TYPE')
                self._require(len(value) <= min(self.limits.max_string, self.limits.max_bytes),
                              'WIRE-LIMIT')
                if kind == 'token':
                    self._require(self.TOKEN.fullmatch(value), 'WIRE-TEXT')
                try:
                    raw = value.encode('ascii' if kind == 'token' else 'utf-8')
                except UnicodeError as error:
                    raise RecordError('WIRE-TEXT') from error
                self._require(len(raw) <= min(self.limits.max_string, 0xffffffff), 'WIRE-LIMIT')
                append(len(raw).to_bytes(1 if kind == 'token' else 4, 'little'))
                append(raw)
            else:
                self._require(type(value) is dict, 'WIRE-TYPE')
                fields, discriminator = self._layout(kind, value)
                if discriminator is not None:
                    emit('token', value[discriminator], depth + 1)
                for name, field_type in fields:
                    emit(field_type, value[name], depth + 1)

        emit(kind, value, 0)
        return bytes(output)

    def decode(self, kind, payload):
        self._kind(kind)
        self._require(type(payload) is bytes, 'WIRE-TYPE')
        self._require(len(payload) <= self.limits.max_bytes, 'WIRE-LIMIT')
        cursor = 0
        visit = self._budget()

        def take(size):
            nonlocal cursor
            self._require(size <= len(payload) - cursor, 'WIRE-TRUNCATED')
            raw = payload[cursor:cursor + size]
            cursor += size
            return raw

        def number(size, signed=False):
            return int.from_bytes(take(size), 'little', signed=signed)

        def read(kind, depth):
            visit(depth)
            if kind.startswith('vec:'):
                count = number(4)
                self._require(count <= self.limits.max_list and count <= self.limits.max_nodes,
                              'WIRE-LIMIT')
                return [read(kind[4:], depth + 1) for _ in range(count)]
            if kind.startswith('opt:'):
                tag = number(1)
                self._require(tag <= 1, 'WIRE-TAG')
                return {'some': read(kind[4:], depth + 1)} if tag else None
            if kind in self.INTEGERS:
                size, signed = self.INTEGERS[kind]
                return number(size, signed)
            if kind == 'bool':
                value = number(1)
                self._require(value <= 1, 'WIRE-RANGE')
                return bool(value)
            if kind in {'bytes', 'hex', 'digest32'}:
                size = 32 if kind == 'digest32' else number(4)
                raw = take(size)
                return raw if kind == 'bytes' else raw.hex()
            if kind in {'utf8', 'token'}:
                size = number(1 if kind == 'token' else 4)
                self._require(size <= self.limits.max_string, 'WIRE-LIMIT')
                try:
                    value = take(size).decode('ascii' if kind == 'token' else 'utf-8')
                except UnicodeError as error:
                    raise RecordError('WIRE-TEXT') from error
                if kind == 'token':
                    self._require(self.TOKEN.fullmatch(value), 'WIRE-TEXT')
                return value
            record = self.records[kind]
            discriminator = record.get('discriminator')
            result = {}
            if discriminator is None:
                fields = record['fields']
            else:
                tag = read('token', depth + 1)
                self._require(tag in record['variants'], 'WIRE-TAG')
                result[discriminator] = tag
                fields = record['variants'][tag]
            for name, field_type in fields:
                result[name] = read(field_type, depth + 1)
            return result

        value = read(kind, 0)
        self._require(cursor == len(payload), 'WIRE-TRAILING')
        return value


def decode(data, max_bytes=DEFAULT_MAX_BYTES, max_sections=1024):
    """Validate framing in O(bytes + sections) time, retaining payload bytes."""
    return _decode_envelope(data, max_bytes, max_sections, candidate=False)


def decode_candidate(data, max_bytes=DEFAULT_MAX_BYTES, max_sections=1024):
    """Unverified 0.2/profile 2 framing; opaque payloads are not executable."""
    return _decode_envelope(data, max_bytes, max_sections, candidate=True)


def _decode_envelope(data, max_bytes, max_sections, *, candidate):
    revision = 2 if candidate else 1
    if len(data) > max_bytes:
        raise DecodeError(5)
    if len(data) < HEADER.size:
        raise DecodeError(1)
    magic, major, minor, kind, flags, profile, count, size, directory, entry, reserved = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise DecodeError(2)
    if (major, minor) != (0, revision):
        raise DecodeError(3)
    if kind not in (1, 2) or flags or profile != revision or size != len(data) or directory != 48 or reserved or (kind == 1 and entry != NO_ENTRY):
        raise DecodeError(4)
    if count > max_sections:
        raise DecodeError(5)
    cursor = 48 + count * 24
    if cursor > len(data):
        raise DecodeError(6)
    previous = 0
    sections = []
    for index in range(count):
        tag, attributes, reserved, offset, length = RECORD.unpack_from(data, 48 + index * 24)
        if tag <= previous or attributes > 1 or reserved:
            raise DecodeError(6)
        known = 1 <= tag <= (10 if candidate else 9) or 0x8000 <= tag <= 0x8002
        if (not known and (tag < 0x8000 or attributes)) or (tag < 0x8000 and attributes != 1) or (tag >= 0x8000 and attributes):
            raise DecodeError(8)
        start = (cursor + 7) // 8 * 8
        end = offset + length
        if offset != start or end > len(data):
            raise DecodeError(7)
        if any(data[cursor:start]):
            raise DecodeError(9)
        sections.append({'kind': tag, 'required': bool(attributes), 'hex': data[offset:end].hex()})
        previous = tag
        cursor = end
    if cursor != len(data):
        raise DecodeError(9)
    if candidate and sum(section['kind'] < 0x8000 for section in sections) != 10:
        raise DecodeError(8)
    return {'kind': kind, 'entry': entry, 'sections': sections}


def encode(module):
    """Emit canonical framing; input payloads remain semantically opaque."""
    return _encode_envelope(module, candidate=False)


def encode_candidate(module):
    """Emit candidate framing only, requiring all ten semantic section slots."""
    return _encode_envelope(module, candidate=True)


def _encode_envelope(module, *, candidate):
    # Python bool is an int subclass; JSON booleans are not integer IDs.
    if not isinstance(module, dict):
        raise ValueError('module must be an object')
    if type(module.get('kind')) is not int:
        raise ValueError('kind must be integer 1 or 2')
    if module['kind'] not in (1, 2):
        raise DecodeError(4)
    entry = module.get('entry', NO_ENTRY)
    if type(entry) is not int or not 0 <= entry <= NO_ENTRY:
        raise ValueError('entry must be a uint32 integer')
    if not isinstance(module.get('sections'), list):
        raise ValueError('sections must be an array')
    for section in module['sections']:
        if not isinstance(section, dict):
            raise ValueError('section must be an object')
        if type(section.get('kind')) is not int or not 0 <= section['kind'] <= 0xffff:
            raise ValueError('section kind must be a uint16 integer')
        if type(section.get('required')) is not bool:
            raise ValueError('required must be a boolean')
        if not isinstance(section.get('hex'), str):
            raise ValueError('hex must be a string')
    sections = sorted(module['sections'], key=lambda section: section['kind'])
    cursor = 48 + len(sections) * 24
    directory = bytearray()
    body = bytearray()
    for section in sections:
        start = (cursor + 7) // 8 * 8
        payload = bytes.fromhex(section['hex'])
        directory.extend(RECORD.pack(section['kind'], int(section['required']), 0, start, len(payload)))
        body.extend(bytes(start - cursor))
        body.extend(payload)
        cursor = start + len(payload)
    revision = 2 if candidate else 1
    result = HEADER.pack(MAGIC, 0, revision, module['kind'], 0, revision, len(sections), cursor, 48, entry, 0) + directory + body
    _decode_envelope(result, DEFAULT_MAX_BYTES, 1024, candidate=candidate)
    return result


@dataclass(frozen=True)
class UnverifiedCandidateModule:
    """Owned logical records, without executable type/CFG/ABI/link admission.

    The dictionaries remain mutable inspection data. This object is never an
    authority token and has no execution, linking or native-code entry method.
    """
    envelope: dict
    roots: dict
    content_digest: str


class CandidateCodec:
    """Full candidate payload representation, parameterized by schema snapshots.

    Common records shared by roles must match exactly. Hashing covers canonical
    required bytes only, with precisely manifest.identity replaced by zero bytes.
    This checks wire/root revision/content identity, not executable semantics.
    Work O(schema size + payload bytes + visited values), space O(the same),
    including owned record trees and canonical payload buffers.
    """
    ROOTS = {
        1: 'execution_types', 2: 'runtime_symbols', 3: 'execution_functions',
        4: 'runtime_data', 5: 'runtime_relocations', 6: 'runtime_imports',
        7: 'runtime_tls', 8: 'execution_exceptions', 9: 'runtime_capabilities',
        10: 'abi_contract',
    }
    # Assigned coherent ordinary-function-address cut. These are record grammar
    # revisions, independent of the unchanged 0.2 envelope/profile2 framing.
    PAYLOAD_REVISIONS = {1: 2, 2: 2, 3: 2, 4: 1, 5: 2,
                         6: 1, 7: 1, 8: 1, 9: 1, 10: 3}

    def __init__(self, schemas, limits=RecordLimits()):
        records = {}
        RecordCodec._require(type(schemas) is dict and set(schemas) == {'execution', 'runtime', 'abi'},
                             'WIRE-SCHEMA')
        for schema in schemas.values():
            RecordCodec._require(type(schema) is dict and type(schema.get('records')) is dict,
                                 'WIRE-SCHEMA')
            for name, record in schema['records'].items():
                RecordCodec._require(name not in records or records[name] == record,
                                     'WIRE-SCHEMA-CONFLICT')
                records[name] = record
        self.records = RecordCodec(records, limits)
        RecordCodec._require(all(root in records for root in self.ROOTS.values()), 'WIRE-SCHEMA')
        # The hash normalization targets a named field in the logical grammar;
        # no occurrence-based replacement or producer-selected byte range.
        manifest = records.get('module_manifest', {}).get('fields', [])
        RecordCodec._require(manifest[:1] == [['identity', 'digest32']] and
                             records['runtime_symbols'].get('fields', [])[:2] == [
                                 ['payload_revision', 'u32'], ['manifest', 'module_manifest']],
                             'WIRE-SCHEMA')

    def _payloads(self, roots):
        RecordCodec._require(type(roots) is dict and all(type(key) is int for key in roots)
                             and roots.keys() == self.ROOTS.keys(), 'WIRE-ROOTS')
        payloads = {}
        for identifier, root in self.ROOTS.items():
            RecordCodec._require(type(roots[identifier]) is dict, 'WIRE-TYPE')
            revision = roots[identifier].get('payload_revision')
            RecordCodec._require(type(revision) is int and
                                 revision == self.PAYLOAD_REVISIONS[identifier], 'WIRE-REVISION')
            payloads[identifier] = self.records.encode(root, roots[identifier])
        return payloads

    def _digest(self, roots, payloads):
        normalized = copy.deepcopy(roots[2])
        normalized['manifest']['identity'] = '00' * 32
        identity_payload = self.records.encode(self.ROOTS[2], normalized)
        digest = hashlib.sha256(b'SMIR0.2\0' + (2).to_bytes(4, 'little'))
        for identifier in self.ROOTS:
            payload = identity_payload if identifier == 2 else payloads[identifier]
            digest.update(identifier.to_bytes(2, 'little'))
            digest.update(len(payload).to_bytes(8, 'little'))
            digest.update(payload)
        return digest.hexdigest()

    def content_digest(self, roots):
        return self._digest(roots, self._payloads(roots))

    def encode(self, roots, *, kind=1, entry=NO_ENTRY, metadata=()):
        payloads = self._payloads(roots)
        digest = self._digest(roots, payloads)
        manifest_root = copy.deepcopy(roots[2])
        manifest_root['manifest']['identity'] = digest
        payloads[2] = self.records.encode(self.ROOTS[2], manifest_root)
        sections = [{'kind': identifier, 'required': True, 'hex': payload.hex()}
                    for identifier, payload in payloads.items()]
        for section in metadata:
            RecordCodec._require(type(section) is dict and type(section.get('kind')) is int
                                 and section['kind'] >= 0x8000, 'WIRE-METADATA')
            sections.append(section)
        return encode_candidate({'kind': kind, 'entry': entry, 'sections': sections})

    def decode(self, payload):
        envelope = decode_candidate(payload)
        roots = {}
        for section in envelope['sections']:
            identifier = section['kind']
            if identifier in self.ROOTS:
                RecordCodec._require(len(section['hex']) <= self.records.limits.max_bytes * 2,
                                     'WIRE-LIMIT')
                encoded = bytes.fromhex(section['hex'])
                # Read the common revision word before any schema-dependent
                # member: an earlier grammar must never be decoded as this cut.
                RecordCodec._require(len(encoded) >= 4 and
                                     int.from_bytes(encoded[:4], 'little') ==
                                     self.PAYLOAD_REVISIONS[identifier], 'WIRE-REVISION')
                roots[identifier] = self.records.decode(self.ROOTS[identifier], encoded)
        payloads = self._payloads(roots)
        digest = self._digest(roots, payloads)
        RecordCodec._require(roots[2]['manifest']['identity'] == digest, 'WIRE-IDENTITY')
        return UnverifiedCandidateModule(envelope, roots, digest)


def reference_report(payload, *, capabilities=()):
    """Inspect actual joined candidate contracts, without executable authority.

    Bounded initial command: one portable module, no external dependencies,
    COMDAT, native/host registrations or extra runtime feature requirements.
    Unsupported composition raises rather than using invented evidence.
    Owner semantic/ABI/runtime algorithms retain their documented resource bounds.
    """
    import sys
    repository = Path(__file__).resolve().parents[2]
    specification = repository / 'docs/specifications/smir/portable'
    schemas = {owner: json.loads((specification / 'schema' / owner / 'candidate.json').read_text())
               for owner in ('execution', 'runtime', 'abi')}
    decoded = CandidateCodec(schemas).decode(payload)
    sections = decoded.roots
    manifest = sections[2]['manifest']
    RecordCodec._require(manifest['kind'] in {'object', 'image'}, 'REFERENCE-MODULE-KIND')
    RecordCodec._require(decoded.envelope['kind'] == {'object': 1, 'image': 2}[manifest['kind']],
                         'REFERENCE-HEADER-KIND')
    entry = manifest['entry']
    RecordCodec._require(entry is None or entry['some']['module'] == {'kind': 'self'}, 'REFERENCE-ENTRY')
    RecordCodec._require(decoded.envelope['entry'] == (NO_ENTRY if entry is None else entry['some']['id']),
                         'REFERENCE-HEADER-ENTRY')
    for domain in sections[10]['domains']:
        if domain['isa'] != 'portable':
            RecordCodec._require(domain['isa'] == manifest['foreign_isa'] and
                                 domain['personality'] == manifest['personality'], 'REFERENCE-NATIVE-DOMAIN')
            raise RecordError('REFERENCE-INDEPENDENT-NATIVE-EVIDENCE-REQUIRED')
    RecordCodec._require(manifest['foreign_isa'] == 'none', 'REFERENCE-FOREIGN-SCOPE')
    RecordCodec._require(not manifest['dependencies'], 'REFERENCE-DEPENDENCY-SCOPE')
    RecordCodec._require(not sections[2]['comdats'], 'REFERENCE-COMDAT-SCOPE')
    RecordCodec._require(not sections[9]['requirements'], 'REFERENCE-REQUIREMENT-SCOPE')
    RecordCodec._require(all(item['kind'] not in {'foreign', 'host'} for item in sections[6]['imports']),
                         'REFERENCE-INDEPENDENT-IMPORT-REGISTRATION-REQUIRED')
    semantic_directory = repository / 'tools/smir-format/execution'
    # Owner tools deliberately use a local candidate/common package. Refuse a
    # conflicting embedded import environment; the CLI runs in its own process.
    for name, expected in [('candidate', semantic_directory / 'candidate/__init__.py'),
                           ('common', semantic_directory / 'common.py')]:
        loaded = sys.modules.get(name)
        RecordCodec._require(loaded is None or isinstance(getattr(loaded, '__file__', None), str) and
                             Path(loaded.__file__).resolve() == expected.resolve(),
                             'REFERENCE-IMPORT-CONTEXT: use the standalone CLI')
    sys.path.insert(0, str(semantic_directory))
    try:
        from candidate.context import RootContext
        from candidate.bindings import runtime_package_module
        context = RootContext(sections)
        abi = context.verify_abi()
        program = context.verify_execution()
        runtime = runtime_package_module('linking')
        RecordCodec._require(type(capabilities) in {tuple, list, set, frozenset} and
                             all(type(item) is str for item in capabilities) and
                             len(capabilities) == len(set(capabilities)) and
                             set(capabilities) <= runtime.CAPABILITIES, 'REFERENCE-CAPABILITY-GRANTS')
        RecordCodec._require(set(sections[9]['capabilities']) <= set(capabilities),
                             'REFERENCE-MANDATORY-CAPABILITY-GRANT')
        effective = set(sections[9]['capabilities']) & set(capabilities)
        RecordCodec._require(all(item['kind'] == 'internal' or item['capability'] in effective
                                 for item in sections[6]['imports']), 'REFERENCE-IMPORT-CAPABILITY-GRANT')
        def unsupported_comparison(*args):
            raise RecordError('REFERENCE-COMDAT-SCOPE')
        binding_context = runtime.Context(site=sections[10]['identity'], execution=context.execution,
            nominal=lambda reference: context.abi_entity('nominal', reference), function=context.function,
            symbol=context.runtime_symbol, execution_equal=context.types.equal,
            nominal_compatible=context.abi_graph.boundary_compatible, storage_layout=context.memory_layout,
            symbol_body=unsupported_comparison, symbol_identity=unsupported_comparison,
            abi_entity=context.abi_entity, target_entity=context.target_entity,
            native_symbol=context.native_symbol, nominal_layout=context.source_layout,
            grants=frozenset(capabilities), signature_compatible=context.abi_graph.signature_compatible,
            source_compatible=context.source_compatible)
        runtime.validate({number: sections[number] for number in runtime.ROOTS}, binding_context)
        identity = decoded.content_digest
        RecordCodec._require(runtime.content_identity({section['kind']: bytes.fromhex(section['hex'])
            for section in decoded.envelope['sections'] if section['kind'] in CandidateCodec.ROOTS}) == identity,
            'REFERENCE-CONTENT-IDENTITY')
        deployment = {'payload_revision': 1, 'modules': [{'key': manifest['key'], 'artifact': identity}], 'edges': []}
        def execution_equal(source, before, target, after):
            RecordCodec._require(source == target == identity, 'REFERENCE-DEPLOYMENT-SCOPE')
            return context.types.equal(before, after)
        def nominal_equal(source, before, target, after):
            RecordCodec._require(source == target == identity, 'REFERENCE-DEPLOYMENT-SCOPE')
            return context.abi_graph.boundary_compatible(before, after)
        plan = runtime.bind_deployment({identity: sections[2]}, deployment, execution_equal, nominal_equal)
        context.assert_snapshot()
        return {'reference_verified': True, 'production_admitted': False,
                'reference_scope': 'single-module-portable-no-comdat-or-feature-registrations',
                'content_digest': identity, 'kind': manifest['kind'], 'roots': 10,
                'functions': len(program.functions_root['functions']), 'abi': abi,
                'effective_capabilities': sorted(effective), 'components': plan['components']}
    finally:
        sys.path.remove(str(semantic_directory))


def reference_policy(payload):
    """Parse a closed, explicit policy; counts are logical resource units."""
    def pairs(items):
        result = {}
        for name, value in items:
            RecordCodec._require(name not in result, 'REFERENCE-POLICY-DUPLICATE')
            result[name] = value
        return result
    RecordCodec._require(type(payload) is bytes and len(payload) <= 65536, 'REFERENCE-POLICY-SIZE')
    result = json.loads(payload, object_pairs_hook=pairs)
    fields = {'fuel', 'max_frames', 'source_budget', 'registry'}
    source = {'max_work', 'max_edges', 'max_copied_bytes', 'max_depth'}
    registry = {'max_targets', 'max_permits', 'max_roots', 'max_activations', 'max_snapshots'}
    RecordCodec._require(type(result) is dict and result.keys() == fields, 'REFERENCE-POLICY')
    for name, expected in [('source_budget', source), ('registry', registry)]:
        RecordCodec._require(type(result[name]) is dict and result[name].keys() == expected,
                             'REFERENCE-POLICY')
    counts = [result['fuel'], result['max_frames'], *result['source_budget'].values(),
              *result['registry'].values()]
    RecordCodec._require(all(type(value) is int and 0 <= value < 2**64 for value in counts),
                         'REFERENCE-POLICY')
    RecordCodec._require(1 <= result['source_budget']['max_depth'] <= 128, 'REFERENCE-POLICY')
    return result


def _reference_source_plan_preflight(context, reference):
    """Finite source-call coverage after genuine ABI/execution verification.

    This classifier creates no source identity, ABI proof or runtime permit.
    It inspects original records; all semantic joins remain owner obligations.
    """
    def require(condition):
        RecordCodec._require(condition, 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')

    def local(item):
        require(item['module'] == {'kind': 'self'})

    def nominal(item):
        local(item)
        node = context.abi_entity('nominal', item)
        identity = node['identity']
        domain = context.abi_entity('nominal_domain', item)
        require(all(domain[name] == 'portable' for name in ('isa', 'abi', 'personality')))
        require(identity['language'] in {'c23', 'cpp23'} and identity['linkage'] == 'builtin'
                and identity['library'] is None and identity['unit'] is None)
        require(not node['qualifiers'] and not node['methods'] and not node['enumerators']
                and node['record_input'] is None)
        return node

    integers = {'signed char': (8, True), 'unsigned char': (8, False),
                'short': (16, True), 'unsigned short': (16, False),
                'int': (32, True), 'unsigned int': (32, False),
                'long': (64, True), 'unsigned long': (64, False),
                'long long': (64, True), 'unsigned long long': (64, False)}

    def scalar(item):
        node = nominal(item)
        shape = integers.get(node['identity']['entity'])
        require(node['kind'] == 'scalar' and shape is not None)
        width, signed = shape
        require(node['bits'] == width and node['signed'] == signed
                and node['representation'] == 'value' and not node['elements']
                and node['extent'] is None and node['layout'] is not None
                and set(node['flags']) == {'complete', 'trivial_copy', 'trivial_destroy'}
                and node['execution'] is not None)
        local(node['execution']['some'])
        execution = context.types.get(node['execution']['some'])
        require(execution['kind'] == 'int' and execution['bits'] == width)
        layout = context.source_layout(item)
        require(all(layout[name] == width // 8 for name in
                    ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align'))
                and not layout['fields'] and not layout['bases'] and not layout['vptrs'])
        return width

    def void(item):
        node = nominal(item)
        require(node['kind'] == 'void' and node['identity']['entity'] == 'void'
                and node['bits'] == 0 and not node['signed']
                and node['representation'] == 'none' and node['execution'] is None
                and node['layout'] is None and node['extent'] is None
                and set(node['flags']) <= {'complete', 'trivial_copy', 'trivial_destroy'}
                and not node['elements'])

    def value(item):
        node = nominal(item)
        if node['kind'] != 'pointer':
            return 'int', scalar(item)
        require(node['identity']['entity'] == 'pointer' and node['bits'] == 64
                and not node['signed'] and node['representation'] == 'value'
                and len(node['elements']) == 1 and node['extent'] is None
                and set(node['flags']) == {'complete', 'trivial_copy', 'trivial_destroy'}
                and node['execution'] is not None and node['layout'] is not None)
        pointee = node['elements'][0]
        if nominal(pointee)['kind'] == 'void':
            void(pointee)
        else:
            scalar(pointee)
        local(node['execution']['some'])
        execution = context.types.get(node['execution']['some'])
        require(execution['kind'] == 'data_ptr' and execution['space'] == 'guest_data')
        layout = context.source_layout(item)
        require(all(layout[name] == 8 for name in
                    ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align'))
                and not layout['fields'] and not layout['bases'] and not layout['vptrs'])
        return 'data_ptr', 64

    local(reference)
    plan = context.abi_entity('signature', reference)
    require(plan['this_type'] is None and not plan['vtt'] and not plan['variadic']
            and plan['varargs'] is None and not plan['noexcept'])
    function = nominal(plan['function_type'])
    require(function['kind'] == 'function' and function['identity']['entity'] == 'function'
            and function['bits'] == 0 and not function['signed'] and function['layout'] is None
            and 'complete' in function['flags']
            and set(function['flags']) <= {'complete', 'c_linkage'}
            and function['extent'] == {'some': len(plan['params'])}
            and len(function['elements']) == len(plan['params']) + 1
            and function['representation'] == ('signature' if function['execution'] is not None else 'none'))
    if function['execution'] is not None:
        local(function['execution']['some'])
    local(plan['execution'])
    physical = context.types.get(plan['execution'])
    require(physical['kind'] == 'function' and physical['cc'] == 'portable'
            and not physical['variadic']
            and len(plan['params']) == len(plan['lowered_params']) == len(physical['params']))
    for position, (source, lowered, actual) in enumerate(zip(
            plan['params'], plan['lowered_params'], physical['params'], strict=True)):
        kind, width = value(source)
        value(function['elements'][position])
        value(lowered['source_type'])
        value(lowered['value_type'])
        local(actual)
        typ = context.types.get(actual)
        require(lowered['role'] == 'parameter' and lowered['mode'] == 'direct'
                and lowered['source_index'] == {'some': position}
                and lowered['align'] == lowered['bytes'] == width // 8
                and all(lowered[name] is None for name in ('copy', 'move', 'destroy'))
                and typ['kind'] == kind and (kind == 'data_ptr' or typ['bits'] == width))
    if plan['result'] is None:
        void(function['elements'][-1])
        require(not plan['lowered_results'] and not physical['results'])
    else:
        kind, width = value(plan['result']['some'])
        value(function['elements'][-1])
        require(len(plan['lowered_results']) == len(physical['results']) == 1)
        value(plan['lowered_results'][0])
        local(physical['results'][0])
        result = context.types.get(physical['results'][0])
        require(result['kind'] == kind and (kind == 'data_ptr' or result['bits'] == width))


def _reference_scalar_preflight(context):
    """Check every body before attachment or guest effects, O(record count).

    Only scalar values and normal calls are supported here. The owner verifiers
    remain responsible for typing, SSA, literal validity and source authority.
    """
    scalar = {'int', 'raw', 'data_ptr', 'code_ptr', 'code_address'}
    integer = {'i_add', 'i_sub', 'i_mul', 'i_udiv', 'i_sdiv', 'i_urem', 'i_srem',
               'i_shl', 'i_lshr', 'i_ashr', 'i_and', 'i_or', 'i_xor', 'i_rotl',
               'i_rotr', 'i_clz', 'i_ctz', 'i_popcount', 'i_abs', 'i_bswap', 'i_bitreverse'}
    allowed = integer | {'constant', 'copy', 'freeze', 'icmp', 'select', 'trunc', 'zext',
                         'sext', 'bitcast', 'address_of', 'code_bind', 'code_erase', 'call'}
    RecordCodec._require(not context.sections[8]['functions'], 'REFERENCE-EXECUTION-EXCEPTION-SCOPE')
    RecordCodec._require(all(domain['isa'] == 'portable' for domain in context.sections[10]['domains']),
                         'REFERENCE-EXECUTION-NATIVE-SCOPE')
    def check_type(reference):
        item = context.types.get(reference)
        RecordCodec._require(item['kind'] in scalar and
                             (item['kind'] not in {'int', 'raw'} or item['bits'] <= 64) and
                             (item['kind'] != 'data_ptr' or item['space'] == 'guest_data'),
                             'REFERENCE-EXECUTION-TYPE-SCOPE')
    for symbol in context.sections[2]['symbols']:
        if symbol['kind'] == 'function' and symbol['source_linkage'] in {'c', 'cpp'}:
            RecordCodec._require(symbol['visibility'] == 'default',
                                 'REFERENCE-SOURCE-VISIBILITY-SCOPE')
    checked_plans = set()
    def check_plan(reference):
        identity = (reference['module']['kind'], reference['id'])
        if identity not in checked_plans:
            _reference_source_plan_preflight(context, reference)
            checked_plans.add(identity)

    for function in context.execution_checked.functions_root['functions']:
        signature = context.types.get(function['signature'])
        RecordCodec._require(not signature['variadic'], 'REFERENCE-EXECUTION-VARARGS-SCOPE')
        RecordCodec._require(signature['cc'] == 'portable', 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')
        if function['abi_signature'] is not None:
            check_plan(function['abi_signature']['some'])
        for reference in signature['params'] + signature['results']:
            check_type(reference)
        declarations = {item['id']: item['type'] for item in function['params']}
        for block in function['blocks']:
            declarations.update((phi['result']['id'], phi['result']['type']) for phi in block['phis'])
            declarations.update((item['id'], item['type'])
                                for operation in block['ops'] for item in operation['results'])
        for block in function['blocks']:
            for phi in block['phis']:
                check_type(phi['result']['type'])
            for operation in block['ops']:
                name = operation['op']
                RecordCodec._require(name in allowed, 'REFERENCE-EXECUTION-OPERATION-SCOPE')
                for output in operation['results']:
                    check_type(output['type'])
                involved = [declarations[item] for item in operation['operands']]
                involved.extend(item['type'] for item in operation['results'])
                if any(context.types.get(item)['kind'] == 'data_ptr' for item in involved):
                    RecordCodec._require(name in {'constant', 'copy', 'freeze', 'select', 'icmp', 'call'},
                                         'REFERENCE-NULL-DATAPTR-OPERATION-SCOPE')
                    if name == 'constant':
                        RecordCodec._require(operation['literal']['kind'] in {'zero', 'poison', 'undef'},
                                             'REFERENCE-NULL-DATAPTR-LITERAL-SCOPE')
                    if name == 'icmp':
                        RecordCodec._require(operation['predicate'] in {'eq', 'ne'},
                                             'REFERENCE-NULL-DATAPTR-OPERATION-SCOPE')
                if name == 'code_bind':
                    check_plan(operation['plan'])
                if name == 'call':
                    target = operation['target']
                    if operation['source_plan'] is None:
                        # A generic indirect entry must not consume a bound
                        # ordinary source pointer through the old code map.
                        RecordCodec._require(target['kind'] == 'direct' and
                            target['function']['module'] == {'kind': 'self'},
                            'REFERENCE-GENERIC-INDIRECT-CALL-SCOPE')
                    else:
                        check_plan(operation['source_plan']['some'])
                        RecordCodec._require(target['kind'] == 'indirect',
                                             'REFERENCE-SOURCE-DIRECT-CALL-SCOPE')
            RecordCodec._require(block['term']['op'] in {'return', 'jump', 'cbranch'},
                                 'REFERENCE-EXECUTION-TERMINATOR-SCOPE')


def run_reference(payload, *, entry_function, argument_bits, policy):
    """Run genuine owner admission and Machine factories; issue no production lease."""
    import importlib.util
    import sys
    policy = reference_policy(json.dumps(policy).encode())
    repository = Path(__file__).resolve().parents[2]
    specification = repository / 'docs/specifications/smir/portable'
    schemas = {owner: json.loads((specification / 'schema' / owner / 'candidate.json').read_text())
               for owner in ('execution', 'runtime', 'abi')}
    decoded = CandidateCodec(schemas).decode(payload)
    manifest = decoded.roots[2]['manifest']
    RecordCodec._require(manifest['kind'] == 'object' and decoded.envelope['kind'] == 1,
                         'REFERENCE-EXECUTION-OBJECT-SCOPE')
    declared_entry = manifest['entry']
    RecordCodec._require(declared_entry is None or declared_entry['some']['module'] == {'kind': 'self'},
                         'REFERENCE-ENTRY')
    RecordCodec._require(decoded.envelope['entry'] ==
                         (NO_ENTRY if declared_entry is None else declared_entry['some']['id']),
                         'REFERENCE-HEADER-ENTRY')
    RecordCodec._require(type(entry_function) is int and 0 <= entry_function < 2**32,
                         'REFERENCE-ENTRY-FUNCTION')
    RecordCodec._require(type(argument_bits) is list and all(type(value) is str and
                         re.fullmatch('[0-9a-f]{2,16}', value) and len(value) % 2 == 0 for value in argument_bits),
                         'REFERENCE-ARGUMENT-BITS')
    semantic_directory = repository / 'tools/smir-format/execution'
    for name, expected in [('candidate', semantic_directory / 'candidate/__init__.py'),
                           ('common', semantic_directory / 'common.py')]:
        loaded = sys.modules.get(name)
        RecordCodec._require(loaded is None or isinstance(getattr(loaded, '__file__', None), str) and
                             Path(loaded.__file__).resolve() == expected.resolve(),
                             'REFERENCE-IMPORT-CONTEXT: use the standalone CLI')
    sys.path.insert(0, str(semantic_directory))
    machine = None
    try:
        from candidate.context import RootContext
        from candidate.machine import Machine
        from candidate.values import Value
        context = RootContext(decoded.roots)
        context.verify_abi()
        context.verify_execution()
        _reference_scalar_preflight(context)
        functions = {function['id']: function for function in context.execution_checked.functions_root['functions']}
        RecordCodec._require(entry_function in functions, 'REFERENCE-ENTRY-FUNCTION')
        signature = context.types.get(functions[entry_function]['signature'])
        RecordCodec._require(all(context.types.get(reference)['kind'] != 'data_ptr'
                             for reference in signature['params'] + signature['results']),
                             'REFERENCE-EXECUTION-TYPE-SCOPE')
        RecordCodec._require(len(argument_bits) == len(signature['params']), 'REFERENCE-ARGUMENT-ARITY')
        for reference in signature['params'] + signature['results']:
            item = context.types.get(reference)
            RecordCodec._require(item['kind'] == 'int' and item['bits'] <= 64,
                                 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')
        for reference, bits in zip(signature['params'], argument_bits):
            width = context.types.get(reference)['bits']
            RecordCodec._require(len(bits) == 2 * ((width + 7) // 8) and
                                 int.from_bytes(bytes.fromhex(bits), 'little') < 1 << width,
                                 'REFERENCE-ARGUMENT-BITS')
        name = '_rax_smir_code_addresses_v1'
        path = repository / 'tools/smir-runtime-contract/source_roles/code_addresses.py'
        runtime = sys.modules.get(name)
        if runtime is None:
            spec = importlib.util.spec_from_file_location(name, path)
            runtime = importlib.util.module_from_spec(spec)
            sys.modules[name] = runtime
            try:
                spec.loader.exec_module(runtime)
            except BaseException:
                if sys.modules.get(name) is runtime:
                    del sys.modules[name]
                raise
        RecordCodec._require(getattr(runtime, '__file__', None) is not None and
                             Path(runtime.__file__).resolve() == path.resolve() and
                             getattr(runtime, '_CODE_ADDRESSES_READY', False) is True,
                             'REFERENCE-REGISTRY-MODULE-IDENTITY')
        try:
            budget = runtime._base.SD.SourceQueryBudget(**policy['source_budget'])
            source = context.source_registry_context(budget=budget)
            registry = runtime.CodeRegistry(budget=budget, policy=runtime.RegistryPolicy(**policy['registry']))
            machine = Machine(context.execution_checked)
            machine.attach_source_registry(registry, source, budget=budget)
            # Legacy CodePtr address producers also use the real shared pool.
            for symbol in decoded.roots[2]['symbols']:
                definition = symbol['definition']
                if symbol['kind'] == 'function' and definition is not None and definition['some']['kind'] == 'function':
                    target = definition['some']['target']
                    function = functions[target['id']]
                    machine.register_function({'module': {'kind': 'self'}, 'id': symbol['id']},
                                              target, function['signature'])
            arguments = [Value(reference, 'concrete', int.from_bytes(bytes.fromhex(bits), 'little'))
                         for reference, bits in zip(signature['params'], argument_bits)]
            machine.start(entry_function, arguments)
            result = machine.run(fuel=policy['fuel'], max_frames=policy['max_frames'])
        except (runtime.CodeRegistryError, runtime._base.SD.SourceDataError,
                sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError) as error:
            return {'status': 'reference-' + error.kind, 'code': error.code,
                    'steps': 0 if machine is None else machine.steps, 'production_admitted': False}
        report = {'status': 'reference-' + result['kind'], 'content_digest': decoded.content_digest,
                  'entry_function': entry_function, 'steps': machine.steps, 'production_admitted': False}
        if result['kind'] == 'return':
            # Poison/undef are observable states, never invented concrete bits.
            report['values'] = [({'bits_le': value.data.to_bytes(
                                    (context.types.get(reference)['bits'] + 7) // 8, 'little').hex()}
                                 if value.state == 'concrete' else {'state': value.state})
                                for reference, value in zip(signature['results'], result['values'], strict=True)]
        else:
            report.update(code=result.get('reason', result['kind']), language_ub=result['kind'] == 'language_ub')
            for field in ('activation', 'function', 'block', 'operation'):
                if field in result:
                    report[field] = result[field]
        return report
    finally:
        sys.path.remove(str(semantic_directory))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('encode', 'inspect', 'encode-candidate', 'inspect-candidate',
                                                       'verify-candidate-reference', 'run-candidate-reference'))
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--capability', action='append', default=[],
                        help='Explicit reference context grant; repeat for each capability')
    parser.add_argument('--entry-function', type=int)
    parser.add_argument('--argument-bits', action='append', default=[])
    parser.add_argument('--reference-policy', type=Path)
    args = parser.parse_args()
    if args.capability and args.operation != 'verify-candidate-reference':
        parser.error('--capability requires verify-candidate-reference')
    if args.operation == 'run-candidate-reference':
        if args.entry_function is None or args.reference_policy is None:
            parser.error('run-candidate-reference requires --entry-function and --reference-policy')
    elif args.entry_function is not None or args.argument_bits or args.reference_policy is not None:
        parser.error('reference execution arguments require run-candidate-reference')
    try:
        if args.operation.startswith('encode'):
            if args.output is None:
                parser.error('encode requires --output')
            encoder = encode_candidate if args.operation == 'encode-candidate' else encode
            args.output.write_bytes(encoder(json.loads(args.input.read_text())))
        else:
            with args.input.open('rb') as source:
                # Bound the read as well as the parser, including a file that
                # grows after opening. The extra byte establishes limit failure.
                data = source.read(DEFAULT_MAX_BYTES + 1)
            if args.operation == 'run-candidate-reference':
                with args.reference_policy.open('rb') as source:
                    policy = reference_policy(source.read(65537))
                result = run_reference(data, entry_function=args.entry_function,
                                       argument_bits=args.argument_bits, policy=policy)
            elif args.operation == 'verify-candidate-reference':
                result = reference_report(data, capabilities=args.capability)
            else:
                decoder = decode_candidate if args.operation == 'inspect-candidate' else decode
                result = decoder(data)
            print(json.dumps(result, indent=2))
            if args.operation == 'run-candidate-reference' and result['status'] != 'reference-return':
                parser.exit(2)
    except (ValueError, KeyError, struct.error) as error:
        if args.operation == 'run-candidate-reference':
            print(json.dumps({'status': 'reference-rejected', 'code': getattr(error, 'code', str(error)),
                              'production_admitted': False}))
            parser.exit(2)
        parser.exit(2, f'{error}\n')


if __name__ == '__main__':
    main()
