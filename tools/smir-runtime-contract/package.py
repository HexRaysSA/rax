"""Exact project locator codec and deterministic launcher negotiation model."""
import hashlib
import struct

from schema import require, unique_list, validate

MAGIC = b'RAXSMIR\0'
LOCATOR = struct.Struct('<8sHHIQQ32s')


def encode_locator(offset, payload):
    require(type(offset) is int and 0 <= offset < 2**64, 'LOCATOR_OFFSET')
    require(offset + len(payload) <= 2**64, 'LOCATOR_OVERFLOW')
    return LOCATOR.pack(MAGIC, 1, 0, 0, offset, len(payload), hashlib.sha256(payload).digest())


def decode_locator(record, carrier, locator_range=None):
    require(len(record) == LOCATOR.size, 'LOCATOR_SIZE')
    magic, revision, flags, reserved, offset, length, digest = LOCATOR.unpack(record)
    require(magic == MAGIC and revision == 1, 'LOCATOR_VERSION')
    require(flags == reserved == 0, 'LOCATOR_RESERVED')
    require(length > 0 and offset + length <= len(carrier), 'LOCATOR_BOUNDS')
    if locator_range is not None:
        a, b = locator_range
        require(offset + length <= a or b <= offset, 'LOCATOR_OVERLAP')
    payload = carrier[offset:offset + length]
    require(hashlib.sha256(payload).digest() == digest, 'LOCATOR_HASH')
    return payload


def verify_package(document):
    validate(document, 'package')
    unique_list(document['required_capabilities'], 'DUPLICATE_CAPABILITY')
    unique_list(document['embedded_modules'], 'DUPLICATE_EMBEDDED_MODULE')
    locator = document['locator']
    require(locator['byte_length'] > 0 and
            locator['file_offset'] + locator['byte_length'] <= 2**64, 'PACKAGE_RANGE')
    require(document['entry'] is not None, 'LAUNCH_ENTRY')
    if document['carrier'] == 'raw':
        require(document['launch'] == 'explicit' and document['bootstrap_arch'] == 'none',
                'RAW_BOOTSTRAP')
        require(locator['file_offset'] == 0, 'RAW_OFFSET')
    if document['launch'] in {'installed', 'embedded'}:
        require(document['bootstrap_arch'] != 'none' and document['carrier'] != 'raw',
                'LAUNCH_BOOTSTRAP')
    if document['launch'] == 'embedded':
        require(document['runtime']['implementation'] is not None, 'EMBEDDED_RUNTIME')
        require(bool(document['embedded_modules']), 'EMBEDDED_MODULES')
    else:
        require(document['embedded_modules'] == [], 'UNEXPECTED_EMBEDDED_MODULES')
    return document


def select_runtime(candidates, manifest, host_arch, host_os):
    """Candidates arrive in explicit discovery order; never try a later fallback."""
    verify_package(manifest)
    require(manifest['launch'] == 'installed', 'DISCOVERY_LAUNCH_MODE')
    require(manifest['bootstrap_arch'] == host_arch, 'BOOTSTRAP_ARCH')
    require({'elf': 'linux', 'macho': 'macos', 'pe': 'windows'}[manifest['carrier']] == host_os,
            'BOOTSTRAP_OS')
    require(bool(candidates), 'RUNTIME_NOT_FOUND')
    runtime = candidates[0]
    required = manifest['runtime']
    require(runtime['arch'] == host_arch and runtime['os'] == host_os, 'RUNTIME_HOST')
    require(runtime['abi_major'] == required['abi_major'] and
            runtime['abi_minor'] >= required['abi_minor'] and
            runtime['revision'] >= required['minimum_revision'], 'RUNTIME_VERSION')
    require(required['implementation'] is None or
            runtime['identity'] == required['implementation'], 'RUNTIME_IDENTITY')
    require(set(manifest['required_capabilities']) <= set(runtime['capabilities']),
            'RUNTIME_CAPABILITY')
    return runtime
