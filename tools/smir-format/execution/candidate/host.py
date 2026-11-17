"""Value-only host primitive metadata admission from independent factory records."""
import hashlib

from common import require
from candidate.type_system import Types, ref
from candidate.wire import decode, encode


def validate(imported, types, registered, records):
    require(imported['kind'] == 'host' and imported['capability'] == 'host_value', 'host_import_kind')
    require(imported['namespace'] and not imported['namespace'].startswith('smir.')
            and '\0' not in imported['namespace'] and imported['name'] and '\0' not in imported['name'], 'host_namespace')
    require(imported['descriptor'] in registered, 'host_descriptor_registry')
    raw = registered[imported['descriptor']]
    require(type(raw) is bytes, 'host_descriptor_bytes')
    descriptor = decode('runtime_host_descriptor', raw, records=records)
    require(encode('runtime_host_descriptor', descriptor, records=records) == raw
            and descriptor['revision'] == 1, 'host_descriptor_revision')
    require(hashlib.sha256(b'SMIR-HOST-V1\0' + raw).hexdigest() == imported['descriptor'], 'host_descriptor_digest')
    require(all(descriptor[field] == imported[field] for field in ['namespace', 'name', 'version']), 'host_descriptor_name')
    payload = bytes.fromhex(descriptor['types'])
    root = decode('execution_types', payload)
    require(encode('execution_types', root) == payload and root['payload_revision'] == 2
            and root['memory_layouts'] == [], 'host_type_root')
    factory_types = Types(root)
    signature = factory_types.get(ref(descriptor['signature']))
    require(signature['kind'] == 'function' and signature['cc'] == 'portable'
            and not signature['variadic'], 'host_signature')
    for child in signature['params'] + signature['results']:
        require(factory_types.get(child)['kind'] in {'int', 'float', 'raw'}, 'host_value_only')
    require(types.digest(imported['signature']) == factory_types.digest(ref(descriptor['signature'])), 'host_signature_identity')
    return descriptor
