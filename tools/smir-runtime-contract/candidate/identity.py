"""Logical source-unit identities, independent of deployment artifacts (INT011)."""
import hashlib
import re
import struct

from .errors import require, uint


def utf8(value):
    require(type(value) is str and value and '\0' not in value, 'RT_IDENTITY_TEXT')
    try:
        encoded = value.encode('utf8', 'strict')
    except UnicodeError:
        require(False, 'RT_IDENTITY_TEXT')
    require(len(encoded) < 2**32, 'RT_IDENTITY_TEXT')
    return struct.pack('<I', len(encoded)) + encoded


def source_unit(namespace, name, project_unit_key, abi_major):
    # Reject absolute POSIX, drive and UNC forms. Relative keys are opaque UTF8:
    # a/../b, case and Unicode normalization are never silently rewritten.
    require(type(project_unit_key) is str and not project_unit_key.startswith(('/', '\\'))
            and re.match(r'^[A-Za-z]:', project_unit_key) is None, 'RT_UNIT_ABSOLUTE')
    uint(abi_major, 32)
    raw = b'rax.source.unit.v1\0' + utf8(namespace) + utf8(name) + utf8(project_unit_key)
    return hashlib.sha256(raw + struct.pack('<I', abi_major)).hexdigest()
