"""Pinned portable libc++/libc++abi/logical-unwinder site choices."""

import hashlib
import json
from pathlib import Path

PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
OPTIONS = {
    'LIBCXX_ABI_VERSION': '1', 'LIBCXX_ABI_NAMESPACE': '__1',
    'LIBCXX_ABI_UNSTABLE': 'OFF', 'LIBCXX_ABI_FORCE_ITANIUM': 'ON',
    'LIBCXX_ABI_FORCE_MICROSOFT': 'OFF', 'LIBCXX_ABI_DEFINES': '',
    'LIBCXX_ENABLE_EXCEPTIONS': 'ON', 'LIBCXX_ENABLE_RTTI': 'ON',
    'LIBCXX_ENABLE_THREADS': 'ON', 'LIBCXX_HAS_EXTERNAL_THREAD_API': 'ON',
    'LIBCXX_HAS_PTHREAD_API': 'OFF', 'LIBCXX_HAS_WIN32_THREAD_API': 'OFF',
    'LIBCXX_HAS_C11_THREAD_API': 'OFF', 'LIBCXX_ENABLE_MONOTONIC_CLOCK': 'ON',
    'LIBCXX_ENABLE_FILESYSTEM': 'ON', 'LIBCXX_ENABLE_RANDOM_DEVICE': 'ON',
    'LIBCXX_ENABLE_LOCALIZATION': 'ON', 'LIBCXX_ENABLE_UNICODE': 'ON',
    'LIBCXX_ENABLE_WIDE_CHARACTERS': 'ON', 'LIBCXX_ENABLE_TIME_ZONE_DATABASE': 'ON',
    'LIBCXX_HARDENING_MODE': 'none', 'LIBCXX_ENABLE_SHARED': 'OFF',
    'LIBCXX_ASSERTION_SEMANTIC': 'ignore', 'LIBCXX_TYPEINFO_COMPARISON_IMPLEMENTATION': '1',
    'LIBCXX_ENABLE_STATIC': 'ON', 'LIBCXX_CXX_ABI': 'libcxxabi',
    'LIBCXX_HAS_MUSL_LIBC': 'OFF', 'LIBCXX_EXTRA_SITE_DEFINES': '',
    'LIBCXXABI_ENABLE_EXCEPTIONS': 'ON', 'LIBCXXABI_ENABLE_THREADS': 'ON',
    'LIBCXXABI_HAS_EXTERNAL_THREAD_API': 'ON', 'LIBCXXABI_HAS_PTHREAD_API': 'OFF',
    'LIBCXXABI_HAS_WIN32_THREAD_API': 'OFF', 'LIBCXXABI_ENABLE_FORGIVING_DYNAMIC_CAST': 'OFF',
    'LIBCXXABI_ENABLE_NEW_DELETE_DEFINITIONS': 'ON',
    'LIBCXXABI_ENABLE_SHARED': 'OFF', 'LIBCXXABI_ENABLE_STATIC': 'ON',
    'LIBCXXABI_USE_LLVM_UNWINDER': 'ON', 'LIBCXXABI_ENABLE_STATIC_UNWINDER': 'ON',
    'LIBCXXABI_USE_COMPILER_RT': 'ON', 'LIBUNWIND_ENABLE_THREADS': 'ON',
    'LIBUNWIND_USE_COMPILER_RT': 'ON', 'LIBUNWIND_ENABLE_SHARED': 'OFF',
    'LIBUNWIND_ENABLE_STATIC': 'ON', 'LIBUNWIND_ENABLE_CROSS_UNWINDING': 'ON',
    'LIBUNWIND_ENABLE_FRAME_APIS': 'ON', 'LIBUNWIND_ENABLE_CET': 'OFF',
    'LIBUNWIND_ENABLE_GCS': 'OFF', 'LIBUNWIND_USE_FRAME_HEADER_CACHE': 'OFF',
}
MACROS = {
    '_LIBCPP_ABI_VERSION': '1', '_LIBCPP_ABI_NAMESPACE': '__1',
    '_LIBCPP_ABI_FORCE_ITANIUM': '1', '_LIBCPP_ABI_FORCE_MICROSOFT': '0',
    '_LIBCPP_HAS_THREADS': '1', '_LIBCPP_HAS_MONOTONIC_CLOCK': '1',
    '_LIBCPP_HAS_MUSL_LIBC': '0', '_LIBCPP_HAS_THREAD_API_PTHREAD': '0',
    '_LIBCPP_HAS_THREAD_API_EXTERNAL': '1', '_LIBCPP_HAS_THREAD_API_WIN32': '0',
    '_LIBCPP_HAS_THREAD_API_C11': '0', '_LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS': '0',
    '_LIBCPP_NO_VCRUNTIME': '1', '_LIBCPP_TYPEINFO_COMPARISON_IMPLEMENTATION': '1',
    '_LIBCPP_HAS_FILESYSTEM': '1', '_LIBCPP_HAS_RANDOM_DEVICE': '1',
    '_LIBCPP_HAS_LOCALIZATION': '1', '_LIBCPP_HAS_UNICODE': '1',
    '_LIBCPP_HAS_WIDE_CHARACTERS': '1', '_LIBCPP_HAS_TIME_ZONE_DATABASE': '1',
    '_LIBCPP_INSTRUMENTED_WITH_ASAN': '0', '_LIBCPP_PSTL_BACKEND_STD_THREAD': '',
    '_LIBCPP_HARDENING_MODE_DEFAULT': '_LIBCPP_HARDENING_MODE_NONE',
    '_LIBCPP_ASSERTION_SEMANTIC_DEFAULT': '_LIBCPP_ASSERTION_SEMANTIC_IGNORE',
    '_LIBCPP_LIBC_PICOLIBC': '0', '_LIBCPP_LIBC_NEWLIB': '0', '_LIBCPP_LIBC_LLVM_LIBC': '1',
    '_LIBCPP_ABI_RAX_EXCEPTION_PTR': '1',
}
UNDEFINED = ['_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS', '_LIBCPP_PSTL_BACKEND_SERIAL',
             '_LIBCPP_PSTL_BACKEND_LIBDISPATCH', '_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT',
             '_LIBCPP_ABI_BOUNDED_UNIQUE_PTR']


def _revision(value):
    if type(value) is not int or value not in (1, 2):
        raise ValueError('ABI_CC_SITE_REVISION')


def config(*, platform_source_abi_revision=1):
    _revision(platform_source_abi_revision)
    if platform_source_abi_revision == 2:
        from copy import deepcopy
        value = deepcopy(config(platform_source_abi_revision=1))
        value.update(platform_source_abi_revision=2, source_byte_projection="raw8-v1")
        return value
    return {'revision': 'portable-site-candidate-v1', 'llvm': PIN,
            'cmake': OPTIONS, 'defined_macros': MACROS, 'undefined_macros': UNDEFINED,
            'abi_flag_policy': 'all other ABI switches follow pinned stable ABI1; no user ABI_DEFINES',
            'clang_cxxabi': {'family': 'generic_itanium', 'compatibility': 'latest_at_pin',
                             'arm_member_pointer': False, 'arm_guard': False,
                             'relative_vtables': False, 'rtti': True, 'exceptions': True},
            'unwinder_backend': 'libunwind_api_with_rax_logical_and_foreign_domain_personalities',
            'portable_private_eh': {'revision': 1, 'exception_value': 'ssa_only',
                'lexical_slots': 'eliminate_before_all_optimization_and_emission',
                'exception_ptr': {'size_bytes': 8, 'alignment_bytes': 8,
                    'field': 'data_ptr_to_canonical_process_owner_proxy',
                    'proxy_size_bytes': 32, 'proxy_alignment_bytes': 8,
                    'proxy_fields': ['revision:u32=1', 'reserved:u32=0', 'proxy_id:u64',
                                     'payload_id:u64', 'generation:u64'],
                    'authority': 'registered_object_origin_and_live_generation'},
                'native_cxa_compatibility': False},
            'thread_backend': 'libcxx_external_api_and_portable_thread_helpers',
            'atomics': 'guarded_lock_full_storage_or_explicit_value_mask',
            'native_host_linking': False, 'installed_headers': 'dedicated_smir_sysroot',
            'build_semantics': 'options are selected port contract; not claim unmodified upstream builds',
            'foreign_libraries': 'retain exact owner build/site identity; never replace by portable site'}


def site_record(*, platform_source_abi_revision=1):
    _revision(platform_source_abi_revision)
    manifest = config(platform_source_abi_revision=platform_source_abi_revision)
    options = [{'name': name, 'state': 'cmake', 'value': value} for name, value in OPTIONS.items()]
    options += [{'name': name, 'state': 'defined', 'value': value} for name, value in MACROS.items()]
    options += [{'name': name, 'state': 'undefined', 'value': ''} for name in UNDEFINED]
    if platform_source_abi_revision == 2:
        options.append({'name': 'RAX_PORTABLE_SOURCE_ABI_REVISION', 'state': 'contract', 'value': '2'})
    return {'llvm': PIN, 'cxxabi': 'generic_itanium', 'compatibility': 'latest_at_pin',
            'libcxx_abi': 1, 'namespace': '__1', 'thread_api': 'external',
            'unwinder': 'rax_logical_libunwind', 'options': sorted(options, key=lambda x: (x['name'], x['state']))}


def identity(*, platform_source_abi_revision=1):
    return hashlib.sha256(json.dumps(config(platform_source_abi_revision=platform_source_abi_revision), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def header():
    lines = ['#ifndef _LIBCPP___CONFIG_SITE', '#define _LIBCPP___CONFIG_SITE']
    lines += ['#define ' + name + (' ' + value if value else '') for name, value in MACROS.items()]
    lines += ['#undef ' + name for name in UNDEFINED]
    return '\n'.join(lines + ['#endif', ''])


# Trusted immutable known-profile text; construction is bounded module metadata,
# never caller-supplied source evidence. Per-query input/serialization/comparison
# stages below retain their own charges. Legacy config/header APIs stay unchanged.
_KNOWN_IDENTITIES = {n: identity(platform_source_abi_revision=n) for n in (1, 2)}
_KNOWN_OPTION_COUNT = len(site_record(platform_source_abi_revision=2)['options'])
_KNOWN_SITES = {n: json.dumps(site_record(platform_source_abi_revision=n),
    sort_keys=True, separators=(',', ':'), ensure_ascii=True) for n in (1, 2)}


def original_profile(root, *, budget=None):
    """Recognize exact original ABI root metadata; result is not source evidence."""
    import factory_meter as M
    from layout import ABIError
    M.check_budget(budget)
    M.charge(budget, work=1, copied_bytes=64)
    if type(root) is not dict or len(root) > 256:
        raise ABIError('ABI_CC_SITE')
    M.charge(budget, work=len(root), edges=len(root))
    for key in root:
        if type(key) is not str:
            raise ABIError('ABI_CC_SITE')
    site, identity_value = root.get('site'), root.get('identity')
    if type(identity_value) is not str or len(identity_value) != 64:
        raise ABIError('ABI_CC_SITE')
    # Exact builtins and bounded traversal before any equality/JSON delegation.
    pending = [(site, 1)]
    nodes = 0
    ascii_bound = 0
    while pending:
        M.charge(budget, work=1)
        value, depth = pending.pop()
        nodes += 1
        if ascii_bound > 1 << 20:
            raise ABIError('ABI_CC_SITE')
        if nodes > 16384 or depth > 16:
            raise ABIError('ABI_CC_SITE')
        if type(value) is dict:
            ascii_bound += 2 + 2*len(value)
            M.charge(budget, work=len(value), edges=2*len(value), copied_bytes=128*len(value))
            for key in value:
                if type(key) is not str or len(key) > 4096:
                    raise ABIError('ABI_CC_SITE')
            pending.extend((x, depth+1) for x in value.keys())
            pending.extend((x, depth+1) for x in value.values())
        elif type(value) is list:
            ascii_bound += 2 + len(value)
            M.charge(budget, work=len(value), edges=len(value), copied_bytes=64*len(value))
            pending.extend((x, depth+1) for x in value)
        elif type(value) is str:
            if len(value) > 256:
                raise ABIError('ABI_CC_SITE')
            ascii_bound += 12*len(value)+2
            M.charge(budget, work=len(value))
        elif type(value) is int:
            if not 0 <= value < 2**64:
                raise ABIError('ABI_CC_SITE')
        elif value is not None and type(value) is not bool:
            raise ABIError('ABI_CC_SITE')
    if ascii_bound > 1 << 20:
        raise ABIError('ABI_CC_SITE')
    if type(site) is not dict or type(site.get('options')) is not list:
        raise ABIError('ABI_CC_SITE')
    M.collection(budget, len(site), 64)
    if set(site) != {'llvm','cxxabi','compatibility','libcxx_abi','namespace','thread_api','unwinder','options'}:
        raise ABIError('ABI_CC_SITE')
    for key in ('llvm','cxxabi','compatibility','namespace','thread_api','unwinder'):
        if type(site[key]) is not str:
            raise ABIError('ABI_CC_SITE')
    if type(site['libcxx_abi']) is not int:
        raise ABIError('ABI_CC_SITE')
    if len(site['options']) > _KNOWN_OPTION_COUNT:
        raise ABIError('ABI_CC_SITE')
    revision = 1
    found = False
    M.collection(budget, len(site['options']), 256)
    for row in site['options']:
        if type(row) is not dict:
            raise ABIError('ABI_CC_SITE')
        M.collection(budget,len(row),16)
        if set(row) != {'name','state','value'} or any(type(row[k]) is not str for k in ('name','state','value')):
            raise ABIError('ABI_CC_SITE')
        if row.get('name') == 'RAX_PORTABLE_SOURCE_ABI_REVISION':
            if found or row.get('state') != 'contract' or row.get('value') != '2':
                raise ABIError('ABI_CC_SITE')
            found = True
            revision = 2
    text = M.encoded_json(site, budget)
    expected = _KNOWN_SITES[revision]
    M.charge(budget, work=len(text)+len(expected)+128)
    if text != expected or identity_value != _KNOWN_IDENTITIES[revision]:
        raise ABIError('ABI_CC_SITE')
    return revision


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2] / 'docs/specifications/smir/portable/schema/abi'
    (root / 'site.json').write_text(json.dumps(config(), indent=2) + '\n')
