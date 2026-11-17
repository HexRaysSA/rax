"""Exact registered requirement support; module bytes cannot self-register it."""
from .errors import require

KINDS={'runtime','feature','catalog','library','native_image','personality','host'}


class RuntimeUnavailable(ValueError):
    """Valid static request lacking the actual runtime issuer, never malformed wire."""
    kind = 'unavailable'

    def __init__(self, code, detail=''):
        self.code, self.detail = code, detail
        super().__init__(code + (': ' + detail if detail else ''))


class Registry:
    def __init__(self,entries=()):
        self.entries=frozenset(entries)
        for kind,name,version in self.entries:
            require(kind in KINDS and type(name) is str and name and '\0' not in name and
                    type(version) is int and 0<version<2**32,'RT_REQUIREMENT_REGISTRY')

    def supports(self,record):
        return (record['kind'],record['name'],record['version']) in self.entries


def validate(records,support):
    keys=[]
    for record in records:
        require(record['kind'] in KINDS,'RT_REQUIREMENT_KIND')
        require(type(record['name']) is str and record['name'] and '\0' not in record['name'] and
                type(record['version']) is int and record['version']>0,'RT_REQUIREMENT_VALUE')
        if record['kind']=='native_image':
            require(len(record['name'])==64 and all(c in '0123456789abcdef' for c in record['name']),
                    'RT_REQUIREMENT_IMAGE')
        keys.append((record['kind'],record['name']))
    require(keys==sorted(set(keys)),'RT_REQUIREMENT_ORDER')
    for record in records:
        require(support is not None,'RT_REQUIREMENT_UNREGISTERED')
        require(support(record) is True,'RT_REQUIREMENT_UNSUPPORTED',
                f"{record['kind']}:{record['name']}@{record['version']}")
    return records
