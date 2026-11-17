"""Read-only current source-corpus consistency check, not admission or execution."""

import hashlib
import json

from .generate import OUT, documents


def check():
    result = {}
    for name, document in documents().items():
        expected = (json.dumps(document, indent=2) + '\n').encode('utf8')
        actual = (OUT / (name + '.json')).read_bytes()
        if actual != expected:
            raise ValueError('ABI_FUNCTION_ADDRESS_SOURCE_DRIFT: ' + name)
        result[name] = dict(sha256=hashlib.sha256(actual).hexdigest(), bytes=len(actual), cases=len(document['cases']))
    return result


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
