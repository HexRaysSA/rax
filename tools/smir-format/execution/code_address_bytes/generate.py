"""Author only the new CodeAddress byte-relay corpus; --check is nonwriting."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[4]
if __name__ == '__main__':
    sys.path.insert(0, str(ROOT/'tools/smir-format/execution'))
from code_address_bytes.contract import EXPECTED, FOLDER, PROFILES, encoded_document


def product():
    producer = encoded_document('producer')
    rows = []
    for profile in PROFILES:
        wire = encoded_document(profile)
        rows.append(dict(id=profile, expected=EXPECTED.get(profile, 'code_address_invalid'),
            sha256=hashlib.sha256(wire).hexdigest(), bytes=len(wire), encoded_hex=wire.hex()))
    return (json.dumps(dict(format='codeaddress-raw8-relay-reference-fixtures', revision=1,
        scope='Original full module/ABI/body verification and actual reference registry; generic Raw8 calls. No source ABI2/LLVM compiler/native guest/importer or independent raw-storage lifetime proof.',
        producer=dict(sha256=hashlib.sha256(producer).hexdigest(), bytes=len(producer), encoded_hex=producer.hex()),
        cases=rows), indent=2)+'\n').encode()


if __name__ == '__main__':
    if sys.argv[1:] not in ([], ['--check']):
        raise SystemExit('usage: generate.py [--check]')
    raw = product()
    path = FOLDER/'cases.json'
    if '--check' in sys.argv:
        if path.read_bytes() != raw:
            raise SystemExit('CodeAddress byte-relay corpus drift')
    else:
        FOLDER.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    print(json.dumps(dict(cases=len(PROFILES), producer=1, files=1, bytes=len(raw), checked='--check' in sys.argv)))
