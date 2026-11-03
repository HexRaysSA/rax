"""Reconstruct the independently compiled native QueryPolicy0 control source."""
from pathlib import Path
import argparse
import hashlib
import json

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["response", "input"])
destination = parser.add_mutually_exclusive_group(required=True)
destination.add_argument("--output", type=Path)
destination.add_argument("--check", action="store_true")
args = parser.parse_args()
here = Path(__file__).resolve().parent
packets = json.loads((here / f"cipher-{args.mode}-requests-v1.json").read_text())
arrays = []
for index, packet in enumerate(packets):
    data = bytes.fromhex(packet)
    arrays.append(f"static const unsigned char packet_{index}[] = {{" + ",".join(map(str, data)) + "};")
arrays.append("struct Case { const unsigned char *data; ULONG bytes; };")
arrays.append("static const Case cases[] = {" + ",".join(
    f"{{packet_{i},sizeof(packet_{i})}}" for i in range(len(packets))) + "};")
template = (here / f"cipher-{args.mode}-v1.cpp.in").read_text()
assert template.count("@ARRAYS@") == 1
source = template.replace("@ARRAYS@", "\n".join(arrays)).encode()
bindings = json.loads((here / "probe-source-bindings-v1.json").read_text())
binding = next(row for row in bindings if row.get("mode") == args.mode)
assert hashlib.sha256(source).hexdigest() == binding["source_sha256"]
if args.check:
    print(json.dumps({"mode": args.mode, "sha256": binding["source_sha256"], "bytes": len(source)}))
    raise SystemExit(0)
output = args.output.resolve()
if not output.is_relative_to(here.parents[3]):
    raise SystemExit("Generated native source must remain inside this repository")
if output.exists() and output.read_bytes() != source:
    raise SystemExit("Refusing to overwrite a different existing source")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(source)
