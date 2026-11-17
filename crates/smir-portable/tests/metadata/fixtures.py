"""Generate owned raw-context fixtures with the frozen independent Python codec.

These are framing-valid metadata tests, not executable admission certificates.
No frozen source/fixture is regenerated. Run with Python -B from the repo root.
"""
from fixture_provenance import provenance, write_bytes, write_text
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/smir-format"))
from codec import CandidateCodec
sys.path.insert(0, str(ROOT / "tools/smir-runtime-contract"))
from generate_service_type_fixtures import prepare_abi2_nonrecord_source

SPEC = ROOT / "docs/specifications/smir/portable"
SCHEMAS = {name: json.loads((SPEC / "schema" / name / "candidate.json").read_text())
           for name in ("execution", "runtime", "abi")}


def prepare_declared_abi2_source(roots):
    """Preserve explicit ABI2 record producer inputs; never derive missing ones.

    The independent source producer supplied and sealed these declarations.
    This structural check is not semantic admission; actual ABI tests still run.
    """
    contract = roots[10]
    if any(item['kind'] == 'record' for item in contract['types']):
        if contract['payload_revision'] != 3:
            raise ValueError('explicit records require source ABI3 producer')
        if any('execution' not in signature for signature in contract['signatures']):
            raise ValueError('explicit records require authored plan.execution')
        for item in contract['types']:
            if item['kind'] == 'record' and 'complete' in item['flags'] and item['record_input'] is None:
                raise ValueError('missing explicit complete source record input')
        return roots
    return prepare_abi2_nonrecord_source(roots)


def ref(identity):
    return {"module": {"kind": "self"}, "id": identity}


def some(value):
    return {"some": value}


def helper_catalog_digest():
    catalog = json.loads((SPEC / 'schema/runtime/helpers-v1.json').read_text())
    raw = json.dumps(catalog, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False).encode('ascii')
    return hashlib.sha256(b'SMIR-HELPERS-V1\0' + raw).hexdigest()


def build():
    roots = {int(k): v for k, v in json.loads((SPEC / "conformance/execution/candidate/portable-identity.json").read_text())["sections"].items()}
    roots[5] = {"payload_revision": 2, "relocations": [], "constant_initializers": []}
    roots[7] = {"payload_revision": 1, "segments": []}
    roots[9] = {"payload_revision": 1, "capabilities": [], "requirements": [], "limits": []}
    storage_type = max(value["id"] for value in roots[1]["types"]) + 1
    roots[1]["types"].append({"id": storage_type, "kind": "array", "element": ref(9), "count": 4})
    segment = {"id": 12, "layout": None, "nominal": None, "abi_binding": None, "alignment": 1,
               "mutable": False, "initial": "010203", "poison": "000000", "undef": "000000",
               "zero_fill": 1, "zero_shadow": "defined"}
    roots[4]["segments"] = [segment]
    roots[7]["segments"] = [{"storage": deepcopy(segment), "initializers": [], "destructors": [], "initialization": "static"}]
    symbol = {"id": 1, "namespace": "metadata", "name": "bytes", "kind": "data", "source_linkage": "none",
              "binding": "strong", "visibility": "default", "execution": ref(storage_type), "nominal": None,
              "abi_signature": None, "definition": some({"kind": "data", "segment": 12}), "size": some(4),
              "alignment": 1, "comdat": None, "fallback": None}
    roots[2]["symbols"].append(symbol)
    for identity, name, kind, definition, binding in [
        (2, "alias", "data", {"kind": "alias", "target": ref(1)}, "strong"),
        (3, "tls", "tls", {"kind": "tls", "segment": 12}, "strong"),
        (4, "missing", "data", None, "weak"),
    ]:
        item = deepcopy(symbol)
        item.update(id=identity, name=name, kind=kind, definition=None if definition is None else some(definition), binding=binding)
        roots[2]["symbols"].append(item)
    roots[2]["manifest"]["dependencies"] = [{"slot": 3, "key": {"namespace": "metadata", "name": "provider", "abi_major": 1, "abi_minor": 0},
        "minimum_minor": 0, "maximum_minor": None, "site": roots[2]["manifest"]["site"],
        "declarations": [{"id": 99, "kind": "symbol", "symbol_kind": "data", "source_linkage": "none",
                          "namespace": "metadata", "name": "external", "execution": some(ref(storage_type)),
                          "nominal": None, "abi_signature": None, "weak": False}]}]
    roots[5]["relocations"] = [{"source_kind": "data", "source": 12, "offset": 1, "width": 1,
        "integer_bits": 8, "kind": "data_integer", "target": ref(1), "addend": 0, "derivation": [],
        "check_base": False, "flags": [], "inrange": None}]
    return roots


def main():
    folder = Path(__file__).with_suffix("")
    folder.mkdir(exist_ok=True)
    base = build()
    cases = {"base": base}
    scalar_profile = {int(k): v for k, v in json.loads((SPEC / "conformance/execution/candidate/portable-identity.json").read_text())["sections"].items()}
    scalar_profile[5] = {"payload_revision": 2, "relocations": [], "constant_initializers": []}
    scalar_profile[7] = {"payload_revision": 1, "segments": []}
    scalar_profile[9] = {"payload_revision": 1, "capabilities": [], "requirements": [], "limits": []}
    cases["scalar-profile"] = scalar_profile
    # Domain IDs are alpha-renamable local identifiers. Source identity
    # fingerprints do not include the arbitrary domain table identifier.
    for domain_id in (0, 1, 19, 65537, 0xfffffffe):
        changed = deepcopy(scalar_profile)
        changed[10]["domains"][0]["id"] = domain_id
        for nominal in changed[10]["types"]:
            nominal["domain"] = domain_id
        cases[f"scalar-profile-domain-{domain_id}"] = changed
        missing = deepcopy(changed)
        missing[2]["symbols"][0]["abi_signature"] = None
        cases[f"scalar-profile-domain-{domain_id}-missing-plan"] = missing
    changed = deepcopy(scalar_profile)
    changed[2]["symbols"][0]["visibility"] = "hidden"
    cases["scalar-profile-hidden"] = changed
    changed = deepcopy(scalar_profile)
    changed[9]["capabilities"] = ["clock"]
    cases["scalar-profile-unused-capability"] = changed
    changed = deepcopy(scalar_profile)
    changed[4]["segments"] = deepcopy(base[4]["segments"])
    cases["scalar-profile-unused-data"] = changed
    changed = deepcopy(scalar_profile)
    changed[2]["symbols"][0]["kind"] = "data"
    cases["scalar-profile-function-as-data"] = changed
    changed = deepcopy(scalar_profile)
    changed[2]["symbols"][0]["execution"] = ref(9)
    cases["scalar-profile-bad-execution"] = changed
    changed = deepcopy(scalar_profile)
    changed[2]["symbols"][0]["nominal"] = some(ref(1))
    cases["scalar-profile-bad-source"] = changed
    changed = deepcopy(scalar_profile)
    changed[3]["functions"][0]["blocks"][0]["term"]["values"] = [99]
    cases["scalar-profile-bad-ssa"] = changed
    for name, field, value in [("mutable", "mutable", True), ("poison", "poison", "010000"), ("undef", "undef", "010000")]:
        case = deepcopy(base)
        case[4]["segments"][0][field] = value
        cases[name] = case
    case = deepcopy(base)
    case[2]["symbols"][1]["size"] = some(3)
    cases["wrong-size"] = case
    case = deepcopy(base)
    extent = (1 << 61) - 1
    case[4]["segments"][0]["zero_fill"] = extent - 3
    case[2]["symbols"][1]["size"] = some(extent)
    case[1]["types"][-1]["count"] = extent
    cases["huge-tail"] = case
    case = deepcopy(base)
    case[2]["symbols"][2]["definition"] = some({"kind": "alias", "target": ref(2)})
    cases["alias-cycle"] = case
    case = deepcopy(base)
    case[2]["symbols"][4]["fallback"] = some(ref(4))
    cases["fallback-cycle"] = case
    case = deepcopy(base)
    case[2]["symbols"][2]["kind"] = "tls"
    cases["alias-kind"] = case
    case = deepcopy(base)
    for symbol in case[2]["symbols"][1:3]:
        symbol["comdat"] = some(0)
    case[2]["comdats"] = [{"id": 0, "namespace": "metadata", "name": "group", "selection": "exactmatch", "key_symbol": 1, "members": [1, 2]}]
    cases["comdat"] = case
    case = deepcopy(case)
    case[2]["comdats"][0]["members"] = [1]
    cases["comdat-missing-member"] = case
    for kind in ("data", "tls", "import"):
        case = deepcopy(base)
        case[2]["symbols"][0]["kind"] = kind
        cases["function-as-" + kind] = case
    case = deepcopy(base)
    signature = max(value["id"] for value in case[1]["types"]) + 1
    case[1]["types"].append({"id": signature, "kind": "function", "params": [ref(4)], "results": [ref(9)],
                           "param_noundef": [False], "result_noundef": [False], "variadic": False, "cc": "portable"})
    layout = max(value["id"] for value in case[1]["memory_layouts"]) + 1
    case[1]["memory_layouts"].append({"id": layout, "type": ref(9), "size": 1, "alignment": 1,
                                    "access_bytes": 1, "fields": [], "element": None, "stride": 0})
    case[6]["imports"] = [{"id": 0, "kind": "internal", "namespace": "smir.internal.v1", "name": "memory_load", "version": 1,
        "catalog": helper_catalog_digest(), "signature": ref(signature),
        "abi": None, "types": [ref(9)], "contract": "ordinary", "options": {"alignment": 1, "scope": "process", "order": "none",
        "failure_order": "none", "weak": False, "comparison": "none", "mask": "", "rounding": "none", "exceptions": "none",
        "predicate": "none", "target": some(ref(layout)), "flags": []}}]
    cases["helper-load"] = case
    changed = deepcopy(case)
    changed[1]["types"][-1]["param_noundef"] = [True]
    cases["helper-load-noundef"] = changed
    changed = deepcopy(case)
    changed[1]["types"][-1]["results"] = [ref(1)]
    cases["helper-load-type"] = changed
    changed = deepcopy(case)
    changed[6]["imports"][0]["options"]["flags"] = ["elementwise"]
    cases["helper-load-options"] = changed
    changed = deepcopy(case)
    changed[6]["imports"][0]["catalog"] = "ff" * 32
    cases["helper-load-catalog"] = changed
    for name, function_execution, function_nominal in [
        ("common-function-type", True, True),
        ("common-function-nominal", False, True),
        ("common-untyped", False, False),
    ]:
        changed = deepcopy(base)
        symbol = changed[2]["symbols"][0]
        symbol.update(kind="data", binding="common", definition=some({"kind": "common", "size": 4, "alignment": 1}))
        if not function_execution:
            symbol["execution"] = deepcopy(base[2]["symbols"][1]["execution"])
        if not function_nominal:
            symbol.update(nominal=None, abi_signature=None, source_linkage="none")
        cases[name] = changed
    constant = deepcopy(base)
    constant_signature = max(value["id"] for value in constant[1]["types"]) + 1
    constant_layout = max(value["id"] for value in constant[1]["memory_layouts"]) + 1
    constant_function = max(value["id"] for value in constant[3]["functions"]) + 1
    constant[1]["types"].append({"id": constant_signature, "kind": "function", "params": [], "results": [ref(9)],
        "variadic": False, "param_noundef": [], "result_noundef": [False], "cc": "portable"})
    constant[1]["memory_layouts"].append({"id": constant_layout, "type": ref(9), "size": 1, "alignment": 1,
        "access_bytes": 1, "fields": [], "element": None, "stride": 0})
    constant[3]["functions"].append({"id": constant_function, "signature": ref(constant_signature), "abi_signature": None,
        "params": [], "entry": 0, "escape": "propagate", "no_return": False, "blocks": [{"id": 0, "phis": [],
        "ops": [{"op": "constant", "results": [{"id": 0, "type": ref(9)}], "operands": [], "literal": {"kind": "bits", "value": "2a"}}],
        "term": {"op": "return", "values": [0]}}]})
    constant[5]["constant_initializers"] = [{"id": 0, "source_kind": "data", "source": 12, "offset": 2,
        "layout": ref(constant_layout), "function": ref(constant_function), "association": None}]
    cases["constant-header"] = constant
    changed = deepcopy(constant)
    changed[5]["constant_initializers"][0]["offset"] = 1
    cases["constant-overlap"] = changed
    changed = deepcopy(constant)
    changed[1]["types"][-1]["result_noundef"] = [True]
    cases["constant-noundef"] = changed
    changed = deepcopy(constant)
    changed[5]["constant_initializers"][0]["association"] = some(ref(2))
    cases["constant-alias-owner"] = changed
    changed = deepcopy(constant)
    changed[2]["symbols"][1]["comdat"] = some(0)
    changed[2]["comdats"] = [{"id": 0, "namespace": "metadata", "name": "split", "selection": "any", "key_symbol": 1, "members": [1]}]
    cases["constant-split-selection"] = changed
    changed = deepcopy(base)
    changed[5]["relocations"].append(deepcopy(changed[5]["relocations"][0]))
    cases["leaf-overlap"] = changed
    changed = deepcopy(base)
    changed[5]["relocations"][0]["target"] = ref(0)
    cases["leaf-function-as-data"] = changed
    codec = CandidateCodec(SCHEMAS)
    receipts = {}
    for name, roots in cases.items():
        prepare_declared_abi2_source(roots)
        encoded = codec.encode(roots)
        # Independent decode confirms complete framing/record shape and identity.
        decoded = codec.decode(encoded)
        assert len(decoded.roots) == 10
        output = folder / (name + ".smo")
        write_bytes(output, encoded)
        receipts[name] = {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest(),
                          "content_identity": decoded.content_digest}
    write_text(folder / "manifest.json", json.dumps({"scope": "raw-context tests; no semantic admission or native evidence", "provenance": provenance(__file__, ["docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json"], receipts), "cases": receipts}, indent=2) + "\n")


if __name__ == "__main__":
    main()
