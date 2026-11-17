"""Independent frozen-Python encoding of complete ABI phase cases; test only."""
from pathlib import Path
from copy import deepcopy
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/smir-format"))
sys.path.insert(0, str(ROOT / "tools/smir-abi"))
from codec import CandidateCodec
from nominal import NominalGraph, ref
from candidate_fixtures import build, native_profile

SPEC = ROOT / "docs/specifications/smir/portable"
source = SPEC / "conformance/execution/candidate/portable-identity.json"
base = {int(k): v for k, v in json.loads(source.read_text())["sections"].items()}
for key, value in {
    5: {"payload_revision": 2, "relocations": [], "constant_initializers": []},
    7: {"payload_revision": 1, "segments": []},
    9: {"payload_revision": 1, "capabilities": [], "requirements": [], "limits": []},
}.items():
    base.setdefault(key, value)
codec = CandidateCodec({owner: json.loads((SPEC / f"schema/{owner}/candidate.json").read_text())
                        for owner in ("execution", "runtime", "abi")})
cases = []


def add(name, roots, expected, reseal=False, all_phase=False):
    if reseal:
        graph = NominalGraph(roots[10], "main")
        for typ in roots[10]["types"]:
            typ["identity"]["definition"] = graph.fingerprint(ref(typ["id"])) if "complete" in typ["flags"] else "0" * 64
    data = codec.encode(roots)
    if codec.decode(data).content_digest != codec.decode(data).roots[2]["manifest"]["identity"]:
        raise ValueError("ABI_FIXTURE_CONTENT_IDENTITY")
    cases.append({"name": name, "expected": expected, "all_phase": all_phase, "encoded_hex": data.hex(),
                  "sha256": hashlib.sha256(data).hexdigest()})


add("portable-identity", deepcopy(base), "verified-abi", all_phase=True)
coherent = deepcopy(base)
coherent[10]["signatures"][0]["return_noundef"] = False
next(t for t in coherent[1]["types"] if t["id"] == 12)["result_noundef"] = [False]
add("coherent-optional-return-noundef", coherent, "verified-abi", all_phase=True)
# Valid unused records must not escape the conservative proof coverage guard.
extra = deepcopy(base)
typ = deepcopy(extra[10]["types"][0])
typ.update(id=501, layout={"some": 501})
layout = deepcopy(extra[10]["layouts"][0])
layout.update(id=501, type=ref(501))
extra[10]["types"].append(typ)
extra[10]["layouts"].append(layout)
add("unused-valid-extra-nominal", extra, "P2_ABI_VERIFIER_INCOMPLETE", True)
extra = deepcopy(base)
extra[10]["types"][0]["qualifiers"] = ["const"]
add("valid-const-qualification-outside-profile", extra, "P2_ABI_VERIFIER_INCOMPLETE", True)
# The guard uses actual associations, never public fixture IDs.
renamed = deepcopy(base)
scalar, function = renamed[10]["types"]
scalar.update(id=501, layout={"some": 601})
function.update(id=512, elements=[ref(501), ref(501)])
renamed[10]["domains"][0]["id"] = 19
scalar["domain"] = function["domain"] = 19
renamed[10]["layouts"][0].update(id=601, type=ref(501))
sig = renamed[10]["signatures"][0]
sig.update(id=77, function_type=ref(512), params=[ref(501)], result={"some": ref(501)}, lowered_results=[ref(501)])
sig["lowered_params"][0].update(source_type=ref(501), value_type=ref(501))
renamed[2]["symbols"][0].update(nominal={"some": ref(512)}, abi_signature={"some": ref(77)})
renamed[3]["functions"][0]["abi_signature"] = {"some": ref(77)}
add("arbitrary-source-layout-signature-domain-ids", renamed, "verified-abi", True, all_phase=True)
for domain, expected in [(0xfffffffe, "verified-abi"), (0xffffffff, "ABI_CC_DUPLICATE_ID")]:
    extra = deepcopy(base)
    extra[10]["domains"][0]["id"] = domain
    for typ in extra[10]["types"]:
        typ["domain"] = domain
    add("domain-upper-bound-" + str(domain), extra, expected, all_phase=domain == 0xfffffffe)
extra = deepcopy(base)
extra[10]["signatures"].append(dict(deepcopy(extra[10]["signatures"][0]), id=77))
add("unused-valid-extra-signature", extra, "P2_ABI_VERIFIER_INCOMPLETE")
extra = deepcopy(base)
extra[1]["types"].append({"id": 900, "kind": "raw", "bits": 32})
extra[10]["types"][0]["execution"] = {"some": ref(900)}
execution_function = next(t for t in extra[1]["types"] if t["id"] == 12)
execution_function.update(params=[ref(900)], results=[ref(900)])
extra[3]["functions"][0]["params"][0]["type"] = ref(900)
add("raw32-scalar-outside-int32-profile", extra, "P2_ABI_VERIFIER_INCOMPLETE")
for name, code, mutate, reseal in [
    ("wrong-site", "ABI_CC_SITE", lambda a: a["site"].update(unwinder="host_default"), False),
    ("wrong-scalar-precision", "ABI_CC_TYPE_BINDING", lambda a: a["types"][0].update(bits=31), True),
    ("wrong-scalar-signedness", "ABI_CC_SCALAR_SIGNEDNESS", lambda a: a["types"][0].update(signed=False), True),
    ("wrong-layout", "ABI_CC_LAYOUT_POLICY", lambda a: a["layouts"][0].update(size=8, data_size=8, nonvirtual_size=8), True),
    ("wrong-source-index", "ABI_CC_CALL_PARAMETER", lambda a: a["signatures"][0]["lowered_params"][0].update(source_index={"some": 1}), False),
    ("wrong-return-noundef", "ABI_CC_LOWERED_SIGNATURE", lambda a: a["signatures"][0].update(return_noundef=False), False),
    ("vtt-without-this", "ABI_CC_VTT_WITHOUT_THIS", lambda a: a["signatures"][0].update(vtt=True), False),
    ("wrong-hidden-role", "ABI_CC_CALL_PARAMETER", lambda a: a["signatures"][0]["lowered_params"][0].update(role="this"), False),
    ("unknown-nominal-kind", "ABI_CC_TYPE_KIND", lambda a: a["types"][0].update(kind="unknown_kind"), True),
    ("duplicate-cv", "ABI_CC_QUALIFIER", lambda a: a["types"][0].update(qualifiers=["const", "const"]), True),
]:
    roots = deepcopy(base)
    mutate(roots[10])
    add(name, roots, code, reseal)

dependency = deepcopy(base)
dependency[2]["manifest"]["dependencies"] = [{
    "slot": 7, "key": {"namespace": "unit", "name": "provider", "abi_major": 1, "abi_minor": 0},
    "minimum_minor": 0, "maximum_minor": None, "site": base[10]["identity"],
    "declarations": [{"id": 99, "kind": "nominal", "symbol_kind": "none", "source_linkage": "none",
                      "namespace": "unit", "name": "int_type", "execution": {"some": ref(17)},
                      "nominal": {"some": ref(1)}, "abi_signature": None, "weak": False}],
}]
source_type = ref(99, 7)
signature = dependency[10]["signatures"][0]
signature["params"][0] = deepcopy(source_type)
signature["lowered_params"][0]["source_type"] = deepcopy(source_type)
signature["lowered_params"][0]["value_type"] = deepcopy(source_type)
add("unresolved-nominal-expectation", dependency, "P2_ABI_VERIFIER_INCOMPLETE")
bad = deepcopy(dependency)
bad[2]["manifest"]["dependencies"][0]["declarations"][0]["kind"] = "type"
add("wrong-declaration-namespace", bad, "ABI_CC_UNBOUND_DECLARATION")


def native_roots(document, evidence):
    """Synthetic native DECLARATIONS, never registered image certificates."""
    roots = deepcopy(base)
    roots[10] = deepcopy(document)
    roots[1]["types"] = deepcopy(evidence["execution_graph"])
    roots[1]["memory_layouts"] = sorted(deepcopy(list(evidence["memory_layouts"].values())), key=lambda r: r["id"])
    types = {t["id"]: t for t in document["types"]}
    def execution(identifier):
        typ = types[identifier]
        return None if typ["kind"] == "void" else deepcopy(typ["execution"]["some"])
    domain = next(d for d in document["domains"] if d["isa"] != "portable")
    roots[2]["manifest"].update(foreign_isa=domain["isa"], personality=domain["personality"])
    symbols = roots[2]["symbols"]
    for index, identifier in enumerate((100, 101)):
        source = evidence["symbols"][str(identifier)]["signature"]
        signature = types[source["id"]]
        params = [execution(r["id"]) for r in signature["elements"][:-1]]
        result = execution(signature["elements"][-1]["id"])
        function_id = 600 + index
        roots[1]["types"].append({"id": function_id, "kind": "function", "cc": "portable", "variadic": False,
                                  "params": params, "results": [] if result is None else [result],
                                  "param_noundef": [True] * len(params), "result_noundef": [] if result is None else [True]})
        symbols.append({"id": identifier, "namespace": "fixture", "name": f"native_{identifier}",
                        "kind": "function", "source_linkage": "cpp", "binding": "strong", "visibility": "hidden",
                        "execution": ref(function_id), "nominal": {"some": source}, "abi_signature": None,
                        "definition": {"some": {"kind": "native", "image": "7" * 64, "domain": domain["id"], "offset": index * 16, "size": 16}},
                        "size": {"some": 16}, "alignment": 16, "comdat": None, "fallback": None})
    data = bytes.fromhex(evidence["metadata"]["103"])
    roots[1]["types"].append({"id": 604, "kind": "raw", "bits": len(data) * 8})
    symbols.append({"id": 103, "namespace": "fixture", "name": "declared_unwind_metadata",
                    "kind": "data", "source_linkage": "none", "binding": "strong", "visibility": "hidden",
                    "execution": ref(604), "nominal": None, "abi_signature": None,
                    "definition": {"some": {"kind": "data", "segment": 103}}, "size": {"some": len(data)},
                    "alignment": 1, "comdat": None, "fallback": None})
    roots[4]["segments"] = [{"id": 103, "layout": None, "nominal": None, "abi_binding": None,
                              "alignment": 1, "mutable": False, "initial": data.hex(),
                              "poison": "00" * len(data), "undef": "00" * len(data),
                              "zero_fill": 0, "zero_shadow": "defined"}]
    roots[1]["types"].sort(key=lambda t: t["id"])
    symbols.sort(key=lambda s: s["id"])
    return roots


complete, complete_evidence = build(all_kinds=True)
native = native_roots(complete, complete_evidence)
add("all-nominal-kinds-and-native-declarations", deepcopy(native), "P2_ABI_VERIFIER_INCOMPLETE")
for isa in ("x86_64", "aarch64"):
    for abi in ("itanium", "microsoft"):
        document, evidence = native_profile(isa=isa, abi=abi)
        add(f"windows-{isa}-{abi}-declarations", native_roots(document, evidence), "P2_ABI_VERIFIER_INCOMPLETE")
for isa, personality in (("aarch64", "linux"), ("x86_64", "darwin"), ("aarch64", "darwin")):
    document, evidence = build()
    document["domains"][1].update(isa=isa, personality=personality)
    if personality == "darwin":
        document["personalities"][0]["flavor"] = "guest_itanium_darwin"
        document["unwind"][0]["source_format"] = "darwin_compact_dwarf"
    add(f"{personality}-{isa}-declarations", native_roots(document, evidence), "P2_ABI_VERIFIER_INCOMPLETE")

for name, code, mutate in [
    ("native-cfa-pc", "ABI_CC_CFA_REGISTER", lambda r: r[10]["unwind"][0]["rows"][0]["cfa"].update(base="register", reg=16)),
    ("native-vector-register", "ABI_CC_CFI_REGISTER", lambda r: r[10]["unwind"][0]["rows"][0]["registers"].append({"reg": 33, "rule": {"kind": "same"}})),
    ("native-expression", "ABI_CC_CFI_EXPRESSION_UNSUPPORTED", lambda r: r[10]["unwind"][0]["rows"][0].update(return_rule={"kind": "expression", "recipe": 0})),
    ("native-gap", "ABI_CC_CFI_COVERAGE", lambda r: r[10]["unwind"][0]["rows"][0].update(start=1)),
    ("native-source-digest", "ABI_CC_METADATA_DIGEST", lambda r: r[10]["unwind"][0]["metadata"][0].update(digest="0" * 64)),
    ("portable-native-cfi", "ABI_CC_CFI_PROFILE", lambda r: r[10]["unwind"][0].update(domain=0)),
    ("native-logical-format", "ABI_CC_CFI_PROFILE", lambda r: r[10]["unwind"][0].update(source_format="logical")),
    ("adapter-action", "ABI_CC_ADAPTER_ACTION", lambda r: r[10]["recipes"][0]["steps"][0].update(action="unknown_action")),
    ("adapter-undefined-value", "ABI_CC_ADAPTER_DOMINANCE", lambda r: r[10]["recipes"][0]["steps"][0].update(inputs=[999])),
    ("journal-parent-self", "ABI_CC_SLOT_PARENT", lambda r: r[10]["journals"][0]["slots"][0].update(parent={"some": 0})),
    ("journal-cleanup-order", "ABI_CC_CLEANUP_ORDER", lambda r: r[10]["journals"][0].update(exception_order=[])),
    ("storage-value-padding", "ABI_CC_STORAGE_VALUE_AS_PADDING", lambda r: r[10]["storage_bindings"][0]["fragments"][0].update(role="padding")),
    ("storage-value-clobber", "ABI_CC_STORAGE_EFFECT_VALUE_CLOBBER", lambda r: r[10]["storage_bindings"][1].update(kind="fieldwise", view_width_bits=8)),
    ("bridge-alias", "ABI_CC_UNREPRESENTABLE_ALIAS", lambda r: r[10]["bridges"][0].update(identity="proxy", aliases="shared")),
    ("bridge-translation", "ABI_CC_EXCEPTION_TRANSLATION", lambda r: r[10]["personalities"][0].update(flags=["search_readonly", "cleanup_calls", "forced_unwind"])),
]:
    roots = deepcopy(native)
    mutate(roots)
    add(name, roots, code)

# Accepted ABI-PROD016 witnesses. Full-factory coverage is separately tracked.
storage_source = SPEC / "conformance/execution/candidate/storage-tls-wrapper.json"
storage_roots = {int(k): v for k, v in json.loads(storage_source.read_text())["sections"].items()}
add("plain-pointer-whole-object-storage", deepcopy(storage_roots), "verified-abi")
storage_graph = NominalGraph(storage_roots[10], "main")
cases[-1]["storage_masks"] = [{"id": b["id"], "mask": None if b["kind"] == "allocation" else storage_graph.value_mask(b["nominal"]).hex()}
                              for b in storage_roots[10]["storage_bindings"]]
for name, code, change in [
    ("storage-wrong-full-view", "ABI_CC_STORAGE_VIEW_EXTENT", lambda a: a["storage_bindings"][0].update(view_width_bits=33)),
    ("storage-wrong-access", "ABI_CC_STORAGE_ACCESS", lambda a: a["storage_bindings"][0].update(access_bytes=8)),
    ("storage-wrong-allocation-role", "ABI_CC_STORAGE_ALLOCATION_FRAGMENT", lambda a: a["storage_bindings"][0]["fragments"][0].update(role="value")),
    ("storage-source-value-as-padding", "ABI_CC_STORAGE_VALUE_AS_PADDING", lambda a: a["storage_bindings"][1]["fragments"][0].update(role="padding")),
    ("storage-fragment-position", "ABI_CC_STORAGE_FRAGMENT_EXTENT", lambda a: a["storage_bindings"][1]["fragments"][0].update(execution_offset_bits=1)),
]:
    item = deepcopy(storage_roots)
    change(item[10])
    add(name, item, code)
for kind in ("empty", "type", "function"):
    item = deepcopy(base)
    declarations = []
    if kind != "empty":
        declarations.append({"id": 91, "kind": kind, "symbol_kind": "none", "source_linkage": "cpp" if kind == "function" else "none", "namespace": "provider", "name": "expected_" + kind,
                             "execution": {"some": ref(12)}, "nominal": {"some": ref(12)} if kind == "function" else None,
                             "abi_signature": {"some": ref(0)} if kind == "function" else None, "weak": False})
    item[2]["manifest"]["dependencies"] = [{"slot": 31, "key": {"namespace": "dependency", "name": "unresolved_" + kind, "abi_major": 1, "abi_minor": 0},
                                             "minimum_minor": 0, "maximum_minor": {"some": 1}, "site": base[10]["identity"], "declarations": declarations}]
    add("unused-unresolved-" + kind + "-dependency", item, "verified-abi")

# ABI-PROD018 local source journals are real proofs, never cleanup execution.
journal_base = deepcopy(base)
journal = {"id": 71, "signature": 0, "params": [], "slots": [{"id": 13, "type": ref(1), "offset": 0, "extent": 4, "align": 4, "parent": None,
            "role": "root", "count": 1, "stride": 4, "count_source": None, "constructor": None, "destructor": None, "destructor_kind": "none",
            "covers": [], "owner": 0, "dependencies": [], "child_program": None}], "normal_order": [13], "exception_order": [13]}
journal_base[10]["journals"] = [journal]
add("trivial-local-scalar-journal", deepcopy(journal_base), "verified-abi", all_phase=True)
for name, code, mutate in [
    ("journal-missing-signature", "ABI_CC_JOURNAL_SIGNATURE", lambda j: j.update(signature=91)),
    ("journal-invalid-owner", "ABI_CC_SLOT_OWNER", lambda j: j["slots"][0].update(owner=99)),
    ("journal-invalid-stride", "ABI_CC_SUBOBJECT_ALIGNMENT", lambda j: j["slots"][0].update(stride=0)),
    ("journal-unaligned-offset", "ABI_CC_SUBOBJECT_ALIGNMENT", lambda j: j["slots"][0].update(offset=1)),
    ("journal-self-parent", "ABI_CC_SLOT_PARENT", lambda j: j["slots"][0].update(parent={"some": 13})),
    ("journal-missing-order", "ABI_CC_CLEANUP_ORDER", lambda j: j.update(exception_order=[])),
    ("journal-reserved-slot", "ABI_CC_DUPLICATE_SLOT", lambda j: (j["slots"][0].update(id=0xffffffff), j.update(normal_order=[0xffffffff], exception_order=[0xffffffff]))),
    ("journal-reserved-formal", "ABI_CC_DUPLICATE_JOURNAL_PARAMETER", lambda j: j.update(params=[{"id": 0xffffffff, "type": ref(1)}])),
]:
    item = deepcopy(journal_base)
    mutate(item[10]["journals"][0])
    add(name, item, code)
item = deepcopy(journal_base)
item[10]["journals"][0]["params"] = [{"id": 37, "type": ref(1)}]
add("unused-valid-journal-capture-outside-profile", item, "P2_ABI_VERIFIER_INCOMPLETE")
item = deepcopy(journal_base)
second = deepcopy(item[10]["journals"][0]["slots"][0]);second.update(id=14, offset=4)
item[10]["journals"][0]["slots"].append(second)
item[10]["journals"][0].update(normal_order=[13, 14], exception_order=[14, 13])
add("unused-valid-second-journal-slot-outside-profile", item, "P2_ABI_VERIFIER_INCOMPLETE")
item = deepcopy(journal_base)
item[10]["domains"][0]["id"] = 19
for typ in item[10]["types"]: typ["domain"] = 19
item[10]["journals"][0].update(id=900)
item[10]["journals"][0]["slots"][0].update(id=901, owner=19)
item[10]["journals"][0].update(normal_order=[901], exception_order=[901])
add("journal-slot-domain-alpha-renaming", item, "verified-abi", all_phase=True)
semantic_cases = json.loads((ROOT / "crates/smir-portable/tests/execution/phase-cases.json").read_text())
external = next(c for c in semantic_cases["cases"] if c["name"] == "static_external_recipe_obligation")
add("actual-sem-external-cleanup-local-journal", codec.decode(bytes.fromhex(external["encoded_hex"])).roots, "verified-abi")

# P2_CANONICAL_STATE_01: real source declarations, independent Python encoding.
# Load the accepted builder under a private module namespace (R/ABI both own a
# physical source_roles directory; plain imports are not isolation).
import importlib.util
builder_spec=importlib.util.spec_from_file_location("rax_abi_fixture_state_builder",ROOT/"tools/smir-abi/source_roles/builder.py")
state_builder=importlib.util.module_from_spec(builder_spec);builder_spec.loader.exec_module(state_builder)
state_roots=deepcopy(base)
source_ids=dict(zip(state_builder.SOURCE_KEYS,range(2101,2107)))
exec_ids=dict(zip(state_builder.EXECUTION_KEYS,range(2201,2206)))
parts=state_builder.build_builtin_states(source_ids=source_ids,execution_ids=exec_ids,domain_id=state_roots[10]["domains"][0]["id"])
state_roots[10]["types"]+=parts["types"];state_roots[10]["layouts"]+=parts["layouts"]
state_roots[1]["types"]+=parts["execution_graph"]
add("canonical-state-closure",deepcopy(state_roots),"verified-abi",True,all_phase=True)
for family,remove in [("va-only",{"uint32","jmp_state","jmp_buf"}),("jmp-only",{"va_state","va_list"})]:
    item=deepcopy(state_roots);removed={source_ids[k] for k in remove}
    item[10]["types"]=[t for t in item[10]["types"] if t["id"] not in removed]
    item[10]["layouts"]=[l for l in item[10]["layouts"] if l["id"] not in removed]
    add("canonical-state-"+family,item,"verified-abi",True,all_phase=True)
alpha=deepcopy(state_roots)
alpha[10]["domains"][0]["id"]=19
for typ in alpha[10]["types"]:typ["domain"]=19
add("canonical-state-nonzero-domain",alpha,"verified-abi",True,all_phase=True)
# Actual32B storage is an explicit byte array; source alignment stays8B.
state_storage=deepcopy(state_roots)
state_storage[1]["memory_layouts"] += [
 {"id":2300,"type":ref(exec_ids["raw8"]),"size":1,"alignment":1,"access_bytes":1,"fields":[],"element":None,"stride":0},
 {"id":2301,"type":ref(exec_ids["state_bytes"]),"size":32,"alignment":1,"access_bytes":32,"fields":[],"element":{"some":ref(2300)},"stride":8}]
for target in ("va_state","jmp_state","va_list","jmp_buf"):
    for kind in ("allocation","object_bytes"):
        item=deepcopy(state_storage)
        binding={"id":2400,"nominal":ref(source_ids[target]),"execution_layout":ref(2301),"kind":kind,
                 "view_offset_bits":0,"view_width_bits":256,"required_alignment":8,"access_bytes":32,
                 "fragments":[{"source_path":[],"source_offset_bits":0,"execution_offset_bits":0,"width_bits":256,
                               "role":"object_representation" if kind=="allocation" else "value"}]}
        item[10]["storage_bindings"]=[binding]
        add("canonical-state-storage-"+target+"-"+kind,item,"verified-abi",True,all_phase=True)
        cases[-1]["storage_masks"]=[{"id":2400,"mask":None if kind=="allocation" else "ff"*32}]
# Valid additional source form remains unavailable, not falsely malformed.
extra=deepcopy(state_roots)
remove={source_ids["jmp_state"],source_ids["jmp_buf"]}
extra[10]["types"]=[t for t in extra[10]["types"] if t["id"] not in remove]
extra[10]["layouts"]=[l for l in extra[10]["layouts"] if l["id"] not in remove]
add("canonical-va-unused-uint32-outside-closure",extra,"P2_ABI_VERIFIER_INCOMPLETE",True)
extra=deepcopy(state_roots)
wrapper=next(t for t in extra[10]["types"] if t["id"]==source_ids["va_list"])
wrapper["extent"]={"some":2};wrapper["execution"]={"some":ref(2206)}
extra[1]["types"].append({"id":2206,"kind":"array","element":ref(exec_ids["state_bytes"]),"count":2})
next(l for l in extra[10]["layouts"] if l["id"]==source_ids["va_list"]).update(size=64,data_size=64,nonvirtual_size=64)
add("valid-array-two-of-state-outside-profile",extra,"P2_ABI_VERIFIER_INCOMPLETE",True)
for name,change in [
 ("identity-language",lambda r:next(t for t in r[10]["types"] if t["id"]==source_ids["va_state"])["identity"].update(language="cpp23")),
 ("missing-copy-flag",lambda r:next(t for t in r[10]["types"] if t["id"]==source_ids["jmp_state"])["flags"].remove("trivial_copy")),
 ("wrong-builtin-kind",lambda r:next(t for t in r[10]["types"] if t["id"]==source_ids["va_state"])["identity"].update(entity="rax.jmp_state")),
 ("source-unsigned-language",lambda r:next(t for t in r[10]["types"] if t["id"]==source_ids["uint64"])["identity"].update(language="cpp23")),
]:
    item=deepcopy(state_roots);change(item)
    add("canonical-state-reject-"+name,item,"ABI_CC_BUILTIN_STATE",True)

# Fresh alpha and alternate-sharing controls over identical canonical source ABI.
alpha=deepcopy(base)
alpha[10]["domains"][0]["id"]=19
for typ in alpha[10]["types"]:typ["domain"]=19
alpha_parts=state_builder.build_builtin_states(source_ids=dict(zip(state_builder.SOURCE_KEYS,range(3101,3107))),
    execution_ids=dict(zip(state_builder.EXECUTION_KEYS,range(3201,3206))),domain_id=19)
alpha[10]["types"]+=alpha_parts["types"];alpha[10]["layouts"]+=alpha_parts["layouts"]
alpha[1]["types"]+=alpha_parts["execution_graph"]
left=NominalGraph(state_roots[10],"main");right=NominalGraph(alpha[10],"main")
for old,new_id in [(2103,3103),(2104,3104),(2105,3105),(2106,3106)]:
    if left.fingerprint(ref(old))!=right.fingerprint(ref(new_id)):raise ValueError("STATE_ALPHA_IDENTITY")
add("canonical-state-source-execution-domain-alpha",alpha,"verified-abi",True,all_phase=True)
sharing=deepcopy(state_roots)
copy_type=deepcopy(next(t for t in sharing[10]["types"] if t["id"]==source_ids["uint64"]))
copy_type.update(id=2502,layout={"some":2502});sharing[10]["types"].append(copy_type)
copy_layout=deepcopy(next(l for l in sharing[10]["layouts"] if l["id"]==source_ids["uint64"]))
copy_layout.update(id=2502,type=ref(2502));sharing[10]["layouts"].append(copy_layout)
next(t for t in sharing[10]["types"] if t["id"]==source_ids["va_state"])["record_input"]["some"]["fields"][1]["type"]=ref(2502)
next(l for l in sharing[10]["layouts"] if l["id"]==source_ids["va_state"])["fields"][1]["type"]=ref(2502)
if left.fingerprint(ref(2103))!=NominalGraph(sharing[10],"main").fingerprint(ref(2103)):
    raise ValueError("STATE_SHARING_IDENTITY")
add("canonical-state-alternate-equal-source-sharing",sharing,"verified-abi",True,all_phase=True)
# Source predicates remain independent of the exact admitted binding subset.
binding_case=deepcopy(state_storage)
binding_case[10]["storage_bindings"]=[{"id":2400,"nominal":ref(source_ids["va_state"]),"execution_layout":ref(2301),"kind":"object_bytes",
    "view_offset_bits":0,"view_width_bits":256,"required_alignment":8,"access_bytes":32,
    "fragments":[{"source_path":[],"source_offset_bits":0,"execution_offset_bits":0,"width_bits":256,"role":"value"}]}]
for name,expected,change in [
 ("short-view","ABI_CC_STORAGE_ALLOCATION",lambda b:b.update(view_width_bits=255)),
 ("wrong-access","ABI_CC_STORAGE_ACCESS",lambda b:b.update(access_bytes=16)),
 ("value-as-padding","ABI_CC_STORAGE_VALUE_AS_PADDING",lambda b:b["fragments"][0].update(role="padding")),
 ("allocation-wrong-role","ABI_CC_STORAGE_ALLOCATION_FRAGMENT",lambda b:b.update(kind="allocation")),
 ("weak-valid-alignment","P2_ABI_VERIFIER_INCOMPLETE",lambda b:b.update(required_alignment=4)),
 ("valid-fieldwise-outside-profile","P2_ABI_VERIFIER_INCOMPLETE",lambda b:b.update(kind="fieldwise")),
]:
    item=deepcopy(binding_case);change(item[10]["storage_bindings"][0])
    add("canonical-state-binding-"+name,item,expected,True)

# ABI040 fresh source-authored semantic counterparts. Preserved old bytes are
# separate wire-revision controls, never decoded/upgraded into new source data.
for name,filename,expected in [
 ("nonrecord-scalar-invented-field","reject-nonrecord-source-field.smo","ABI_CC_NONRECORD_LAYOUT"),
 ("function-forged-object-layout","reject-function-object-layout.smo","ABI_CC_NONOBJECT_LAYOUT")]:
    raw=(SPEC/"conformance/abi/record-layout"/filename).read_bytes()
    current=deepcopy(base)
    if name=="nonrecord-scalar-invented-field":
        current[10]["layouts"][0]["fields"]=[dict(declaration_index=0,name="invented",
            type=ref(1),offset_bits=0,width_bits=32,flags=[])]
    else:
        next(t for t in current[10]["types"] if t["kind"]=="function")["layout"]={"some":900}
        current[10]["layouts"].append(dict(id=900,type=ref(12),size=8,align=8,data_size=8,
            nonvirtual_size=8,nonvirtual_align=8,fields=[],bases=[],vptrs=[]))
    add("abi040-"+name,current,expected,True)
    cases[-1]["factory_expected"]=expected
    cases[-1]["historical_raw"]={"path":"docs/specifications/smir/portable/conformance/abi/record-layout/"+filename,
        "sha256":hashlib.sha256(raw).hexdigest(),"expected_wire_error":"WIRE-REVISION"}
# Incomplete declarations carry no storage, regardless canonical constructor tag.
opaque=deepcopy(base)
forward=deepcopy(opaque[10]["types"][0]);forward.update(id=2601,kind="record",bits=0,signed=False,
    flags=[],elements=[],extent=None,representation="none",execution=None,layout=None,record_input=None)
forward["identity"].update(language="cpp23",linkage="external",entity="example.OpaqueArray",definition="0"*64)
array=deepcopy(forward);array.update(id=2602,kind="array",elements=[ref(2601)],extent={"some":3})
array["identity"].update(language="c23",linkage="builtin",entity="array")
opaque[10]["types"] += [forward,array]
add("abi040-opaque-cpp-array-expectation",deepcopy(opaque),"P2_ABI_VERIFIER_INCOMPLETE",True)
known=deepcopy(opaque)
next(t for t in known[10]["types"] if t["id"]==2602)["elements"]=[ref(1)]
add("abi040-complete-element-incomplete-known-array",known,"ABI_CC_ARRAY_COMPLETENESS",True)
unknown=deepcopy(opaque)
next(t for t in unknown[10]["types"] if t["id"]==2602).update(elements=[ref(1)],extent=None)
add("abi040-unknown-bound-complete-element",unknown,"P2_ABI_VERIFIER_INCOMPLETE",True)

# ABI042 global base declaration accepts outer CV; actual helper profile remains
# exact unqualified and must return Unknown for these otherwise valid types.
for key in ("va_state","jmp_state"):
    for qualifier in ("const","volatile"):
        item=deepcopy(state_roots)
        next(t for t in item[10]["types"] if t["id"]==source_ids[key])["qualifiers"]=[qualifier]
        add("abi042-qualified-"+key+"-"+qualifier,item,"P2_ABI_VERIFIER_INCOMPLETE",True)
for name,key,qualifier in [("nested-unsigned-cv","uint64","const"),("outer-restrict","va_state","restrict")]:
    item=deepcopy(state_roots)
    next(t for t in item[10]["types"] if t["id"]==source_ids[key])["qualifiers"]=[qualifier]
    add("abi042-reject-"+name,item,"ABI_CC_BUILTIN_STATE",True)

document = {"generator": "Current Python CandidateCodec + independently checked V3 NominalGraph; explicit source-authored mandatory fields",
            "source": str(source.relative_to(ROOT)), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "stage": "ABI phase only; genuine private static facts limited to audited core/canonical-state profiles; source native declarations remain synthetic, not image/CFI certificates",
            "cases": cases}
(Path(__file__).parent / "phase-cases.json").write_text(json.dumps(document, indent=2) + "\n")
print("ABI phase cases", len(cases))
