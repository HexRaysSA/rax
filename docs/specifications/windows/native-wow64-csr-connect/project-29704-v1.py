"""Verify and project the retained, naturally completed 29704 BASE controls."""
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ARCHIVE_BYTES = 18897725
ARCHIVE_SHA256 = "4cedec9326b946cd15e7216f226dda0cecd3a00d728cad9e083dbe0f3d95bd1f"
PROFILE_SHA256 = "569b9be2147eb08cc2fa193581e44d9af87a8c3ccb8c32b7a422d1ac7383b366"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(line):
    return dict(re.findall(r"([\w-]+)=([^\s]+)", line))


def published(name):
    if name.startswith(".task-evidence/windows29704-wow64-v1/"):
        return "docs/specifications/windows/native-wow64-csr-connect/captured-29704-v1/" + Path(name).name
    return name


def initial(raw):
    lines = raw.decode("ascii").splitlines()
    require(lines[-1].startswith("DONE ") and fields(lines[-1])["exit"] == "0", "natural child completion")
    require(any("machine=014C ret-bytes=20" in line for line in lines
                if line.startswith("INSTALLED ")), "installed x86 RET20")
    cleanup = "CLEANUP original-call=1 observed-rows-complete=1 breakpoints-removed=1"
    require(lines.count(cleanup) == 1, "restore original call after measuring")
    require(not any(line.startswith("RETURN ") for line in lines[lines.index(cleanup) + 1:]),
            "cleanup execution is not a measured return")
    result, step = [], None
    for line in lines[:lines.index(cleanup)]:
        row = fields(line)
        if line.startswith("RETURN "):
            require(step is None, "complete preceding return")
            step = {"ordinal": int(row["ordinal"]), "status": row["status"],
                    "new_handles": [], "new_mappings": []}
        elif line.startswith("HANDLE_NEW "):
            require(step is not None and row["duplicate"] == "1" and row["query"] == "00000000",
                    "independent handle observation")
            kind = re.search(r" type=(.*?)(?= name-query=|$)", line)
            name = re.search(r" name=(.*?)(?= section-query=|$)", line)
            require(kind is not None, "handle type")
            step["new_handles"].append({"access": row["access"], "type": kind[1],
                                        "name": name[1] if name else None})
        elif line.startswith("MAPPED_NEW "):
            require(step is not None, "mapping belongs to a return")
            step["new_mappings"].append({"bytes": int(row["bytes"]),
                "state": int(row["state"], 16), "protect": int(row["protect"], 16),
                "type": int(row["type"], 16)})
        elif line.startswith("PEB_DELTA "):
            require(step is not None, "publication belongs to a return")
            before, after = map(int, row["handles"].split(":"))
            step.update(handles_before=before, handles_after=after,
                        changed64=int(row["changed64"]), changed32=int(row["changed32"]))
            require(len(step["new_handles"]) == after - before, "complete handle delta")
            result.append(step)
            step = None
    require(step is None and result, "complete return sequence")
    return {"terminal": lines[-1], "steps": result}


def normalized_step(step, selected_session):
    result = json.loads(json.dumps(step))
    for handle in result["new_handles"]:
        if handle["name"] == r"\Windows\SharedSection":
            handle["name"] = rf"\Sessions\{selected_session}\Windows\SharedSection"
    for key in ("changed64", "changed32"):
        result[key] = bool(result[key])
    result["handle_delta"] = result.pop("handles_after") - result.pop("handles_before")
    return result


def identity(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def pe_machine(raw):
    require(raw[:2] == b"MZ", "PE DOS header")
    at = struct.unpack_from("<I", raw, 0x3C)[0]
    require(raw[at:at + 4] == b"PE\0\0", "PE signature")
    return struct.unpack_from("<H", raw, at + 4)[0]


def verify_receipt(z, binding_name, receipt_name, package, sources, images, providers):
    binding_raw = z.read("bindings/" + binding_name + ".json")
    binding = json.loads(binding_raw)
    receipt = json.loads(z.read("receipts/" + receipt_name + ".json"))
    require(receipt["source_sha256"] == sha(binding_raw), "receipt binds exact launch input")
    require(receipt["phase"] == "finished" and not receipt.get("error")
            and receipt["images_unchanged"] and not receipt["native_validation_jobs_restarted"],
            "completed acquisition with held images and no restart")
    require(receipt["native_kernel"] == binding["native_kernel"] == "10.0.29704.0",
            "exact measured native kernel")
    for name, digest in binding["source_frame"].items():
        raw = z.read("source/" + name)
        require(sha(raw) == digest and (ROOT / published(name)).read_bytes() == raw,
                "executed and published source bytes: " + name)
        sources[published(name)] = identity(raw)
    for item in binding["inputs"]:
        raw = z.read(package + "/" + item["package_name"])
        require(identity(raw) == {key: item[key] for key in ("bytes", "sha256")},
                "bound input: " + item["package_name"])
        if item["package_name"].endswith(".exe"):
            images[package + "/" + item["package_name"]] = {
                **identity(raw), "machine": pe_machine(raw)}
    require(len(receipt["runs"]) == len(binding["programs"]), "all declared invocations")
    for run, program in zip(receipt["runs"], binding["programs"]):
        require(run["label"] == program["architecture"]
                and run["arguments"] == program["arguments"]
                and run["exit_code"] == 0 and run["stderr_sha256"] == sha(b""),
                "original invocation verdict")
        require(identity(z.read(package + "/" + program["package_name"]))
                == {key: program["image"][key] for key in ("bytes", "sha256")},
                "executed image identity")
        raw = base64.b64decode(run["stdout_base64"], validate=True)
        require(identity(raw) == {"bytes": run["stdout_bytes"], "sha256": run["stdout_sha256"]},
                "complete native stdout")
    for item in receipt["captured_providers"]:
        raw = base64.b64decode(item["data_base64"], validate=True)
        name = item["path"].replace("\\", "/").split("/")[-2]
        require(raw == z.read("providers/" + name + "/ntdll.dll")
                and identity(raw) == {key: item[key] for key in ("bytes", "sha256")}
                and receipt["installed_images"][item["path"]] == sha(raw),
                "captured installed provider: " + name)
        require(name not in providers or providers[name] == identity(raw), "provider stability")
        providers[name] = identity(raw)
    return receipt


def project(archive):
    require(identity(archive.read_bytes()) == {"bytes": ARCHIVE_BYTES, "sha256": ARCHIVE_SHA256},
            "retained archive identity")
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read("archive-manifest.json"))
        require(len(manifest) == 83 and len(z.namelist()) == 84
                and set(z.namelist()) == set(manifest) | {"archive-manifest.json"}
                and z.testzip() is None, "complete archive payload inventory")
        for name, expected in manifest.items():
            require(identity(z.read(name)) == expected, "archive payload: " + name)
        sources, images, providers, fresh = {}, {}, {}, {}
        pairs = [("native-source-lifecycle-v2", "initial-lifecycle-v1-tests-receipt-v6", "v6"),
                 ("native-source-initial-matrix-v1", "initial-lifecycle-v1-tests-receipt-v7", "v7")]
        for binding, receipt_name, version in pairs:
            receipt = verify_receipt(z, binding, "wow64-29704-" + receipt_name,
                                     "initial-package", sources, images, providers)
            for run in receipt["runs"]:
                mode = run["label"]
                raw = z.read("stdout/" + version + "-" + mode + ".log")
                require(raw == base64.b64decode(run["stdout_base64"], validate=True)
                        and mode not in fresh, "unique, original first/retry sample")
                fresh[mode] = {"mode": mode, "stdout_sha256": sha(raw), **initial(raw)}
        typed = json.loads(z.read("records/typed-initial-v1.json"))
        require(typed["kernel"] == [10, 0, 29704] and typed["native_machine"] == 0xAA64
                and typed["session"] == 1 and not typed["differences"]
                and {row["mode"]: row for row in typed["profiles"]} == fresh,
                "independent raw initial re-projection")
        groups = []
        for version in (8, 9):
            previous = json.loads(z.read("retained/initial-29695-v%d.json" % version))
            samples = []
            for sample in previous["samples"]:
                observed = fresh[sample["mode"]]
                require([normalized_step(row, 1) for row in sample["steps"]]
                        == [normalized_step(row, 1) for row in observed["steps"]],
                        "status, resources and publication: " + sample["mode"])
                samples.append(observed)
            groups.append({"version": version, "case_count": len(samples),
                           "return_count": sum(len(row["steps"]) for row in samples),
                           "samples": samples})
        require(sum(group["case_count"] for group in groups) == len(fresh) == 31
                and sum(group["return_count"] for group in groups) == 38,
                "complete initial/retry matrix")
        receipt = verify_receipt(z, "native-source-family-v1",
                                 "wow64-29704-family-tests-receipt-resume-v2",
                                 "family-package", sources, images, providers)
        family = project_family(z, receipt, providers)
        require(images["initial-package/initial.exe"]["machine"] == 0xAA64
                and images["initial-package/child.exe"]["machine"] == 0x14C
                and images["family-package/family.exe"]["machine"] == 0x14C
                and images["family-package/launcher.exe"]["machine"] == 0xAA64,
                "native controller and x86 subject architectures")
        return {"schema": "rax-native-wow64-csr-29704-v1", "kernel": [10, 0, 29704],
                "native_machine": 0xAA64, "session": 1, "archive_bytes": ARCHIVE_BYTES,
                "archive_sha256": ARCHIVE_SHA256, "natural_child_exit": 0,
                "cleanup_replay_excluded_from_measured_returns": True,
                "fresh_cases": 31, "fresh_returns": 38, "family_calls": 336,
                "sources": sources, "images": images, "providers": providers,
                "groups": groups, "family": family,
                "comparison": "Exact statuses, grants/types, mapped geometry, per-step handle "
                "deltas, publication booleans and repeated-call rows match preserved controls. "
                "Only the independently observed session component of the named section is "
                "relocated from session 0 to 1; actual addresses and changed-byte counts remain "
                "in native logs. Default/disabled map SysWOW64; enabled maps SyChpe32."}


def project_family(z, receipt, providers):
    old = json.loads(z.read("retained/family-raw-v2.json"))
    result = []
    require({row["mode"] for row in receipt["family_logs"]}
            == {"default", "enabled", "disabled"} and len(receipt["family_logs"]) == 3,
            "all declared CHPE creation modes")
    for sample in receipt["family_logs"]:
        mode = sample["mode"]
        raw = z.read("family/" + mode + ".log")
        require(raw == base64.b64decode(sample["data_base64"], validate=True)
                and identity(raw) == {key: sample[key] for key in ("bytes", "sha256")},
                "complete original family log")
        lines = raw.decode("ascii").splitlines()
        require("KERNEL major=10 minor=0 build=29704" in lines and lines[-1] == "DONE calls=112",
                "native family kernel and completed call count")
        rows = [fields(line) for line in lines if line.startswith("CASE ")]
        previous = base64.b64decode(old["logs"][mode + ".log"], validate=True).decode("ascii")
        require(len(rows) == 112 and rows == [fields(line) for line in previous.splitlines()
                                            if line.startswith("CASE ")],
                "exact original family row comparison")
        provider = next(fields(line) for line in lines if line.startswith("PROVIDER "))
        encoded = provider["hex"]
        mapped = "".join(chr(int(encoded[at:at + 4], 16)) for at in range(0, len(encoded), 4))
        view = "SyChpe32" if mode == "enabled" else "SysWOW64"
        require(mapped.lower().endswith(("\\windows\\" + view + "\\ntdll.dll").lower()),
                "observed provider, independent of creation-mode label")
        leaves = [fields(line) for line in lines if line.startswith("LEAF ")]
        require(len(leaves) == 2 and all(row["bytes"] == "32"
                and len(bytes.fromhex(row["hex"])) == 32 for row in leaves), "observed native leaves")
        leaf = next(row for row in leaves if row["name"] == "NtWow64CsrClientConnectToServer")
        require(bytes.fromhex(leaf["hex"])[12:15] == b"\xc2\x14\x00", "five-argument RET20")
        result.append({"mode": mode, "rows": len(rows), "stdout_sha256": sha(raw),
                       "provider": {"mapped_path": mapped, "view": view, **providers[view]},
                       "leaves": leaves})
    return result


def main():
    require(len(sys.argv) in (1, 2), "usage: project-29704-v1.py [native-archive.zip]")
    if len(sys.argv) == 2:
        sys.stdout.write(json.dumps(project(Path(sys.argv[1])), indent=2) + "\n")
        return
    raw = (HERE / "profile-29704-v1.json").read_bytes()
    require(sha(raw) == PROFILE_SHA256, "frozen projection identity")
    data = json.loads(raw)
    require(data["archive_sha256"] == ARCHIVE_SHA256 and data["kernel"] == [10, 0, 29704]
            and data["native_machine"] == 0xAA64 and data["session"] == 1, "profile identity")
    for name, expected in data["sources"].items():
        require(identity((ROOT / name).read_bytes()) == expected, "published executed source: " + name)
    require(sum(len(group["samples"]) for group in data["groups"]) == 31
            and sum(len(row["steps"]) for group in data["groups"] for row in group["samples"]) == 38
            and sum(row["rows"] for row in data["family"]) == 336, "profile coverage")
    print("Verified published source identities and profile counts: 31 cases, 38 returns, "
          "336 repeated calls. Raw archive not checked.")


if __name__ == "__main__":
    main()
