#!/usr/bin/env python3
"""Observe SDK access to RAX VMCS candidate fields; no guest instructions run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_suffix(".c")
    root = Path(__file__).resolve().parents[2]
    context = root / "src/backend/hvf/intel_context_format.rs"
    registers = root / "src/backend/hvf/intel_registers.rs"
    result = {"scope": __doc__, "commands": [], "success": False, "error": None,
              "guest_execution_qualified": False, "observations": [],
              "source_sha256": sha(source), "script_sha256": sha(Path(__file__)),
              "availability_source_sha256": sha(source.with_name("native_intel_availability.c")),
              "candidate_sources": {str(p.relative_to(root)): sha(p) for p in [context, registers]}}
    scratch = None

    def run(label, argv):
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        result["commands"].append({"label": label, "argv": [str(x) for x in argv],
                                   "exit_code": completed.returncode,
                                   "stdout": completed.stdout, "stderr": completed.stderr})
        if completed.returncode:
            raise RuntimeError(f"{label} failed with status {completed.returncode}")
        return completed

    try:
        body = re.search(r"pub\(crate\) fn vmcs_candidates\(\) -> Vec<u32> \{.*?\[(.*?)\]\s*"
                         r"\.into_iter", context.read_text(), re.S).group(1)
        identifiers = re.findall(r"\bVMCS_\w+\b", body)
        values = {name: int(value, 16) for name, value in re.findall(
            r"^\s+(VMCS_\w+)\s*=\s*(0x[0-9a-fA-F]+)", registers.read_text(), re.M)}
        assert identifiers and len(identifiers) == len(set(identifiers))
        fields = [{"name": name, "id": values[name]} for name in identifiers]
        (args.output / "fields.json").write_text(json.dumps(fields, indent=2) + "\n")
        run("os", ["sw_vers"])
        run("sdk", ["xcrun", "--sdk", "macosx", "--show-sdk-version"])
        run("compiler", ["xcrun", "--sdk", "macosx", "clang", "--version"])
        with tempfile.TemporaryDirectory(prefix="rax-hvf-intel-vmcs-",
                                         dir=os.environ.get("RUNNER_TEMP") or "/tmp") as tmp:
            scratch = Path(tmp)
            header = "struct probe_field { unsigned id; const char *name; };\n"
            header += "static const struct probe_field probe_fields[] = {\n"
            header += "".join('    {%d, "%s"},\n' % (row["id"], row["name"]) for row in fields)
            header += "};\n"
            (scratch / "probe_fields.h").write_text(header)
            result["generated_fields_sha256"] = hashlib.sha256(header.encode()).hexdigest()
            executable = scratch / "probe"
            entitlements = scratch / "entitlements.plist"
            entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
            run("build", ["xcrun", "--sdk", "macosx", "clang", "-arch", "x86_64",
                          "-std=c11", "-O1", "-Wall", "-Wextra", str(source),
                          "-I", str(scratch), "-framework", "Hypervisor", "-o", str(executable)])
            run("sign", ["codesign", "--force", "--sign", "-", "--entitlements",
                         str(entitlements), "--timestamp=none", str(executable)])
            run("verify-signature", ["codesign", "--verify", "--strict", str(executable)])
            result["executable_sha256"] = sha(executable)
            observed = subprocess.run([str(executable)], capture_output=True, text=True, timeout=60)
            result["commands"].append({"label": "observe", "exit_code": observed.returncode,
                                       "stdout": observed.stdout, "stderr": observed.stderr})
            result["observations"] = [json.loads(line) for line in observed.stdout.splitlines()]
            if observed.returncode:
                raise RuntimeError(f"observe failed with status {observed.returncode}")
            assert len(result["observations"]) == 2
            availability, vmcs = result["observations"]
            assert availability["native_intel_process"] and availability["vm_created"]
            assert vmcs["field_count"] == len(fields)
            assert [(row["id"], row["name"]) for row in vmcs["fields"]] == [
                (row["id"], row["name"]) for row in fields]
            assert all(sha(root / name) == digest for name, digest in result["candidate_sources"].items())
            result["success"] = True
    except (OSError, ValueError, AttributeError, KeyError, AssertionError,
            RuntimeError, subprocess.TimeoutExpired) as error:
        result["success"] = False
        result["error"] = repr(error)
    finally:
        result["owned_build_removed"] = scratch is None or not scratch.exists()
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name: result[name] for name in (
        "success", "guest_execution_qualified", "owned_build_removed", "error")}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
