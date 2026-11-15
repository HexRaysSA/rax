#!/usr/bin/env python3
"""Check the finite 29708 CHPE profile and optionally both native archives."""
import ast
import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PROFILE_SHA256 = "aa5d0bafecab334f102fdd2fbd947767f23be8525d8dcca0339c5e99090f9efd"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def machine(raw):
    require(raw[:2] == b"MZ", "DOS signature")
    offset = struct.unpack_from("<I", raw, 0x3C)[0]
    require(raw[offset:offset + 4] == b"PE\0\0", "PE signature")
    return struct.unpack_from("<H", raw, offset + 4)[0]


class KernelAdapter(ast.NodeTransformer):
    """Change only the expected kernel literals in frozen pure validators."""
    def __init__(self):
        self.changes = 0

    def visit_Constant(self, node):
        if node.value == 29704:
            self.changes += 1
            return ast.copy_location(ast.Constant(value=29708), node)
        if node.value == "10.0.29704.0":
            self.changes += 1
            return ast.copy_location(ast.Constant(value="10.0.29708.0"), node)
        return node


def projector(binding, names):
    path = ROOT / binding["path"]
    require(digest(path.read_bytes()) == binding["sha256"], "Projection source changed")
    definitions = [node for node in ast.parse(path.read_bytes()).body
                   if isinstance(node, ast.FunctionDef) and node.name in names]
    require(len(definitions) == len(names), "Projection function inventory")
    adapter = KernelAdapter()
    tree = adapter.visit(ast.Module(body=definitions, type_ignores=[]))
    require(adapter.changes == binding["expected_kernel_literal_substitutions"],
            "Unexpected kernel adapter extent")
    namespace = dict(re=re, base64=base64, hashlib=hashlib)
    exec(compile(ast.fix_missing_locations(tree), str(path), "exec"), namespace)
    return namespace


def check_archive(path, expected):
    raw = path.read_bytes()
    require(len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], "Archive identity")
    archive = zipfile.ZipFile(path)
    names = archive.namelist()
    require(len(names) == len(set(names)) and archive.testzip() is None, "Archive names/CRC")
    manifest = json.loads(archive.read("manifest-v1.json"))["files"]
    require(set(names) == set(manifest) | {"manifest-v1.json"}
            and len(manifest) == expected["payloads"], "Complete archive inventory")
    for name, binding in manifest.items():
        payload = archive.read(name)
        require(len(payload) == binding["bytes"] and digest(payload) == binding["sha256"],
                "Archive member: " + name)
    return archive


def verify_native(archive, controller_name, exit_name, profile):
    controller = json.loads(archive.read("acquisition/" + controller_name + ".json"))
    terminal = json.loads(archive.read("acquisition/" + exit_name + ".json"))
    require(terminal == profile["native_controller"], "Controller exit projection")
    require(controller["state"] == terminal["state"] == "finished"
            and terminal["native_exit_code"] == 0 and terminal["source_hash_held"], "Native controller exit")
    require(controller["native_pid"] == terminal["native_pid"]
            and controller["creation_filetime"] == terminal["creation_filetime"]
            == terminal["creation_filetime_after"], "Native controller birth")
    capture_name = "capture-" + controller_name.replace("-controller-", "-") + ".py"
    require(digest(archive.read("acquisition/" + capture_name)) == terminal["source_sha256"],
            "Executed acquisition controller")
    host = dict(major=10, minor=0, build=29708, process_machine=0, native_machine=0xAA64)
    require(controller["host_before"] == controller["host_after"] == host, "Native kernel identity")
    require(controller["source_hashes_held"] and controller["installed_images_held"], "Inputs changed")
    source_bindings = {}
    for value, expected in controller["source_sha256"].items():
        native = PureWindowsPath(value)
        if ".assist-process-native-windows-29708-v1" in native.parts:
            relative = "/".join(native.parts[native.parts.index("rax") + 1:])
            member = "inputs/" + relative
            require(digest((ROOT / relative).read_bytes()) == expected, "Public native input changed")
        else:
            member = "acquisition/" + native.name
        require(digest(archive.read(member)) == expected, "Executed native input changed")
        source_bindings[member] = expected
    require(source_bindings == profile["source_bindings"] if "source_bindings" in profile
            else controller["source_sha256"] == profile["source_sha256"], "Source identity projection")
    require(len(controller["installed_images_before"]) == 8, "Physical provider inventory")
    providers = {}
    for value, expected in controller["installed_images_before"].items():
        native = PureWindowsPath(value)
        member = "providers/" + native.parent.name + "/" + native.name
        require(digest(archive.read(member)) == expected, "Physical provider binding")
        providers[member] = expected
    expected_providers = profile["physical_providers"]
    if "source_bindings" not in profile:
        expected_providers = {"providers/" + PureWindowsPath(p).parent.name + "/" + PureWindowsPath(p).name: h
                              for p, h in expected_providers.items()}
    require(providers == expected_providers, "Provider identity projection")
    require(len(controller["runs"]) == 3, "Native producer inventory")
    runs = {}
    for run in controller["runs"]:
        label = run["label"]
        require(label not in runs and run["source_hashes_held"], "Duplicate producer/changed source")
        for phase, key in [("compile", "compile"), ("observe", "observation")]:
            proof = json.loads(archive.read("outputs/" + label + "/" + phase + ".native.json"))
            require(proof == run[key] and proof["state"] == "finished"
                    and proof["native_exit_code"] == 0 and proof["stderr_bytes"] == 0,
                    "Actual native compiler/producer verdict")
            require(proof["native_pid"] > 0 and proof["creation_filetime"] == proof["creation_filetime_after"]
                    and proof["timeout_seconds"] is None, "Native birth/deadline")
            for extension in ["stdout", "stderr"]:
                data = archive.read("outputs/" + label + "/" + phase + "." + extension)
                require(len(data) == proof[extension + "_bytes"]
                        and digest(data) == proof[extension + "_sha256"], "Native raw stream binding")
        stdout = archive.read("outputs/" + label + "/observe.stdout")
        require(stdout.decode("ascii") == run["stdout"], "Native stdout projection")
        image = archive.read("outputs/" + label + "/" + label + ".exe")
        require(digest(image) == run["image_sha256"], "Executed image binding")
        expected_machine = 0xAA64 if label in ["creation", "active-arm64"] else 0x14C if label == "active-x86" else 0x8664
        require(machine(image) == expected_machine, "Executed producer PE machine")
        runs[label] = run
    return controller, runs


def verify(profile, startup_path, active_path):
    with check_archive(startup_path, profile["archive"]) as startup:
        controller, runs = verify_native(startup, "chpe-startup-controller-v1",
                                         "chpe-startup-native-controller-exit-v1", profile)
        require(set(runs) == {"creation", "segments", "xstate"}, "Startup producer inventory")
        creation = projector(profile["projection_adapters"][0], {"require", "children"})
        require(creation["children"](runs["creation"]["stdout"].encode("ascii")) == profile["children"],
                "Initial-record/lifecycle projection")
        for arch, binding in profile["fixtures"].items():
            image = startup.read(binding["member"])
            require(len(image) == binding["bytes"] and digest(image) == binding["sha256"]
                    and machine(image) == binding["pe_machine"], "Unchanged child fixture: " + arch)
        segments = projector(profile["projection_adapters"][1], {"require", "digest", "fields", "project"})
        run = runs["segments"]
        raw = run["stdout"].encode("ascii")
        receipt = dict(phase="finished", native_kernel="10.0.29708.0", images_unchanged=True,
                       installed_images=controller["installed_images_before"],
                       runs=[dict(exit_code=run["observation"]["native_exit_code"], stderr_bytes=0,
                                  stdout_base64=base64.b64encode(raw).decode("ascii"),
                                  stdout_bytes=len(raw), stdout_sha256=digest(raw))])
        for key, value in segments["project"](raw, receipt).items():
            require(profile["segments"][key] == value, "Selector/descriptor projection: " + key)
        require([json.loads(line) for line in runs["xstate"]["stdout"].splitlines()] == profile["xstate"],
                "XSTATE raw projection")
    active = profile["active_context"]
    with check_archive(active_path, active["archive"]) as archive:
        _, runs = verify_native(archive, "chpe-active-controller-v3",
                                "chpe-active-native-controller-exit-v3", active)
        require(set(runs) == {"active-arm64", "active-x64", "active-x86"}, "Active-context ABI inventory")
        for sample in active["native_runs"]:
            run = runs[sample["label"]]
            require(run["compile"] == sample["compile"] and run["observation"] == sample["observation"]
                    and run["image_sha256"] == sample["image_sha256"], "Active-context native proof projection")
            words = run["stdout"].split()
            require(len(words) == 65 and words[0] == "state", "Active-context state extent")
            values = [int(word, 16) for word in words[1:]]
            require(values == sample["state_words"] and [values[i] for i in [0, 1, 6, 10, 12]]
                    == [0x52415854, 4, 0, 78, 1], "Active-context assertions/lifecycle")


def main():
    require(len(sys.argv) in [1, 3], "usage: check-29708.py [startup.zip active.zip]")
    raw = (HERE / "profile-29708-v1.json").read_bytes()
    require(digest(raw) == PROFILE_SHA256, "Frozen profile identity")
    profile = json.loads(raw)
    require(profile["kernel"] == [10, 0, 29708] and profile["native_machine"] == 0xAA64,
            "Finite native identity")
    for member, expected in profile["source_bindings"].items():
        if member.startswith("inputs/"):
            require(digest((ROOT / member.removeprefix("inputs/")).read_bytes()) == expected,
                    "Published producer/fixture identity")
    source = ROOT / "docs/specifications/windows/native-chpe-context-owner/native-active-context-v2.cpp"
    require(digest(source.read_bytes()) == "273ae4e6233d9476725c816e15bb98b36dcb09c05f3696120cee2669dbc3628f",
            "Active-context producer identity")
    if len(sys.argv) == 3:
        verify(profile, Path(sys.argv[1]), Path(sys.argv[2]))
        print("Verified both archives, six compilers, six producers, four child exits and 234 native assertions.")
    else:
        print("Verified frozen profile and public inputs. Separate native archives were not checked.")


if __name__ == "__main__":
    main()
