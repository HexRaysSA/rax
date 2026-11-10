"""Verify the frozen creation profile and, optionally, its retained archive."""
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = "3601d909f07f3b851954ba32853004f9cca0bada7fc26cd7b0275121e1039097"
ARCHIVE_SHA256 = "5d60b1e5883c9bb438ba269240dbbe42c9de92172f44f2509b6653e4cc81609a"
ARCHIVE_BYTES = 1847291


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def machine(raw):
    require(raw[:2] == b"MZ", "DOS signature")
    at = struct.unpack_from("<I", raw, 0x3c)[0]
    require(raw[at:at + 4] == b"PE\0\0", "PE signature")
    return struct.unpack_from("<H", raw, at + 4)[0]


def children(raw):
    result, current = [], None
    for line in raw.decode("ascii").splitlines():
        row = dict(re.findall(r"([\w-]+)=([^\s]+)", line))
        if line.startswith("KERNEL "):
            require([int(row[k]) for k in ("major", "minor", "build")] == [10, 0, 29704]
                    and row["pointer-bytes"] == "8", "controller kernel and ABI")
        elif line.startswith("CHILD "):
            require(row["identify"] == "1", "native machine query")
            current = dict(architecture=row["label"], reported_machine=int(row["machine"], 16),
                           native_machine=int(row["native"], 16), fields=[])
            result.append(current)
        elif line.startswith("PEB native-status="):
            require(row["native-status"] == "00000000" and row["returned"] == "48", "native PEB query")
        elif line.startswith("PEB compat-status="):
            require(row["compat-status"] == "00000000" and row["returned"] == "8", "compat PEB query")
        elif line.startswith("FIELD "):
            require(current is not None and row["read"] == "1", "field ownership and read")
            peb, pointer = int(row["peb"], 16), int(row["pointer"], 16)
            payload = bytes.fromhex(row.get("hex", ""))
            require((row["payload"] == "1" and len(payload) == 32) if pointer
                    else row["payload"] == "0" and not payload, "record extent")
            current["fields"].append(dict(name=row["name"], field_offset=int(row["offset"], 16),
                pointer_bytes=int(row["pointer-bytes"]), field_read=True,
                pointer_nonzero=bool(pointer), peb_relative=pointer - peb if pointer else None,
                payload_hex=payload.hex(), memory=dict(state=int(row["state"], 16),
                    protect=int(row["protect"], 16), type=int(row["type"], 16),
                    region_bytes=int(row["region-bytes"]),
                    base_relative_to_peb=int(row["base"], 16) - peb if pointer else None,
                    allocation_relative_to_peb=int(row["allocation"], 16) - peb if pointer else None)))
        elif line.startswith("RESUME "):
            require(row["label"] == current["architecture"] and row["previous"] == "1", "one resume")
            current["resume_previous"] = 1
        elif line.startswith("EXIT "):
            require(row["label"] == current["architecture"] and row["wait"] == "0"
                    and row["query"] == "1" and row["code"] == "0"
                    and row["thread-closed"] == row["process-closed"] == "1", "natural exit and closure")
            current["exit_code"] = 0
        elif line.startswith("DONE "):
            require(row == {"completed": "3", "expected": "3", "debug-flags": "0"}, "completed normal capture")
    require(len(result) == 3 and all(c.get("exit_code") == 0 for c in result), "all original children")
    return result


def archive(path, profile):
    raw = path.read_bytes()
    require(identity(raw) == {"bytes": ARCHIVE_BYTES, "sha256": ARCHIVE_SHA256}, "archive identity")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        manifest = json.loads(z.read("archive-manifest.json"))
        require(len(manifest) == 12 and len(z.namelist()) == 13
                and set(z.namelist()) == set(manifest) | {"archive-manifest.json"}
                and z.testzip() is None, "complete payload inventory")
        for name, expected in manifest.items():
            require(identity(z.read(name)) == expected, "payload: " + name)
        binding_raw = z.read("binding/native-source-v1.json")
        binding = json.loads(binding_raw)
        receipt = json.loads(z.read("receipt/native-receipt-v1.json"))
        require(receipt["source_sha256"] == identity(binding_raw)["sha256"]
                == profile["source_binding_sha256"], "launch binding")
        require(receipt["phase"] == "finished" and not receipt.get("error")
                and receipt["images_unchanged"] and receipt["inputs_unchanged"]
                and not receipt["native_validation_jobs_restarted"], "completed unchanged acquisition")
        require(receipt["installed_images"] == profile["held_installed_images"]
                and receipt["native_kernel"] == "10.0.29704.0", "native identity")
        require(len(binding["programs"]) == len(receipt["runs"]) == 1, "one controller")
        run, program = receipt["runs"][0], binding["programs"][0]
        require(run["label"] == program["architecture"] and run["arguments"] == program["arguments"]
                and run["exit_code"] == 0 and run["stderr_bytes"] == 0
                and run["stderr_sha256"] == identity(b"")["sha256"], "original controller verdict")
        stdout = base64.b64decode(run["stdout_base64"], validate=True)
        require(identity(stdout) == {"bytes": run["stdout_bytes"], "sha256": run["stdout_sha256"]}
                and stdout == z.read("stdout/native-stdout-v1.log"), "complete original stdout")
        require(children(stdout) == profile["children"], "independent field and lifecycle projection")
        package = z.read("package/executed-inputs.zip")
        require(identity(package) == binding["package"], "executed package")
        with zipfile.ZipFile(io.BytesIO(package)) as inputs:
            for item in binding["inputs"]:
                require(identity(inputs.read(item["package_name"]))
                        == {key: item[key] for key in ("bytes", "sha256")}, "executed input")
            require(inputs.read("creation.cpp") == (HERE / "creation-v1.cpp").read_bytes(), "executed source")
            require(identity(inputs.read("creation.exe")) == profile["controller_image"]
                    and machine(inputs.read("creation.exe")) == 0xaa64, "controller image")
            for arch, expected in profile["original_fixtures"].items():
                image = inputs.read(arch + ".exe")
                require(identity(image) == expected and machine(image) == profile["input_pe_machines"][arch],
                        "original child image: " + arch)
        provider = receipt["captured_xtajit"]
        dll = base64.b64decode(provider["data_base64"], validate=True)
        require(dll == z.read("providers/xtajit64.dll")
                and identity(dll) == {key: profile["xtajit64"][key] for key in ("bytes", "sha256")}
                and identity(dll)["sha256"] == receipt["installed_images"][provider["path"]], "held XtA provider")


def main():
    require(len(sys.argv) in (1, 2), "usage: verify-v1.py [native-chpe-creation-29704-v1.zip]")
    raw = (HERE / "profile-29704-v1.json").read_bytes()
    require(identity(raw)["sha256"] == PROFILE_SHA256, "frozen profile identity")
    profile = json.loads(raw)
    require(identity((HERE / "creation-v1.cpp").read_bytes())["sha256"] == profile["source"]["sha256"],
            "published controller source")
    require(profile["kernel"] == [10, 0, 29704] and profile["native_machine"] == 0xaa64,
            "finite native identity")
    if len(sys.argv) == 2:
        archive(Path(sys.argv[1]), profile)
        print("Verified archive, launch/source/image bindings, three natural exits and initial PEB fields.")
    else:
        print("Verified frozen profile and source. Separate raw archive was not checked.")


if __name__ == "__main__":
    main()
