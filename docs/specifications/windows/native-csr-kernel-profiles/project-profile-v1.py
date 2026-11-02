#!/usr/bin/env python3
"""Project and verify a retained, correctly provider-bound CSR observation ZIP."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import zipfile


def require(condition, description):
    if not condition:
        raise ValueError(description)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def captures(text):
    pattern = r"^dump name=([\w-]+).*?requested=(\d+) ok=(\d+) error=(\d+) got=(\d+) hex=([0-9A-F]*)$"
    result = []
    for line in text.splitlines():
        if not line.startswith("dump "):
            continue
        match = re.fullmatch(pattern, line)
        require(match is not None, "native dump grammar")
        name, requested, ok, error, got, raw = match.groups()
        data = bytes.fromhex(raw)
        require(len(data) == int(got) <= int(requested), "native dump extent")
        if name != "caller-code":
            require(int(ok) == 1 and int(error) == 0 and len(data) == int(requested), name)
        result.append((name, data))
    return result


def metadata(text, arch, kind):
    dumps = dict(captures(text))
    width = int(re.search(r"profile width=(\d+)", text)[1])
    selected = re.search(r"selected shared=([0-9A-F]+) statics=([0-9A-F]+) offset=([0-9A-F]+)", text)
    require(selected is not None, "selected CSR pointers")
    shared, statics, offset = [int(word, 16) for word in selected.groups()]
    require(statics - shared == offset, "native statics arithmetic")
    row = {"architecture": arch, "kind": kind, "pointer_bytes": width,
           "shared": shared, "statics": statics, "statics_offset": offset,
           "getter_code_hex": dumps["csr-pid-code"].hex(),
           "getter_code_sha256": sha(dumps["csr-pid-code"]),
           "selected_prefix_hex": dumps["selected-prefix"].hex()}
    if width == 8:
        peb = dumps["peb"]
        row.update(kernel=[struct.unpack_from("<I", peb, 0x118)[0],
                           struct.unpack_from("<I", peb, 0x11C)[0],
                           struct.unpack_from("<H", peb, 0x120)[0]],
                   session=struct.unpack_from("<I", peb, 0x2C0)[0],
                   server_base=struct.unpack_from("<Q", peb, 0x380)[0],
                   prefix_server=struct.unpack_from("<Q", dumps["selected-prefix"], 40)[0],
                   prefix_server_alias=struct.unpack_from("<Q", dumps["selected-prefix"], 48)[0])
        require(row["kernel"] == [10, 0, 29698] and row["session"] == 0, "native64 kernel/session")
        require(row["server_base"] == row["prefix_server"] == row["prefix_server_alias"], "native CSR aliases")
        require(offset == 0x750, "native64 statics offset")
    pid = re.search(r"csr-pid-value value=([0-9A-F]+)", text)
    if pid:
        row["server_pid"] = int(pid[1], 16)
        require(row["server_pid"] > 0 and row["server_pid"] % 4 == 0, "native server PID")
    require("complete status=0 read-only=1" in text, "readonly terminal record")
    return row


def section(text, arch):
    first = text.split("case=1 ", 1)[0]
    require("status=00000000" in first and "size-out=1048576" in first, "full section map")
    rows = re.findall(r"^region offset=(\d+) bytes=(\d+) state=([0-9A-F]+) protection=([0-9A-F]+) type=([0-9A-F]+)", first, re.M)
    regions = [{"offset": int(offset), "bytes": int(size), "state": int(state, 16),
                "protection": int(protection, 16), "type": int(kind, 16)}
               for offset, size, state, protection, kind in rows]
    require(regions == [{"offset": 0, "bytes": 20480, "state": 4096, "protection": 2, "type": 262144},
                        {"offset": 20480, "bytes": 1028096, "state": 8192, "protection": 0, "type": 262144}], "native SharedSection geometry")
    data = bytes.fromhex(re.search(r"bytes name=committed-snapshot size=20480 hex=([0-9A-F]+)", first)[1])
    require(len(data) == 20480, "committed section bytes")
    require("complete cases=40 mapped-views=20" in text, "all native mapping controls")
    return {"architecture": arch, "view_bytes": 1048576, "regions": regions,
            "committed_sha256": sha(data), "cases": 40, "mapped_views": 20}


def project(bundle, archive_sha256):
    receipt = json.loads(bundle.read("repeat/receipt.json"))
    require(receipt["state"] == "finished" and receipt["inputs_unchanged"], "completed source-bound observation")
    require(receipt["kernel"][:3] == [10, 0, 29698], "29698 native kernel")
    require(len(receipt["samples"]) == 14, "four controls per ABI plus two ARM64 protocol controls")
    for name, expected in receipt["original_sources"].items():
        require(sha(bundle.read("sources/" + name)) == expected, "producer source: " + name)
    for arch, provider in receipt["providers"].items():
        raw = bundle.read("providers/" + arch + "-ntdll.dll")
        require(sha(raw) == provider["before_sha256"] == provider["after_sha256"], "actual mapped provider: " + arch)
        mapped = bytes.fromhex(provider["identity_before"]["mapped_provider_utf16"]).decode("utf-16le")
        require(mapped == provider["mapped_native_path"], "mapped provider identity")
        require(provider["identity_before"] == provider["identity_after"], "provider identity stability")
        if arch == "x86":
            require("\\sychpe32\\" in provider["path"].lower(), "x86 physical provider, not redirected System32")
    logs, identities = {}, []
    for row in receipt["samples"]:
        arch, kind = row["arch"], row["kind"]
        image = bundle.read("executables/" + arch + "-" + kind + ".exe")
        require(sha(image) == row["image"]["sha256"] and len(image) == row["image"]["bytes"], "executed image")
        pe = struct.unpack_from("<I", image, 0x3C)[0]
        require(image[pe:pe + 4] == b"PE\0\0" and struct.unpack_from("<H", image, pe + 4)[0] == row["image"]["machine"], "executed PE machine")
        raw = bundle.read("repeat/" + arch + "-" + kind + ".log")
        require(sha(raw) == row["stdout_sha256"] and row["exit_code"] == 0, "native process output")
        logs[arch, kind] = raw.decode("ascii").replace("\r\n", "\n")
        identities.append({"architecture": arch, "kind": kind, "image": row["image"],
                           "stdout_sha256": row["stdout_sha256"], "compiler_sha256": row["compiler_sha256"]})
    metas = [metadata(logs[arch, kind], arch, kind)
             for arch in ("arm64", "x64", "x86") for kind in ("metadata1", "metadata2")]
    shared = [section(logs[arch, "section"], arch) for arch in ("arm64", "x64", "x86")]
    require(len({row["committed_sha256"] for row in shared}) == 1, "one captured shared section across process ABIs")
    arm64 = [row for row in metas if row["architecture"] == "arm64"]
    require(arm64[0]["getter_code_hex"] == arm64[1]["getter_code_hex"], "independent PID getter code captures")
    getter = bytes.fromhex(arm64[0]["getter_code_hex"])
    words = struct.unpack_from("<7I", getter)
    require(words[0] & 0x9F00001F == 0x90000008 and words[3] & 0x9F00001F == 0x90000008, "PID getter ADRP registers")
    require(words[1] & 0xFFC003FF == 0x39400108 and words[4] & 0xFFC003FF == 0xF9400108, "byte flag and pointer-width PID loads")
    require(words[2] == 0x7100011F and words[5:] == (0x9A8813E0, 0xD65F03C0), "PID getter compare/select/return ABI")
    secure_text = logs["arm64", "secure"]
    require("return ordinal=0 status=00000000" in secure_text and "complete captured=1 calls=1 exit=41" in secure_text, "natural secure connection")
    secure = dict(captures(secure_text))
    require(secure["port-name-utf16"].decode("utf-16le") == "\\Windows\\ApiPort", "selected CSR port")
    require(secure["security-qos"].hex() == "000000000200000001010000", "native security QoS")
    require(secure["required-server-sid"].hex() == "010100000000000512000000", "required System SID")
    require(len(secure["client-view-before"]) == 48 and len(secure["server-view-after"]) == 24, "native view widths")
    require(secure["server-view-after"] == bytes(24), "cleared server view")
    require(struct.unpack_from("<I", secure["client-view-before"])[0] == 48 and struct.unpack_from("<Q", secure["client-view-before"], 24)[0] == 65536, "native client view geometry")
    require(int.from_bytes(secure["max-message-after"], "little") == 952 and int.from_bytes(secure["connection-length-after"], "little") == 48, "native connection output widths")
    server, statics, pid = struct.unpack_from("<QQQ", secure["connection-after"])
    require(server == arm64[1]["server_base"] and statics - server == 0x750 and pid == arm64[1]["server_pid"], "independent metadata/reply identity")
    require(secure["connection-after"][32:] == secure["connection-before"][32:], "preserved native information tail")
    user_text = logs["arm64", "exchange"]
    require("complete installed=1 entered=2 returned=2 exit=41" in user_text, "natural USER exchange")
    returns = re.findall(r"^return ordinal=\d+ name=\w+ status=([0-9A-F]+)$", user_text, re.M)
    require(returns == ["00000000", "00000000"], "successful native protocol returns")
    entry = re.search(r"^entry ordinal=1 name=NtAlpcSendWaitReceivePort caller=[0-9A-F]+ args=([0-9A-F,]+)$", user_text, re.M)
    require(entry is not None, "native USER entry")
    arguments = [int(word, 16) for word in entry[1].rstrip(",").split(",")]
    require(len(arguments) == 8 and arguments[1] == 0x20000 and arguments[2] == arguments[4], "native synchronous USER flags/alias")
    require(arguments[3] == arguments[6] == arguments[7] == 0, "no native attributes or timeout")
    user = captures(user_text)
    send = next(raw for name, raw in user if name == "send-message")
    before = [raw for name, raw in user if name == "client-section-before-call"][-1]
    aliases = re.search(r"client-alias local=([0-9A-F]+) remote=([0-9A-F]+) size=(\d+)", user_text)
    local, remote, size = int(aliases[1], 16), int(aliases[2], 16), int(aliases[3])
    require(size == 65536, "pagefile connection backing size")
    capture_pointer = struct.unpack_from("<Q", send, 40)[0]
    offset = capture_pointer - remote
    require(0 <= offset <= size - 628, "captured USER pointer bounds")
    capture = before[offset:offset + 628]
    require(len(capture) == 628 and struct.unpack_from("<I", capture)[0] == 628, "native capture extent")
    require(struct.unpack_from("<I", capture, 16)[0] == 1 and struct.unpack_from("<Q", capture, 32)[0] == 72, "one capture pointer field")
    require(capture[40:624] == bytes(584), "zero native USER information input")
    require(len(send) == 88 and struct.unpack_from("<HH", send) == (48, 88), "native message widths")
    require(struct.unpack_from("<Q", send, 64)[0] == 3 and struct.unpack_from("<Q", send, 80)[0] == 584, "native USER selector/length")
    require(struct.unpack_from("<Q", send, 72)[0] == capture_pointer + 40, "native USER pointer relocation")
    reply = dict(user)["receive-after"]
    require(len(reply) == 88 and struct.unpack_from("<3H", reply) == (48, 88, 2), "native USER reply widths/type")
    client_geometry = {}
    for arch in ("arm64", "x64", "x86"):
        text = logs[arch, "client"]
        require("SUMMARY calls=2" in text, "both native USER acquisition calls")
        require(len(re.findall(r"^CONNECT sample=\d+ server=3 supplied=584 status=00000000 exception=00000000 returned=584 inside=0", text, re.M)) == 2, "successful USER acquisitions")
        rows = []
        for line in text.splitlines():
            if line.startswith("MAP "):
                require(line.endswith("stable=1") or "state=00002000" in line, "stable readonly USER bytes")
                rows.append(line.split(" hex=", 1)[0])
            elif line.startswith("MAP-END "):
                rows.append(line)
        client_geometry[arch] = rows
    return {"schema": 1, "kernel": {"major": 10, "minor": 0, "build": 29698},
            "admitted_profile": {"host_arch": "arm64", "guest_arch": "arm64", "session": 0,
                                 "measured_build_set": [29683, 29695, 29698]},
            "metadata_samples": metas, "shared_section": shared, "client_geometry": client_geometry,
            "secure_connect": {"status": 0, "dumps": {name: raw.hex() for name, raw in secure.items() if name != "caller-code"}},
            "user_exchange": {"request_hex": send.hex(), "capture_header_hex": capture[:40].hex(),
                              "allocation_bytes": 628, "header_bytes": 40, "information_bytes": 584,
                              "pointer_count": 1, "pointer_field_offset": 72, "padding_hex": capture[624:].hex(),
                              "native_client_base": local, "native_server_base": remote,
                              "response_hex": dict(user)["receive-after"].hex(), "status": 0},
            "evidence": {"archive_sha256": archive_sha256, "samples": identities,
                         "source_origins": receipt["original_source_origins"],
                         "providers": receipt["providers"],
                         "native_source_inputs_unchanged": True,
                         "scope": "Three process ABIs on one ARM64 kernel; model server identities are not whole-reply byte equality."}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--archive-sha256", required=True)
    args = parser.parse_args()
    archive_hash = sha(args.archive.read_bytes())
    require(archive_hash == args.archive_sha256, "archive identity")
    with zipfile.ZipFile(args.archive) as bundle:
        manifest = json.loads(bundle.read("archive-manifest.json"))
        names = bundle.namelist()
        require(len(names) == len(set(names)) == len(manifest) + 1, "unique archive members")
        require(set(names) == set(manifest) | {"archive-manifest.json"}, "complete archive manifest")
        for name, identity in manifest.items():
            path = PurePosixPath(name)
            require(not path.is_absolute() and ".." not in path.parts, "archive member path")
            raw = bundle.read(name)
            require(len(raw) == identity["bytes"] and sha(raw) == identity["sha256"], name)
        projected = project(bundle, archive_hash)
    args.output.write_text(json.dumps(projected, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "metadata_samples": 6, "native_images": 14}))


if __name__ == "__main__":
    main()
