"""Project private Windows ARM64 BASE locale observations without subject bytes."""

import argparse
import json
from pathlib import Path
import re
import struct
import zipfile

from verify import digest, dumps


def project(native_archive, diagnostic_archive):
    with zipfile.ZipFile(native_archive) as archive:
        receipt = json.loads(archive.read("native-receipt.json"))
        assert receipt["state"] == "finished"
        assert (receipt["build"], receipt["revision"], receipt["native_machine"], receipt["session"]) == (
            29708, 1003, "ARM64", 1
        )
        assert receipt["ntdll"] == "ef1c9034813e18e5fb7cf6dc44802c15952d27dcecec46813ba883adda572f44"
        assert [run["label"] for run in receipt["runs"]] == ["public", "public-and-fixed"]
        runs, results = [], []
        for run, count in zip(receipt["runs"], (1, 7), strict=True):
            raw = archive.read(run["label"] + ".stdout")
            assert run["exit"] == 0 and digest(raw) == run["stdout_sha256"]
            stderr = archive.read(run["label"] + ".stderr")
            assert not stderr and digest(stderr) == run["stderr_sha256"]
            stdout = "\n".join(raw.decode().splitlines())
            assert "controller-session=1" in stdout
            assert f"complete installed=1 entered={count + 1} returned={count + 1} exit=41" in stdout
            assert re.findall(r"^receive-length before=(\d+) after=(\d+)$", stdout, re.M) == [
                ("952", "80")
            ] * count
            assert re.findall(r"^return ordinal=\d+ name=NtAlpcSendWaitReceivePort status=(\w+)$",
                              stdout, re.M) == ["00000000"] * count

            aliases = re.findall(r"^client-alias local=([0-9A-F]+) remote=([0-9A-F]+) size=(\d+)$",
                                 stdout, re.M)
            assert len(aliases) == 1
            local, remote = (int(value, 16) for value in aliases[0][:2])
            view_size = int(aliases[0][2])
            assert view_size == 65536
            locations = re.findall(
                r"^base-info api=1001B capture-remote=([0-9A-F]+) info-remote=([0-9A-F]+) "
                r"info-local=([0-9A-F]+) bytes=1660$", stdout, re.M
            )
            assert len(locations) == count
            names = ("base-info-before", "base-info-after", "send-message", "receive-after",
                     "base-capture-before")
            observed = [dumps(stdout, name) for name in names]
            assert all(len(group) == count for group in observed)
            for initial, final, send, reply, header, location in zip(*observed, locations, strict=True):
                assert len(initial) == len(final) == 1660
                assert len(send) == len(reply) == 80
                assert send[:8] == bytes.fromhex("2800500000000000")
                assert reply[:8] == bytes.fromhex("2800500002000000")
                assert send[48:64] == reply[48:64] == struct.pack("<IIII", 0x1001B, 0, 0, 0)
                capture, = struct.unpack_from("<Q", send, 40)
                info, declared = struct.unpack_from("<QQ", send, 64)
                assert declared == 1660 and reply[64:] == send[64:]
                assert remote <= capture and capture + 1704 <= remote + view_size
                assert info == capture + 40
                assert tuple(int(address, 16) for address in location) == (
                    capture, info, local + info - remote
                )
                assert len(header) == 40
                assert struct.unpack_from("<I", header)[0] == 1704
                assert struct.unpack_from("<I", header, 16)[0] == 1
                assert struct.unpack_from("<QQ", header, 24) == (0, 64)
                results.append(final)

            fixed = re.findall(
                r"^fixed-base-query sample=(\d+) allocated=1660 status=00000000 "
                r"reply=00000000 bytes=1660 data=", stdout, re.M
            )
            poison = struct.pack("<I", 0xBAADF00D) * 415
            zero = bytes(1660)
            controls = (
                [("BAADF00D", poison), ("A5", bytes([0xA5]) * 1660),
                 ("5A", bytes([0x5A]) * 1660), ("00", zero),
                 ("BAADF00D", poison), ("00", zero)]
                if count == 7 else []
            )
            assert fixed == [str(index) for index in range(count - 1)]
            assert observed[0][1:] == [prefill for _, prefill in controls]
            runs.append(dict(label=run["label"], child_exit=41, calls=count,
                             fixed_output_prefills=[label for label, _ in controls]))
        assert len(results) == 8 and len(set(results)) == 1

    with zipfile.ZipFile(diagnostic_archive) as archive:
        trace = json.loads(archive.read("trace.json"))
        assert trace["exit"] == 125
        assert trace["cmd_sha256"] == "731ce9be4b04b567696b6fb88769d73997d2957bb2d6f6e87574360a250beb96"
        assert digest(archive.read("stderr.log")) == trace["stderr_sha256"]
        assert trace["matches"][0] == (
            "CSR own-child observation arch=arm64 build=29708 request=Some(65563) message_len=80 "
            "data=40 total=80 declared_bytes=Some(1660) send_attributes=false "
            "receive_attributes=false timeout=false capacity=952"
        )
        assert "NtAlpcSendWaitReceivePort unmeasured CSR message/profile" in trace["matches"][1]
    return dict(
        native_kernel=[10, 0, receipt["build"], receipt["revision"]],
        native_machine=receipt["native_machine"], native_session=receipt["session"],
        native_ntdll_sha256=receipt["ntdll"], native_archive_sha256=digest(native_archive.read_bytes()),
        runs=runs, public_and_fixed_outputs_identical=True,
        transport_status=0, service_status=0,
        api=0x1001B, port_data_bytes=40, port_message_bytes=80, receive_capacity_bytes=952,
        receive_bytes=80, capture_bytes=1704, capture_header_bytes=40,
        capture_pointer_count=1, message_pointer_slot=64, information_bytes=1660,
        cmd_sha256=trace["cmd_sha256"],
        unmodeled_cmd_exit=trace["exit"], diagnostic_archive_sha256=digest(diagnostic_archive.read_bytes()),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_archive", type=Path)
    parser.add_argument("diagnostic_archive", type=Path)
    options = parser.parse_args()
    print(json.dumps(project(options.native_archive, options.diagnostic_archive), indent=2))
