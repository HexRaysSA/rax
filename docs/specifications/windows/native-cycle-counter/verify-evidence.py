"""Check native counter observations and the actual Rust adapter execution."""
from pathlib import Path
import copy
import hashlib
import json
import re


SOURCE_SHA256 = "495a17c31e6aacac04e40aa7298b9128ed6f4b836c797fc38556f07a48cfe24e"
IMAGE_SHA256 = "d0cb73246d27431ae082421d79c59ae62d1a1c42dd9f83be5f3a66107245cb89"
NTDLL_SHA256 = "e9943254a04813ede84d84b1be5fb4f41537d103d2771449db56a80cf6f301fd"
REGISTERS_SOURCE_SHA256 = "512b11ae0579e7e08c7f0ed626f45368be0cbad6055bf5461beb07a0ad84b3cf"
REGISTERS_IMAGE_SHA256 = "cff08a7d0a80079c062ddb2a71f5c26d1ae0db59ca79e6e17d81c161130f59c2"
RUST_IMAGE_SHA256 = "8c04265ea4b70894601cd9e6f4f5c865b60bb60cbfe555416b053971cf506204"
SUBJECT = "S-1-5-21-432357189-4232641918-3742464398-1000"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(source, receipt):
    require(hashlib.sha256(source).hexdigest() == SOURCE_SHA256, "source identity")
    require(receipt["schema"] == "assist-native-pmu-probe-v27", "receipt schema")
    require(type(receipt["exit_code"]) is int and receipt["exit_code"] == 0, "producer exit")
    require(receipt["native_machine"] == "ARM64", "native architecture")
    require(receipt["windows_version"][:3] == [10, 0, 29698], "native kernel")
    require(receipt["image_sha256"] == IMAGE_SHA256, "producer image")
    require(receipt["ntdll_sha256"] == NTDLL_SHA256, "native NTDLL")
    require(receipt["stderr"] == "", "producer stderr")
    require(receipt["native_validation_jobs_restarted"] is False, "validation ownership")
    stdout = receipt["stdout"].encode("utf-8")
    require(hashlib.sha256(stdout).hexdigest() == receipt["stdout_sha256"], "raw stdout hash")
    rows = [json.loads(line) for line in receipt["stdout"].splitlines()]
    require(len(rows) == 10, "complete record count")
    require(rows[0] == {"kind": "host", "schema": "rax-native-pmccntr-read-v1",
                        "pointer_bytes": 8, "qpc_frequency_hz": 24000000}, "host record")
    require(rows[-1] == {"kind": "finished", "samples": 8}, "completion record")
    for index, row in enumerate(rows[1:-1]):
        require(row["kind"] == "sample" and row["index"] == index, "ordered samples")
        require(row["busy"] == index % 2, "workload partition")
        for suffix in ["before", "after"]:
            status = row["status_" + suffix]
            value = row["counter_" + suffix]
            require(type(status) is int and status == 0, "permitted read")
            require(type(value) is int and 0 < value < 2**64, "live full-width counter")
        require(row["qpc_after"] > row["qpc_before"], "independent QPC interval")
        require(row["thread_cycles_after"] >= row["thread_cycles_before"], "calling-thread control")
    return rows


def verify_current_user(receipt, schema, image):
    require(receipt["schema"] == schema, "receipt schema")
    require(type(receipt["exit_code"]) is int and receipt["exit_code"] == 0,
            "producer exit")
    require(receipt["image_sha256"] == image, "producer image")
    require(receipt["ntdll_sha256"] == NTDLL_SHA256, "native NTDLL")
    require(receipt["subject"] == SUBJECT, "captured ordinary-user subject")
    require(type(receipt["pid"]) is int and receipt["pid"] > 0, "native PID")
    require(re.fullmatch(r"[0-9]{18}", receipt["creation"]) is not None,
            "native creation FILETIME")
    require(receipt["stderr"] == "", "producer stderr")
    require(receipt["native_validation_jobs_restarted"] is False,
            "validation ownership")
    require(receipt["new_subject_control"] is True, "distinct subject control")
    require(hashlib.sha256(receipt["stdout"].encode()).hexdigest()
            == receipt["stdout_sha256"], "raw stdout hash")


def verify_registers(source, receipt):
    require(hashlib.sha256(source).hexdigest() == REGISTERS_SOURCE_SHA256,
            "register control source")
    require(receipt["source_sha256"] == REGISTERS_SOURCE_SHA256,
            "native register source identity")
    verify_current_user(receipt, "assist-native-pmu-probe-v35", REGISTERS_IMAGE_SHA256)
    lines = receipt["stdout"].splitlines()
    require(len(lines) == 37, "complete all-destination control")
    require(lines[-1] == "summary calls=36 allocations=36 releases=36 failures=0",
            "all native pages released and cases completed")
    negative_words = [0xD5381000, 0xD5382000, 0xD5384200, 0xD5384100]
    for index, line in enumerate(lines[:-1]):
        row = dict(field.split("=", 1) for field in line.split())
        rt = index if index < 32 else 0
        instruction = 0xD53B9D00 | rt if index < 32 else negative_words[index - 32]
        require(int(row["row"]) == index and int(row["rt"]) == rt,
                "ordered unique destinations and controls")
        require(int(row["insn"], 16) == instruction, "actual MRS encoding")
        if 0 < rt < 31:
            scratch = 16 if rt == 17 else 17
            code = [0xAA0003E0 | rt << 16 | scratch, instruction,
                    0xAA0003E0 | rt << 16, 0xAA0003E0 | scratch << 16 | rt]
        else:
            code = [instruction] + ([0xAA1F03E0] if rt == 31 else [])
        code.append(0xD65F03C0)
        require(int(row["words"]) == len(code), "exact thunk length")
        require([int(word, 16) for word in row["code"].split(",")] == code,
                "exact saved instruction bytes")
        require(all(row[key] == "1" for key in ["stable", "teb_stable", "ok"]),
                "instruction and caller TEB preservation")
        value = int(row["value"], 16)
        if index < 32:
            require(int(row["status"], 16) == 0, "permitted native counter read")
            require(value == 0 if rt == 31 else 0 < value < 2**64 - 1,
                    "XZR discard or full-width live value")
        else:
            require(int(row["status"], 16) == 0xC000001D and value == 2**64 - 1,
                    "privileged negative control remains denied")


def verify_rust(proof, receipt):
    verify_current_user(receipt, "assist-native-pmu-probe-v37", RUST_IMAGE_SHA256)
    require(proof["schema"] == "rax-windows-cycle-counter-build-source-v1",
            "build-source schema")
    require(proof["target"] == "aarch64-pc-windows-msvc", "actual native target")
    require(proof["image_sha256"] == RUST_IMAGE_SHA256, "built/native image join")
    require(hashlib.sha256(proof["wrapper_source"].encode()).hexdigest()
            == proof["wrapper_source_sha256"] == receipt["source_sha256"],
            "built/native source join")
    require(hashlib.sha256(proof["case_source"].encode()).hexdigest()
            == proof["case_source_sha256"]
            == proof["production_and_test_source_sha256"][
                "src/user/windows/arch/tests/cycle_counter_tests.rs"],
            "actual captured regression source")
    expected = {
        "pmccntr_remains_disabled_in_the_default_os_neutral_arm64_cpu",
        "windows_pmccntr_does_not_grant_other_pmu_reads_or_writes",
        "windows_pmccntr_inherits_the_profile_in_new_threads",
        "windows_pmccntr_matches_a_pinned_native_processor_counter",
        "windows_pmccntr_read_preserves_an_exclusive_reservation_across_slices",
        "windows_pmccntr_retires_all_destinations_without_losing_context",
    }
    names = re.findall(r"^test counter_cases::([a-z0-9_]+) \.\.\. ",
                       receipt["stdout"], re.MULTILINE)
    require(len(names) == 6 and set(names) == expected, "all six actual adapter cases")
    require(re.search(r"^test result: ok\. 6 passed; 0 failed; 0 ignored; "
                      r"0 measured; 0 filtered out; finished in [0-9.]+s$",
                      receipt["stdout"], re.MULTILINE) is not None,
            "complete unfiltered native Rust result")
    samples = re.findall(r"native-pmccntr before=(0x[0-9a-f]+) actual=(0x[0-9a-f]+) "
                         r"after=(0x[0-9a-f]+) group=([0-9]+) affinity=(0x[0-9a-f]+)",
                         receipt["stdout"])
    require(len(samples) == 1, "independent pinned native bracket")
    before, actual, after, group, mask = samples[0]
    before, actual, after, mask = (int(value, 16) for value in [before, actual, after, mask])
    require(0 < before <= actual <= after < 2**64, "same-processor counter interval")
    require(int(group) < 2**16 and 0 < mask < 2**64 and mask & (mask - 1) == 0,
            "one processor in a native group")


def reject_corruption(check, *args):
    try:
        check(*args)
    except ValueError:
        return
    raise ValueError("accepted a controlled corruption")


def main():
    root = Path(__file__).resolve().parent
    source = (root / "native-pmccntr-read-v1.c").read_bytes()
    receipt = json.loads((root / "native-read-arm64-v1.json").read_text())
    rows = verify(source, receipt)
    corruptions = []
    for field, value in [("image_sha256", "0" * 64), ("ntdll_sha256", "0" * 64),
                         ("exit_code", False), ("native_machine", "AMD64")]:
        changed = copy.deepcopy(receipt)
        changed[field] = value
        corruptions.append(changed)
    for mutation in ["missing", "status", "zero"]:
        changed = copy.deepcopy(receipt)
        records = copy.deepcopy(rows)
        if mutation == "missing":
            records.pop(1)
        elif mutation == "status":
            records[1]["status_before"] = 0xC000001D
        else:
            records[1]["counter_before"] = 0
        changed["stdout"] = "\r\n".join(json.dumps(row) for row in records) + "\r\n"
        changed["stdout_sha256"] = hashlib.sha256(changed["stdout"].encode()).hexdigest()
        corruptions.append(changed)
    for changed in corruptions:
        reject_corruption(verify, source, changed)
    register_source = (root / "native-pmccntr-registers.cpp").read_bytes()
    registers = json.loads((root / "native-registers-arm64-v1.json").read_text())
    proof = json.loads((root / "native-rust-build-source-v1.json").read_text())
    rust = json.loads((root / "native-rust-arm64-v1.json").read_text())
    verify_registers(register_source, registers)
    verify_rust(proof, rust)
    rejected = len(corruptions)
    for check, source_data, native in [(verify_registers, register_source, registers),
                                       (verify_rust, proof, rust)]:
        for field, value in [("exit_code", False), ("subject", "S-1-5-18"),
                             ("image_sha256", "0" * 64), ("stdout_sha256", "0" * 64)]:
            changed = copy.deepcopy(native)
            changed[field] = value
            reject_corruption(check, source_data, changed)
            rejected += 1
        changed = copy.deepcopy(native)
        changed["stdout"] = changed["stdout"].replace("rt=18 ", "rt=17 ") if check == verify_registers else changed["stdout"].replace("6 passed", "5 passed")
        changed["stdout_sha256"] = hashlib.sha256(changed["stdout"].encode()).hexdigest()
        reject_corruption(check, source_data, changed)
        rejected += 1
    print(f"verified 16 native reads, 36 register controls, 6 native Rust cases; "
          f"rejected {rejected} controlled corruptions")


if __name__ == "__main__":
    main()
