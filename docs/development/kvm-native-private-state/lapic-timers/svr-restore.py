#!/usr/bin/env python3
"""Compare raw and SVR-staged restore of an expired x2APIC one-shot."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent
SVR_SEQUENCE = r"""
    (void)events;
    *pending_nmi = 0;
    uint32_t svr = get_register(saved, 0xf0);
    struct {
        struct kvm_msrs header;
        struct kvm_msr_entry entries[9];
    } msrs = {
        .header.nmsrs = 8,
        .entries = {
            {.index = 0x80f, .data = svr & ~(1u << 8)},
            {.index = 0x80f, .data = svr},
            {.index = 0x832, .data = get_register(saved, 0x320)},
            {.index = 0x833, .data = get_register(saved, 0x330)},
            {.index = 0x834, .data = get_register(saved, 0x340)},
            {.index = 0x835, .data = get_register(saved, 0x350)},
            {.index = 0x836, .data = get_register(saved, 0x360)},
            {.index = 0x837, .data = get_register(saved, 0x370)},
        }
    };
    if ((get_register(saved, 0x30) >> 16 & 0xffu) >= 6) {
        msrs.entries[8] = (struct kvm_msr_entry){.index = 0x82f, .data = get_register(saved, 0x2f0)};
        msrs.header.nmsrs++;
    }
    int completed = ioctl(target->cpu, KVM_SET_MSRS, &msrs);
    if (completed != (int)msrs.header.nmsrs) {
        fprintf(stderr, "APIC SVR and LVT restore completed %d/%u\n", completed, msrs.header.nmsrs);
        exit(1);
    }"""


def source_for(parent, masked, initialized):
    text = masked["candidate"](parent, initialized)
    start = text.index("    struct kvm_mp_state original = {0};",
                       text.index("static void normalize_expired"))
    finish = text.index("\n}\n\nint main(", start)
    text = text[:start] + SVR_SEQUENCE + text[finish:]
    return masked["replace_once"](
        text,
        "    set_register(&initial, 0x350, 1u << 16);",
        "    set_register(&initial, 0x330, 0x51);\n"
        "    set_register(&initial, 0x340, 0x400u);\n"
        "    set_register(&initial, 0x350, 1u << 16);\n"
        "    set_register(&initial, 0x360, 0x53);\n"
        "    set_register(&initial, 0x370, 0x5f);",
    )


def validate(observation, pending, stage):
    assert observation["pending_case"] == pending
    assert observation["normalized"] == stage
    assert observation["source_delivery"] == int(pending)
    assert observation["target_delivery"] == int(pending or not stage)
    assert observation["source_extra"] == observation["target_extra"] == 0
    assert observation["saved_current_count"] == 0
    assert observation["saved_initial_count"] == observation["restored_initial_count"] == 1_000_000
    assert observation["fake_nmi_pending"] == 0
    for equal in ("registers", "special", "events", "mp", "memory"):
        assert observation[equal + "_equal"], (equal, observation)
    assert observation["source_destroyed_before_restore"]
    if stage:
        assert observation["lapic_equal"], observation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=5, choices=range(1, 101),
                        metavar="1–100")
    repetitions = parser.parse_args().repetitions
    masked_path = ROOT / "masked-restore.py"
    masked = runpy.run_path(str(masked_path))
    parent = (ROOT / "lapic-expired-normalize-v2.c").read_bytes()
    sha256 = lambda data: hashlib.sha256(data).hexdigest()
    assert sha256(parent) == masked["PARENT_SHA256"]
    compiler_flags = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2", "-pthread"]
    sources, trials = {}, []
    with tempfile.TemporaryDirectory(prefix="rax-svr-lapic-") as temporary:
        scratch = Path(temporary)
        for initialized in (False, True):
            profile = "initialized-relocated" if initialized else "fresh-default"
            source = scratch / (profile + ".c")
            source.write_text(source_for(parent.decode(), masked, initialized))
            sources[profile] = sha256(source.read_bytes())
            binary = source.with_suffix("")
            subprocess.run(["gcc", *compiler_flags, str(source), "-o", str(binary)], check=True)
            for case in ("settled", "pending"):
                for method in ("raw", "normalize"):
                    for trial in range(repetitions):
                        run = subprocess.run([str(binary), case, method], check=True,
                                             capture_output=True, text=True, timeout=5)
                        observation = json.loads(run.stdout)
                        validate(observation, case == "pending", method == "normalize")
                        trials.append(dict(profile=profile, case=case, method=method,
                                           trial=trial, observation=observation))
    assert not scratch.exists()
    print(json.dumps(dict(
        machine=platform.machine(), kernel=platform.release(), compiler_flags=compiler_flags,
        parent_source_sha256=sha256(parent), generated_source_sha256=sources,
        masked_script_sha256=sha256(masked_path.read_bytes()),
        replay_script_sha256=sha256(Path(__file__).read_bytes()),
        verified_observations=len(trials), trials=trials, owned_build_artifacts_removed=True,
    ), indent=2))


if __name__ == "__main__":
    main()
