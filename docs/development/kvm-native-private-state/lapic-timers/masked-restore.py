#!/usr/bin/env python3
"""Reproduce the APIC initialization counterexample to masked restoration."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile


PARENT_SHA256 = "bb80c4efd746e7d85861828e3cd4706227556c69dfba4d5199e374be6c68fcf3"


def replace_once(source, original, replacement):
    assert source.count(original) == 1, original
    return source.replace(original, replacement)


def candidate(parent, initialized):
    source = replace_once(
        parent,
        "(get_register(saved, 0x320) & ~0x700u) | 0x400u",
        "get_register(saved, 0x320) | (1u << 16)",
    )
    source = replace_once(
        source,
        "// Experimental x2APIC-only expired one-shot normalization control.\n"
        "// The temporary raw NMI delivery mode is not a production restore contract.",
        "// Independent x2APIC masked expired one-shot restoration control.\n"
        "// Test whether an architecturally valid mask drains the native timer latch.",
    )
    source = replace_once(
        source,
        "// Preserve the timer mode and its initial-count register. Only the raw\n"
        "    // SET_LAPIC delivery mode is changed for this experiment.",
        "// Preserve mode, vector and initial count. Mask the restored LVT\n"
        "    // while the halted, entry-only signal control attempts to drain it.",
    )
    source = source.replace("temporary NMI timer", "temporary masked timer")
    source = source.replace("materialized NMI events", "events after masked entry")
    if not initialized:
        return source
    source = replace_once(
        source,
        "special.apic_base |= 1u << 10; // Keep x2APIC enabled on source and target.",
        "special.apic_base |= 1u << 10; // Keep x2APIC enabled on source and target.\n"
        "    // A nondefault APIC base inhibits APICv in the retained Linux source.\n"
        "    special.apic_base = (special.apic_base & ~0xfffff000ull) | 0xfee01000ull;",
    )
    return replace_once(
        source,
        'checked(ioctl(graph.cpu, KVM_SET_REGS, &regs), "set regs");\n'
        "    return graph;",
        '''checked(ioctl(graph.cpu, KVM_SET_REGS, &regs), "set regs");
    // Run an owned initialization output before any captured state is loaded.
    // This processes APICV_UPDATE through a real native guest entry.
    graph.memory[0x1000] = 0xe6;
    graph.memory[0x1001] = 0xe8;
    checked(ioctl(graph.cpu, KVM_RUN, 0), "prime native entry");
    if (graph.run->exit_reason != KVM_EXIT_IO || graph.run->io.port != 0xe8) {
        fprintf(stderr, "native priming exit %u\\n", graph.run->exit_reason);
        exit(1);
    }
    graph.run->immediate_exit = 1;
    errno = 0;
    int completed = ioctl(graph.cpu, KVM_RUN, 0);
    int completion_error = errno;
    graph.run->immediate_exit = 0;
    if (completed != -1 || completion_error != EINTR) {
        fprintf(stderr, "native priming completion %d/%d\\n", completed, completion_error);
        exit(1);
    }
    memcpy(graph.memory + 0x1000, main_code, sizeof(main_code));
    checked(ioctl(graph.cpu, KVM_SET_REGS, &regs), "restore primed GPRs");
    return graph;''',
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=3)
    arguments = parser.parse_args()
    assert 1 <= arguments.repetitions <= 100
    root = Path(__file__).resolve().parent
    parent_bytes = (root / "lapic-expired-normalize-v2.c").read_bytes()
    assert hashlib.sha256(parent_bytes).hexdigest() == PARENT_SHA256
    records = []
    sources = {}
    builds = []
    with tempfile.TemporaryDirectory(prefix="rax-masked-lapic-") as temporary:
        for initialized in [False, True]:
            profile = "initialized-relocated" if initialized else "fresh-default"
            source = Path(temporary) / (profile + ".c")
            source.write_text(candidate(parent_bytes.decode(), initialized))
            sources[profile] = hashlib.sha256(source.read_bytes()).hexdigest()
            binary = source.with_suffix("")
            command = [
                "gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2",
                "-pthread", str(source), "-o", str(binary),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            builds.append(command)
            for case in ["settled", "pending"]:
                for mode in ["raw", "normalize"]:
                    for trial in range(arguments.repetitions):
                        result = subprocess.run(
                            [str(binary), case, mode], capture_output=True,
                            text=True, timeout=5,
                        )
                        assert result.returncode == 0, (result.stdout, result.stderr)
                        value = json.loads(result.stdout)
                        assert value["pending_case"] == (case == "pending")
                        assert value["normalized"] == (mode == "normalize")
                        expected = int(case == "pending" or mode == "raw" or initialized)
                        assert value["target_delivery"] == expected, value
                        assert value["source_delivery"] == int(case == "pending")
                        assert value["source_extra"] == value["target_extra"] == 0
                        assert value["saved_current_count"] == 0
                        assert value["saved_initial_count"] == 1_000_000
                        assert value["restored_initial_count"] == 1_000_000
                        assert value["fake_nmi_pending"] == 0
                        for key in [
                            "registers_equal", "special_equal", "events_equal",
                            "mp_equal", "memory_equal", "source_destroyed_before_restore",
                        ]:
                            assert value[key] is True, (key, value)
                        if mode == "normalize":
                            assert value["lapic_equal"] is True, value
                        records.append(dict(
                            profile=profile, case=case, mode=mode,
                            trial=trial, observation=value,
                        ))
    assert not Path(temporary).exists()
    print(json.dumps(dict(
        status="masked_candidate_falsified",
        kernel=platform.release(), machine=platform.machine(),
        parent_source_sha256=PARENT_SHA256,
        generated_source_sha256=sources,
        replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        build_argv=builds, verified_observations=len(records), trials=records,
        owned_build_artifacts_removed=True,
        production_changed=False, full_goal_complete=False,
    ), indent=2))


if __name__ == "__main__":
    main()
