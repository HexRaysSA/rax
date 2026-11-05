# First native Intel guest frontier

[Run 41978606771](https://github.com/HexRaysSA/rax/actions/runs/41978606771)
built and signed the actual 130-case audit consumer on Intel macOS, retained
its build artifact, and passed source/signature/availability admission in the
separate execution job. The guest executable exited 101 in its first RAM-only
control, with `guest did not reach HLT`. No passed-case record was written.

The original assertion discarded the actual returned exit. Whether that
attempt executed a guest instruction is unknown; a failed-entry exit would
also satisfy the observed failure. The diagnostic now includes that exit and
the public CPU-state projection. The 100-entry scheduling timeout also records
the state projection. Successful-case behavior and case counts are unchanged.

The enhanced diagnostic in
[run 41983036300](https://github.com/HexRaysSA/rax/actions/runs/41983036300)
reports `FailEntry { reason: 2147483681 }` (`0x80000021`), before the first
passed-case record. Bit 31 identifies failed VM entry; basic reason 33 is
invalid guest state. RIP remains `0x10000` and R10 remains zero. The public
post-failure projection has CR4 `0x2260` and EFER `0x100`, compared with input
CR4 `0x220` and EFER `0x500`. The [raw diagnostic](native-entry-failure-41983036300.txt)
and [qualification](ram-entry-qualification.json) retain the exact frozen
executable/source identity. The later [read-shadow correction](control-shadow-import.md)
allows the actual RAX consumer to pass its RAM and MMIO controls.

The [SDK-only RAM-entry matrix](ram-entry-controls.md) compares control-register
write interfaces, read shadows and SDK-required bits independently of the RAX
library. Completing that observation is separate from passing native RAX cases.

The independent [KVM control](../hvf-intel-sdk/ram-control-kvm.c) reproduces the
consumer's RAM bytes, page tables, segment/descriptor layout, control registers,
debug registers and general registers through Linux KVM without linking RAX.
It reaches HLT with RIP `0x1000b`, R10 `0xa1b2c3d4e5f60718`, unchanged RAX/RDI
and RFLAGS 2. Host-supported CPUID and the KVM APIC base are installed through
KVM UAPI; these interfaces differ from HVF. This result establishes a working
x86-64 guest-setup control, and does not identify the HVF failure's cause.

Build and run on Linux x86-64 with `/dev/kvm`, using a temporary owned directory:

```sh
cc -std=c11 -O1 -Wall -Wextra -Werror \
  docs/development/hvf-intel-sdk/ram-control-kvm.c -o /tmp/rax-ram-control
/tmp/rax-ram-control
rm /tmp/rax-ram-control
```

The probe owns one VM, one CPU and 2097152 bytes of RAM, with a 5 s execution
watchdog. Runtime and storage are constant with respect to guest inputs.
Its actual qualification compiler/executable directory was removed.

[Qualification](qualification.json) retains the failed native command and
independent Linux result, plus the changed consumer's compile/link/signature
check on Apple Silicon. The published diagnostic change applies to the existing
114-case production consumer; the pending 130-case candidate keeps its additional
PAT and reserved-MSR cases. Neither a cross-build nor the KVM control qualifies
native HVF guest execution.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | The initial RAM guest is executable with the specified architectural setup | Distinguishing guest setup from HVF transfer | Execute its bytes and state through independent KVM; require HLT, exact RIP and marker, preserved input registers | Confirmed on the recorded Linux host |
| A2 | The old native failure identifies a particular exit | Native failure diagnosis | Inspect the captured error; absence of an exit means the cause cannot be assigned | Falsified for the old run; enhanced run 41983036300 observes failed entry, basic reason 33 |

The later [run 41992554080](control-mask-policy.md) passes 118 ordered native
RAX cases before private checkpoint capture rejects SDK-normalized masks.
Its retained result supersedes the first-control failure as the current native
frontier. High impact: native private continuation, the remaining cases and the
full audit findings remain unqualified.
