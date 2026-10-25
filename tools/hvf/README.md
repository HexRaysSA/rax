# Hypervisor.framework SDK contract

Run the compiler-backed check on macOS with Xcode command-line tools, Python 3,
and stable Rust available:

```sh
python3 tools/hvf/check_sdk_abi.py --work-dir ./target/hvf-sdk-abi
cargo +stable test --test hvf_sdk_abi -- --nocapture
```

The probe extracts the register enum, relevant type aliases, constants and every
Intel foreign function declaration from the actual bindings source. A standalone
Rust program reports values, widths and alignments; Clang checks those results
and function pointer types against the installed Intel SDK headers. A second
Clang invocation checks the shared error and mapping constants against the Arm64
SDK headers. The work directory retains commands, compiler versions, header and
source hashes, generated probes and diagnostics. A missing tool or compiler
failure fails the check. The Cargo target is compiled only on macOS.

The probe performs source and compiler ABI checks. Native Intel VM creation,
VM-exit behavior, guest execution and Arm64 function signatures require separate
validation. The probe also checks every declared VMCS field with explicit SDK
name aliases, plus the actual shared exit-information field used at runtime. Rosetta can run the x86_64 test process
on Apple Silicon; it does not establish native Intel hypervisor execution.

The SDK defines Intel vCPU identifiers as 32-bit unsigned integers. Register IDs
include separate IDT, GDT, LDT and TSS fields before CR0, so architectural register
numbers cannot substitute for SDK identifiers. VMX capabilities use
`hv_vmx_read_capability`. The Intel and Arm64 APIs have different function
signatures and are compiled under their respective architecture gates.

## XSETBV and XSAVE enumeration

```sh
cargo +stable test --test hvf_xsetbv
python3 tools/hvf/xsetbv_oracle.py --llvm-bin /path/to/llvm/bin --work-dir ./target/hvf-xsetbv
```

The Intel exit adapter reads the live CR0/CR4, privilege state, EAX/ECX/EDX and
configured XSAVE capabilities. It validates before writing XCR0. Success writes
XCR0 through the SDK register API before advancing RIP. Failure queues a hardware
exception at the faulting instruction; #GP carries error code0, #UD has no error
code. A queued synchronous exception takes priority over a pending IRQ. Host API
errors propagate without manufacturing successful retirement.

| Condition | Result |
| --- | --- |
| XSAVE absent or CR4.OSXSAVE0 | #UD |
| Protected-mode CPL1-3 or virtual8086 | #GP(0) |
| Nonzero ECX, x870, unsupported bit, invalid component dependency | #GP(0) |
| Valid configured XCR0 value1,3,7 | XCR0 write, then RIP advance |

Upper32 bits of RAX/RCX/RDX do not participate in XSETBV. The configured x87/SSE/
AVX profile advertises XCR0 mask7, a576-byte base area, and a256-byte YMM_Hi128
component at offset576. CPUID.1.OSXSAVE follows live CR4.OSXSAVE; CPUID.D.0.EBX is
576 or832 bytes according to enabled AVX state. These layout rules do not claim
support for additional CPUID-configured state components. Dependency checks for
MPX, AVX-512 and AMX do not advertise those extensions.

The independent probe boots a Haswell-noTSX QEMU TCG guest, verifies XCR0 mask7
and the AVX component layout, installs actual #UD/#GP handlers and executes114
instructions. OSXSAVE0/1, three ECX selectors and19 candidate values produce
three successful writes,57 #UD and54 #GP cases. It compares fault vector/error,
XCR0, instruction-boundary behavior, commit order and dynamic CPUID fields with
the actual product decision/commit module. All records and completion markers
must be present. The host-independent Cargo target additionally checks CPL,
virtual8086, ignored high halves, each reserved bit and host API failures.

TCG instruction execution supplies an independent architectural reference for
this listed CPL0 profile. Mock host calls and compiler/link checks do not prove
native Intel VMX calls, VM-entry delivery or every pending-event interleaving.
The original CR-access and MMIO exit defects remain separate. Internal exits use the shared iterative driver described below; actual native
VMX transitions and the individual handler effects retain their separate limits.

## Iterative VM-exit dispatch

```sh
cargo +stable test --test hvf_run_loop
```

The Intel backend drives internal exits in one loop. It checks halt state
before every entry, executes the selected handler once and either resumes or
returns its public exit/error. CPUID, completed RDMSR/WRMSR, external-interrupt,
interrupt-window, CR-access and XSETBV exits no longer recurse through `VCpu::run`.
Work is O(n) for n internal exits; driver stack and auxiliary space are O(1).

Bit31 of the VM-exit reason identifies VM-entry failure. It takes priority over
the low16-bit basic reason and returns `VcpuExit::FailEntry` with the raw32-bit
reason. It cannot become an ordinary exception, shutdown or MMIO dispatch.

Eight host-independent tests execute the actual driver. They cover all65536
basic codes under four non-failure flag partitions,65536 entry-failure codes,
every handled reason, MSR public/resume outcomes, preparation exits and all host
error phases. One million internal exits complete on a65536-byte thread stack.
The controlled recursive/low16-only reproducer overflows that small stack and
fails two entry-failure/error tests. The driver delegates port, MMIO, MSR, control and interrupt effects to their
individual handlers. Shared dispatch tests do not certify native Intel delivery.
Remaining CR-access and MMIO semantics retain their explicit limits below.

## CR8 transfers and state access

```sh
cargo +stable test --test hvf_cr8
python3 tools/hvf/cr8_oracle.py --llvm-bin /path/to/llvm/bin --work-dir ./target/hvf-cr8
```

The configured CR8 load/store VM exits now transfer the selected architectural
GPR and SDK TPR state. The GPR qualification index follows Intel table29-3 and
uses an explicit mapping to SDK register identifiers. A valid CR8 value0-15
writes TPR=value<<4, clearing its low subclass nibble, before advancing RIP.
MOV from CR8 writes a zero-extended64-bit TPR[7:4] into the selected GPR.
Reserved CR8 bits require #GP(0) with unchanged TPR/GPR and faulting RIP.

System-state reads expose the live SDK TPR priority class as CR8. System-state
writes restore it; invalid CR8 values fail before any supplied CPU state is
written. This uses the already serialized CR8 field and adds no checkpoint
layout field. Host API failures propagate; an error after a successful TPR write
can leave that write visible without a successful RIP advance.

```text
qualification -> recognized CR8 transfer -> GPR/TPR commit -> RIP advance
                           |
                           +-> reserved CR8 bits -> #GP(0), faulting RIP
```

Other control-register exit forms return an explicit host error with their raw
qualification and leave RIP unchanged. CR0.NE mask/shadow semantics and optional
CR3/CR4 intercepts still need implementation; this bounded group does not claim
to implement them.

The six complete host-independent tests cover all16 GPRs, all256 TPR byte reads,
all16 valid CR8 writes, every one of60 reserved CR8 bits, unrepresented control
forms, every reserved qualification bit and host-failure boundaries. The actual
QEMU long-mode guest executes335 instructions and retains all raw records.

| Input class | RAX requirement | QEMU11.1.2 TCG result |
| --- | --- | --- |
| 272 legal transfers | Exact CR8/TPR transfer | Independent match |
| 63 reserved-bit writes | #GP(0), no TPR/RIP commit | Masks to low4 bits and writes TPR |

The probe validates the RAX local profile against Intel for every record and
compares legal transfers independently. It reports all63 raw disagreements;
reserved-bit exception behavior is primary-source validation, not a QEMU match.
The installed reference permits precisely this known masking behavior or the
correct architectural fault, and rejects other unexplained reference results.
Native Intel VMX/exception delivery and SDK-TPR/software-LAPIC/IRQ coherence remain
separate. The VMM LocalApic and software x86 InlineLapic ownership also require
reconciliation with the pending platform/checkpoint/SMP work.

## Synchronous exit IP, halt and event information

```sh
cargo +stable test --test hvf_sync_exits
python3 tools/hvf/sync_exit_oracle.py --llvm-bin /path/to/llvm/bin --work-dir ./target/hvf-sync-exits
```

HLT advances past the complete instruction before setting the software halted
flag. A failed advance leaves that flag unset. `wake()` clears the flag without
advancing again. CPUID, RDMSR and WRMSR use the actual VM-exit instruction length,
including accepted prefixes, rather than assuming two bytes.

Straight-line EIP advancement uses32-bit storage outside64-bit mode; RIP uses
64-bit storage in64-bit mode. CS.D controls decoding defaults and does not make
fallthrough EIP16-bit. The arithmetic is `(current+length) mod2^32` or `mod2^64`,
with length measured in bytes and required to be1-15. Subsequent code-segment,
canonical-address and fetch faults are separate from this arithmetic.

| Information | Encoding | Meaning |
| --- | --- | --- |
| VM-exit interruption information | 0x4404 | Event causing this exit |
| IDT-vectoring information | 0x4408 | Interrupted delivery of another event |

Exception/NMI exits read0x4404 through the same shared field selector exercised
by the boundary tests and checked against Apple SDK headers. They preserve the
existing vector-only public exit shape. An invalid record reports a host error;
it does not fabricate vector0 or substitute IDT-vectoring information. Full
exception frames, error-code propagation and reinjection remain separate.

The SDK probe now validates85 declared VMCS field values,29 explicit SDK-name
aliases and the actual shared runtime field selector. A wrong-selector mutation
fails both boundary tests and SDK assertions. The nine complete owning tests
cover full32/64-bit IP arithmetic, malformed lengths, all65536 exit/IDT vector
pairs, invalid/error records and a halt/wake/halt sequence.

The independent guest uses actual debug traps after CPUID in16-bit and32-bit
protected code segments with4GiB limits. Twelve cases combine instruction lengths
2,3,15 with ordinary offsets and64KiB boundary crossings. Every case must record
both debug traps and its exact next EIP/CS. Full32-bit EIP is compared; only the
16 defined CS selector bits are compared and raw stack padding is retained.
The initial16-bit truncation hypothesis fails three cases; the legacy fixed
length2 CPUID effect fails eight. The final helper matches all twelve.

These are IP/halt/event-source checks, not complete native retirement proof.
RF handling after EPT emulation, single-step traps and
full event delivery, APIC/device coherence, remaining CR forms and MMIO need
separate work. VM-entry arbitration is checked separately below. Native Intel VMX execution remains unverified on Apple Silicon.

## VM-entry event arbitration

`cargo +stable test --test hvf_event_injection` exercises the same boundary used
by the Intel adapter. An occupied VM-entry event slot blocks both IRQ and NMI
requests. IRQs require IF=1 and no STI/MOV-SS blocking; NMI blocking alone does
not block IRQs. NMIs ignore IF and require no STI/MOV-SS/NMI blocking.

A blocked request returns `Ok(false)` and remains owned by the caller, as required
by `VCpu`. It is not privately queued for later duplicate delivery. A successful
VMCS write returns `Ok(true)` and clears software halt. Read/write failures are
propagated and leave halt unchanged. The availability query returns false on a
host read error. Existing synchronous events retain their slot.

This covers arbitration at the adapter boundary. Interrupt-controller retention,
VM-entry failure recovery, event-delivery faults and pending debug state,
concurrent callers and native Intel delivery require separate validation.

## Emulated instruction interrupt shadows

`cargo +stable test --test hvf_interrupt_shadow` checks completion of saved
STI/MOV-SS blocking after a successful emulated instruction. The VM exit saves
the pre-instruction state. Advancing IP now also clears bits0-1, preserving every
other interruptibility bit. This allows an IRQ after an emulated `STI; HLT`
sequence. The shadow is read before IP is written; failed reads or IP writes do
not change it. A failed shadow write propagates the host error after the IP write;
this is not an atomic rollback protocol.

Fault injection paths do not advance IP and do not use this completion boundary.
RF, pending debug exceptions/TF, full event delivery and controller ownership
remain separate. This change covers shadow expiration only. Native Intel VMX
execution remains unverified on Apple Silicon.

The independent shadow oracle runs six actual CPL0 `STI; CPUID` and `STI; HLT`
sequences, using instruction lengths2/3/15 and1/2/15 respectively. It polls PIC
IRR to prove IRQ0 is pending before STI. Every case records exactly one hardware
IRQ and its full next EIP. The same product completion and event-eligibility
boundaries must permit the IRQ after completion. The previous IP-only effect
fails all six comparisons; the corrected boundary matches all six. These are
TCG direct-instruction records, not native VMX exit delivery.

```sh
python3 tools/hvf/interrupt_shadow_oracle.py --llvm-bin /path/to/llvm/bin --work-dir ./target/hvf-shadow
```
