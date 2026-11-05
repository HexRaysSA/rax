# Hypervisor.framework SDK contract

The [SDK DEBUGCTL observer](../../docs/development/hvf-debugctl-sdk/README.md)
records guest MSR access and TF/BTF stepping separately from RAX execution.
Run `intel_debugctl_native.py --output <new-directory>` on Intel macOS, or add
`--compile-only` for a signed cross-build. The native availability workflow
retains this sixteen-case diagnostic alongside its RAM-entry controls, comparing
VMCS fields with native and managed MSR bindings.

## Intel host stepping and deferred output completion

```sh
cargo +stable test --locked --no-default-features --features hvf,debug \
  --test hvf_native_debug --test hvf_run_loop --test hvf_sync_exits
```

Intel host single stepping uses VMX monitor-trap control, independently of guest
RFLAGS.TF. Changing host step mode preserves guest registers and modifies only
the monitor-trap bit of the current primary processor controls. Capability
checks precede changes; SDK writes require exact readback. A failed change is
recoverable only after the complete previous control word is verified restored.
The compatibility setter cannot return errors, so any unsuccessful request
latches a failure that prohibits subsequent execution and state capture.

MTF exits return a host debugger stop. They can follow event delivery or one
REP iteration and do not establish an exact retired-instruction count. Supported
non-branch instruction emulation clears RF, expires STI/MOV-SS blocking, and
retains or generates the guest's pending instruction-step trap according to TF
and IA32_DEBUGCTL.BTF. Host stops leave that guest trap pending. The native
profile checks IA32_VMX_MISC.HLT support before admitting VM-entry HLT activity;
a pending unblocked guest debug trap can wake a halted CPU on entry.

Scalar port and MMIO writes retain their output operands until
`complete_io_out` acknowledges device dispatch. Before acknowledgment, another
run returns the same output and architectural-state capture is rejected.
Acknowledgment retires the instruction and completes a pending host step. An
SDK failure after device acknowledgment fences the CPU and prevents replaying
the committed device effect. Inputs retain their existing completion-error
latches; full input-request retry and serialized native private state remain
separate requirements. Device callbacks that partially mutate before returning
an error do not acquire rollback semantics from this CPU-side protocol.

`hvf_native_debug` executes production control, retirement, output and SDK-bridge
policies with injected host failures. It does not create a native VM. SDK ABI
checks and Intel-target compilation provide separate evidence; physical Intel
VMX execution remains required. Full guest data/I/O breakpoint synthesis for
emulated accesses, other MMIO/intercept profiles, native checkpoint restoration,
and native clock/retirement accounting remain open.

Architectural sources are the retained December 2024 Intel SDM, Vol.3B
19.3.1.1/19.3.1.4, Vol.3C 27.5.2, 28.3.1.5, 28.7.1–28.7.3, 29.3.3–29.3.4,
and Vol.3D Appendix A.3/A.6. Exact installed Apple SDK VMX headers and provenance
are retained in `docs/specifications/apple/hypervisor-sdk-27.2/`.

## Intel owner and VM lifetime

Intel vCPU creation, access and destruction belong to the thread that created
the SDK handle. The public Intel vCPU now forwards synchronous operations to a
permanent worker; its private core is explicitly non-Send. Each request binds
the caller's VM clock for that operation and restores the worker's previous
binding afterward.

The VM and registered RAM remain retained until every CPU owner has joined.
Failed CPU destruction fences peer operations and new CPU creation. If final
SDK VM destruction fails, mapped backing is quarantined rather than freed.
CPU creation, ordinary requests, IRQ publication and RAM-map changes participate
in the same VM exclusion. Checkpoint record operations use the matching held
boundary without reacquiring its read lease.

```sh
cargo +stable test --locked --no-default-features --features hvf,debug \
  --test hvf_owner --test hvf_intel_owner
```

`hvf_owner` tests the production worker and VM-lifetime policies on portable
hosts. `hvf_intel_owner` runs the actual public Intel backend with SDK functions
supplied by the test executable. It requires an Intel macOS target, creates no
hardware VM, and is cfg-empty elsewhere. On Apple Silicon, the Intel executable
can run through Rosetta when available. To discard its unused SDK framework
dependency when cross-running, use a local target flag:

```sh
CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS="-C target-cpu=x86-64-v3 -C link-arg=-Wl,-dead_strip_dylibs" \
  cargo +stable test --locked --no-default-features --features hvf,debug \
  --target x86_64-apple-darwin --test hvf_intel_owner
```

These tests establish the listed Rust/SDK-boundary behavior, including moved
front ends and held checkpoint leases. They do not establish physical Intel
VMX execution, complete XSAVE/private context restoration, native scheduling,
or interrupt-device conservation. The existing architectural register projection
still omits SIMD/private state; complete native context support remains required.
The exact SDK ownership and XSAVE API contracts are retained in
`docs/specifications/apple/hypervisor-sdk-27.2/hv.h` with
`intel-owner-provenance.json`.

## Native syscall and SWAPGS MSRs

Intel CPU creation binds STAR, LSTAR, CSTAR, FMASK, KERNEL_GS_BASE and TSC_AUX
to SDK-managed native state. Each binding, initial zero write and readback must
succeed before the CPU is returned. A failed setup destroys the partial CPU on
its owner thread. This gives native SYSCALL/SYSRET, SWAPGS and RDTSCP the same
backing used by handled MSR accesses; syscall targets are no longer discarded.
CSTAR remains a readable/writable register on Intel; this does not enable
SYSCALL in compatibility mode.

The public STAR/LSTAR/CSTAR/FMASK fields read and write that SDK execution bank,
including during architectural checkpoint projection. SDK errors propagate;
failed register import or handled execution fences subsequent CPU entry and
capture. Kernel-GS and TSC_AUX still require the complete native private record
to participate in checkpoint restoration; their live SDK backing alone does not
provide that serialization. Full XSAVE/private/in-flight state remains open.

Run the complete `hvf_intel_owner` target with the Intel cross-running command
above. Its `native_msr` cases substitute SDK functions and execute the actual
backend constructor, public projection, MSR exit handlers and held checkpoint
path. They do not execute hardware SYSCALL, SYSRET, SWAPGS or RDTSCP. Physical
Intel qualification remains required. SDK ABI checks include all three added
native-MSR function signatures. Primary SDK/article sources and an independent
QEMU SDK client are retained under
`docs/specifications/apple/hypervisor-sdk-27.2/native-msr/`; the Intel SDM
December 2024 Vol.4 Table 2-2 defines the corresponding architectural MSRs.

## SDK ABI verification

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
SDK headers. The Mach timebase layout and field offsets, and both Mach clock function
signatures, are extracted from `src/backend/hvf/native_deadline.rs` and checked for both SDK
targets. The work directory retains commands, compiler versions, header and
source hashes, generated probes and diagnostics. A missing tool or compiler
failure fails the check. The Cargo target is compiled only on macOS.

The probe performs source and compiler ABI checks. Native Intel VM creation,
VM-exit behavior, guest execution and Arm64 hypervisor function signatures require separate
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

The attached per-CPU software LAPIC now owns the complete TPR byte; CR8 reads
its high nibble. Native entry refreshes the SDK mirror from that owner. Public
state import preserves the subclass when its CR8 class is unchanged, including
when only GPRs change; a changed class clears the subclass. Explicit MOV-to-CR8
always clears the subclass. Invalid CR8 values reject before any CPU-state
write. A failed SDK priority/state publication permanently prohibits entry
through that CPU because the SDK may have partially changed. Rebinding or
import cannot clear this failure. A read failure before mutation is retryable.
The existing CR8 and `u32` TPR wire fields retain their layouts.

```text
qualification -> recognized CR8 transfer -> GPR/TPR commit -> RIP advance
                           |
                           +-> reserved CR8 bits -> #GP(0), faulting RIP
```

Other control-register exit forms return an explicit host error with their raw
qualification and leave RIP unchanged. CR0.NE mask/shadow semantics and optional
CR3/CR4 intercepts still need implementation; this bounded group does not claim
to implement them.

The six original host-independent tests cover all16 GPRs, all256 TPR byte reads,
all16 valid CR8 writes, every one of60 reserved CR8 bits, unrepresented control
forms, every reserved qualification bit and host-failure boundaries. Seven
additional tests execute the production priority-publication policy with an
explicit SDK substitute, including partial-write failures and entry exclusion.
The actual QEMU long-mode guest executes335 instructions and retains all raw
records.

| Input class | RAX requirement | QEMU11.1.2 TCG result |
| --- | --- | --- |
| 272 legal transfers | Exact CR8/TPR transfer | Independent match |
| 63 reserved-bit writes | #GP(0), no TPR/RIP commit | Masks to low4 bits and writes TPR |

The probe validates the RAX local profile against Intel for every record and
compares legal transfers independently. It reports all63 raw disagreements;
reserved-bit exception behavior is primary-source validation, not a QEMU match.
The installed reference permits precisely this known masking behavior or the
correct architectural fault, and rejects other unexplained reference results.
The product consumer additionally executes actual software guest MMIO and CR8
instructions against the same controller, comparing all272 legal records:

```sh
cargo +stable build --locked --no-default-features --features x86_64-suite,smir-jit,hvf --lib
rustc +stable --edition=2024 tools/hvf/priority_compare.rs \
  --extern "rax=${CARGO_TARGET_DIR:-target}/debug/librax.rlib" \
  -L "dependency=${CARGO_TARGET_DIR:-target}/debug/deps" \
  -o "${CARGO_TARGET_DIR:-target}/priority-compare"
"${CARGO_TARGET_DIR:-target}/priority-compare" target/hvf-cr8/cases.bin target/hvf-cr8/results.bin
```

Expected output reports `compared_legal:272`, `retained_reserved_primary_cases:63`
and `mismatches:0`. The63 reserved-bit records remain assessed separately by
the original driver. Generated x86 JIT execution under Rosetta and substituted
SDK tests do not prove physical Intel VMX/exception delivery. See
[task-priority coherence](../../docs/development/task-priority-coherence.md)
for checkpoint bindings, PPR subclass behavior, evidence and the remaining
APIC_BASE/x2APIC/interrupt-source/native scheduling gates.

## Per-CPU initial APIC identity and BSP state

```sh
cargo +stable test --locked --no-default-features --features hvf --test hvf_apic_identity
```

Configured guest IDs now reach CPUID's initial-APIC field and the supported HVF
extended-topology leaf. APIC-base reads start with BSP set on CPU zero, and BSP
writes update represented state after SDK instruction completion. Failed native
completion fences entry; unrepresented mode/enable/relocation writes inject
`#GP(0)` without retirement. The seven tests cover identity masks, CPU defaults,
successful publication, all other single-bit changes and partial SDK failures.
The actual-profile CPUID case requires macOS with `hvf`; six portable policy
cases remain available elsewhere. See [CPU identity](../../docs/development/x86-cpu-identity/README.md)
for the context version boundary, software INIT/SIPI behavior, independent QEMU
observations and remaining full-profile/native gates.

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

## Scalar port-I/O completion

```sh
cargo +stable test --test hvf_port_io
python3 tools/hvf/port_io_oracle.py --llvm-bin /path/to/llvm/bin --work-dir ./target/hvf-port-io
```

The Intel scalar port handler accepts only VMX size codes0/1/3 (1/2/4 bytes).
String or REP-qualified forms return an explicit unsupported-form error before
any device exit or IP advance. Undefined qualification bits are ignored. String
INS/OUTS transfer, address translation and restart semantics remain separate.

OUT emits the exact low AL/AX/EAX bytes in little-endian order. Input captures
RAX and the validated VM-exit instruction length before returning its device
request. Completion requires exactly the requested number of bytes. IN AL/AX
preserves the upper RAX bits; IN EAX zero-extends. Success writes RAX before
advancing the complete instruction and expiring its interrupt shadow.

The existing void completion API retains a terminal error on malformed data or
host failure. Every later run reports that error before guest execution; it is
not consumed after one report. A request must be completed before another run, CPU-state write or
IRQ/NMI injection. Duplicate or unsolicited completion is an explicit error.
A failed advance after a successful RAX write can leave RAX modified; no atomic
host rollback or automatic retry is claimed.

Eight owning tests cover every port/width/direction, invalid/string forms,
all byte/word values, dword zero-extension, exact framing, instruction lengths,
host failures and repeated error observation. The independent QEMU long-mode
guest executes36 IN instructions across three widths, immediate/DX encodings
and six initial RAX patterns. It compares full RAX and before/after flags;
actual lower input bytes are retained, without assuming a device constant.
The previous input effect fails20 records and six owning tests; two controls
still pass. Native Intel VMX/device delivery and string I/O remain unverified.
Pending input and terminal-error state must be included in the planned complete
checkpoint format; the existing checkpoint schema is not extended here.

## Decoded scalar MMIO

[Native Intel memory admission and PCI routing](../../docs/development/hvf-memory-layout.md)
exclude padded backing and device pages, follow live BAR relocation/restore, and
service ordinary RAM data sharing a page with a subpage BAR. `hvf_memory` tests
the actual mapping policy and adapter with a substituted SDK. It provides no
physical Intel execution evidence.

```sh
cargo +stable test --test hvf_mmio --test hvf_guest_translation --test hvf_memory
python3 tools/hvf/mmio_oracle.py --llvm-bin /path/to/llvm/bin --work-dir ./target/hvf-mmio
```

An EPT exit becomes scalar device I/O only after validating a data read XOR
write, valid translated GLA, absence of event delivery and absence of special
shadow-stack, paging-verification or asynchronous accesses. Guest RAM permission
faults are not MMIO. Instructions are fetched incrementally, at most15 bytes,
through read-only guest translation. Only required instruction bytes are read.
Introspection preserves page-table A/D state; hardware guest permission checks
are distinct from this inspection path.

Supported translations are identity, nonPAE32-bit paging with PSE/PSE36,
legacy PAE using the architectural cached VMCS PDPTEs, and four-level IA32e
paging with4KiB/2MiB/1GiB leaves. LA57 and malformed/nonpresent mappings stop
before device access. The configured CPUID physical-address width is used.
Legacy PAE inspection never reloads a changed guest PDPT from RAM.

The transfer path requires a complete scalar MOV, MOVSX, MOVSXD or MOVZX memory operand.
[MOVSXD admission and native records](../../docs/development/hvf-mmio-movsxd.md)
cover all three operand-size forms without changing the checkpoint input format.
Additional [scalar ALU reads](../../docs/development/hvf-mmio-alu-read.md) support
ADD/ADC/SUB/SBB/AND/OR/XOR register results and CMP/TEST flag-only effects;
[modifying scalar operands](../../docs/development/hvf-mmio-rmw.md) use RMW
transactions. The effective address, including active segment
base and address-width wrapping, must match the exit GLA. Every byte must map
to the reported contiguous GPA range outside RAM. Moffs metadata now retains
all segment overrides. SDK GPR indices are shared with CR8 conversion.

Stores return the actual low register bytes or sign-extended immediate; reads
retain the exact GPR part, original value, width, extension and instruction
length. High-byte and16-bit writes preserve untouched bits;32-bit writes
zero-extend. Completion requires exact framing and commits the destination
before retirement. EPT retirement expires STI/MOVSS blocking and clears RF.
Malformed input or a host error remains terminal before later execution,
CPU-state writes and external-event injection. Partial host commits are not
rolled back. The existing void completion API is unchanged.

The immutable reference fixture contains1204 direct TCG long-mode RAM
instructions:912 loads and292 stores across all16 GPRs, high-byte aliases,
MOVSX/MOVZX, widths1/2/4/8, immediate sign extension, two data patterns and two
flag patterns. Every register, all8 observed data bytes and before/after flags
are compared with the product plan. The fixture presents the operand as an
MMIO hole to exercise planning; these records do not prove native device or
VMX delivery. Re-running the oracle must reproduce the exact fixture bytes
and pass the complete MMIO owning binary. Input is202272 bytes; output is
183028 bytes including20 framing bytes; guest RAM is64MiB.

Atomic forms outside the represented RMW table, string, vector,
segment-register, APX-only and incomplete metadata forms remain unsupported.
Guest TF now uses the common scalar MMIO retirement boundary, with pending
debug traps preceding IRQ/NMI injection; see
[guest debug qualification](../../docs/development/hvf-mmio-guest-debug/README.md).
Data/I/O breakpoint synthesis, controller/device ordering, concurrent page-table
changes and the complete checkpoint representation remain separate requirements.


## Native Apple Silicon consumers

The maintained state and scalar-input probes execute the public RAX backend
and vCPU interfaces in signed native consumers:

```sh
python3 -B tools/hvf/arm64_native_state_probe.py \
  --repo "$PWD" --work-dir /tmp/rax-native-state-evidence \
  --target-dir /tmp/rax-hvf-target
python3 -B tools/hvf/arm64_mmio_native_probe.py \
  --repo "$PWD" --work-dir /tmp/rax-native-mmio-evidence \
  --target-dir /tmp/rax-hvf-target --llvm-bin /path/to/llvm/bin
```

Use an actively owned Cargo target directory for `--target-dir`; both commands
can share it. Evidence directories retain guest inputs, raw observations and
verification manifests. The probes select Cargo's exact reported library
artifacts, record their hashes, verify executable signatures, and remove their
temporary native executables. They do not copy library archives into evidence.
`cleanup.json` records executable cleanup. Remove the idle Cargo cache after
validation; retain the evidence needed for review.

The state probe covers twelve current/banked-SP cases, rejected invalid modes
and 63 verifier mutations. Bare native register access permits an unconfigured,
unmapped VM. Complete checkpoint capture has additional topology/RAM graph
requirements. The scalar-input probe uses a fresh VM/CPU cohort for each case
to isolate guest and controller state. Individual CPU destruction preserves
surviving CPUs and permits reuse of the released logical identity. It covers 108 loads,
short replies, repeated pending exits and explicit state replacement. Neither
probe establishes native retirement budgets, architectural SMP or Intel HVF.

## VMCS capability validation

`cargo +stable test --test hvf_controls` executes the shared initialization
sequence with deterministic host-call traces. All four used capability banks
must be read successfully and satisfy the requested controls before the first
VMCS write. Required controls are preserved; unavailable controls and
contradictory required-one/allowed-one masks return explicit errors. The unused
VM-exit capability query is removed. Low32 capability bits require one; high32
bits permit one, as defined in Intel SDM Vol.3D AppendicesA.3/A.4.

The existing pin, processor, secondary and entry policy is retained, including
EPT, unrestricted guest, RDTSCP, CR8/I/O/HLT exits and EFER/IA-32e entry controls.
The policy still starts in IA-32e mode; complete guest mode transitions remain
separate. Host capability errors include the bank and SDK error. VMCS write
errors propagate with prior successful writes visible; constructor failure
destroys the newly allocated vCPU. There is no atomic rollback claim.

Seven tests cover all256 single-bit mask cells, a high requested bit,65536
seeded valid32-bit masks, all128 inconsistent bank/bit cells, every12 requested
control bits, all4 capability read failures and all10 write failure boundaries.
The controlled prior behavior fails four tests and passes three controls.
These are software contract and SDK compilation checks. Native Intel capability
queries, VM entry and hardware execution require separate validation.
