# KVM I/O continuation ownership

Production KVM entry now retains port element width/count and an owned transfer.
A REP input batch becomes `IoInString`; a scalar input remains `IoIn`. Replies
must contain exactly the requested bytes. Short, long, duplicate or unexpected
compatibility replies latch an error without permitting another native entry.

Port output retains its full payload and emits one width-preserving element at
the same port until acknowledged. MMIO output retains the exact address/payload
until acknowledged. Accepting a reply or all output acknowledgments does not
complete the kernel's emulation: the transfer remains pending until the following
KVM_RUN. A rejected entry preserves it. The native API's completion EINTR clears
the completed frame without inventing a new guest exit or retired instruction.
MMIO read-modify-write can return a followon write which remains owned.

```text
native input exit -> owned request -> exact device reply -> KVM_RUN -> completion
native output exit -> owned payload -> device ACKs       -> KVM_RUN -> completion
```

Public register overlays reject every pending native completion, including a
ready reply or fully acknowledged output. The mapped input pointer remains with
the CPU; only the owned reply is copied into it immediately before native entry.
Native MP state is read before public register banks and restored last after
register writes, including rollback. An independent managed-CPU probe reproduced
UNINITIALIZED becoming RUNNABLE on the prior production library; the corrected
complete library preserves RUNNABLE, UNINITIALIZED, INIT_RECEIVED and HALTED
while applying CR8 and retaining GPRs. `mp-production.json` records the complete
compile/probe and repeated ten-case native IO/VMM run. These are four values in
one probe; SMM and blocked INIT/SIPI ordering remain separate requirements.

The actual VMM input path uses one scalar port transaction per REP element.
Generic and UART byte lanes advance within each element; every next element
starts at the original port. IDE data-register bytes all use the fixed FIFO
port. Invalid width/count and allocation failure occur before device read
side effects. Work/storage are O(count * width); metadata checks are O(1).

## Actual production evidence

The complete ten-case native `kvm_host_slices` target includes all six new
regressions plus the four earlier finite-entry/ownership controls. Against the
unchanged complete production library it runs4 passing controls and6 failing
regressions, without skips or a test-name filter. The wired complete production
library then passes all10 cases. `baseline-native.json`, `production-native.json`
and `production-identity.json` retain the actual commands and result/source
identities. Earlier replacement-type seams remain historical supporting evidence;
these production results use the real KvmVcpu trait wiring and Vmm loop.

The actual VMM guest writes UART.SCR=0x5a, runs256 REP INSD elements, checks the
fourth byte of every dword, publishes a RAM result and requests ACPI shutdown.
Its baseline result is0xbad0bad0 and its corrected result is0x5a5a5a5a; the host
also verifies all256 bytes. `uart-rep.S` and `uart-encoding.json` retain source,
GNU assembler identity, exact bytes/digest and disassembly. The assembler is an
encoding tool; the managed native guest executions establish behavior.

Native CPU cases cover widths1/2/4, both DF directions, nonuniform input/output,
exact reply lengths, pending overlay rejection, repeated output before ACK,
MMIO INC's read-to-write transition and duplicate ACK rejection. The whole
owning target is selected by the existing native KVM CI command.

## Assumptions and boundaries

`qualification.json` records the assumptions and stress/falsification probes.
KVM API section5 distinguishes device completion from subsequent kernel
completion. The retained native completion probes also cover entry EINTR and
followon MMIO exits. The MP API/kernel references explain why public register
writes require preservation of native halted/startup state.

`io_completion_result()` establishes the device phase only. This group does not
implement the complete backend checkpoint producer or native AP startup. It
does not establish physical Intel HVF behavior. Those remain high-impact full
goal requirements; no guard or retained frame is counted as their completion.
The final combined IO/SMP Cargo/unit/feature/lint/doc gates passed below.

Direct embedding clients must acknowledge output after successful dispatch and
check input completion status before further execution. Those operations are the
existing VCpu trait contract; the actual Vmm loop performs them.

## Public observation and pending INIT

The MP overlay backup originally made public `get_state()` query native MP state
as well. That query accepts pending INIT: the actual two-CPU probe observed an
uncompleted input's RIP change from0x1000 to0xfff0 during a public read. Public
observation now reads register banks without MP processing. Overlays still take
MP backup before reading banks and restore it last; a projection without that
backup rejects before any native setter.

The exact paired corrected probe keeps RIP0x1000, then completes input before
entering native INIT wait. All four MP values and the whole ten-case native IO
target pass again. The earlier eleven Cargo gates passed before this correction
and are retained as historical receipts. Final combined IO/SMP Cargo checks
passed with the public-observation correction, as recorded below.

Final combined IO/SMP qualification passed all14 gates. The actual expanded native
public-state selection passes16 cases; IO8, port3, XSAVE15, coordinator20, native
SMP3, nativeIO10, minimal2 and workflow12 also pass. Two compile-fail doctests
pass and five pre-existing examples remain ignored. These component results do
not replace the separate unfiltered-library result or close the full findings.
