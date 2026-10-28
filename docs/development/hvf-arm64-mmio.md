# Native ARM64 MMIO read completion

A scalar MMIO read stays pending until `complete_io_in` receives at least the
trapped transfer width. Empty and truncated replies leave the public register
state unchanged. A subsequent `run` returns the same address and width without
entering the guest. The initial data-abort exit still stages PC at the next
instruction; this change prevents later execution while data is incomplete.

The represented little-endian scalar profile uses the first 1, 2, 4 or 8 reply
bytes.
Signed loads extend to the instruction's W or X destination width. A W write
clears the upper 32 bits. WZR/XZR discard the result, but the memory transaction
still requires a complete reply. Additional reply bytes are ignored.

A successful external `set_state` cancels the old pending read. A late reply
therefore cannot overwrite the replacement context. Invalid execution-mode
admission leaves the old transaction pending. This does not establish atomic
rollback if an SDK state-restoration write fails after earlier SDK writes.
If a destination-register SDK write fails during completion, the backend retains
the request and returns that error from the next `run` before guest entry.
The production completion helper is tested with an injected destination-write
error and a successful retry. Actual SDK register-write failure injection remains
unverified.

The earlier implementation accepted an empty 8-byte reply, changed X0 from
`0x1122334455667788` to zero, and executed a following guest marker. The predecessor source, library and signed-executable hashes, assembly, ELF and
public state observations document that failure independently of the corrected
tests. Native producer executables are temporary and removed after each run.

| Evidence | Domain |
| --- | --- |
| `hvf_arm64_mmio` | Seven portable regressions for transfer values and destination publication, executed on ARM64 and x86-64 under Rosetta. |
| `arm64_mmio_oracle.py` | Nine load forms, two destinations, six patterns and every short length: 516 records and 37152 bytes. |
| `arm64_mmio_native_probe.py` | Actual Apple Silicon backend execution: 108 load cases, 216 incomplete replies and repeated exits, plus invalid/successful state replacement and late reply cancellation. 761 records and 73056 bytes. |

The portable model uses integer arithmetic independently of the product's
bit-shift implementation. The native producer assembles and links all nine
scalar load forms for X0/W0 and XZR/WZR using LLVM. It executes the same complete
and incomplete reply sequences through the public backend and vCPU API. Its
final BRK enters the guest exception vector, which deliberately ends at an
unmapped instruction address. That instruction-abort stop is recorded separately
from MMIO exits and is not a retirement measurement.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| M1 | A read needs its complete transfer width; incomplete data cannot fabricate a destination. | Every short length; native repeated `run`. Any changed register or executed marker before completion falsifies it. |
| M2 | Signedness and W/X width follow the represented scalar instruction. | Zero, one, all ones, sign bit, adjacent value and mixed bytes; an incorrect sign bit or upper half falsifies it. |
| M3 | External successful state replacement cancels old I/O. | Reject invalid mode without changing state, replace context successfully, then supply an old reply. A dropped request after rejection or overwritten new X0 falsifies it. |
| M4 | A failed SDK destination write cannot complete a request. | Inject a destination-writer error and retry through the product helper; source retains the request and returns the saved error before entry. Actual SDK failure injection is unknown. |
| M5 | Evidence covers scalar transactions on the creating native thread. | Exact source hashes and exit records. Inferring worker migration, budgets or complete checkpoint state would exceed this domain. |

The completion algorithm takes O(1) time and O(1) space: at most eight bytes are
copied and one destination is written. Existing public CPU, IR, GuestRegs and C
ABI shapes remain unchanged.

Scope implications: high impact work remains for exact native retirement
budgets, SMP, worker migration and complete checkpoint state. Medium impact
validation remains for SDK write failures and partial SDK restore failures.
Unsupported data-abort forms without a valid instruction syndrome, including
pair and writeback loads, retain their existing explicit rejection. Big-endian
guest MMIO and additional native instruction profiles remain outside this
validated scalar profile. No physical
Intel, KVM, full private-state, scheduler or formal-proof result is implied.

The value rules follow the archived [Arm A64 Instruction Set Architecture Guide,
102374_0102_02_en, version 1.2](../specifications/arm/learn_the_architecture_-_a64_instruction_set_architecture_guide_102374_0102_02_en.pdf):
section 7 defines WZR/XZR write discard, section 9 defines W-register upper-half
clearing, and section 17 defines zero/sign extension. Transaction completion and
state replacement are RAX `VCpu` API behavior, tested separately from those ISA
value rules. Producer manifests retain exact source, input, library and signed
executable hashes. Both tools link directly to the existing Cargo artifacts;
they remove temporary producer executables on success and failure and never copy
Rust library archives into evidence directories.
