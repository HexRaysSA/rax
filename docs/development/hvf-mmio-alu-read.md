# Scalar ALU reads from MMIO

[Scalar guest TF completion](hvf-mmio-guest-debug/README.md) supersedes the historical TF limit recorded below; other debug profiles remain open.

Intel HVF now accepts device-read operands for ADD, ADC, SUB, SBB, AND, OR, XOR,
CMP and TEST. Previously the planner rejected these instructions even when the
EPT exit described an ordinary read. The four baseline positive groups failed
with `unsupported MMIO instruction operands or effects`.

The planner captures the operand width, other source value, incoming flags,
destination register part and instruction length. It validates the complete
metadata and guest address before returning an ordinary `MmioRead`. The reply
then determines the arithmetic result and flags. Register-result operations
publish the captured destination; CMP/TEST publish flags without a GPR write.
Neither operation writes the device. Memory-destination arithmetic retains its
separate RMW path.

Widths are 1, 2, 4 and 8 bytes. High-byte and 16-bit destinations preserve the
other register bits; dword destinations zero extend. ADC/SBB use the captured
carry/borrow. Immediate CMP/TEST operands retain the decoder's architectural
extension. Completion publishes register/flags before instruction retirement,
which clears RF and uses the existing interrupt-shadow handling. Exact reply
width is required before any publication. The existing completion error latch
continues to prevent later execution and duplicate publication after an SDK
failure; complete recovery/private checkpoint representation remains open.

The independent corpus executes 721 unique encodings with four memory values
and two incoming flag states: 5,768 QEMU 11.1.2 TCG instructions. Each records all
16 GPRs, unchanged memory, and before/after RFLAGS. Only AF for logical/test
instructions is excluded as ISA-undefined. The product comparison uses the
actual metadata planner and InputState completion with an MMIO-hole operand,
including RF1 at the emulated EPT frontier and RF0 after retirement. No product
helper generates expected instruction results.

The owning tests also cover operand order, sign extension, delayed carry,
partial registers, qword signed-overflow boundaries, flags-only publication,
duplicate/overlapping completion, short replies and every SDK publication
failure stage. Unit cases establish 16/32-bit code-mode admission; independent
instruction-record comparison is long-mode evidence. Full legacy/native debug,
exception and device profiles retain their separate requirements.

The immutable fixture is `tests/fixtures/hvf/mmio-alu-read-v1`. Its manifest
records framing, producer/tool hashes and actual reference commands. Reproduction
uses a new output directory and automatically removes compiled guest/consumer
artifacts:

```sh
cargo +stable build --locked --no-default-features --features x86_64-suite,smir-jit,hvf --lib
python3 -B tools/hvf/mmio_alu_oracle.py \
  --out /path/to/new-evidence-directory --llvm-bin /path/to/llvm/bin \
  --product-rlib target/debug/librax.rlib
cargo +stable test --locked --no-default-features \
  --features x86_64-suite,smir-jit,hvf --test hvf_mmio
```

`--capture` requires an absent fixture and refuses to overwrite retained data.
The qualification JSON records the current 65 selected tests, fresh product
comparison, Arm-host checks, Intel macOS target compile check, Clippy and format
results. Cross-compilation and QEMU RAM instructions do not establish physical
Intel VMX exits or actual device delivery.

Primary semantics are the retained Intel SDM revision 086 instruction entries,
including CMP Vol.2A 3-179–3-180 and TEST Vol.2B 4-713–4-714. The qualification
includes source hashes, assumption probes and explicit plane/coverage limits.

Remaining high-impact work includes effective native RAM/device-hole mapping
(the current Intel mapper and RAM classifier use backing-allocation extents),
physical Intel execution, remaining atomic/string/vector/segment/APX profiles,
TF/debug and exception completion, IRQ/controller coherence, full backend/private
checkpoint state and failure recovery. The original A32-FP/C-STATE/C-SMP/C-HVF
objective remains incomplete.

## Memory-source POPCNT

Intel HVF admits translated 2-, 4- and 8-byte POPCNT reads. A pending read
captures the destination and the incoming flags. The exact-width reply
supplies the count. Completion clears CF, PF, AF, SF and OF, and sets ZF
exactly when the source is zero. A 16-bit result preserves the upper register
bits and a 32-bit result zero extends. Completion uses constant time and
space for the supported widths. [Intel SDM Volume 2B, POPCNT](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf)

The parent rejected the legal operand as unsupported. The portable regression
checks the requested width, the serialized pending operation, exact register
and flag results and one retirement. A separate 960-case reference on physical
Intel executed native memory-source POPCNT over five input values and all 64
combinations of the six status flags at each width. The Intel macOS workflow
also exposes a `popcnt` profile with direct and source-free restored reads.

The hosted Intel macOS 15.7.9 run with SDK 15.5 executed all 12 cases on
`a1c320246a8e5ad5da3039f245b43886bbbdd7ce`. All six width/value pairs
completed both directly and after restoring into a fresh native CPU. The
runner reported `hypervisor_guest=1`. The downloaded artifact matched its
published SHA-256, and all 4,783 recorded engine inputs and ten consumer and
tool inputs matched the tested Git tree. Bare-metal Intel macOS execution,
compatibility-mode device exits and broader interrupt profiles remain open.
[Native workflow run 44428586669](https://github.com/HexRaysSA/rax/actions/runs/44428586669)

| Assumption | Stress test and falsification probe |
| --- | --- |
| The captured device reply supplies the full source at its encoded width. | Exercise zero and nonzero replies at all three widths. A register-source value, extra device access, wrong partial write or changed control flag falsifies the contract. |
| A pending POPCNT resumes at the same instruction frontier. | Serialize the pending read, restore it, complete the reply and require one retirement. The native profile additionally requires the following guest marker and HLT. |

## Memory-source BSF and BSR

Intel HVF accepts translated 2-, 4- and 8-byte reads for `0F BC /r` (BSF)
and `0F BD /r` (BSR). BSF returns the lowest set-bit index and BSR returns
the highest set-bit index. The pending read accepts exactly the decoded byte
width before updating any guest state. A nonzero 16-bit source produces a
partial register write. A nonzero 32-bit source zero-extends the written
index in 64-bit mode. For a zero source, completion sets ZF and keeps the
entire captured destination by issuing no register write. For a nonzero source
it clears ZF. RAX preserves the prior value of the other flags that Intel
leaves undefined. These choices match the direct software executor, and the
result calculation takes constant time and space for the admitted widths.
[Intel SDM Volume 2A, BSF and BSR, pp. 3-125 to 3-128](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

Before the change, the portable test reached the decoded MMIO frontier and
failed with `unsupported MMIO instruction operands or effects`. The independent
Linux oracle executed 1,536 RAM-operand cases on a physical Intel Xeon
E5-1650 v3 (Haswell). It varied two instructions, three widths, four source
patterns and all 64 initial arithmetic-flag combinations. It compared the
destination for nonzero sources, ZF for every source and preserved DF. All
384 zero-source observations retained the full destination on that CPU.
The portable tests also cover 16- and 32-bit instruction modes, operand-size
overrides, short replies and pending-checkpoint admission. The `bit-scan`
native profile runs 36 long-mode MMIO cases, including restoration of the
pending read into a fresh native vCPU. Each case checks that the guest
continues through a following register marker and HLT.

Hosted Intel macOS 15.7.9 (24G830), SDK 15.5, executed all 36 cases on
`f837b851703e09ba10fb0d1e2be9f405659d253c`. All 18 instruction, width and
value combinations passed both directly and after restoration. The runner
reported `hypervisor_guest=1`. The execution artifact matched its published
SHA-256, and all 4,786 engine inputs and 11 consumer and tool inputs matched
the tested Git tree.
[Native workflow run 44437835424](https://github.com/HexRaysSA/rax/actions/runs/44437835424)

| ID | Assumption and dependent result | Falsification probe | Status |
| --- | --- | --- | --- |
| B1 | The device reply is the entire source operand. The translated EPT record and decoded width supply its identity. | Test zero, the top bit, and mixed bits at every width. Reject mismatched direction, short replies, and register-only forms. | Confirmed in the portable MMIO tests. |
| B2 | Leaving the undefined zero-source destination unchanged is the selected RAX behavior. | Complete a zero reply with a nonzero upper half and require no destination write. Compare the defined flags against the physical CPU without including its undefined outputs in the comparison mask. | Confirmed for RAX. The Linux observations are host-specific. |
| B3 | Pending records retain the scan direction and instruction length. | Serialize both operations, restore, and require the expected result, flag transition and exactly one retirement. | Confirmed in the portable tests. |

## F3-prefixed BSF and BSR aliases

For `F3 0F BC /r` and `F3 0F BD /r`, the Intel vCPU owner measures how
its processor executes each encoding. The register-only probe uses a
nonzero value with both extreme bits set. The count instructions produce
zero and set ZF for that value. The legacy scans clear ZF. The two bits
are recorded independently and select the MMIO completion operation.
This probe is separate from the CPUID feature words exposed to the guest.
Intel documents processors that execute TZCNT while its CPUID bit is clear.
[Intel 8th and 9th Generation Core Specification Update, CFL010](https://cdrdv2-public.intel.com/337346/337346_008.pdf)

On a processor executing the count form, TZCNT and LZCNT work over the
decoded 16-, 32- or 64-bit operand and return that width for a zero source.
They set CF for a zero source and ZF for a zero result. RAX retains the
incoming values of the undefined flags. A legacy scan uses the BSF or BSR
contract above. The pending descriptor records the resolved operation before
the device reply and restores that operation without probing again. New
descriptor variants follow the existing variants in the serialized enum.
Planning and completing the count use constant time and space beyond
the existing decode and address validation.
[Intel SDM Vol. 2A pp. 3-634–635 and Vol. 2B pp. 4-723–724](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The baseline decoded the instruction, then rejected the read as unsupported.
A physical Intel Xeon E5-1650 v3 passed 1,920 RAM cases spanning the two
instructions, three widths, five source values and every initial combination
of the six arithmetic flags. KVM guests on the same processor executed both
count instructions with their guest CPUID feature bits either set or clear.
QEMU 11.1.2's `core2duo` and `max` profiles independently distinguished the
two legacy scan results from the count results. The native `bit-count` profile
compares each translated device read with the same instruction and input in
RAM. It checks 48 device completions, including 24 after restoration into a
fresh native vCPU.

Hosted Intel macOS 15.7.9 (24G830), SDK 15.5, executed both count forms and
passed all 48 device cases on `ce9e6ed8038934224917f1ee99b40f9dbe120723`.
The runner reported `hypervisor_guest=1`. The execution artifact matched its
published SHA-256, and all 4,786 engine inputs and 11 consumer and tool inputs
matched the tested Git tree. The legacy fallbacks were exercised in the
portable tests and the QEMU profile control.
[Native workflow run 44441741303](https://github.com/HexRaysSA/rax/actions/runs/44441741303)

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| C1 | The native owner and its HVF guest execute the same F3 encoding. | Compare each MMIO result and defined flags to the same instruction operating on guest RAM, including the source that distinguishes ZF. |
| C2 | Both count features can be selected independently. | Test all four combinations in the portable planner. A zero source distinguishes a count equal to the width from a scan with no destination write. |
| C3 | The saved descriptor contains the operation selected at the device-read frontier. | Serialize and restore the read before applying the reply, then verify exact width, destination, flags and single retirement. |

High impact. Native compatibility-mode exits, bare-metal Intel macOS, wider
interrupt coherence and the broader guest CPUID policy remain open.

## Scalar SCAS

Intel HVF accepts one translated 1-, 2-, 4- or 8-byte read for scalar SCAS.
Completion compares the selected accumulator width with the reply and
updates CF, PF, AF, ZF, SF and OF. DF selects whether the index advances or
retreats by the operand size. The guest address size controls index wrapping
and the 32-bit index write zero-extends in 64-bit mode. RAX and RCX retain
their values. A pending read records the accumulator, index, flags and
instruction length. Restore checks the captured CPU boundary before allowing
the reply. The completion uses constant time and auxiliary storage.
[Intel SDM Volume 2, SCAS](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The two owning regressions failed on the parent because the MMIO planner
rejected the scalar instruction. All 118 portable MMIO tests and 16 workflow
checks passed at `746a89486`. An x86-64 userspace reference under Rosetta
confirmed the defined flags and index movement for ten RAM-operand cases.
Those cases covered all operand widths, both directions, and the
address-size override.

Hosted Intel macOS 15.7.9 (24G830), SDK 15.5, passed all 22 string-MMIO
cases at `746a89486e864d0d3ca3fe76de990fbb2f6ec734`. Five scalar SCAS
cases ran directly and the same five ran after restoration into a fresh
vCPU. Each case verified its device reply and the following guest marker.
The runner reported an untranslated GenuineIntel process and
`hypervisor_guest=1`. The execution archive matched its published SHA-256.
All 4,884 engine inputs and 17 consumer and runner inputs matched the
tested Git tree. [Hosted Intel run](https://github.com/HexRaysSA/rax/actions/runs/44777966388/job/136432769442)

| Assumption | Falsification probe |
| --- | --- |
| The device reply is the complete right-hand operand. | Compare all four operand widths to RAM-operand observations. An index or arithmetic flag mismatch falsifies the operand or width selection. |
| The restored read still refers to the saved scalar instruction boundary. | Restore into a fresh CPU and check the index, count, accumulator and flags before completion. Require one device access, one retirement and the following guest marker. |

Repeated SCAS remains outside this profile. That path must preserve the
original comparison flags across the whole repeat instruction so a later
fault can restart with the specified flags. Bare-metal Intel macOS and
compatibility-mode device exits remain open.
