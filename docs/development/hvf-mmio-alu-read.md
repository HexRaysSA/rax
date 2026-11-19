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

| Assumption | Stress test and falsification probe |
| --- | --- |
| The captured device reply supplies the full source at its encoded width. | Exercise zero and nonzero replies at all three widths. A register-source value, extra device access, wrong partial write or changed control flag falsifies the contract. |
| A pending POPCNT resumes at the same instruction frontier. | Serialize the pending read, restore it, complete the reply and require one retirement. The native profile additionally requires the following guest marker and HLT. |
