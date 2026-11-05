# Read-only bit tests from MMIO

[Scalar guest TF completion](../hvf-mmio-guest-debug/README.md) supersedes the historical TF-rejection controls and limitation below.

Intel HVF now plans both scalar BT memory encodings: register bit strings
(`0F A3 /r`) and immediate bit selection (`0F BA /4 ib`). Operand widths are
16, 32 and 64 bits. The baseline planner rejected all four new positive test
groups with `unsupported MMIO instruction operands or effects`.

The register index is signed at operand width. Its floor division by the word
size selects the addressed word; its low bits select the bit within that word.
An immediate selects only a bit in the addressed word. Address-size wrapping
applies after the word displacement. Planning validates the resulting guest
linear/physical address, the read-only EPT direction and the complete operand
extent before any device effect. LOCK, TF, truncated instructions, RAM operands
and inconsistent exit addresses reject before device access.

The existing retained ALU-read completion performs one ordinary device read,
publishes CF and retires the instruction without a GPR or device write. ZF and
unrelated flags remain unchanged. The implementation preserves OF/SF/AF/PF,
which the architecture leaves undefined for BT. JSON and binary pending records
retain the selected bit, original flags and instruction length; malformed
descriptors reject before register publication. Existing ALU operation indices
remain unchanged because the new operation is appended.

Intel SDM revision 086, Vol. 2A, BT entry, pages 3-130--3-131, defines these
encodings, bit-string addressing, flags and LOCK rejection. The primary source
is retained at
[`325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf).
That entry advises using MOV around memory-mapped devices because BT can access
the full operand word. This implementation consequently validates and requests
the complete word, including its boundaries.

## Evidence

The independent Linux KVM runner executes physical Intel instructions without
linking RAX. The boundary corpus contains 2,808 cases; a larger external control
contains 8,640 cases, including every immediate byte. It records all 16 GPRs,
24 unchanged memory bytes and before/after flags. The central word and its
neighbors use different patterns so an adjacent-word addressing error is not
hidden by repeated data. Only ISA-undefined flags are excluded from comparison.
All 8,640 comparisons against production planning/completion match.

The complete source-module harness passes 55 tests, with no failed, ignored or
filtered tests. Its seven initial new tests were extended by one address-alias
and wrapping test. The earlier baseline ran 52 tests: 48 passed and four failed.
These module controls include the actual production source and engine metadata;
they do not replace the complete owning Cargo target or root-library gate.
The later actual complete `hvf_mmio` Cargo target passes all 55 tests, with no
failures, ignored or filtered cases. The frozen Apple Silicon library passes
12,440 tests, with 36 ignored, none failed and no filter, on source digest
`81682891f1a3775815a2f860f64e4b7026ac5d51ad7df9341fa1a0327e2b8a87`.
The subsequent INIT changes are confined to the Intel-only adapter; these
results do not qualify BT device cycles through native macOS HVF.

The checked-in reference data occupy 954,740 bytes, excluding their manifest.
The manifest records the host, tool/source hashes, framing and actual commands.
Reproduction requires Linux x86-64 with `/dev/kvm`, GCC and LLVM tools:

```sh
python3 -B tools/hvf/mmio_bt_oracle.py \
  --out /path/to/new-evidence-directory --llvm-bin /path/to/llvm/bin
cargo +stable test --locked --no-default-features \
  --features x86_64-suite,smir-jit,hvf --test hvf_mmio
```

`--exhaustive-immediates` selects the larger external corpus. `--capture`
requires an absent fixture directory. Generated executable/object artifacts are
removed on success and failure; reference records and failure evidence remain.
The generator and comparison use O(cases) time and retained storage.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| BT1 | The admitted BT semantics follow SDM086 | Exact instruction entry and physical Intel runner | Addresses, CF and unaffected state | Signed boundaries, dirty upper register bits, every immediate, distinct neighboring words | Any native GPR, memory or defined/unaffected flag mismatch | Confirmed for the recorded 8,640 cases; portable tests additionally cover address wrapping and base/index aliasing |
| BT2 | Linux Intel instruction evidence does not establish Intel HVF execution | Separate OS/backend and device frontier | Qualification scope | Keep native records distinct from planner/SDK tests | Actual Intel macOS Hypervisor VM execution with recorded exits and device effects | Retained; physical Intel HVF remains unverified |

High impact: physical Intel macOS exits/device cycles, remaining MMIO and
intercept/exception profiles, IRQ coherence and complete checkpoint conservation
remain open. This change does not close C-HVF or the other active audit goals.
