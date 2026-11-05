# Intel HVF SHLD/SHRD memory transactions

The native MMIO planner previously rejected `66 0f a4 07 00` (`SHLD word
[RDI], AX, 0`) as unsupported. The [observed baseline](baseline.json) and
[diagnostic](baseline.stderr) retain the first failing independent reference
case. SHLD and SHRD now admit their 16-, 32- and 64-bit memory destinations,
register sources and imm8/CL counts in the existing IA-32e MMIO profile.

The planner captures the source operand and count before any device callback.
The bus performs one width-bounded transformation. Completion publishes flags
and advances RIP once; it does not write a source GPR. Pending transactions
retain these operands across JSON/binary codecs and native private-state restore.
Byte operands, LOCK, incomplete operands, incompatible EPT qualifications and
existing unsupported event/debug profiles reject before device effects.

| Representation | Change |
|---|---|
| HVF MMIO plan | Three-operand SHLD/SHRD admission and completion |
| Device bus | Width-checked double-shift transformations |
| Public operation codec | Append tags 13 and 14; tags 0-12 unchanged |
| Deferred software CPU context | Append tags 19 and 20; tags 0-18 unchanged |
| Native CPU private context | Existing payload encodes the pending new operation |
| Direct execute, SMIR, JIT, C ABI | No instruction implementation or ABI change |

The primary definition is [Intel SDM revision 086](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md),
Vol. 2B pages 4-636/637 (SHLD) and 4-639/640 (SHRD), PDF pages
1863/1864 and 1866/1867. Counts are reduced modulo 32, or modulo 64 for
64-bit operands. A masked-zero count preserves destination and flags.
For a defined nonzero count, CF is the final bit shifted out and SF/ZF/PF
describe the result. OF is the destination sign change for count 1; AF is
undefined, and OF is undefined for larger counts. The implementation retains
undefined AF/OF inputs. Masked 16-bit counts 17-31 have undefined destination
and arithmetic flags; the selected policy retains both while still admitting
the instruction and performing its memory transaction.

The [independent fixture](../../../tests/fixtures/hvf/mmio-double-shifts-v1/README.md)
contains 25,344 physical Intel Linux KVM executions. All 16 GPRs, the 24-byte
operand neighborhood and defined/unaffected flags are checked against SDM
formulas. The complete production-planner replay also checks both accepted
RMW EPT read-bit forms. These RAM reference observations establish values;
they do not observe native HVF exits or external device ordering.

The [native reference receipt](native-reference.json) records a second capture
with the checked-in collector. Both binary hashes reproduce the first capture
exactly. Another [32 native permission controls](native-access.jsonl) first
read the operand successfully from a read-only page, then observe `SIGSEGV`
with `SEGV_ACCERR` at that same address for SHLD/SHRD. Both count forms,
all widths, zero/masked-zero counts and undefined 16-bit counts are covered.
This establishes write-permission requirements, not external bus cycles.
Remote compiler/guest/runner directories were removed before evidence transfer.

The native HVF consumer retains the previous 155 cases and adds 48 cases from
[these independently observed records](selected-records.json). It covers both
directions, all widths, imm8/CL, counts 0/1/half-width/width-minus-one, source
GPRs AX/EAX/RAX, CX/ECX/RCX, R8 and R15, including CL/source aliasing.
Each checks the exact descriptor, pending re-emission, device result,
unchanged GPRs, defined/unaffected flags, RIP and a subsequent guest marker.
The 24 CL cases restore the encoded pending private payload into a fresh
VM/SDK CPU before completion. This is private CPU restoration; whole checkpoint
file continuation remains covered separately by the original consumer cases.

Prepared consumer format version 2 binds the SHA-256 mapping of both compiled
Rust source files in `consumer_sha256`; version 1 artifacts reject explicitly.
The engine digest continues to bind engine/vendor/Cargo inputs independently.
`--emit-double-shift-references` emits the actual compiled constants without
creating a VM, permitting byte-for-byte comparison with the selected records.
Compilation, signing and that emission provide zero native guest executions.
Actual 203-case native qualification remains a separate required gate.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| D1 | SDM-defined values are independent of the RAX implementation | Fixed-value expectations | All 25,344 native records checked with standalone formulas; corrupt GPR/memory/defined-flag records reject | Confirmed for this corpus |
| D2 | Undefined results do not remove memory access requirements | Admission of zero/undefined counts | 32 native permission controls and all 256 raw counts in local policy checks | Confirmed within recorded controls |
| D3 | Native HVF resumes the new pending transactions correctly | Native completion/restore claim | Actual 48 selected cases, including 24 fresh private restores, must pass within the complete 203-case run | Pending native execution |
| D4 | Prepared artifacts contain the exact separately compiled consumer | Artifact admission | Modify each Rust source independently; digest mismatch rejects; compiled constants equal selected native records | Confirmed in tooling and compiled emission controls |

High-impact remaining scope: native HVF qualification of this extension and
the original audit's other MMIO, interrupt, FP and checkpoint requirements.
Medium impact: the Linux reference host and hosted Intel HVF runner expose
different virtualization interfaces; agreement is restricted to the recorded
architectural fields. No remaining original finding is closed by this subgroup.

Each transaction uses O(1) time and auxiliary space. Reference generation,
validation and retained evidence use O(N) time/space for N cases. Run the
complete `hvf_mmio` and `hvf_intel_owner` Cargo targets, full affected library
suite and `python3 -m unittest discover -s tools/hvf -p 'test_*.py' -v` before
publication. Qualification results and their exact limits accompany this file.

The final unchanged-source library run passes 12,446 tests with zero failures,
36 ignored and zero filtered. The complete MMIO target passes all 61 cases;
the complete Intel SDK-owner target passes all 73. All 38 Python tooling
checks, Clippy and formatting pass. The 203-case consumer compiles, signs and
passes strict signature verification; its 48 emitted constants exactly match
the selected native records. That local emission executes zero guests.
[qualification.json](qualification.json) retains source/executable/log hashes,
commands, counts, timings and pending native gate status.
