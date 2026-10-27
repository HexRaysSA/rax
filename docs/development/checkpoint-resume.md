# Expanded checkpoint files and detached resume

Console/hotkey/signal and periodic capture now save `SnapshotBundle` files,
including every mapped physical region and represented PCI/controller/media
state. `--checkpoint file.rxc` resolves recorded configuration with CLI
overrides, builds a bare target and imports those represented components. It
requires neither the original kernel/initrd nor the original storage paths.
Writable restored media retain guest changes in memory and subsequent checkpoint
files. Read-only media remain protected. Explicit image overrides still need to
match recorded identity/policy before restore.

`VmConfig::from_checkpoint_bundle`, `validate_resume_bundle` and
`Vmm::new_resume_bundle` are additive typed entrypoints. Source-independent image
admission requires represented endpoint/media state. The older base-only config
and capture/restore entrypoints retain their image-state guards. `--resume`
retains its CLI/file configuration and fresh-machine construction semantics,
then imports represented extensions when compatible; `--checkpoint` is the
source-independent path.

Geometry/count/architecture/PCI/storage compatibility is checked before target
construction and trace side effects. The constructor registers the same PCI
profile with empty detached placeholders, then validates/imports captured media
before exposing the returned VM. No placeholder guest work is executed.

Checkpoint configuration now records the page-rounded allocated/reportable RAM
extent. The predecessor accepted a request for 134,217,729 bytes, returned a
snapshot object with that configured extent and 134,221,824 RAM bytes, then
rejected decompression/save as inconsistent. The correction records 134,221,824
bytes. The same public client and source cookie are retained across actual
predecessor/current libraries; initial strict-observation failures are archived.

The CLI fixture loads an actual LLVM-produced RISC-V ELF with text at
`0x80000000` and `tohost` at `0x80001000`, captures before guest execution, removes
the original kernel, then resumes the file. Acceptance requires exactly one
`RAX`/newline UART marker and a shutdown event. An owned stdin pipe remains open
until exit, so EOF cannot supply that event. The independent oracle streams
system-zstd output and compares every physical/projection byte against the ELF
load segments and zero backing using bounded chunks. This is a small emulated
bare-metal execution check.

| ID | Assumption / dependency | Stress and falsification probe | Status |
|---|---|---|---|
| F1 | Typed resume may use captured media without source descriptors. | All three image modes, renamed/missing sources, exact live media/control state and unchanged original bytes. | Owning unit and ledger receipts required. |
| F2 | Compatibility is admitted before constructing a target. | Wrong version/count/extent/architecture/PCI with a trace-side-effect sentinel. | Owning regressions and ledger receipts. |
| F3 | Configuration records allocated geometry. | Actual accepted 128 MiB + 1 request, source cookie in the final rounded byte, old/current same-client observations and save result. | Owning regression and ledger receipts. |
| F4 | CLI success represents guest execution. | Unique UART marker plus shutdown, open stdin writer, missing original ELF and independent full-byte comparison. | Owning CLI case and independent receipts required. |
| F5 | Independent writers remain quiescent. | Capture precedes guest execution; constructor stays private until represented import completes. | Full SMP coordinator remains open. |
| F6 | Expanded files still represent a bounded subset of VM state. | Additional CPU/private/platform/scheduler, per-VM timing, replay and native failure transactions remain separate. | Full VM closure remains open. |

For N backing bytes, M media bytes and K control bytes, capture/restore cost is
O(N + M + K), plus bounded region lookup work documented by the physical-memory
format. Independent comparison uses at most 1 MiB output chunks plus compressed
input and ELF segment data. Resident compressed snapshots and detached candidate
media still consume their admitted byte budgets.

High impact: additional CPUs/private/platform/scheduler state, full quiescence,
per-VM clocks, replay, Linux boot and native KVM/HVF transactions remain open.
Medium impact: legacy base files retain their represented-projection semantics;
restored writable images are detached. Low impact: future required sections must
extend typed admission and explicit publication.
