# PCI host-bridge checkpoints

`PciStub::checkpoint()` captures the CONFIG_ADDRESS latch, every raw function
configuration byte, BAR descriptors and ordered endpoint routing bases.
`restore_checkpoint()` requires the destination's exact function keys, BAR
profiles and endpoint order/type/size. It validates the full record before
changing any field and never calls an endpoint handler. Handler-private state,
guest RAM and VM quiescence remain the caller's responsibility.

The `RAXPCI01` record uses fixed little-endian integers and strict 0/1 booleans.
Its 20-byte header contains the tag, latch and two u32 counts. Each function is
307 bytes: three raw key bytes, 256 raw configuration bytes and six 8-byte BAR
records (presence, u32 size, I/O, prefetchable and 64-bit flags). Each endpoint is
21 bytes: key, BAR index, u64 window size, I/O flag and u64 current routing base.
Functions are sorted by key; endpoints retain insertion order because overlapping
BAR windows resolve by that order. Absent BAR metadata is canonical zero.

The routing base is preserved explicitly. `add_function` can replace raw config
without recomputing an already attached endpoint; capture must retain that
observable state, including a pending sizing probe, rather than silently repair
it. The next ordinary guest config write recomputes bases as before. Raw IDs and
class bytes are also retained because the current model allows guest writes to
all configuration dwords; checkpoint decoding does not redefine that behavior.

Input counts are bounded to 65,536 functions and 393,216 endpoints. Exact encoded
length and destination topology are checked before allocation. Capture takes
O(f log f + e) time and O(f + e) additional space; restore takes expected O(f + e)
time and space, where f is function count and e is endpoint count. Restoring a
record neither creates handlers nor changes their identity.

| ID | Assumption / dependent result | Stress and falsification probe | Status |
|---|---|---|---|
| P1 | Every bridge-owned field is captured; handlers remain external. | Modified raw config, partial latch, disabled/probed/remapped BARs, stale routing base and overlapping endpoints must continue identically. | Locally tested. |
| P2 | Endpoint ordering is observable. | Reversed otherwise-identical registrations must reject atomically; overlapping handlers retain routing order. | Locally tested. |
| P3 | Malformed input never partially changes live state or calls handlers. | Every prefix, trailing bytes, count overflow, noncanonical keys/booleans, profile/type/size mismatch; compare before/after and handler calls. | Locally tested. |
| P4 | Hash-map insertion order is not observable configuration state. | Equivalent maps with reversed insertion order must emit identical records. | Locally tested. |

High impact: endpoint-private state, full VM/container integration, all CPUs,
quiescence and replay remain open. Medium impact: raw public registration permits
keys/profile combinations beyond standard PCI topology; capture preserves
existing represented values within explicit resource bounds. Low impact: future
bridge fields require a new wire revision. The complete `pci_checkpoint` owner has 17 tests; direct owning-source execution also runs the 11 existing bridge tests. An independent parser checks seven actual source/restored fixtures, all 9,826 control bytes and 112 routing-trace bytes. The whole library, translated owners, and other final gates remain required before commit.

The [endpoint state APIs](pci-endpoint-checkpoints.md) independently capture e1000, UHCI and AC'97 private state; the runtime must coordinate their capture with the bridge and guest RAM.
