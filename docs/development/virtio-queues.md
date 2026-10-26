# Virtio split queues and block requests

The modern MMIO transport negotiates indirect descriptors for the in-memory
block device. A request can use a direct chain, one indirect table, or a direct
prefix followed by an indirect table. Block fields are parsed as readable and
writable byte streams, independently of descriptor boundaries.

The primary reference is [VIRTIO 1.2, Committee Specification 01](../specifications/virtio/virtio-v1.2.pdf),
sections 2.1, 2.2, 2.7.4, 2.7.5, 4.2 and 5.2. The retained
[provenance](../specifications/virtio/PROVENANCE.md) identifies the exact PDF and
an explanatory QEMU source revision.

## Queue admission and publication

A queue must have a power-of-two size within the advertised maximum of 256
entries. The public queue helper additionally accepts sizes through the split
ring architectural maximum of 32,768 entries. Descriptor, available and used
areas require alignment of 16, 2 and 4 bytes respectively. Their full extents
must fit the 64-bit guest physical address space. Extent arithmetic uses a
128-bit intermediate, permitting an exclusive end equal to 2^64.

All reachable descriptor metadata is validated before invoking the request
handler. Validation covers indices, direct and indirect cycles, indirect feature
negotiation, nested indirect descriptors, simultaneous INDIRECT and NEXT,
readable buffers after writable buffers, payload extents, reachable buffer
count and the 2^32-byte inclusive chain limit. The wrapper's WRITE flag is
ignored. An indirect table can be unaligned; unused table entries can exceed
the queue size. Only reachable buffers count toward the queue limit.

The chain planner uses ordered visited-index sets: O(n log n) time and O(n)
storage for n reachable descriptors. It is iterative. A block write stages all
source bytes before changing media: O(b + n) time and O(b + n) storage for b
payload bytes. These bounds exclude the memory provider's own access cost.

A successful request publishes in this order:

```text
payload writes -> status byte -> complete used entry -> used.idx
```

The synchronous device owns the used counter through `last_avail_idx`; it does
not adopt a guest-written used index. Available-index distance cannot exceed the
queue size. Both counters wrap modulo 2^16.

A failed destination, status or used-ring write can leave partial guest memory
or an already committed media write. The checked transport sets
DEVICE_NEEDS_RESET, requests a configuration interrupt if DRIVER_OK was set,
and suppresses further execution until reset. It does not promise rollback.
A failed source read completes with IOERR when a status byte can be written;
no prefix of a block write reaches media.

The public `Descriptor`, `DescriptorChain` and `VirtQueue` field layouts and
existing call signatures remain available through their original module paths.
`QueueError`, checked processing and a feature-aware device callback are
additive. The legacy queue callback cannot convey rich errors; its compatibility
helper disables the queue on failure. The block transport uses the checked path.

## Transport lifecycle

Unsupported feature requests, or omission of VERSION_1, prevent FEATURES_OK
from being accepted. Feature words become immutable once accepted; invalid
feature selectors do not alias valid words. Queue notifications do no DMA before
FEATURES_OK and DRIVER_OK, while the queue is not ready, or after FAILED or
DEVICE_NEEDS_RESET.

An unavailable queue selector reads zero maximum size and ready state and cannot
modify queue zero. Queue sizes and addresses are immutable while ready. A zero
status write resets negotiation, queue state and pending interrupts while retaining
block media. Used-buffer interrupts honor the available ring's NO_INTERRUPT
flag; acknowledgement clears only the supplied pending bits.

## Block framing and implemented commands

The first 16 readable bytes contain type, reserved field and sector. The last
writable byte is the status. Header fragments, combined header/write-data
buffers, fragmented read destinations and combined read-data/status buffers are
supported. Read and Write require payload sizes divisible by 512 bytes. Sector
multiplication and end calculations are checked against capacity. Read-only
writes return IOERR without modifying media.

GET_ID fills exactly 20 bytes, including NUL padding, and can span writable
buffers. Flush completes against the current in-memory media; persistent host
storage and durable flush are outside this implementation. Unknown commands
return UNSUPP. Discard and Write Zeroes are separate capability work.

## Executable evidence

`cargo test --test virtio_indirect` compiles the owning transport, queue and block
sources, retaining all 20 existing unit tests and adding 22 regressions. The
baseline implementation fails all 22 regressions. The final tests include
65,538 queue submissions across index wraparound, exact byte limits, malformed
metadata, negotiation, DMA failures, media preservation and publication order.
The target is registered in core CI and the scheduled backend/device shard.

`tools/virtio-diff/indirect_oracle.py` builds bare-metal AArch64 guests, executes
real MMIO negotiations and queues under QEMU TCG, and retains each input, ELF,
raw serial frame and disk image. The product comparator compiles the current
owning modules; the linked RAX library supplies the existing bus interface.
No product ring implementation supplies the independent guest's result.

The 16 scenarios contain 24 product scenario requests plus one complete media
read per scenario. Twelve scenarios, containing 18 requests, require exact
completion records, interrupt/status words, 7,186 output bytes and 49,152 media
bytes against QEMU. Four differences are retained and checked explicitly:

| Scenarios | QEMU observation | Product contract |
|---|---|---|
| Mixed read and mixed write | Reports missing headers; guest records failure without completing a request | Direct prefix plus an indirect tail is supported under section 2.7.5.3.2 |
| Fragmented ID | Writes the ID and one NUL, leaving five seeded bytes unchanged | Fills the 20-byte NUL-padded ID under section 5.2.6 |
| Zero-length buffer | Rejects the request | Accepts zero-length buffers as a bounded local policy; no mandatory cross-implementation equivalence claim |

The product is checked against the explicit primary or local contract in those
four scenarios. QEMU's failed mixed-write case leaves media unchanged; the
product's specified write changes it. Their media are therefore not claimed to
match. The other three differing scenarios retain equal media. All 65,536
product media bytes are independently checked against the scenario contract.

All 16 runs also retain full feature words. QEMU offers additional capabilities;
only the negotiated required bits are common. The source archive is QEMU
v11.1.0; the executed binary reports its own version in the manifest. They are
separate provenance records.

## Assumption register

| ID | Assumption and basis | Dependent result | Stress or falsification probe | Status |
|---|---|---|---|---|
| V1 | The synchronous memory provider truthfully reports each requested DMA result | Fault handling and publication | Inject source, payload, status, entry and index failures; inspect ordered accesses | Exercised; partial writes remain permitted |
| V2 | Driver-owned metadata remains stable during a synchronous notification | One planned chain corresponds to one request | Concurrent mutation during planning | Required integration assumption; concurrent DMA synchronization remains open |
| V3 | Public layout and existing signatures are compatibility constraints | Queue module extraction and default callback | Compile all owning controls and all Cargo targets | Required final build gate |
| V4 | A complete indirect chain can end at any valid index and use an unaligned table | Traversal and bounds | Nonlinear indices, unused entries, mixed prefixes and wrapper WRITE | Local regressions and retained independent cases |
| V5 | QEMU need not implement every primary case identically | Independent result interpretation | Preserve mixed, ID-padding and zero-length counterexamples | Confirmed; four differences remain explicit |
| V6 | Media are the device's current byte vector, without host durability | Write/Flush result | Crash/restart a persistent backend after Flush | Unknown for persistent storage; excluded from this group |

## Bounded scope and quality gates

High impact: concurrent guest-memory ownership, native interrupt routing and
complete checkpoint/media state remain integration requirements. Device reset
prevents replay of an ambiguous completion, but an already committed write is
not rolled back. Medium impact: packed rings, EVENT_IDX, notification-data and
queue-reset features are not advertised. Zero-length-buffer acceptance is a local
policy. Low impact: control-register subword access compatibility remains;
compliant MMIO drivers use aligned 32-bit control accesses.

QG1: no normative assessment of the project is needed. QG2: assumptions and
falsification probes are above. QG3: coverage is limited to split queues, MMIO
lifecycle and existing block commands. QG4: byte/sector widths and bounds are
explicit. QG5: failures and reference differences are retained. QG6: primary
inputs and executable records are identified. QG7: integration limits are
explicit. Broad build, library, C API, translated-host and CI checks are recorded
in the audit ledger before the semantic group is committed. These tests do not
establish native hypervisor execution or a complete operating-system boot.
