[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# Instruction and memory-access tracing (`--mem-trace`)

`rax-user --mem-trace FILE` records the guest's instruction fetches and every
guest memory read and write, then `rax-trace-map` turns the capture into a
region-by-region view of the address space. The intended use is reverse
engineering and packer analysis: a virtualised binary shows its unpacking
stub, its VM code, its handler pages, its dispatch tables, and the context
those handlers share as distinct access patterns.

## Capture

```sh
# x86-64 guest: the trace disables the native JIT so the interpreter can
# report every access.
./target/debug/rax-user --mem-trace program.raxtrace ./program arg1

# Report on the terminal
./target/debug/rax-trace-map program.raxtrace

# Standalone report and machine-readable data
./target/debug/rax-trace-map program.raxtrace --html report.html --json report.json

# One region or one page in detail
./target/debug/rax-trace-map program.raxtrace --region 0x7ffd12345000
./target/debug/rax-trace-map program.raxtrace --page 0x401000
```

`--mem-trace` covers x86-64 user-mode execution. It records the initial and
final address-space snapshots, instruction fetches (decode-miss addresses),
and data reads and writes with their width, value, and the address of the
instruction that performed them. The trace is a compact binary file; it is
written as execution proceeds, so a capture survives a guest crash.

The native JIT is disabled while capture is active. Native regions perform
their loads and stores inline, outside the MMU access stream, so a trace would
otherwise miss writes. This makes capture slower than normal execution but
exact for the accesses it reports.

Guest child processes share the trace file. Their accesses are appended, but
interleaving between processes is not ordered by a clock; a report over a
fork-heavy program therefore aggregates all processes.

## What the report shows

Regions are contiguous groups of touched pages. For each region the report
shows fetch, read, and write counts; store widths; zero-valued stores; the
fraction of the region covered by writes; the first-write/first-fetch order;
permissions from the first and final map snapshots; and the code pages that
wrote it. The classifier names evidence, not facts:

| Report term | Evidence |
|---|---|
| executable code | pages fetched but never written |
| self-modifying code | pages fetched and written; the ordering separates a page written before its first fetch (unpacked) from one patched after it |
| pointer / dispatch table | read-only pages where sampled loaded values point into executable pages |
| multi-writer context | written pages with mostly wide stores issued by two or more code pages |
| stack, heap | the final map's VMA name |
| written data, read-only data | the remaining written or read-only pages |

`handler candidate` lines list code pages whose writes concentrate on a
context, pointer table, or other executable page. In a VM, these are the
handler entries; the shared writable region they converge on is the VM
context.

The address-space map uses `X` for executable pages, `S` for pages both
executed and written, `W` for written pages, `r` for read-only touched pages,
and `.` for untouched bytes inside a touched cluster. Sparse address spaces
are shown as clusters so the image and the stack remain visible at the same
time.

## Limits

- The trace is per-access and can be large for memory-heavy programs.
- Fetch records identify executed instructions, not execution frequency: the
  decoder caches fetched instructions, so a hot loop appears once. The page is
  still classified as code.
- The classifier is heuristic. A global written by two functions can be called
  a context; the report's counts and ordering are the primary evidence.
- JIT-disabled execution does not exercise the native lowering path, so a
  timing-sensitive program may behave differently under capture.
- Values and map names make the trace potentially sensitive; it contains guest
  paths and sampled memory values.
