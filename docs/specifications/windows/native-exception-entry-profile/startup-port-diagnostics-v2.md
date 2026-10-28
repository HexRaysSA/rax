# Installed startup port terminal diagnostic, version 2

CI run40546497102/job122338809227 passes the installed AMD64 current-session
section leaf. The unchanged full hardware-fault fixture then stops at
unimplemented `NtConnectPort` (service0xA2). The port name, views and connection
information are unknown from the existing version1 terminal observer.

`startup_diagnostics_v2.rs` is a separate observer. Version1, the original Rust
test, fault source, three binaries, assertions and execution limits remain
unchanged. Version2 independently requires the same exit0, RTL-owned VEH state,
60 s deadline,16384 turns and4096 instructions per slice. No service is replaced
or made successful by observation. Only an exact terminal NtConnectPort failure
enables argument decoding; successful processes emit no port snapshot.

The eight-argument declaration is recorded in the primary
[System Informer header](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntlpcapi.h).
The first x64 argument is retained in R10 after SYSCALL; the next three use
RDX/R8/R9, and stack arguments start at RSP+0x28. ARM64 uses X0-X7; the WoW64
transition retains two return slots before the first stack argument. The
observer records all raw arguments and retained registers, so these decoding
assumptions remain independently inspectable.

At most eight threads are inspected after execution has terminated. A name
preview retains up to1024 UTF-16 bytes; information previews retain up to4096
bytes and report the declared length and truncation. Fixed-size QoS, view,
maximum-length and handle snapshots retain raw bytes. Null pointers, unreadable
spans and checked-address overflow remain explicit. The algorithm uses
O(T + B) time and O(T + B) output storage for T<=8 threads and bounded B preview
bytes. This test-only module compiles on macOS/Linux/Windows. The existing
process/SEH CI selection runs installed NTDLL on native Windows; no job is added.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SP1 | Terminal NtConnectPort failure retains entry arguments. | Existing scheduler reinserts failed threads; version1 retained the actual section request. | Version2 port snapshot. | Native64 register/stack boundaries, WoW64 return slots, unreadable views and lengths. | Compare raw registers and stack words with decoded name and service entry; reject inconsistent layouts. | Retained pending native capture. |

High impact, blocking full-process qualification: the actual requested port and
its protocol are unknown until capture. This observer does not infer a CSR
connection from the service name. Medium impact, non-blocking for the observer:
the existing CSR connection profile supports measured ARM64/session0 only.
No shipping behavior, public/private ABI, ISA, permissions or package changes.

The source compiles on macOS ARM64, where all eight selected native-entry
unit/qualification tests pass without failures or ignored cases. Linux
compilation is active. Local native Windows transport is intermittent and has
not started this observer; the existing AMD64 CI lane remains the independent
native capture route. No native port identity or connection verdict is claimed
by this candidate publication.
