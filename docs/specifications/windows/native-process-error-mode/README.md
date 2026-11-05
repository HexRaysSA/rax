# Windows process error mode

`ProcessDefaultHardErrorMode` (information class 12) is a mutable, process-owned
`ULONG`. The NT query/set services and the builtin `GetErrorMode`/`SetErrorMode`
exports share that state. Guest setters never call a host setter.

## Sources and observation scope

The exact producers, captures and provenance records are in this directory.
`primary/provenance.json` pins Microsoft SDK documentation and its licenses.
The class name and `ULONG` declaration are also present in the pinned
[PHNT header](../native-process-tls/phnt-ntpsapi.h); its provenance is recorded
in that directory's `primary-contracts.json`.

The public contracts are Microsoft's [GetErrorMode documentation](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-geterrormode),
[SetErrorMode documentation](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode),
[NtQueryInformationProcess documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
and [process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags).
The private flag translation, rights, fault priority and guard behavior below
come from independent native calls, rather than the public documentation.

All captures use Windows kernel 10.0.29698 on an ARM64 host. The four caller
views are native ARM64, translated x64, WoW64 x86 and large-address-aware WoW64
x86. These are not physical AMD64 kernel measurements. Provenance records bind
producer bytes, image bytes, output bytes, process identity and DLL filesystem
context. DLL filesystem hashes do not attest which modules were loaded.

| Producer | Per view | Four-view total |
| --- | ---: | ---: |
| Main query/set length, pointer, alias and handle calls | 3,780 | 15,120 |
| Main NT/public state transitions | 34 | 136 |
| Upper-address query/set calls | 720 | 2,880 |
| Inheritance child processes | 10 | 40 |
| Inheritance thread observations | 5 | 20 |

Every native producer terminated with exit code 0. The main and upper-address
producers each closed seven owned handles and released two owned allocations.
Each inheritance producer reaped its ten children, closed 45 handles and
restored its initial error mode. No protected validation job was modified.

## State translation and initialization

Let `N` be the raw NT value, `P` its public representation, and `R` a requested
public value. Arithmetic is bitwise over unsigned 32-bit values:

```text
GetErrorMode:       P = N XOR 0x00000001
NtSet class 12:     N = requested ULONG
SetErrorMode:       return old P
                   N = (R OR (old P AND 0x00000004)) XOR 0x00000001
```

The NT setter accepts every tested bit, including `0xffffffff`, and can clear
mask `0x00000004`. The public wrapper retains that mask once enabled. Both
interfaces preserve the caller's last-error value in the captured transitions.
Independent threads observe the same process mode; their thread error mode
remains independent.

Windows-native startup captures the creator's current raw mode through a
synchronous, read-only host query into two private aligned `ULONG` variables.
It neither passes guest pointers to NT nor changes the host's mode. The
standalone Windows personality starts at raw `1`, public `0`, corresponding to
the measured `CREATE_DEFAULT_ERROR_MODE` child behavior. Native normal children
inherit their creator's complete raw value. The inheritance controls justify
startup selection; they do not add guest process creation or child scheduling.

## Query and set contract

Both records have exactly four bytes. Nonzero lengths require four-byte buffer
alignment. A query probes a nonnull `ReturnLength` for four writable bytes
before class-specific length or handle checks, including a zero-length query.
Only a successful query publishes `ReturnLength = 4`. Output is written before
the optional returned length, including aliases.

| Real self-handle grant | Query | Set |
| --- | --- | --- |
| `0x0000` | access denied | access denied |
| `0x1400` | success | access denied |
| `0x1000` | success | access denied |
| `0x2200` | access denied | success |
| `0x2000` | access denied | access denied |
| `0x1fffff` | success | success |

The current-process pseudo-handle is accepted. An event or the current-thread
pseudo-handle produces `STATUS_OBJECT_TYPE_MISMATCH`; an absent handle produces
`STATUS_INVALID_HANDLE`. A modeled handle to another process is explicitly
unsupported after access validation: no host process state is substituted.

The query validates exact length and handle before touching its output. An
output page with read-only and guard protections returns access violation
without consuming the guard. A reached guarded `ReturnLength` probe consumes
the guard. A setter captures its input before checking the handle, accepts
read-only input, and consumes a reached input guard while returning the guard
status. WoW64 does not retry that setter input guard.

Native 64-bit callers reject an upper-user-span or arithmetic overflow before
the query's returned-length probe, and before the setter's exact-length check.
WoW64 omits that early span rejection and reaches its exact-length checks first.
The upper-bound replay maps the producer's first address above its application
range to the guest VM's corresponding boundary. It verifies logical boundary
ordering, not equality of host and guest virtual addresses.

## Implementation and validation

`process/error_mode.rs` owns the state and creator capture. Native service
handlers preserve measured validation order. The two public exports append to
the existing KERNEL32/KERNELBASE export groups, preserving earlier synthetic
ordinal positions. No C API, SDK ABI, serialized format or dependency default
changes.

The `native_process_error_mode` test filter replays all 18,136 main and
upper-address observations through the existing ARM64, x64 and WoW64 service
transports. It also checks shared public/native state, process isolation,
export registration and calling conventions. Windows additionally checks the
creator capture against the native public getter without calling a host
setter. Run with Rust 1.95.0:

```text
cargo +1.95.0 test --locked --offline --no-default-features --features x86_64-suite -p rax --lib native_process_error_mode -- --test-threads=1
```

The process-query regression filter is
`user::windows::process::sched::tests::services_tests::process_query_tests::`.
Focused tests do not establish complete installed-program execution or fix
unrelated failures in earlier full-library runs.

The independent installed ARM64 `cmd.exe /d /c dir /b
C:\Windows\System32\cmd.exe` comparison completes both natively and under
emulation with exit code 0, stdout bytes `636d642e6578650d0a` (`cmd.exe\r\n`)
and empty stderr. It uses the installed DLLs and host filesystem without a
separate sysroot. The guest completes at sample 232,023 with instruction-budget
upper bound 14,849,536, below the 50,000,000 limit; this bound is not an exact
retired-instruction count. The arena is 1 GiB and the seed is 7. Observer source,
RAX library, executable, output and native process identity are separately
bound in the qualification receipt. This establishes that one command on the
measured subject, not arbitrary Windows programs or a completed process goal.
The unfiltered native macOS ARM64 library run completed with 9,995 passed,
2 failed and 2 deliberately ignored tests. Both failures were Linux-personality
socket tests: the identical executable reproduces them with the original long
temporary directory and passes them with a shorter directory inside the same
worktree. The recovered `--lib --no-run` compiler record identifies the exact
same executable SHA-256. This is not an all-green full-suite claim.

The original Linux container run remains active. Its executable is PID 1,
which selects namespace-init signal behavior; 16 PID-sensitive diagnostic
cases, including the linked-SIGSTOP case that loops in the original run, pass
with Docker's init wrapper and the original temporary directory. A further
socket failure passes with a short directory. Eleven unchanged Darwin registry
tests independently reproduce `ReadOnlyFilesystem` because their fixture
helper uses `/tmp` under the read-only container root. With the identical
checked executable and an owned, in-worktree scratch directory bound to
`/tmp`, all 18 registry tests pass without source changes. These harness
conditions are distinct from the class12 implementation.

An additional complete Windows ARM64 run, compiled with optimization level 2,
debug assertions and overflow checks, completed with 9,120 passed, 173 failed
and 2 ignored tests, with none filtered. All five error-mode tests passed.
The failure messages comprise 158 Windows commit-limit errors (1455),
10 registry-fixture permission failures, 3 inconsistent cross-view registry
captures, 1 unavailable GUI-thread profile and 1 persistent-file sharing lock.
The three registry-capture cases pass when run individually with the same
executable; their original full-run failures remain recorded. These results
do not establish an all-green suite. The earlier unoptimized Windows ARM64
run remains active. The checked x64 complete run is active with one worker;
x64 runs use Windows ARM64 translation, not a physical AMD64 kernel.

The same Windows library also completes `cmd.exe /d /c echo
rax-native-error-mode` with matching native exit and output bytes. The broader
command matrix has an unresolved result for `ver`: both executions exit 0,
but the guest emits two CRLF lines while the native command emits the Windows
version banner. The complete cause remains unproven. Native child output uses a pipe whereas
the guest observer uses `CapturedConsole`; matching IO preconditions and tracing
message/resource lookup are required before assigning a cause. This observation
does not alter the independently captured class12 state/ordering contract.
A read-only service-return observer now records successful opens of the
installed `en-US` MUI files followed by `STATUS_ACCESS_DENIED` from read-only
`NtCreateSection`. An independent native control confirms that a read-data-only
file handle supports both `FileStandardInformation` and read-only section
creation, while Rust's `File::metadata()` fails without read-attributes rights.
The retained-file-section adapter currently requires that metadata query before
creating a section. Its incorrect precondition needs a separate fix; complete
banner revalidation and the IO-precondition caveat remain. Other finite command
checks have exposed a `type NUL` exit-status difference and an explicit
unsupported native image-section allocation mode while handling `where.exe`.
Those file/section behaviors remain outside this error-mode changeset.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Basis | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| EM1 | One process-owned raw `ULONG` backs both interfaces. State storage and dispatch depend on it. | Pinned declaration and native calls. | Sequential NT/public writes, every tested flag pattern, another thread and real self handles; falsified by divergent values. | Confirmed within all four captured views. |
| EM2 | Native creator inheritance differs from standalone default initialization. Startup selection depends on it. | Creator samples and process-creation controls. | Five parent values, inherited/default children and native getter agreement; falsified by a child or getter mismatch. | Confirmed within all four captured views. |
| EM3 | Captured private fault ordering is usable for this qualified kernel profile. Replay expectations depend on it. | Source-bound 10.0.29698 captures. | Re-run the exact producers on another kernel build; any changed status, memory or guard trace falsifies transfer to that build. | Retained only within the measured scope; other builds unknown. |

High impact: a constant mode would discard setter state and creator inheritance;
the shared state and independent controls address that issue. Medium impact:
private behavior on other kernel builds and physical AMD64 remains unmeasured;
it does not block the captured profile and is not represented as validated.
Guest child-process creation, other process personalities and unrelated native
service gaps remain outside this changeset.
