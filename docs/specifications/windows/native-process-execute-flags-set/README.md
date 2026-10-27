# Permanent ProcessExecuteFlags setter and caller-read boundaries

The original immutable x86 fault fixture now reaches `NtSetInformationProcess`
class34 with the self pseudo-handle, a four-byte input, and flags `0x0000000A`.
`stopped-observer-v1.rs` records the packet and the installed wrapper's actual
`RET16`; it supplies no syscall result and changes no original fixture bytes,
assertions or execution budget. Its receipt binds the pre-change native rlib.
The fixture PE header has NX_COMPAT. The observed input requests
MEM_EXECUTE_OPTION_ENABLE (`2`) | MEM_EXECUTE_OPTION_PERMANENT (`8`).

## Independent observations

`native-set-v1.cpp` and `native-set-v2.cpp` call the actual installed entry in
ARM64, x64 compatibility, and x86 processes on native ARM64 Windows 10.0.29695.
The v2 source additionally tests invalid flag bits on guarded inputs.
`family-launcher-v2.cpp` creates separate default/enabled/disabled CHPE x86
children using the immutable launcher already published for the x86 profile.
Every child explicitly has NX_COMPAT, independently queries private execute
flags before and after each call, and verifies that they remain `0x0D`.

The frozen corpus has nine observations: three times 574, plus six times 594,
equal 5286 calls. Raw output bytes are preserved as base64 JSON with byte counts
and SHA-256 hashes; the decoded rows are `local-29695-v1.json`. Receipts bind
exact producer, compiler, executable, installed-library and output identities.
Default, enabled and disabled CHPE x86 agree. Native64 ARM64 and x64 compatibility
agree. None of these calls changes system DEP policy or the original fixture.

A separate disposable native64 Python process checks eight full-width
handle boundaries. Only `0xFFFFFFFFFFFFFFFF` is the native64 self pseudo-handle;
`0x00000000FFFFFFFF` and other high-word variants reject the operation before
reading input. Guard retention distinguishes that rejection from native64's
later invalid-parameter result after a reached read. The policy stays `0x0D`.
This supplement is a native boundary control, separate from the 5286-call replay.

## Measured order

| Stage | Native64 | WoW64 x86 |
|---|---|---|
| Nonzero length | Require four-byte input alignment, then validate the complete upper user span | Require four-byte input alignment; defer upper-address access |
| Length | Require exactly 4 bytes | Require exactly 4 bytes |
| Handle | Require exact self pseudo-handle, otherwise STATUS_INVALID_PARAMETER before input access | Same, including real self handles with any measured rights/tags |
| Input | Read one ULONG; reached guards return STATUS_GUARD_PAGE_VIOLATION and are consumed | Consume a reached read guard, retry, and retain the actual input value |
| Policy/result | STATUS_INVALID_PARAMETER after the reached read | Bits outside 0x7F give STATUS_INVALID_PARAMETER; otherwise permanent policy gives STATUS_ACCESS_DENIED |

The input is read-only: neither path publishes caller data or changes policy.
Read-only pages are readable inputs. A guarded read-only page is consumed on
both paths; native64 returns its warning while WoW64 continues with the actual
word. Values 0x80 and 0xFFFFFFFF on guarded x86 input still produce invalid parameter,
which distinguishes a retried read from substituting zero after the guard.
Wrong lengths do not touch data pages. Alignment and native64 upper-span checks
still precede that size rejection. Non-pseudo handles never visit the input.

The existing guest policy reports `0x0D`: DISABLE | DISABLE_THUNK_EMULATION |
PERMANENT. The new adapter returns the measured rejection and preserves both
that query result and effective execute permissions. It does not return success
for an unimplemented transition. A mutable or default no-NX profile still needs
an actual policy owner coordinated with execute permissions and handler policy;
this remains a high-impact prerequisite for the full process objective.

Reached-page metadata lookup costs O(log r) for r mapping runs, with fixed-size
four-byte input and O(1) auxiliary storage. No caller-sized allocation or host
process query occurs. The replay checks native statuses, all 16 input bytes,
guard protection, unchanged queried policy, non-executable RW mappings, return
PC, stack restoration and frame cleanup. Native installed-leaf coverage checks
the actual four-slot setter and its RET16, separate from the synthetic dispatcher.

## Provenance and limits

The public [SetProcessDEPPolicy](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy)
contract describes the Win32 flags and 32-bit API limitation; it does not specify
private class34 validation/copy order or promise the same error code.
[GetProcessDEPPolicy](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessdeppolicy)
likewise describes the Win32 flags, not the raw private options. Both were
accessed 2026-10-27. Private MEM_EXECUTE_OPTION definitions and the 0x7F valid mask
come from [PHNT ntmmapi.h revision 53fbbdc5](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntmmapi.h).
The complete original header is retained byte-for-byte as base64, with its
independent Git blob identity and SHA-256 in `references/ntmmapi-source.json`.
Native results, rather than those declarations, establish the copy order.

These ARM64-kernel observations do not qualify every Windows build, an actual
native32 kernel, or a physical AMD64 kernel. Linux/macOS run the same portable
guest adapter and frozen replay; those runs are not native Windows oracle data.
The three architectures retain the existing permanent guest policy. No exported
service, public C ABI, ISA, SMIR, JIT, persisted format, package layout, dependency
pin or default feature changes. Five pre-existing tracked edits and the separate
native-entry draft remain outside this changeset; combined-tree validation is
identified separately from clean published source or installed Assist proof.

## Validation

| Host | Process-query filter | Complete C API | Native capture verifier |
|---|---:|---:|---|
| macOS ARM64 | 29 passed | 191 passed | Passed |
| Linux x86-64 configuration under ARM64-hosted Docker | 29 passed | 191 passed | Passed |
| Native Windows ARM64 with actual ARM64/x86 NTDLL leaves | 35 passed | 191 passed | Passed |

These selected gates have zero failures and ignored cases. The unchanged original
hardware-fault fixture separately passes 1 test, zero failures/ignored: both ARM64
and x86 perform the actual access violation, RTL handler/context continuation and
exit0. Its original source, three binary fixtures, assertions and 60 s/16384-slice/
4096-instruction limits are unchanged. This is combined-tree validation with the
pre-existing native-entry draft; that draft remains outside this changeset.
It does not establish a clean published native-entry implementation, full native
AMD64 qualification, shipping plugin/package/installed Assist behavior, mutable
DEP, or the complete Linux/macOS/Windows host-library-backed process objective.
