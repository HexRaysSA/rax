# Translation-cache ALPC startup

This model supplies the installed Windows ARM64 translation-cache startup
connection to `\{BEC19D6F-D7B2-41A8-860C-8787BB964F2D}`. The qualified native
profile is Windows 10.0.29704.0. Native ARM64 and translated AMD64/x86 callers
were measured on that ARM64 kernel. These observations do not qualify a physical
AMD64 Windows kernel. The earlier 29698 capture established the initial request;
its unmeasured section/lifetime details do not enable that older profile.

Runtime selection reads captured namespace presence, query-only SCM status and
the fixed `NT SERVICE\XtaCache` account SID. Guest PEB version edits cannot select
a different kernel profile. Guest execution never connects to a native ALPC
service: it uses an owned endpoint, private server VM and anonymous shared
backing. Unknown service/profile/protocol options report unsupported behavior.

The transfer creates distinct port and Section handles. Port access is
`0x001F0001`; the Section grants map-read/write access `0x6`, without section-query
access. Each connection receives a distinct, initially zero 65,536-byte Section.
Views retain that backing independently after the port and Section handles close.
The model bounds concurrent peer allocations to 32; this is an emulator resource
bound, not an observed native server limit.

The caller handle-attribute ABI is measured through NTDLL's own helpers:

| Caller | Complete attributes | Handle payload | Handle offset |
|---|---:|---:|---:|
| ARM64 / AMD64 | 32 bytes | 24 bytes | 16 bytes |
| x86 | 24 bytes | 16 bytes | 12 bytes |

Native64 overwrites the four padding bytes after payload `Flags` with zero.
This caller ABI differs from the private/internal ALPC handle layout in the
retained PHNT reference; the independent helper size, returned type/access and
working mappings establish the caller representation.

The connection reply remains owned by its endpoint until
`ALPC_MSGFLG_RELEASE_MESSAGE` (`0x10000`) acknowledges it, or the endpoint closes.
Opaque message identities are allocated within the model and are not host kernel
identifiers. A reply from another endpoint cannot consume this endpoint's pending
message. The measured acknowledgement returns success and leaves caller buffers
unchanged. Unmeasured release forms remain explicit unsupported paths.

Direct `NtMapViewOfSection` controls establish initial readonly/readwrite view
protection and allocation protection. Size zero maps all 65,536 bytes; size one
maps 4,096 bytes; 65,535 rounds to 65,536 bytes. Requests for 65,537 or 131,072
bytes fail with `STATUS_INVALID_VIEW_SIZE` (`0xC000001F`) and preserve the requested
size. The Win32 wrapper reports error 5 for those native failures. Mapping,
shared-alias protection and retirement use the portable shared-section backend.

## Evidence and reproduction

`native-controls-v1.json` contains 36 direct mapping records, three normal reply
release records, and 372 private-name/owned-Event connection capture records.
The private records are acquisition evidence; their inclusion is not a claim
that every corresponding guest failure path has been implemented. The producer
sources are retained alongside it and compile with the Windows SDK using
`/std:c11 /W4 /WX /MT`, linking `kernel32.lib`, `advapi32.lib` and `ntdll.lib`.
Compile and execute separate ARM64, AMD64 and x86 binaries. Native receipts bind
source/executable identities and the six installed NTDLL/Kernel32/KernelBase file
hashes before and after execution. A producer exit code zero alone does not prove
that an individual native API succeeded; inspect each recorded NTSTATUS.

The fixed cache controls use only their returned handles and do not write mapped
service memory. The private capture matrix addresses unique missing names or its
own named Event, so no malformed request is sent to the system-service endpoint.

Primary ABI references are the retained
[PHNT LPC declarations](../native-csr-connect-model/references/phnt-ntlpcapi.h),
[PHNT section declarations](../native-section-open/references/phnt-ntmmapi.h), and
Microsoft's [SCM status contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex).
Native measurements own private caller-layout, copyback and service semantics.
