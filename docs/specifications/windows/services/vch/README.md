# Windows vectored continue handler primary references

These three Microsoft API pages were consulted for the public
`AddVectoredContinueHandler`/`RemoveVectoredContinueHandler` contract and
the `PVECTORED_EXCEPTION_HANDLER` callback type. They were retrieved on
2026-09-28 from the official MicrosoftDocs `sdk-api` repository at commit
`a4fd3f7efe2e3378a96c6fe5a6a9455eba9fa021`. The raw Markdown pages
are retained byte-for-byte; their front matter includes Microsoft's titles
and `ms.date` fields. The canonical rendered pages and immutable raw URLs
are recorded in [sources.json](sources.json).

Microsoft documentation prose is licensed under Creative Commons Attribution
4.0 International; code samples, if any, are subject to the repository's
separate MIT `LICENSE-CODE`. Both publisher notices are retained here as
[SDK-API-LICENSE](SDK-API-LICENSE) and
[SDK-API-LICENSE-CODE](SDK-API-LICENSE-CODE). Only a terminal LF was added
to each license notice; the source pages were not normalized. The manifest
records local SHA-256 digests and the original license-file digests.

The Add page specifies `ULONG First`, a callback pointer, first/last
registration order, a non-NULL success result, and persistence after unloading
the callback's DLL. The Remove page specifies a handle obtained from Add
and a nonzero/zero success result. The callback page specifies one
`EXCEPTION_POINTERS*` argument and the `EXCEPTION_CONTINUE_EXECUTION` and
`EXCEPTION_CONTINUE_SEARCH` returns. These pages do not specify handle
encoding, registration during an active dispatch, self-removal traversal, or
exhaustion/wrap behavior; those require a native probe or an explicit emulator
policy.

Integrity check from the repository root:

```sh
jq -r '.sources[] | [.sha256, ("docs/specifications/windows/services/vch/" + .path)] | join("  ")' docs/specifications/windows/services/vch/sources.json | shasum -a 256 -c -
```
