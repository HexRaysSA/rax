# Thread/synchronization primary sources

This directory retains MicrosoftDocs `sdk-api` and `win32` source Markdown
consulted for the Windows thread, wait, event, mutex, semaphore and handle
service group. `sources.json` contains each issuing organization, raw/canonical
URL, retrieval date, license URL, normalization and retained-byte SHA-256.
Revisions of the mutable `docs`/`main` branches are **unknown**. Source front
matter is preserved; trailing blank lines are normalized. `LICENSE` is the
MicrosoftDocs SDK API repository's CC-BY-4.0 license.

`thread-constants.h` is a declaration excerpt from Microsoft's SDK-header
repository, not a complete compilable header or a native runtime oracle. It
retains both `THREAD_ALL_ACCESS` branches and the referenced `MAXCHAR` value.

The architectural admission/rejection contract, assumptions, source conflicts
and validation scope are recorded in
[`windows-threading.md`](../../../../architecture/user-mode/windows-threading.md).
Primary-source text is evidence, not an implemented-feature inventory. In
particular, full ACL/token semantics, native demand stack growth, cross-process
named-object sharing and private namespaces are not implied by retention.
