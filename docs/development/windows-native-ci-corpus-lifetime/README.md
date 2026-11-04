# Native Windows corpus lifetime across Rust cache setup

The `windows-exception-profile.yml` job initializes its contained temporary
directory and Rust/cache action immediately after checkout, before any native
producer. Captured corpora remain under the same in-tree `target/` paths, and
all native producers, artifact uploads and replay tests remain selected.

The pinned `Swatinem/rust-cache` restore calls `cleanTargetDir` after a partial
key match. Its `cleanProfileTarget` treats custom directories under `target/`
as profile directories and removes entries other than `build`, `.fingerprint`
and `deps`. This removes newly captured `receipt.json` files and mapped-name
observations if cache restore follows capture. The unmodified primary source,
upstream commit, checksums and license are retained in [primary](primary/).

Run [41864274661](https://github.com/HexRaysSA/rax/actions/runs/41864274661),
job `126694293203`, recorded a partial cache restore after its native captures.
Nine replay tests then panicked while reading their fresh corpora with Windows
error 2 (`NotFound`): thread open/resume, prefetch, primary-user hive, extended
key open, key query and mapped-file-name families. Their native producer
artifacts still contained the captured receipts. These failures do not establish
any mismatch between native and emulated API behavior.

The dependency order is:

```text
checkout -> contained temporary directory -> Rust/cache restore
         -> native captures -> artifact uploads -> replay tests
```

`ci_actions_pinned` checks that temporary-directory preparation and the single
Rust/cache setup precede the first native capture. The regression must fail
against the earlier workflow ordering and pass after reordering. The native
Windows workflow also runs the complete tooling test binary before its runtime
replays. The existing Windows Server 2022 and 2025 lanes remain required for
actual fresh-corpus qualification; a tooling test alone cannot qualify native
kernel behavior.

Assumption A1 is confirmed by the pinned restore/cleanup implementation and the
partial-cache CI log: restoring this cache after capture can delete those files.
Moving initialization ahead of capture must preserve all producer and replay
commands. A later cache restore or a missing consumed corpus falsifies that
lifetime requirement. No production interpreter, loader, host adapter, public
C ABI, dependency pin or feature default changes in this correction. Linux and
macOS use the same portable workflow test; this workflow executes only on
Windows. The broader process-emulation goal remains incomplete.

Workflow text is normalized from CRLF to LF at its reading boundary before
applying the existing policy markers and command-selection checks. Policy
assertions remain identical on Windows, macOS and Linux. The complete tooling
binary is checked against both LF and CRLF workflow fixtures; unrelated jobs
remain outside each selected block. Changes to its owning Rust source trigger
the native Windows workflow for both pushes and pull requests.
