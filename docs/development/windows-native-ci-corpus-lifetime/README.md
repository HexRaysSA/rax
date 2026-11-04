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

The exact warm-cache run
[41897713812](https://github.com/HexRaysSA/rax/actions/runs/41897713812)
restored a complete target-root cache and then failed the first producer's
existing-output guard. Restoring before capture prevents deletion of new data,
but saving/restoring the entire target root can also retain native output
directories. Ownership guards remain required; they are not relaxed or replaced
with deletion.

The native job now isolates Cargo output and its cache workspace together:

```text
target/
|-- native-csr-cargo/       Cargo artifacts; cache restore/save is confined here
|-- native-csr-build-tmp/   contained build temporaries; outside the Cargo cache
`-- native-*/              existing native capture/artifact paths; outside cache
```

The shared Rust action forwards an optional `workspaces` input. Its default is
`.` so other callers preserve their previous cache layout. This native job
sets `CARGO_TARGET_DIR` to the same contained directory named by its explicit
`. -> target/native-csr-cargo` cache mapping. Its path filters also cover the
shared action. Qualification requires native runs on both initial and exact
warm cache states; an initial passing run alone does not establish that boundary.
