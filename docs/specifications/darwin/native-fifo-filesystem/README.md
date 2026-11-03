# Linux FIFO qualification filesystem

An open named FIFO on the recorded OrbStack shared FUSE mount loses usable
metadata after its pathname is removed: native `fstat` returns `EBADF`, and
`fstatfs` returns `ENOENT`. The same descriptor still accepts `F_GETFL` and is
visible through `/proc/self/fd`. This causes the FIFO eligibility/lifetime checks
to miss the descriptor. The exact failing layer within the shared-filesystem
implementation is unknown.

The same native controls and unchanged RAX executables succeed when test scratch
storage uses Linux tmpfs mounted at a resolved path inside the worktree. No
product code, test assertion, platform skip, permission or global default was
changed to resolve the qualification failures.

| Observation | Shared FUSE mount | In-worktree Linux tmpfs |
|---|---|---|
| Linked FIFO metadata | Succeeds | Succeeds |
| Unlinked FIFO `fstat` | `EBADF` (9) | Succeeds, link count 0 |
| Unlinked FIFO `fstatfs` | `ENOENT` (2) | Succeeds |
| Unlinked FIFO `F_GETFL` | Succeeds | Succeeds |
| Baseline FIFO cases | 2 pass, 8 fail | 10 pass, 0 fail |
| Current FIFO cases | 2 pass, 8 fail | 10 pass, 0 fail |
| Current timed/pipe/continuation cases | 15 pass | 15 pass |
| Current owning total | 17 pass, 8 fail | 25 pass, 0 fail |

All reported test groups have zero ignored cases. The paired native observations
cover linked/unlinked FIFOs and both anonymous-pipe endpoints. Filesystem magic
values are `0x65735546` (shared FUSE), `0x01021994` (tmpfs) and `0x50495045`
(anonymous PIPEFS). Anonymous pipe classification was not the cause.

`bindings-v1.json` binds the exact archived producer scripts and result bytes,
the current and baseline ELF hashes, and the container image. The model code is
the published `07f99838` tree. The same current executable hash is used on both
filesystems. The recorded Linux kernel is `7.2.12-orbstack-00394-gbecdd6130068`;
x86-64 executes through translation on an ARM64 Docker daemon. Physical Intel
execution is unverified.

The archived producers preserve their original `/work`, `.task-evidence` and
`target/qualified-v1/tmp` paths. `native-shared-v1.py` and
`native-tmpfs-v1.py` collect independent native metadata; the runtime producers
run the declared, hash-checked RAX test executables. Receipts are historical
observations, not commands that execute when the verifier runs.

Validate the retained evidence from the repository root:

```text
python3 -B docs/specifications/darwin/native-fifo-filesystem/verify.py
```

For a fresh native repeat, mount the worktree as `/work`, create the producer's
task-owned output parent, and use an empty, owned scratch directory. The tmpfs
run used this per-container mount option:

```text
--tmpfs /work/target/qualified-v1/tmp/linux-fifo-entry-native-v3:rw,size=64m,mode=0700,uid=501,gid=20
```

The owning runtime used the same option at
`/work/target/qualified-v1/tmp/linux-fifo-entry-model-v1`, with `TMPDIR`, `TMP`
and `TEMP` set to that path. UID/GID describe this measurement; select the
container caller's actual IDs on another host. The mount remains inside the
worktree and is removed when its container exits. Repeating the runtime also
requires the exact ELF images declared in the bindings or a separately recorded
rebuild and its own result hashes.

Material assumptions:

| ID | Assumption / basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| L1 | The failures are caused by anonymous FIFO classification | Adapter change | Native metadata and classification distinguish the descriptors | Falsified: native metadata fails on the shared mount |
| L2 | The recorded shared-filesystem path invalidates unlinked FIFO metadata | Use native Linux scratch storage for qualification | Repeat linked/unlinked FIFO controls and both model epochs on tmpfs | Confirmed for the recorded environment |

High impact beyond this finite qualification: successful Windows CMD execution,
untimed blocking-lock scheduling and the remaining Darwin pipe/protection
contracts still require their own validation. This result does not complete the
full process-emulation goal.
