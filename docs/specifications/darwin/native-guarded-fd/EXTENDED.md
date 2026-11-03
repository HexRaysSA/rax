# Extended native guarded-descriptor controls

The v3-v9 acquisitions contain 1,240 additional cases: 620 ARM64 cases and
620 x86-64 cases executed through Rosetta on the same ARM64 Mac. The earlier
v1-v2 acquisition contains 292 cases. These are native observations, not a
statement that the emulator passes all cases or that physical Intel hardware
was tested.

The recorded host is Darwin 27.2.0, kernel
`xnu-13432.41.4~3/RELEASE_ARM64_T6041`. Each campaign preserves source hashes,
argument vectors, executable hashes, and record hashes. The v3 edge receipt
records its producer hash; its argument vectors and durations are in the case
records. Later receipts also record included source inputs and compiler/SDK
paths. The checked-in Apple reference sources are older than this measured
kernel; the acquisitions establish the observations below.

| Campaign | Version | Cases per ABI | Observed surface |
|---|---|---:|---|
| `edge` | v3 | 296 | Cookie, descriptor, scalar-length and vector-copy error ordering |
| `fdinfo` | v4 | 32 | Guarded file and kqueue `proc_fileinfo` |
| `spawn` | v5 | 32 | Duplication, self-duplication, inheritance and close file actions |
| `inherit` | v6 | 8 | Fork inheritance and removal of inherited guards |
| `devfd` | v7 | 198 | Access modes, descriptor flags and shared open descriptions |
| `devfd-directory` | v8 | 6 | Directory descriptors accessed through fdescfs |
| `devfd-alias` | v9 | 48 | Direct, relative and symlinked fdescfs paths |

Material observations:

- Guard cookies are copied before guarded-write validation. Vector descriptors
  are copied before descriptor lookup; total-length validation follows the
  descriptor/access/ordinary-write guard checks in the measured cases.
- `proc_fileinfo` reports guarded status and the low four guard-attribute bits;
  `GUARD_WRITE` is excluded from `fi_guardflags`.
- A forked child's inherited descriptor loses its fileproc guard and retains
  its close-on-exec flag. A descriptor still marked close-on-fork is absent.
  This falsified the initial implementation assumption that fork preserves the
  parent descriptor's guard. The parent's guard remains present.
- The SETEXEC descriptor copy excludes close-on-exec descriptors before the
  measured spawn file actions. These actions return `EBADF` for the guarded
  descriptors even after close-on-fork was cleared.
- An ordinary fdescfs open refuses guarded duplication with `EPERM` without a
  fatal guard exception. `O_CREAT | O_EXCL` reports `EEXIST`, and `O_DIRECTORY`
  reports `ENOTDIR`, including when the source descriptor names a directory.
- A successful fdescfs duplication preserves the original descriptor flags,
  adds requested close flags, shares its offset, and does not truncate the file.
- `O_NOFOLLOW_ANY` refuses a symlinked parent directory with `ELOOP` before
  guarded-descriptor lookup. On a final symlink, `O_SYMLINK` opens the link
  itself, including with `O_NOFOLLOW_ANY`; the guarded target is not duplicated.

Verify preserved inputs and records on Python 3.9 or newer:

```text
python3 docs/specifications/darwin/native-guarded-fd/verify-extended-v3.py
```

Rebuild and rerun a native campaign on macOS in a fresh in-tree output
directory:

```text
python3 docs/specifications/darwin/native-guarded-fd/capture-extended-v3.py --output target/guarded-fd-recapture-v3 --campaign devfd-alias
```

Omit `--campaign` to run all seven campaigns for both ABIs. The runner
reconstructs the preserved argument vectors with fresh task-owned paths and
records current compiler/SDK versions. The original acquisitions predate this
portable runner. Fresh receipts and records remain in its output directory;
it never overwrites the frozen observations. Exception packet presence under
Rosetta is preserved separately from comparison of operation results.

The alias campaign was independently reconstructed by this runner: all 96
operation results matched its frozen observations. This establishes the
runner's alias-campaign reconstruction, not replay of every other campaign.

Unresolved native coverage includes data-protection open flags and input-copy
aliasing in `change_fdguard_np`, plus entered guarded-write/close lifetime.
Fileport creation is a separate existing unimplemented service; acquisition of
the fileport guard refusal does not implement successful fileport creation.
