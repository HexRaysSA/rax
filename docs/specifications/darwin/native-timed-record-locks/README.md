# Native Darwin timed advisory record locks

Commands `F_SETLKWTIMEOUT` (10) and `F_OFD_SETLKWTIMEOUT` (93) copy a
40-byte request at entry: a 24-byte Darwin `flock`, followed by two 8-byte
timespec fields. RAX retains the entered file, copied range and one absolute
deadline while sleeping cooperatively. Retries use nonblocking host lock
operations, scheduling each retry for 1 ms later or the earlier timeout. A pending close reserves its descriptor
until the entered operation releases its file reference.

This directory preserves independent native controls from Darwin 27.2.0,
XNU 13432.41.4, on an ARM64 host. ARM64 images execute natively; x86-64 images
execute through Rosetta on that same kernel. Physical Intel execution is
unverified. Native compiler arguments, image hashes and observations are in the
receipts; source and old-record hashes are checked by `verify.py`.

| Evidence | Recorded runs | Checked behavior |
|---|---:|---|
| `timed-lock-probe-v13.c`, old records and `current-native-v1.json` | 144 per ABI | Both commands, lock types, conflict, signed timespec boundaries, invalid pointer/descriptor and confined descriptors |
| `timed-lock-lifetime-probe-v14.c`, old records and `current-native-v1.json` | 8 per ABI | Waiting request mutation, entered close, invalidated descriptor and delayed descriptor reuse |
| `offset-probe-v1.c`, `offset-native-v1.json` | 4 per ABI | `SEEK_CUR`/`SEEK_END` resolve before another thread changes offset/file size |
| `range-errors-probe-v1.c`, `range-errors-native-v1.json` | 16 per ABI | Relative signed-offset boundaries: overflow, negative resolved range and valid negative displacement |
| `field-precedence-probe-v1.c`, `field-precedence-native-v1.json` | 18 per ABI | Accepted nonzero `l_pid`, invalid type/whence, and relative-overflow error ordering |
| `linux-pid-native-v1.json` | 2 | Linux rejects nonzero `l_pid` for its OFD-setting command; the timed adapter normalizes it to zero |

The Rust tests replay 136 unconfined matrix cases per guest ABI, all 16 lifetime
observations, all eight offset observations, all 32 range-boundary observations
and all 36 PID/precedence observations. The eight confined matrix cases
per ABI remain native evidence only: `F_FDCONFINED` (95) is outside this change.
Additional Rust regressions cover an unchanged absolute deadline across spurious
wakes and interruption of retained operations under the existing signal policy.
Those regressions do not claim a new independent native signal oracle.
The 144 matrix observations per ABI contain 142 distinct inputs: each command's
unconfined, uncontended `{0, 0}` write-lock input occurs twice.

The measured timespec behavior uses unsigned arithmetic:
`duration_ns = (seconds * 1_000_000_000 + nanoseconds) mod 2^64`.
Exactly `{0, 0}` waits without a deadline. For example, `{-1, 1_000_000_000}`
wraps to 0 ns and expires when the lock needs to wait; an immediately available
lock still succeeds. The request bytes remain unchanged. Timing samples are
observations, not bounds on scheduler latency.

Run the portable evidence check from the repository root:

```text
python3 docs/specifications/darwin/native-timed-record-locks/verify.py
```

It reports 288 native matrix, 16 lifetime, eight offset, 32 range and 36 field
observations, plus two Linux adapter controls, and separately
reports 272 model matrix cases. It parses and validates retained evidence;
it does not execute native programs or establish runtime qualification.
Its time and memory use are O(total receipt bytes).

Run the owning Rust tests with the repository's pinned toolchain and an in-tree
temporary/output directory:

```sh
mkdir -p target/timed-lock-validation/tmp
TMPDIR="$PWD/target/timed-lock-validation/tmp" \
TMP="$PWD/target/timed-lock-validation/tmp" \
TEMP="$PWD/target/timed-lock-validation/tmp" \
CARGO_TARGET_DIR="$PWD/target/timed-lock-validation" \
cargo +1.95.0 test --locked --offline --no-default-features \
  -p rax --lib --features x86_64-suite timed_lock_ -- --test-threads=1
```

The native descriptor adapter executes on macOS and Linux. Linux maps the OFD
operation to its native command and Darwin lock/errno values at the existing
adapter boundary. Windows retains the existing unavailable native-Darwin-host
capability; this change does not add a Windows host descriptor adapter or change
the portable closed Darwin profile. The Windows workspace is compile-checked.
Untimed blocking commands 9 and 91 are unchanged and remain separate scheduler
work.

All seven timed-lock tests pass on macOS and Linux. The broader Linux FIFO
lifecycle group has eight pre-existing failures: the same eight fail in the
retained executable built before this timed-lock change. Its two other cases,
the pipe-drain case and seven continuation cases pass. This corpus does not
establish general FIFO parity, and the full process-emulation goal remains open.

Material assumptions and falsification probes:

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| D1 | Retained native witnesses still match this kernel; all 304 freshly repeated matrix/lifetime observations agree | Command admission, input copying and close lifetime | A fresh status, width, mutation or close-order observation differs | Confirmed for recorded kernel and ABIs |
| D2 | Relative lock ranges are resolved at entry; eight independent waiting controls retain the old range | Copied `SEEK_CUR`/`SEEK_END` range | Change offset/EOF while parked; observe a lock on the changed range | Confirmed for recorded kernel and ABIs |
| D3 | Darwin accepts nonzero `l_pid` on lock-setting commands; Linux OFD setting requires zero | Normalize the host field while retaining guest bytes | Native status differs for PID 1, -1 or 2147483647; Linux rejects the normalized call | Confirmed for recorded controls |
| D4 | Invalid type precedes `SEEK_END` overflow; `SEEK_CUR` overflow precedes type validation | Entry validation order | Combine invalid type and overflowing relative start; compare native errno | Confirmed for recorded controls |

The receipts are finite observations. They do not establish behavior on another
kernel version, every file type, confined descriptors, native Windows Darwin
services or arbitrary lock contention schedules.
