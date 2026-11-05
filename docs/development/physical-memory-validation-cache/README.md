# Physical-memory verification caching

Native run `42022280261` completed source-free continuation for one and two
CPUs, then reached its 600 s execution limit during the four-CPU case. Its
[retained evidence](../hvf-native-file-continuation/native-timeout-42022280261.json)
contains 151 ordered passes. The four-CPU checkpoint retains 4,429,185,024 bytes
of backing: 4 GiB of historical padding plus 128 MiB of configured RAM.

A one-second sample of the live local owner test placed 349 of 391 samples
in its active restore path under SHA-256 updates. Complete snapshots repeatedly
validated the same compressed backing during admission and publication. The
change retains all backing and checksum checks while caching successful proofs
against fingerprints of the compressed image.

The physical fingerprint covers the region count and each region's address,
declared size, expected digest, compressed length and compressed bytes. A
projection proof additionally binds the compressed legacy projection and its
declared size. Changing any input prevents reuse. First admission of an imported
image still decompresses it and checks every uncompressed digest and length.
Successful capture can establish the proof directly: the complete encoders and
digests consumed the same captured chunks. Callback failures do not establish
proofs for unvisited bytes. Memory publication continues to decompress and
visit every represented byte; the cache certifies input, not publication.

The caches use two bounded `OnceLock` values. They are absent from the custom
`RAXRAM01` wire representation. Cache state never changes saved file bytes,
topology, error admission, or the amount of memory restored.

Let `N` be total uncompressed backing bytes, `C` its compressed bytes, `P` the
compressed legacy projection bytes and `R` the number of regions:

| Operation | Time | Additional storage |
|---|---|---|
| First imported physical verification | `O(N + C + R)` | 64 KiB scratch and constant cache state |
| Repeated physical verification | `O(C + R)` | Constant |
| Repeated matching projection verification | `O(C + P + R)` | Constant |
| Actual RAM publication | Still visits `N` bytes | Existing bounded scratch |

For incompressible images, `C` approaches `N`; the cache does not make those
checks constant time. Fingerprinting adds work to a first imported validation.
The benefit is largest for compressible backing and repeated admission.

The unchanged [public-API benchmark](benchmark.rs) captures 67,108,864 zero
bytes and calls `verify` four times. Both binaries use the same x86-64 library
profile and run through Rosetta on the same host. Raw command and timing records
are retained in [benchmark-baseline.json](benchmark-baseline.json) and
[benchmark-corrected.json](benchmark-corrected.json).

| Measurement | Before | After |
|---|---|---|
| Median repeated verification | 0.140326250 s | 0.000007125 s |
| Single capture | 0.214523208 s | 0.254901208 s |

These are four development observations with concurrent host work, without a
statistical confidence interval. They establish the observed verification
improvement for this compressible input; they do not establish faster capture,
whole-VM performance, native Intel performance or incompressible-input speed.

New regression cases check changed frames, expected digests, declared lengths,
projection contents and sizes, corruption beyond the projected prefix, exact
wire roundtrips, complete restored bytes and failure before destination writes.
The complete owner target passes 73 cases and the physical-memory integration
target passes 30, both with zero failures, ignored or filtered cases. The
unfiltered library target passes 12,445 cases with zero failures, 36 ignored
and zero filtered. Clippy and full formatting pass. All gates used the same
combined topology/cache engine fingerprint, and the single owned build cache
was removed after its processes exited. [qualification.json](qualification.json)
records these results.

[Native run 42031432817](https://github.com/HexRaysSA/rax/actions/runs/42031432817)
passes all 155 ordered controls on the exact combined topology/cache source.
The [verified artifact](../hvf-native-file-continuation/native-pass-42031432817-archive.json)
confirms actual source-free 1/2/4-CPU file continuation, including new work on
every AP after restore. The four-CPU case that previously reached the timeout
now completes. The complete guest command takes 421.807526 s on that run;
runner/workload variation prevents treating this as a controlled performance
comparison. Negative corruption and partial-callback guarantees remain
established by the focused and complete local suites.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| V1 | A reused proof identifies the same compressed image and declarations | Cached admission | Alter the last frame, digest or size after a successful verification; restore must reject before writing the first region | Local controls confirmed; native155 valid-file continuation confirmed |
| V2 | Capture encoders represent the chunks that supplied their digests | Constructor proof | Complete wire roundtrip, imported verification and byte-exact restore of multiple regions | Local controls confirmed; native155 valid-file continuation confirmed |
| V3 | Partial visits cannot certify unvisited data | Failure handling | Fail the first callback with a bad final-region digest, then require ordinary verification to reject it | Local controls confirmed; native155 valid-file continuation confirmed |

High impact: the wider original backend/private/in-flight, SMP, A32-FP and
HVF requirements remain open.
Medium impact: first-validation overhead and limited benefit for incompressible
images require separate performance characterization. No additional uncompressed
RAM copy, dependency, host-kernel change or build worktree is introduced.
