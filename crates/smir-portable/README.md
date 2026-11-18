# Portable SMIR production subsystem

This standalone Rust crate decodes and statically verifies portable SMIR objects,
lowers verified objects to a typed IR, and interprets the scalar subset. It is
under development and is not yet integrated with the RAX engine. Its own
workspace avoids changes to the parent Cargo workspace and existing lifted-ISA
paths.

## Interpreter

`ir::Module::load` runs every semantic check of the static verifier described
below and then lowers the object once into typed functions, blocks and
operations. It does not apply the verifier's two audited-profile gates, which
refuse valid objects whose ABI or metadata shape has not been individually
audited for the static proof (a `weak`, `hidden` or `local` function symbol, for
example). The engine's coverage boundary is the lowering itself. `interp::run` executes
one function of a loaded module, and `interp::run_program` its `main`. What executes today:

- integers of 1 to 128 bits: arithmetic with `nsw`/`nuw`/`exact`, shifts,
  rotates, bit counts, `abs`, byte and bit reversal, comparisons, `trunc`,
  `zext`, `sext`, `select`, `copy`, `freeze` and constants, with poison and
  undef;
- binary32, binary64 and binary128 floats in the default environment (round
  to nearest with ties to even, no observable exception): arithmetic,
  remainder, fused multiply-add, square root, negation, absolute value,
  `copysign`, the six minimum and maximum operations, every comparison
  predicate, conversions to and from integers (plain and saturating) and
  between the two formats, and `bitcast` to and from an integer of the same
  width. A float value is its bit pattern, so it is passed to and reported
  by `smir-run` like an integer. Results are those of correctly rounded IEEE
  754 arithmetic; a NaN result is the first NaN operand made quiet, or the
  positive quiet NaN with no payload when no operand is a NaN. binary32 and
  binary64 use the host's arithmetic, except for fused multiply-add.
  binary128 is computed exactly in
  software, with integers as long as the result needs, and rounded once;
  the same code run in the two narrower formats is tested against the
  host. Fused multiply-add is that software in every format: where a
  processor has no instruction for it, the host's is its C library's
  function, and musl's, for one, answers +0 where a product that underflows
  to zero is negative and zero is added to it;
- `return`, `jump`, `cbranch`, `switch`, `trap` and `unreachable`, with phis
  committed simultaneously;
- direct calls, and indirect calls through a code pointer. A code pointer
  comes from `address_of` on a function symbol (directly, or as a code
  address passed through `code_bind`); it can be stored, loaded, copied,
  compared for equality and retyped with `bitcast`, and an indirect call
  checks that it still designates a function and that the function has the
  call's signature;
- memory: stack objects from the `stack_alloc` helper, `lifetime_start` and
  `lifetime_end`, plain loads and stores of integers and data pointers,
  `memcpy`, `memmove` and `memset`, `ptr_offset` with its `inbounds`, `nuw`
  and `nusw` flags, `ptrtoint`, `ptrtoaddr` and `inttoptr`, for data
  pointers and for code pointers: `ptrtoint` of a code pointer exposes its
  function, and `inttoptr` to a code pointer designates the function whose
  exposed token the integer is;
- atomic memory operations: ordered loads and stores, read-modify-write
  with the integer actions and exchange, compare-and-exchange (which
  compares bits, with poison and undef bits read as zero) and fences. A
  volatile access is performed like any other. Guest memory can be used by
  several host threads at once: an object is found without a lock, and each
  has a reader-writer lock of its own, held for one operation, so threads
  that read the same object or work on different ones do not wait for each
  other, an atomic update is one step for every thread, and a racing
  program can corrupt only its own data;
- data: each data segment becomes one object before the program starts, with
  its initial bits and per-bit poison and undef shadow; `data_address`,
  `data_integer`, `function_token` and `function_integer` relocations are
  applied, the last of which makes its function reachable from integers
  as `data_integer` does its object; read-only
  segments reject writes;
  `address_of` yields the address of a data symbol. Every access is checked against the object its
  pointer came from: provenance, liveness, bounds, alignment and byte
  lifetime. Each byte tracks poison and undef per bit, and a pointer keeps
  its origin through memory when it is stored and loaded whole. Reading the
  bytes of a stored pointer as an integer exposes the object or function it
  designates, as `ptrtoint` does, and an address loaded as a pointer
  designates an exposed object that contains it, as `inttoptr` would; code
  that copies or transforms pointers byte by byte therefore works, and an
  address that was never exposed still names nothing;
- initializers and finalizers: the module's initializers run before the
  entry function, by ascending priority and then ordinal, and its finalizers
  in the reverse order after the entry returns or the program makes a clean
  exit. They run before every entry, in function mode too, and their steps
  count against the same limit;
- runtime services: `file.read`, `file.write`, `file.open`, `file.close`,
  `file.seek`, `file.unlink`, `file.rename`, `process.exit`, `process.abort`
  and `clock.now`, performed against an `interp::Host`. The interpreter
  validates the arguments and guards every guest buffer; the host only sees
  byte slices and strings it owns. A module runs only if the host grants
  every capability it declares. `interp::StandardStreams` is a host with the
  three standard streams (handles 0, 1 and 2) and the host's clocks, and no
  files; `interp::Directory` adds to another host the files under one
  directory, which is all of the file system the program then sees;
- threads: `thread.spawn`, `thread.join`, `thread.detach`, `thread.yield`,
  `thread.id`, `thread.exit` and `thread.concurrency`, which says how many
  threads run at one time (`Policy::processors`, or what the machine has),
  and waiting on a 32-bit word of memory with
  `sync.wait32` and `sync.wake32`. Every guest thread runs on a host thread
  of its own, so a program's threads run in parallel. The program ends when
  its first thread returns from the entry function, when any thread ends it
  or faults, or when every thread waits, without a deadline, for another
  (`Exit::Deadlock`); the other threads then stop at their next step. The
  step limit covers all threads together. A program that starts no thread
  runs the same way every time; one that does can end differently from run
  to run, as its interleaving decides;
- mapped memory: `memory.map`, `memory.unmap` and `memory.protect`. A
  mapping is a new object of defined zero bytes that permits reading,
  writing, both or neither, counts against the memory limit, and is
  unmapped or protected whole;
- thread-local storage: a call of the `tls_address_raw` helper yields the
  address of the calling thread's copy of the segment the import names. A
  thread gets its copy, a new object that starts as the segment's image,
  when it first asks for it, and the copy ends with the thread.

A valid module that uses anything else (aggregate memory
access, thread-local storage that functions initialize or destroy or that
holds relocations, constant initializer functions, relocations
with a derivation, constrained floating-point environments, the floating-point
environment operations, the 16-bit float formats, imports other than
those helpers and services, exceptions, dependencies) is refused as a whole with error
class `unimplemented` before any of it runs. Undefined behaviour and traps end a run
with a fault that names the function, block and operation. Every fault code is
listed, with its class and meaning, in `interp::faults::FAULTS`, which is
published as `docs/specifications/smir/portable/faults-v1.json`.

```sh
cargo build --offline --locked --manifest-path crates/smir-portable/Cargo.toml
crates/smir-portable/target/debug/smir-run \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/call42.smo \
  --entry-function 1 --argument-bits 2a000000
```

prints `{"status":"return","steps":7,"values":[{"bits_le":"2a000000"}],...}`.
Arguments are little-endian hex of exactly the parameter's byte size. Exit
status is 0 when the program ran, whatever its outcome, 1 when the object or
request was rejected, and 2 for a usage error.

`smir-run OBJECT --batch` loads the object once, reads a JSON array of
`{"function": ID, "arguments": [HEX, ...]}` from stdin and prints an array of
reports in the same order.

`smir-run OBJECT --program [-- ARGUMENT...]` runs the program: the exported
function `_start`, which the compiler generates and which is
`int(int, char **, char **)`, or else the exported `main`, which is
`int(void)` or `int(int, char **)`. The object's path and the arguments are
its argument vector, and its environment is empty. The program reads this process's
standard input and writes its standard output and error. With
`--directory DIR` it has the files under DIR as well, and no others: DIR is
the root of every path it uses. `--processors N` is how many threads it is
told run at one time, in place of what this machine runs. The exit status is
the low eight bits of what `main` returned or of the status the program
exited with. If the program did not end that way, one line of JSON on
standard error says how it ended, and the status is 134 for an abort and 125
for a fault, an exhausted limit, a deadlock or an object that cannot be run. The other
two modes grant no capability, so they reject an object that imports
services.

The interpreter is compared with the Python reference machine report for
report (status, result values, step count, and the code and location of every
fault):

```sh
cargo test --offline --locked --manifest-path crates/smir-portable/Cargo.toml --test interp
```

## Processes that last

`interp::run_on` makes a process for one call and ends it with the call.
`interp::Instance` is a process that stays, as a library needs it:
`Instance::start` creates the module's data and runs its initializers,
`call` runs a function on what the earlier calls left, and `finish` runs
the finalizers and stops the program's threads. The process lives on a host
thread of its own, its first guest thread, which runs the calls one after
another; a thread a call started goes on running after the call. A call
that faults or ends the program ends the instance: every later call is
told how the program ended. `tests/interp/instances.rs` checks this on both
engines.

## Modules that are linked

A module may call functions of other modules: its manifest names each as a
dependency, by key and version range, and declares the functions it calls
there. Such a module is a valid object and not yet a program
(`Module::needs_linking`); `Module::link` makes one program of it and the
modules that answer its dependencies, which then runs like any other.

```sh
smir-run main.smo --library shapes.smo --library base.smo --entry-function 300 --argument-bits 05000000
```

The first module is the program, and the others may come in any order. A
module that several depend on is there once. A dependency that no module
answers, or two do, a function that is missing or of another type, modules
in a circle and modules nobody needs are each refused with a `LINK_` code.
Chapter 06 of the specification, "Linking as implemented", says what is
linked and what is not yet; `tests/interp/linking.rs` checks it on
`tests/interp/programs/linked-*.smo`, which `build_linked.py` there authors.

## Carriers

An object may come inside a native file: an ELF, Mach-O or PE file with a
locator that says where in the file the object is and what its SHA-256 is
(chapter 10 of the specification). `carrier::find` finds it, with every
check the specification asks for and without mapping or running any of the
file; `smir-run` accepts such a file wherever it accepts an object.

```sh
smir-pack program.smo --carrier elf --machine aarch64 -o program.elf
smir-run program.elf --program
smir-pack --show program.elf
smir-pack --extract program.elf -o program.smo
```

`smir-pack` wraps an object, after verifying it, in a file that has the
headers discovery needs and no code. It is a way to hand an object to a
runtime in the dress of a native file, not yet a program the system can
start: no native bootstrap is written.

## Native code

`interp::Code::compile` compiles a module to code for the host, AArch64 or
x86-64, and a run takes an `interp::Engine`: the interpreter, or that code.
`smir-run --native` runs an object as native code in any of its modes.

A run ends the same on either engine: the same values or the same fault at
the same place, after the same number of steps, with the same effects in
between. Native code runs on the interpreter's own state (the same
activation records, the same guarded memory, the same step count). The
order of operations, the block a terminator chooses and the function a call
enters are instructions, and so are constants, copies, phis, selections and
integer arithmetic, comparisons and conversions on defined integers of up
to 64 bits; every other operation, and every unusual case of those, is
performed by the interpreter's code for that operation. The
`interp` tests run every authored case on both engines, under several sets
of limits, and require identical outcomes; the service, thread and mapping
tests run their programs on both as well. The same tests pass for x86-64
when built for that target and run under Rosetta:

```sh
cargo test --offline --locked --manifest-path crates/smir-portable/Cargo.toml \
  --target x86_64-apple-darwin --test interp native::
```

And on Linux, for both architectures, from a machine that is not Linux and
has a container engine:

```sh
sh crates/smir-portable/tests/linux.sh
```

That script has three lanes. In one the crates are built and tested inside
a container, against glibc, for the architecture the engine runs natively,
with the host C interface and its C program. In the other two the tests
are built on this machine for `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`, as programs that need nothing of the system
they run on, and run in a container; the architecture the machine is not is
emulated. The repository is mounted for reading only. The tests that run
the repository's Python tools are left out where the container's Python is
older than 3.11; the script's comment says how to choose the images.

The tests need Python 3. It runs about 23,000 cases over the programs authored in
`tests/interp/programs/build.py`, and every function of the existing
conformance objects that both engines accept. The reference machine performs
no services, so `tests/interp/services.rs` checks those on a second authored
object, `programs/build_services.py`, against a host that records what the
programs write, and `tests/interp/files.rs` the file services on another,
against directories it makes for the purpose. The same builder authors a third object whose initializers
and finalizers each write a letter, which shows the order they ran in. The reference machine executes
about five thousand steps a second, so the test takes a minute or two. To
change the programs, edit `build.py`, run it, and reassemble:

```sh
python3 -B crates/smir-portable/tests/interp/programs/build.py
python3 -B tools/smir-format/smir.py assemble \
  crates/smir-portable/tests/interp/programs/programs.json \
  --output crates/smir-portable/tests/interp/programs/programs.smo
```

## Static verification

The independent compiler-contract references have separate, versioned receipts;
earlier candidate qualification is historical during the ABI revision 2 migration.

The current public representation APIs are `decode_object` and `canonical_bytes`.
They check candidate0.2/profile2 framing, all ten ordered payload roots, revision,
aggregate limits and exact content identity. `ParsedObject` is unverified syntax;
it provides no executable admission or guest execution method.

Build from the repository root with locally available pinned dependencies:

```sh
CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/INTEGRATOR/portable-cargo-target \
  cargo build --offline --locked --manifest-path crates/smir-portable/Cargo.toml \
  --bin smir-inspect
```

Inspect canonical encoding:

```sh
/tmp/rax-portable-smir-01/INTEGRATOR/portable-cargo-target/debug/smir-inspect \
  roundtrip example.smo
```

The result is one JSON object with `status:"decoded-object"`, content identity,
`executable_admitted:false` and canonical bytes. Optional metadata bytes survive
the roundtrip. Exit0 is inspection success; exit1 is a rejected object/resource
request; exit2 is an invocation or IO failure. No instruction executes.

`verify PATH` calls the actual type, ABI, metadata, program and cross-root static
verification phases. Successful inputs must satisfy both the semantic predicates
and explicit, finite ABI/metadata coverage predicates. The source-function profile
uses portable signed `int32(int32)`, with separately checked optional pointer,
canonical C23 variadic/jump-state, storage, service and internal-helper forms.
These extensions do not admit arbitrary records, imports, C++ metadata or data/TLS
symbols merely because their sizes match. The exact current restrictions are in
`src/abi/audit_profile.rs` and `src/metadata/audit_profile.rs`. Names and IDs are
checked through actual references. Every present record is checked, including
unused records. Valid forms outside the audited coverage reject as unavailable
evidence; full production P2 qualification remains incomplete.

A successful result has `status:"verified-object"`, `executable_admitted:false`
and seven lossless owner-root inspection entries. Its private `VerifiedObject`
retains all ten source roots and every phase's checked facts and requirements.
Inspection JSON cannot construct a proof. Providers, capabilities, native
evidence and runtime lifetimes require a later process-bound admission stage.

The draft compiler contracts and independent oracles are under
`../../docs/specifications/smir/portable/`. Current compiler qualification is
computed by `../../tools/smir-format/check_spec.py`; observed counterexamples
reopen that gate. Production implementation and host qualification are separate.
No foreign C++ engine or six-host qualification is supplied by compiling this
crate.

Focused core tests use the same production files:

```sh
CARGO_TARGET_DIR=/tmp/rax-portable-smir-01/INTEGRATOR/portable-cargo-target \
  cargo test --offline --locked --manifest-path crates/smir-portable/Cargo.toml \
  --lib core_tests::
```

The independent Python generator in `tests/integration/` records exact wire
fixtures and node counts. It is a test oracle only; production Rust does not
invoke Python. The separately owned differential suite compares real Rust output
against unchanged Python/C++ references and contract-derived semantic negatives.
