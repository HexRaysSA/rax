# rax-smir-portable-capi: the runtime for programs in C and C++

The host C interface of the portable SMIR runtime (chapter 10 of the
specification, "Exact host C ABI declarations"), as a static library and as
a shared one, and the launchers that make an executable of a portable
program: one for an executable that carries the runtime, one for an
executable that finds the runtime installed.

```sh
cargo build --offline --locked --manifest-path crates/smir-portable-capi/Cargo.toml
cc host.c -I crates/smir-portable-capi/include -I tools/smir-runtime-contract/include \
   crates/smir-portable-capi/target/debug/librax_smir_portable_capi.a -lSystem -lc -lm
```

The declarations are those of `tools/smir-runtime-contract/include/
rax_portable_contract_v1.h`, unchanged; `include/rax_portable_extensions_v1.h`
adds what that header has no word for.

## What is implemented

A process is used in one of two ways: as an image, whose program runs from
its entry to its end, once; or as a library, whose exported functions are
called any number of times, each call on what the earlier ones left.

| Function | What it does here |
|---|---|
| `context_create` | Copies the configuration: the capabilities granted (names in ascending order, none twice), the memory a process may hold (0 for 16 MiB), how many threads a program is told run at once (`workers`, 0 for what the machine has), and the profile, which is empty or `interpreter`, or `native` for code compiled for this host. A size or version that is not the structure's is refused before anything else is read. Host imports are refused with `ENOTSUP`. |
| `module_verify` | Copies the bytes, which are an object or a native file that carries one, verifies and lowers the module, and compiles it if the context's profile is `native`. `ENOEXEC` for what is no module this runtime runs. Nothing of it runs. A module that calls functions of other modules is verified like any other and is not compiled: it is a program only once linked. |
| `process_create` | Takes a canonical `runtime_spawn_spec` record for the program's arguments, or no bytes for one argument, `program`. The record names its module by identity or by 32 zero bytes, and may ask for no environment, no working directory and no handles beyond the standard streams. `ENOEXEC` for a module that calls functions of others and is not linked with them. |
| `process_run` | Starts the program at its entry, on a thread of its own, once; a second start, or one of a process that was called as a library, is `EBUSY`. |
| `symbol` | The function a module exports under a name. The namespace is not compared. What comes back is of the module; any process of the module can be asked to run it. |
| `value_bits` | A value of one of the module's integer or float types, from its bits: as many bytes as the type has, least significant first, and no bit beyond its width. |
| `start` | Calls a function with values for its parameters, on a thread of its own. The first call of a process makes it a library and runs the module's initializers. The values must be in number and width what the function takes; a function that takes or returns anything but integers and floats is `ENOTSUP`. The calls of one process run one after another, on its first thread: a call does not get a guest thread of its own, as the specification has it. |
| `poll` | Of an image's run: `pending`, or `exited` or `failed` with a record. Of a call: `pending`; `returned` with what the function returned; or `exited` or `failed` with a record, if the call ended the program, after which every call says the same. It never waits. Each observation of an end owns a handle to what it came with. |
| `result_count`, `result_at`, `value_read_bits` | What a call returned: how many values, each as a value of its own, and a value's bits. Bits the program left unspecified read as zero. |
| `process_join` | Waits for an image that was started. Finishes a library: its finalizers run, unless a call ended the program, and its threads stop; `EBUSY` while a call is running. |
| `record_read` | One line of ASCII JSON: `version`, `reason` (`normal`, `abort`, `trap`, `failed`), `code`, `thread`, `trap`. A capacity of zero asks for the size; too small a one is `ERANGE`. |
| `cancel` | A program that has started is not stopped: it reports 0. |
| `retain`, `release` | A handle is three numbers: this runtime, a slot of its table, and which use of the slot. Released by its last owner it names nothing, and no other handle will be those three numbers again. What it named lasts as long as something needs it: a running process keeps its module. |
| `rax_portable_x1_context_files` | An extension: gives the processes a context makes from then on the files under one directory of the machine. |
| `rax_portable_x1_module_link` | An extension: links verified modules of a context into one program, which is a module like any other. The first is the program, whose exported functions and types the linked module has; the others are the modules it and they depend on, in any order. `ENOEXEC` if they do not link (chapter 06, "Linking as implemented"), `EBADF` for a handle that is no module of the context. The contract's own `runtime_deployment` record is not read: no function of the contract takes one. |
| `rax_portable_x1_runtime` | An extension: the runtime as it describes itself, for a launcher that found it installed. The version of this interface (major 1, the contract's; minor 1, which is the contract's functions and these extensions), the implementation's revision, the executable profile (2), the implementation's identity, and the identities of its catalogs of helpers and of services. The identity is the SHA-256 of what the runtime was built of (its version, revision, machine and catalogs), which two builds of one version for one machine share: it names what was built, not the file. |

The other five functions return `ENOSYS`: `value_aggregate` and
`value_pointer`, since values are scalars so far, and `call_result_bits`,
`call_return` and `host_complete`, which answer host imports, of which a
context accepts none.

A process's standard streams are the host program's. No function unwinds
into its caller; a panic inside one is `EIO`.

## The launchers

`launcher/launcher.c` is the `main` of an executable that carries its
runtime and its program, and `launcher/launch.c` what it does. It reads its
own file, hands it to `module_verify`,
which finds the program in it as in any carrier, and runs it with this
process's arguments and streams, the files under the directory it was
started in, and every capability. The program runs as native code where the
runtime compiles any. It ends as the program ends: with its status, by
aborting, or, if the program faults, with a line of JSON on standard error
and status 125. `tools/smir-clang/smirpack.py` links such an executable.

A program that is linked with other modules when it is loaded has them in
the executable too, each as it is in a section beside the program's
(`__SMIR,__needs0`, `__needs1`, and so on; Mach-O only so far). The launcher
verifies each and links them with `rax_portable_x1_module_link` before it
makes the process.

`launcher/bootstrap.c` is the `main` of an executable that carries its
program and not its runtime (`smirpack.py --installed`): some tens of
kilobytes and the program. It loads the runtime's shared library,
`librax_smir_portable_capi.dylib` or `.so`, and does the same with it. The
runtime is looked for in three places, and the first that is configured is
the one: if the runtime is not there, cannot be loaded or will not do, the
program is not run and nothing further is tried.

1. The absolute path the executable was built with, if any.
2. `../lib/rax/` and the library's name, from the directory the executable
   is in, if there is such a file. A program in `PREFIX/bin` runs with the
   runtime in `PREFIX/lib/rax`.
3. The path in the first line of the installation record, if there is that
   file: `/Library/Application Support/RAX/portable-runtime` on macOS,
   `/etc/rax/portable-runtime` elsewhere.

The working directory, the environment and the system's library search are
not consulted. The path is resolved to the file it names, that file is
loaded, and what was loaded is what is asked and what runs the program. It
must have the major version of the interface the executable was built
against, the same minor version or a later one, the profile, and, if the
executable was built to ask for them, at least a revision and exactly an
implementation identity. The catalogs are compared when the program is
verified, each import quoting the one it is from. Installing a runtime is
putting the shared library in one of those places. This is written for
systems with `dlopen`; on Windows the bootstrap says that it finds none.

## Tests

```sh
cargo test --offline --locked --manifest-path crates/smir-portable-capi/Cargo.toml
```

`tests/host.rs` calls the functions as a C program does: images, libraries
called again and again on both engines, modules linked into one program,
and every refusal. It also compiles
`tests/consumer.c` against the static library and runs it: a C program that
has a module verified, runs it and reads how it ended.
`tools/smir-clang/test_pack.py` tests the launchers: executables that carry
the runtime, and executables that find it, by each of the three places, and
that refuse a runtime that is missing, is no runtime, or has another
version, profile, revision or identity than they were built to ask for.
