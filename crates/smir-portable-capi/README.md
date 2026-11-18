# rax-smir-portable-capi: the runtime for programs in C and C++

The host C interface of the portable SMIR runtime (chapter 10 of the
specification, "Exact host C ABI declarations"), as a static library, and
the launcher that makes an executable of a portable program.

```sh
cargo build --offline --locked --manifest-path crates/smir-portable-capi/Cargo.toml
cc host.c -I crates/smir-portable-capi/include -I tools/smir-runtime-contract/include \
   crates/smir-portable-capi/target/debug/librax_smir_portable_capi.a -lSystem -lc -lm
```

The declarations are those of `tools/smir-runtime-contract/include/
rax_portable_contract_v1.h`, unchanged; `include/rax_portable_extensions_v1.h`
adds what that header has no word for.

## What is implemented

The life of an image:

| Function | What it does here |
|---|---|
| `context_create` | Copies the configuration: the capabilities granted (names in ascending order, none twice), the memory a process may hold (0 for 16 MiB), how many threads a program is told run at once (`workers`, 0 for what the machine has), and the profile, which is empty or `interpreter`, or `native` for code compiled for this host. A size or version that is not the structure's is refused before anything else is read. Host imports are refused with `ENOTSUP`. |
| `module_verify` | Copies the bytes, which are an object or a native file that carries one, verifies and lowers the module, and compiles it if the context's profile is `native`. `ENOEXEC` for what is no module this runtime runs. Nothing of it runs. |
| `process_create` | Takes a canonical `runtime_spawn_spec` record for the program's arguments, or no bytes for one argument, `program`. The record names its module by identity or by 32 zero bytes, and may ask for no environment, no working directory and no handles beyond the standard streams. |
| `process_run` | Starts the program at its entry, on a thread of its own, once; a second start is `EBUSY`. |
| `poll`, `process_join` | `pending`, or `exited` or `failed` with a record of it. `poll` never waits; `process_join` waits for a process that was started. Each observation of the end owns a handle to the record. |
| `record_read` | One line of ASCII JSON: `version`, `reason` (`normal`, `abort`, `trap`, `failed`), `code`, `thread`, `trap`. A capacity of zero asks for the size; too small a one is `ERANGE`. |
| `cancel` | A program that has started is not stopped: it reports 0. |
| `retain`, `release` | A handle is three numbers: this runtime, a slot of its table, and which use of the slot. Released by its last owner it names nothing, and no other handle will be those three numbers again. What it named lasts as long as something needs it: a running process keeps its module. |
| `rax_portable_x1_context_files` | An extension: gives the processes a context makes from then on the files under one directory of the machine. |

The other eleven functions, which call single functions of a library module,
make values for them and answer host imports, return `ENOSYS`: the engine
does not yet keep a process between calls.

A process's standard streams are the host program's. No function unwinds
into its caller; a panic inside one is `EIO`.

## The launcher

`launcher/launcher.c` is the `main` of an executable that carries its
runtime and its program. It reads its own file, hands it to `module_verify`,
which finds the program in it as in any carrier, and runs it with this
process's arguments and streams, the files under the directory it was
started in, and every capability. The program runs as native code where the
runtime compiles any. It ends as the program ends: with its status, by
aborting, or, if the program faults, with a line of JSON on standard error
and status 125. `tools/smir-clang/smirpack.py` links such an executable.

## Tests

```sh
cargo test --offline --locked --manifest-path crates/smir-portable-capi/Cargo.toml
```

`tests/host.rs` calls the functions as a C program does, and compiles
`tests/consumer.c` against the static library and runs it: a C program that
has a module verified, runs it and reads how it ended.
`tools/smir-clang/test_pack.py` tests the launcher.
