# rax-smir-portable-foreign

A processor for the foreign code of Portable SMIR programs.

A Portable SMIR module may call machine code of another processor through
bridges (chapter 07 of the specification, `docs/specifications/smir/portable`).
The engine, `crates/smir-portable`, has no such processor: it makes the frame
and the arguments of each call, judges what comes back, and asks its host for
something that runs the code, an `interp::Foreign`. This crate is one. It runs
x86-64 and AArch64 code on the emulator's user-mode cores (`rax::user::cpu`),
on any machine the emulator builds for, so a module with x86-64 code in it
runs on an AArch64 host and the other way round.

```rust
use rax_smir_portable::interp::NoHost;
use rax_smir_portable::ir::ForeignIsa;
use rax_smir_portable_foreign::{Hosting, Limits, Processor};

let mut processor = Processor::new(ForeignIsa::X86_64, Limits::default())?;
processor.load(&std::fs::read("library.elf")?)?;
let record = processor.record();
// `Hosting` is the host given to it, with the processor: it grants `foreign`
// and hands the processor to the process it starts.
let mut host = Hosting::new(NoHost, processor);
// ... run_on(engine, &module, entry, &arguments, policy, &mut host) ...
println!("{} calls returned; {:?}", record.crossings(), record.reasons());
```

## What it does

- **Images.** `Processor::load` takes a static ELF executable for the
  processor (64-bit, little-endian, `ET_EXEC`) and puts each of its segments
  at the address the file says, with the permissions the file says. Its
  identity is the SHA-256 of the file. A module names code by that identity
  and by the offset and size of the code in the file; the processor has the
  code if those bytes lie in one segment that may be executed. Nothing is
  relocated and nothing is linked, so position-independent executables and
  shared objects are refused, as is an image that would lie where another
  is.
- **Memory for calls.** The engine's frame, arguments and result of a
  crossing are in a heap of the processor's, zeroed when handed out and
  free again when the call is over. The engine reads and writes what the
  foreign code itself may: that memory, and the frames of callbacks, which
  the code has on its stack. It does not write code.
- **Stacks.** Each thread of the program that crosses has a stack
  (`Limits::stack`, 1 MiB unless said otherwise), with 256 MiB below it at
  which nothing is mapped: code that runs out of stack faults, and does not
  reach another thread's.
- **Entry.** Code is entered with one argument, the frame's address, as its
  convention has it: System V x86-64 in RDI with the stack as a `call`
  leaves it; Win64 in RCX with the 32 bytes above the return address that
  are the callee's; AArch64 in X0 with the return address in X30. The return
  address is one at which nothing is ever mapped. The code has returned when
  the core faults fetching from there with the stack pointer where a return
  leaves it.
- **Code that does not return.** There is no operating system under foreign
  code. A system call, a fault, an exception, an undefined instruction, a
  return with the stack elsewhere, and code that runs longer than
  `Limits::time` are all code that has not returned: the engine ends the
  program with the trap `foreign_fault`, and the processor's `Record` has the
  reason in words. The thread's next call, if there is one, starts on a new
  core.
- **Callbacks.** A module's bridge from foreign code to one of its functions
  has an entry in the image: a function there in name only. The processor
  takes it over (`intercept`) by putting a breakpoint where its code begins.
  Foreign code that calls it stops there; the engine reads the frame the
  code brought, runs the function, writes the result, and has the processor
  go on (`resume`) as if the entry had returned. If the function calls
  foreign code again, that call runs on the same thread's stack, below the
  code that waits, and what waits last goes on first.

A processor is for one kind of code and one process. All it uses comes out of
`Limits::memory`.

## What it does not do

- Exceptions, arguments other than scalars, and callbacks on a thread other
  than the one that called: the engine does not do them yet (chapter 07,
  "As implemented").
- Relocation and dynamic linking of images; PE and Mach-O images.
- Giving a thread's stack back when the thread ends: the engine does not say
  when that is. A stack is the thread's until the process ends.
- Saving and restoring the floating-point environment around a call: what a
  call leaves in the thread's core, the thread's next call finds.

## Building and testing

The crate is a package of its own, outside the emulator's workspace, with a
lock file of its own that has the versions of the emulator's. It repeats the
emulator's `[patch.crates-io]`, which a package that depends on the emulator
by path has to.

```sh
cargo test --offline --locked --manifest-path crates/smir-portable-foreign/Cargo.toml
```

The first build compiles the emulator (about two minutes and three gigabytes
of target directory), without its hypervisors: only the user-mode cores are
used. The feature `jit`, which is on unless turned off, is the emulator's
`smir-jit`: native code for hot regions of the foreign code on hosts that
have it. With `--no-default-features` the cores interpret everything; the
tests pass either way. `tests/guest.rs` runs the modules of the engine's
tests that call foreign code, `crates/smir-portable/tests/interp/programs/foreign-*.smo`,
with the images those name, `crates/smir-portable/tests/interp/foreign/guest-*.elf`
(compiled from `guest.c` there for both processors): on both engines, for
both processors, with real machine code. The engine's own tests run the same
modules against a model of the stubs.

On Linux from another system: `sh crates/smir-portable/tests/linux.sh foreign`.
