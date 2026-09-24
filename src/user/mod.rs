//! Userland (process-level) emulation.
//!
//! This subsystem runs a single guest *program* rather than a whole machine:
//! the guest's user-mode instructions execute on RAX's software CPUs, while
//! operating-system services requested through system calls are implemented
//! by an OS personality on the host. It is the engine behind the `rax-user`
//! binary.
//!
//! | Module | Owns |
//! |---|---|
//! | [`image`] | Executable file formats (ELF) and their validation |
//!
//! The subsystem is independent of `machine/`, `devices/`, and `vm/runtime`:
//! there is no board, firmware, or device model, only a guest address space,
//! one or more guest threads, and the personality that services them.

pub mod image;
