//! Executable image formats.
//!
//! Each format module parses and validates a file into a format-specific view;
//! loaders for a given operating-system personality turn that view into guest
//! mappings. ELF serves Linux, Mach-O serves Darwin, and PE serves Windows.

pub mod elf;
pub mod macho;
pub mod pe;
