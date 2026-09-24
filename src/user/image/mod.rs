//! Executable image formats.
//!
//! Each format module parses and validates a file into a format-specific view;
//! loaders for a given operating-system personality turn that view into guest
//! mappings. ELF is the first supported format.

pub mod elf;
