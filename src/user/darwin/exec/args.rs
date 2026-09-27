//! Copying in `exec`'s arguments and environment (`exec_extract_strings`,
//! `exec_add_user_string` in `bsd/kern/kern_exec.c`).
//!
//! The strings share `NCARGS` (1 MiB) of space: each is charged its length
//! with the NUL plus a pointer (8 bytes) for its vector slot, each vector
//! a pointer for its NULL terminator, and the combined strings are padded
//! to a pointer boundary from the same space. A string that does not fit
//! is `E2BIG`; one the caller cannot read, or a vector slot it cannot
//! read, is `EFAULT`. A NULL vector is empty.
//!
//! For a `#!` script, the new `argv` is the interpreter line's words, the
//! path the caller passed, and the caller's `argv` without its first
//! element.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::syscall::Ctx;

/// `NCARGS` (`ARG_MAX`).
pub const NCARGS: i64 = 1 << 20;

/// A 64-bit process's pointer size.
const PTR: i64 = 8;

/// The caller's memory as `exec` reads it.
pub trait UserMem {
    /// A pointer-sized vector slot (`copyinptr`).
    fn ptr(&self, addr: u64) -> Result<u64, Errno>;
    /// A string of at most `max` bytes with its NUL (`copyinstr`).
    fn cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, Errno>;
}

impl UserMem for Ctx<'_> {
    fn ptr(&self, addr: u64) -> Result<u64, Errno> {
        self.read_u64(addr)
    }

    fn cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
        Ctx::cstr(self, addr, max)
    }
}

/// The new image's vectors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Strings {
    /// `argv`.
    pub argv: Vec<Vec<u8>>,
    /// `envp`.
    pub envp: Vec<Vec<u8>>,
}

/// What is left of `NCARGS` (`ip_argspace`).
struct Space {
    left: i64,
    /// String bytes copied, for the final padding.
    bytes: i64,
}

impl Space {
    /// Charges a string of `len` bytes with its NUL and its vector slot.
    fn charge(&mut self, len: usize) -> Result<(), Errno> {
        let len = len as i64 + 1;
        // copyinstr with the space left as its limit: a longer string
        // uses up the space, and the next attempt finds none.
        if self.left <= 0 || len > self.left {
            return Err(Errno::E2BIG);
        }
        self.left -= len;
        self.bytes += len;
        self.slot()
    }

    /// Charges a vector slot.
    fn slot(&mut self) -> Result<(), Errno> {
        if self.left < PTR {
            return Err(Errno::E2BIG);
        }
        self.left -= PTR;
        Ok(())
    }

    /// Copies a string from the caller and charges it.
    fn user(&mut self, mem: &impl UserMem, addr: u64) -> Result<Vec<u8>, Errno> {
        if self.left <= 0 {
            return Err(Errno::E2BIG);
        }
        let s = match mem.cstr(addr, self.left as usize) {
            Err(Errno::ENAMETOOLONG) => return Err(Errno::E2BIG),
            r => r?,
        };
        self.charge(s.len())?;
        Ok(s)
    }
}

/// Copies in `argv` and `envp` (addresses of NULL-terminated vectors, or
/// 0), with a script's interpreter words and `user_path` first.
pub fn extract(
    mem: &impl UserMem,
    interp: &[Vec<u8>],
    user_path: &[u8],
    mut argv: u64,
    mut envp: u64,
) -> Result<Strings, Errno> {
    let mut space = Space {
        left: NCARGS,
        bytes: 0,
    };
    let mut out = Strings::default();
    if !interp.is_empty() {
        for w in interp {
            space.charge(w.len())?;
            out.argv.push(w.clone());
        }
        // The script's path replaces the caller's argv[0].
        if argv != 0 && mem.ptr(argv)? != 0 {
            argv += PTR as u64;
        }
        space.charge(user_path.len())?;
        out.argv.push(user_path.to_vec());
    }
    while argv != 0 {
        let arg = mem.ptr(argv)?;
        if arg == 0 {
            break;
        }
        argv += PTR as u64;
        out.argv.push(space.user(mem, arg)?);
    }
    space.slot()?;
    while envp != 0 {
        let env = mem.ptr(envp)?;
        envp += PTR as u64;
        if env == 0 {
            break;
        }
        out.envp.push(space.user(mem, env)?);
    }
    space.slot()?;
    // The strings' tail is padded to a pointer boundary from the same
    // space. (What is left is congruent to the padding modulo the pointer
    // size, so the padding always fits once everything else has.)
    let pad = (PTR - space.bytes % PTR) % PTR;
    if space.left < pad {
        return Err(Errno::E2BIG);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Caller memory: vectors of pointers and strings by address.
    #[derive(Default)]
    struct Mem {
        ptrs: BTreeMap<u64, u64>,
        strs: BTreeMap<u64, Vec<u8>>,
    }

    impl UserMem for Mem {
        fn ptr(&self, addr: u64) -> Result<u64, Errno> {
            self.ptrs.get(&addr).copied().ok_or(Errno::EFAULT)
        }
        fn cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
            let s = self.strs.get(&addr).ok_or(Errno::EFAULT)?;
            if s.len() + 1 > max {
                return Err(Errno::ENAMETOOLONG);
            }
            Ok(s.clone())
        }
    }

    impl Mem {
        /// A vector at `at` of strings placed from `at + 0x1000`.
        fn vector(&mut self, at: u64, strings: &[&[u8]]) {
            for (i, s) in strings.iter().enumerate() {
                let addr = at + 0x1000 + (i as u64) * 0x10_0000;
                self.ptrs.insert(at + 8 * i as u64, addr);
                self.strs.insert(addr, s.to_vec());
            }
            self.ptrs.insert(at + 8 * strings.len() as u64, 0);
        }
    }

    fn v(s: &[&str]) -> Vec<Vec<u8>> {
        s.iter().map(|x| x.as_bytes().to_vec()).collect()
    }

    #[test]
    fn vectors_are_copied_and_null_vectors_are_empty() {
        let mut m = Mem::default();
        m.vector(0x1_0000_0000, &[b"prog", b"a"]);
        m.vector(0x2_0000_0000, &[b"K=V"]);
        let s = extract(&m, &[], b"/p", 0x1_0000_0000, 0x2_0000_0000).unwrap();
        assert_eq!(s.argv, v(&["prog", "a"]));
        assert_eq!(s.envp, v(&["K=V"]));
        assert_eq!(extract(&m, &[], b"/p", 0, 0).unwrap(), Strings::default());
    }

    #[test]
    fn scripts_put_the_interpreter_and_path_first() {
        let mut m = Mem::default();
        m.vector(0x1_0000_0000, &[b"ignored", b"x"]);
        let s = extract(&m, &v(&["/bin/sh", "-e"]), b"./s.sh", 0x1_0000_0000, 0).unwrap();
        assert_eq!(s.argv, v(&["/bin/sh", "-e", "./s.sh", "x"]));
        // A NULL argv, or an empty one, loses nothing.
        let s = extract(&m, &v(&["/bin/sh"]), b"./s.sh", 0, 0).unwrap();
        assert_eq!(s.argv, v(&["/bin/sh", "./s.sh"]));
        m.vector(0x3_0000_0000, &[]);
        let s = extract(&m, &v(&["/bin/sh"]), b"./s.sh", 0x3_0000_0000, 0).unwrap();
        assert_eq!(s.argv, v(&["/bin/sh", "./s.sh"]));
    }

    #[test]
    fn unreadable_vectors_and_strings_fault() {
        let mut m = Mem::default();
        assert_eq!(extract(&m, &[], b"", 0x9000, 0), Err(Errno::EFAULT));
        m.ptrs.insert(0x9000, 0x7777);
        m.ptrs.insert(0x9008, 0);
        assert_eq!(extract(&m, &[], b"", 0x9000, 0), Err(Errno::EFAULT));
    }

    /// The space one string of `len` bytes uses, with its slot.
    fn cost(len: i64) -> i64 {
        len + 1 + PTR
    }

    #[test]
    fn ncargs_is_charged_exactly() {
        // One argument filling NCARGS: its string and slot, the two
        // terminators, and the padding of the string bytes.
        let fits = |len: i64| {
            let mut m = Mem::default();
            let big = vec![b'x'; len as usize];
            m.vector(0x1_0000_0000, &[&big]);
            extract(&m, &[], b"", 0x1_0000_0000, 0)
        };
        // len + 1 is a multiple of 8, so there is no padding.
        let max = NCARGS - 2 * PTR - PTR - 1;
        assert_eq!(cost(max) + 2 * PTR, NCARGS);
        assert_eq!((max + 1) % PTR, 0);
        assert!(fits(max).is_ok());
        assert_eq!(fits(max + 1), Err(Errno::E2BIG));
        // A shorter string leaves exactly the padding it needs.
        for k in 1..8 {
            assert!(fits(max - k).is_ok(), "{k}");
        }
        // Two strings: the second's slot no longer fits.
        let mut m = Mem::default();
        let a = vec![b'a'; (NCARGS - cost(0) - 3 * PTR) as usize];
        m.vector(0x1_0000_0000, &[&a, b""]);
        assert_eq!(extract(&m, &[], b"", 0x1_0000_0000, 0), Err(Errno::E2BIG));
        // The environment shares the space.
        let mut m = Mem::default();
        let big = vec![b'x'; max as usize];
        m.vector(0x1_0000_0000, &[]);
        m.vector(0x2_0000_0000, &[&big]);
        assert!(extract(&m, &[], b"", 0x1_0000_0000, 0x2_0000_0000).is_ok());
        m.vector(0x1_0000_0000, &[b""]);
        assert_eq!(
            extract(&m, &[], b"", 0x1_0000_0000, 0x2_0000_0000),
            Err(Errno::E2BIG)
        );
    }
}
