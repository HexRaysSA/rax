//! The initial stack `exec` builds (`exec_copyout_strings`).
//!
//! From the top of the stack (`p->user_stack`) down:
//!
//! ```text
//! string area   "executable_path=<path>" NUL, padding to 8 bytes,
//!               argv strings, env strings, padding to 8,
//!               apple strings (applev[1..]), padding to 8
//! pointer area  argv[0..argc] NULL  envp[0..envc] NULL  applev[0..applec] NULL
//! argc          (8 bytes)
//! mach_header   (8 bytes, only when dyld runs the program)  <- SP
//! ```
//!
//! `applev[0]` points at the `executable_path=` string at the start of the
//! string area. The stack pointer is only 8-byte aligned; `__dyld_start`
//! aligns it.

use crate::user::mm::AddressSpace;

/// `ARG_MAX`/`NCARGS`: the bytes `execve` accepts for arguments and
/// environment (strings and pointers).
pub const NCARGS: usize = 1024 * 1024;

/// `EXECUTABLE_KEY`.
pub const EXECUTABLE_KEY: &str = "executable_path=";

/// The vectors an initial stack carries.
#[derive(Clone, Debug, Default)]
pub struct StackStrings {
    /// The path `execve` was given (without the key).
    pub exec_path: Vec<u8>,
    /// `argv`.
    pub argv: Vec<Vec<u8>>,
    /// `envp`.
    pub envp: Vec<Vec<u8>>,
    /// `applev[1..]` (the key=value strings after the executable path).
    pub apple: Vec<Vec<u8>>,
}

/// Where the pieces of a built stack are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackLayout {
    /// The stack pointer the thread starts with.
    pub sp: u64,
    /// Address of `argc`.
    pub argc_addr: u64,
    /// Address of `argv[0]`'s slot.
    pub argv_addr: u64,
    /// Address of `envp[0]`'s slot.
    pub envp_addr: u64,
    /// Address of `applev[0]`'s slot.
    pub apple_addr: u64,
    /// Start of the string area.
    pub string_area: u64,
    /// `p_argslen`: bytes from the string area to the top.
    pub argslen: u64,
    /// The bytes to write at `sp` (everything up to the top).
    pub image: Vec<u8>,
}

/// Why a stack cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StackError {
    /// The arguments exceed `NCARGS` (`E2BIG`).
    TooBig,
    /// The stack could not be written.
    Fault(u64),
}

fn pad8(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

/// Lays the stack out below `top`; `mach_header` is pushed below `argc`
/// when a dynamic linker runs the program.
pub fn layout(
    strings: &StackStrings,
    top: u64,
    mach_header: Option<u64>,
) -> Result<StackLayout, StackError> {
    // The string area, and the offset of each string in it.
    let mut area = Vec::new();
    area.extend_from_slice(EXECUTABLE_KEY.as_bytes());
    area.extend_from_slice(&strings.exec_path);
    area.push(0);
    pad8(&mut area);
    let mut argv_off = Vec::with_capacity(strings.argv.len());
    let mut env_off = Vec::with_capacity(strings.envp.len());
    let mut apple_off = Vec::with_capacity(strings.apple.len() + 1);
    apple_off.push(0usize);
    let args_start = area.len();
    for a in &strings.argv {
        argv_off.push(area.len());
        area.extend_from_slice(a);
        area.push(0);
    }
    for e in &strings.envp {
        env_off.push(area.len());
        area.extend_from_slice(e);
        area.push(0);
    }
    // exec_extract_strings charges each string and each pointer slot (and
    // the envp NULL) to NCARGS.
    let charged = area.len() - args_start + 8 * (strings.argv.len() + strings.envp.len() + 1);
    if charged > NCARGS {
        return Err(StackError::TooBig);
    }
    pad8(&mut area);
    for s in &strings.apple {
        apple_off.push(area.len());
        area.extend_from_slice(s);
        area.push(0);
    }
    pad8(&mut area);

    let string_area = top - area.len() as u64;
    let nptrs = strings.argv.len() + strings.envp.len() + apple_off.len() + 3;
    let ptr_area = string_area - 8 * nptrs as u64;
    let argc_addr = ptr_area - 8;
    let sp = if mach_header.is_some() {
        argc_addr - 8
    } else {
        argc_addr
    };

    let mut image = Vec::with_capacity((top - sp) as usize);
    if let Some(mh) = mach_header {
        image.extend_from_slice(&mh.to_le_bytes());
    }
    image.extend_from_slice(&(strings.argv.len() as u64).to_le_bytes());
    let ptr = |off: usize| (string_area + off as u64).to_le_bytes();
    for &o in &argv_off {
        image.extend_from_slice(&ptr(o));
    }
    image.extend_from_slice(&0u64.to_le_bytes());
    for &o in &env_off {
        image.extend_from_slice(&ptr(o));
    }
    image.extend_from_slice(&0u64.to_le_bytes());
    for &o in &apple_off {
        image.extend_from_slice(&ptr(o));
    }
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&area);
    debug_assert_eq!(sp + image.len() as u64, top);

    let argv_addr = ptr_area;
    let envp_addr = argv_addr + 8 * (strings.argv.len() as u64 + 1);
    let apple_addr = envp_addr + 8 * (strings.envp.len() as u64 + 1);
    Ok(StackLayout {
        sp,
        argc_addr,
        argv_addr,
        envp_addr,
        apple_addr,
        string_area,
        argslen: top - string_area,
        image,
    })
}

/// Builds the stack below `top` in `space`.
pub fn write(
    space: &AddressSpace,
    strings: &StackStrings,
    top: u64,
    mach_header: Option<u64>,
) -> Result<StackLayout, StackError> {
    let l = layout(strings, top, mach_header)?;
    space
        .write(l.sp, &l.image)
        .map_err(|f| StackError::Fault(f.address))?;
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u64(img: &[u8], off: u64) -> u64 {
        u64::from_le_bytes(img[off as usize..off as usize + 8].try_into().unwrap())
    }

    fn cstr(img: &[u8], base: u64, addr: u64) -> Vec<u8> {
        let o = (addr - base) as usize;
        let end = img[o..].iter().position(|&b| b == 0).unwrap();
        img[o..o + end].to_vec()
    }

    #[test]
    fn layout_follows_exec_copyout_strings() {
        let s = StackStrings {
            exec_path: b"/bin/echo".to_vec(),
            argv: vec![b"echo".to_vec(), b"hi".to_vec()],
            envp: vec![b"A=1".to_vec()],
            apple: vec![b"ptr_munge=0x1".to_vec(), b"th_port=0x103".to_vec()],
        };
        let top = 0x1_7000_0000;
        let l = layout(&s, top, Some(0x1_0000_0000)).unwrap();
        let img = &l.image;
        let base = l.sp;
        assert_eq!(l.sp % 8, 0);
        assert_eq!(read_u64(img, 0), 0x1_0000_0000, "mach_header");
        assert_eq!(read_u64(img, 8), 2, "argc");
        assert_eq!(l.argc_addr, l.sp + 8);
        assert_eq!(l.argv_addr, l.argc_addr + 8);
        let argv0 = read_u64(img, l.argv_addr - base);
        assert_eq!(cstr(img, base, argv0), b"echo");
        assert_eq!(
            cstr(img, base, read_u64(img, l.argv_addr - base + 8)),
            b"hi"
        );
        assert_eq!(read_u64(img, l.argv_addr - base + 16), 0);
        assert_eq!(l.envp_addr, l.argv_addr + 24);
        assert_eq!(cstr(img, base, read_u64(img, l.envp_addr - base)), b"A=1");
        assert_eq!(read_u64(img, l.envp_addr - base + 8), 0);
        // applev[0] is the executable path at the start of the string area.
        let a0 = read_u64(img, l.apple_addr - base);
        assert_eq!(a0, l.string_area);
        assert_eq!(cstr(img, base, a0), b"executable_path=/bin/echo");
        assert_eq!(
            cstr(img, base, read_u64(img, l.apple_addr - base + 8)),
            b"ptr_munge=0x1"
        );
        assert_eq!(
            cstr(img, base, read_u64(img, l.apple_addr - base + 16)),
            b"th_port=0x103"
        );
        assert_eq!(read_u64(img, l.apple_addr - base + 24), 0);
        // The argv strings start pointer-aligned after the path.
        assert_eq!((argv0 - l.string_area) % 8, 0);
        assert_eq!(l.argslen, top - l.string_area);
        assert_eq!((top - l.string_area) % 8, 0);
    }

    #[test]
    fn a_static_program_gets_no_mach_header() {
        let s = StackStrings {
            exec_path: b"/x".to_vec(),
            argv: vec![b"x".to_vec()],
            ..Default::default()
        };
        let l = layout(&s, 0x10_0000, None).unwrap();
        assert_eq!(l.sp, l.argc_addr);
        assert_eq!(read_u64(&l.image, 0), 1);
    }

    #[test]
    fn arguments_beyond_ncargs_are_too_big() {
        let s = StackStrings {
            exec_path: b"/x".to_vec(),
            argv: vec![vec![b'a'; NCARGS]],
            ..Default::default()
        };
        assert_eq!(layout(&s, 1 << 32, None), Err(StackError::TooBig));
    }
}
