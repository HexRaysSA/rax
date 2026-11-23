//! Extended-attribute ABI checks shared by both Darwin file backends.

/// Options defined by `bsd/sys/xattr.h`.
pub mod opt {
    pub const NOFOLLOW: u32 = 0x0001;
    pub const NOSECURITY: u32 = 0x0008;
    pub const NODEFAULT: u32 = 0x0010;
    pub const NOFOLLOW_ANY: u32 = 0x0040;
    pub const RESOLVE_BENEATH: u32 = 0x0080;
}

pub(super) const XATTR_MAXNAMELEN: usize = 127;
pub(super) const PATH_REFUSED: u32 = opt::NOSECURITY | opt::NODEFAULT;
pub(super) const FD_REFUSED: u32 =
    PATH_REFUSED | opt::NOFOLLOW | opt::NOFOLLOW_ANY | opt::RESOLVE_BENEATH;

pub(super) fn protected(name: &[u8]) -> bool {
    name.starts_with(b"com.apple.system.")
}
