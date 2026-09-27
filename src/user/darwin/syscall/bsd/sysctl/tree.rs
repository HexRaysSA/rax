//! The sysctl subtrees the personality answers itself (`hw` and
//! `machdep`: the emulated machine's), and the walks the kernel makes over
//! a subtree (`kern_newsysctl.c`): an OID to its node (`sysctl_root`,
//! `find_oid_by_name`), a name to its OID (`name2oid`), an OID to its name
//! (`sysctl_sysctl_name`), and the leaf after an OID (`sysctl_sysctl_next`).
//!
//! A subtree is its nodes sorted by OID, interior nodes included; none of
//! them has a handler that takes further OID components.

use std::sync::OnceLock;

use super::arm64;
use crate::user::darwin::abi::{DarwinAbi, Errno};

/// `CTLTYPE`: a kind's type bits.
pub const CTLTYPE: u32 = 0xf;
/// `CTLTYPE_NODE`.
pub const CTLTYPE_NODE: u32 = 1;

/// A node as the metadata nodes report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// The OID.
    pub oid: &'static [i32],
    /// The full name.
    pub name: &'static str,
    /// `oid_kind` less `CTLFLAG_KERNEL_PRIVATE_MASK`.
    pub kind: u32,
    /// `oid_fmt`.
    pub fmt: &'static str,
    /// `oid_descr`.
    pub descr: &'static str,
}

impl Row {
    /// Whether the node is interior (`CTLTYPE_NODE`).
    pub fn is_node(&self) -> bool {
        self.kind & CTLTYPE == CTLTYPE_NODE
    }

    /// The last component of the name.
    pub fn component(&self) -> &'static str {
        self.name.rsplit('.').next().unwrap_or(self.name)
    }
}

/// Whether the personality answers the subtree of top-level OID `top`.
pub fn owns(top: i32) -> bool {
    matches!(top, CTL_HW | CTL_MACHDEP)
}

/// Whether the personality answers the subtree `name` is in.
pub fn owns_name(name: &str) -> bool {
    matches!(name.split('.').next(), Some("hw" | "machdep"))
}

/// `CTL_HW`.
pub const CTL_HW: i32 = 6;
/// `CTL_MACHDEP`.
pub const CTL_MACHDEP: i32 = 7;

/// The nodes of the emulated machine for `abi`, sorted by OID.
pub fn rows(abi: DarwinAbi) -> &'static [Row] {
    match abi {
        DarwinAbi::Arm64 => arm64::ROWS,
        DarwinAbi::X86_64 => {
            static X86: OnceLock<Vec<Row>> = OnceLock::new();
            X86.get_or_init(x86_rows)
        }
    }
}

/// The Intel kernel's `hw` nodes: the arm64 kernel's that `kern_mib.c`
/// declares for every architecture, under the same OIDs (the automatic
/// numbers follow declaration order, which the two share). The `machdep`
/// subtree is the Intel kernel's own (`bsd/dev/i386/sysctl.c`).
fn x86_rows() -> Vec<Row> {
    let arm_only = |n: &str| {
        n.starts_with("hw.optional.arm")
            || n.starts_with("hw.optional.neon")
            || n.starts_with("hw.perflevel2")
            || n.starts_with("hw.features")
            || n.starts_with("machdep")
            || matches!(
                n,
                "hw.optional.watchpoint"
                    | "hw.optional.breakpoint"
                    | "hw.optional.ucnormal_mem"
                    | "hw.targettype"
                    | "hw.jetsam_properties_product_type"
            )
    };
    arm64::ROWS
        .iter()
        .filter(|r| !arm_only(r.name))
        .copied()
        .collect()
}

/// `sysctl_root`'s walk: the leaf `oid` names. An interior node is not
/// read (`ENOENT`), a leaf takes no further components (`EISDIR`).
pub fn leaf(rows: &'static [Row], oid: &[i32]) -> Result<&'static Row, Errno> {
    for i in 1..=oid.len() {
        let row = find(rows, &oid[..i]).ok_or(Errno::ENOENT)?;
        if !row.is_node() {
            return if i == oid.len() {
                Ok(row)
            } else {
                Err(Errno::EISDIR)
            };
        }
    }
    Err(Errno::ENOENT)
}

/// `find_oid_by_name`: the node `oid` names, interior or not.
pub fn node(rows: &'static [Row], oid: &[i32]) -> Result<&'static Row, Errno> {
    for i in 1..=oid.len() {
        let row = find(rows, &oid[..i]).ok_or(Errno::ENOENT)?;
        if i == oid.len() {
            return Ok(row);
        }
        if !row.is_node() {
            return Err(Errno::EISDIR);
        }
    }
    Err(Errno::ENOENT)
}

fn find(rows: &'static [Row], oid: &[i32]) -> Option<&'static Row> {
    rows.binary_search_by(|r| r.oid.cmp(oid))
        .ok()
        .map(|i| &rows[i])
}

/// `name2oid`: the OID of `name` (one trailing `.` ignored).
pub fn oid_of(rows: &'static [Row], name: &str) -> Result<&'static [i32], Errno> {
    let name = name.strip_suffix('.').unwrap_or(name);
    rows.iter()
        .find(|r| r.name == name)
        .map(|r| r.oid)
        .ok_or(Errno::ENOENT)
}

/// `sysctl_sysctl_name`'s components for `oid`: each a node's name while
/// the walk finds nodes, then the numbers of the rest.
pub fn name_parts(rows: &'static [Row], oid: &[i32]) -> Vec<String> {
    let mut parts = Vec::with_capacity(oid.len());
    let mut in_tree = true;
    for i in 0..oid.len() {
        let row = in_tree.then(|| find(rows, &oid[..=i])).flatten();
        match row {
            Some(r) => {
                parts.push(r.component().to_string());
                in_tree = r.is_node();
            }
            None => {
                parts.push(oid[i].to_string());
                in_tree = false;
            }
        }
    }
    parts
}

/// `sysctl_sysctl_next` within the subtree: the first leaf after `oid` in
/// OID order (a prefix sorts first); interior nodes without leaves are
/// skipped, as they are by being empty.
pub fn next(rows: &'static [Row], oid: &[i32]) -> Option<&'static [i32]> {
    rows.iter()
        .filter(|r| !r.is_node())
        .map(|r| r.oid)
        .find(|o| *o > oid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_follow_the_kernel() {
        let rows = rows(DarwinAbi::Arm64);
        assert!(rows.windows(2).all(|w| w[0].oid < w[1].oid));
        assert_eq!(leaf(rows, &[6, 3]).unwrap().name, "hw.ncpu");
        assert_eq!(leaf(rows, &[6]), Err(Errno::ENOENT));
        assert_eq!(leaf(rows, &[6, 101]), Err(Errno::ENOENT));
        assert_eq!(leaf(rows, &[6, 3, 7]), Err(Errno::EISDIR));
        assert_eq!(leaf(rows, &[6, 9999]), Err(Errno::ENOENT));
        assert_eq!(node(rows, &[6, 101]).unwrap().name, "hw.optional");
        assert_eq!(oid_of(rows, "hw.ncpu"), Ok(&[6, 3][..]));
        assert_eq!(oid_of(rows, "hw."), Ok(&[6][..]));
        assert_eq!(oid_of(rows, "hw.ncpu.extra"), Err(Errno::ENOENT));
        assert_eq!(name_parts(rows, &[6, 3, 5]), ["hw", "ncpu", "5"]);
        assert_eq!(name_parts(rows, &[6, 9999, 1]), ["hw", "9999", "1"]);
        assert_eq!(next(rows, &[6]), Some(&[6, 1][..]));
        assert_eq!(next(rows, &[6, 3]), Some(&[6, 4][..]));
        assert_eq!(next(rows, &[6, 3, 5]), Some(&[6, 4][..]));
        // Into a subtree past its interior node.
        assert_eq!(next(rows, &[6, 101, 100]).map(|o| o.len()), Some(4));
        assert_eq!(next(rows, &[7, i32::MAX]), None);
    }

    #[test]
    fn the_intel_tree_keeps_the_shared_nodes() {
        let x86 = rows(DarwinAbi::X86_64);
        assert_eq!(oid_of(x86, "hw.pagesize"), Ok(&[6, 116][..]));
        assert_eq!(oid_of(x86, "hw.optional.avx2_0"), Ok(&[6, 101, 116][..]));
        assert!(oid_of(x86, "hw.optional.arm").is_err());
        assert!(oid_of(x86, "hw.optional.neon").is_err());
        assert!(x86.iter().all(|r| r.oid[0] == CTL_HW));
    }
}
