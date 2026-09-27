//! Windows paths and their host files.
//!
//! Guest paths follow Win32 path normalization (`GetFullPathNameW`):
//! `/` is a separator like `\`, repeated separators collapse, `.` and `..`
//! components are resolved (`..` never climbs above the root), trailing
//! dots and spaces of the final component are removed, and a relative
//! path is taken from the current directory (a rooted path `\x` from the
//! current drive's root). A `\\?\` prefix disables normalization.
//!
//! A [`DriveMap`] assigns host directories to drive letters; by default
//! `C:` is the host root, so the host path `/a/b` is `C:\a\b` in the
//! guest. Windows file names are case-insensitive: on a case-sensitive
//! host each component that does not exist as written is matched
//! case-insensitively against its directory.

use std::path::{Path, PathBuf};

/// Drive letters and the host directories they map to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveMap {
    drives: Vec<(char, PathBuf)>,
}

impl Default for DriveMap {
    /// `C:` is the host root.
    fn default() -> Self {
        DriveMap {
            drives: vec![('C', PathBuf::from("/"))],
        }
    }
}

/// A normalized absolute Windows path, split into its drive and
/// components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinPath {
    /// Drive letter (upper case).
    pub drive: char,
    /// Components below the root.
    pub parts: Vec<String>,
}

impl WinPath {
    /// The path as text: `C:\a\b` (the root is `C:\`).
    pub fn to_string_path(&self) -> String {
        let mut s = format!("{}:\\", self.drive);
        s.push_str(&self.parts.join("\\"));
        s
    }
}

impl DriveMap {
    /// A map with no drives.
    pub fn empty() -> Self {
        DriveMap { drives: Vec::new() }
    }

    /// Maps `letter` to `root`, replacing an earlier mapping.
    pub fn set(&mut self, letter: char, root: impl Into<PathBuf>) {
        let letter = letter.to_ascii_uppercase();
        self.drives.retain(|(l, _)| *l != letter);
        self.drives.push((letter, root.into()));
    }

    /// The host root of `letter`.
    pub fn root(&self, letter: char) -> Option<&Path> {
        let letter = letter.to_ascii_uppercase();
        self.drives
            .iter()
            .find(|(l, _)| *l == letter)
            .map(|(_, p)| p.as_path())
    }

    /// Mapped drive letters, in order.
    pub fn letters(&self) -> Vec<char> {
        let mut v: Vec<char> = self.drives.iter().map(|(l, _)| *l).collect();
        v.sort_unstable();
        v
    }

    /// The Windows path of host path `host`: the drive whose root is the
    /// longest prefix of it. A path under no drive maps below the first
    /// drive's root as written.
    pub fn to_windows(&self, host: &Path) -> String {
        let host = if host.is_absolute() {
            host.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|c| c.join(host))
                .unwrap_or_else(|_| host.to_path_buf())
        };
        let best = self
            .drives
            .iter()
            .filter(|(_, root)| host.starts_with(root))
            .max_by_key(|(_, root)| root.components().count());
        let (letter, rest) = match best {
            Some((l, root)) => (*l, host.strip_prefix(root).unwrap_or(&host).to_path_buf()),
            None => (
                self.drives.first().map_or('C', |d| d.0),
                host.strip_prefix("/").unwrap_or(&host).to_path_buf(),
            ),
        };
        let parts: Vec<String> = rest
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        WinPath {
            drive: letter,
            parts,
        }
        .to_string_path()
    }

    /// The host path of Windows path `path` relative to current directory
    /// `cwd` (UTF-16, absolute). `None` for a path on an unmapped drive, a
    /// UNC path, or a device path.
    pub fn to_host(&self, path: &str, cwd: &[u16]) -> Option<PathBuf> {
        let cwd = String::from_utf16_lossy(cwd);
        let full = full_path(path, &cwd)?;
        self.resolve(&full)
    }

    /// The host path of a normalized path, matching components
    /// case-insensitively where the exact name does not exist.
    pub fn resolve(&self, p: &WinPath) -> Option<PathBuf> {
        let mut host = self.root(p.drive)?.to_path_buf();
        for part in &p.parts {
            let exact = host.join(part);
            host = if exact.exists() {
                exact
            } else {
                find_case_insensitive(&host, part).unwrap_or(exact)
            };
        }
        Some(host)
    }
}

/// Finds `name` in host directory `dir`, exactly or case-insensitively.
pub fn find_case_insensitive(dir: &Path, name: &str) -> Option<PathBuf> {
    let exact = dir.join(name);
    if exact.exists() {
        return Some(exact);
    }
    let lower = name.to_lowercase();
    std::fs::read_dir(dir).ok()?.find_map(|e| {
        let e = e.ok()?;
        (e.file_name().to_string_lossy().to_lowercase() == lower).then(|| e.path())
    })
}

/// Whether `c` separates path components.
fn is_sep(c: char) -> bool {
    c == '\\' || c == '/'
}

/// Normalizes `path` against the absolute current directory `cwd`
/// (`C:\dir\`) into an absolute path, as `GetFullPathNameW` does. `None`
/// for UNC and device (`\\.\`) paths and malformed drive specifications.
pub fn full_path(path: &str, cwd: &str) -> Option<WinPath> {
    let cwd_path = parse_absolute(cwd)?;
    if let Some(rest) = path.strip_prefix("\\\\?\\") {
        // Verbatim: no normalization, only splitting.
        let b = rest.as_bytes();
        if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
            let parts = rest[2..]
                .split('\\')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            return Some(WinPath {
                drive: (b[0] as char).to_ascii_uppercase(),
                parts,
            });
        }
        return None;
    }
    let chars: Vec<char> = path.chars().collect();
    if chars.len() >= 2 && is_sep(chars[0]) && is_sep(chars[1]) {
        // UNC (`\\server\share`) or device (`\\.\`) path.
        return None;
    }
    let (drive, rest, base) =
        if chars.len() >= 2 && chars[1] == ':' && chars[0].is_ascii_alphabetic() {
            let drive = chars[0].to_ascii_uppercase();
            let rest: String = chars[2..].iter().collect();
            if rest.starts_with(is_sep) {
                (drive, rest, Vec::new())
            } else if drive == cwd_path.drive {
                (drive, rest, cwd_path.parts.clone())
            } else {
                // A drive-relative path on another drive: that drive's
                // current directory is its root here.
                (drive, rest, Vec::new())
            }
        } else if path.starts_with(is_sep) {
            (cwd_path.drive, path.to_string(), Vec::new())
        } else {
            (cwd_path.drive, path.to_string(), cwd_path.parts.clone())
        };
    let mut parts = base;
    let pieces: Vec<&str> = rest.split(is_sep).collect();
    let last = pieces.iter().rposition(|s| !s.is_empty());
    for (i, piece) in pieces.iter().enumerate() {
        let piece = if Some(i) == last && !matches!(*piece, "." | "..") {
            piece.trim_end_matches(['.', ' '])
        } else {
            piece
        };
        match piece {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p.to_string()),
        }
    }
    // Exact dot components retain their traversal meaning before ordinary
    // final-name trimming; other all-dot/space names become empty.
    Some(WinPath { drive, parts })
}

/// Parses an absolute `X:\...` path.
fn parse_absolute(path: &str) -> Option<WinPath> {
    let b: Vec<char> = path.chars().collect();
    if b.len() < 2 || b[1] != ':' || !b[0].is_ascii_alphabetic() {
        return None;
    }
    let rest: String = b[2..].iter().collect();
    Some(WinPath {
        drive: b[0].to_ascii_uppercase(),
        parts: rest
            .split(is_sep)
            .filter(|s| !s.is_empty() && *s != ".")
            .map(str::to_string)
            .collect(),
    })
}

/// Whether the final component of `path` names a DOS device (`CON`,
/// `NUL`, `CONIN$`, `CONOUT$`, `PRN`, `AUX`, `COM1`-`COM9`,
/// `LPT1`-`LPT9`), ignoring an extension and trailing spaces, as Win32
/// path parsing does. Returns the upper-case device name.
pub fn dos_device(path: &str) -> Option<String> {
    let name = path.rsplit(is_sep).next()?;
    let stem = name.split('.').next()?.trim_end().to_ascii_uppercase();
    let is_device = matches!(
        stem.as_str(),
        "CON" | "NUL" | "PRN" | "AUX" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    is_device.then_some(stem)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(p: &str) -> String {
        full_path(p, "C:\\work\\dir\\")
            .map(|w| w.to_string_path())
            .unwrap_or_default()
    }

    #[test]
    fn full_path_normalization() {
        assert_eq!(fp("C:\\a\\b.txt"), "C:\\a\\b.txt");
        assert_eq!(fp("c:/a//b/./c/../d"), "C:\\a\\b\\d");
        assert_eq!(fp("file.txt"), "C:\\work\\dir\\file.txt");
        assert_eq!(fp("..\\x"), "C:\\work\\x");
        assert_eq!(fp("..\\..\\..\\..\\x"), "C:\\x", "`..` stops at the root");
        assert_eq!(fp("\\root.txt"), "C:\\root.txt");
        assert_eq!(
            fp("C:rel"),
            "C:\\work\\dir\\rel",
            "drive-relative, same drive"
        );
        assert_eq!(fp("D:rel"), "D:\\rel");
        assert_eq!(
            fp("name.. "),
            "C:\\work\\dir\\name",
            "trailing dots and spaces"
        );
        assert_eq!(fp("C:\\"), "C:\\");
        assert_eq!(fp("\\\\?\\C:\\a\\..\\b"), "C:\\a\\..\\b", "verbatim");
        assert_eq!(full_path("\\\\server\\share\\x", "C:\\"), None);
        assert_eq!(full_path("\\\\.\\PhysicalDrive0", "C:\\"), None);
    }

    #[test]
    fn terminal_parent_components_traverse_before_name_trimming() {
        assert_eq!(fp(".."), "C:\\work");
        assert_eq!(fp("a\\.."), "C:\\work\\dir");
        assert_eq!(fp("C:\\a\\.."), "C:\\");
        assert_eq!(fp("C:\\..\\.."), "C:\\");
        assert_eq!(fp("C:\\a\\."), "C:\\a");
        assert_eq!(fp("C:\\a\\..\\"), "C:\\");
        assert_eq!(fp("\\\\?\\C:\\a\\.."), "C:\\a\\..");
    }

    #[test]
    fn devices_are_recognized_with_extensions() {
        assert_eq!(dos_device("NUL").as_deref(), Some("NUL"));
        assert_eq!(dos_device("c:\\dir\\con.txt").as_deref(), Some("CON"));
        assert_eq!(dos_device("CONOUT$").as_deref(), Some("CONOUT$"));
        assert_eq!(dos_device("com1").as_deref(), Some("COM1"));
        assert_eq!(dos_device("com0"), None);
        assert_eq!(dos_device("console.txt"), None);
    }

    #[test]
    fn drive_map_translates_both_ways() {
        let mut m = DriveMap::empty();
        m.set('c', "/");
        m.set('D', "/tmp/rax-drive-d");
        assert_eq!(m.to_windows(Path::new("/usr/bin/x")), "C:\\usr\\bin\\x");
        assert_eq!(
            m.to_windows(Path::new("/tmp/rax-drive-d/sub/f")),
            "D:\\sub\\f"
        );
        let host = m.to_host("D:\\sub\\f", &"C:\\".encode_utf16().collect::<Vec<_>>());
        assert_eq!(host, Some(PathBuf::from("/tmp/rax-drive-d/sub/f")));
        assert_eq!(
            m.to_host("E:\\x", &"C:\\".encode_utf16().collect::<Vec<_>>()),
            None
        );
    }
}
