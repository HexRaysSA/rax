//! Final-component CRT globbing: an explicitly source-derived DOS profile.
//!
//! Primary comparison: retained dotnet/runtime FileSystemName.cs at
//! 33baf8ee337b20dd0f184b69a6f09be92850bf9e (crt-startup archive). This does not
//! prove native CRT quote handling, enumeration/case ordering or 8.3 aliases.
//! No argv0/initially quoted expansion; no-match retains the original argument.
//! Files and directories participate. Results preserve the original prefix and
//! sort by raw UTF-16 filename units.
//! Case matching uses one-BMP-unit Rust uppercase, not a native Windows table.
//! Directory components must be literal mapped paths; unsupported host/path
//! forms fail explicitly, without lossy Unicode conversion or guest writes.

use super::{codepage, parse::Argument};
use crate::user::windows::fs::{DriveMap, WinPath, dos_device, full_path};
use crate::user::windows::hle::ApiErr;
use crate::user::windows::process::Proc;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    Star,
    DosStar,
    DosQuestion,
    DosDot,
    Literal(u16),
}

fn unsupported(detail: impl std::fmt::Display) -> ApiErr {
    ApiErr::Unimplemented(format!("CRT wildcard expansion: {detail}"))
}

fn separator(unit: u16) -> bool {
    unit == u16::from(b'\\') || unit == u16::from(b'/')
}

fn has_wildcard(units: &[u16]) -> bool {
    units
        .iter()
        .any(|&unit| unit == u16::from(b'*') || unit == u16::from(b'?'))
}

fn uppercase(unit: u16) -> u16 {
    let Some(character) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut upper = character.to_uppercase();
    let first = upper.next().unwrap();
    if upper.next().is_none() && u32::from(first) <= u32::from(u16::MAX) {
        first as u16
    } else {
        // Windows-style single-unit comparison is not a full Unicode case fold.
        unit
    }
}

fn equal_case(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&a, &b)| uppercase(a) == uppercase(b))
}

fn translate(pattern: &[u16]) -> Vec<Token> {
    if pattern == [u16::from(b'*')] || pattern == [42, 46, 42] {
        return vec![Token::Star];
    }
    let mut tokens = Vec::with_capacity(pattern.len());
    for (index, &unit) in pattern.iter().enumerate() {
        tokens.push(match unit {
            42 => Token::Star,
            63 => Token::DosQuestion,
            46 if index != 0 && index + 1 == pattern.len() && pattern[index - 1] == 42 => {
                // Translate final '*.' to DOS_STAR, removing its final period.
                *tokens.last_mut().unwrap() = Token::DosStar;
                continue;
            }
            46 if pattern
                .get(index + 1)
                .is_some_and(|&next| next == 42 || next == 63) =>
            {
                Token::DosDot
            }
            other => Token::Literal(other),
        });
    }
    tokens
}

/// Nonrecursive NFA frontier. O(P*F) time and O(P) scratch for P tokens and F
/// filename units; each frontier contains at most P+1 states, without backtracking.
fn matches(tokens: &[Token], name: &[u16]) -> bool {
    if tokens.is_empty() || name.is_empty() {
        return false;
    }
    let last_dot = name.iter().rposition(|&unit| unit == 46);
    let mut current = vec![false; tokens.len() + 1];
    let mut next = vec![false; tokens.len() + 1];
    current[0] = true;
    for offset in 0..=name.len() {
        // Ascending epsilon closure is sufficient: every epsilon edge advances.
        for index in 0..tokens.len() {
            if current[index]
                && match tokens[index] {
                    Token::Star | Token::DosStar => true,
                    Token::DosQuestion => offset == name.len() || name[offset] == 46,
                    Token::DosDot => offset == name.len(),
                    Token::Literal(_) => false,
                }
            {
                current[index + 1] = true;
            }
        }
        if offset == name.len() {
            return current[tokens.len()];
        }
        next.fill(false);
        for (index, token) in tokens.iter().enumerate() {
            if !current[index] {
                continue;
            }
            match *token {
                Token::Star => next[index] = true,
                Token::DosStar if last_dot != Some(offset) => next[index] = true,
                Token::DosQuestion if name[offset] != 46 => next[index + 1] = true,
                Token::DosDot if name[offset] == 46 => next[index + 1] = true,
                Token::Literal(unit) if uppercase(unit) == uppercase(name[offset]) => {
                    next[index + 1] = true;
                }
                _ => {}
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
    false
}

fn missing(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

fn host_name(name: &std::ffi::OsStr) -> Result<Vec<u16>, ApiErr> {
    let text = name
        .to_str()
        .ok_or_else(|| unsupported("non-Unicode host filename"))?;
    if text.is_empty()
        || text.chars().any(|c| c < ' ' || "<>:\"|?*/\\".contains(c))
        || text.ends_with(['.', ' '])
        || dos_device(text).is_some()
    {
        return Err(unsupported(
            "host filename outside ordinary Windows pathname profile",
        ));
    }
    Ok(text.encode_utf16().collect())
}

fn entries(path: &Path) -> Result<Option<std::fs::ReadDir>, ApiErr> {
    match std::fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if missing(&error) => Ok(None),
        Err(error) => Err(unsupported(format!(
            "directory enumeration failed: {error}"
        ))),
    }
}

fn resolve_directory(drives: &DriveMap, path: &WinPath) -> Result<Option<PathBuf>, ApiErr> {
    let mut host = drives
        .root(path.drive)
        .ok_or_else(|| unsupported("unmapped drive"))?
        .to_path_buf();
    for part in &path.parts {
        let exact = host.join(part);
        match std::fs::metadata(&exact) {
            Ok(_) => {
                host = exact;
                continue;
            }
            Err(error) if missing(&error) => {}
            Err(error) => return Err(unsupported(format!("directory lookup failed: {error}"))),
        }
        let Some(children) = entries(&host)? else {
            return Ok(None);
        };
        let requested: Vec<_> = part.encode_utf16().collect();
        let mut candidate = None;
        for child in children {
            let child =
                child.map_err(|error| unsupported(format!("directory entry failed: {error}")))?;
            if equal_case(&host_name(&child.file_name())?, &requested) {
                if candidate.is_some() {
                    return Err(unsupported("ambiguous case-insensitive host directory"));
                }
                candidate = Some(child.path());
            }
        }
        let Some(found) = candidate else {
            return Ok(None);
        };
        host = found;
    }
    Ok(Some(host))
}

fn expanded(
    drives: &DriveMap,
    cwd: &[u16],
    original: &[u16],
    narrow: bool,
) -> Result<Vec<Vec<u16>>, ApiErr> {
    let units = if narrow {
        let bytes = original
            .iter()
            .map(|&unit| u8::try_from(unit))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| unsupported("narrow argument contains a non-byte unit"))?;
        codepage::decode(&bytes)
    } else {
        original.to_vec()
    };
    String::from_utf16(&units).map_err(|_| unsupported("unpaired UTF-16 in wildcard pathname"))?;
    if units.len() >= 2 && separator(units[0]) && separator(units[1]) {
        return Err(unsupported("UNC or device namespace"));
    }
    let cut = units.iter().rposition(|&unit| separator(unit)).map_or_else(
        || if units.get(1) == Some(&58) { 2 } else { 0 },
        |index| index + 1,
    );
    let (prefix, pattern) = units.split_at(cut);
    if has_wildcard(prefix) {
        return Err(unsupported("wildcard directory component"));
    }
    if pattern.is_empty()
        || pattern
            .iter()
            .any(|&u| u < 32 || matches!(u, 34 | 58 | 60 | 62 | 124))
    {
        return Err(unsupported("invalid final-component pattern"));
    }
    let directory =
        String::from_utf16(prefix).map_err(|_| unsupported("unpaired UTF-16 directory prefix"))?;
    let components = if directory.as_bytes().get(1) == Some(&b':')
        && directory.as_bytes()[0].is_ascii_alphabetic()
    {
        &directory[2..]
    } else {
        &directory
    };
    for component in components.split(['\\', '/']) {
        if component.chars().any(|c| c < ' ' || "<>:\"|?*".contains(c))
            || (!matches!(component, "" | "." | "..") && component.ends_with(['.', ' ']))
            || dos_device(component).is_some()
        {
            return Err(unsupported(
                "directory outside ordinary Windows pathname profile",
            ));
        }
    }
    let cwd =
        String::from_utf16(cwd).map_err(|_| unsupported("unpaired UTF-16 current directory"))?;
    let directory = if directory.is_empty() {
        "."
    } else {
        &directory
    };
    let windows =
        full_path(directory, &cwd).ok_or_else(|| unsupported("malformed Windows directory"))?;
    let Some(host) = resolve_directory(drives, &windows)? else {
        return Ok(vec![original.to_vec()]);
    };
    let Some(children) = entries(&host)? else {
        return Ok(vec![original.to_vec()]);
    };
    let tokens = translate(pattern);
    let mut names = Vec::new();
    for child in children {
        let child =
            child.map_err(|error| unsupported(format!("directory entry failed: {error}")))?;
        let name = host_name(&child.file_name())?;
        let metadata = child
            .metadata()
            .map_err(|error| unsupported(format!("entry metadata failed: {error}")))?;
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(unsupported("non-file/directory host object"));
        }
        if matches(&tokens, &name) {
            names.push(name);
        }
    }
    // Deterministic ordinal profile; not claimed native CRT enumeration order.
    names.sort();
    if names.is_empty() {
        return Ok(vec![original.to_vec()]);
    }
    Ok(names
        .into_iter()
        .map(|name| {
            let mut value = prefix.to_vec();
            value.extend(name);
            if narrow {
                codepage::encode(&value)
                    .into_iter()
                    .map(u16::from)
                    .collect()
            } else {
                value
            }
        })
        .collect())
}

/// Filesystem-only, no guest writes. Per argument, enumeration costs
/// O(D*P*F + D*log(D)*F) time and O(P + output) storage, excluding path lookup,
/// for D entries, P pattern units and maximum F filename units. Literal path
/// lookup can additionally enumerate every directory component on a case miss.
pub(super) fn expand(p: &Proc, args: Vec<Argument>, narrow: bool) -> Result<Vec<Vec<u16>>, ApiErr> {
    let mut result = Vec::new();
    for (index, argument) in args.into_iter().enumerate() {
        if !p.cfg.host_filesystem
            || index == 0
            || argument.leading_quote
            || !has_wildcard(&argument.units)
        {
            result.push(argument.units);
        } else {
            result.extend(expanded(&p.cfg.drives, &p.cwd, &argument.units, narrow)?);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn independent_dos_pattern_partitions() {
        for (pattern, name, expected) in [
            ("*.*", "plain", true),
            ("*.*", "a.b.c", true),
            ("*.", "plain", true),
            ("*.", "a.txt", false),
            ("*.txt", "A.TXT", true),
            ("*.txt", "txt", false),
            ("a?.txt", "a.txt", true),
            ("a?.txt", "ab.txt", true),
            ("a?.txt", "abc.txt", false),
            ("a??.txt", "a.txt", true),
            ("a??", "a", true),
            ("a??", "abc", true),
            ("a??", "abcd", false),
            ("a.*", "a", true),
            ("a.*", "a.b.c", true),
            ("a.*", "ab", false),
            ("foo?.bar", "foo.bar", true),
            ("foo?bar", "foobar", false),
            ("file.*x", "file.x", true),
            ("file.*x", "filex", false),
            ("*.?", "a", true),
            ("*.?", "a.x", true),
            // The translated Star may consume the entire name; DOS_DOT and
            // DOS_QM both take zero-width EOF transitions. This is the retained
            // .NET profile, not a native CRT one-character-extension oracle.
            ("*.?", "a.xy", true),
            ("", "x", false),
            ("*", "", false),
        ] {
            assert_eq!(
                matches(&translate(&wide(pattern)), &wide(name)),
                expected,
                "{pattern} / {name}"
            );
        }
    }

    #[test]
    fn long_frontiers_do_not_use_recursive_backtracking() {
        let pattern = format!("{}end", "*a".repeat(256));
        let name = format!("{}end", "a".repeat(256));
        assert!(matches(&translate(&wide(&pattern)), &wide(&name)));
        assert!(!matches(
            &translate(&wide(&pattern)),
            &wide(&format!("{}bad", "a".repeat(256)))
        ));
        assert!(equal_case(&wide("éÅ"), &wide("Éå")));
        assert!(!equal_case(&wide("ß"), &wide("SS")));
        assert!(equal_case(&[0xd800], &[0xd800]));
    }

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "rax-crt-glob-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn actual_mapped_directory_expansion_and_prefix_byte_encoding_all_abis() {
        let directory = Directory::new();
        let sub = directory.0.join("Sub");
        std::fs::create_dir(&sub).unwrap();
        for name in ["b.TXT", "A.txt", "é.txt", "plain", "z.bin"] {
            std::fs::write(sub.join(name), []).unwrap();
        }
        crate::user::windows::dll::crt::tests::run(|c| {
            std::sync::Arc::make_mut(&mut c.p.cfg)
                .drives
                .set('C', &directory.0);
            c.p.cwd = wide("C:\\Sub\\");
            let mut arguments = super::super::parse::arguments(&wide("program *.txt"));
            assert_eq!(
                expand(c.p, arguments.clone(), false).unwrap(),
                vec![wide("program"), wide("A.txt"), wide("b.TXT"), wide("é.txt")]
            );
            assert_eq!(
                expand(c.p, arguments.clone(), true).unwrap(),
                vec![
                    wide("program"),
                    wide("A.txt"),
                    wide("b.TXT"),
                    vec![0xe9, 46, 116, 120, 116]
                ]
            );
            arguments[1].units = wide("c:\\sUb\\*.txt");
            assert_eq!(
                expand(c.p, arguments, false).unwrap(),
                vec![
                    wide("program"),
                    wide("c:\\sUb\\A.txt"),
                    wide("c:\\sUb\\b.TXT"),
                    wide("c:\\sUb\\é.txt")
                ]
            );
            let drive_relative = super::super::parse::arguments(&wide("program c:*.txt"));
            assert_eq!(
                expand(c.p, drive_relative, false).unwrap(),
                vec![
                    wide("program"),
                    wide("c:A.txt"),
                    wide("c:b.TXT"),
                    wide("c:é.txt")
                ]
            );
            c.p.cwd = wide("C:\\");
            let relative_prefix = super::super::parse::arguments(&wide("program c:sUb\\*.txt"));
            assert_eq!(
                expand(c.p, relative_prefix, false).unwrap(),
                vec![
                    wide("program"),
                    wide("c:sUb\\A.txt"),
                    wide("c:sUb\\b.TXT"),
                    wide("c:sUb\\é.txt")
                ]
            );
            let absolute_root = super::super::parse::arguments(&wide("program c:\\*.*"));
            assert_eq!(
                expand(c.p, absolute_root, false).unwrap(),
                vec![wide("program"), wide("c:\\Sub")]
            );
            c.p.cwd = wide("C:\\Sub\\");
            let retained = super::super::parse::arguments(&wide("program missing*.txt \"*.txt\""));
            assert_eq!(
                expand(c.p, retained, false).unwrap(),
                vec![wide("program"), wide("missing*.txt"), wide("*.txt")]
            );
            let argv0 = super::super::parse::arguments(&wide("*.txt"));
            assert_eq!(expand(c.p, argv0, false).unwrap(), vec![wide("*.txt")]);
        });
    }

    #[test]
    fn unsupported_paths_and_missing_directory_are_distinct() {
        let directory = Directory::new();
        let mut drives = DriveMap::empty();
        drives.set('C', &directory.0);
        for pattern in [
            "d*\\*.txt",
            "\\\\server\\*.txt",
            "\\\\?\\C:\\*.txt",
            "C:\\*.txt:stream",
            "NUL\\*.txt",
            "folder.\\*.txt",
        ] {
            assert!(
                matches!(
                    expanded(&drives, &wide("C:\\"), &wide(pattern), false),
                    Err(ApiErr::Unimplemented(_))
                ),
                "{pattern}"
            );
        }
        assert!(expanded(&drives, &wide("C:\\"), &[0xd800, 42], false).is_err());
        assert!(expanded(&drives, &wide("C:\\"), &[256, 42], true).is_err());
        assert_eq!(
            expanded(&drives, &wide("C:\\"), &wide("absent\\*.txt"), false).unwrap(),
            vec![wide("absent\\*.txt")]
        );
    }

    #[test]
    fn closed_process_does_not_expand_host_directory_entries_all_abis() {
        crate::user::windows::dll::crt::tests::run(|c| {
            let cfg = std::sync::Arc::make_mut(&mut c.p.cfg);
            cfg.host_filesystem = false;
            cfg.drives.set('C', Path::new(env!("CARGO_MANIFEST_DIR")));
            c.p.cwd = wide("C:\\");
            let args = vec![
                Argument {
                    units: wide("program"),
                    leading_quote: false,
                },
                Argument {
                    units: wide("*.toml"),
                    leading_quote: false,
                },
            ];
            assert_eq!(
                expand(c.p, args, false).unwrap(),
                vec![wide("program"), wide("*.toml")]
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_host_names_fail_without_lossy_fabrication() {
        use std::os::unix::ffi::OsStringExt;
        // Some Unix filesystems reject such names at creation. Test the exact
        // OsStr boundary used for every enumerated child without requiring it.
        let name = std::ffi::OsString::from_vec(vec![0xff]);
        assert!(matches!(host_name(&name), Err(ApiErr::Unimplemented(_))));
    }
}
