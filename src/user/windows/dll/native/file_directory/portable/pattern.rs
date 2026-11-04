//! Raw NT expressions: ordinary '*'/'?' and DOS_STAR/DOS_QM/DOS_DOT.
//! Win32's '*.*' translation belongs to the caller, not this NT boundary.

fn uppercase(unit: u16) -> u16 {
    let Some(character) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut upper = character.to_uppercase();
    let first = upper.next().unwrap();
    if upper.next().is_none() && u32::from(first) <= u32::from(u16::MAX) {
        first as u16
    } else {
        unit
    }
}

/// Nonrecursive NFA: O(pattern_units * name_units) time and O(pattern_units)
/// storage. Windows hosts delegate casing and matching to the installed FS.
pub(super) fn matches(pattern: &[u16], name: &[u16]) -> bool {
    let last_dot = name.iter().rposition(|&unit| unit == 46);
    let mut current = vec![false; pattern.len() + 1];
    let mut next = vec![false; pattern.len() + 1];
    current[0] = true;
    for offset in 0..=name.len() {
        for index in 0..pattern.len() {
            if current[index]
                && match pattern[index] {
                    42 | 60 => true,
                    62 => offset == name.len() || name[offset] == 46,
                    34 => offset == name.len(),
                    _ => false,
                }
            {
                current[index + 1] = true;
            }
        }
        if offset == name.len() {
            return current[pattern.len()];
        }
        next.fill(false);
        for (index, &unit) in pattern.iter().enumerate() {
            if !current[index] {
                continue;
            }
            match unit {
                42 => next[index] = true,
                60 if last_dot != Some(offset) => next[index] = true,
                63 => next[index + 1] = true,
                62 if name[offset] != 46 => next[index + 1] = true,
                34 if name[offset] == 46 => next[index + 1] = true,
                other if uppercase(other) == uppercase(name[offset]) => next[index + 1] = true,
                _ => {}
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_nt_patterns_keep_the_observed_dot_and_case_semantics() {
        for (pattern, name, expected) in [
            ("*", "empty", true),
            ("*.*", "empty", false),
            ("*.txt", "alpha.txt", true),
            ("ALPHA.TXT", "alpha.txt", true),
            ("a?pha.txt", "alpha.txt", true),
            ("<.txt", "alpha.txt", true),
            ("*.*", ".", true),
            ("*.*", "..", true),
            ("*.txt", "long supplementary 🚀 filename.txt", true),
            ("absent.xyz", "alpha.txt", false),
            ("a?pha.txt", "apha.txt", false),
        ] {
            assert_eq!(
                matches(
                    &pattern.encode_utf16().collect::<Vec<_>>(),
                    &name.encode_utf16().collect::<Vec<_>>()
                ),
                expected,
                "{pattern:?}/{name:?}"
            );
        }
    }
}
