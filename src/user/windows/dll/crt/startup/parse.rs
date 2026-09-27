//! UTF-16 Microsoft C command-line parsing, without Unicode normalization.
//!
//! Primary contract: Microsoft "Parsing C command-line arguments", retained at
//! docs/specifications/windows/crt-initializers/microsoft/
//! parsing-c-command-line-arguments.md (cpp-docs f2355df9f7136d8a2097193fc507882a7caeb5f5).
//! argv0 has its own quote-toggle rule; the later backslash rules do not apply.
//!
//! Assumption A1: raw empty input yields one empty argv0; leading space/tab
//! yields empty argv0 followed by the normal arguments. Basis: an explicit
//! personality choice where the public parsing page does not settle the raw
//! empty/leading-whitespace input. Dependent result: the corresponding boundary
//! tests. Stress test: empty, NUL-first, whitespace-only, and leading tab input.
//! Falsification probe: record argv from these raw inputs on a pinned native
//! CRT build, separating OS command-line substitution from this parser.
//! Status: retained profile; exact native equivalence unknown.

const QUOTE: u16 = b'"' as u16;
const SLASH: u16 = b'\\' as u16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Argument {
    pub(super) units: Vec<u16>,
    /// Whether the first raw unit of this argument was a quote. This is only
    /// input metadata for the caller; this module does not expand wildcards.
    pub(super) leading_quote: bool,
}

fn whitespace(unit: u16) -> bool {
    matches!(unit, 0x20 | 0x09)
}

/// Parse up to the first NUL. O(n) time and O(n + a) output storage for n raw
/// UTF-16 units and a arguments; O(1) auxiliary state apart from that output.
/// Surrogate pairs and unpaired surrogates remain unchanged raw code units.
pub(super) fn arguments(input: &[u16]) -> Vec<Argument> {
    let input = &input[..input
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(input.len())];
    let mut cursor = 0;
    let mut quoted = false;
    let mut first = Argument {
        units: Vec::new(),
        leading_quote: input.first() == Some(&QUOTE),
    };
    while cursor < input.len() {
        let unit = input[cursor];
        if unit == QUOTE {
            quoted = !quoted;
        } else if !quoted && whitespace(unit) {
            break;
        } else {
            first.units.push(unit);
        }
        cursor += 1;
    }
    let mut result = vec![first];
    loop {
        while cursor < input.len() && whitespace(input[cursor]) {
            cursor += 1;
        }
        if cursor == input.len() {
            break;
        }
        let mut argument = Argument {
            units: Vec::new(),
            leading_quote: input[cursor] == QUOTE,
        };
        quoted = false;
        while cursor < input.len() {
            let slash_start = cursor;
            while cursor < input.len() && input[cursor] == SLASH {
                cursor += 1;
            }
            let slashes = cursor - slash_start;
            if cursor < input.len() && input[cursor] == QUOTE {
                argument
                    .units
                    .extend(std::iter::repeat_n(SLASH, slashes / 2));
                if slashes & 1 != 0 {
                    argument.units.push(QUOTE);
                    cursor += 1;
                } else if quoted && input.get(cursor + 1) == Some(&QUOTE) {
                    // A quote pair inside a quoted region emits one literal
                    // quote, leaving the quoted region open.
                    argument.units.push(QUOTE);
                    cursor += 2;
                } else {
                    quoted = !quoted;
                    cursor += 1;
                }
            } else {
                argument.units.extend(std::iter::repeat_n(SLASH, slashes));
                if cursor == input.len() || (!quoted && whitespace(input[cursor])) {
                    break;
                }
                argument.units.push(input[cursor]);
                cursor += 1;
            }
        }
        result.push(argument);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn units(text: &str) -> Vec<Vec<u16>> {
        arguments(&wide(text))
            .into_iter()
            .map(|argument| argument.units)
            .collect()
    }

    fn check(text: &str, expected: &[&str]) {
        assert_eq!(
            units(text),
            expected.iter().map(|value| wide(value)).collect::<Vec<_>>(),
            "raw command line: {text:?}"
        );
    }

    #[test]
    fn primary_document_examples_are_independent_literal_expectations() {
        // The primary table describes argv1 onwards; prepend a simple argv0.
        check(r#"program "a b c" d e"#, &["program", "a b c", "d", "e"]);
        check(
            r#"program "ab\"c" "\\" d"#,
            &["program", "ab\"c", "\\", "d"],
        );
        check(
            r#"program a\\\b d"e f"g h"#,
            &["program", r"a\\\b", "de fg", "h"],
        );
        check(r#"program a\\\"b c d"#, &["program", r#"a\"b"#, "c", "d"]);
        check(
            r#"program a\\\\"b c" d e"#,
            &["program", r"a\\b c", "d", "e"],
        );
        check(r#"program a"b"" c d"#, &["program", r#"ab" c d"#]);
    }

    #[test]
    fn argv0_quotes_toggle_but_backslashes_are_always_literal() {
        check(
            r#""C:\Program Files\app.exe" tail"#,
            &[r"C:\Program Files\app.exe", "tail"],
        );
        check(r#"ab\"cd ef" tail"#, &[r"ab\cd ef", "tail"]);
        check(r#""a""b" tail"#, &["ab", "tail"]);
        check(r#"C:\"open ended path"#, &[r"C:\open ended path"]);
        check(r#""two words"suffix next"#, &["two wordssuffix", "next"]);
    }

    #[test]
    fn quoted_double_quotes_empty_and_unclosed_arguments() {
        check(r#"p "" "" last"#, &["p", "", "", "last"]);
        check(r#"p "red""blue" end"#, &["p", "red\"blue", "end"]);
        check(r#"p """ end"#, &["p", "\" end"]);
        check(r#"p """" end"#, &["p", "\"", "end"]);
        check(r#"p a"b c"d tail"#, &["p", "ab cd", "tail"]);
        check(
            r#"p head "unfinished tail"#,
            &["p", "head", "unfinished tail"],
        );
        check(r#"p "a^b" ^x ^"y z""#, &["p", "a^b", "^x", "^y z"]);
    }

    #[test]
    fn backslash_quote_parity_is_checked_at_small_and_long_boundaries() {
        for count in [0, 1, 2, 3, 4, 5, 31, 32, 255, 256, 4095, 4096] {
            let mut raw = wide("p item");
            raw.extend(std::iter::repeat_n(SLASH, count));
            raw.extend(wide("\" tail"));
            let mut expected = wide("item");
            expected.extend(std::iter::repeat_n(SLASH, count / 2));
            let mut values = vec![wide("p")];
            if count & 1 == 0 {
                // The unclosed quote includes the space and following text.
                expected.extend(wide(" tail"));
                values.push(expected);
            } else {
                expected.push(QUOTE);
                values.push(expected);
                values.push(wide("tail"));
            }
            assert_eq!(
                arguments(&raw)
                    .into_iter()
                    .map(|a| a.units)
                    .collect::<Vec<_>>(),
                values,
                "slashes={count}"
            );
        }
    }

    #[test]
    fn literal_and_trailing_backslashes_are_not_discarded() {
        check(r"p a\\z \ tail\\", &["p", r"a\\z", r"\", r"tail\\"]);
        check(r#"p "with space\\" next"#, &["p", "with space\\", "next"]);
        check(r#"p "unfinished\\"#, &["p", r"unfinished\\"]);
    }

    #[test]
    fn only_space_and_tab_are_delimiters_and_nul_ends_input() {
        check("p\tone  two\t\tthree ", &["p", "one", "two", "three"]);
        check("p a\nb a\rb a\u{a0}b", &["p", "a\nb", "a\rb", "a\u{a0}b"]);
        check("p first\0 ignored \"tail\"", &["p", "first"]);
        check("p \"quoted\0 ignored", &["p", "quoted"]);
    }

    #[test]
    fn empty_and_leading_whitespace_follow_the_explicit_profile() {
        check("", &[""]);
        check("\0ignored", &[""]);
        check(" \t  ", &[""]);
        check(" p one", &["", "p", "one"]);
        check("\t\"two words\" tail", &["", "two words", "tail"]);
        check("\"\"", &[""]);
    }

    #[test]
    fn first_raw_quote_is_metadata_not_a_globbing_or_quote_presence_test() {
        let values = arguments(&wide(r#""p q" "*.c" prefix"*.h" \".x" "#));
        assert_eq!(
            values
                .iter()
                .map(|argument| argument.leading_quote)
                .collect::<Vec<_>>(),
            [true, true, false, false]
        );
        assert_eq!(
            values
                .iter()
                .map(|argument| argument.units.clone())
                .collect::<Vec<_>>(),
            [wide("p q"), wide("*.c"), wide("prefix*.h"), wide("\".x ")]
        );
        assert!(!arguments(&[])[0].leading_quote);
        assert!(!arguments(&wide(" \t\"x\""))[0].leading_quote);
    }

    #[test]
    fn utf16_units_survive_without_lossy_conversion_or_normalization() {
        let raw = [
            0xd800, 0x20, QUOTE, 0xdc00, 0xd83d, 0xde00, QUOTE, 0x20, 0x0065, 0x0301,
        ];
        let values = arguments(&raw);
        assert_eq!(values[0].units, [0xd800]);
        assert_eq!(values[1].units, [0xdc00, 0xd83d, 0xde00]);
        assert_eq!(values[2].units, [0x0065, 0x0301]);
        assert!(values[1].leading_quote);
    }

    /// Independent canonical encoder used only for an additional inverse
    /// property. The primary literal tests above remain the semantic oracle.
    fn quote(units: &[u16]) -> Vec<u16> {
        let mut encoded = vec![QUOTE];
        let mut slashes = 0;
        for &unit in units {
            if unit == SLASH {
                slashes += 1;
                continue;
            }
            encoded.extend(std::iter::repeat_n(
                SLASH,
                if unit == QUOTE {
                    2 * slashes + 1
                } else {
                    slashes
                },
            ));
            encoded.push(unit);
            slashes = 0;
        }
        encoded.extend(std::iter::repeat_n(SLASH, 2 * slashes));
        encoded.push(QUOTE);
        encoded
    }

    #[test]
    fn adversarial_short_strings_roundtrip_through_a_separate_encoder() {
        let alphabet = [0x0061, SLASH, QUOTE, 0x20, 0x09, 0xd800, 0xdc00];
        // Every sequence of length 0..4: 1+7+49+343+2401 = 2801 inputs.
        let mut tested = 0;
        for length in 0..=4_u32 {
            for mut index in 0..7_usize.pow(length) {
                let mut original = Vec::new();
                for _ in 0..length {
                    original.push(alphabet[index % alphabet.len()]);
                    index /= alphabet.len();
                }
                let mut raw = wide("program ");
                raw.extend(quote(&original));
                raw.extend(wide(" tail"));
                let parsed = arguments(&raw);
                assert_eq!(parsed.len(), 3);
                assert_eq!(parsed[0].units, wide("program"));
                assert_eq!(parsed[1].units, original);
                assert!(parsed[1].leading_quote);
                assert_eq!(parsed[2].units, wide("tail"));
                tested += 1;
            }
        }
        assert_eq!(tested, 2801);
    }
}
