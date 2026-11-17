//! Standalone cross-codec probe. This is not a runtime execution tool.
// This private probe exercises framing, while the imported public module also
// contains independent arithmetic witnesses used by a different test harness.
#[allow(dead_code)]
#[path = "../../src/smir/portable/mod.rs"]
mod framing;

#[cfg(smir_record_schema)]
include!(env!("SMIR_RECORD_TEST_SCHEMA"));

#[cfg(smir_record_schema)]
fn record_json(value: &framing::records::Value, output: &mut String) {
    use framing::records::Value;
    use std::fmt::Write;
    fn quote(text: &str, output: &mut String) {
        use std::fmt::Write;
        output.push('"');
        for character in text.chars() {
            match character {
                '"' | '\\' => {
                    output.push('\\');
                    output.push(character);
                }
                '\0'..='\u{1f}' => {
                    write!(output, "\\u{:04x}", character as u32).unwrap();
                }
                _ => output.push(character),
            }
        }
        output.push('"');
    }
    match value {
        Value::Unsigned(number) => write!(output, "{number}").unwrap(),
        Value::Signed(number) => write!(output, "{number}").unwrap(),
        Value::Boolean(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Text(text) => quote(text, output),
        Value::Bytes(bytes) => {
            output.push('"');
            for byte in bytes {
                write!(output, "{byte:02x}").unwrap();
            }
            output.push('"');
        }
        Value::Option(None) => output.push_str("null"),
        Value::Option(Some(value)) => {
            output.push_str("{\"some\":");
            record_json(value, output);
            output.push('}');
        }
        Value::Vector(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                record_json(value, output);
            }
            output.push(']');
        }
        Value::Record(fields) => {
            output.push('{');
            for (index, (name, value)) in fields.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                quote(name, output);
                output.push(':');
                record_json(value, output);
            }
            output.push('}');
        }
    }
}

#[cfg(smir_record_schema)]
fn record_probe(kind: &str, path: &std::ffi::OsStr) -> i32 {
    use std::io::Read;
    let Ok(source) = std::fs::File::open(path) else {
        return 3;
    };
    let limits = framing::records::Limits::default();
    let mut bytes = Vec::new();
    if source
        .take(limits.bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return 3;
    }
    let checked = (|| {
        let codec = framing::records::Codec::new(smir_test_schema(), limits)?;
        let value = codec.decode(kind, &bytes)?;
        let encoded = codec.encode(kind, &value)?;
        if encoded != bytes {
            return Err(framing::records::Error("WIRE-REENCODE"));
        }
        Ok(value)
    })();
    match checked {
        Ok(value) => {
            let mut json = String::new();
            record_json(&value, &mut json);
            println!("{json}");
            0
        }
        Err(error) => {
            println!("{error}");
            2
        }
    }
}

fn main() {
    use std::io::Read;

    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(smir_record_schema)]
    if arguments.len() == 3 && arguments[0] == "--record" {
        let Some(kind) = arguments[1].to_str() else {
            std::process::exit(3)
        };
        std::process::exit(record_probe(kind, &arguments[2]));
    }
    let candidate = arguments.len() == 2 && arguments[0] == "--candidate";
    if arguments.len() != 1 && !candidate {
        std::process::exit(3);
    }
    let path = &arguments[usize::from(candidate)];
    let Ok(source) = std::fs::File::open(path) else {
        std::process::exit(3);
    };
    let limits = framing::DecodeLimits::default();
    let mut bytes = Vec::new();
    if source
        .take(limits.max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        std::process::exit(3);
    }
    let decoded = if candidate {
        framing::decode_candidate(&bytes, limits)
            .map(|module| (module.kind, module.entry_function, module.sections))
    } else {
        framing::decode(&bytes, limits)
            .map(|module| (module.kind, module.entry_function, module.sections))
    };
    match decoded {
        Ok((module_kind, entry_function, sections)) => {
            let kind = match module_kind {
                framing::ModuleKind::Object => 1,
                framing::ModuleKind::Image => 2,
            };
            println!("OK {kind} {}", entry_function.unwrap_or(framing::NO_ENTRY));
            for section in sections {
                print!("{} {} ", section.kind, u8::from(section.required));
                for byte in section.bytes {
                    print!("{byte:02x}");
                }
                println!();
            }
        }
        Err(error) => {
            println!("{}", error.code());
            std::process::exit(2);
        }
    }
}
