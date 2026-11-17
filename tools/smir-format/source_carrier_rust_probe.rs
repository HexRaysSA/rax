//! Independent typed ordered payload oracle; never an executable-module loader.
#[allow(dead_code)]
#[path = "../../src/smir/portable/mod.rs"]
mod framing;
include!(env!("SMIR_SOURCE_CARRIER_SCHEMA"));

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

fn main() {
    use std::io::Read;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 || args[0] != "--record" { std::process::exit(3); }
    let Some(requested) = args[1].to_str() else { std::process::exit(3); };
    let Ok(file) = std::fs::File::open(&args[2]) else { std::process::exit(3); };
    let limits = framing::records::Limits { depth: 128, ..framing::records::Limits::default() };
    let mut bytes = Vec::new();
    if file.take(limits.bytes as u64 + 1).read_to_end(&mut bytes).is_err() { std::process::exit(3); }
    let result = (|| {
        let kind = if requested == "root3" {
            let word = bytes.get(..4).ok_or(framing::records::Error("V3-REVISION-TRUNCATED"))?;
            match u32::from_le_bytes(word.try_into().unwrap()) {
                2 => "execution_functions", 3 => "execution_functions_v3",
                _ => return Err(framing::records::Error("V3-REVISION")),
            }
        } else { requested };
        let codec = framing::records::Codec::new_refined(carrier_schema(), limits, carrier_refinements())?;
        let value = codec.decode(kind, &bytes)?;
        if codec.encode(kind, &value)? != bytes { return Err(framing::records::Error("WIRE-REENCODE")); }
        Ok(value)
    })();
    match result {
        Ok(value) => { let mut text = String::new(); record_json(&value, &mut text); println!("{text}"); }
        Err(error) => { println!("{error}"); std::process::exit(2); }
    }
}
