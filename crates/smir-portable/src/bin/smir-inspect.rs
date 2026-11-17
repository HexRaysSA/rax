//! Inspection only. JSON results cannot create runtime authority.

use rax_smir_portable::{
    Error, Limits, VerifiedObject, canonical_bytes, decode_object, verify_object,
};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::process::ExitCode;

fn hex(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.write_all(&[DIGITS[(byte >> 4) as usize], DIGITS[(byte & 15) as usize]])?;
    }
    Ok(())
}

fn reject(out: &mut impl Write, class: &str, code: &str) -> io::Result<()> {
    serde_json::to_writer(
        &mut *out,
        &serde_json::json!({"status":"rejected","class":class,"code":code}),
    )?;
    out.write_all(b"\n")?;
    out.flush()
}

fn error(out: &mut impl Write, diagnostic: Error) -> io::Result<()> {
    eprintln!("{diagnostic}");
    reject(out, diagnostic.class().as_str(), diagnostic.code())
}

fn verified(out: &mut impl Write, object: &VerifiedObject) -> io::Result<u8> {
    // Encode every source contract before emitting success. Rendering is a
    // separately bounded inspection stage, not a new semantic proof.
    let mut entries = Vec::new();
    let mut output_bytes = 0usize;
    for view in object.requirements().iter() {
        let length = match view.encoded_length() {
            Ok(length) => length,
            Err(diagnostic) => {
                error(out, diagnostic)?;
                return Ok(1);
            }
        };
        output_bytes = match output_bytes
            .checked_add(length)
            .filter(|bytes| *bytes <= Limits::default().max_derived_bytes)
        {
            Some(bytes) => bytes,
            None => {
                reject(out, "resource", "P2_OUTPUT_LIMIT")?;
                return Ok(1);
            }
        };
        let bytes = match view.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(diagnostic) => {
                error(out, diagnostic)?;
                return Ok(1);
            }
        };
        entries.push((view, bytes));
    }
    out.write_all(b"{\"status\":\"verified-object\",\"identity\":\"")?;
    hex(out, &object.identity())?;
    out.write_all(b"\",\"executable_admitted\":false,\"required_admission\":{\"format\":\"smir-required-admission-v1\",\"entries\":[")?;
    for (index, (view, bytes)) in entries.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        write!(
            out,
            "{{\"kind\":\"{}\",\"section\":{},\"path\":[],\"record_type\":\"{}\",\"canonical_record_hex\":\"",
            view.kind(),
            view.section(),
            view.record_type()
        )?;
        hex(out, bytes)?;
        out.write_all(b"\"}")?;
    }
    out.write_all(b"]}}\n")?;
    out.flush()?;
    Ok(0)
}

fn inspect() -> Result<u8, io::Error> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 || !matches!(arguments[0].to_str(), Some("roundtrip" | "verify")) {
        eprintln!("usage: smir-inspect roundtrip|verify PATH");
        return Ok(2);
    }
    let limits = Limits::default();
    let mut file = File::open(&arguments[1])?;
    let mut out = BufWriter::new(io::stdout().lock());
    let length = file.metadata()?.len();
    if length > limits.max_object_bytes as u64 {
        reject(&mut out, "resource", "P2_OBJECT_LIMIT")?;
        return Ok(1);
    }
    let mut input = Vec::new();
    input
        .try_reserve_exact(length as usize)
        .map_err(|_| io::Error::other("input allocation unavailable"))?;
    let mut chunk = [0u8; 8192];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if input
            .len()
            .checked_add(count)
            .is_none_or(|length| length > limits.max_object_bytes)
        {
            reject(&mut out, "resource", "P2_OBJECT_LIMIT")?;
            return Ok(1);
        }
        input
            .try_reserve_exact(count)
            .map_err(|_| io::Error::other("input allocation unavailable"))?;
        input.extend_from_slice(&chunk[..count]);
    }
    if arguments[0] == "verify" {
        match verify_object(&input, limits) {
            Ok(object) => return verified(&mut out, &object),
            Err(diagnostic) => {
                error(&mut out, diagnostic)?;
                return Ok(1);
            }
        }
    }
    let parsed = match decode_object(&input, limits) {
        Ok(object) => object,
        Err(diagnostic) => {
            error(&mut out, diagnostic)?;
            return Ok(1);
        }
    };
    let canonical = match canonical_bytes(&parsed) {
        Ok(bytes) => bytes,
        Err(diagnostic) => {
            error(&mut out, diagnostic)?;
            return Ok(1);
        }
    };
    out.write_all(b"{\"status\":\"decoded-object\",\"identity\":\"")?;
    hex(&mut out, &parsed.identity())?;
    out.write_all(b"\",\"executable_admitted\":false,\"canonical_hex\":\"")?;
    hex(&mut out, &canonical)?;
    out.write_all(b"\"}\n")?;
    out.flush()?;
    Ok(0)
}

fn main() -> ExitCode {
    match inspect() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("smir-inspect: {error}");
            ExitCode::from(2)
        }
    }
}
