//! Run one function of a portable SMIR object in the interpreter.
//!
//! ```text
//! smir-run OBJECT --entry-function ID [--argument-bits HEX]... [--fuel N] [--max-frames N]
//! ```
//!
//! Each `--argument-bits` is one integer argument as little-endian hex of
//! exactly its type's byte size. The result is one line of JSON on stdout.
//! Exit status: 0 when the program ran (whatever its outcome), 1 when the
//! object or the entry request was rejected, 2 for a usage error.

use rax_smir_portable::interp::{Exit, Fault, Outcome, Policy, run};
use rax_smir_portable::ir::{Module, Type, Value};
use rax_smir_portable::{Error, Limits};
use serde_json::{Value as Json, json};
use std::process::ExitCode;

const USAGE: &str = "usage: smir-run OBJECT --entry-function ID \
[--argument-bits HEX]... [--fuel N] [--max-frames N]";

struct Request {
    object: String,
    entry: u32,
    arguments: Vec<String>,
    policy: Policy,
}

fn parse(mut args: impl Iterator<Item = String>) -> Option<Request> {
    let mut object = None;
    let mut entry = None;
    let mut arguments = Vec::new();
    let mut policy = Policy::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--entry-function" => entry = Some(args.next()?.parse().ok()?),
            "--argument-bits" => arguments.push(args.next()?),
            "--fuel" => policy.fuel = args.next()?.parse().ok()?,
            "--max-frames" => policy.max_frames = args.next()?.parse().ok()?,
            _ if arg.starts_with("--") || object.is_some() => return None,
            _ => object = Some(arg),
        }
    }
    Some(Request {
        object: object?,
        entry: entry?,
        arguments,
        policy,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn rejected(class: &str, code: &str, detail: &str) -> (Json, u8) {
    (
        json!({"status": "rejected", "class": class, "code": code, "detail": detail}),
        1,
    )
}

fn error(diagnostic: &Error) -> (Json, u8) {
    rejected(
        diagnostic.class().as_str(),
        diagnostic.code(),
        diagnostic.context(),
    )
}

/// Decode little-endian hex for an integer of `bits` width.
fn argument(text: &str, bits: u32) -> Option<Value> {
    let size = bits.div_ceil(8) as usize;
    if text.len() != 2 * size || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut value = 0_u128;
    for position in 0..size {
        let byte = u8::from_str_radix(text.get(2 * position..2 * position + 2)?, 16).ok()?;
        value |= u128::from(byte) << (8 * position);
    }
    (bits == 128 || value >> bits == 0).then_some(Value::Int(value))
}

fn result(value: Value, bits: u32) -> Json {
    match value {
        Value::Int(payload) => {
            json!({"bits_le": hex(&payload.to_le_bytes()[..bits.div_ceil(8) as usize])})
        }
        Value::Poison => json!({"state": "poison"}),
        Value::Undef => json!({"state": "undef"}),
        // The entry signature was checked to return integers only.
        Value::DataPtr(_) | Value::CodeAddress(_) | Value::CodePtr(_) => {
            json!({"state": "pointer"})
        }
    }
}

fn located(status: &str, fault: &Fault, steps: u64) -> Json {
    json!({
        "status": status, "code": fault.code, "steps": steps,
        "function": fault.function, "block": fault.block, "operation": fault.operation,
    })
}

fn execute(request: &Request) -> (Json, u8) {
    let bytes = match std::fs::read(&request.object) {
        Ok(bytes) => bytes,
        Err(failure) => return rejected("io", "OBJECT_READ", &failure.to_string()),
    };
    let module = match Module::load(&bytes, Limits::default()) {
        Ok(module) => module,
        Err(diagnostic) => return error(&diagnostic),
    };
    let Some(entry) = module.function(request.entry) else {
        return rejected("request", "ENTRY_FUNCTION", "no such function");
    };
    let signature = module.signature(entry);
    let width = |ty| match module.ty(ty) {
        Type::Int { bits } => Some(*bits),
        _ => None,
    };
    let (Some(params), Some(results)) = (
        signature
            .params()
            .iter()
            .map(|ty| width(*ty))
            .collect::<Option<Vec<u32>>>(),
        signature
            .results()
            .iter()
            .map(|ty| width(*ty))
            .collect::<Option<Vec<u32>>>(),
    ) else {
        return rejected(
            "request",
            "ENTRY_SIGNATURE",
            "entry parameters and results must be integers",
        );
    };
    if params.len() != request.arguments.len() {
        return rejected(
            "request",
            "ARGUMENT_ARITY",
            "argument count differs from the signature",
        );
    }
    let Some(arguments) = request
        .arguments
        .iter()
        .zip(&params)
        .map(|(text, bits)| argument(text, *bits))
        .collect::<Option<Vec<Value>>>()
    else {
        return rejected(
            "request",
            "ARGUMENT_BITS",
            "malformed or out-of-range argument",
        );
    };
    let Outcome { exit, steps } = match run(&module, entry, &arguments, request.policy) {
        Ok(outcome) => outcome,
        Err(diagnostic) => return error(&diagnostic),
    };
    let report = match exit {
        Exit::Return(values) => json!({
            "status": "return",
            "content_digest": hex(&module.identity()),
            "entry_function": request.entry,
            "steps": steps,
            "values": values.iter().zip(&results).map(|(value, bits)| result(*value, *bits)).collect::<Vec<_>>(),
        }),
        Exit::Trap(fault) => located("trap", &fault, steps),
        Exit::LanguageUb(fault) => located("language_ub", &fault, steps),
        Exit::Resource(reason) => json!({"status": "resource", "code": reason, "steps": steps}),
    };
    (report, 0)
}

fn main() -> ExitCode {
    let Some(request) = parse(std::env::args().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (report, status) = execute(&request);
    println!("{report}");
    ExitCode::from(status)
}
