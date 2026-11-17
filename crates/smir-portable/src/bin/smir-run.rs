//! Run functions of a portable SMIR object in the interpreter.
//!
//! ```text
//! smir-run OBJECT --entry-function ID [--argument-bits HEX]... [--fuel N] [--max-frames N]
//! smir-run OBJECT --batch [--fuel N] [--max-frames N] < cases.json
//! ```
//!
//! Each `--argument-bits` is one integer argument as little-endian hex of
//! exactly its type's byte size. The result is one line of JSON on stdout.
//! Exit status: 0 when the program ran (whatever its outcome), 1 when the
//! object or the entry request was rejected, 2 for a usage error.
//!
//! `--batch` loads the object once and reads a JSON array of
//! `{"function": ID, "arguments": [HEX, ...]}` from stdin. It prints a JSON
//! array with one report per case, in order. A case whose request is rejected
//! gets a `rejected` report and does not stop the batch; the exit status is 0
//! once the object has loaded and the input has parsed.

use rax_smir_portable::interp::{Exit, Fault, Outcome, Policy, run};
use rax_smir_portable::ir::{Module, Type, Value};
use rax_smir_portable::{Error, Limits};
use serde_json::{Value as Json, json};
use std::io::Read;
use std::process::ExitCode;

const USAGE: &str = "usage: smir-run OBJECT --entry-function ID \
[--argument-bits HEX]... [--fuel N] [--max-frames N]\n       \
smir-run OBJECT --batch [--fuel N] [--max-frames N] < cases.json";

/// Largest batch description read from stdin.
const MAX_BATCH_BYTES: u64 = 256 * 1024 * 1024;

enum Mode {
    Single { entry: u32, arguments: Vec<String> },
    Batch,
}

struct Request {
    object: String,
    mode: Mode,
    policy: Policy,
}

fn parse(mut args: impl Iterator<Item = String>) -> Option<Request> {
    let mut object = None;
    let mut entry = None;
    let mut batch = false;
    let mut arguments = Vec::new();
    let mut policy = Policy::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--entry-function" => entry = Some(args.next()?.parse().ok()?),
            "--argument-bits" => arguments.push(args.next()?),
            "--batch" => batch = true,
            "--fuel" => policy.fuel = args.next()?.parse().ok()?,
            "--max-frames" => policy.max_frames = args.next()?.parse().ok()?,
            _ if arg.starts_with("--") || object.is_some() => return None,
            _ => object = Some(arg),
        }
    }
    let mode = match (batch, entry) {
        (true, None) if arguments.is_empty() => Mode::Batch,
        (false, Some(entry)) => Mode::Single { entry, arguments },
        _ => return None,
    };
    Some(Request {
        object: object?,
        mode,
        policy,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn rejected(class: &str, code: &str, detail: &str) -> Json {
    json!({"status": "rejected", "class": class, "code": code, "detail": detail})
}

fn error(diagnostic: &Error) -> Json {
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

fn load(object: &str) -> Result<Module, Json> {
    let bytes = std::fs::read(object)
        .map_err(|failure| rejected("io", "OBJECT_READ", &failure.to_string()))?;
    Module::load(&bytes, Limits::default()).map_err(|diagnostic| error(&diagnostic))
}

/// Run one function. `Err` is a rejected request; nothing ran.
fn case(
    module: &Module,
    function: u32,
    arguments: &[String],
    policy: Policy,
) -> Result<Json, Json> {
    let entry = module
        .function(function)
        .ok_or_else(|| rejected("request", "ENTRY_FUNCTION", "no such function"))?;
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
        return Err(rejected(
            "request",
            "ENTRY_SIGNATURE",
            "entry parameters and results must be integers",
        ));
    };
    if params.len() != arguments.len() {
        return Err(rejected(
            "request",
            "ARGUMENT_ARITY",
            "argument count differs from the signature",
        ));
    }
    let values = arguments
        .iter()
        .zip(&params)
        .map(|(text, bits)| argument(text, *bits))
        .collect::<Option<Vec<Value>>>()
        .ok_or_else(|| {
            rejected(
                "request",
                "ARGUMENT_BITS",
                "malformed or out-of-range argument",
            )
        })?;
    let Outcome { exit, steps } =
        run(module, entry, &values, policy).map_err(|diagnostic| error(&diagnostic))?;
    Ok(match exit {
        Exit::Return(values) => json!({
            "status": "return",
            "content_digest": hex(&module.identity()),
            "entry_function": function,
            "steps": steps,
            "values": values.iter().zip(&results).map(|(value, bits)| result(*value, *bits)).collect::<Vec<_>>(),
        }),
        Exit::Trap(fault) => located("trap", &fault, steps),
        Exit::LanguageUb(fault) => located("language_ub", &fault, steps),
        Exit::Resource(reason) => json!({"status": "resource", "code": reason, "steps": steps}),
    })
}

/// Parse one batch entry into a function identifier and its arguments.
fn batch_entry(entry: &Json) -> Option<(u32, Vec<String>)> {
    let function = u32::try_from(entry.get("function")?.as_u64()?).ok()?;
    let arguments = entry
        .get("arguments")?
        .as_array()?
        .iter()
        .map(|argument| argument.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()?;
    Some((function, arguments))
}

fn batch(module: &Module, policy: Policy) -> Result<Json, Json> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_BATCH_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|failure| rejected("io", "BATCH_READ", &failure.to_string()))?;
    if input.len() as u64 > MAX_BATCH_BYTES {
        return Err(rejected(
            "request",
            "BATCH_SIZE",
            "batch description is too large",
        ));
    }
    let cases: Vec<Json> = serde_json::from_slice(&input)
        .map_err(|failure| rejected("request", "BATCH_JSON", &failure.to_string()))?;
    Ok(Json::Array(
        cases
            .iter()
            .map(|entry| match batch_entry(entry) {
                Some((function, arguments)) => {
                    case(module, function, &arguments, policy).unwrap_or_else(|rejection| rejection)
                }
                None => rejected("request", "BATCH_ENTRY", "expected {function, arguments}"),
            })
            .collect(),
    ))
}

fn execute(request: &Request) -> Result<Json, Json> {
    let module = load(&request.object)?;
    match &request.mode {
        Mode::Single { entry, arguments } => case(&module, *entry, arguments, request.policy),
        Mode::Batch => batch(&module, request.policy),
    }
}

fn main() -> ExitCode {
    let Some(request) = parse(std::env::args().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (report, status) = match execute(&request) {
        Ok(report) => (report, 0),
        Err(rejection) => (rejection, 1),
    };
    println!("{report}");
    ExitCode::from(status)
}
