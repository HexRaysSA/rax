//! Isolated two-frame JSON reference protocol; never an execution loader.
mod canonical;
mod graph;

use canonical::{Budget, Error, Limits, Result, object, parse, resource, semantic};
use serde_json::Value;
use std::io::{Read, Write};

fn run(input: &mut impl Read) -> Result<Value> {
    let mut header = Vec::with_capacity(1024);
    loop {
        let mut byte = [0u8];
        let read = input.read(&mut byte).map_err(|_| semantic("HASH3_IO"))?;
        if read == 0 {
            return Err(semantic("HASH3_HEADER"));
        }
        if byte[0] == b'\n' {
            break;
        }
        if header.len() == 1024 {
            return Err(resource("HASH3_HEADER"));
        }
        header.push(byte[0]);
    }
    // Fixed bounded protocol bootstrap only; operation has no default limits.
    let mut bootstrap = Budget::new(Limits {
        work: 1_000_000,
        edges: 128,
        bytes: 131072,
        depth: 4,
        nodes: 64,
        input: 1024,
        output: 1024,
    });
    let limits = Limits::from_header(&parse(&header, &mut bootstrap)?)?;
    let mut budget = Budget::new(limits);
    let capacity = usize::try_from(budget.limits.input).map_err(|_| resource("HASH3_INPUT"))?;
    budget.charge(1, 0, budget.limits.input)?;
    let mut body = Vec::new();
    body.try_reserve_exact(capacity)
        .map_err(|_| resource("HASH3_RESOURCE"))?;
    let mut chunk = [0u8; 4096];
    loop {
        let remaining = capacity - body.len();
        let allowed = remaining.min(chunk.len()).max(1);
        budget.charge(allowed as u64, 0, 0)?;
        let read = input
            .read(&mut chunk[..allowed])
            .map_err(|_| semantic("HASH3_IO"))?;
        if read == 0 {
            break;
        }
        if read > remaining {
            return Err(resource("HASH3_INPUT"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let request = parse(&body, &mut budget)?;
    let graph = graph::Graph::new(&request, &mut budget)?;
    let output = graph.hash(&request, &mut budget)?;
    let bound = output
        .preimage
        .len()
        .checked_mul(6)
        .and_then(|n| n.checked_add(2048))
        .ok_or_else(|| resource("HASH3_OUTPUT"))?;
    budget.output(bound)?;
    budget.charge(bound as u64, 0, bound as u64)?;
    let preimage =
        String::from_utf8(output.preimage).map_err(|_| semantic("HASH3_INTERNAL_ASCII"))?;
    Ok(object([
        ("ok", Value::Bool(true)),
        ("sha256", Value::String(output.digest)),
        ("preimage_ascii", Value::String(preimage)),
        ("states", Value::from(output.states as u64)),
        ("edges", Value::from(output.edges as u64)),
        ("work", Value::from(budget.work)),
        ("allocated_payload_bytes", Value::from(budget.bytes)),
    ]))
}

fn main() {
    let response = match run(&mut std::io::stdin().lock()) {
        Ok(value) => value,
        Err(Error { kind, code }) => object([
            ("ok", Value::Bool(false)),
            ("kind", Value::from(kind)),
            ("code", Value::from(code)),
        ]),
    };
    // Success JSON was preflighted; diagnostic response is fixed <=256B bootstrap.
    let bytes = serde_json::to_vec(&response).expect("reference response uses only JSON values");
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(&bytes)
        .and_then(|_| stdout.write_all(b"\n"))
        .is_err()
    {
        std::process::exit(2);
    }
}
