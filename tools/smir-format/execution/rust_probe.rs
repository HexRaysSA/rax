//! Batched text transport for the independent fixed-width integer witness.
#[path = "../../../src/smir/portable/execution/mod.rs"]
mod execution;

use execution::{Error, Flags, Value};
use std::io::{self, BufRead};

fn parse_value(text: &str) -> Result<Value, String> {
    match text {
        "p" => Ok(Value::Poison),
        "u" => Ok(Value::Undef),
        _ => u128::from_str_radix(text, 16)
            .map(Value::Bits)
            .map_err(|e| e.to_string()),
    }
}

fn probe(line: &str) -> Result<String, String> {
    let parts: Vec<_> = line.split_whitespace().collect();
    if parts.len() != 5 {
        return Err("five fields required".into());
    }
    let width = parts[1].parse::<u32>().map_err(|e| e.to_string())?;
    let flags = Flags {
        nsw: parts[4].contains('s'),
        nuw: parts[4].contains('u'),
        exact: parts[4].contains('e'),
    };
    Ok(
        match execution::evaluate(
            parts[0],
            width,
            parse_value(parts[2])?,
            parse_value(parts[3])?,
            flags,
        ) {
            Ok(Value::Bits(bits)) => format!("{bits:x}"),
            Ok(Value::Poison) => "P".into(),
            Ok(Value::Undef) => "U".into(),
            Err(Error::PoisonDivisor) => "T:ub_poison_divisor".into(),
            Err(Error::DivisionByZero) => "T:ub_div_zero".into(),
            Err(Error::SignedDivisionOverflow) => "T:ub_signed_div_overflow".into(),
            Err(error) => format!("E:{error:?}"),
        },
    )
}

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        println!("{}", probe(&line)?);
    }
    Ok(())
}
