//! Independent canonical ASCII writer, explicit budgets and strict JSON parser.

use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct Error {
    pub kind: &'static str,
    pub code: &'static str,
}
pub type Result<T> = std::result::Result<T, Error>;

pub fn semantic(code: &'static str) -> Error {
    Error {
        kind: "semantic",
        code,
    }
}
pub fn resource(code: &'static str) -> Error {
    Error {
        kind: "resource",
        code,
    }
}
pub fn require(condition: bool, code: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(semantic(code))
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub work: u64,
    pub edges: u64,
    pub bytes: u64,
    pub depth: u64,
    pub nodes: u64,
    pub input: u64,
    pub output: u64,
}

impl Limits {
    pub fn from_header(value: &Value) -> Result<Self> {
        let names = [
            "max_work",
            "max_edges",
            "max_bytes",
            "max_depth",
            "max_nodes",
            "max_input_bytes",
            "max_output_bytes",
        ];
        exact(value, &names)?;
        let n = |name| value[name].as_u64().ok_or_else(|| resource("HASH3_BUDGET"));
        let limits = Self {
            work: n(names[0])?,
            edges: n(names[1])?,
            bytes: n(names[2])?,
            depth: n(names[3])?,
            nodes: n(names[4])?,
            input: n(names[5])?,
            output: n(names[6])?,
        };
        if !(1..=128).contains(&limits.depth) {
            return Err(resource("HASH3_BUDGET"));
        }
        Ok(limits)
    }
}

pub struct Budget {
    pub limits: Limits,
    pub work: u64,
    pub edges: u64,
    pub bytes: u64,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            work: 0,
            edges: 0,
            bytes: 0,
        }
    }
    pub fn charge(&mut self, work: u64, edges: u64, bytes: u64) -> Result<()> {
        let next = (
            self.work.checked_add(work),
            self.edges.checked_add(edges),
            self.bytes.checked_add(bytes),
        );
        if let (Some(w), Some(e), Some(b)) = next {
            if w <= self.limits.work && e <= self.limits.edges && b <= self.limits.bytes {
                (self.work, self.edges, self.bytes) = (w, e, b);
                return Ok(());
            }
        }
        Err(resource("HASH3_RESOURCE"))
    }
    pub fn depth(&self, depth: u64) -> Result<()> {
        if depth <= self.limits.depth {
            Ok(())
        } else {
            Err(resource("HASH3_DEPTH"))
        }
    }
    pub fn nodes(&self, nodes: usize) -> Result<()> {
        if nodes as u64 <= self.limits.nodes {
            Ok(())
        } else {
            Err(resource("HASH3_NODES"))
        }
    }
    pub fn output(&self, bytes: usize) -> Result<()> {
        if bytes as u64 <= self.limits.output {
            Ok(())
        } else {
            Err(resource("HASH3_OUTPUT"))
        }
    }
}

pub fn exact(value: &Value, names: &[&str]) -> Result<()> {
    let map = value.as_object().ok_or_else(|| semantic("HASH3_SHAPE"))?;
    require(
        map.len() == names.len() && names.iter().all(|name| map.contains_key(*name)),
        "HASH3_SHAPE",
    )
}
pub fn object(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// Header has a separate fixed 1 KiB/128 KiB bootstrap bound, not a model default.
/// Body parsing receives the actual caller ledger before allocation. Duplicate
/// object keys, floating numbers, invalid escapes and out-of-range integers reject.
pub fn parse(input: &[u8], budget: &mut Budget) -> Result<Value> {
    budget.charge(input.len() as u64, 0, 0)?;
    let mut parser = Parser {
        input,
        position: 0,
        budget,
    };
    let value = parser.value(1)?;
    parser.space();
    require(parser.position == input.len(), "HASH3_JSON")?;
    Ok(value)
}

struct Parser<'a, 'b> {
    input: &'a [u8],
    position: usize,
    budget: &'b mut Budget,
}
impl Parser<'_, '_> {
    fn space(&mut self) {
        while self.position < self.input.len() && b" \n\r\t".contains(&self.input[self.position]) {
            self.position += 1;
        }
    }
    fn take(&mut self, byte: u8) -> Result<()> {
        self.space();
        require(self.input.get(self.position) == Some(&byte), "HASH3_JSON")?;
        self.position += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String> {
        self.space();
        let start = self.position;
        self.take(b'"')?;
        let mut escaped = false;
        while let Some(&byte) = self.input.get(self.position) {
            self.budget.charge(1, 0, 0)?;
            self.position += 1;
            if !escaped && byte == b'"' {
                let raw = &self.input[start..self.position];
                self.budget.charge(raw.len() as u64, 0, raw.len() as u64)?;
                return serde_json::from_slice(raw).map_err(|_| semantic("HASH3_UTF8"));
            }
            escaped = !escaped && byte == b'\\';
        }
        Err(semantic("HASH3_JSON"))
    }
    fn value(&mut self, depth: u64) -> Result<Value> {
        self.budget.depth(depth)?;
        self.budget.charge(1, 0, 32)?;
        self.space();
        match self.input.get(self.position).copied() {
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'{') => {
                self.position += 1;
                let mut map = Map::new();
                self.space();
                if self.input.get(self.position) == Some(&b'}') {
                    self.position += 1;
                    return Ok(Value::Object(map));
                }
                loop {
                    let key = self.string()?;
                    self.take(b':')?;
                    let comparisons = 32
                        * (key.len() as u64 + 1)
                        * (u64::from(usize::BITS - (map.len() + 1).leading_zeros()) + 1);
                    self.budget.charge(comparisons, 1, 128)?;
                    require(!map.contains_key(&key), "HASH3_DUPLICATE_KEY")?;
                    let value = self.value(depth + 1)?;
                    map.insert(key, value);
                    self.space();
                    if self.input.get(self.position) == Some(&b'}') {
                        self.position += 1;
                        break;
                    }
                    self.take(b',')?;
                }
                Ok(Value::Object(map))
            }
            Some(b'[') => {
                self.position += 1;
                let mut values = Vec::new();
                self.space();
                if self.input.get(self.position) == Some(&b']') {
                    self.position += 1;
                    return Ok(Value::Array(values));
                }
                loop {
                    if values.len() == values.capacity() {
                        let next = values.capacity().saturating_mul(2).max(4);
                        self.budget
                            .charge(values.len() as u64 * 32, 0, next as u64 * 32)?;
                        values
                            .try_reserve_exact(next - values.len())
                            .map_err(|_| resource("HASH3_RESOURCE"))?;
                    }
                    self.budget.charge(1, 1, 0)?;
                    values.push(self.value(depth + 1)?);
                    self.space();
                    if self.input.get(self.position) == Some(&b']') {
                        self.position += 1;
                        break;
                    }
                    self.take(b',')?;
                }
                Ok(Value::Array(values))
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Value::Bool(false))
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.position;
                while self
                    .input
                    .get(self.position)
                    .is_some_and(|b| b.is_ascii_digit() || *b == b'-')
                {
                    self.budget.charge(1, 0, 0)?;
                    self.position += 1;
                }
                let raw = &self.input[start..self.position];
                require(raw.len() <= 20, "HASH3_INTEGER")?;
                let number: Number =
                    serde_json::from_slice(raw).map_err(|_| semantic("HASH3_INTEGER"))?;
                require(number.is_u64() || number.is_i64(), "HASH3_INTEGER")?;
                Ok(Value::Number(number))
            }
            _ => Err(semantic("HASH3_JSON")),
        }
    }
    fn literal(&mut self, text: &[u8]) -> Result<()> {
        self.budget.charge(text.len() as u64, 0, 0)?;
        require(
            self.input.get(self.position..self.position + text.len()) == Some(text),
            "HASH3_JSON",
        )?;
        self.position += text.len();
        Ok(())
    }
}

fn append(out: &mut Vec<u8>, bytes: &[u8], budget: &mut Budget) -> Result<()> {
    budget.output(
        out.len()
            .checked_add(bytes.len())
            .ok_or_else(|| resource("HASH3_OUTPUT"))?,
    )?;
    if out.capacity() - out.len() < bytes.len() {
        let needed = out
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| resource("HASH3_RESOURCE"))?;
        let capacity = out
            .capacity()
            .saturating_mul(2)
            .max(64)
            .max(needed)
            .min(usize::try_from(budget.limits.output).unwrap_or(usize::MAX));
        budget.charge(out.len() as u64, 0, capacity as u64)?;
        out.try_reserve_exact(capacity - out.len())
            .map_err(|_| resource("HASH3_RESOURCE"))?;
    }
    budget.charge(bytes.len() as u64, 0, 0)?;
    out.extend_from_slice(bytes);
    Ok(())
}

pub fn ascii(value: &Value, budget: &mut Budget) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write(value, &mut out, budget, 1)?;
    Ok(out)
}
fn string(value: &str, out: &mut Vec<u8>, budget: &mut Budget) -> Result<()> {
    append(out, b"\"", budget)?;
    for ch in value.chars() {
        budget.charge(1, 0, 0)?;
        let code = ch as u32;
        match ch {
            '"' => append(out, b"\\\"", budget)?,
            '\\' => append(out, b"\\\\", budget)?,
            '\n' => append(out, b"\\n", budget)?,
            '\r' => append(out, b"\\r", budget)?,
            '\t' => append(out, b"\\t", budget)?,
            '\u{8}' => append(out, b"\\b", budget)?,
            '\u{c}' => append(out, b"\\f", budget)?,
            _ if (32..127).contains(&code) => append(out, &[code as u8], budget)?,
            _ => {
                let units = if code < 65536 {
                    [code, 0]
                } else {
                    let n = code - 65536;
                    [0xd800 + (n >> 10), 0xdc00 + (n & 1023)]
                };
                for unit in units.into_iter().take(if code < 65536 { 1 } else { 2 }) {
                    let mut bytes = *b"\\u0000";
                    for i in 0..4 {
                        bytes[5 - i] = b"0123456789abcdef"[((unit >> (4 * i)) & 15) as usize];
                    }
                    append(out, &bytes, budget)?;
                }
            }
        }
    }
    append(out, b"\"", budget)
}
fn write(value: &Value, out: &mut Vec<u8>, budget: &mut Budget, depth: u64) -> Result<()> {
    budget.depth(depth)?;
    budget.charge(1, 0, 0)?;
    match value {
        Value::Null => append(out, b"null", budget),
        Value::Bool(v) => append(out, if *v { b"true" } else { b"false" }, budget),
        Value::Number(v) => {
            budget.charge(48, 0, 48)?;
            append(out, v.to_string().as_bytes(), budget)
        }
        Value::String(v) => string(v, out, budget),
        Value::Array(rows) => {
            append(out, b"[", budget)?;
            for (i, row) in rows.iter().enumerate() {
                if i > 0 {
                    append(out, b",", budget)?;
                }
                write(row, out, budget, depth + 1)?;
            }
            append(out, b"]", budget)
        }
        Value::Object(map) => {
            // serde_json's default Map is sorted; no preserve_order feature.
            append(out, b"{", budget)?;
            for (i, (key, value)) in map.iter().enumerate() {
                if i > 0 {
                    append(out, b",", budget)?;
                }
                string(key, out, budget)?;
                append(out, b":", budget)?;
                write(value, out, budget, depth + 1)?;
            }
            append(out, b"}", budget)
        }
    }
}

pub fn quotient(labels: &[Value], edges: &[Vec<usize>], budget: &mut Budget) -> Result<Vec<u8>> {
    let count = labels.len();
    budget.charge(count as u64, 0, count as u64 * 64)?;
    let mut encoded = Vec::with_capacity(count);
    for label in labels {
        encoded.push(ascii(label, budget)?);
    }
    // Independently assign partitions through ordered signature sets, not hashes.
    let mut colors = vec![0usize; count];
    let max_label = encoded.iter().map(Vec::len).max().unwrap_or(0) as u64;
    for _ in 0..=count {
        let edge_count: usize = edges.iter().map(Vec::len).sum();
        let log = u64::from(usize::BITS - count.max(1).leading_zeros()) + 1;
        budget.charge(
            32 * count as u64 * (max_label + edge_count as u64 + 1) * log,
            edge_count as u64,
            count as u64 * (4 * max_label + 1024) + edge_count as u64 * 32,
        )?;
        let signatures: Vec<_> = (0..count)
            .map(|i| {
                (
                    encoded[i].clone(),
                    edges[i].iter().map(|c| colors[*c]).collect::<Vec<_>>(),
                )
            })
            .collect();
        let unique: BTreeSet<_> = signatures.iter().cloned().collect();
        let ranks: std::collections::BTreeMap<_, _> = unique
            .into_iter()
            .enumerate()
            .map(|(i, s)| (s, i))
            .collect();
        let next: Vec<_> = signatures.iter().map(|s| ranks[s]).collect();
        let stable = next.iter().max() == colors.iter().max();
        colors = next;
        if stable {
            break;
        }
    }
    budget.charge(count as u64, 0, count as u64 * 192)?;
    let mut representatives = std::collections::BTreeMap::new();
    for (i, color) in colors.iter().enumerate() {
        representatives.entry(*color).or_insert(i);
    }
    let mut order = vec![colors[0]];
    let mut indices = std::collections::BTreeMap::from([(colors[0], 0usize)]);
    let mut records = Vec::new();
    let mut i = 0;
    while i < order.len() {
        let representative = representatives[&order[i]];
        budget.charge(
            edges[representative].len() as u64,
            edges[representative].len() as u64,
            128 + 32 * edges[representative].len() as u64,
        )?;
        let mut children = Vec::new();
        for child in &edges[representative] {
            let color = colors[*child];
            let next = indices.len();
            let index = *indices.entry(color).or_insert_with(|| {
                order.push(color);
                next
            });
            children.push(Value::from(index as u64));
        }
        budget.charge(
            encoded[representative].len() as u64 * 64,
            0,
            encoded[representative].len() as u64 * 64 + 256,
        )?;
        records.push(object([
            ("label", labels[representative].clone()),
            ("children", Value::Array(children)),
        ]));
        i += 1;
    }
    ascii(&Value::Array(records), budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ledger() -> Budget {
        Budget::new(Limits {
            work: 1_000_000,
            edges: 10000,
            bytes: 1_000_000,
            depth: 128,
            nodes: 1000,
            input: 10000,
            output: 10000,
        })
    }
    #[test]
    fn ascii_unicode() {
        let value = Value::String("é🔮\n\u{7f}".to_owned());
        assert_eq!(
            ascii(&value, &mut ledger()).unwrap(),
            br#""\u00e9\ud83d\udd2e\n\u007f""#
        );
    }
    #[test]
    fn duplicates_reject() {
        assert_eq!(
            parse(br#"{"x":1,"x":2}"#, &mut ledger()).unwrap_err().code,
            "HASH3_DUPLICATE_KEY"
        );
    }
    #[test]
    fn failed_charge_atomic() {
        let mut b = ledger();
        b.limits.work = 0;
        assert!(b.charge(1, 1, 1).is_err());
        assert_eq!((b.work, b.edges, b.bytes), (0, 0, 0));
    }
}
