//! Optional typed grammar refinements. Draft; no executable authority.
use super::records::{Error, Schema, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct CountBounds {
    pub minimum: usize,
    pub maximum: usize,
}

#[derive(Clone, Debug)]
pub enum ScalarRule {
    UnsignedRange { minimum: u64, maximum: u64 },
    UnsignedEquals(u64),
    TextOneOf(Vec<String>),
    BooleanEquals(bool),
}

#[derive(Clone, Debug, Default)]
pub struct Refinements {
    pub counts: BTreeMap<String, CountBounds>,
    pub scalars: BTreeMap<String, Vec<ScalarRule>>,
}

impl Refinements {
    fn field_kind<'a>(schema: &'a Schema, path: &str) -> Result<&'a str, Error> {
        let invalid = Error("WIRE-REFINEMENT-CONFIG");
        let mut parts = path.split('.');
        let record = schema.get(parts.next().ok_or(invalid)?).ok_or(invalid)?;
        let (fields, member) = if record.discriminator.is_some() {
            let variant = parts.next().ok_or(invalid)?;
            (record.variants.get(variant).ok_or(invalid)?, parts.next().ok_or(invalid)?)
        } else {
            (&record.fields, parts.next().ok_or(invalid)?)
        };
        if parts.next().is_some() { return Err(invalid); }
        let mut field = member;
        let mut vectors = 0;
        while let Some(shorter) = field.strip_suffix("[]") {
            vectors += 1;
            if vectors > 128 { return Err(invalid); }
            field = shorter;
        }
        let mut kind = fields.iter().find(|(name, _)| name == field).ok_or(invalid)?.1.as_str();
        for _ in 0..vectors {
            while let Some(child) = kind.strip_prefix("opt:") { kind = child; }
            kind = kind.strip_prefix("vec:").ok_or(invalid)?;
        }
        while let Some(child) = kind.strip_prefix("opt:") { kind = child; }
        Ok(kind)
    }

    pub(super) fn audit(&self, schema: &Schema) -> Result<(), Error> {
        let invalid = Error("WIRE-REFINEMENT-CONFIG");
        for (path, bound) in &self.counts {
            if !Self::field_kind(schema, path)?.starts_with("vec:")
                || bound.minimum > bound.maximum || bound.maximum > u32::MAX as usize {
                return Err(invalid);
            }
        }
        for (path, rules) in &self.scalars {
            let kind = Self::field_kind(schema, path)?;
            if rules.is_empty() { return Err(invalid); }
            for rule in rules {
                let valid = match rule {
                    ScalarRule::UnsignedRange { minimum, maximum } => {
                        matches!(kind, "u8" | "u16" | "u32" | "u64") && minimum <= maximum
                    }
                    ScalarRule::UnsignedEquals(_) => matches!(kind, "u8" | "u16" | "u32" | "u64"),
                    ScalarRule::TextOneOf(values) => matches!(kind, "token" | "utf8") && !values.is_empty(),
                    ScalarRule::BooleanEquals(_) => kind == "bool",
                };
                if !valid { return Err(invalid); }
            }
        }
        Ok(())
    }

    pub(super) fn count(&self, path: &str, count: usize) -> Result<(), Error> {
        if let Some(bound) = self.counts.get(path) {
            if count < bound.minimum || count > bound.maximum {
                return Err(Error("WIRE-REFINEMENT-COUNT"));
            }
        }
        Ok(())
    }

    pub(super) fn scalar(&self, path: &str, value: &Value) -> Result<(), Error> {
        if matches!(value, Value::Record(_) | Value::Option(_) | Value::Vector(_)) { return Ok(()); }
        if let Some(rules) = self.scalars.get(path) {
            for rule in rules {
                let valid = match (rule, value) {
                    (ScalarRule::UnsignedRange { minimum, maximum }, Value::Unsigned(n)) => minimum <= n && n <= maximum,
                    (ScalarRule::UnsignedEquals(expected), Value::Unsigned(n)) => expected == n,
                    (ScalarRule::TextOneOf(choices), Value::Text(text)) => choices.contains(text),
                    (ScalarRule::BooleanEquals(expected), Value::Boolean(flag)) => expected == flag,
                    _ => false,
                };
                if !valid { return Err(Error("WIRE-REFINEMENT-SCALAR")); }
            }
        }
        Ok(())
    }
}
