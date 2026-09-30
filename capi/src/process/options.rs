//! Strict and bounded process-open configuration, before any worker is started.
use super::*;
use rax_engine::user::windows::WindowsConfig;
use serde_json::Value;

pub(super) const MAX_IMAGE: usize = 64 << 20;
pub(super) const MAX_IMAGES: usize = 64;
pub(super) const MAX_TOTAL_IMAGES: usize = 256 << 20;
pub(super) const MAX_OPTIONS: usize = 64 << 10;
pub(super) const MAX_TRANSFER: usize = 16 << 20;
pub(super) const MAX_INFO: usize = 4 << 20;

fn number(v: &Value, key: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match v.get(key) {
        None => default,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| bad(format!("{key} must be an unsigned integer")))?,
    };
    if !(min..=max).contains(&value) {
        return Err(bad(format!("{key} must be in [{min}, {max}]")));
    }
    Ok(value)
}

fn text(v: &Value, key: &str, default: &str) -> Result<String> {
    let value = match v.get(key) {
        None => default,
        Some(v) => v
            .as_str()
            .ok_or_else(|| bad(format!("{key} must be a string")))?,
    };
    if value.len() > 4096 || value.contains('\0') {
        return Err(bad(format!("invalid {key} string")));
    }
    Ok(value.to_owned())
}

pub(super) fn config(bytes: &[u8]) -> Result<WindowsConfig> {
    let value: Value = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(bytes).map_err(|e| bad(format!("invalid process options: {e}")))?
    };
    let object = value
        .as_object()
        .ok_or_else(|| bad("process options must be an object"))?;
    const FIELDS: &[&str] = &[
        "personality",
        "guest_path",
        "arguments",
        "environment",
        "current_directory",
        "memory_bytes",
        "slice_instructions",
        "console_capacity",
        "seed",
    ];
    for key in object.keys() {
        if !FIELDS.contains(&key.as_str()) {
            return Err(bad(format!("unknown process option {key}")));
        }
    }
    if text(&value, "personality", "windows")? != "windows" {
        return Err(Failure(
            RaxStatus::Unsupported,
            "this process ABI currently supports the Windows PE personality".into(),
        ));
    }
    let mut arguments = Vec::new();
    if let Some(array) = value.get("arguments") {
        let array = array
            .as_array()
            .ok_or_else(|| bad("arguments must be an array"))?;
        if array.len() > 256 {
            return Err(bad("at most 256 arguments are accepted"));
        }
        for argument in array {
            let argument = argument
                .as_str()
                .ok_or_else(|| bad("each argument must be a string"))?;
            if argument.len() > 4096 || argument.contains('\0') {
                return Err(bad("invalid argument string"));
            }
            arguments.push(argument.to_owned());
        }
    }
    let capacity = number(&value, "console_capacity", 1 << 20, 0, MAX_TRANSFER as u64)? as usize;
    let mut cfg = WindowsConfig::embedded(
        text(&value, "guest_path", "C:\\program.exe")?,
        arguments,
        Vec::new(),
        capacity,
    )
    .map_err(|e| bad(e.to_string()))?;
    cfg.arena_bytes = number(&value, "memory_bytes", 128 << 20, 8 << 20, 1 << 30)?;
    if cfg.arena_bytes % 4096 != 0 {
        return Err(bad("memory_bytes must be a multiple of 4096 bytes"));
    }
    cfg.slice_insns = number(&value, "slice_instructions", 4096, 1, 65_536)?;
    cfg.seed = Some(number(&value, "seed", 0, 0, u64::MAX)?);
    cfg.cwd = Some(text(&value, "current_directory", "C:\\")?);
    if let Some(environment) = value.get("environment") {
        let environment = environment
            .as_object()
            .ok_or_else(|| bad("environment must be an object of string values"))?;
        if environment.len() > 256 {
            return Err(bad("at most 256 environment variables are accepted"));
        }
        let mut pairs = Vec::new();
        for (key, value) in environment {
            let value = value
                .as_str()
                .ok_or_else(|| bad("environment values must be strings"))?;
            if key.is_empty()
                || key.contains(['\0', '='])
                || value.contains('\0')
                || key.len() > 4096
                || value.len() > 4096
            {
                return Err(bad("invalid environment entry"));
            }
            pairs.push((key.clone(), value.to_owned()));
        }
        cfg.env = Some(pairs);
    }
    Ok(cfg)
}
