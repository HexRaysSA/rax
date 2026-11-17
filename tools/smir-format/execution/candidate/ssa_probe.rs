//! Independent path-exclusion dominance witness (not the Python bitset algorithm).
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead};

fn reachable(entry: u32, target: u32, forbidden: Option<u32>, edges: &[(u32, u32)]) -> bool {
    let mut pending = vec![entry];
    let mut visited = HashSet::new();
    while let Some(block) = pending.pop() {
        if forbidden == Some(block) || !visited.insert(block) {
            continue;
        }
        if block == target {
            return true;
        }
        for &(from, to) in edges {
            if from == block {
                pending.push(to);
            }
        }
    }
    false
}

fn check(lines: &[String]) -> Result<(), String> {
    let mut entry = None;
    let mut blocks = HashSet::new();
    let mut edges = Vec::new();
    let mut definitions = HashMap::new();
    let mut uses = Vec::new();
    for line in lines {
        let parts: Vec<_> = line.split_whitespace().collect();
        let number = |index: usize| -> Result<i64, String> {
            parts
                .get(index)
                .ok_or("field missing")?
                .parse::<i64>()
                .map_err(|_| "integer".into())
        };
        let identifier = |index| -> Result<u32, String> {
            u32::try_from(number(index)?).map_err(|_| "u32".into())
        };
        match parts.first().copied() {
            Some("entry") if parts.len() == 2 => entry = Some(identifier(1)?),
            Some("block") if parts.len() == 2 => {
                if !blocks.insert(identifier(1)?) {
                    return Err("block_duplicate".into());
                }
            }
            Some("edge") if parts.len() == 3 => edges.push((identifier(1)?, identifier(2)?)),
            Some("def") if parts.len() == 5 => {
                let id = identifier(1)?;
                if definitions
                    .insert(id, (identifier(2)?, number(3)?, number(4)?))
                    .is_some()
                {
                    return Err("ssa_duplicate".into());
                }
            }
            Some("use") if parts.len() == 5 => {
                uses.push((identifier(1)?, identifier(2)?, identifier(3)?, number(4)?))
            }
            _ => return Err("syntax".into()),
        }
    }
    let entry = entry.ok_or("entry")?;
    if !blocks.contains(&entry) {
        return Err("entry".into());
    }
    for &(from, to) in &edges {
        if !blocks.contains(&from) || !blocks.contains(&to) {
            return Err("edge".into());
        }
    }
    for &block in &blocks {
        if !reachable(entry, block, None, &edges) {
            return Err("unreachable".into());
        }
    }
    for (value, expected_type, block, position) in uses {
        let &(actual_type, origin, birth) = definitions.get(&value).ok_or("ssa_reference")?;
        if actual_type != expected_type {
            return Err("ssa_type".into());
        }
        if origin >= 0 {
            let origin = u32::try_from(origin).map_err(|_| "origin")?;
            if !blocks.contains(&origin) {
                return Err("origin".into());
            }
            if (origin == block && birth >= position)
                || (origin != block && reachable(entry, block, Some(origin), &edges))
            {
                return Err("ssa_dominance".into());
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let mut lines = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line == "end" {
            match check(&lines) {
                Ok(()) => println!("OK"),
                Err(error) => println!("{error}"),
            }
            lines.clear();
        } else {
            lines.push(line);
        }
    }
    if !lines.is_empty() {
        return Err("unterminated case".into());
    }
    Ok(())
}
