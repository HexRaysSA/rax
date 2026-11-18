//! Registered window messages and clipboard format names share guest atom IDs.

use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};
use std::collections::{BTreeMap, btree_map::Entry};

const FIRST_STRING_ATOM: u32 = 0xc000;

#[derive(Default)]
pub(super) struct Table {
    names: BTreeMap<Vec<u16>, u16>,
}

impl Table {
    pub(super) fn register(&mut self, upcase: &[u16], name: &[u16]) -> Result<u16, u32> {
        if name.is_empty() {
            return Ok(0);
        }
        if let [0x23, digits @ ..] = name
            && !digits.is_empty()
            && digits.iter().all(|unit| (0x30..=0x39).contains(unit))
        {
            let number = digits.iter().fold(0u32, |number, digit| {
                number
                    .saturating_mul(10)
                    .saturating_add(u32::from(digit - 0x30))
            });
            if (1..FIRST_STRING_ATOM).contains(&number) {
                return Ok(number as u16);
            }
            return Err(ERROR_INVALID_PARAMETER);
        }

        let folded = name.iter().map(|&unit| upcase[usize::from(unit)]).collect();
        let next = FIRST_STRING_ATOM + self.names.len() as u32;
        match self.names.entry(folded) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let atom = u16::try_from(next).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
                entry.insert(atom);
                Ok(atom)
            }
        }
    }
}
