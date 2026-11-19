//! Guest USER atoms shared by window messages, clipboard formats and window classes.

use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

const FIRST_STRING_ATOM: u32 = 0xc000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Name {
    Ordinal(u16),
    String(Vec<u16>),
}

impl Name {
    pub(super) fn counted(upcase: &[u16], name: &[u16]) -> Result<Self, u32> {
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
                return Ok(Self::Ordinal(number as u16));
            }
            return Err(ERROR_INVALID_PARAMETER);
        }
        Ok(Self::String(
            name.iter().map(|&unit| upcase[usize::from(unit)]).collect(),
        ))
    }
}

struct Atom {
    value: u16,
    permanent: bool,
    class_references: usize,
}

pub(super) struct Table {
    names: BTreeMap<Vec<u16>, Atom>,
    next: u32,
    vacant: BTreeSet<u16>,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            names: BTreeMap::new(),
            next: FIRST_STRING_ATOM,
            vacant: BTreeSet::new(),
        }
    }
}

impl Table {
    fn entry(&mut self, name: Vec<u16>) -> Result<&mut Atom, u32> {
        match self.names.entry(name) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let value = if let Some(reused) = self.vacant.pop_first() {
                    reused
                } else {
                    let next = u16::try_from(self.next).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
                    self.next += 1;
                    next
                };
                Ok(entry.insert(Atom {
                    value,
                    permanent: false,
                    class_references: 0,
                }))
            }
        }
    }

    pub(super) fn register(&mut self, upcase: &[u16], name: &[u16]) -> Result<u16, u32> {
        if name.is_empty() {
            return Ok(0);
        }
        match Name::counted(upcase, name)? {
            Name::Ordinal(value) => Ok(value),
            Name::String(name) => {
                let atom = self.entry(name)?;
                atom.permanent = true;
                Ok(atom.value)
            }
        }
    }

    pub(super) fn acquire(&mut self, name: &Name) -> Result<u16, u32> {
        match name {
            Name::Ordinal(value) => Ok(*value),
            Name::String(name) => {
                let atom = self.entry(name.clone())?;
                atom.class_references += 1;
                Ok(atom.value)
            }
        }
    }

    pub(super) fn find(&self, name: &Name) -> Option<u16> {
        match name {
            Name::Ordinal(value) => Some(*value),
            Name::String(name) => self.names.get(name).map(|atom| atom.value),
        }
    }

    pub(super) fn release(&mut self, name: &Name) {
        let Name::String(name) = name else {
            return;
        };
        let Entry::Occupied(mut entry) = self.names.entry(name.clone()) else {
            return;
        };
        let atom = entry.get_mut();
        atom.class_references -= 1;
        if !atom.permanent && atom.class_references == 0 {
            let removed = entry.remove();
            self.vacant.insert(removed.value);
        }
    }
}
