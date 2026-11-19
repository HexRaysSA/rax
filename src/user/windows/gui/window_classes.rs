//! Class ownership and lifetime inside the emulated process and USER atom namespace.

use super::{State, message_atoms};
use std::collections::BTreeMap;

pub(crate) const RECORD_BYTES: usize = 80;
pub(crate) const MENU_BYTES: usize = 32;
const CS_GLOBALCLASS: u32 = 0x4000;
const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;

#[derive(Clone, Debug)]
pub(crate) enum Name {
    Ordinal(u16),
    Counted(Vec<u16>),
}

impl Name {
    fn atom_name(&self, upcase: &[u16]) -> Result<message_atoms::Name, u32> {
        match self {
            Self::Ordinal(value) => Ok(message_atoms::Name::Ordinal(*value)),
            Self::Counted(value) => message_atoms::Name::counted(upcase, value),
        }
    }
}

pub(crate) struct Definition {
    pub(crate) record: [u8; RECORD_BYTES],
    pub(crate) menu: [u64; 2],
    pub(crate) ansi_procedure: bool,
}

#[derive(Default)]
pub(super) struct Classes {
    entries: BTreeMap<(u16, Option<u64>), Class>,
}

pub(crate) struct Class {
    pub(crate) public_atom: u16,
    pub(crate) definition: Definition,
    primary: message_atoms::Name,
    version: message_atoms::Name,
}

impl Definition {
    pub(crate) fn module(&self) -> u64 {
        u64::from_le_bytes(self.record[24..32].try_into().expect("class module"))
    }

    fn scope(&self) -> Option<u64> {
        let style = u32::from_le_bytes(self.record[4..8].try_into().expect("class style"));
        (style & CS_GLOBALCLASS == 0).then_some(self.module())
    }
}

impl State {
    pub(crate) fn register_class(
        &mut self,
        upcase: &[u16],
        primary: &Name,
        version: &Name,
        definition: Definition,
    ) -> Result<u16, u32> {
        let primary = primary.atom_name(upcase)?;
        let version = version.atom_name(upcase)?;
        let mut atoms = self.message_atoms.borrow_mut();
        let scope = definition.scope();
        if let Some(atom) = atoms.find(&version)
            && (self.classes.entries.contains_key(&(atom, scope))
                || (scope.is_none()
                    && self
                        .classes
                        .entries
                        .contains_key(&(atom, Some(definition.module())))))
        {
            return Err(ERROR_CLASS_ALREADY_EXISTS);
        }
        let public_atom = atoms.acquire(&primary)?;
        let version_atom = match atoms.acquire(&version) {
            Ok(atom) => atom,
            Err(error) => {
                atoms.release(&primary);
                return Err(error);
            }
        };
        self.classes.entries.insert(
            (version_atom, scope),
            Class {
                public_atom,
                definition,
                primary,
                version,
            },
        );
        Ok(public_atom)
    }

    fn class_key(
        &self,
        upcase: &[u16],
        name: &Name,
        local_module: Option<u64>,
        system_module: Option<u64>,
    ) -> Option<(u16, Option<u64>)> {
        let name = name.atom_name(upcase).ok()?;
        let atom = self.message_atoms.borrow().find(&name)?;
        local_module
            .into_iter()
            .chain(system_module)
            .map(Some)
            .chain([None])
            .map(|scope| (atom, scope))
            .find(|key| self.classes.entries.contains_key(key))
    }

    pub(crate) fn class(
        &self,
        upcase: &[u16],
        name: &Name,
        module: u64,
        system_module: Option<u64>,
    ) -> Option<&Class> {
        let key = self.class_key(upcase, name, (module != 0).then_some(module), system_module)?;
        self.classes.entries.get(&key)
    }

    pub(crate) fn unregister_class(
        &mut self,
        upcase: &[u16],
        name: &Name,
        module: u64,
        system_module: Option<u64>,
    ) -> Option<Definition> {
        let system_module = system_module.filter(|_| module == 0);
        let key = self.class_key(upcase, name, Some(module), system_module)?;
        let entry = self.classes.entries.remove(&key)?;
        let mut atoms = self.message_atoms.borrow_mut();
        atoms.release(&entry.primary);
        atoms.release(&entry.version);
        Some(entry.definition)
    }

    pub(crate) fn retire_classes(&mut self) {
        let mut atoms = self.message_atoms.borrow_mut();
        for entry in std::mem::take(&mut self.classes.entries).into_values() {
            atoms.release(&entry.primary);
            atoms.release(&entry.version);
        }
    }
}
