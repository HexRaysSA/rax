//! Class ownership and lifetime inside the emulated process and USER atom namespace.

use super::{State, message_atoms};
use std::collections::BTreeMap;
use std::rc::Rc;

pub(crate) const RECORD_BYTES: usize = 80;
pub(crate) const MENU_BYTES: usize = 32;
pub(crate) const CS_GLOBALCLASS: u32 = 0x4000;
pub(crate) const DEFAULT_IME_ATOM: u16 = 0xc027;
pub(crate) const DEFAULT_IME_NAME: [u16; 3] = [0x49, 0x4d, 0x45];
pub(crate) const DEFAULT_IME_CURSOR: u64 = 0x10003;
const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1411;
const ERROR_CLASS_HAS_WINDOWS: u32 = 1412;

#[derive(Clone, Debug)]
pub(crate) enum Name {
    Ordinal(u16),
    Counted(Vec<u16>),
}

impl Name {
    pub(crate) fn is_default_ime(&self, upcase: &[u16]) -> bool {
        matches!(self, Self::Counted(units) if units
            .iter()
            .map(|&unit| upcase[usize::from(unit)])
            .eq(DEFAULT_IME_NAME))
    }

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
    pub(crate) ime_ansi_procedure: Option<u64>,
}

#[derive(Default)]
pub(super) struct Classes {
    entries: BTreeMap<(u16, Option<u64>), Rc<Class>>,
}

pub(crate) struct Class {
    pub(crate) public_atom: u16,
    pub(crate) definition: Definition,
    pub(crate) spelling: Name,
    primary: message_atoms::Name,
    version: message_atoms::Name,
}

impl Class {
    pub(crate) fn default_ime(module: u64, procedure: u64) -> Rc<Self> {
        let mut record = [0; RECORD_BYTES];
        record[..4].copy_from_slice(&(RECORD_BYTES as u32).to_le_bytes());
        record[4..8].copy_from_slice(&CS_GLOBALCLASS.to_le_bytes());
        record[8..16].copy_from_slice(&procedure.to_le_bytes());
        record[20..24].copy_from_slice(&8u32.to_le_bytes());
        record[24..32].copy_from_slice(&module.to_le_bytes());
        record[40..48].copy_from_slice(&DEFAULT_IME_CURSOR.to_le_bytes());
        Rc::new(Self {
            public_atom: DEFAULT_IME_ATOM,
            definition: Definition {
                record,
                menu: [0; 2],
                ansi_procedure: false,
                ime_ansi_procedure: None,
            },
            spelling: Name::Counted(DEFAULT_IME_NAME.to_vec()),
            primary: message_atoms::Name::Ordinal(DEFAULT_IME_ATOM),
            version: message_atoms::Name::Ordinal(DEFAULT_IME_ATOM),
        })
    }
}

impl Definition {
    pub(crate) fn procedure(&self) -> u64 {
        u64::from_le_bytes(self.record[8..16].try_into().expect("class procedure"))
    }

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
        let spelling = primary.clone();
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
            Rc::new(Class {
                public_atom,
                definition,
                spelling,
                primary,
                version,
            }),
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
        self.classes.entries.get(&key).map(Rc::as_ref)
    }

    /// A window keeps its exact scoped class registered until it is destroyed.
    pub(crate) fn class_for_window(
        &self,
        upcase: &[u16],
        name: &Name,
        module: u64,
        system_module: Option<u64>,
    ) -> Option<Rc<Class>> {
        let key = self.class_key(upcase, name, (module != 0).then_some(module), system_module)?;
        self.classes.entries.get(&key).cloned()
    }

    pub(crate) fn unregister_class(
        &mut self,
        upcase: &[u16],
        name: &Name,
        module: u64,
        system_module: Option<u64>,
    ) -> Result<Definition, u32> {
        let system_module = system_module.filter(|_| module == 0);
        let key = self
            .class_key(upcase, name, Some(module), system_module)
            .ok_or(ERROR_CLASS_DOES_NOT_EXIST)?;
        if Rc::strong_count(&self.classes.entries[&key]) > 1 {
            return Err(ERROR_CLASS_HAS_WINDOWS);
        }
        let entry = Rc::into_inner(self.classes.entries.remove(&key).expect("resolved class"))
            .expect("unreferenced class");
        let mut atoms = self.message_atoms.borrow_mut();
        atoms.release(&entry.primary);
        atoms.release(&entry.version);
        Ok(entry.definition)
    }

    pub(crate) fn retire_classes(&mut self) {
        let mut atoms = self.message_atoms.borrow_mut();
        for entry in std::mem::take(&mut self.classes.entries).into_values() {
            atoms.release(&entry.primary);
            atoms.release(&entry.version);
        }
    }
}
