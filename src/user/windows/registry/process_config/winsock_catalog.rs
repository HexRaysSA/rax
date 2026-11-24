//! Fixed layouts for the shared SYSTEM Winsock catalogs.
use super::{Value, covers_name, invalid, io};

const PROTOCOL_HEADER: &[&str] = &[
    "Num_Catalog_Entries",
    "Num_Catalog_Entries64",
    "Next_Catalog_Entry_ID",
    "Serial_Access_Num",
];
const NAMESPACE_HEADER: &[&str] = &[
    "Num_Catalog_Entries",
    "Num_Catalog_Entries64",
    "Serial_Access_Num",
];
const ENTRY_LISTS: &[&str] = &["Catalog_Entries", "Catalog_Entries64"];

#[derive(Clone, Copy)]
pub(in crate::user::windows::registry) enum Catalog {
    Protocol,
    Namespace,
}

impl Catalog {
    pub(super) fn header_values(self) -> &'static [&'static str] {
        match self {
            Self::Protocol => PROTOCOL_HEADER,
            Self::Namespace => NAMESPACE_HEADER,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Protocol => "Winsock protocol catalog",
            Self::Namespace => "Winsock namespace catalog",
        }
    }

    pub(in crate::user::windows::registry) fn check_node<'a>(
        self,
        upcase: &[u16],
        depth: usize,
        values: &[Value],
        mut children: impl Iterator<Item = &'a [u16]>,
    ) -> io::Result<()> {
        let valid = match depth {
            0 => {
                values.iter().all(|value| {
                    covers_name(self.header_values(), upcase, &value.name)
                        && value.kind == 4
                        && value.data.len() == 4
                }) && children.all(|name| covers_name(ENTRY_LISTS, upcase, name))
            }
            1 => {
                values.is_empty()
                    && children.all(|name| {
                        name.len() == 12 && name.iter().all(|unit| (48..=57).contains(unit))
                    })
            }
            2 => {
                children.next().is_none()
                    && values.iter().all(|value| self.entry_value(upcase, value))
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(invalid(&format!(
                "{} contains an unexpected key or value",
                self.label()
            )))
        }
    }

    fn entry_value(self, upcase: &[u16], value: &Value) -> bool {
        let named = |names: &[&str]| covers_name(names, upcase, &value.name);
        match (self, value.kind) {
            (Self::Protocol, 1) => named(&["ProtocolName"]),
            (Self::Protocol, 3) => named(&["PackedCatalogItem"]),
            (Self::Namespace, 1) => named(&["DisplayString", "LibraryPath"]),
            (Self::Namespace, 3) => {
                named(&["ProviderInfo"]) || value.data.len() == 16 && named(&["ProviderId"])
            }
            (Self::Namespace, 4) => {
                value.data.len() == 4
                    && named(&[
                        "Enabled",
                        "StoresServiceClassInfo",
                        "SupportedNameSpace",
                        "Version",
                    ])
            }
            _ => false,
        }
    }
}
