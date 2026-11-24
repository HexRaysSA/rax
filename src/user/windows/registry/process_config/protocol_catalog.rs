//! The shared SYSTEM protocol catalog retains native lookup and enumeration order.
use super::{Value, covers_name, invalid, io};

pub(super) const HEADER_VALUES: &[&str] = &[
    "Num_Catalog_Entries",
    "Num_Catalog_Entries64",
    "Next_Catalog_Entry_ID",
    "Serial_Access_Num",
];
const ENTRY_LISTS: &[&str] = &["Catalog_Entries", "Catalog_Entries64"];

pub(in crate::user::windows::registry) fn check_node<'a>(
    upcase: &[u16],
    depth: usize,
    values: &[Value],
    mut children: impl Iterator<Item = &'a [u16]>,
) -> io::Result<()> {
    let valid = match depth {
        0 => {
            values.iter().all(|value| {
                covers_name(HEADER_VALUES, upcase, &value.name)
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
                && values.iter().all(|value| match value.kind {
                    1 => covers_name(&["ProtocolName"], upcase, &value.name),
                    3 => covers_name(&["PackedCatalogItem"], upcase, &value.name),
                    _ => false,
                })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "Winsock protocol catalog contains an unexpected key or value",
        ))
    }
}
