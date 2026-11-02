//! Independent native acquisition and full factory wiring of the fixed path.
use super::*;
use crate::user::windows::registry::{Lookup, MACHINE_HIVE_KEY};

#[test]
fn installed_system_command_capture_and_machine_routes_match_native_selection() {
    let selected = crate::user::windows::registry::snapshot().unwrap();
    let machine = selected
        .key(&MACHINE_HIVE_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        let logical = CommandRoot::System.path(&[]).unwrap();
        match open(CommandRoot::System, &[], view) {
            Ok(native) => {
                let count =
                    tests::compare_node(&selected, CommandRoot::System, &[], view, logical, native);
                assert!(count > 0);
                eprintln!("native System CMD {view:?}: {count} complete nodes");
                assert!(matches!(
                    machine.relative_in_view(
                        &"System\\Software\\Microsoft\\Command Processor"
                            .encode_utf16()
                            .collect::<Vec<_>>(),
                        view
                    ),
                    Lookup::Present(_)
                ));
            }
            Err(error) => {
                let absolute = selected.lookup_view(&logical, view);
                let relative = machine.relative_in_view(
                    &"System\\Software\\Microsoft\\Command Processor"
                        .encode_utf16()
                        .collect::<Vec<_>>(),
                    view,
                );
                for result in [absolute, relative] {
                    assert!(
                        matches!(
                            (error.raw_os_error(), result),
                            (Some(2), Lookup::Missing) | (Some(3), Lookup::MissingPath)
                        ),
                        "native result {error}"
                    );
                }
                eprintln!(
                    "native System CMD {view:?}: captured not-found {}",
                    error.raw_os_error().unwrap()
                );
            }
        }
    }
}
