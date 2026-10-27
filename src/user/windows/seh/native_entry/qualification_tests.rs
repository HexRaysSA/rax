use super::x64_recipe;

// Expectations come from the two independent native debugger captures, rather
// than from a second copy of the production recipe or a rebuilt fault fixture.
fn captured_recipes() -> Vec<(Vec<u8>, Vec<u8>)> {
    let document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../docs/specifications/windows/native-exception-entry-profile/hosted-dispatch-v4.json"
    ))
    .unwrap();
    fn collect(value: &serde_json::Value, recipes: &mut Vec<(Vec<u8>, Vec<u8>)>) {
        match value {
            serde_json::Value::Object(fields) => {
                if value["kind"] == "unwind_metadata"
                    && value["arch"] == "x64"
                    && value["available"] == true
                {
                    let slots = value["slots"].as_array().unwrap();
                    let header = vec![
                        (value["version"].as_u64().unwrap() | value["flags"].as_u64().unwrap() << 3)
                            as u8,
                        value["prolog_bytes"].as_u64().unwrap() as u8,
                        slots.len().try_into().unwrap(),
                        (value["frame_register"].as_u64().unwrap()
                            | value["frame_offset_units16"].as_u64().unwrap() << 4)
                            as u8,
                    ];
                    let codes = slots
                        .iter()
                        .flat_map(|v| u16::try_from(v.as_u64().unwrap()).unwrap().to_le_bytes())
                        .collect();
                    recipes.push((header, codes));
                } else {
                    for child in fields.values() {
                        collect(child, recipes);
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    collect(child, recipes);
                }
            }
            _ => {}
        }
    }
    let mut recipes = Vec::new();
    collect(&document, &mut recipes);
    assert_eq!(
        recipes.len(),
        2,
        "both native AMD64 controls must be selected"
    );
    recipes
}

#[test]
fn captured_amd64_dispatcher_recipes_remain_qualified() {
    for (header, codes) in captured_recipes() {
        assert!(x64_recipe(&header, &codes));
    }
}

#[test]
fn machine_frame_tail_cannot_qualify_incompatible_header_or_prefix() {
    for (header, codes) in captured_recipes() {
        for (offset, value) in [(0, 3), (0, 10), (1, 1), (3, 5), (3, 0x10)] {
            let mut changed = header.clone();
            changed[offset] = value;
            assert!(!x64_recipe(&changed, &codes), "header {changed:?}");
        }
        // An extra PUSH/ALLOC/SET_FPREG changes the frame even though the
        // original six-byte machine-frame tail is still present.
        for operation in [[0, 0x30], [0, 2], [0, 3]] {
            let mut changed_header = header.clone();
            changed_header[2] += 1;
            let mut changed_codes = operation.to_vec();
            changed_codes.extend_from_slice(&codes);
            assert!(!x64_recipe(&changed_header, &changed_codes));
        }
        // The captured first register save is XMM15 at CONTEXT + 0x290.
        let mut changed = codes.clone();
        changed[6] ^= 1;
        assert!(!x64_recipe(&header, &changed));
        let mut changed = codes.clone();
        changed[4] = 1;
        assert!(!x64_recipe(&header, &changed));
    }
}
