//! Native reference calls reuse the unchanged standalone producer.
//! Only its record sink is redirected; no emulation code computes expected values.
std::thread_local! {
    static ROWS: std::cell::RefCell<Vec<serde_json::Value>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

macro_rules! println {
    ($($argument:tt)*) => {
        ROWS.with(|rows| rows.borrow_mut().push(
            serde_json::from_str(&format!($($argument)*)).expect("native control emits JSON")
        ))
    };
}

include!(
    "../../../../../docs/specifications/windows/native-directory-enumeration/native-directory-event-v1.rs"
);

pub(super) fn capture() -> Vec<serde_json::Value> {
    ROWS.with(|rows| assert!(rows.borrow().is_empty()));
    main();
    let rows = ROWS.with(|rows| std::mem::take(&mut *rows.borrow_mut()));
    assert_eq!(rows.len(), 12);
    rows
}
