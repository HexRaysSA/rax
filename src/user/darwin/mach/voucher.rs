//! Mach vouchers (`osfmk/ipc/ipc_voucher.c`) and the attribute managers a
//! macOS kernel registers: importance (`osfmk/ipc/ipc_importance.c`), bank
//! (`osfmk/bank/bank.c`), pthread priority
//! (`osfmk/voucher/ipc_pthread_priority.c`), and user data.
//!
//! A voucher is a set of attribute values, one per key; vouchers with the
//! same values are one voucher (`iv_dedup`), so one port and, in one space,
//! one name. [`create`] runs a recipe array (`ipc_create_mach_voucher_internal`
//! and `ipc_execute_voucher_recipe_command`); [`extract`] and [`command`]
//! are the managers' `extract_content` and `command` entry points.
//!
//! Every emulated task is alone in its host process, so the values that
//! need a second task never arise: bank accounts (between tasks or
//! personas) and importance inherits (boosts from other tasks). What
//! remains is, per key: whether the voucher carries the task's own
//! importance element; no bank value, the default task value, or the
//! task's bank context; a normalized pthread priority; and user data.
//! Keys 1 (ATM), 5, 6, and 8 have no manager on macOS.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use super::ipc::{KObject, Port};
use super::kr::{self, KernReturn};

/// `MACH_VOUCHER_ATTR_KEY_*`.
pub mod key {
    /// `MACH_VOUCHER_ATTR_KEY_ALL`.
    pub const ALL: u32 = !0;
    /// `MACH_VOUCHER_ATTR_KEY_IMPORTANCE`.
    pub const IMPORTANCE: u32 = 2;
    /// `MACH_VOUCHER_ATTR_KEY_BANK`.
    pub const BANK: u32 = 3;
    /// `MACH_VOUCHER_ATTR_KEY_PTHPRIORITY`.
    pub const PTHPRIORITY: u32 = 4;
    /// `MACH_VOUCHER_ATTR_KEY_USER_DATA`.
    pub const USER_DATA: u32 = 7;
    /// `MACH_VOUCHER_ATTR_KEY_NUM`: value slots per voucher (keys 1-8).
    pub const NUM: u32 = 8;
}

/// Recipe commands (`mach_voucher_attr_recipe_command_t`).
pub mod cmd {
    /// `MACH_VOUCHER_ATTR_NOOP`.
    pub const NOOP: u32 = 0;
    /// `MACH_VOUCHER_ATTR_COPY`.
    pub const COPY: u32 = 1;
    /// `MACH_VOUCHER_ATTR_REMOVE`.
    pub const REMOVE: u32 = 2;
    /// `MACH_VOUCHER_ATTR_SET_VALUE_HANDLE`.
    pub const SET_VALUE_HANDLE: u32 = 3;
    /// `MACH_VOUCHER_ATTR_AUTO_REDEEM`.
    pub const AUTO_REDEEM: u32 = 4;
    /// `MACH_VOUCHER_ATTR_SEND_PREPROCESS`.
    pub const SEND_PREPROCESS: u32 = 5;
    /// `MACH_VOUCHER_ATTR_REDEEM`.
    pub const REDEEM: u32 = 10;
    /// `MACH_VOUCHER_ATTR_IMPORTANCE_SELF`.
    pub const IMPORTANCE_SELF: u32 = 200;
    /// `MACH_VOUCHER_ATTR_USER_DATA_STORE`.
    pub const USER_DATA_STORE: u32 = 211;
    /// `MACH_VOUCHER_ATTR_BANK_NULL`: the command of an extracted bank value.
    pub const BANK_NULL: u32 = 601;
    /// `MACH_VOUCHER_ATTR_BANK_CREATE`.
    pub const BANK_CREATE: u32 = 610;
    /// `MACH_VOUCHER_ATTR_BANK_MODIFY_PERSONA`.
    pub const BANK_MODIFY_PERSONA: u32 = 611;
    /// `MACH_VOUCHER_ATTR_PTHPRIORITY_NULL`: the command of an extracted
    /// priority.
    pub const PTHPRIORITY_NULL: u32 = 701;
    /// `MACH_VOUCHER_ATTR_PTHPRIORITY_CREATE`.
    pub const PTHPRIORITY_CREATE: u32 = 710;
}

/// `sizeof(mach_voucher_attr_recipe_data_t)`: key, command,
/// previous voucher, and content size, packed.
pub const RECIPE_HEADER: usize = 16;
/// `MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE`.
pub const MAX_RECIPE_ARRAY: usize = 5120;
/// The MIG bound of `mach_voucher_attr_content_t` and
/// `mach_voucher_attr_raw_recipe_t`.
pub const MAX_CONTENT: usize = 4096;
/// `MACH_VOUCHER_BANK_CONTENT_SIZE`: the room a bank value's text needs.
const BANK_CONTENT_SIZE: usize = 500;
/// `USER_DATA_MAX_DATA`.
const USER_DATA_MAX: usize = 16 * 1024;
/// `MACH_VOUCHER_PTHPRIORITY_CONTENT_SIZE`.
const PTHPRIORITY_CONTENT_SIZE: usize = 4;
/// `PERSONA_ID_NONE`.
const PERSONA_ID_NONE: u32 = !0;
/// `sizeof(struct persona_token)`.
const PERSONA_TOKEN_SIZE: usize = 96;

/// A bank attribute value a lone task can hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Bank {
    /// No value.
    #[default]
    None,
    /// `BANK_DEFAULT_TASK_VALUE`: what `BANK_CREATE` makes.
    DefaultTask,
    /// The task's own bank context (`bank_task`), what sending makes of
    /// the default task value.
    Task,
}

/// A voucher's attribute values; equal values are the same voucher.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Attrs {
    /// Key 2: the task's importance element (`IMPORTANCE_SELF`).
    pub importance: bool,
    /// Key 3.
    pub bank: Bank,
    /// Key 4: a normalized pthread priority, 0 for none.
    pub pthpriority: u32,
    /// Key 7: stored bytes (1 or more), `None` for none.
    pub user_data: Option<Arc<[u8]>>,
}

impl Attrs {
    /// Whether the slot of `key` (1-8) holds the same value in both.
    fn same(&self, other: &Attrs, key: u32) -> bool {
        match key {
            key::IMPORTANCE => self.importance == other.importance,
            key::BANK => self.bank == other.bank,
            key::PTHPRIORITY => self.pthpriority == other.pthpriority,
            key::USER_DATA => self.user_data == other.user_data,
            _ => true,
        }
    }

    /// Copies the slot of `key` (1-8) from `from`.
    fn copy_slot(&mut self, from: &Attrs, key: u32) {
        match key {
            key::IMPORTANCE => self.importance = from.importance,
            key::BANK => self.bank = from.bank,
            key::PTHPRIORITY => self.pthpriority = from.pthpriority,
            key::USER_DATA => self.user_data = from.user_data.clone(),
            _ => {}
        }
    }

    /// Resets the slot of `key` (1-8) to its default.
    fn clear_slot(&mut self, key: u32) {
        self.copy_slot(&Attrs::default(), key);
    }

    /// Whether the slot of `key` holds a value (keys outside 1-8 and keys
    /// without a manager never do).
    pub fn has(&self, key: u32) -> bool {
        !self.same(&Attrs::default(), key) && matches!(key, 2 | 3 | 4 | 7)
    }
}

/// The voucher a port stands for.
pub fn attrs_of(port: &Port) -> Option<&Arc<Attrs>> {
    match &port.kobject {
        KObject::Voucher(a) => Some(a),
        _ => None,
    }
}

/// The process's vouchers: one port per set of values, kept only while
/// something (a send right, a thread, a queued message) holds it.
#[derive(Default)]
pub struct Vouchers {
    by_attrs: HashMap<Arc<Attrs>, Weak<Port>>,
    /// The next activity ID where the host has no counter (0: not yet
    /// seeded).
    activity_next: u64,
}

impl Vouchers {
    /// Reserves `count` activity IDs (`mach_generate_activity_id`) and
    /// returns the first. XNU keeps one counter for the system: on a macOS
    /// host that is the host kernel's; elsewhere each process counts from
    /// a start its pid sets apart (below 2^52, as libdispatch's scaling of
    /// IDs by 16 into 56 bits needs).
    pub fn activity_ids(&mut self, pid: i32, count: u64) -> u64 {
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn mach_generate_activity_id(target: u32, count: i32, activity_id: *mut u64)
                -> i32;
            }
            let mut id = 0u64;
            // SAFETY: the result goes to a live u64; the kernel does not
            // look at the target.
            if unsafe { mach_generate_activity_id(0, count as i32, &mut id) } == 0 {
                return id;
            }
        }
        if self.activity_next == 0 {
            self.activity_next = ((u64::from(pid as u32) & 0xff_ffff) << 28) | 1;
        }
        let id = self.activity_next;
        self.activity_next += count;
        id
    }

    /// A forked child's vouchers: its own activity-ID range.
    pub fn fork(&mut self) {
        self.activity_next = 0;
    }

    /// The voucher with values `attrs` (`iv_dedup`): the live one, or a new
    /// one.
    pub fn canonical(&mut self, attrs: Attrs) -> Arc<Port> {
        if let Some(p) = self.by_attrs.get(&attrs).and_then(Weak::upgrade) {
            return p;
        }
        self.by_attrs.retain(|_, w| w.strong_count() > 0);
        let attrs = Arc::new(attrs);
        let port = Port::new(KObject::Voucher(attrs.clone()));
        self.by_attrs.insert(attrs, Arc::downgrade(&port));
        port
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

/// Runs a recipe array (`ipc_create_mach_voucher_internal`): `Ok(None)`
/// for an empty array, the new voucher's values otherwise. `prev_of`
/// converts a recipe's previous-voucher name (`convert_port_name_to_voucher`):
/// `None` for a name that is not a send right to a voucher.
pub fn create(
    recipes: &[u8],
    prev_of: impl Fn(u32) -> Option<Attrs>,
) -> Result<Option<Attrs>, KernReturn> {
    if recipes.is_empty() {
        return Ok(None);
    }
    let mut v = Attrs::default();
    let mut used = 0usize;
    while used < recipes.len() {
        if recipes.len() - used < RECIPE_HEADER {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
        let key = le32(recipes, used);
        let command = le32(recipes, used + 4);
        let prev_name = le32(recipes, used + 8);
        let size = le32(recipes, used + 12) as usize;
        if recipes.len() - used - RECIPE_HEADER < size {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
        let prev = match prev_name {
            0 => None,
            n => Some(prev_of(n).ok_or(kr::KERN_INVALID_CAPABILITY)?),
        };
        let content = &recipes[used + RECIPE_HEADER..used + RECIPE_HEADER + size];
        used += RECIPE_HEADER + size;
        execute(&mut v, key, command, prev.as_ref(), content)?;
    }
    Ok(Some(v))
}

/// One recipe (`ipc_execute_voucher_recipe_command`).
fn execute(
    v: &mut Attrs,
    key: u32,
    command: u32,
    prev: Option<&Attrs>,
    content: &[u8],
) -> Result<(), KernReturn> {
    let valid_key = (1..=key::NUM).contains(&key);
    match command {
        cmd::COPY => {
            if !content.is_empty() {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let Some(p) = prev else {
                return Ok(());
            };
            if key == key::ALL {
                *v = p.clone();
            } else if valid_key {
                v.copy_slot(p, key);
            } else {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
        }
        cmd::REMOVE => {
            if !content.is_empty() {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            if key == key::ALL {
                for k in 1..=key::NUM {
                    if prev.is_none_or(|p| v.same(p, k)) {
                        v.clear_slot(k);
                    }
                }
            } else if valid_key {
                if prev.is_none_or(|p| v.same(p, key)) {
                    v.clear_slot(key);
                }
            } else {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
        }
        // Only a manager's own control may set a value directly.
        cmd::SET_VALUE_HANDLE => return Err(kr::KERN_INVALID_CAPABILITY),
        // Redeeming every key reaches key 1 first, which has no manager.
        cmd::REDEEM if key == key::ALL => return Err(kr::KERN_INVALID_ARGUMENT),
        _ => {
            // ipc_replace_voucher_value: the manager sees the previous
            // voucher's value for the key, or the forming voucher's.
            let input = prev.unwrap_or(v).clone();
            match key {
                key::IMPORTANCE => {
                    v.importance = importance_value(command, input.importance, content)?
                }
                key::BANK => v.bank = bank_value(command, input.bank)?,
                key::PTHPRIORITY => v.pthpriority = pthpriority_value(command, content)?,
                key::USER_DATA => v.user_data = user_data_value(command, input.user_data, content)?,
                _ => return Err(kr::KERN_INVALID_ARGUMENT),
            }
        }
    }
    Ok(())
}

/// `ipc_importance_get_value`.
fn importance_value(command: u32, prev: bool, content: &[u8]) -> Result<bool, KernReturn> {
    if !content.is_empty() {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    match command {
        cmd::REDEEM => Ok(prev),
        cmd::IMPORTANCE_SELF => Ok(true),
        _ => Err(kr::KERN_INVALID_ARGUMENT),
    }
}

/// `bank_get_value` for a task alone: `BANK_CREATE` makes the default task
/// value; sending (`SEND_PREPROCESS`) turns a task value into the task's
/// context; receiving (`AUTO_REDEEM`) turns the context back and drops the
/// default value; `REDEEM` makes the default value of either;
/// `BANK_MODIFY_PERSONA` needs an entitlement the guest lacks.
fn bank_value(command: u32, prev: Bank) -> Result<Bank, KernReturn> {
    Ok(match (command, prev) {
        (cmd::BANK_CREATE, _) => Bank::DefaultTask,
        (cmd::SEND_PREPROCESS, Bank::None) => Bank::None,
        (cmd::SEND_PREPROCESS, _) => Bank::Task,
        (cmd::AUTO_REDEEM, Bank::Task) => Bank::DefaultTask,
        (cmd::AUTO_REDEEM, _) => Bank::None,
        (cmd::REDEEM, Bank::None) => Bank::None,
        (cmd::REDEEM, _) => Bank::DefaultTask,
        (cmd::BANK_MODIFY_PERSONA, Bank::Task) => return Err(kr::KERN_NO_ACCESS),
        (cmd::BANK_MODIFY_PERSONA, _) => Bank::None,
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    })
}

/// `ipc_pthread_priority_get_value`: the priority normalized for IPC
/// (`_pthread_priority_normalize_for_ipc`), 0 (no value) for one without a
/// QoS class.
fn pthpriority_value(command: u32, content: &[u8]) -> Result<u32, KernReturn> {
    if command != cmd::PTHPRIORITY_CREATE || content.len() != 4 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let mut pp = le32(content, 0);
    if pp == 0 {
        return Ok(0);
    }
    // _pthread_priority_has_qos: no event-manager or scheduler-priority
    // flag, and a QoS class.
    let has_qos = pp & 0x2200_0000 == 0 && pp & 0x0000_3f00 != 0;
    if !has_qos {
        return Ok(0);
    }
    let relpri = i32::from(pp as u8 as i8) + 1;
    if !(-15..=0).contains(&relpri) {
        pp |= 0xff;
    }
    Ok(pp & 0x003f_ffff)
}

/// The user-data manager's `get_value`.
fn user_data_value(
    command: u32,
    prev: Option<Arc<[u8]>>,
    content: &[u8],
) -> Result<Option<Arc<[u8]>>, KernReturn> {
    match command {
        cmd::REDEEM => Ok(prev),
        cmd::USER_DATA_STORE if content.len() > USER_DATA_MAX => Err(kr::KERN_RESOURCE_SHORTAGE),
        cmd::USER_DATA_STORE if content.is_empty() => Ok(None),
        cmd::USER_DATA_STORE => Ok(Some(Arc::from(content))),
        _ => Err(kr::KERN_INVALID_ARGUMENT),
    }
}

/// A manager's `extract_content` for the value of `key` in `v` (the
/// caller checked there is one): the recipe command and content that fit
/// in `room` bytes. `pid` is the task's, which the texts name.
pub fn extract(v: &Attrs, key: u32, room: usize, pid: i32) -> Result<(u32, Vec<u8>), KernReturn> {
    match key {
        key::IMPORTANCE => {
            if room < 1 {
                return Err(kr::KERN_NO_SPACE);
            }
            // "Importance for pid N" with its NUL, cut to fit (scnprintf).
            let mut text = format!("Importance for pid {pid}").into_bytes();
            text.truncate(room - 1);
            text.push(0);
            Ok((cmd::NOOP, text))
        }
        key::BANK => {
            if room == 0 {
                return Ok((cmd::NOOP, Vec::new()));
            }
            if room < BANK_CONTENT_SIZE {
                return Err(kr::KERN_NO_SPACE);
            }
            let mut text = format!(" Bank Context for a pid {pid}\n").into_bytes();
            text.push(0);
            Ok((cmd::BANK_NULL, text))
        }
        key::PTHPRIORITY => {
            if room == 0 {
                return Err(kr::KERN_INVALID_VALUE);
            }
            if room < PTHPRIORITY_CONTENT_SIZE {
                return Err(kr::KERN_NO_SPACE);
            }
            Ok((cmd::PTHPRIORITY_NULL, v.pthpriority.to_le_bytes().to_vec()))
        }
        key::USER_DATA => {
            let data = v.user_data.as_deref().unwrap_or_default();
            if room == 0 {
                return Ok((cmd::USER_DATA_STORE, Vec::new()));
            }
            if data.len() > room {
                return Err(kr::KERN_NO_SPACE);
            }
            Ok((cmd::USER_DATA_STORE, data.to_vec()))
        }
        _ => Ok((cmd::NOOP, Vec::new())),
    }
}

/// `mach_voucher_extract_attr_recipe`: the recipe for `key` in at most
/// `size` bytes; empty when the voucher has no value for it.
pub fn extract_recipe(v: &Attrs, key: u32, size: usize, pid: i32) -> Result<Vec<u8>, KernReturn> {
    if !v.has(key) {
        return Ok(Vec::new());
    }
    if size < RECIPE_HEADER {
        return Err(kr::KERN_NO_SPACE);
    }
    let (command, content) = extract(v, key, size - RECIPE_HEADER, pid)?;
    Ok(recipe(key, command, &content))
}

/// A recipe: header (previous voucher 0) and content.
fn recipe(key: u32, command: u32, content: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(RECIPE_HEADER + content.len());
    r.extend_from_slice(&key.to_le_bytes());
    r.extend_from_slice(&command.to_le_bytes());
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&(content.len() as u32).to_le_bytes());
    r.extend_from_slice(content);
    r
}

/// `mach_voucher_extract_all_attr_recipes`: the recipes of every key with
/// a value, in key order, in at most `size` bytes.
pub fn extract_all(v: &Attrs, size: usize, pid: i32) -> Result<Vec<u8>, KernReturn> {
    let mut out = Vec::new();
    for k in 1..=key::NUM {
        if !v.has(k) {
            continue;
        }
        let left = size - out.len();
        if left < RECIPE_HEADER {
            return Err(kr::KERN_NO_SPACE);
        }
        let (command, content) = extract(v, k, left - RECIPE_HEADER, pid)?;
        out.extend_from_slice(&recipe(k, command, &content));
    }
    Ok(out)
}

/// `mach_voucher_attr_command`: the manager of `key` runs `command` on the
/// voucher's value with `input`, producing at most `out_size` bytes.
pub fn command(
    v: &Attrs,
    key: u32,
    command: u32,
    input: &[u8],
    out_size: usize,
    pid: i32,
) -> Result<Vec<u8>, KernReturn> {
    match key {
        key::BANK => bank_command(v.bank, command, out_size, pid),
        key::IMPORTANCE => {
            // ipc_importance_command: a 4-byte count in, nothing or 4
            // bytes out, and only dropping external references, which a
            // task's own element (never an inherit) does not have.
            if input.len() != 4 || (out_size != 0 && out_size != 4) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            if command != 2 {
                return Err(kr::KERN_NOT_SUPPORTED);
            }
            Err(kr::KERN_INVALID_ARGUMENT)
        }
        key::PTHPRIORITY | key::USER_DATA => Err(kr::KERN_FAILURE),
        _ => Err(kr::KERN_INVALID_ARGUMENT),
    }
}

/// `bank_command`: the output size each command needs is checked before
/// the value.
fn bank_command(
    bank: Bank,
    command: u32,
    out_size: usize,
    pid: i32,
) -> Result<Vec<u8>, KernReturn> {
    const ORIGINATOR_PID: u32 = 1;
    const PERSONA_TOKEN: u32 = 2;
    const PERSONA_ID: u32 = 3;
    const PERSONA_ADOPT_ANY: u32 = 4;
    const ORIGINATOR_PROXIMATE_PID: u32 = 5;
    let need = match command {
        ORIGINATOR_PID | PERSONA_ID | PERSONA_ADOPT_ANY => 4,
        PERSONA_TOKEN => PERSONA_TOKEN_SIZE,
        ORIGINATOR_PROXIMATE_PID => 8,
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    };
    if out_size < need {
        return Err(kr::KERN_NO_SPACE);
    }
    if command == PERSONA_ADOPT_ANY {
        // The task may adopt any persona: platform binaries and holders of
        // an entitlement only, which guests are not.
        return Ok(0u32.to_le_bytes().to_vec());
    }
    if bank == Bank::None {
        return Err(kr::KERN_INVALID_VALUE);
    }
    Ok(match command {
        ORIGINATOR_PID => pid.to_le_bytes().to_vec(),
        // A bank context carries no persona token.
        PERSONA_TOKEN => return Err(kr::KERN_INVALID_OBJECT),
        PERSONA_ID => PERSONA_ID_NONE.to_le_bytes().to_vec(),
        _ => {
            let mut b = pid.to_le_bytes().to_vec();
            b.extend_from_slice(&(-1i32).to_le_bytes());
            b
        }
    })
}

/// The voucher a message carries once sent (`ipc_voucher_send_preprocessing`):
/// a bank value becomes the task's bank context. `None` when sending
/// leaves it as it is.
pub fn sent(v: &Attrs) -> Option<Attrs> {
    if v.bank == Bank::None {
        return None;
    }
    Some(Attrs {
        bank: Bank::Task,
        ..v.clone()
    })
}

/// The voucher a receiver gets (`ipc_importance_receive`, then
/// `ipc_voucher_receive_postprocessing`): without an importance inherit
/// the importance value is dropped, and the bank redeems the task's
/// context (`AUTO_REDEEM`).
pub fn received(v: &Attrs) -> Attrs {
    let mut r = v.clone();
    r.importance = false;
    if r.bank != Bank::None {
        r.bank = match r.bank {
            Bank::Task => Bank::DefaultTask,
            _ => Bank::None,
        };
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(key: u32, command: u32, prev: u32, content: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        for w in [key, command, prev, content.len() as u32] {
            r.extend_from_slice(&w.to_le_bytes());
        }
        r.extend_from_slice(content);
        r
    }

    #[test]
    fn recipes_build_values_in_order() {
        let none = |_| None;
        assert_eq!(create(&[], none), Ok(None));
        let bank = create(&rec(key::BANK, cmd::BANK_CREATE, 0, &[]), none).unwrap();
        assert_eq!(bank.as_ref().map(|a| a.bank), Some(Bank::DefaultTask));
        let mut r = rec(key::BANK, cmd::BANK_CREATE, 0, &[]);
        r.extend(rec(key::BANK, cmd::SEND_PREPROCESS, 0, &[]));
        assert_eq!(create(&r, none).unwrap().unwrap().bank, Bank::Task);
        // A truncated second header, a content overrun, an unknown key.
        assert_eq!(create(&r[..24], none), Err(kr::KERN_INVALID_ARGUMENT));
        let mut o = rec(key::USER_DATA, cmd::USER_DATA_STORE, 0, b"abc");
        o.pop();
        assert_eq!(create(&o, none), Err(kr::KERN_INVALID_ARGUMENT));
        assert_eq!(
            create(&rec(5, 1000, 0, &[]), none),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
        // A previous voucher that does not convert.
        assert_eq!(
            create(&rec(key::BANK, cmd::COPY, 9, &[]), none),
            Err(kr::KERN_INVALID_CAPABILITY)
        );
        // Copying without a previous voucher succeeds before the key is checked.
        assert_eq!(
            create(&rec(9, cmd::COPY, 0, &[]), none),
            Ok(Some(Attrs::default()))
        );
        assert_eq!(
            create(&rec(9, cmd::REMOVE, 0, &[]), none),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
        assert_eq!(
            create(&rec(key::ALL, cmd::REDEEM, 0, &[]), none),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn pthread_priorities_are_normalized() {
        assert_eq!(
            pthpriority_value(cmd::PTHPRIORITY_CREATE, &0x21000u32.to_le_bytes()),
            Ok(0x210ff)
        );
        assert_eq!(
            pthpriority_value(cmd::PTHPRIORITY_CREATE, &0x15u32.to_le_bytes()),
            Ok(0)
        );
        assert_eq!(
            pthpriority_value(cmd::PTHPRIORITY_CREATE, &[1, 0, 0]),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
        // A relative priority of -1 is kept.
        assert_eq!(
            pthpriority_value(cmd::PTHPRIORITY_CREATE, &0x210feu32.to_le_bytes()),
            Ok(0x210fe)
        );
    }

    #[test]
    fn extraction_follows_the_managers() {
        let v = Attrs {
            importance: true,
            bank: Bank::DefaultTask,
            pthpriority: 0x210ff,
            user_data: Some(Arc::from(&b"hello\0"[..])),
        };
        assert_eq!(extract(&v, key::BANK, 499, 7), Err(kr::KERN_NO_SPACE));
        assert_eq!(extract(&v, key::BANK, 0, 7), Ok((cmd::NOOP, Vec::new())));
        assert_eq!(
            extract(&v, key::BANK, 500, 7).unwrap().1,
            b" Bank Context for a pid 7\n\0"
        );
        assert_eq!(extract(&v, key::IMPORTANCE, 5, 7).unwrap().1, b"Impo\0");
        assert_eq!(
            extract(&v, key::PTHPRIORITY, 0, 7),
            Err(kr::KERN_INVALID_VALUE)
        );
        assert_eq!(extract(&v, key::USER_DATA, 5, 7), Err(kr::KERN_NO_SPACE));
        let all = extract_all(&v, 5120, 7).unwrap();
        // Importance (16 + 21: 20 + one digit), bank (16 + 27: 26 + one
        // digit), priority (16 + 4), user data (16 + 6).
        assert_eq!(all.len(), 37 + 43 + 20 + 22);
        assert_eq!(
            extract_recipe(&Attrs::default(), key::BANK, 0, 7),
            Ok(Vec::new())
        );
    }

    #[test]
    fn sending_and_receiving_move_the_bank_value() {
        let bank = Attrs {
            bank: Bank::DefaultTask,
            ..Default::default()
        };
        let sent = sent(&bank).unwrap();
        assert_eq!(sent.bank, Bank::Task);
        assert_eq!(received(&sent), bank);
        let imp = Attrs {
            importance: true,
            ..Default::default()
        };
        assert_eq!(sent_or(&imp), imp);
        assert_eq!(received(&imp), Attrs::default());
    }

    fn sent_or(v: &Attrs) -> Attrs {
        sent(v).unwrap_or_else(|| v.clone())
    }
}
