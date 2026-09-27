//! The `pthread_priority_t` encoding and thread QoS classes
//! (`bsd/pthread/priority_private.h`, `bsd/pthread/pthread_priority.c`,
//! `osfmk/mach/thread_policy.h`).
//!
//! A pthread priority is either a QoS class (one bit of
//! `0x3f00` per class, a relative priority in the low byte stored minus
//! one, and flags in the top byte), a scheduler priority (with
//! `SCHED_PRI_FLAG`), or the event manager's (`EVENT_MANAGER_FLAG`).

/// `THREAD_QOS_*`.
pub mod thread_qos {
    pub const UNSPECIFIED: u8 = 0;
    pub const MAINTENANCE: u8 = 1;
    pub const BACKGROUND: u8 = 2;
    pub const UTILITY: u8 = 3;
    pub const LEGACY: u8 = 4;
    pub const USER_INITIATED: u8 = 5;
    pub const USER_INTERACTIVE: u8 = 6;
    /// `THREAD_QOS_LAST`.
    pub const LAST: u8 = 7;
}

/// `THREAD_QOS_MIN_TIER_IMPORTANCE` (and `QOS_MIN_RELATIVE_PRIORITY`).
pub const MIN_TIER_IMPORTANCE: i32 = -15;

pub const OVERCOMMIT_FLAG: u32 = 0x8000_0000;
pub const SCHED_PRI_FLAG: u32 = 0x2000_0000;
pub const FALLBACK_FLAG: u32 = 0x0400_0000;
pub const COOPERATIVE_FLAG: u32 = 0x0800_0000;
pub const EVENT_MANAGER_FLAG: u32 = 0x0200_0000;
pub const NEEDS_UNBIND_FLAG: u32 = 0x0100_0000;
pub const OVERRIDE_QOS_FLAG: u32 = 0x0080_0000;
pub const FLAGS_MASK: u32 = 0xff00_0000;
pub const SCHED_PRI_MASK: u32 = 0x0000_ffff;
pub const QOS_CLASS_MASK: u32 = 0x003f_ff00;
pub const QOS_CLASS_SHIFT: u32 = 8;
pub const VALID_QOS_CLASS_MASK: u32 = 0x0000_3f00;
pub const VALID_OVERRIDE_QOS_MASK: u32 = 0x003f_c000;
pub const QOS_OVERRIDE_SHIFT: u32 = 14;
pub const PRIORITY_MASK: u32 = 0x0000_00ff;

/// `_pthread_priority_has_qos`.
pub fn has_qos(pp: u32) -> bool {
    pp & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0 && pp & VALID_QOS_CLASS_MASK != 0
}

/// `_pthread_priority_has_sched_pri`.
pub fn has_sched_pri(pp: u32) -> bool {
    pp & SCHED_PRI_FLAG != 0
}

/// `_pthread_priority_has_override_qos`.
pub fn has_override_qos(pp: u32) -> bool {
    pp & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0
        && pp & OVERRIDE_QOS_FLAG != 0
        && pp & VALID_OVERRIDE_QOS_MASK != 0
}

/// `_pthread_priority_thread_qos_fast`: the lowest class bit, as a QoS.
pub fn thread_qos_fast(pp: u32) -> u8 {
    let bits = (pp & VALID_QOS_CLASS_MASK) >> QOS_CLASS_SHIFT;
    if bits == 0 {
        0
    } else {
        bits.trailing_zeros() as u8 + 1
    }
}

/// `_pthread_priority_thread_qos`.
pub fn thread_qos(pp: u32) -> u8 {
    if has_qos(pp) { thread_qos_fast(pp) } else { 0 }
}

/// `_pthread_priority_thread_override_qos`.
pub fn thread_override_qos(pp: u32) -> u8 {
    if !has_override_qos(pp) {
        return 0;
    }
    let bits = (pp & VALID_OVERRIDE_QOS_MASK) >> QOS_OVERRIDE_SHIFT;
    bits.trailing_zeros() as u8 + 1
}

/// `_pthread_priority_relpri`.
pub fn relpri(pp: u32) -> i32 {
    if has_qos(pp) {
        i32::from((pp & PRIORITY_MASK) as u8 as i8) + 1
    } else {
        0
    }
}

/// `_pthread_priority_make_from_thread_qos`.
pub fn make_from_thread_qos(qos: u8, relpri: i32, flags: u32) -> u32 {
    let mut pp = flags & FLAGS_MASK;
    if qos != 0 && qos < thread_qos::LAST {
        pp |= 1 << (QOS_CLASS_SHIFT + u32::from(qos) - 1);
        pp |= (relpri as u8).wrapping_sub(1) as u32 & PRIORITY_MASK;
    }
    pp
}

/// `_pthread_priority_normalize`: the flags the kernel keeps, and the
/// class with a valid relative priority.
pub fn normalize(pp: u32) -> u32 {
    if pp & EVENT_MANAGER_FLAG != 0 {
        return EVENT_MANAGER_FLAG;
    }
    if has_qos(pp) {
        let r = relpri(pp);
        let mut pp = pp;
        if r > 0 || r < MIN_TIER_IMPORTANCE {
            pp |= PRIORITY_MASK;
        }
        return pp & (OVERCOMMIT_FLAG | FALLBACK_FLAG | QOS_CLASS_MASK | PRIORITY_MASK);
    }
    0
}

/// `_pthread_priority_combine`: an event's priority, raised to `qos`.
pub fn combine(base: u32, qos: u8) -> u32 {
    if base & EVENT_MANAGER_FLAG != 0 {
        return EVENT_MANAGER_FLAG;
    }
    if base & FALLBACK_FLAG != 0 {
        if qos == 0 {
            return base;
        }
    } else if qos < thread_qos(base) {
        return base;
    }
    make_from_thread_qos(qos, 0, base & OVERCOMMIT_FLAG)
}

/// `_pthread_priority_to_policy`: whether a thread may request `pp`
/// (a QoS class with a relative priority in range).
pub fn to_policy_valid(pp: u32) -> bool {
    if !has_qos(pp) {
        return false;
    }
    let r = relpri(pp);
    r <= 0 && r >= MIN_TIER_IMPORTANCE
}

/// `_pthread_priority_is_overcommit`.
pub fn is_overcommit(pp: u32) -> bool {
    pp & OVERCOMMIT_FLAG != 0
}

/// `_pthread_priority_is_cooperative`.
pub fn is_cooperative(pp: u32) -> bool {
    pp & COOPERATIVE_FLAG != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_classes_like_libpthread() {
        // QOS_CLASS_DEFAULT with relative priority 0: 0x8ff.
        assert_eq!(make_from_thread_qos(thread_qos::LEGACY, 0, 0), 0x08ff);
        assert_eq!(thread_qos(0x08ff), thread_qos::LEGACY);
        assert_eq!(relpri(0x08ff), 0);
        // USER_INTERACTIVE, relative priority -3, overcommit.
        let pp = make_from_thread_qos(thread_qos::USER_INTERACTIVE, -3, OVERCOMMIT_FLAG);
        assert_eq!(pp, 0x8000_20fc);
        assert_eq!(thread_qos(pp), thread_qos::USER_INTERACTIVE);
        assert_eq!(relpri(pp), -3);
        // No class, a scheduler priority, or the manager: unspecified.
        assert_eq!(thread_qos(0), 0);
        assert_eq!(thread_qos(SCHED_PRI_FLAG | 0x0800), 0);
        assert_eq!(thread_qos(EVENT_MANAGER_FLAG), 0);
        assert_eq!(make_from_thread_qos(thread_qos::LAST, 0, 0), 0);
    }

    #[test]
    fn normalize_and_combine() {
        // A positive relative priority is clamped to 0 (0xff).
        assert_eq!(normalize(0x0800 | 0x05), 0x08ff);
        // Dispatch-only flags are dropped; overcommit stays.
        assert_eq!(normalize(0x5000_08ff | OVERCOMMIT_FLAG), 0x8000_08ff);
        assert_eq!(normalize(EVENT_MANAGER_FLAG | 0x0800), EVENT_MANAGER_FLAG);
        assert_eq!(normalize(SCHED_PRI_FLAG | 4), 0);
        // Raising DEFAULT to USER_INITIATED keeps overcommit, drops relpri.
        assert_eq!(
            combine(0x8000_08fe, thread_qos::USER_INITIATED),
            0x8000_10ff
        );
        // A lower QoS leaves the priority alone.
        assert_eq!(combine(0x10ff, thread_qos::UTILITY), 0x10ff);
        assert_eq!(combine(0, 0), 0);
        assert_eq!(combine(EVENT_MANAGER_FLAG, 4), EVENT_MANAGER_FLAG);
    }

    #[test]
    fn policy_validity() {
        assert!(to_policy_valid(0x08ff));
        assert!(to_policy_valid(0x0800 | (-16i8 as u8 as u32)));
        assert!(!to_policy_valid(0x0800 | (-17i8 as u8 as u32)));
        assert!(!to_policy_valid(0x0800));
        assert!(!to_policy_valid(0x00ff));
    }

    #[test]
    fn override_classes() {
        let pp = OVERRIDE_QOS_FLAG | (1 << (QOS_OVERRIDE_SHIFT + 4)) | 0x08ff;
        assert_eq!(thread_override_qos(pp), thread_qos::USER_INITIATED);
        assert_eq!(thread_override_qos(0x08ff), 0);
    }
}
