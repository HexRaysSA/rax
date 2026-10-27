//! Owned user-alert consumption and synchronous guest APC delivery.
use crate::host::time::Instant;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::{STATUS_ALERTED, STATUS_SUCCESS};
use crate::user::windows::process::thread::AlertCheck;
use crate::user::windows::sync::Wait;

pub(super) fn test(c: &mut Ctx) -> ApiResult {
    // An existing user alert wins over a queued APC and is consumed exactly
    // once. Guest thread state never queries or changes a host thread alert.
    match c.t.check_user_alert() {
        AlertCheck::Alerted => return Flow::ret(u64::from(STATUS_ALERTED)),
        AlertCheck::Empty => return Flow::ret(u64::from(STATUS_SUCCESS)),
        AlertCheck::PendingApcs => {}
    }
    // Reuse the scheduler's checked wait/APC frame ownership: it captures the
    // interrupted CPU, drains the queue (including nested/appended work), then
    // restores this continuation. The zero deadline cannot delay completion.
    // STATUS_USER_APC is an internal wake reason; NtTestAlert returns SUCCESS
    // after delivery. Callback changes to guest TEB memory remain observable.
    Flow::block(
        Wait::Sleep {
            deadline: Some(Instant::now()),
            alertable: true,
        },
        |_, _| Flow::ret(u64::from(STATUS_SUCCESS)),
    )
}
