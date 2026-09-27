//! Serialized DLL/TLS startup and normal-exit guest continuations.
//!
//! TLS callbacks precede the PE DLL entry on attach. On detach the entry
//! precedes TLS callbacks, whose array order is unchanged. Reverse ready-native
//! plus dynamic UCRT completion order on detach is a personality profile: the public API
//! documentation does not specify every inter-category/dependency ordering.

use std::collections::VecDeque;

use super::{Proc, Thread};
use crate::user::windows::dll::libraries::{LoaderGuard, tls_callbacks, with_lock};
use crate::user::windows::hle::dispatch::{self, CallSite, Outcome};
use crate::user::windows::hle::{Api, ApiErr, ApiResult, Conv, Ctx, Flow};
use crate::user::windows::loader::{self, LoadError, ModuleKind};
use crate::user::windows::nt::status::*;

static START: Api = Api {
    name: "RtlUserThreadStart",
    args: &[],
    conv: Conv::Custom,
    imp: start,
};

static EXIT_THREAD: Api = Api {
    name: "RtlExitUserThread",
    args: &[],
    conv: Conv::Custom,
    imp: synthetic_exit,
};

static EXIT_PROCESS: Api = Api {
    name: "RtlExitUserProcess",
    args: &[],
    conv: Conv::Custom,
    imp: synthetic_exit,
};

fn synthetic_exit(_: &mut Ctx) -> ApiResult {
    Err(ApiErr::Internal(
        "synthetic exit requires an exit code".into(),
    ))
}

fn internal(error: LoadError) -> ApiErr {
    ApiErr::Internal(error.to_string())
}

/// Native initialization order only; data images, built-ins and dead entries
/// never receive process/thread DLL notifications.
fn native_order(p: &Proc, ready_only: bool) -> Vec<usize> {
    let order = if ready_only {
        // Nested loads can complete between outer initializers: completion
        // order, not mapping post-order, owns normal notification reversal.
        p.modules.ready_order()
    } else {
        p.modules.init_order.clone()
    };
    order
        .into_iter()
        .filter(|&index| {
            p.modules.is_live(index)
                && matches!(p.modules.list[index].kind, ModuleKind::Native)
                && (!ready_only || p.modules.list[index].initialized)
        })
        .collect()
}

/// Only UCRT admits a built-in process-detach hook in this profile. Other
/// built-ins stay pinned but have no invented DLL notifications.
fn process_order(p: &Proc) -> Vec<usize> {
    p.modules
        .ready_order()
        .into_iter()
        .filter(|&index| match p.modules.list[index].kind {
            ModuleKind::Native => true,
            ModuleKind::Builtin(dll) => dll.name == "ucrtbase.dll",
            _ => false,
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Callback {
    target: u64,
    dll_main: bool,
}

struct Attach {
    modules: std::vec::IntoIter<usize>,
    current: Option<usize>,
    callbacks: VecDeque<Callback>,
    /// Successful startup attachments only, for FALSE rollback.
    completed: Vec<usize>,
    process: bool,
}

fn start(c: &mut Ctx) -> ApiResult {
    with_lock(
        c,
        Box::new(|c, guard| {
            let process = c.t.main;
            let mut modules = native_order(c.p, !process);
            if c.p.modules.is_live(0) {
                // The executable's initial initialized=true meant only that it had
                // no DllMain. Track completion of its process TLS callbacks too:
                // startup failure must not detach an executable never attached.
                if process {
                    c.p.modules.list[0].initialized = false;
                }
                modules.push(0);
            }
            initialize(
                c,
                guard,
                Attach {
                    modules: modules.into_iter(),
                    current: None,
                    callbacks: VecDeque::new(),
                    completed: Vec::new(),
                    process,
                },
            )
        }),
    )
}

fn initialize(c: &mut Ctx, mut guard: LoaderGuard, mut attach: Attach) -> ApiResult {
    loop {
        if let Some(callback) = attach.callbacks.pop_front() {
            let Some(index) = attach.current else {
                return Err(ApiErr::Internal(
                    "initializer callback has no module".into(),
                ));
            };
            if attach.process && callback.dll_main {
                loader::attach_started(c.p, index, true).map_err(internal)?;
            }
            let reserved = if attach.process && callback.dll_main {
                c.p.params // DllMain static load: non-NULL; TLS always zero.
            } else {
                0
            };
            let reason = if attach.process { 1 } else { 2 };
            let base = c.p.modules.list[index].base;
            return Flow::call_checked(
                callback.target,
                vec![base, reason, reserved],
                move |c, result| {
                    if attach.process && callback.dll_main && result as u32 == 0 {
                        // The failing entry itself must receive PROCESS_DETACH;
                        // successfully attached predecessors follow in reverse.
                        let mut modules = vec![index];
                        modules.extend(attach.completed.into_iter().rev());
                        return detach(
                            c,
                            guard,
                            Detach::new(
                                modules,
                                0,
                                0,
                                true,
                                false,
                                Finish::Process(STATUS_DLL_INIT_FAILED),
                            ),
                        );
                    }
                    initialize(c, guard, attach)
                },
            );
        }
        if let Some(index) = attach.current.take() {
            if attach.process {
                loader::attach_succeeded(c.p, index).map_err(internal)?;
                attach.completed.push(index);
            }
        }
        let Some(index) = attach.modules.next() else {
            guard.finish(c)?;
            c.t.attached = true;
            let args = if c.t.main {
                Vec::new()
            } else {
                vec![c.t.param]
            };
            let main = c.t.main;
            // The notification lock is released before ordinary user code.
            return Flow::call_checked(c.t.start, args, move |_, result| {
                Ok(if main {
                    Flow::ExitProcess(result as u32)
                } else {
                    Flow::ExitThread(result as u32)
                })
            });
        };
        if !c.p.modules.is_live(index) {
            continue;
        }
        let module = &c.p.modules.list[index];
        if attach.process && module.initialized
            || !attach.process && (!module.initialized || !module.thread_calls)
        {
            continue;
        }
        let entry = module.has_dll_main().then_some(module.entry);
        let callbacks = tls_callbacks(c, index)?;
        attach.current = Some(index);
        attach
            .callbacks
            .extend(callbacks.into_iter().map(|target| Callback {
                target,
                dll_main: false,
            }));
        if let Some(target) = entry {
            attach.callbacks.push_back(Callback {
                target,
                dll_main: true,
            });
        }
        if attach.process {
            loader::attach_started(c.p, index, false).map_err(internal)?;
        }
    }
}

enum Finish {
    Thread(u32),
    Process(u32),
}

struct Detach {
    modules: std::vec::IntoIter<usize>,
    current: Option<usize>,
    callbacks: VecDeque<Callback>,
    reason: u64,
    reserved: u64,
    clear_ready: bool,
    skip_tls: bool,
    finish: Finish,
}

impl Detach {
    fn new(
        modules: Vec<usize>,
        reason: u64,
        reserved: u64,
        clear_ready: bool,
        skip_tls: bool,
        finish: Finish,
    ) -> Self {
        Self {
            modules: modules.into_iter(),
            current: None,
            callbacks: VecDeque::new(),
            reason,
            reserved,
            clear_ready,
            skip_tls,
            finish,
        }
    }
}

fn detach(c: &mut Ctx, mut guard: LoaderGuard, mut plan: Detach) -> ApiResult {
    loop {
        if let Some(callback) = plan.callbacks.pop_front() {
            let Some(index) = plan.current else {
                return Err(ApiErr::Internal("detach callback has no module".into()));
            };
            let reserved = if callback.dll_main { plan.reserved } else { 0 };
            let base = c.p.modules.list[index].base;
            return Flow::call_checked(
                callback.target,
                vec![base, plan.reason, reserved],
                move |c, _| {
                    // DllMain returns are ignored except for PROCESS_ATTACH;
                    // TLS callbacks have a VOID return type.
                    detach(c, guard, plan)
                },
            );
        }
        if let Some(index) = plan.current.take() {
            if plan.clear_ready {
                loader::detach_completed(c.p, index).map_err(internal)?;
            }
        }
        let Some(index) = plan.modules.next() else {
            guard.finish(c)?;
            return Ok(match plan.finish {
                Finish::Thread(code) => Flow::ExitThread(code),
                Finish::Process(code) => Flow::ExitProcess(code),
            });
        };
        if !c.p.modules.is_live(index) {
            continue;
        }
        if plan.reason == 0
            && matches!(c.p.modules.list[index].kind, ModuleKind::Builtin(dll) if dll.name == "ucrtbase.dll")
        {
            loader::detach_started(c.p, index).map_err(internal)?;
            plan.current = Some(index);
            return crate::user::windows::dll::crt::stdio::ucrt_process_detach(
                c,
                Box::new(move |c, _| detach(c, guard, plan)),
            );
        }
        let module = &c.p.modules.list[index];
        let entry = module.has_dll_main().then_some(module.entry);
        let callbacks = if plan.skip_tls {
            Vec::new()
        } else {
            tls_callbacks(c, index)?
        };
        plan.current = Some(index);
        if let Some(target) = entry {
            plan.callbacks.push_back(Callback {
                target,
                dll_main: true,
            });
        }
        plan.callbacks
            .extend(callbacks.into_iter().map(|target| Callback {
                target,
                dll_main: false,
            }));
        if plan.reason == 0 && !plan.callbacks.is_empty() {
            // Public lookups remain visible during cleanup, but a reentrant
            // FreeLibrary(self) must not start a second PROCESS_DETACH plan.
            // Thread detach does not retire process-wide module admission.
            loader::detach_started(c.p, index).map_err(internal)?;
        }
    }
}

/// Normal ExitThread only. The scheduler marks its exit stage and preserves
/// TEB/TLS/stack until the returned ThreadExit outcome; TerminateThread bypasses
/// this function. The PE TLS table excludes the original thread from thread
/// reasons, while DLL entries can still receive its THREAD_DETACH notification.
pub fn thread_exit(p: &mut Proc, t: &mut Thread, code: u32) -> Outcome {
    let site = exit_site(p, t, &EXIT_THREAD);
    dispatch::run(p, t, site, move |c| {
        with_lock(
            c,
            Box::new(move |c, guard| {
                let mut modules = native_order(c.p, true);
                modules.retain(|&index| c.p.modules.list[index].thread_calls);
                modules.reverse();
                if c.p.modules.is_live(0) && c.p.modules.list[0].initialized {
                    modules.push(0);
                }
                let plan = Detach::new(modules, 3, 0, false, c.t.main, Finish::Thread(code));
                detach(c, guard, plan)
            }),
        )
    })
}

/// Normal ExitProcess only. The scheduler has already terminated other threads
/// without THREAD_DETACH; the caller and process resources remain usable until
/// its final ProcessExit outcome. Forced process termination does not use this.
pub fn process_exit(p: &mut Proc, t: &mut Thread, code: u32) -> Outcome {
    let site = exit_site(p, t, &EXIT_PROCESS);
    dispatch::run(p, t, site, move |c| {
        with_lock(
            c,
            Box::new(move |c, guard| {
                let mut modules = process_order(c.p);
                modules.reverse();
                if c.p.modules.is_live(0) && c.p.modules.list[0].initialized {
                    modules.push(0);
                }
                let plan = Detach::new(modules, 0, c.p.params, true, false, Finish::Process(code));
                detach(c, guard, plan)
            }),
        )
    })
}

fn exit_site(_p: &Proc, t: &Thread, api: &'static Api) -> CallSite {
    let sp = t.cpu.sp();
    CallSite {
        api,
        entry_pc: t.cpu.pc(),
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp.saturating_sub(32) & !15,
        framed: false,
    }
}

/// Begins a newly created thread at the personality's startup trap.
pub fn thread_start(p: &mut Proc, t: &mut Thread) -> Outcome {
    let sp = t.cpu.sp();
    let site = CallSite {
        api: &START,
        entry_pc: p.traps.thread_start(),
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp.saturating_sub(32) & !15,
        framed: false,
    };
    dispatch::run(p, t, site, start)
}

#[cfg(test)]
#[path = "lifecycle/detach_tests.rs"]
mod detach_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::loader::{Module, ModuleTls};
    use crate::user::windows::memory::{Mem, mem, prot};
    use crate::user::windows::objects::Object;
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    // These tests step HLE continuations without executing callback bodies.
    // They verify ABI arguments/state transitions, not a native ordering oracle.
    pub(super) fn fixture(arch: WinArch) -> (WindowsProcess, Thread) {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        let mut config = WindowsConfig::new("lifecycle-test.exe", Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let t = p.threads.remove(&tid).unwrap();
        (process, t)
    }

    pub(super) fn native(p: &mut Proc, name: &str, callbacks: usize, ready: bool) -> usize {
        let base =
            p.vm.allocate(None, 0x1000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        for offset in 0..callbacks {
            p.space
                .wptr(
                    base + 0x200 + offset as u64 * p.arch.ptr_size(),
                    p.arch.ptr_size(),
                    base + 0x80 + offset as u64 * 0x10,
                )
                .unwrap();
        }
        p.space
            .wptr(
                base + 0x200 + callbacks as u64 * p.arch.ptr_size(),
                p.arch.ptr_size(),
                0,
            )
            .unwrap();
        let index = p.modules.list.len();
        p.modules.list.push(Module {
            name: name.into(),
            path: name.into(),
            host_path: None,
            base,
            size: 0x1000,
            entry: base + 0x100,
            kind: ModuleKind::Native,
            timestamp: 0,
            exports: Default::default(),
            pdata: Default::default(),
            no_seh: false,
            safe_seh: None,
            tls: (callbacks != 0).then_some(ModuleTls {
                index: 0,
                template: 0,
                raw_size: 0,
                zero_fill: 0,
                callbacks: base + 0x200,
            }),
            ldr_entry: 0,
            load_count: 1,
            thread_calls: true,
            initialized: false,
            builtin_symbols: Default::default(),
            builtin_ordinals: Vec::new(),
            text: 0,
            stubs: Default::default(),
        });
        p.modules.init_order.push(index);
        if ready {
            loader::attach_started(p, index, true).unwrap();
            loader::attach_succeeded(p, index).unwrap();
        }
        index
    }

    pub(super) fn args(p: &Proc, t: &Thread) -> [u64; 3] {
        std::array::from_fn(|index| match p.arch {
            WinArch::X86 => p.space.ptr(t.cpu.sp() + 4 + index as u64 * 4, 4).unwrap(),
            WinArch::X64 => t.cpu.gpr([1, 2, 8][index]),
            WinArch::Arm64 => t.cpu.gpr(index),
        })
    }

    pub(super) fn returned(p: &mut Proc, t: &mut Thread, value: u64) -> Outcome {
        t.cpu.set_gpr(0, value);
        dispatch::callback_return(p, t)
    }

    #[test]
    fn startup_commits_each_module_and_releases_lock_before_user_entry_all_abis() {
        for arch in WinArch::ALL {
            let (mut process, mut t) = fixture(arch);
            let p = process.state_mut();
            let first = native(p, "first.dll", 2, false);
            let second = native(p, "second.dll", 0, false);
            let base = p.modules.list[first].base;
            assert_ne!(p.params, 0);
            assert_eq!(thread_start(p, &mut t), Outcome::Continue);
            assert!(!p.loader.is_idle());
            assert_eq!(t.cpu.pc(), base + 0x80);
            assert_eq!(args(p, &t), [base, 1, 0]);
            assert_eq!(returned(p, &mut t, 0), Outcome::Continue); // TLS is VOID.
            assert_eq!(t.cpu.pc(), base + 0x90);
            assert_eq!(args(p, &t), [base, 1, 0]);
            assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
            assert_eq!(t.cpu.pc(), p.modules.list[first].entry);
            assert_eq!(args(p, &t), [base, 1, p.params]);
            assert_eq!(returned(p, &mut t, 1), Outcome::Continue);
            assert!(p.modules.list[first].initialized);
            assert!(!p.modules.list[second].initialized);
            assert_eq!(t.cpu.pc(), p.modules.list[second].entry);
            assert_eq!(returned(p, &mut t, 1), Outcome::Continue);
            assert!(p.modules.list[second].initialized);
            assert!(p.modules.list[0].initialized);
            assert!(t.attached);
            assert!(p.loader.is_idle());
            assert_eq!(t.cpu.pc(), t.start);
        }
    }

    #[test]
    fn startup_false_detaches_failing_then_ready_modules_without_repeat_all_abis() {
        for arch in WinArch::ALL {
            let (mut process, mut t) = fixture(arch);
            let p = process.state_mut();
            let first = native(p, "accepted.dll", 0, false);
            let second = native(p, "rejected.dll", 1, false);
            let second_base = p.modules.list[second].base;
            assert_eq!(thread_start(p, &mut t), Outcome::Continue);
            assert_eq!(returned(p, &mut t, 1), Outcome::Continue);
            assert_eq!(t.cpu.pc(), second_base + 0x80);
            assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
            assert_eq!(t.cpu.pc(), p.modules.list[second].entry);
            assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
            assert_eq!(t.cpu.pc(), p.modules.list[second].entry);
            assert_eq!(args(p, &t), [second_base, 0, 0]);
            assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
            assert_eq!(t.cpu.pc(), second_base + 0x80);
            assert_eq!(args(p, &t), [second_base, 0, 0]);
            assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
            assert!(!p.modules.list[second].initialized);
            assert_eq!(t.cpu.pc(), p.modules.list[first].entry);
            assert_eq!(args(p, &t), [p.modules.list[first].base, 0, 0]);
            assert_eq!(
                returned(p, &mut t, 0),
                Outcome::ProcessExit(STATUS_DLL_INIT_FAILED)
            );
            assert!(!p.modules.list[first].initialized);
            assert!(!p.modules.list[0].initialized);
            assert!(p.loader.is_idle());
            t.frames.clear();
            assert_eq!(
                process_exit(p, &mut t, STATUS_DLL_INIT_FAILED),
                Outcome::ProcessExit(STATUS_DLL_INIT_FAILED)
            );
            assert!(p.loader.is_idle());
        }
    }

    #[test]
    fn normal_detach_preserves_thread_resources_until_exit_outcome_all_abis() {
        for arch in WinArch::ALL {
            let (mut process, mut t) = fixture(arch);
            let p = process.state_mut();
            let first = native(p, "first.dll", 1, true);
            let second = native(p, "second.dll", 1, true);
            t.main = false;
            t.attached = true;
            t.frames.clear();
            assert_eq!(thread_exit(p, &mut t, 37), Outcome::Continue);
            for index in [second, first] {
                let base = p.modules.list[index].base;
                assert_eq!(t.cpu.pc(), p.modules.list[index].entry);
                assert_eq!(args(p, &t), [base, 3, 0]);
                assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
                assert_eq!(t.cpu.pc(), base + 0x80);
                assert_eq!(args(p, &t), [base, 3, 0]);
                let outcome = returned(p, &mut t, 0);
                assert_eq!(
                    outcome,
                    if index == first {
                        Outcome::ThreadExit(37)
                    } else {
                        Outcome::Continue
                    }
                );
            }
            assert!(p.loader.is_idle());
            assert!(p.modules.list[first].initialized);
            assert!(p.modules.list[second].initialized);
            assert!(matches!(
                p.objects.obj(t.obj),
                Some(Object::Thread {
                    exit_code: None,
                    ..
                })
            ));
            assert!(p.space.u32(t.teb).is_ok());
            assert!(p.space.u32(t.stack_base - 4).is_ok());

            t.frames.clear();
            assert_eq!(process_exit(p, &mut t, 49), Outcome::Continue);
            let second_base = p.modules.list[second].base;
            assert!(matches!(
                loader::begin_unload(p, second_base),
                Err(error) if error.status == STATUS_DLL_INIT_FAILED
            ));
            for index in [second, first] {
                let base = p.modules.list[index].base;
                assert_eq!(t.cpu.pc(), p.modules.list[index].entry);
                assert_eq!(args(p, &t), [base, 0, p.params]);
                assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
                assert_eq!(t.cpu.pc(), base + 0x80);
                assert_eq!(args(p, &t), [base, 0, 0]);
                let outcome = returned(p, &mut t, 0);
                assert_eq!(
                    outcome,
                    if index == first {
                        Outcome::ProcessExit(49)
                    } else {
                        Outcome::Continue
                    }
                );
            }
            assert!(!p.modules.list[first].initialized);
            assert!(!p.modules.list[second].initialized);
            assert!(!p.modules.list[0].initialized);
            assert!(p.loader.is_idle());
        }
    }

    #[test]
    fn detach_reverses_completion_order_not_mapping_order_all_abis() {
        for arch in WinArch::ALL {
            let (mut process, mut t) = fixture(arch);
            let p = process.state_mut();
            let first = native(p, "mapped-first.dll", 0, false);
            let second = native(p, "mapped-second.dll", 0, false);
            // This order models an inner load completing before its outer
            // DLL's attach returns; image mapping happened in the other order.
            for index in [second, first] {
                loader::attach_started(p, index, true).unwrap();
                loader::attach_succeeded(p, index).unwrap();
            }
            assert_eq!(native_order(p, true), [second, first]);
            t.attached = true;
            assert_eq!(thread_exit(p, &mut t, 52), Outcome::Continue);
            assert_eq!(t.cpu.pc(), p.modules.list[first].entry);
            assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
            assert_eq!(t.cpu.pc(), p.modules.list[second].entry);
            assert_eq!(returned(p, &mut t, 0), Outcome::ThreadExit(52));
            assert!(p.loader.is_idle());
        }
    }

    #[test]
    fn original_thread_and_suppressed_module_skip_thread_tls_notifications_all_abis() {
        for arch in WinArch::ALL {
            let (mut process, mut t) = fixture(arch);
            let p = process.state_mut();
            let first = native(p, "active.dll", 1, true);
            let second = native(p, "suppressed.dll", 0, true);
            p.modules.list[second].thread_calls = false;
            t.attached = true;
            assert!(t.main);
            assert_eq!(thread_exit(p, &mut t, 63), Outcome::Continue);
            assert_eq!(t.cpu.pc(), p.modules.list[first].entry);
            assert_eq!(args(p, &t), [p.modules.list[first].base, 3, 0]);
            assert_eq!(returned(p, &mut t, 0), Outcome::ThreadExit(63));
            assert!(p.loader.is_idle());
            assert!(p.modules.list[first].initialized);
            assert!(p.modules.list[second].initialized);
        }
    }
}
