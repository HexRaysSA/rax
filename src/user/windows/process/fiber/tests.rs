use super::*;
use crate::user::windows::hle::{Api, ApiResult, Conv, Ctx, Flow};
use crate::user::windows::process::{WindowsConfig, WindowsProcess, thread};

static CALLBACK: Api = Api {
    name: "HostFiberCallback",
    args: &[],
    conv: Conv::Custom,
    imp: noop,
};

static START_WRAPPER: Api = Api {
    name: "RtlUserThreadStart",
    args: &[],
    conv: Conv::Custom,
    imp: noop,
};

fn noop(_: &mut Ctx) -> ApiResult {
    Flow::ret(0)
}

fn process(arch: WinArch) -> WindowsProcess {
    let bytes: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::new("fiber-host.exe", Vec::new());
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap()
}

#[test]
fn fiber_conversion_switch_reconversion_owns_stacks_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let original_stack = t.stack_alloc;
        let original_pc = t.cpu.pc();
        let root = convert(p, &mut t, 0x1234, 1).unwrap();
        assert_eq!(p.space.ptr(root, arch.ptr_size()).unwrap(), 0x1234);
        assert_eq!(t.thread_stack_alloc, 0);
        assert_eq!(t.cpu.pc(), original_pc);
        let created = create(p, &t, 0x20000, PAGE_SIZE, 1, 0x12340000, 0x5678).unwrap();
        let allocated = p.fibers.fibers[&created].stack.alloc;
        let base = p.fibers.fibers[&created].stack.base;
        assert_eq!(
            p.vm.query(base - PAGE_SIZE).unwrap().state,
            crate::user::windows::memory::mem::COMMIT
        );
        assert_ne!(
            p.vm.query(base - 2 * PAGE_SIZE).unwrap().protect & prot::GUARD,
            0
        );
        assert_eq!(
            p.vm.query(allocated).unwrap().state,
            crate::user::windows::memory::mem::RESERVE
        );
        switch(p, &mut t, created).unwrap();
        assert_eq!(start_info(p, &t), Ok((0x12340000, 0x5678)));
        assert_eq!(t.stack_alloc, allocated);
        assert_eq!(t.cpu.teb(), t.teb);
        assert_eq!(
            p.space
                .ptr(t.teb + offsets(arch).teb_fiber_data, arch.ptr_size())
                .unwrap(),
            created
        );
        assert_eq!(
            validate_switch(p, &t, created),
            Err(STATUS_INVALID_PARAMETER)
        );
        switch(p, &mut t, root).unwrap();
        assert_eq!(t.cpu.pc(), original_pc);
        assert_eq!(t.stack_alloc, original_stack);
        assert_eq!(begin_delete(p, &t, created), Ok(false));
        finish_delete(p, created).unwrap();
        assert!(!p.fibers.contains(created));
        assert_eq!(
            p.vm.query(allocated).unwrap().state,
            crate::user::windows::memory::mem::FREE
        );
        reconvert(p, &mut t).unwrap();
        assert_eq!(t.thread_stack_alloc, original_stack);
        assert_eq!(p.fibers.len(), 0);
        assert_eq!(
            p.space
                .ptr(t.teb + offsets(arch).teb_fiber_data, arch.ptr_size())
                .unwrap(),
            0
        );
        p.threads.insert(tid, t);
    }
}

#[test]
fn fiber_invalid_sizes_and_faulting_conversion_are_transactional_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let before = p.vm.committed_bytes();
        assert_eq!(
            create(p, &t, u64::MAX, 4096, 0, 1, 2),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            create(p, &t, 0x10000, u64::MAX, 0, 1, 2),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            create(p, &t, 0x10000, 4096, 2, 1, 2),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(p.vm.committed_bytes(), before);
        let page = t.teb & !(PAGE_SIZE - 1);
        let old = p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        assert_eq!(convert(p, &mut t, 0, 1), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(p.vm.committed_bytes(), before);
        assert_eq!(p.fibers.len(), 0);
        assert_eq!(t.thread_stack_alloc, t.stack_alloc);
        p.vm.protect(page, PAGE_SIZE, old).unwrap();
        p.threads.insert(tid, t);
    }
}

#[test]
fn dormant_fiber_migrates_without_thread_tls_or_stack_ownership_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let first = *p.threads.keys().next().unwrap();
        let second = thread::create(p, 0x23450000, 0, 0x10000, false).unwrap();
        let mut a = p.threads.remove(&first).unwrap();
        let mut b = p.threads.remove(&second).unwrap();
        let a_root = convert(p, &mut a, 0, 1).unwrap();
        let b_root = convert(p, &mut b, 0, 1).unwrap();
        let f = create(p, &a, 0x10000, 4096, 1, 0x34560000, 7).unwrap();
        switch(p, &mut a, f).unwrap();
        assert_eq!(validate_switch(p, &b, f), Err(STATUS_INVALID_PARAMETER));
        a.cpu.set_pc(0xABC000);
        a.cpu.set_gpr(3, 0x12345678);
        let f_stack = a.stack_alloc;
        switch(p, &mut a, a_root).unwrap();
        switch(p, &mut b, f).unwrap();
        assert_eq!(b.cpu.teb(), b.teb);
        assert_eq!(b.cpu.pc(), 0xABC000);
        assert_eq!(b.cpu.gpr(3), 0x12345678);
        assert_eq!(b.stack_alloc, f_stack);
        assert_eq!(
            p.space
                .ptr(b.teb + offsets(arch).teb_tls_pointer, arch.ptr_size())
                .unwrap(),
            b.tls_array
        );
        switch(p, &mut b, b_root).unwrap();
        assert_eq!(begin_delete(p, &a, f), Ok(false));
        finish_delete(p, f).unwrap();
        p.threads.insert(first, a);
        p.threads.insert(second, b);
    }
}

#[test]
fn fiber_continuations_seh_and_fls_follow_context_not_thread_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let slot = p.tls.fls_alloc(0).unwrap();
        p.tls.fls_set(FlsKey::Thread(tid), slot, 42).unwrap();
        let root = convert(p, &mut t, 0, 1).unwrap();
        assert_eq!(p.tls.fls_get(FlsKey::Fiber(root), slot), Ok(42));
        assert_eq!(p.tls.fls_get(FlsKey::Thread(tid), slot), Ok(0));
        p.space
            .wptr(
                t.teb + offsets(arch).teb_exception_list,
                arch.ptr_size(),
                0x12340000,
            )
            .unwrap();
        p.space
            .w32(t.teb + offsets(arch).teb_guaranteed_stack_bytes, 8192)
            .unwrap();
        t.frames.push(Frame {
            api: &CALLBACK,
            entry_pc: 0xABC0,
            entry_sp: t.cpu.sp(),
            ret_addr: 0xDEF0,
            cursor: t.cpu.sp(),
            cont: Some(Box::new(|_, _| Flow::ret(7))),
            retry: None,
        });
        let f = create(p, &t, 0x10000, 4096, 1, 0x34560000, 0).unwrap();
        switch(p, &mut t, f).unwrap();
        assert!(t.frames.is_empty());
        assert_eq!(p.fibers.fibers[&root].frames.len(), 1);
        assert_eq!(p.tls.fls_get(FlsKey::Fiber(f), slot), Ok(0));
        switch(p, &mut t, root).unwrap();
        assert_eq!(t.frames.len(), 1);
        assert_eq!(t.frames[0].api.name, CALLBACK.name);
        assert_eq!(
            p.space
                .ptr(t.teb + offsets(arch).teb_exception_list, arch.ptr_size())
                .unwrap(),
            0x12340000
        );
        assert_eq!(
            p.space
                .u32(t.teb + offsets(arch).teb_guaranteed_stack_bytes)
                .unwrap(),
            8192
        );
        reconvert(p, &mut t).unwrap();
        assert_eq!(p.tls.fls_get(FlsKey::Thread(tid), slot), Ok(42));
        t.frames.clear();
        p.threads.insert(tid, t);
    }
}

#[test]
fn x86_float_switch_restores_saving_targets_and_shares_nonsaving_targets() {
    fn mxcsr(cpu: &WinCpu) -> u32 {
        let bytes = cpu.x86().unwrap().vcpu().xsave_image(3).bytes;
        u32::from_le_bytes(bytes[24..28].try_into().unwrap())
    }
    fn set_mxcsr(cpu: &mut WinCpu, value: u32) {
        let core = cpu.x86_mut().unwrap().vcpu_mut();
        let mut image = core.xsave_image(3).bytes;
        image[24..28].copy_from_slice(&value.to_le_bytes());
        core.fxrstor_image(&image).unwrap();
    }
    let mut process = process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let root = convert(p, &mut t, 0, 1).unwrap();
    let save = create(p, &t, 0x10000, 4096, 1, 1, 0).unwrap();
    let shared = create(p, &t, 0x10000, 4096, 0, 1, 0).unwrap();
    set_mxcsr(&mut t.cpu, 0x3F80);
    switch(p, &mut t, save).unwrap();
    assert_eq!(mxcsr(&t.cpu), 0x1F80);
    set_mxcsr(&mut t.cpu, 0x5F80);
    switch(p, &mut t, root).unwrap();
    assert_eq!(mxcsr(&t.cpu), 0x3F80);
    switch(p, &mut t, shared).unwrap();
    assert_eq!(mxcsr(&t.cpu), 0x3F80);
    set_mxcsr(&mut t.cpu, 0x7F80);
    switch(p, &mut t, save).unwrap();
    assert_eq!(mxcsr(&t.cpu), 0x5F80);
    switch(p, &mut t, shared).unwrap();
    assert_eq!(mxcsr(&t.cpu), 0x5F80);
    p.threads.insert(tid, t);
}

#[test]
fn fiber_cap_precedes_new_stack_and_heap_effects_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        for handle in 1..=MAX_FIBERS as u64 {
            p.fibers.fibers.insert(
                handle,
                Fiber {
                    cpu: None,
                    frames: Vec::new(),
                    stack: Stack {
                        alloc: 0,
                        base: 0,
                        limit: 0,
                        exception_list: 0,
                        guaranteed_bytes: 0,
                    },
                    active: None,
                    deleting: false,
                    flags: 0,
                    start: 0,
                    parameter: 0,
                    last_tid: tid,
                    thread_bound: false,
                },
            );
        }
        let before = p.vm.committed_bytes();
        assert_eq!(create(p, &t, 0x10000, 4096, 1, 1, 0), Err(STATUS_NO_MEMORY));
        assert_eq!(convert(p, &mut t, 0, 1), Err(STATUS_NO_MEMORY));
        assert_eq!(p.vm.committed_bytes(), before);
        assert_eq!(p.fibers.len(), MAX_FIBERS);
        p.fibers.fibers.clear(); // Synthetic ledgers have no guest allocations.
        p.threads.insert(tid, t);
    }
}

#[test]
fn active_cleanup_does_not_destroy_other_owned_dormant_stacks_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let root = convert(p, &mut t, 0, 1).unwrap();
        let root_stack = t.stack_alloc;
        let f = create(p, &t, 0x10000, 4096, 1, 1, 0).unwrap();
        let f_stack = p.fibers.fibers[&f].stack.alloc;
        switch(p, &mut t, f).unwrap();
        destroy_active(p, &t).unwrap();
        assert!(!p.fibers.contains(f));
        assert!(p.fibers.contains(root));
        assert!(p.fibers.retains_stack(root_stack));
        assert_eq!(
            p.vm.query(f_stack).unwrap().state,
            crate::user::windows::memory::mem::FREE
        );
        assert_ne!(
            p.vm.query(root_stack).unwrap().state,
            crate::user::windows::memory::mem::FREE
        );
        t.current_fiber = None; // This host test already performed final cleanup.
        t.stack_alloc = 0;
        p.threads.insert(tid, t);
        destroy_all(p).unwrap();
        assert_eq!(p.fibers.len(), 0);
        assert_eq!(
            p.vm.query(root_stack).unwrap().state,
            crate::user::windows::memory::mem::FREE
        );
    }
}

#[test]
fn recycled_opaque_marker_cannot_replace_a_live_context_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let root = convert(p, &mut t, 0x1234, 1).unwrap();
        let stack = t.stack_alloc;
        p.heaps.free(p.process_heap, root).unwrap(); // Invalid private-object tampering.
        assert_eq!(reconvert(p, &mut t), Err(STATUS_INVALID_PARAMETER));
        let before = p.vm.committed_bytes();
        assert_eq!(
            create(p, &t, 0x10000, 4096, 1, 1, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(p.vm.committed_bytes(), before);
        assert_eq!(p.fibers.len(), 1);
        assert_eq!(p.fibers.fibers[&root].stack.alloc, stack);
        assert_eq!(t.current_fiber, Some(root));
        p.threads.insert(tid, t);
    }
}

#[test]
fn fiber_stack_commit_promotion_obeys_1mib_boundaries_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let t = p.threads.remove(&tid).unwrap();
        for (reserve, commit, expected_reserve, expected_commit) in [
            (0x10000, 0x10000, 0x100000, 0x10000),
            (0x100000, 0x100000, 0x100000, 0x100000),
            (0x10000, 0x100001, 0x200000, 0x101000),
            (0x10001, 0x10000, 0x20000, 0x10000),
        ] {
            let f = create(p, &t, reserve, commit, 1, 1, 0).unwrap();
            let stack = &p.fibers.fibers[&f].stack;
            assert_eq!(stack.base - stack.alloc, expected_reserve);
            assert_eq!(stack.base - stack.limit, expected_commit);
            if expected_reserve == expected_commit {
                assert_eq!(stack.limit, stack.alloc);
                assert_eq!(p.vm.query(stack.alloc).unwrap().protect, prot::READWRITE);
            } else {
                assert_ne!(
                    p.vm.query(stack.limit - PAGE_SIZE).unwrap().protect & prot::GUARD,
                    0
                );
            }
            assert_eq!(begin_delete(p, &t, f), Ok(false));
            finish_delete(p, f).unwrap();
        }
        p.threads.insert(tid, t);
    }
}

#[test]
fn loader_owned_start_wrapper_is_thread_bound_until_callback_completes_all_abis() {
    use crate::user::windows::dll::libraries::with_lock;
    use crate::user::windows::hle::dispatch::{CallSite, Outcome, complete};
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let first = *p.threads.keys().next().unwrap();
        let second = thread::create(p, 1, 0, 0x10000, false).unwrap();
        let mut a = p.threads.remove(&first).unwrap();
        let mut b = p.threads.remove(&second).unwrap();
        let a_root = convert(p, &mut a, 0, 1).unwrap();
        convert(p, &mut b, 0, 1).unwrap();
        let f = create(p, &a, 0x10000, 4096, 1, 1, 0).unwrap();
        let sp = a.cpu.sp();
        let site = CallSite {
            api: &START_WRAPPER,
            entry_pc: a.cpu.pc(),
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp.saturating_sub(32) & !15,
            framed: false,
        };
        let target = p.modules.list[0].entry;
        let result = with_lock(
            &mut Ctx {
                p,
                t: &mut a,
                api: &START_WRAPPER,
                entry_pc: site.entry_pc,
                entry_sp: sp,
                ret_addr: 0,
                cursor: site.cursor,
            },
            Box::new(move |_, mut guard| {
                Flow::call(target, Vec::new(), move |c, _| {
                    guard.finish(c)?;
                    Flow::void()
                })
            }),
        );
        assert_eq!(complete(p, &mut a, site, result), Outcome::Continue);
        assert!(p.loader.held_by(first));
        switch(p, &mut a, f).unwrap();
        assert!(p.fibers.fibers[&a_root].thread_bound);
        assert_eq!(validate_switch(p, &b, a_root), Err(STATUS_NOT_SUPPORTED));
        switch(p, &mut a, a_root).unwrap();
        let frame = a.frames.pop().unwrap();
        let mut c = Ctx {
            p,
            t: &mut a,
            api: frame.api,
            entry_pc: frame.entry_pc,
            entry_sp: frame.entry_sp,
            ret_addr: frame.ret_addr,
            cursor: frame.cursor,
        };
        assert!(frame.cont.unwrap()(&mut c, 1).is_ok());
        assert!(p.loader.is_idle());
        // Recapture after the thread-bound continuation has completed.
        switch(p, &mut a, f).unwrap();
        assert!(!p.fibers.fibers[&a_root].thread_bound);
        assert!(validate_switch(p, &b, a_root).is_ok());
        p.threads.insert(first, a);
        p.threads.insert(second, b);
    }
}
