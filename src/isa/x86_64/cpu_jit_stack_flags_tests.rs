//! Helper, native, fault-frontier, and direct differentials for PUSHF/POPF.

use super::*;
use crate::isa::x86_64::execute::system::X86_INTERRUPT_CONTROL_RFLAGS_MASK;
use crate::smir::lower::runtime::GuestRegs;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const CR0_PE: u64 = 1;
const CR0_AM: u64 = 1 << 18;
const CR4_VME: u64 = 1;
const EFER_LMA: u64 = 1 << 10;

const POPF_MODIFIABLE_W64: u64 = flags::bits::CF
    | flags::bits::PF
    | flags::bits::AF
    | flags::bits::ZF
    | flags::bits::SF
    | flags::bits::TF
    | flags::bits::IF
    | flags::bits::DF
    | flags::bits::OF
    | flags::bits::IOPL_MASK
    | flags::bits::NT
    | flags::bits::AC
    | flags::bits::ID;

fn memory_with_code(code: &[u8]) -> Arc<GuestMemoryMmap> {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1_0000)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    memory
}

fn test_vcpu(memory: Arc<GuestMemoryMmap>) -> X86_64Vcpu {
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.cr0 = CR0_PE;
    vcpu.sregs.efer = EFER_LMA;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.selector = 0;
    vcpu.regs.rip = 0;
    vcpu.regs.rsp = 0x8000;
    vcpu.regs.rbp = 0x7000;
    vcpu.regs.rax = 0x0123_4567_89AB_CDEF;
    vcpu.regs.rbx = 0xF0E1_D2C3_B4A5_9687;
    vcpu.regs.r15 = 0x1515_1515_1515_1515;
    vcpu.regs.r31 = 0x3131_3131_3131_3131;
    vcpu.regs.rflags = 0x2 | flags::bits::CF | flags::bits::DF | flags::bits::IF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);
    vcpu
}

fn helper_state(vcpu: &mut X86_64Vcpu, rsp: u64, rflags: u64) -> GuestRegs {
    let mut state = GuestRegs::default();
    state.ctx = (vcpu as *mut X86_64Vcpu) as u64;
    state.gpr[0] = 0x0123_4567_89AB_CDEF;
    state.gpr[3] = 0xF0E1_D2C3_B4A5_9687;
    state.gpr[4] = rsp;
    state.gpr[15] = 0x1515_1515_1515_1515;
    state.gpr[31] = 0x3131_3131_3131_3131;
    state.rflags = rflags & !flags::bits::AC;
    state.ac_flag = u64::from(rflags & flags::bits::AC != 0);
    state.interrupt_flags = rflags & X86_INTERRUPT_CONTROL_RFLAGS_MASK;
    state.cr0 = vcpu.sregs.cr0;
    state.cr4 = vcpu.sregs.cr4;
    state.efer = vcpu.sregs.efer;
    state.cs_l = u64::from(vcpu.sregs.cs.l);
    state.cpl = if rflags & flags::bits::VM != 0 {
        3
    } else {
        u64::from(vcpu.sregs.cs.selector & 3)
    };
    state.apx_enabled = u64::from(vcpu.apx_enabled());
    state
}

fn scalar_state(vcpu: &X86_64Vcpu) -> [u64; 9] {
    [
        vcpu.regs.rax,
        vcpu.regs.rbx,
        vcpu.regs.rsp,
        vcpu.regs.rbp,
        vcpu.regs.r15,
        vcpu.regs.r31,
        vcpu.regs.rip,
        vcpu.regs.rflags,
        u64::from(vcpu.interrupt_inhibit),
    ]
}

struct UserRam;

impl crate::vm::memory::FlatTranslation for UserRam {
    fn translate(
        &self,
        linear: u64,
        access: crate::error::MemoryAccessKind,
    ) -> std::result::Result<u64, crate::error::GuestMemoryFault> {
        if linear < 0x1_0000 {
            Ok(linear)
        } else {
            Err(crate::error::GuestMemoryFault::unmapped(linear, 1, access))
        }
    }
}

#[test]
fn user_popf_enabling_tf_deoptimizes_before_any_native_commit() {
    // POPFQ; INC EAX; SYSCALL. A helper must return at POPFQ, allowing its
    // direct replay to arm TF without tracing POPFQ itself or running INC.
    let memory = memory_with_code(&[0x9d, 0xff, 0xc0, 0x0f, 0x05]);
    let mut cpu = test_vcpu(memory.clone());
    cpu.enable_user_mode(Arc::new(UserRam));
    cpu.regs.rsp = 0x8000;
    memory
        .write_obj(0x202u64 | flags::bits::TF, GuestAddress(0x8000))
        .unwrap();
    let mut state = helper_state(&mut cpu, 0x8000, 0x202);
    let before_state = state;
    cpu.jit_mem_trace = Some(Vec::new());
    assert_eq!(
        unsafe { rax_jit_stack_flags(&mut state, 1, 8, 0, 0x202) },
        0
    );
    assert_eq!(state, before_state);
    assert!(cpu.jit_mem_trace.as_ref().unwrap().is_empty());
    cpu.jit_mem_trace = None;

    let before = scalar_state(&cpu);
    let region = cpu
        .jit_compile_region()
        .unwrap()
        .expect("native POPFQ region");
    cpu.jit_run_region_native(&region);
    assert_eq!(scalar_state(&cpu), before);
    assert!(cpu.step_with_faults().unwrap().is_none());
    assert_eq!(cpu.regs.rip, 1);
    assert_eq!(cpu.regs.rsp, 0x8008);
    assert_ne!(cpu.user_rflags() & flags::bits::TF, 0);
    assert!(matches!(
        cpu.step_with_faults(),
        Err(Error::GuestEvent { vector: 1 })
    ));
    assert_eq!(cpu.regs.rip, 3);
    assert_eq!(cpu.regs.rax, (before[0] as u32).wrapping_add(1) as u64);
}

#[test]
fn user_tf_rejects_cached_regions_and_hot_promotion() {
    let memory = memory_with_code(&[0xff, 0xc0, 0xff, 0xc0, 0x0f, 0x05]);
    let mut cpu = test_vcpu(memory);
    cpu.enable_user_mode(Arc::new(UserRam));
    cpu.jit_hot.insert(0, JIT_HOT_THRESHOLD - 1);
    cpu.jit_sample_backedge(0x100);
    assert_eq!(cpu.jit_region_count(), 1);
    cpu.regs.rip = 0;
    cpu.set_user_rflags(0x202 | flags::bits::TF);
    let before = scalar_state(&cpu);
    assert!(!cpu.jit_try_block().unwrap());
    assert!(cpu.jit_compile_region().unwrap().is_none());
    assert_eq!(scalar_state(&cpu), before);
    cpu.jit_hot.insert(0, 7);
    cpu.jit_sample_backedge(0x100);
    assert_eq!(cpu.jit_hot.get(&0), Some(&7));
    assert!(matches!(cpu.run(), Err(Error::GuestEvent { vector: 1 })));
    assert_eq!(cpu.regs.rip, 2);
    assert_eq!(cpu.regs.rax, (before[0] as u32).wrapping_add(1) as u64);
}

#[test]
fn stack_flags_helper_commits_complete_push_and_pop_transactions() {
    let memory = memory_with_code(&[]);
    let mut vcpu = test_vcpu(memory.clone());
    let push_flags = 0xF000_0000_0000_0002
        | flags::bits::CF
        | flags::bits::PF
        | flags::bits::AF
        | flags::bits::ZF
        | flags::bits::SF
        | flags::bits::TF
        | flags::bits::IF
        | flags::bits::DF
        | flags::bits::OF
        | flags::bits::IOPL_MASK
        | flags::bits::NT
        | flags::bits::RF
        | flags::bits::AC
        | flags::bits::VIF
        | flags::bits::VIP
        | flags::bits::ID;
    let mut push = helper_state(&mut vcpu, 0x8000, push_flags);
    let push_gprs = push.gpr;
    vcpu.jit_mem_trace = Some(Vec::new());

    assert_eq!(
        unsafe { rax_jit_stack_flags(&mut push, 0, 8, 0, push_flags) },
        1
    );
    assert_eq!(push.gpr[4], 0x7FF8);
    assert_eq!(
        memory.read_obj::<u64>(GuestAddress(0x7FF8)).unwrap(),
        push_flags & 0x00FC_FFFF
    );
    for index in 0..push.gpr.len() {
        if index != 4 {
            assert_eq!(push.gpr[index], push_gprs[index], "GPR {index}");
        }
    }
    assert_eq!(push.stack_flags_rflags_valid, 0);
    assert_eq!(
        vcpu.jit_mem_trace.as_deref(),
        Some(&[(1, 0x7FF8, 8, push_flags & 0x00FC_FFFF)][..])
    );

    let old = 0x2 | flags::bits::RF | flags::bits::VIF | flags::bits::VIP;
    let popped = POPF_MODIFIABLE_W64;
    memory.write_obj(popped, GuestAddress(0x8100)).unwrap();
    let mut pop = helper_state(&mut vcpu, 0x8100, old);
    let pop_gprs = pop.gpr;
    vcpu.jit_mem_trace = Some(Vec::new());
    assert_eq!(unsafe { rax_jit_stack_flags(&mut pop, 1, 8, 0, old) }, 1);
    let expected = ((old & !POPF_MODIFIABLE_W64) | popped) & !flags::bits::RF;
    assert_eq!(pop.gpr[4], 0x8108);
    assert_eq!(pop.stack_flags_rflags, expected);
    assert_eq!(pop.stack_flags_rflags_valid, 1);
    assert_eq!(pop.rflags, expected & !flags::bits::AC);
    assert_eq!(pop.ac_flag, 1);
    assert_eq!(
        pop.interrupt_flags,
        expected & X86_INTERRUPT_CONTROL_RFLAGS_MASK
    );
    for index in 0..pop.gpr.len() {
        if index != 4 {
            assert_eq!(pop.gpr[index], pop_gprs[index], "GPR {index}");
        }
    }
    assert_eq!(
        vcpu.jit_mem_trace.as_deref(),
        Some(&[(0, 0x8100, 8, popped)][..])
    );
}

#[test]
fn vme_post_read_gp_deopts_without_state_or_trace_commit() {
    let memory = memory_with_code(&[]);
    let mut vcpu = test_vcpu(memory.clone());
    vcpu.sregs.cr4 = CR4_VME;
    let rflags = 0x2
        | flags::bits::VM
        | flags::bits::VIF
        | flags::bits::VIP
        | flags::bits::CF
        | flags::bits::DF;
    memory
        .write_obj(flags::bits::IF as u16, GuestAddress(0x8000))
        .unwrap();
    let mut state = helper_state(&mut vcpu, 0x8000, rflags);
    let before = state;
    let sentinel = (0, 0x1234, 1, 0x56);
    vcpu.jit_mem_trace = Some(vec![sentinel]);

    assert_eq!(
        unsafe { rax_jit_stack_flags(&mut state, 1, 2, 0, rflags) },
        0
    );
    assert_eq!(state, before);
    assert_eq!(vcpu.jit_mem_trace.as_deref(), Some(&[sentinel][..]));

    memory.write_obj(0_u16, GuestAddress(0x8000)).unwrap();
    assert_eq!(
        unsafe { rax_jit_stack_flags(&mut state, 1, 2, 0, rflags) },
        1
    );
    assert_eq!(state.gpr[4], 0x8002);
    assert_eq!(state.stack_flags_rflags_valid, 1);
    assert_eq!(state.stack_flags_rflags & flags::bits::VIF, 0);
    assert_eq!(
        state.stack_flags_rflags & flags::bits::VIP,
        flags::bits::VIP
    );
}

#[test]
fn stack_flags_helper_rejections_are_noncommitting_and_nonobservable() {
    assert_eq!(
        unsafe { rax_jit_stack_flags(std::ptr::null_mut(), 0, 8, 0, 0) },
        0
    );

    let memory = memory_with_code(&[]);
    let mut vcpu = test_vcpu(memory);
    let mut state = helper_state(&mut vcpu, 0x8000, 0x2 | flags::bits::CF);
    let baseline = state;
    let trace = (1, 0x1234, 1, 0x56);
    vcpu.jit_mem_trace = Some(vec![trace]);

    for (name, kind, width, apx) in [
        ("kind", 2, 8, 0),
        ("width", 0, 4, 0),
        ("APX field", 0, 8, 2),
        ("APX disabled", 0, 8, 1),
    ] {
        assert_eq!(
            unsafe { rax_jit_stack_flags(&mut state, kind, width, apx, 0x2) },
            0,
            "{name}"
        );
        assert_eq!(state, baseline, "{name}");
        assert_eq!(vcpu.jit_mem_trace.as_deref(), Some(&[trace][..]), "{name}");
    }

    state.gpr[4] = 0x0000_8000_0000_0008;
    let noncanonical = state;
    assert_eq!(unsafe { rax_jit_stack_flags(&mut state, 0, 8, 0, 0x2) }, 0);
    assert_eq!(state, noncanonical);

    state = baseline;
    state.gpr[4] = 0x8001;
    state.cr0 |= CR0_AM;
    state.cpl = 3;
    state.ac_flag = 1;
    let unaligned = state;
    assert_eq!(unsafe { rax_jit_stack_flags(&mut state, 1, 8, 0, 0x2) }, 0);
    assert_eq!(state, unaligned);

    state = baseline;
    vcpu.mmu.mark_code_page(0x7FF8);
    assert_eq!(unsafe { rax_jit_stack_flags(&mut state, 0, 8, 0, 0x2) }, 0);
    assert_eq!(state, baseline);
}

#[test]
fn native_stack_flags_matches_direct_across_width_privilege_and_apx_forms() {
    struct Case {
        name: &'static str,
        instruction: &'static [u8],
        popped: Option<u64>,
        cpl: u16,
        apx: bool,
    }
    let cases = [
        Case {
            name: "pushfq",
            instruction: &[0x9C],
            popped: None,
            cpl: 0,
            apx: false,
        },
        Case {
            name: "pushfw",
            instruction: &[0x66, 0x9C],
            popped: None,
            cpl: 0,
            apx: false,
        },
        Case {
            name: "66 REX.W pushfq",
            instruction: &[0x66, 0x48, 0x9C],
            popped: None,
            cpl: 0,
            apx: false,
        },
        Case {
            name: "REX2 pushfq",
            instruction: &[0xD5, 0x08, 0x9C],
            popped: None,
            cpl: 0,
            apx: true,
        },
        Case {
            name: "popfq cpl0 full controls",
            instruction: &[0x9D],
            popped: Some(POPF_MODIFIABLE_W64),
            cpl: 0,
            apx: false,
        },
        Case {
            name: "popfw preserves AC ID",
            instruction: &[0x66, 0x9D],
            popped: Some(0xFFFF),
            cpl: 0,
            apx: false,
        },
        Case {
            name: "66 REX.W popfq",
            instruction: &[0x66, 0x48, 0x9D],
            popped: Some(POPF_MODIFIABLE_W64),
            cpl: 0,
            apx: false,
        },
        Case {
            name: "popfq cpl3 iopl0",
            instruction: &[0x9D],
            popped: Some(POPF_MODIFIABLE_W64),
            cpl: 3,
            apx: false,
        },
    ];

    for case in cases {
        let mut code = case.instruction.to_vec();
        let frontier = code.len() as u64;
        code.push(0xF4);
        let direct_memory = memory_with_code(&code);
        let native_memory = memory_with_code(&code);
        let mut direct = test_vcpu(direct_memory.clone());
        let mut native = test_vcpu(native_memory.clone());
        for candidate in [&mut direct, &mut native] {
            candidate.sregs.cs.selector = case.cpl;
            candidate.set_apx_enabled(case.apx);
            candidate.regs.rflags = 0x2
                | flags::bits::CF
                | flags::bits::DF
                | flags::bits::RF
                | flags::bits::VIF
                | flags::bits::VIP
                | if case.instruction.starts_with(&[0x66]) {
                    flags::bits::AC | flags::bits::ID
                } else {
                    0
                };
        }
        if let Some(popped) = case.popped {
            direct_memory
                .write_obj(popped, GuestAddress(direct.regs.rsp))
                .unwrap();
            native_memory
                .write_obj(popped, GuestAddress(native.regs.rsp))
                .unwrap();
        }

        assert!(
            direct.step().expect("direct stack-flags").is_none(),
            "{}",
            case.name
        );
        assert_eq!(direct.regs.rip, frontier, "{}", case.name);
        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{}: {error}", case.name))
            .unwrap_or_else(|| panic!("{}: not native eligible", case.name));
        native.jit_run_region_native(&region);

        assert_eq!(
            scalar_state(&native),
            scalar_state(&direct),
            "{}",
            case.name
        );
        let start = direct.regs.rsp.min(native.regs.rsp).saturating_sub(8);
        let mut direct_stack = [0_u8; 24];
        let mut native_stack = [0_u8; 24];
        direct_memory
            .read_slice(&mut direct_stack, GuestAddress(start))
            .unwrap();
        native_memory
            .read_slice(&mut native_stack, GuestAddress(start))
            .unwrap();
        assert_eq!(native_stack, direct_stack, "{}: stack", case.name);
    }
}

#[test]
fn native_push_flags_continues_through_following_scalar_work() {
    // PUSHFQ; MOV RAX,RSP; INC RAX; HLT. A helper-backed PUSHFQ preserves
    // native flags and publishes its new guest RSP to state-backed successors,
    // so the complete scalar sequence remains in one region.
    let code = [0x9C, 0x48, 0x89, 0xE0, 0x48, 0xFF, 0xC0, 0xF4];
    let direct_memory = memory_with_code(&code);
    let native_memory = memory_with_code(&code);
    let mut direct = test_vcpu(direct_memory.clone());
    let mut native = test_vcpu(native_memory.clone());

    assert!(direct.step().expect("direct PUSHFQ").is_none());
    assert!(direct.step().expect("direct MOV RAX,RSP").is_none());
    assert!(direct.step().expect("direct INC RAX").is_none());
    direct.materialize_flags();
    let region = native
        .jit_compile_region()
        .expect("compile PUSHFQ successor region")
        .expect("PUSHFQ successor must remain native eligible");
    native.jit_run_region_native(&region);

    assert_eq!(scalar_state(&native), scalar_state(&direct));
    assert_eq!(native.regs.rip, 7, "one native run must reach HLT");
    assert_eq!(
        native_memory
            .read_obj::<u64>(GuestAddress(native.regs.rsp))
            .unwrap(),
        direct_memory
            .read_obj::<u64>(GuestAddress(direct.regs.rsp))
            .unwrap()
    );
}

#[test]
fn native_stack_flags_faults_deoptimize_at_the_exact_noncommitting_frontier() {
    let cases: [(&str, &[u8], fn(&mut X86_64Vcpu)); 3] = [
        ("unmapped push", &[0x9C][..], |vcpu: &mut X86_64Vcpu| {
            vcpu.regs.rsp = 0x1_0008
        }),
        ("noncanonical pop", &[0x9D][..], |vcpu: &mut X86_64Vcpu| {
            vcpu.regs.rsp = 0x0000_8000_0000_0000
        }),
        ("alignment pop", &[0x9D][..], |vcpu: &mut X86_64Vcpu| {
            vcpu.sregs.cr0 |= CR0_AM;
            vcpu.sregs.cs.selector = 3;
            vcpu.regs.rflags |= flags::bits::AC;
            vcpu.regs.rsp = 0x8001;
        }),
    ];
    for (name, instruction, configure) in cases {
        let mut code = instruction.to_vec();
        code.push(0xF4);
        let memory = memory_with_code(&code);
        let mut vcpu = test_vcpu(memory);
        configure(&mut vcpu);
        let before = scalar_state(&vcpu);

        let region = vcpu
            .jit_compile_region()
            .expect("compile dynamically guarded stack flags")
            .expect("dynamic stack fault must remain native eligible");
        vcpu.jit_run_region_native(&region);
        assert_eq!(scalar_state(&vcpu), before, "{name}");
        assert_eq!(vcpu.regs.rip, 0, "{name}: precise fault PC");
        assert!(vcpu.step().is_err(), "{name}: direct replay must fault");
        assert_eq!(vcpu.regs.rsp, before[2], "{name}: direct noncommit");
    }

    let memory = memory_with_code(&[0xD5, 0x00, 0x9C, 0xF4]);
    let mut vcpu = test_vcpu(memory);
    let before = scalar_state(&vcpu);
    let region = vcpu
        .jit_compile_region()
        .expect("compile guarded REX2 PUSHF")
        .expect("APX availability is a runtime guard");
    vcpu.jit_run_region_native(&region);
    assert_eq!(scalar_state(&vcpu), before);
    assert!(vcpu.step().is_err(), "direct replay must deliver #UD");
}

#[test]
fn compatibility_mode_stack_flags_stays_out_of_long_mode_jit() {
    for instruction in [&[0x9C][..], &[0x9D][..]] {
        let mut code = instruction.to_vec();
        code.push(0xF4);
        let memory = memory_with_code(&code);
        let mut vcpu = test_vcpu(memory);
        vcpu.sregs.cs.l = false;
        vcpu.sregs.cs.db = true;

        assert!(
            vcpu.jit_compile_region().unwrap().is_none(),
            "compatibility-mode PUSHFD/POPFD must use direct width and fault semantics"
        );
    }
}

#[test]
fn verified_stack_flags_restores_memory_and_adopts_complete_pop_state() {
    for (instruction, popped) in [
        (&[0x9C][..], None),
        (&[0x9D][..], Some(POPF_MODIFIABLE_W64)),
    ] {
        let mut code = instruction.to_vec();
        let frontier = code.len() as u64;
        code.push(0xF4);
        let memory = memory_with_code(&code);
        let mut vcpu = test_vcpu(memory.clone());
        vcpu.regs.rflags |= flags::bits::RF | flags::bits::VIF | flags::bits::VIP;
        if let Some(value) = popped {
            memory
                .write_obj(value, GuestAddress(vcpu.regs.rsp))
                .unwrap();
        }
        let region = vcpu
            .jit_compile_region()
            .expect("compile verified stack flags")
            .expect("stack flags must be native eligible");
        vcpu.jit_run_region_verified(&region);
        assert_eq!(vcpu.regs.rip, frontier);
        if popped.is_some() {
            assert_eq!(vcpu.regs.rflags & POPF_MODIFIABLE_W64, POPF_MODIFIABLE_W64);
            assert_eq!(vcpu.regs.rflags & flags::bits::RF, 0);
        } else {
            assert_eq!(
                memory.read_obj::<u64>(GuestAddress(0x7FF8)).unwrap(),
                (0x2 | flags::bits::CF
                    | flags::bits::DF
                    | flags::bits::IF
                    | flags::bits::VIF
                    | flags::bits::VIP)
                    & 0x00FC_FFFF
            );
        }
    }
}
