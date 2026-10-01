//! End-to-end RISC-V machine code -> SMIR -> AArch64 native execution tests.
#![cfg(all(feature = "smir-jit", target_arch = "aarch64"))]

use rax::isa::riscv::{FlatMemory, Isa, RiscVConfig, RiscVCpu, RiscVExit, Trap, Xlen};
use rax::smir::optimize::OptLevel;

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;
const MEMORY_LEN: usize = 0x4000;

fn r_type(funct7: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8) -> u32 {
    r_type_opcode(funct7, rs2, rs1, funct3, rd, 0x33)
}

fn r_type_opcode(funct7: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8, opcode: u32) -> u32 {
    (funct7 << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | opcode
}

fn i_type(imm: i32, rs1: u8, funct3: u32, rd: u8, opcode: u32) -> u32 {
    ((imm as u32 & 0xfff) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | opcode
}

fn s_type(imm: i32, rs2: u8, rs1: u8, funct3: u32) -> u32 {
    let imm = imm as u32 & 0xfff;
    ((imm >> 5) << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | ((imm & 0x1f) << 7)
        | 0x23
}

fn b_type(offset: i32, rs2: u8, rs1: u8, funct3: u32) -> u32 {
    let imm = offset as u32 & 0x1fff;
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3f) << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (((imm >> 1) & 0xf) << 8)
        | (((imm >> 11) & 1) << 7)
        | 0x63
}

fn amo_type(funct5: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8) -> u32 {
    (funct5 << 27)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | 0x2f
}

fn v_type(funct6: u32, vm: u32, vs2: u32, src: u32, funct3: u32, vd: u32) -> u32 {
    (funct6 << 26) | (vm << 25) | (vs2 << 20) | (src << 15) | (funct3 << 12) | (vd << 7) | 0x57
}

fn make_cpu(config: RiscVConfig) -> RiscVCpu {
    RiscVCpu::new(config, Box::new(FlatMemory::new(0, MEMORY_LEN)))
}

fn install(cpu: &mut RiscVCpu, instructions: &[u32]) {
    let bytes = instructions
        .iter()
        .flat_map(|instruction| instruction.to_le_bytes())
        .collect::<Vec<_>>();
    install_bytes(cpu, &bytes);
}

fn install_bytes(cpu: &mut RiscVCpu, bytes: &[u8]) {
    cpu.write_memory(CODE, &bytes).expect("write RISC-V code");
    cpu.set_pc(CODE);
}

fn c_addi(rd: u8, imm: i8) -> u16 {
    assert!(rd < 32 && (-32..=31).contains(&imm) && imm != 0);
    let immediate = imm as u16 & 0x3f;
    ((immediate >> 5) << 12) | (u16::from(rd) << 7) | ((immediate & 0x1f) << 2) | 0b01
}

fn cm_zcmp_move(r1s: u16, r2s: u16, funct2: u16) -> u16 {
    assert!(r1s < 8 && r2s < 8 && matches!(funct2, 0b01 | 0b11));
    (0b101 << 13) | (0b011 << 10) | (r1s << 7) | (funct2 << 5) | (r2s << 2) | 0b10
}

fn cm_zcmp_stack(funct5: u16, rlist: u16, spimm: u16) -> u16 {
    assert!(matches!(funct5, 0x18 | 0x1a | 0x1c | 0x1e));
    assert!((4..=15).contains(&rlist) && spimm < 4);
    (0b101 << 13) | (funct5 << 8) | (rlist << 4) | (spimm << 2) | 0b10
}

fn cm_zcmt(index: u16) -> u16 {
    assert!(index < 256);
    (0b101 << 13) | (index << 2) | 0b10
}

fn assert_equivalent(actual: &RiscVCpu, expected: &RiscVCpu) {
    for register in 0..32u8 {
        assert_eq!(actual.x(register), expected.x(register), "x{register}");
        assert_eq!(actual.f(register), expected.f(register), "f{register}");
    }
    assert_eq!(actual.pc(), expected.pc(), "PC");
    assert_eq!(actual.fcsr(), expected.fcsr(), "FCSR");
    assert_eq!(actual.vl(), expected.vl(), "vl");
    assert_eq!(actual.vtype(), expected.vtype(), "vtype");
    assert_eq!(actual.vstart(), expected.vstart(), "vstart");
    assert_eq!(actual.vcsr(), expected.vcsr(), "vcsr");
    for register in 0..32u8 {
        assert_eq!(
            actual.vreg(register),
            expected.vreg(register),
            "v{register}"
        );
    }
    assert_eq!(actual.instret(), expected.instret(), "instret");
    for csr in [0x017, 0xc00, 0x341, 0x342, 0x343] {
        assert_eq!(actual.csr_read(csr), expected.csr_read(csr), "CSR {csr:#x}");
    }
    let mut actual_memory = vec![0; MEMORY_LEN];
    let mut expected_memory = vec![0; MEMORY_LEN];
    actual
        .read_memory(0, &mut actual_memory)
        .expect("read JIT memory");
    expected
        .read_memory(0, &mut expected_memory)
        .expect("read interpreter memory");
    assert_eq!(actual_memory, expected_memory, "guest memory");
}

#[test]
fn production_scalar_i_m_zbb_and_control_flow_match_interpreter() {
    let instructions = [
        i_type(17, 1, 0, 5, 0x13),     // addi x5,x1,17
        r_type(0x20, 2, 5, 0, 6),      // sub x6,x5,x2
        r_type(0x00, 3, 6, 1, 7),      // sll x7,x6,x3
        r_type(0x20, 3, 7, 5, 8),      // sra x8,x7,x3
        r_type(0x01, 2, 1, 0, 9),      // mul x9,x1,x2
        r_type(0x01, 2, 1, 1, 10),     // mulh x10,x1,x2
        r_type(0x01, 2, 1, 4, 11),     // div x11,x1,x2
        r_type(0x01, 2, 1, 6, 12),     // rem x12,x1,x2
        i_type(0x600, 1, 1, 13, 0x13), // clz x13,x1
        i_type(0x601, 1, 1, 14, 0x13), // ctz x14,x1
        i_type(0x602, 1, 1, 15, 0x13), // cpop x15,x1
        b_type(8, 2, 1, 0),            // beq x1,x2,+8 (not taken)
        b_type(8, 2, 1, 1),            // bne x1,x2,+8 (taken)
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &instructions);
        cpu.set_x(1, 0xf123_4567_89ab_cdf0);
        cpu.set_x(2, 0x1234_5678);
        cpu.set_x(3, 11);
    }

    for instruction in instructions {
        assert_eq!(expected.step(), RiscVExit::Continue, "{instruction:08x}");
        assert_eq!(
            actual.step_jit(OptLevel::O2),
            RiscVExit::Continue,
            "{instruction:08x}"
        );
        assert_equivalent(&actual, &expected);
        // Branches alter PC; restore the next corpus address so both branch
        // outcomes are verified as independent single-instruction blocks.
        let next = CODE
            + 4 * (instructions
                .iter()
                .position(|candidate| *candidate == instruction)
                .unwrap() as u64
                + 1);
        expected.set_pc(next);
        actual.set_pc(next);
    }

    let stats = actual.jit_stats();
    assert_eq!(stats.native_executions, instructions.len() as u64);
    assert_eq!(stats.interpreter_fallbacks, 0);
}

#[test]
fn production_scalar_memory_and_faults_are_precise() {
    let instructions = [
        i_type(0, 1, 0b010, 5, 0x03), // lw x5,0(x1)
        s_type(8, 2, 1, 0b011),       // sd x2,8(x1)
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &instructions);
        cpu.set_x(1, DATA);
        cpu.set_x(2, 0x1122_3344_5566_7788);
        cpu.write_memory(DATA, &0x8000_0001u32.to_le_bytes())
            .expect("seed load word");
    }
    for instruction in instructions {
        assert_eq!(expected.step(), RiscVExit::Continue, "{instruction:08x}");
        assert_eq!(actual.step_jit(OptLevel::O0), RiscVExit::Continue);
        assert_equivalent(&actual, &expected);
    }
    assert_eq!(actual.jit_stats().native_executions, 2);

    let faulting = i_type(0, 1, 0b011, 5, 0x03); // ld x5,0(x1)
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &[faulting]);
        cpu.set_x(1, MEMORY_LEN as u64 - 4);
        cpu.set_x(5, 0xfeed_face_cafe_beef);
    }
    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 5,
            tval: MEMORY_LEN as u64 - 4,
        })
    );
    assert_eq!(actual_exit, expected_exit);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_integer_crypto_is_native_and_scalar_fp_falls_back() {
    let instructions = [
        r_type(0x05, 2, 1, 1, 5),              // clmul x5,x1,x2
        r_type_opcode(0x00, 2, 1, 0, 5, 0x53), // fadd.s f5,f1,f2
        r_type_opcode(0x50, 2, 1, 2, 6, 0x53), // feq.s x6,f1,f2
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        cpu.csr_write(0x300, 0b01 << 13)
            .expect("production FP state must be enabled");
        install(cpu, &instructions);
        cpu.set_x(1, 0x0123_4567_89ab_cdef);
        cpu.set_x(2, 0xfedc_ba98_7654_3210);
        cpu.set_f(1, 0xffff_ffff_3fc0_0000); // 1.5f32
        cpu.set_f(2, 0xffff_ffff_4020_0000); // 2.5f32
    }
    for instruction in instructions {
        assert_eq!(expected.step(), RiscVExit::Continue, "{instruction:08x}");
        assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
        assert_equivalent(&actual, &expected);
    }
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 2);
}

#[test]
fn production_rvv_op_v_is_native_and_transactional() {
    const E32_M1: u64 = 0x10;
    let instructions = [
        v_type(0b000000, 1, 2, 3, 0, 1),  // vadd.vv v1,v2,v3
        v_type(0b010000, 1, 1, 0, 2, 11), // vmv.x.s x11,v1
    ];
    for config in [RiscVConfig::rv64gc(), RiscVConfig::rv32(Isa::rv64gc())] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut expected = make_cpu(config);
            let mut actual = make_cpu(config);
            for cpu in [&mut expected, &mut actual] {
                install(cpu, &instructions);
                cpu.set_vl_vtype(2, E32_M1);
                let mut v2 = [0u8; 16];
                v2[0..4].copy_from_slice(&1u32.to_le_bytes());
                v2[4..8].copy_from_slice(&2u32.to_le_bytes());
                let mut v3 = [0u8; 16];
                v3[0..4].copy_from_slice(&10u32.to_le_bytes());
                v3[4..8].copy_from_slice(&20u32.to_le_bytes());
                cpu.set_vreg(2, &v2);
                cpu.set_vreg(3, &v3);
            }

            assert_eq!(expected.run(2), RiscVExit::Continue);
            assert_eq!(actual.run_jit(2, level), RiscVExit::Continue);
            assert_equivalent(&actual, &expected);
            assert_eq!(actual.x(11), 11, "{config:?}, {level:?}");
            let stats = actual.jit_stats();
            assert_eq!(stats.native_executions, 2, "{config:?}, {level:?}");
            assert_eq!(stats.interpreter_fallbacks, 0, "{config:?}, {level:?}");
        }
    }
}

#[test]
fn production_rvv_op_v_failure_replays_only_the_isolated_instruction() {
    let instruction = v_type(0b000000, 1, 2, 3, 0, 1); // vadd.vv v1,v2,v3
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &[instruction]);
        cpu.set_vl_vtype(2, 1 << 63); // vill=1
        let v1 = [0xa5; 16];
        cpu.set_vreg(1, &v1);
    }

    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert!(matches!(actual_exit, RiscVExit::Trap(_)));
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.vreg(1), [0xa5; 16]);
    let stats = actual.jit_stats();
    assert_eq!(stats.native_executions, 1);
    assert_eq!(stats.interpreter_fallbacks, 1);
}

#[test]
fn production_rv32_wraps_addresses_and_scalar_atomics_are_native() {
    let mut expected = make_cpu(RiscVConfig::rv32(Isa::rv64gc()));
    let mut actual = make_cpu(RiscVConfig::rv32(Isa::rv64gc()));
    let load = i_type(1, 1, 0b100, 5, 0x03); // lbu x5,1(x1)
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &[load]);
        cpu.set_x(1, 0xffff_ffff);
        cpu.write_memory(0, &[0xab]).expect("seed wrapped byte");
    }
    assert_eq!(expected.step(), RiscVExit::Continue);
    assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 0xab);
    assert_eq!(actual.jit_stats().native_executions, 1);

    let atomics = [
        amo_type(0b00010, 0, 1, 0b010, 3), // lr.w x3,(x1)
        amo_type(0b00011, 2, 1, 0b010, 4), // sc.w x4,x2,(x1)
        amo_type(0b00000, 2, 1, 0b010, 5), // amoadd.w x5,x2,(x1)
        amo_type(0b00101, 8, 1, 0b010, 6), // amocas.w x6,x8,(x1)
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &atomics);
        cpu.set_x(1, DATA);
        cpu.set_x(2, 7);
        cpu.set_x(6, 14);
        cpu.set_x(8, 21);
        cpu.write_memory(DATA, &5u32.to_le_bytes())
            .expect("seed atomic word");
    }
    for instruction in atomics {
        assert_eq!(expected.step(), RiscVExit::Continue, "{instruction:08x}");
        assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
        assert_equivalent(&actual, &expected);
    }
    assert_eq!(actual.jit_stats().native_executions, atomics.len() as u64);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);

    let pair_cas = amo_type(0b00101, 8, 10, 0b100, 6); // amocas.q x6,x8,(x10)
    let old = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210u64];
    let new = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888u64];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &[pair_cas]);
        cpu.set_x(10, DATA);
        cpu.set_x(6, old[0]);
        cpu.set_x(7, old[1]);
        cpu.set_x(8, new[0]);
        cpu.set_x(9, new[1]);
        cpu.write_memory(DATA, &old[0].to_le_bytes())
            .expect("seed pair-CAS low word");
        cpu.write_memory(DATA + 8, &old[1].to_le_bytes())
            .expect("seed pair-CAS high word");
    }
    assert_eq!(expected.step(), RiscVExit::Continue);
    assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_rv32_zilsd_pairs_are_native_at_every_optimization_level() {
    let mut isa = Isa::rv64gc();
    isa.zilsd = true;
    let config = RiscVConfig::rv32(isa);
    let instructions = [
        i_type(8, 10, 0b011, 6, 0x03), // ld x6,8(x10)
        s_type(16, 6, 10, 0b011),      // sd x6,16(x10)
        i_type(8, 10, 0b011, 0, 0x03), // ld x0,8(x10), discard x1 too
        s_type(24, 0, 10, 0b011),      // sd x0,24(x10), ignore x1
    ];
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let mut expected = make_cpu(config);
        let mut actual = make_cpu(config);
        for cpu in [&mut expected, &mut actual] {
            install(cpu, &instructions);
            cpu.set_x(1, 0xfeed_face);
            cpu.set_x(10, DATA);
            cpu.write_memory(DATA + 8, &0xaabb_ccdd_1122_3344u64.to_le_bytes())
                .expect("seed Zilsd pair");
            cpu.write_memory(DATA + 24, &u64::MAX.to_le_bytes())
                .expect("seed zero-store destination");
        }

        assert_eq!(expected.run(4), RiscVExit::Continue);
        assert_eq!(actual.run_jit(4, level), RiscVExit::Continue);
        assert_equivalent(&actual, &expected);
        assert_eq!(actual.x(1), 0xfeed_face, "{level:?}");
        assert_eq!(actual.x(6), 0x1122_3344, "{level:?}");
        assert_eq!(actual.x(7), 0xaabb_ccdd, "{level:?}");
        let mut stored = [0; 8];
        actual
            .read_memory(DATA + 16, &mut stored)
            .expect("read stored pair");
        assert_eq!(u64::from_le_bytes(stored), 0xaabb_ccdd_1122_3344);
        actual
            .read_memory(DATA + 24, &mut stored)
            .expect("read x0 pair store");
        assert_eq!(u64::from_le_bytes(stored), 0);
        let stats = actual.jit_stats();
        assert_eq!(stats.native_executions, 4, "{level:?}");
        assert_eq!(stats.interpreter_fallbacks, 0, "{level:?}");
    }
}

#[test]
fn production_rv32_zilsd_load_fault_and_base_overlap_are_precise() {
    let mut isa = Isa::rv64gc();
    isa.zilsd = true;
    let config = RiscVConfig::rv32(isa);
    let overlap = i_type(0, 10, 0b011, 10, 0x03); // ld x10,0(x10)
    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &[overlap]);
        cpu.set_x(10, DATA);
        cpu.set_x(11, 0xfeed_face);
        cpu.write_memory(DATA, &0xaabb_ccdd_1122_3344u64.to_le_bytes())
            .expect("seed overlapping pair load");
    }
    assert_eq!(expected.step(), RiscVExit::Continue);
    assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(10), 0x1122_3344);
    assert_eq!(actual.x(11), 0xaabb_ccdd);
    assert_eq!(actual.jit_stats().native_executions, 1);

    let faulting = i_type(0, 10, 0b011, 6, 0x03); // ld x6,0(x10)
    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &[faulting]);
        cpu.set_x(10, MEMORY_LEN as u64 - 4);
        cpu.set_x(6, 0x1111_2222);
        cpu.set_x(7, 0x3333_4444);
    }
    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 5,
            tval: MEMORY_LEN as u64 - 4,
        })
    );
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(6), 0x1111_2222);
    assert_eq!(actual.x(7), 0x3333_4444);
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);

    let faulting = s_type(0, 6, 10, 0b011); // sd x6,0(x10)
    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &[faulting]);
        cpu.set_x(10, MEMORY_LEN as u64 - 4);
        cpu.set_x(6, 0x1111_2222);
        cpu.set_x(7, 0x3333_4444);
    }
    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 7,
            tval: MEMORY_LEN as u64 - 4,
        })
    );
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_rv32_zclsd_compressed_pairs_are_native() {
    let mut isa = Isa::rv64gc();
    isa.zilsd = true;
    isa.zclsd = true;
    let config = RiscVConfig::rv32(isa);
    let c_sd = ((0b111 << 13) | (2 << 7) | 0b00) as u16; // c.sd x8,0(x10)
    let c_ld = ((0b011 << 13) | (2 << 7) | 0b00) as u16; // c.ld x8,0(x10)
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&c_sd.to_le_bytes());
    bytes.extend_from_slice(&c_ld.to_le_bytes());
    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install_bytes(cpu, &bytes);
        cpu.set_x(8, 0x1122_3344);
        cpu.set_x(9, 0xaabb_ccdd);
        cpu.set_x(10, DATA);
    }

    assert_eq!(expected.run(2), RiscVExit::Continue);
    assert_eq!(actual.run_jit(2, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(8), 0x1122_3344);
    assert_eq!(actual.x(9), 0xaabb_ccdd);
    assert_eq!(actual.pc(), CODE + 4);
    let stats = actual.jit_stats();
    assert_eq!(stats.native_executions, 2);
    assert_eq!(stats.interpreter_fallbacks, 0);
}

#[test]
fn production_zcmp_double_moves_are_native_for_rv32_and_rv64() {
    let mut isa = Isa::rv64gc();
    isa.zcmp = true;
    let cm_mvsa01 = cm_zcmp_move(0, 2, 0b01); // cm.mvsa01 x8,x18
    let cm_mva01s = cm_zcmp_move(0, 2, 0b11); // cm.mva01s x8,x18
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&cm_mvsa01.to_le_bytes());
    bytes.extend_from_slice(&cm_mva01s.to_le_bytes());

    for config in [
        RiscVConfig::rv32(isa),
        RiscVConfig {
            xlen: Xlen::Rv64,
            isa,
        },
    ] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut expected = make_cpu(config);
            let mut actual = make_cpu(config);
            for cpu in [&mut expected, &mut actual] {
                install_bytes(cpu, &bytes);
                cpu.set_x(8, 0x1111_2222_3333_4444);
                cpu.set_x(18, 0x5555_6666_7777_8888);
                cpu.set_x(10, 0x0123_4567_89ab_cdef);
                cpu.set_x(11, 0xfedc_ba98_7654_3210);
            }

            assert_eq!(expected.run(2), RiscVExit::Continue);
            assert_eq!(actual.run_jit(2, level), RiscVExit::Continue);
            assert_equivalent(&actual, &expected);
            assert_eq!(actual.x(8), actual.x(10), "{:?} {level:?}", config.xlen);
            assert_eq!(actual.x(18), actual.x(11), "{:?} {level:?}", config.xlen);
            assert_eq!(actual.pc(), CODE + 4);
            let stats = actual.jit_stats();
            assert_eq!(stats.native_executions, 1, "{:?} {level:?}", config.xlen);
            assert_eq!(
                stats.interpreter_fallbacks, 0,
                "{:?} {level:?}",
                config.xlen
            );
        }
    }
}

#[test]
fn production_zcmp_stack_macros_are_native_for_rv32_and_rv64() {
    const SAVED: [u8; 13] = [1, 8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27];
    let mut isa = Isa::rv64gc();
    isa.zcmp = true;
    let push = cm_zcmp_stack(0x18, 15, 3);
    let pop = cm_zcmp_stack(0x1a, 15, 3);

    for config in [
        RiscVConfig::rv32(isa),
        RiscVConfig {
            xlen: Xlen::Rv64,
            isa,
        },
    ] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut expected = make_cpu(config);
            let mut actual = make_cpu(config);
            for cpu in [&mut expected, &mut actual] {
                install_bytes(cpu, &push.to_le_bytes());
                cpu.set_x(2, DATA + 0x400);
                for (index, register) in SAVED.into_iter().enumerate() {
                    cpu.set_x(register, 0x1111_2222_0000_0000 | index as u64);
                }
            }

            assert_eq!(expected.step(), RiscVExit::Continue);
            assert_eq!(actual.step_jit(level), RiscVExit::Continue);
            assert_equivalent(&actual, &expected);
            let pushed_sp = actual.x(2);

            for cpu in [&mut expected, &mut actual] {
                install_bytes(cpu, &pop.to_le_bytes());
                for register in SAVED {
                    cpu.set_x(register, 0xdead_beef);
                }
            }
            assert_eq!(expected.step(), RiscVExit::Continue);
            assert_eq!(actual.step_jit(level), RiscVExit::Continue);
            assert_equivalent(&actual, &expected);
            assert!(actual.x(2) > pushed_sp, "{:?} {level:?}", config.xlen);
            for (index, register) in SAVED.into_iter().enumerate() {
                let mask = if config.xlen == Xlen::Rv32 {
                    u64::from(u32::MAX)
                } else {
                    u64::MAX
                };
                assert_eq!(
                    actual.x(register),
                    (0x1111_2222_0000_0000 | index as u64) & mask,
                    "x{register} {:?} {level:?}",
                    config.xlen
                );
            }
            let stats = actual.jit_stats();
            assert_eq!(stats.native_executions, 2, "{:?} {level:?}", config.xlen);
            assert_eq!(
                stats.interpreter_fallbacks, 0,
                "{:?} {level:?}",
                config.xlen
            );
        }
    }
}

#[test]
fn production_zcmp_stack_partial_faults_match_interpreter() {
    let mut isa = Isa::rv64gc();
    isa.zcmp = true;
    let config = RiscVConfig {
        xlen: Xlen::Rv64,
        isa,
    };

    let push = cm_zcmp_stack(0x18, 6, 0); // ra,s0-s1; 32-byte adjustment
    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install_bytes(cpu, &push.to_le_bytes());
        cpu.set_x(1, 0x0123_4567_89ab_cdef);
        cpu.set_x(8, 0x1111_2222_3333_4444);
        cpu.set_x(9, 0x5555_6666_7777_8888);
        cpu.set_x(2, 8); // s1 store at 0 succeeds; s0 store wraps and faults
    }
    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 7,
            tval: u64::MAX - 7,
        })
    );
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(2), 8, "SP must not commit after a partial push");
    let mut stored = [0; 8];
    actual
        .read_memory(0, &mut stored)
        .expect("read completed prefix store");
    assert_eq!(u64::from_le_bytes(stored), 0x5555_6666_7777_8888);
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);

    let pop = cm_zcmp_stack(0x1a, 6, 0);
    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install_bytes(cpu, &pop.to_le_bytes());
        cpu.set_x(1, 1);
        cpu.set_x(8, 2);
        cpu.set_x(9, 3);
        cpu.set_x(2, u64::MAX - 15);
        cpu.write_memory(8, &0xaabb_ccdd_eeff_0011u64.to_le_bytes())
            .expect("seed restored s1");
        cpu.write_memory(0, &0x1122_3344_5566_7788u64.to_le_bytes())
            .expect("seed restored s0");
    }
    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 5,
            tval: u64::MAX - 7,
        })
    );
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(1), 1);
    assert_eq!(actual.x(8), 0x1122_3344_5566_7788);
    assert_eq!(actual.x(9), 0xaabb_ccdd_eeff_0011);
    assert_eq!(actual.x(2), u64::MAX - 15);
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_zcmp_popret_variants_commit_final_control_updates() {
    let mut isa = Isa::rv64gc();
    isa.zcmp = true;
    let config = RiscVConfig {
        xlen: Xlen::Rv64,
        isa,
    };
    let push = cm_zcmp_stack(0x18, 4, 0); // {ra}, 16-byte adjustment

    for (pop_funct5, zero_a0) in [(0x1e, false), (0x1c, true)] {
        let pop = cm_zcmp_stack(pop_funct5, 4, 0);
        let mut expected = make_cpu(config);
        let mut actual = make_cpu(config);
        for cpu in [&mut expected, &mut actual] {
            install_bytes(cpu, &push.to_le_bytes());
            cpu.set_x(1, CODE + 0x101); // POPRET clears target bit zero.
            cpu.set_x(2, DATA + 0x400);
            cpu.set_x(10, 0xfeed_face);
        }
        assert_eq!(expected.step(), RiscVExit::Continue);
        assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);

        for cpu in [&mut expected, &mut actual] {
            install_bytes(cpu, &pop.to_le_bytes());
        }
        assert_eq!(expected.step(), RiscVExit::Continue);
        assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
        assert_equivalent(&actual, &expected);
        assert_eq!(actual.pc(), CODE + 0x100);
        assert_eq!(actual.x(2), DATA + 0x400);
        assert_eq!(actual.x(10), if zero_a0 { 0 } else { 0xfeed_face });
        let stats = actual.jit_stats();
        assert_eq!(stats.native_executions, 2);
        assert_eq!(stats.interpreter_fallbacks, 0);
    }
}

#[test]
fn production_zcmt_table_jumps_are_native_and_fault_as_fetches() {
    let mut isa = Isa::rv64gc();
    isa.zcmt = true;
    let cm_jt = cm_zcmt(17);
    let cm_jalt = cm_zcmt(32);

    for config in [
        RiscVConfig::rv32(isa),
        RiscVConfig {
            xlen: Xlen::Rv64,
            isa,
        },
    ] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut expected = make_cpu(config);
            let mut actual = make_cpu(config);
            let entry_size = if config.xlen == Xlen::Rv32 { 4 } else { 8 };
            for cpu in [&mut expected, &mut actual] {
                install_bytes(cpu, &cm_jt.to_le_bytes());
                cpu.csr_write(0x017, DATA | 0x3f).expect("write WARL jvt");
                cpu.set_x(1, 0xfeed_face);
                let target = CODE + 0x201;
                cpu.write_memory(
                    DATA + 17 * entry_size,
                    &target.to_le_bytes()[..entry_size as usize],
                )
                .expect("write cm.jt table target");
            }
            assert_eq!(expected.csr_read(0x017), Ok(DATA));
            assert_eq!(actual.csr_read(0x017), Ok(DATA));
            assert_eq!(expected.step(), RiscVExit::Continue);
            assert_eq!(actual.step_jit(level), RiscVExit::Continue);
            assert_equivalent(&actual, &expected);
            assert_eq!(actual.pc(), CODE + 0x200);
            assert_eq!(actual.x(1), 0xfeed_face);

            for cpu in [&mut expected, &mut actual] {
                install_bytes(cpu, &cm_jalt.to_le_bytes());
                let target = CODE + 0x301;
                cpu.write_memory(
                    DATA + 32 * entry_size,
                    &target.to_le_bytes()[..entry_size as usize],
                )
                .expect("write cm.jalt table target");
            }
            assert_eq!(expected.step(), RiscVExit::Continue);
            assert_eq!(actual.step_jit(level), RiscVExit::Continue);
            assert_equivalent(&actual, &expected);
            assert_eq!(actual.pc(), CODE + 0x300);
            assert_eq!(actual.x(1), CODE + 2);
            let stats = actual.jit_stats();
            assert_eq!(stats.native_executions, 2, "{:?} {level:?}", config.xlen);
            assert_eq!(
                stats.interpreter_fallbacks, 0,
                "{:?} {level:?}",
                config.xlen
            );
        }
    }

    let config = RiscVConfig {
        xlen: Xlen::Rv64,
        isa,
    };
    let csrrw_jvt = i_type(0x017, 5, 0b001, 6, 0x73);
    let mut code = csrrw_jvt.to_le_bytes().to_vec();
    code.extend_from_slice(&cm_jt.to_le_bytes());
    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install_bytes(cpu, &code);
        cpu.set_x(5, DATA | 0x3f);
        cpu.set_x(6, 0xfeed_face);
        cpu.write_memory(DATA + 17 * 8, &(CODE + 0x400).to_le_bytes())
            .expect("write CSR-configured cm.jt target");
    }
    assert_eq!(expected.run(2), RiscVExit::Continue);
    assert_eq!(actual.run_jit(2, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(6), 0, "CSRRW must return the old jvt value");
    assert_eq!(actual.csr_read(0x017), Ok(DATA));
    assert_eq!(actual.pc(), CODE + 0x400);
    assert_eq!(actual.jit_stats().native_executions, 2);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);

    let mut expected = make_cpu(config);
    let mut actual = make_cpu(config);
    for cpu in [&mut expected, &mut actual] {
        install_bytes(cpu, &cm_jalt.to_le_bytes());
        cpu.csr_write(0x017, MEMORY_LEN as u64 - 64)
            .expect("write out-of-range jvt base");
        cpu.set_x(1, 0xfeed_face);
    }
    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 1,
            tval: MEMORY_LEN as u64 - 64 + 32 * 8,
        })
    );
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(1), 0xfeed_face, "faulting JALT must not link");
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_cache_reuses_native_aarch64_blocks() {
    let mut cpu = make_cpu(RiscVConfig {
        xlen: Xlen::Rv64,
        isa: Isa::rv64gc(),
    });
    let add = i_type(5, 5, 0, 5, 0x13);
    install(&mut cpu, &[add]);
    cpu.set_x(5, 10);
    for expected in [15, 20] {
        cpu.set_pc(CODE);
        assert_eq!(cpu.step_jit(OptLevel::O2), RiscVExit::Continue);
        assert_eq!(cpu.x(5), expected);
    }
    let stats = cpu.jit_stats();
    assert_eq!(stats.cache_entries, 1);
    assert_eq!(stats.cache_misses, 1);
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.native_executions, 2);
    assert_eq!(stats.interpreter_fallbacks, 0);

    cpu.reset(CODE);
    assert_eq!(cpu.jit_stats(), Default::default());
}

#[test]
fn production_run_jit_forms_bounded_regions_at_every_optimization_level() {
    let instructions = vec![i_type(1, 5, 0, 5, 0x13); 20]; // addi x5,x5,1
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let mut expected = make_cpu(RiscVConfig::rv64gc());
        let mut actual = make_cpu(RiscVConfig::rv64gc());
        install(&mut expected, &instructions);
        install(&mut actual, &instructions);

        assert_eq!(expected.run(instructions.len() as u64), RiscVExit::Continue);
        assert_eq!(
            actual.run_jit(instructions.len() as u64, level),
            RiscVExit::Continue
        );
        assert_equivalent(&actual, &expected);
        assert_eq!(actual.x(5), 20);
        assert_eq!(actual.pc(), CODE + 80);

        let stats = actual.jit_stats();
        assert_eq!(stats.cache_entries, 2, "{level:?}");
        assert_eq!(stats.cache_misses, 2, "{level:?}");
        assert_eq!(stats.native_executions, 2, "{level:?}");
        assert_eq!(stats.interpreter_fallbacks, 0, "{level:?}");
    }
}

#[test]
fn production_run_jit_obeys_the_exact_remaining_instruction_budget() {
    let instructions = vec![i_type(1, 5, 0, 5, 0x13); 8]; // addi x5,x5,1
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    install(&mut expected, &instructions);
    install(&mut actual, &instructions);

    assert_eq!(expected.run(3), RiscVExit::Continue);
    assert_eq!(actual.run_jit(3, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 3);
    assert_eq!(actual.pc(), CODE + 12);
    assert_eq!(actual.jit_stats().native_executions, 1);

    assert_eq!(expected.run(5), RiscVExit::Continue);
    assert_eq!(actual.run_jit(5, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 8);
    assert_eq!(actual.pc(), CODE + 32);
    assert_eq!(actual.jit_stats().native_executions, 2);
}

#[test]
fn production_region_cache_identity_covers_every_instruction() {
    let mut cpu = make_cpu(RiscVConfig::rv64gc());
    let mut instructions = [
        i_type(1, 5, 0, 5, 0x13),
        i_type(2, 5, 0, 5, 0x13),
        i_type(3, 5, 0, 5, 0x13),
    ];
    install(&mut cpu, &instructions);

    assert_eq!(cpu.run_jit(3, OptLevel::O2), RiscVExit::Continue);
    assert_eq!(cpu.x(5), 6);
    instructions[2] = i_type(7, 5, 0, 5, 0x13);
    cpu.write_memory(CODE + 8, &instructions[2].to_le_bytes())
        .expect("replace region tail");
    cpu.set_pc(CODE);
    assert_eq!(cpu.run_jit(3, OptLevel::O2), RiscVExit::Continue);
    assert_eq!(cpu.x(5), 16);

    let stats = cpu.jit_stats();
    assert_eq!(stats.cache_entries, 2);
    assert_eq!(stats.cache_misses, 2);
    assert_eq!(stats.cache_hits, 0);
    assert_eq!(stats.native_executions, 2);
}

#[test]
fn production_regions_end_after_memory_side_effects() {
    let instructions = [
        i_type(0x55, 0, 0, 5, 0x13), // addi x5,x0,0x55
        s_type(0, 5, 1, 0b010),      // sw x5,0(x1)
        i_type(9, 5, 0, 6, 0x13),    // addi x6,x5,9
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &instructions);
        cpu.set_x(1, DATA);
    }

    assert_eq!(expected.run(3), RiscVExit::Continue);
    assert_eq!(actual.run_jit(3, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    let stats = actual.jit_stats();
    assert_eq!(stats.native_executions, 2);
    assert_eq!(stats.cache_entries, 2);
    assert_eq!(stats.interpreter_fallbacks, 0);
}

#[test]
fn production_store_boundary_observes_a_self_modified_successor() {
    let original_tail = i_type(2, 5, 0, 5, 0x13); // addi x5,x5,2
    let replacement_tail = i_type(7, 5, 0, 5, 0x13); // addi x5,x5,7
    let instructions = [
        i_type(1, 5, 0, 5, 0x13), // addi x5,x5,1
        s_type(8, 2, 1, 0b010),   // sw x2,8(x1)
        original_tail,
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &instructions);
        cpu.set_x(1, CODE);
        cpu.set_x(2, u64::from(replacement_tail));
    }

    assert_eq!(expected.run(3), RiscVExit::Continue);
    assert_eq!(actual.run_jit(3, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 8);
    assert_eq!(actual.pc(), CODE + 12);
    assert_eq!(actual.jit_stats().native_executions, 2);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_region_fault_retires_only_preceding_instructions() {
    let instructions = [
        i_type(7, 5, 0, 5, 0x13),     // addi x5,x5,7
        i_type(0, 1, 0b011, 5, 0x03), // ld x5,0(x1)
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &instructions);
        cpu.set_x(1, MEMORY_LEN as u64 - 4);
        cpu.set_x(5, 10);
    }

    let expected_exit = expected.run(2);
    let actual_exit = actual.run_jit(2, OptLevel::O2);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 5,
            tval: MEMORY_LEN as u64 - 4,
        })
    );
    assert_eq!(actual_exit, expected_exit);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 17);
    assert_eq!(actual.instret(), 1);
    assert_eq!(actual.csr_read(0xc00), Ok(2));
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_region_store_fault_preserves_preceding_retirement() {
    let instructions = [
        i_type(3, 5, 0, 5, 0x13), // addi x5,x5,3
        s_type(0, 5, 1, 0b011),   // sd x5,0(x1)
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &instructions);
        cpu.set_x(1, MEMORY_LEN as u64 - 4);
        cpu.set_x(5, 20);
    }

    let expected_exit = expected.run(2);
    let actual_exit = actual.run_jit(2, OptLevel::O1);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(Trap {
            cause: 7,
            tval: MEMORY_LEN as u64 - 4,
        })
    );
    assert_eq!(actual_exit, expected_exit);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 23);
    assert_eq!(actual.instret(), 1);
    assert_eq!(actual.csr_read(0xc00), Ok(2));
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_regions_isolate_control_flow() {
    let instructions = [
        i_type(1, 5, 0, 5, 0x13),   // addi x5,x5,1
        b_type(8, 0, 0, 0),         // beq x0,x0,+8
        i_type(100, 5, 0, 5, 0x13), // skipped
        i_type(2, 5, 0, 5, 0x13),   // addi x5,x5,2
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    install(&mut expected, &instructions);
    install(&mut actual, &instructions);

    assert_eq!(expected.run(3), RiscVExit::Continue);
    assert_eq!(actual.run_jit(3, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 3);
    assert_eq!(actual.pc(), CODE + 16);
    assert_eq!(actual.jit_stats().native_executions, 3);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_regions_isolate_replay_sensitive_fp_failures() {
    let invalid_rm_fadd = r_type_opcode(0x00, 2, 1, 0b101, 3, 0x53);
    let instructions = [
        i_type(1, 5, 0, 5, 0x13), // addi x5,x5,1
        invalid_rm_fadd,          // reserved static rounding mode
    ];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        cpu.csr_write(0x300, 0b01 << 13)
            .expect("production FP state must be enabled");
        install(cpu, &instructions);
        cpu.set_x(5, 10);
        cpu.set_f(1, 0xffff_ffff_3f80_0000);
        cpu.set_f(2, 0xffff_ffff_4000_0000);
    }

    let expected_exit = expected.run(2);
    let actual_exit = actual.run_jit(2, OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert!(matches!(actual_exit, RiscVExit::Trap(_)));
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 11);
    assert_eq!(actual.instret(), 1);
    let stats = actual.jit_stats();
    assert_eq!(stats.native_executions, 1);
    assert_eq!(stats.interpreter_fallbacks, 1);
}

#[test]
fn production_run_jit_preserves_interrupt_budget_accounting() {
    const MSTATUS_MIE: u64 = 1 << 3;
    const MIP_MEIP: u64 = 1 << 11;
    let instructions = vec![i_type(1, 5, 0, 5, 0x13); 3];
    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    for cpu in [&mut expected, &mut actual] {
        install(cpu, &instructions);
        cpu.csr_write(0x305, CODE).expect("set mtvec");
        cpu.csr_write(0x304, MIP_MEIP).expect("enable MEIP");
        cpu.csr_write(0x300, MSTATUS_MIE)
            .expect("enable machine interrupts");
        cpu.set_interrupt_pending(MIP_MEIP, true);
    }

    assert_eq!(expected.run(3), RiscVExit::Continue);
    assert_eq!(actual.run_jit(3, OptLevel::O2), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 2);
    assert_eq!(actual.instret(), 2);
    assert_eq!(actual.csr_read(0xc00), Ok(2));
    assert_eq!(actual.jit_stats().native_executions, 1);
}

#[test]
fn production_regions_track_mixed_compressed_instruction_lengths() {
    let mut bytes = Vec::new();
    for instruction in [c_addi(5, 1), c_addi(5, -2), c_addi(5, 7)] {
        bytes.extend_from_slice(&instruction.to_le_bytes());
    }
    bytes.extend_from_slice(&i_type(9, 5, 0, 6, 0x13).to_le_bytes());

    let mut expected = make_cpu(RiscVConfig::rv64gc());
    let mut actual = make_cpu(RiscVConfig::rv64gc());
    install_bytes(&mut expected, &bytes);
    install_bytes(&mut actual, &bytes);
    expected.set_x(5, 11);
    actual.set_x(5, 11);

    assert_eq!(expected.run(4), RiscVExit::Continue);
    assert_eq!(actual.run_jit(4, OptLevel::O1), RiscVExit::Continue);
    assert_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 17);
    assert_eq!(actual.x(6), 26);
    assert_eq!(actual.pc(), CODE + 10);
    let stats = actual.jit_stats();
    assert_eq!(stats.cache_entries, 1);
    assert_eq!(stats.native_executions, 1);
    assert_eq!(stats.interpreter_fallbacks, 0);
}
