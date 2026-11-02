//! DDI0406C.d D11 optional short-vector profile regression controls.
use rax::isa::arm::aarch32::{instructions::ExecResult, vfp::Fpscr};
use rax::isa::arm::decoder::Aarch32Decoder;
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, Executor};
fn execute(cpu: &mut Armv7Cpu, word: u32) -> ExecResult {
    let mut memory = FlatMemory::new(4096, 0);
    Executor::new(cpu, &mut memory).execute(&Aarch32Decoder::decode(word).unwrap())
}
#[test]
fn short_vector_baseline_vmsr_vmrs_preserve_selected_len_stride() {
    for enabled in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 24)) | ((enabled as u32) << 24);
        cpu.regs[0] = 0x00370000;
        assert!(matches!(
            execute(&mut cpu, 0xeee10a10),
            ExecResult::Continue
        ));
        assert!(matches!(
            execute(&mut cpu, 0xeef11a10),
            ExecResult::Continue
        ));
        assert_eq!(cpu.regs[1], if enabled { 0x00370000 } else { 0 });
    }
}
#[test]
fn short_vector_baseline_vadd_updates_every_selected_element() {
    let mut cpu = Armv7Cpu::new();
    cpu.vfp.mvfr0 |= 1 << 24;
    cpu.vfp.fpscr = Fpscr::from_bits(3 << 16);
    for i in 0..4 {
        cpu.vfp.write_s(16 + i, (i + 1) as f32);
        cpu.vfp.write_s(24 + i, 10.0 * (i + 1) as f32);
    }
    assert!(matches!(
        execute(&mut cpu, 0xee384a0c),
        ExecResult::Continue
    ));
    for i in 0..4 {
        assert_eq!(cpu.vfp.read_s(8 + i), (i + 1) as f32 * 11.0);
    }
}
#[test]
fn short_vector_baseline_reserved_capability_rejects_dependent_scalar() {
    let mut cpu = Armv7Cpu::new();
    cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 24)) | (2 << 24);
    cpu.vfp.write_s(16, 1.0);
    cpu.vfp.write_s(24, 2.0);
    assert!(matches!(
        execute(&mut cpu, 0xee384a0c),
        ExecResult::Undefined
    ));
}
#[test]
fn short_vector_baseline_invalid_iteration_shape_rejects_before_effects() {
    let mut cpu = Armv7Cpu::new();
    cpu.vfp.mvfr0 |= 1 << 24;
    cpu.vfp.fpscr = Fpscr::from_bits(0x00370000);
    assert!(matches!(
        execute(&mut cpu, 0xee384a0c),
        ExecResult::Undefined
    ));
}

fn cases() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a32-short-vectors/cases.json"
    )))
    .unwrap()
}
#[test]
fn short_vector_primary_matrix_matches_every_register_in_arm_and_thumb() {
    use rax::isa::arm::decoder::ThumbDecoder;
    let all = cases();
    let rows = all["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 1064);
    for row in rows {
        for thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.vfp.mvfr0 |= 1 << 24;
            cpu.cpsr.t = thumb;
            cpu.vfp.fpscr = Fpscr::from_bits(row["control"].as_u64().unwrap() as u32);
            let image = &all["initials"][row["initial"].as_u64().unwrap() as usize];
            for (i, x) in image.as_array().unwrap().iter().enumerate() {
                cpu.vfp.dregs[i] = x.as_u64().unwrap();
            }
            let mut expected = cpu.vfp.dregs;
            for change in row["changes"].as_array().unwrap() {
                expected[change[0].as_u64().unwrap() as usize] = change[1].as_u64().unwrap();
            }
            let raw = row[if thumb { "thumb" } else { "arm" }].as_u64().unwrap() as u32;
            let decoded = if thumb {
                ThumbDecoder::decode_32bit(raw)
            } else {
                Aarch32Decoder::decode(raw)
            }
            .unwrap();
            let mut memory = FlatMemory::new(4096, 0);
            let result = Executor::new(&mut cpu, &mut memory).execute(&decoded);
            assert!(
                matches!(result, ExecResult::Continue),
                "{} thumb={thumb}: {result:?}",
                row["name"]
            );
            assert_eq!(cpu.vfp.dregs, expected, "{} thumb={thumb}", row["name"]);
            assert_eq!(
                cpu.vfp.fpscr.bits(),
                row["expected_fpscr"].as_u64().unwrap() as u32,
                "{} thumb={thumb}",
                row["name"]
            );
        }
    }
}
#[test]
fn short_vector_invalid_controls_and_reserved_profiles_are_denied_before_data_or_access() {
    use rax::isa::arm::cp15::Cpacr;
    for double in [false, true] {
        for destination_scalar in [false, true] {
            for length in 1u32..=8 {
                for stride in 0u32..4 {
                    let valid = (stride == 0 || stride == 3 && (2..=4).contains(&length))
                        && (!double
                            || destination_scalar
                            || length <= 4 && (stride == 0 || length <= 2));
                    let all = cases();
                    let row = all["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| {
                            r["operation"] == "vadd"
                                && r["bits"] == if double { 64 } else { 32 }
                                && r["d"] == if destination_scalar { 1 } else { 29 }
                        })
                        .unwrap();
                    let raw = row["arm"].as_u64().unwrap() as u32;
                    for denied in [false, true] {
                        let mut cpu = Armv7Cpu::new();
                        cpu.vfp.mvfr0 |= 1 << 24;
                        cpu.vfp.fpscr = Fpscr::from_bits(((length - 1) << 16) | (stride << 20));
                        if denied {
                            cpu.cp15.cpacr = Cpacr::from_bits(0);
                        }
                        let before = cpu.vfp.dregs;
                        let flags = cpu.vfp.fpscr.bits();
                        let result = execute(&mut cpu, raw);
                        if !valid {
                            assert!(
                                matches!(result, ExecResult::Undefined),
                                "double={double} scalar={destination_scalar} len={length} stride={stride}: {result:?}"
                            );
                        } else if denied {
                            assert!(matches!(result, ExecResult::Exception(_)), "{result:?}");
                        } else {
                            assert!(matches!(result, ExecResult::Continue), "{result:?}");
                        }
                        if !valid || denied {
                            assert_eq!(cpu.vfp.dregs, before);
                            assert_eq!(cpu.vfp.fpscr.bits(), flags);
                        }
                    }
                }
            }
        }
    }
    for capability in 2..=15 {
        let mut cpu = Armv7Cpu::new();
        cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 24)) | (capability << 24);
        cpu.cp15.cpacr = Cpacr::from_bits(0);
        assert!(matches!(
            execute(&mut cpu, 0xee384a0c),
            ExecResult::Undefined
        ));
        // ID reads remain independent of the reserved operation capability.
        cpu.cp15.cpacr = Cpacr::from_bits(0x00f00000);
        assert!(matches!(
            execute(&mut cpu, 0xeef70a10),
            ExecResult::Continue
        ));
    }
}
#[test]
fn short_vector_predicates_independent_operations_and_fused_control_policy() {
    use rax::isa::arm::decoder::ThumbDecoder;
    for thumb in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.vfp.mvfr0 |= 1 << 24;
        cpu.vfp.fpscr = Fpscr::from_bits(0x00370000);
        cpu.cpsr.z = false;
        cpu.cpsr.t = thumb;
        let raw = if thumb {
            cpu.cpsr.set_it_state(0, 8);
            0xee384a0c
        } else {
            0x0e384a0c
        };
        let decoded = if thumb {
            ThumbDecoder::decode_32bit(raw)
        } else {
            Aarch32Decoder::decode(raw)
        }
        .unwrap();
        let before = cpu.vfp.dregs;
        let mut memory = FlatMemory::new(4096, 0);
        assert!(matches!(
            Executor::new(&mut cpu, &mut memory).execute(&decoded),
            ExecResult::Continue
        ));
        assert_eq!(cpu.vfp.dregs, before);
    }
    let mut cpu = Armv7Cpu::new();
    cpu.vfp.mvfr0 |= 1 << 24;
    cpu.vfp.fpscr = Fpscr::from_bits(3 << 16);
    // Comparison and Advanced SIMD ADD ignore the legacy vector controls.
    for raw in [0xeeb40a40, 0xf2000d40] {
        assert!(
            matches!(execute(&mut cpu, raw), ExecResult::Continue),
            "{raw:x}"
        );
    }
    let all = cases();
    for (asm, mnemonic) in [
        ("vfma.f32 s0,s0,s0", rax::isa::arm::decoder::Mnemonic::VFMA),
        ("vfms.f32 s0,s0,s0", rax::isa::arm::decoder::Mnemonic::VFMS),
        (
            "vfnma.f32 s0,s0,s0",
            rax::isa::arm::decoder::Mnemonic::VFNMA,
        ),
        (
            "vfnms.f32 s0,s0,s0",
            rax::isa::arm::decoder::Mnemonic::VFNMS,
        ),
    ] {
        let raw = all["control_words"][asm]["arm"].as_u64().unwrap() as u32;
        assert_eq!(Aarch32Decoder::decode(raw).unwrap().mnemonic, mnemonic);
        assert!(
            matches!(execute(&mut cpu, raw), ExecResult::Undefined),
            "{raw:x}"
        );
    }
}
#[test]
fn short_vector_accumulates_exception_flags_across_all_iterations() {
    let mut cpu = Armv7Cpu::new();
    cpu.vfp.mvfr0 |= 1 << 24;
    cpu.vfp.fpscr = Fpscr::from_bits((3 << 16) | 0x80);
    // VDIV S8..11,S16..19,S24..27: divide by zero, invalid, exact, inexact.
    for (i, (a, b)) in [(1.0, 0.0), (0.0, 0.0), (4.0, 2.0), (1.0, 3.0)]
        .into_iter()
        .enumerate()
    {
        cpu.vfp.write_s(16 + i as u8, a);
        cpu.vfp.write_s(24 + i as u8, b);
    }
    // The VDIV opcode differs from VADD only in its operation bits.
    assert!(matches!(
        execute(&mut cpu, 0xee884a0c),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_s_bits(8), 0x7f800000);
    assert_eq!(cpu.vfp.read_s_bits(9) & 0x7fffffff, 0x7fc00000);
    assert_eq!(cpu.vfp.read_s_bits(10), 2.0f32.to_bits());
    assert_eq!(cpu.vfp.fpscr.bits(), (3 << 16) | 0x80 | 0x13);
}

#[test]
fn short_vectors_keep_the_complete_arm_and_thumb_smir_frontier_closed() {
    use rax::smir::ir::types::SourceArch;
    use rax::smir::lift::aarch32::Aarch32Lifter;
    use rax::smir::lift::thumb::ThumbLifter;
    use rax::smir::lift::{LiftContext, LiftError, SmirLifter};
    let all = cases();
    let mut seen = std::collections::BTreeSet::new();
    for row in all["cases"].as_array().unwrap() {
        for thumb in [false, true] {
            let raw = row[if thumb { "thumb" } else { "arm" }].as_u64().unwrap() as u32;
            if !seen.insert((thumb, raw)) {
                continue;
            }
            let mut lifter: Box<dyn SmirLifter> = if thumb {
                Box::new(ThumbLifter::new())
            } else {
                Box::new(Aarch32Lifter::new())
            };
            let bytes = if thumb {
                [
                    ((raw >> 16) as u16).to_le_bytes(),
                    (raw as u16).to_le_bytes(),
                ]
                .concat()
            } else {
                raw.to_le_bytes().to_vec()
            };
            let mut context = LiftContext::new(if thumb {
                SourceArch::Thumb
            } else {
                SourceArch::Aarch32
            });
            assert!(
                matches!(
                    lifter.lift_insn(0x100, &bytes, &mut context),
                    Err(LiftError::Unsupported { addr: 0x100, .. })
                ),
                "{} thumb={thumb}",
                row["name"]
            );
        }
    }
    assert_eq!(seen.len(), 220);
}
#[test]
fn short_vector_restricted_operating_mode_bounces_before_any_iteration() {
    let mut cpu = Armv7Cpu::new();
    cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 28)) | (1 << 24);
    cpu.vfp.fpscr = Fpscr::from_bits((7 << 16) | (1 << 22));
    for i in 0..32 {
        cpu.vfp.write_s_bits(i, 0x3f800000 + u32::from(i));
    }
    let before = cpu.vfp.dregs;
    let flags = cpu.vfp.fpscr.bits();
    assert!(matches!(
        execute(&mut cpu, 0xee384a0c),
        ExecResult::Exception(_)
    ));
    assert_eq!(cpu.vfp.dregs, before);
    assert_eq!(cpu.vfp.fpscr.bits(), flags);
}

#[test]
fn short_vector_overlaps_use_encoded_element_order_without_snapshotting_operands() {
    use rax::isa::arm::decoder::ThumbDecoder;
    let all = cases();
    for (asm, double, start, length, negative, expected) in [
        (
            "vadd.f32 s9,s8,s10",
            false,
            8,
            4,
            false,
            vec![1.0, 4.0, 8.0, 13.0, 19.0, 6.0, 7.0, 8.0],
        ),
        (
            "vadd.f64 d5,d4,d6",
            true,
            4,
            4,
            false,
            vec![13.0, 4.0, 8.0, 9.0],
        ),
        (
            "vmov.f32 s8,s9",
            false,
            8,
            8,
            false,
            vec![2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 2.0],
        ),
        (
            "vmov.f64 d4,d5",
            true,
            4,
            4,
            false,
            vec![2.0, 3.0, 4.0, 2.0],
        ),
        ("vabs.f64 d4,d5", true, 4, 4, true, vec![2.0, 3.0, 4.0, 2.0]),
    ] {
        for thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.vfp.mvfr0 |= 1 << 24;
            cpu.vfp.fpscr = Fpscr::from_bits((length - 1) << 16);
            cpu.cpsr.t = thumb;
            for i in 0..expected.len() {
                let value = (i + 1) as f64 * if negative { -1.0 } else { 1.0 };
                if double {
                    cpu.vfp.write_d(start + i as u8, value);
                } else {
                    cpu.vfp.write_s(start + i as u8, value as f32);
                }
            }
            let mut expected_image = cpu.vfp.dregs;
            for (i, value) in expected.iter().copied().enumerate() {
                let reg = usize::from(start) + i;
                if double {
                    expected_image[reg] = (value as f64).to_bits();
                } else {
                    let shift = (reg & 1) * 32;
                    expected_image[reg / 2] = (expected_image[reg / 2] & !(0xffffffffu64 << shift))
                        | (u64::from((value as f32).to_bits()) << shift);
                }
            }
            let raw = all["control_words"][asm][if thumb { "thumb" } else { "arm" }]
                .as_u64()
                .unwrap() as u32;
            let decoded = if thumb {
                ThumbDecoder::decode_32bit(raw)
            } else {
                Aarch32Decoder::decode(raw)
            }
            .unwrap();
            let mut memory = FlatMemory::new(4096, 0);
            assert!(matches!(
                Executor::new(&mut cpu, &mut memory).execute(&decoded),
                ExecResult::Continue
            ));
            assert_eq!(cpu.vfp.dregs, expected_image, "{asm} thumb={thumb}");
            for (i, value) in expected.iter().copied().enumerate() {
                let actual = if double {
                    cpu.vfp.read_d(start + i as u8)
                } else {
                    f64::from(cpu.vfp.read_s(start + i as u8))
                };
                assert_eq!(actual, value, "{asm} thumb={thumb} index={i}");
            }
        }
    }
}

#[test]
fn recorded_short_vector_oracle_retains_every_deviation_and_matches_input_fingerprints() {
    use sha2::{Digest, Sha256};
    let reference: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a32-short-vectors/qemu-reference.json"
    )))
    .unwrap();
    let hash = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hash(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/development/a32-short-vectors/cases.json"
        ))),
        reference["cases_sha256"].as_str().unwrap()
    );
    assert_eq!(
        hash(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tools/execution/a32_short_vector_qemu.py"
        ))),
        reference["runner_sha256"].as_str().unwrap()
    );
    assert_eq!(reference["cases"], 2138);
    assert_eq!(reference["matched"], 1938);
    assert_eq!(reference["mismatched"], 200);
    let deviations = reference["deviations"].as_array().unwrap();
    assert_eq!(deviations.len(), 200);
    for row in deviations {
        assert!(!row["matched"].as_bool().unwrap());
        assert!(!row["differences"].as_array().unwrap().is_empty());
        assert_eq!(row["fpscr"], row["expected_fpscr"]);
        assert!(
            row["bits"] == 32 && row["stride"] == 2 || row["bits"] == 64 && row["shape"] == "unary"
        );
    }
}

#[test]
fn short_vectors_preserve_d16_admission_and_never_access_an_unavailable_bank() {
    let all = cases();
    for row in all["cases"].as_array().unwrap() {
        let double = row["bits"] == 64;
        let shape = row["shape"].as_str().unwrap();
        let high = double
            && (row["d"].as_u64().unwrap() >= 16
                || shape == "binary" && row["n"].as_u64().unwrap() >= 16
                || shape != "immediate" && row["m"].as_u64().unwrap() >= 16);
        let mut cpu = Armv7Cpu::new();
        cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !15) | 1 | (1 << 24);
        // D16 has no Advanced SIMD. Scalar half/FP feature fields are separate.
        cpu.vfp.mvfr1 &= !(0xffff << 8);
        cpu.vfp.fpscr = Fpscr::from_bits(row["control"].as_u64().unwrap() as u32);
        let initial = all["initials"][row["initial"].as_u64().unwrap() as usize]
            .as_array()
            .unwrap();
        for (i, value) in initial.iter().enumerate() {
            cpu.vfp.dregs[i] = value.as_u64().unwrap();
        }
        let before = cpu.vfp.dregs;
        let flags = cpu.vfp.fpscr.bits();
        let mut expected = before;
        for change in row["changes"].as_array().unwrap() {
            expected[change[0].as_u64().unwrap() as usize] = change[1].as_u64().unwrap();
        }
        let result = execute(&mut cpu, row["arm"].as_u64().unwrap() as u32);
        if high {
            assert!(
                matches!(result, ExecResult::Undefined),
                "{}: {result:?}",
                row["name"]
            );
            assert_eq!(cpu.vfp.dregs, before);
            assert_eq!(cpu.vfp.fpscr.bits(), flags);
        } else {
            assert!(
                matches!(result, ExecResult::Continue),
                "{}: {result:?}",
                row["name"]
            );
            assert_eq!(cpu.vfp.dregs, expected, "{}", row["name"]);
            assert_eq!(cpu.vfp.fpscr.bits(), flags);
        }
    }
}
