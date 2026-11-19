//! Paired-register compare-exchange at a device address.
use super::*;
use devices::bus::MmioRmwOp;
use isa::x86_64::instruction_metadata::{self, OperandKind};

const EXPECTED: u64 = 0xabcd_1234_1234_5678;
const REPLACEMENT: u64 = 0x5555_7777_8765_4321;
const DIFFERENT: u64 = 0x8899_aabb_ccdd_eeff;
const ZF: u64 = 1 << 6;
const FLAGS: u64 = 0xa97;

#[test]
fn cmpxchg8b_metadata_identifies_the_read_write_qword_with_or_without_lock() {
    for (bits, code) in [
        (16, &[0x0f, 0xc7, 0x0f][..]),
        (32, &[0x66, 0x0f, 0xc7, 0x0f]),
        (64, &[0xf0, 0x0f, 0xc7, 0x0f]),
    ] {
        let result = instruction_metadata::decode(bits, 0x1000, code).unwrap();
        assert_eq!(result.mnemonic, "cmpxchg8b");
        assert_eq!(result.size as usize, code.len());
        assert!(result.operands_complete);
        let operand = &result.operands[0];
        assert_eq!(operand.kind, OperandKind::Memory);
        assert_eq!(operand.width_bits, 64);
        assert!(operand.read && operand.write && !operand.conditional);
        for end in 0..code.len() {
            assert!(instruction_metadata::decode(bits, 0x1000, &code[..end]).is_err());
        }
    }
}

#[derive(Debug)]
struct PairHost {
    registers: [u64; 16],
    flags: u64,
    calls: Vec<&'static str>,
    reject_edx: bool,
}

impl mmio::CompletionAccess for PairHost {
    type Error = &'static str;

    fn write_gpr(&mut self, index: usize, value: u64) -> Result<(), Self::Error> {
        self.calls.push("gpr");
        if index == 2 && self.reject_edx {
            return Err("EDX rejected");
        }
        self.registers[index] = value;
        Ok(())
    }

    fn write_rflags(&mut self, flags: u64) -> Result<(), Self::Error> {
        self.calls.push("flags");
        self.flags = flags;
        Ok(())
    }

    fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
        assert!(matches!(length, 3..=5));
        self.calls.push("retire");
        Ok(())
    }
}

fn transaction(code: &[u8], qualification: u64, flags: u64) -> (Context, mmio::InputState) {
    let (mut context, mut memory, mut record) = fixture(code);
    context.registers[0] = 0xfeed_face_1234_5678;
    context.registers[1] = 0x8765_1234_5555_7777;
    context.registers[2] = 0xd00d_f00d_abcd_1234;
    context.registers[3] = 0xcccc_dddd_8765_4321;
    context.rflags = flags;
    record.qualification = qualification;
    let plan = prepare(&context, &mut memory, record).unwrap();
    assert_eq!(
        (plan.physical, plan.linear),
        (record.physical, record.linear)
    );
    let Action::Rmw(input) = plan.action else {
        panic!("expected device compare-exchange");
    };
    assert_eq!(input.size, 8);
    assert_eq!(
        input.operation,
        MmioRmwOp::CompareExchange {
            expected: EXPECTED,
            replacement: REPLACEMENT
        }
    );
    let mut pending = mmio::InputState::default();
    pending.begin_rmw(input).unwrap();
    (context, pending)
}

#[test]
fn cmpxchg8b_completes_equal_or_unequal_device_results_after_checkpoint() {
    for (old, equal) in [(EXPECTED, true), (DIFFERENT, false)] {
        let flags_before = if equal { FLAGS } else { FLAGS | ZF };
        let (context, state) = transaction(&[0xf0, 0x0f, 0xc7, 0x0f], 0x182, flags_before);
        let encoded = rax::codec::serialize(&state).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&encoded).unwrap();
        restored.validate_checkpoint().unwrap();
        let (size, op) = restored.descriptor().unwrap();
        let mut data = old.to_le_bytes();
        assert_eq!(size, 8);
        op.unwrap().apply(&mut data).unwrap();
        assert_eq!(data, (if equal { REPLACEMENT } else { old }).to_le_bytes());
        let mut host = PairHost {
            registers: context.registers,
            flags: context.rflags,
            calls: Vec::new(),
            reject_edx: false,
        };
        restored.complete(&mut host, &old.to_le_bytes());
        assert_eq!(restored.ready(), Ok(()));
        let mut registers = context.registers;
        if !equal {
            registers[0] = old & 0xffff_ffff;
            registers[2] = old >> 32;
        }
        assert_eq!(host.registers, registers);
        assert_eq!(host.flags, (FLAGS & !ZF) | if equal { ZF } else { 0 });
        assert_eq!(
            host.calls.as_slice(),
            if equal {
                &["flags", "retire"][..]
            } else {
                &["gpr", "gpr", "flags", "retire"]
            }
        );
    }
}

#[test]
fn cmpxchg8b_second_register_failure_fences_before_flags_or_retirement() {
    let (context, mut pending) = transaction(&[0x0f, 0xc7, 0x0f], 0x183, FLAGS | ZF);
    let mut host = PairHost {
        registers: context.registers,
        flags: context.rflags,
        calls: Vec::new(),
        reject_edx: true,
    };
    pending.complete(&mut host, &DIFFERENT.to_le_bytes());
    assert!(pending.ready().unwrap_err().contains("EDX rejected"));
    assert_eq!(host.calls, ["gpr", "gpr"]);
    assert_eq!(host.flags, context.rflags);
    pending.complete(&mut host, &DIFFERENT.to_le_bytes());
    assert_eq!(host.calls, ["gpr", "gpr"]);
}

#[test]
fn paired_compare_exchange_requires_memory_and_a_qualified_write() {
    for (bytes, qualification) in [
        (&[0x0f, 0xc7, 0xc8][..], 0x183),
        (&[0x48, 0x0f, 0xc7, 0xc8], 0x183),
        (&[0x0f, 0xc7, 0x0f], 0x181),
        (&[0x48, 0x0f, 0xc7, 0x0f], 0x181),
    ] {
        let (context, mut ram, mut exit) = fixture(bytes);
        exit.qualification = qualification;
        assert!(prepare(&context, &mut ram, exit).is_err());
    }
}

const WIDE_CODE: &[u8] = &[0xf0, 0x48, 0x0f, 0xc7, 0x0f];
const WIDE_ORIGINAL: u128 = 0xffee_ddcc_bbaa_9988_1122_3344_5566_7788;
const WIDE_REPLACEMENT: u128 = 0x0102_0304_0506_0708_a5a5_a5a5_b6b6_b6b6;

struct WideDevice {
    data: [u8; 16],
    accesses: Vec<(bool, u64, usize)>,
}

impl devices::bus::MmioDevice for WideDevice {
    fn read(&mut self, address: u64, data: &mut [u8]) {
        self.accesses.push((false, address, data.len()));
        data.copy_from_slice(&self.data);
    }
    fn write(&mut self, address: u64, data: &[u8]) {
        self.accesses.push((true, address, data.len()));
        self.data.copy_from_slice(data);
    }
}

#[test]
fn cmpxchg16b_restores_one_wide_device_transaction_and_retires() {
    use devices::bus::{MmioBus, MmioRange, SharedMmioDevice};
    use std::sync::{Arc, Mutex};

    for (code, qualification, matched) in [
        (WIDE_CODE, 0x182, true),
        (WIDE_CODE, 0x183, false),
        (&WIDE_CODE[1..], 0x183, true),
        (&WIDE_CODE[1..], 0x182, false),
    ] {
        let decoded = instruction_metadata::decode(64, 0x1000, code).unwrap();
        assert_eq!(decoded.mnemonic, "cmpxchg16b");
        assert_eq!(decoded.size as usize, code.len());
        assert!(decoded.operands_complete);
        let [operand] = decoded.operands.as_slice() else {
            panic!("expected one explicit memory operand");
        };
        assert_eq!(operand.kind, OperandKind::Memory);
        assert_eq!(operand.width_bits, 128);
        assert!(operand.read && operand.write && !operand.conditional);
        for end in 0..code.len() {
            assert!(instruction_metadata::decode(64, 0x1000, &code[..end]).is_err());
        }

        let (mut context, mut ram, mut exit) = fixture(code);
        exit.qualification = qualification;
        let expected = if matched {
            WIDE_ORIGINAL
        } else {
            WIDE_ORIGINAL ^ (1 << 96)
        };
        context.registers[0] = expected as u64;
        context.registers[2] = (expected >> 64) as u64;
        context.registers[3] = WIDE_REPLACEMENT as u64;
        context.registers[1] = (WIDE_REPLACEMENT >> 64) as u64;
        context.rflags = if matched { FLAGS & !ZF } else { FLAGS | ZF };

        let plan = prepare(&context, &mut ram, exit).unwrap();
        assert_eq!(plan.length as usize, code.len());
        let Action::Rmw(input) = plan.action else {
            panic!("expected CMPXCHG16B RMW plan");
        };
        assert_eq!(input.size, 16);
        assert_eq!(
            input.operation,
            MmioRmwOp::CompareExchange16B {
                expected,
                replacement: WIDE_REPLACEMENT,
            }
        );
        let mut pending = mmio::InputState::default();
        pending.begin_rmw(input).unwrap();
        let encoded = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&encoded).unwrap();
        restored.validate_checkpoint().unwrap();

        let model = Arc::new(Mutex::new(WideDevice {
            data: WIDE_ORIGINAL.to_le_bytes(),
            accesses: Vec::new(),
        }));
        let mut bus = MmioBus::new();
        bus.register(
            MmioRange {
                base: plan.physical,
                len: 16,
            },
            Box::new(SharedMmioDevice::new(model.clone())),
        )
        .unwrap();
        let (size, operation) = restored.descriptor().unwrap();
        let operation = operation.unwrap();
        // A scalar descriptor or a range crossing the model boundary cannot
        // trigger callbacks in either the model or the open-bus fallback.
        assert!(
            bus.read_modify_write(plan.physical, size, MmioRmwOp::Not)
                .is_err()
        );
        assert!(
            bus.read_modify_write(plan.physical + 8, size, operation)
                .is_err()
        );
        assert!(model.lock().unwrap().accesses.is_empty());

        let old = bus
            .read_modify_write(plan.physical, size, operation)
            .unwrap();
        assert_eq!(old, WIDE_ORIGINAL.to_le_bytes());
        let device = model.lock().unwrap();
        assert_eq!(
            device.accesses,
            [(false, plan.physical, 16), (true, plan.physical, 16)]
        );
        assert_eq!(
            device.data,
            (if matched {
                WIDE_REPLACEMENT
            } else {
                WIDE_ORIGINAL
            })
            .to_le_bytes()
        );
        drop(device);

        let mut host = PairHost {
            registers: context.registers,
            flags: context.rflags,
            calls: Vec::new(),
            reject_edx: false,
        };
        let mut malformed = restored.clone();
        malformed.complete(&mut host, &old[..8]);
        assert!(malformed.ready().unwrap_err().contains("width"));
        assert!(host.calls.is_empty());

        restored.complete(&mut host, &old);
        assert_eq!(restored.ready(), Ok(()));
        let mut registers = context.registers;
        registers[0] = WIDE_ORIGINAL as u64;
        registers[2] = (WIDE_ORIGINAL >> 64) as u64;
        assert_eq!(host.registers, registers);
        assert_eq!(host.flags, (FLAGS & !ZF) | if matched { ZF } else { 0 });
        assert_eq!(
            host.calls.as_slice(),
            if matched {
                &["flags", "retire"][..]
            } else {
                &["gpr", "gpr", "flags", "retire"]
            }
        );
    }
}

#[test]
fn cmpxchg16b_rejects_misalignment_even_when_the_exit_address_matches() {
    let (mut context, mut ram, mut exit) = fixture(WIDE_CODE);
    context.registers[7] += 8;
    exit.linear += 8;
    exit.physical += 8;
    exit.qualification = 0x183;
    assert!(
        prepare(&context, &mut ram, exit)
            .unwrap_err()
            .contains("alignment")
    );
}
