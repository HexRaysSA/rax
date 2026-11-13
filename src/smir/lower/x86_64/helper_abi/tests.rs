use super::*;
use crate::smir::lower::CodeBuffer;
use crate::smir::lower::runtime::ExecMem;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct Pair {
    value: u64,
    status: u64,
}

fn mix([a, b, c, d, e, f]: [u64; 6]) -> u64 {
    a.rotate_left(3)
        ^ b.rotate_left(11)
        ^ c.rotate_left(19)
        ^ d.rotate_left(27)
        ^ e.rotate_left(37)
        ^ f.rotate_left(51)
}

extern "C" fn scalar(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    mix([a, b, c, d, e, f])
}

extern "C" fn pair(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> Pair {
    Pair {
        value: mix([a, b, c, d, e, f]),
        status: mix([f, e, d, c, b, a]),
    }
}

fn bridge(target: u64, target_register: PhysReg, returns_pair: bool) -> ExecMem {
    let mut code = CodeBuffer::new();
    {
        let mut emitter = X86Emitter::new(&mut code);
        emitter.emit_push(PhysReg::Rbp); // SysV entry RSP=8 mod 16; align CALL.
        emitter.emit_mov_ri_imm64(target_register, target as i64);
    }
    emit_host_c_call(&mut code, target_register, returns_pair);
    {
        let mut emitter = X86Emitter::new(&mut code);
        emitter.emit_pop(PhysReg::Rbp);
        emitter.emit_ret();
    }
    ExecMem::new(code.as_slice()).expect("map native callback bridge")
}

fn operands(n: u64) -> [u64; 6] {
    [
        n,
        !n,
        n.rotate_left(17),
        n.wrapping_mul(0xdeadbeef),
        0x1122334455667788,
        n << 51,
    ]
}

#[test]
fn host_c_callback_preserves_six_integer_arguments_and_scalar_result() {
    let executable = bridge(scalar as *const () as u64, PhysReg::Rax, false);
    let call: unsafe extern "sysv64" fn(u64, u64, u64, u64, u64, u64) -> u64 =
        unsafe { core::mem::transmute(executable.mapping_bounds().0) };
    for n in 0..32 {
        let [a, b, c, d, e, f] = operands(n);
        assert_eq!(unsafe { call(a, b, c, d, e, f) }, mix([a, b, c, d, e, f]));
    }
}

#[test]
fn host_c_callback_normalizes_two_word_result_with_six_integer_arguments() {
    let executable = bridge(pair as *const () as u64, PhysReg::R11, true);
    let call: unsafe extern "sysv64" fn(u64, u64, u64, u64, u64, u64) -> Pair =
        unsafe { core::mem::transmute(executable.mapping_bounds().0) };
    for n in 0..32 {
        let [a, b, c, d, e, f] = operands(n);
        assert_eq!(
            unsafe { call(a, b, c, d, e, f) },
            Pair {
                value: mix([a, b, c, d, e, f]),
                status: mix([f, e, d, c, b, a]),
            }
        );
    }
}
