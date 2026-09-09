//! Native x86-64 JIT tests for the architectural MM0-MM7 state bridge.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn test_vcpu_with_mem() -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    (X86_64Vcpu::new(0, mem.clone()), mem)
}

fn test_vcpu() -> X86_64Vcpu {
    test_vcpu_with_mem().0
}

#[test]
fn jit_native_region_synchronizes_mmx_values_and_precise_guest_tags() {
    // push rbp; mov rbp,rsp; push rax; mov rax,[rbp+24];
    // mov qword ptr [rax+x87_tag],0; pop rax; paddb mm0,mm1; leave; ret.
    // The explicit state-slot store models the lowerer's precise EnterMmx
    // commit independently of the trampoline's host-only EMMS cleanup.
    let mut code = vec![
        0x55, 0x48, 0x89, 0xE5, 0x50, 0x48, 0x8B, 0x45, 0x18, 0x48, 0xC7, 0x80,
    ];
    code.extend_from_slice(
        &(crate::smir::lower::X86_GUEST_X87_TAG_WORD_OFFSET as u32).to_le_bytes(),
    );
    code.extend_from_slice(&0u32.to_le_bytes());
    code.extend_from_slice(&[0x58, 0x0F, 0xFC, 0xC1, 0xC9, 0xC3]);
    let region = JitRegion {
        exec: crate::smir::lower::runtime::ExecMem::new(&code).expect("map MMX region"),
        entry_offset: 0,
        source_pages: Vec::new(),
        uses_vector: false,
        uses_xmm_state: false,
        uses_mxcsr_state: false,
        avx_ymm16_vector_state: false,
        narrow_vector_opmasks: false,
        uses_mmx: true,
        uses_x87_tag_state: true,
        uses_x87_environment_state: false,
        uses_timestamp: false,
        uses_io: false,
        yielded_backward_exit_pcs: Vec::new(),
        callout_boundaries: Vec::new(),
        vsib_instructions: Vec::new(),
    };
    let mut vcpu = test_vcpu();
    vcpu.regs.rip = 0x1000;
    vcpu.regs.rflags = 0x2;
    vcpu.regs.mm = [
        0x00ff_7f80_0102_0304,
        0x0102_0304_0506_0708,
        2,
        3,
        4,
        5,
        6,
        7,
    ];
    vcpu.fpu.tag_word = 0xFFFF;

    vcpu.jit_run_region_native(&region);

    assert_eq!(vcpu.regs.mm[0], 0x0101_8284_0608_0A0C);
    assert_eq!(
        &vcpu.regs.mm[1..],
        &[0x0102_0304_0506_0708, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rip, 0x1000);
}

#[test]
fn jit_compiles_and_executes_lifted_register_mmx_logic() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // pand mm0,mm1; jmp next; ret. The RET block is an interpreter
    // frontier, leaving the MMX instruction in the executable native block.
    mem.write_slice(&[0x0F, 0xDB, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rflags = 0x2;
    vcpu.regs.mm[0] = 0xF0F0_0FF0_AA55_1234;
    vcpu.regs.mm[1] = 0x0FF0_FFFF_0F0F_FFFF;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(false);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile MMX region")
        .expect("register MMX logic should be JIT eligible");
    assert!(region.uses_mmx);
    assert!(!region.uses_vector);

    vcpu.jit_run_region_native(&region);

    assert_eq!(vcpu.regs.mm[0], 0x00F0_0FF0_0A05_1234);
    assert_eq!(vcpu.regs.mm[1], 0x0FF0_FFFF_0F0F_FFFF);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rip, 5);
}

#[test]
fn jit_compiles_and_executes_mmx_movq_memory_helpers() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // movq mm7,[rbx]; movq [rbx+8],mm7; jmp next; ret.
    mem.write_slice(
        &[0x0F, 0x6F, 0x3B, 0x0F, 0x7F, 0x7B, 0x08, 0xEB, 0x00, 0xC3],
        GuestAddress(0),
    )
    .unwrap();
    let source = 0xFEDC_BA98_7654_3210u64;
    mem.write_slice(&source.to_le_bytes(), GuestAddress(0x2000))
        .unwrap();
    mem.write_slice(
        &0xCCCC_CCCC_CCCC_CCCCu64.to_le_bytes(),
        GuestAddress(0x2008),
    )
    .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rbx = 0x2000;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm = std::array::from_fn(|index| 0x1111_1111_1111_1111u64 * index as u64);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile MMX memory region")
        .expect("MMX MOVQ memory forms should be JIT eligible");
    assert!(region.uses_mmx);
    assert!(!region.uses_vector);

    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 8];
    mem.read_slice(&mut stored, GuestAddress(0x2008)).unwrap();
    assert_eq!(u64::from_le_bytes(stored), source);
    assert_eq!(vcpu.regs.mm[7], source);
    assert_eq!(&vcpu.regs.mm[..7], &original[..7]);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rip, 9);
}

#[test]
fn jit_compiles_and_executes_mmx_movd_q_scalar_memory_helpers() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // movd mm0,[rbx]; movd [rbx+4],mm0
    // movq mm1,[rbx+8]; movq [rbx+16],mm1
    // jmp next; ret.
    mem.write_slice(
        &[
            0x0F, 0x6E, 0x03, 0x0F, 0x7E, 0x43, 0x04, 0x48, 0x0F, 0x6E, 0x4B, 0x08, 0x48, 0x0F,
            0x7E, 0x4B, 0x10, 0xEB, 0x00, 0xC3,
        ],
        GuestAddress(0),
    )
    .unwrap();
    mem.write_slice(&0x89AB_CDEFu32.to_le_bytes(), GuestAddress(0x2000))
        .unwrap();
    mem.write_slice(&0xCCCC_CCCCu32.to_le_bytes(), GuestAddress(0x2004))
        .unwrap();
    mem.write_slice(
        &0x0123_4567_89AB_CDEFu64.to_le_bytes(),
        GuestAddress(0x2008),
    )
    .unwrap();
    mem.write_slice(
        &0xCCCC_CCCC_CCCC_CCCCu64.to_le_bytes(),
        GuestAddress(0x2010),
    )
    .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rbx = 0x2000;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0xF0E1_D2C3_B4A5_9687u64.rotate_left(index as u32 * 7));
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile MMX MOVD/MOVQ scalar-memory region")
        .expect("exact MMX MOVD/MOVQ scalar memory forms should be JIT eligible");
    assert!(region.uses_mmx);
    assert!(!region.uses_vector);

    vcpu.jit_run_region_native(&region);

    let mut stored_dword = [0u8; 4];
    mem.read_slice(&mut stored_dword, GuestAddress(0x2004))
        .unwrap();
    let mut stored_qword = [0u8; 8];
    mem.read_slice(&mut stored_qword, GuestAddress(0x2010))
        .unwrap();
    assert_eq!(u32::from_le_bytes(stored_dword), 0x89AB_CDEF);
    assert_eq!(u64::from_le_bytes(stored_qword), 0x0123_4567_89AB_CDEF);
    assert_eq!(vcpu.regs.mm[0], 0x0000_0000_89AB_CDEF);
    assert_eq!(vcpu.regs.mm[1], 0x0123_4567_89AB_CDEF);
    assert_eq!(&vcpu.regs.mm[2..], &original[2..]);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rbx, 0x2000);
    assert_eq!(vcpu.regs.rip, 19);
}

#[test]
fn jit_compiles_and_executes_mmx_movntq_memory_helper() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // movntq [rbx],mm3; jmp next; ret. MOVNTQ permits an unaligned m64.
    mem.write_slice(&[0x0F, 0xE7, 0x1B, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0x2003;
    mem.write_slice(&[0xCC; 8], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rbx = address;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0xF0E1_D2C3_B4A5_9687u64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[3] = 0x0123_4567_89AB_CDEF;
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile MMX MOVNTQ memory region")
        .expect("exact MMX MOVNTQ memory form should be JIT eligible");
    assert!(region.uses_mmx);
    assert!(!region.uses_vector);

    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 8];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(u64::from_le_bytes(stored), 0x0123_4567_89AB_CDEF);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rbx, address);
    assert_eq!(vcpu.regs.rip, 5);
}

#[test]
fn jit_mmx_movntq_uses_exact_width_at_mapped_boundary() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // movntq [rbx],mm7; jmp next; ret.
    mem.write_slice(&[0x0F, 0xE7, 0x3B, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0x10000 - 8;
    mem.write_slice(&[0xCC; 8], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rbx = address;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm = std::array::from_fn(|index| 0x1111_1111_1111_1111u64 * index as u64);
    vcpu.regs.mm[7] = 0xFEDC_BA98_7654_3210;
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile boundary MOVNTQ")
        .expect("exactly mapped MOVNTQ should be JIT eligible");
    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 8];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(u64::from_le_bytes(stored), 0xFEDC_BA98_7654_3210);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rbx, address);
    assert_eq!(vcpu.regs.rip, 5);
}

#[test]
fn jit_faulting_mmx_movntq_preserves_state_and_store_atomicity() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // movntq [rbx],mm7; jmp next; ret. Only the first 4 bytes are mapped.
    mem.write_slice(&[0x0F, 0xE7, 0x3B, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0x10000 - 4;
    let before = [0xA5; 4];
    mem.write_slice(&before, GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rbx = address;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile faulting MOVNTQ")
        .expect("fault-capable MOVNTQ should retain a native deopt path");
    vcpu.jit_run_region_native(&region);

    let mut after = [0u8; 4];
    mem.read_slice(&mut after, GuestAddress(address)).unwrap();
    assert_eq!(
        after, before,
        "MOVNTQ must not partially write before fault"
    );
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0xFFFF);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rbx, address);
    assert_eq!(
        vcpu.regs.rip, 0,
        "MOVNTQ fault must restart the instruction"
    );
}

#[test]
fn jit_compiles_and_executes_mmx_maskmovq_memory_helper() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // maskmovq mm0,mm1; jmp next; ret. The implicit destination is DS:RDI.
    mem.write_slice(&[0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0x2003;
    let before = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    mem.write_slice(&before, GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = address;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0xF0E1_D2C3_B4A5_9687u64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[0] = u64::from_le_bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    vcpu.regs.mm[1] = u64::from_le_bytes([0x80, 0x00, 0xFF, 0x7F, 0x01, 0x80, 0x00, 0xFF]);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile MMX MASKMOVQ memory region")
        .expect("exact MMX MASKMOVQ form should be JIT eligible");
    assert!(region.uses_mmx);
    assert!(!region.uses_vector);

    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 8];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(stored, [0x10, 0xA1, 0x30, 0xA3, 0xA4, 0x60, 0xA6, 0x80]);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rdi, address);
    assert_eq!(vcpu.regs.rip, 5);
}

#[test]
fn jit_mmx_maskmovq_all_zero_mask_performs_no_memory_access() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // maskmovq mm0,mm1; jmp next; ret. RDI is deliberately unmapped.
    mem.write_slice(&[0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 0x1_0000;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[1] = 0;
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile all-zero-mask MASKMOVQ")
        .expect("all-zero-mask MASKMOVQ should be JIT eligible");
    vcpu.jit_run_region_native(&region);

    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, 0x1_0000);
    assert_eq!(vcpu.regs.rip, 5);
}

#[test]
fn jit_faulting_mmx_maskmovq_preserves_ordered_partial_completion() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // maskmovq mm0,mm1; jmp next; ret. Lane 0 is mapped and lane 1 faults.
    mem.write_slice(&[0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0xFFFF;
    mem.write_slice(&[0xA5], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = address;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0xF0E1_D2C3_B4A5_9687u64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[0] = u64::from_le_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    vcpu.regs.mm[1] = u64::from_le_bytes([0x80, 0x80, 0, 0, 0, 0, 0, 0]);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile faulting MASKMOVQ")
        .expect("fault-capable MASKMOVQ should retain native lane exits");
    vcpu.jit_run_region_native(&region);

    let mut committed = [0u8; 1];
    mem.read_slice(&mut committed, GuestAddress(address))
        .unwrap();
    assert_eq!(committed, [0x11], "lane 0 must commit before lane 1 faults");
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0xFFFF);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, address);
    assert_eq!(vcpu.regs.rip, 0, "fault must restart MASKMOVQ");
}

#[test]
fn jit_mmx_maskmovq_honors_fs_segment_base() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // fs maskmovq mm0,mm1; jmp next; ret.
    mem.write_slice(&[0x64, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0x2003;
    let before = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    mem.write_slice(&before, GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.fs.base = 0x2000;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 3;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[0] = u64::from_le_bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    vcpu.regs.mm[1] = u64::from_le_bytes([0, 0x80, 0, 0, 0, 0xFF, 0, 0]);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile FS MASKMOVQ")
        .expect("FS-relative MASKMOVQ should be JIT eligible");
    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 8];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(stored, [0xA0, 0x20, 0xA2, 0xA3, 0xA4, 0x60, 0xA6, 0xA7]);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rdi, 3);
    assert_eq!(vcpu.regs.rip, 6);
}

#[test]
fn jit_mmx_maskmovq_address_size_override_uses_zero_extended_edi() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // addr32 maskmovq mm0,mm1; jmp next; ret.
    mem.write_slice(&[0x67, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0x2003;
    let before = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    mem.write_slice(&before, GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 0xDEAD_BEEF_0000_2003;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[0] = u64::from_le_bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    vcpu.regs.mm[1] = u64::from_le_bytes([0x80, 0, 0, 0x80, 0, 0, 0x80, 0]);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile addr32 MASKMOVQ")
        .expect("exact addr32 MASKMOVQ should be JIT eligible");
    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 8];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(stored, [0x10, 0xA1, 0xA2, 0x40, 0xA4, 0xA5, 0x70, 0xA7]);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rdi, 0xDEAD_BEEF_0000_2003);
    assert_eq!(vcpu.regs.rip, 6);
}

#[test]
fn jit_mmx_maskmovq_address_size_wraps_before_adding_fs_base() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // fs addr32 maskmovq mm0,mm1; jmp next; ret. Lane 1 wraps EDI to zero.
    mem.write_slice(
        &[0x64, 0x67, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3],
        GuestAddress(0),
    )
    .unwrap();
    let address = 0x2000;
    mem.write_slice(&[0xA0], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.fs.base = address;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 0xDEAD_BEEF_FFFF_FFFF;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0xF0E1_D2C3_B4A5_9687u64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[0] = u64::from_le_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    vcpu.regs.mm[1] = u64::from_le_bytes([0, 0x80, 0, 0, 0, 0, 0, 0]);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile FS addr32 MASKMOVQ")
        .expect("FS addr32 MASKMOVQ should be JIT eligible");
    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 1];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(stored, [0x22]);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, 0xDEAD_BEEF_FFFF_FFFF);
    assert_eq!(vcpu.regs.rip, 7);
}

#[test]
fn direct_mmx_maskmovq_address_size_wraps_before_adding_fs_base() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    mem.write_slice(&[0x64, 0x67, 0x0F, 0xF7, 0xC1], GuestAddress(0))
        .unwrap();
    let address = 0x2000;
    mem.write_slice(&[0xA0], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.fs.base = address;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 0xDEAD_BEEF_FFFF_FFFF;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[0] = u64::from_le_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    vcpu.regs.mm[1] = u64::from_le_bytes([0, 0x80, 0, 0, 0, 0, 0, 0]);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;

    assert!(vcpu.step().unwrap().is_none());

    let mut stored = [0u8; 1];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(stored, [0x22]);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, 0xDEAD_BEEF_FFFF_FFFF);
    assert_eq!(vcpu.regs.rip, 5);
}

#[test]
fn jit_faulting_mmx_maskmovq_address_size_preserves_partial_completion() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // addr32 maskmovq mm0,mm1; jmp next; ret. Lane 0 commits, lane 1 faults.
    mem.write_slice(&[0x67, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0xFFFF;
    mem.write_slice(&[0xA5], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 0xDEAD_BEEF_0000_FFFF;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
    vcpu.regs.mm[0] = u64::from_le_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    vcpu.regs.mm[1] = u64::from_le_bytes([0x80, 0x80, 0, 0, 0, 0, 0, 0]);
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile faulting addr32 MASKMOVQ")
        .expect("fault-capable addr32 MASKMOVQ should retain native lane exits");
    vcpu.jit_run_region_native(&region);

    let mut committed = [0u8; 1];
    mem.read_slice(&mut committed, GuestAddress(address))
        .unwrap();
    assert_eq!(committed, [0x11]);
    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0xFFFF);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, 0xDEAD_BEEF_0000_FFFF);
    assert_eq!(vcpu.regs.rip, 0);
}

#[test]
fn jit_compiles_and_executes_xmm_maskmovdqu_memory_helper() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // maskmovdqu xmm0,xmm1; jmp next; ret. The implicit destination is DS:RDI.
    mem.write_slice(&[0x66, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0x3000;
    let before = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ];
    mem.write_slice(&before, GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = address;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.xmm[0] = [
        u64::from_le_bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]),
        u64::from_le_bytes([0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01]),
    ];
    vcpu.regs.xmm[1] = [
        u64::from_le_bytes([0x80, 0, 0, 0x80, 0, 0, 0x80, 0]),
        u64::from_le_bytes([0x80, 0, 0, 0, 0, 0x80, 0, 0x80]),
    ];
    let original = vcpu.regs.xmm;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile XMM MASKMOVDQU memory region")
        .expect("exact XMM MASKMOVDQU form should be JIT eligible");
    assert!(!region.uses_vector);
    assert!(region.uses_xmm_state);
    assert!(!region.uses_mmx);
    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 16];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(
        stored,
        [
            0x10, 0xA1, 0xA2, 0x40, 0xA4, 0xA5, 0x70, 0xA7, 0x90, 0xA9, 0xAA, 0xAB, 0xAC, 0xE0,
            0xAE, 0x01,
        ]
    );
    assert_eq!(vcpu.regs.xmm, original);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, address);
    assert_eq!(vcpu.regs.rip, 6);
}

#[test]
fn jit_xmm_maskmovdqu_all_zero_mask_performs_no_memory_access() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    mem.write_slice(&[0x66, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 0x1_0000;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.xmm = std::array::from_fn(|index| {
        [
            0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 5),
            0xFEDC_BA98_7654_3210u64.rotate_right(index as u32 * 7),
        ]
    });
    vcpu.regs.xmm[1] = [0, 0];
    let original = vcpu.regs.xmm;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile all-zero-mask XMM MASKMOVDQU")
        .expect("all-zero-mask XMM MASKMOVDQU should be JIT eligible");
    assert!(region.uses_xmm_state);
    vcpu.jit_run_region_native(&region);

    assert_eq!(vcpu.regs.xmm, original);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rdi, 0x1_0000);
    assert_eq!(vcpu.regs.rip, 6);
}

#[test]
fn jit_faulting_xmm_maskmovdqu_preserves_ordered_partial_completion() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    mem.write_slice(&[0x66, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    let address = 0xFFFF;
    mem.write_slice(&[0xA5], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = address;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.xmm[0] = [
        u64::from_le_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        0x0102_0304_0506_0708,
    ];
    vcpu.regs.xmm[1] = [u64::from_le_bytes([0x80, 0x80, 0, 0, 0, 0, 0, 0]), 0];
    let original = vcpu.regs.xmm;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile faulting XMM MASKMOVDQU")
        .expect("fault-capable XMM MASKMOVDQU should retain native lane exits");
    vcpu.jit_run_region_native(&region);

    let mut committed = [0u8; 1];
    mem.read_slice(&mut committed, GuestAddress(address))
        .unwrap();
    assert_eq!(committed, [0x11]);
    assert_eq!(vcpu.regs.xmm, original);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, address);
    assert_eq!(vcpu.regs.rip, 0);
}

#[test]
fn jit_xmm_maskmovdqu_addr32_wraps_before_adding_fs_base() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    mem.write_slice(
        &[0x64, 0x67, 0x66, 0x0F, 0xF7, 0xC1, 0xEB, 0x00, 0xC3],
        GuestAddress(0),
    )
    .unwrap();
    let address = 0x2000;
    mem.write_slice(&[0xA0], GuestAddress(address)).unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.fs.base = address;
    vcpu.regs.rip = 0;
    vcpu.regs.rdi = 0xDEAD_BEEF_FFFF_FFFF;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.xmm[0] = [
        u64::from_le_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        0x0102_0304_0506_0708,
    ];
    vcpu.regs.xmm[1] = [u64::from_le_bytes([0, 0x80, 0, 0, 0, 0, 0, 0]), 0];
    let original = vcpu.regs.xmm;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile FS addr32 XMM MASKMOVDQU")
        .expect("FS addr32 XMM MASKMOVDQU should be JIT eligible");
    assert!(region.uses_xmm_state);
    vcpu.jit_run_region_native(&region);

    let mut stored = [0u8; 1];
    mem.read_slice(&mut stored, GuestAddress(address)).unwrap();
    assert_eq!(stored, [0x22]);
    assert_eq!(vcpu.regs.xmm, original);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rdi, 0xDEAD_BEEF_FFFF_FFFF);
    assert_eq!(vcpu.regs.rip, 8);
}

#[test]
fn jit_mmx_scalar_memory_transfers_use_exact_width_at_mapped_boundary() {
    for (instruction, is_load, width, value, name) in [
        (
            &[0x0F, 0x6E, 0x1B][..],
            true,
            4usize,
            0x0000_0000_89AB_CDEFu64,
            "MOVD mm3,m32",
        ),
        (
            &[0x0F, 0x7E, 0x1B][..],
            false,
            4usize,
            0xFEDC_BA98_7654_3210u64,
            "MOVD m32,mm3",
        ),
        (
            &[0x48, 0x0F, 0x6E, 0x1B][..],
            true,
            8usize,
            0x0123_4567_89AB_CDEFu64,
            "MOVQ mm3,m64",
        ),
        (
            &[0x48, 0x0F, 0x7E, 0x1B][..],
            false,
            8usize,
            0xFEDC_BA98_7654_3210u64,
            "MOVQ m64,mm3",
        ),
    ] {
        let (mut vcpu, mem) = test_vcpu_with_mem();
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xC3]);
        mem.write_slice(&code, GuestAddress(0)).unwrap();
        let address = 0x10000 - width as u64;
        if is_load {
            mem.write_slice(&value.to_le_bytes()[..width], GuestAddress(address))
                .unwrap();
        } else {
            mem.write_slice(&[0xCC; 8][..width], GuestAddress(address))
                .unwrap();
        }
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;
        vcpu.regs.rip = 0;
        vcpu.regs.rbx = address;
        vcpu.regs.rflags = 0x246;
        vcpu.regs.mm =
            std::array::from_fn(|index| 0xF0E1_D2C3_B4A5_9687u64.rotate_left(index as u32 * 7));
        if !is_load {
            vcpu.regs.mm[3] = value;
        }
        let original = vcpu.regs.mm;
        vcpu.fpu.tag_word = 0xFFFF;
        vcpu.set_jit_mem(true);
        vcpu.set_jit_call(false);

        let region = vcpu
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("compile boundary {name}: {error}"))
            .unwrap_or_else(|| panic!("exactly mapped {name} should be JIT eligible"));
        vcpu.jit_run_region_native(&region);

        if is_load {
            assert_eq!(vcpu.regs.mm[3], value, "{name}");
            assert_eq!(&vcpu.regs.mm[..3], &original[..3], "{name}");
            assert_eq!(&vcpu.regs.mm[4..], &original[4..], "{name}");
        } else {
            let mut stored = [0u8; 8];
            mem.read_slice(&mut stored[..width], GuestAddress(address))
                .unwrap();
            assert_eq!(&stored[..width], &value.to_le_bytes()[..width], "{name}");
            assert_eq!(vcpu.regs.mm, original, "{name}");
        }
        assert_eq!(vcpu.fpu.tag_word, 0, "{name}");
        assert_eq!(vcpu.regs.rflags, 0x246, "{name}");
        assert_eq!(vcpu.regs.rbx, address, "{name}");
        assert_eq!(vcpu.regs.rip, instruction.len() as u64 + 2, "{name}");
    }
}

#[test]
fn jit_faulting_mmx_scalar_memory_transfers_preserve_state_and_store_atomicity() {
    for (instruction, width, name) in [
        (&[0x0F, 0x6E, 0x1B][..], 4usize, "MOVD mm3,m32"),
        (&[0x0F, 0x7E, 0x1B][..], 4usize, "MOVD m32,mm3"),
        (&[0x48, 0x0F, 0x6E, 0x1B][..], 8usize, "MOVQ mm3,m64"),
        (&[0x48, 0x0F, 0x7E, 0x1B][..], 8usize, "MOVQ m64,mm3"),
    ] {
        let (mut vcpu, mem) = test_vcpu_with_mem();
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xC3]);
        mem.write_slice(&code, GuestAddress(0)).unwrap();
        let mapped = width / 2;
        let address = 0x10000 - mapped as u64;
        let before = vec![0xA5; mapped];
        mem.write_slice(&before, GuestAddress(address)).unwrap();
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;
        vcpu.regs.rip = 0;
        vcpu.regs.rbx = address;
        vcpu.regs.rflags = 0x8D7;
        vcpu.regs.mm =
            std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
        let original = vcpu.regs.mm;
        vcpu.fpu.tag_word = 0xFFFF;
        vcpu.set_jit_mem(true);
        vcpu.set_jit_call(false);

        let region = vcpu
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("compile faulting {name}: {error}"))
            .unwrap_or_else(|| panic!("fault-capable {name} should retain a native deopt path"));
        vcpu.jit_run_region_native(&region);

        let mut after = vec![0u8; mapped];
        mem.read_slice(&mut after, GuestAddress(address)).unwrap();
        assert_eq!(
            after, before,
            "{name} must not partially write before fault"
        );
        assert_eq!(vcpu.regs.mm, original, "{name}");
        assert_eq!(vcpu.fpu.tag_word, 0xFFFF, "{name}");
        assert_eq!(vcpu.regs.rflags, 0x8D7, "{name}");
        assert_eq!(vcpu.regs.rbx, address, "{name}");
        assert_eq!(
            vcpu.regs.rip, 0,
            "{name} fault must restart the instruction"
        );
    }
}

#[test]
fn jit_scalar_memory_helper_preserves_live_register_mmx_state() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // pand mm0,mm1; mov rax,[rbx]; jmp next; ret.
    mem.write_slice(
        &[0x0F, 0xDB, 0xC1, 0x48, 0x8B, 0x03, 0xEB, 0x00, 0xC3],
        GuestAddress(0),
    )
    .unwrap();
    let scalar = 0x0123_4567_89AB_CDEFu64;
    mem.write_slice(&scalar.to_le_bytes(), GuestAddress(0x2000))
        .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rbx = 0x2000;
    vcpu.regs.rflags = 0x246;
    vcpu.regs.mm[0] = 0xF0F0_0FF0_AA55_1234;
    vcpu.regs.mm[1] = 0x0FF0_FFFF_0F0F_FFFF;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile mixed MMX/scalar-memory region")
        .expect("scalar MMU helpers should preserve live MMX state");
    vcpu.jit_run_region_native(&region);

    assert_eq!(vcpu.regs.rax, scalar);
    assert_eq!(vcpu.regs.mm[0], 0x00F0_0FF0_0A05_1234);
    assert_eq!(vcpu.regs.mm[1], 0x0FF0_FFFF_0F0F_FFFF);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rflags, 0x246);
    assert_eq!(vcpu.regs.rip, 8);
}

#[test]
fn jit_faulting_mmx_movq_memory_helper_preserves_pre_instruction_state() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // movq mm3,[rbx]; jmp next; ret. RBX points one byte beyond guest RAM.
    mem.write_slice(&[0x0F, 0x6F, 0x1B, 0xEB, 0x00, 0xC3], GuestAddress(0))
        .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rbx = 0x10000;
    vcpu.regs.rflags = 0x8D7;
    vcpu.regs.mm =
        std::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32 * 7));
    let original = vcpu.regs.mm;
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .expect("compile faulting MMX memory region")
        .expect("fault-capable MMX MOVQ should retain a native deopt path");
    vcpu.jit_run_region_native(&region);

    assert_eq!(vcpu.regs.mm, original);
    assert_eq!(vcpu.fpu.tag_word, 0xFFFF);
    assert_eq!(vcpu.regs.rflags, 0x8D7);
    assert_eq!(vcpu.regs.rip, 0, "fault must restart the MOVQ instruction");
}

#[test]
fn jit_call_helper_round_trips_interpreter_modified_mmx_state() {
    let (mut vcpu, mem) = test_vcpu_with_mem();
    // pand mm0,mm1; call callee; pand mm0,mm2; jmp next;
    // callee: por mm0,mm3; ret; next: ret.
    mem.write_slice(
        &[
            0x0F, 0xDB, 0xC1, 0xE8, 0x05, 0x00, 0x00, 0x00, 0x0F, 0xDB, 0xC2, 0xEB, 0x04, 0x0F,
            0xEB, 0xC3, 0xC3, 0xC3,
        ],
        GuestAddress(0),
    )
    .unwrap();
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rsp = 0x8000;
    vcpu.regs.rflags = 0x202;
    vcpu.regs.mm[0] = 0xF0F0_0FF0_AA55_1234;
    vcpu.regs.mm[1] = 0x0FF0_FFFF_0F0F_FFFF;
    vcpu.regs.mm[2] = 0xFFFF_00FF_FFFF_0FF0;
    vcpu.regs.mm[3] = 0x8000_0000_5000_0001;
    let expected = ((vcpu.regs.mm[0] & vcpu.regs.mm[1]) | vcpu.regs.mm[3]) & vcpu.regs.mm[2];
    vcpu.fpu.tag_word = 0xFFFF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(true);

    let region = vcpu
        .jit_compile_region()
        .expect("compile MMX call-through region")
        .expect("MMX call-through should be JIT eligible");
    vcpu.jit_run_region_native(&region);

    assert_eq!(vcpu.regs.mm[0], expected);
    assert_eq!(vcpu.fpu.tag_word, 0);
    assert_eq!(vcpu.regs.rsp, 0x8000);
    assert_eq!(vcpu.regs.rflags, 0x202);
    assert_eq!(vcpu.regs.rip, 17);
}
