//! Initial-stack layout. The expected addresses are derived by hand from
//! `copy_strings` and `create_elf_tables` (Linux 6.19) for a fixed input.

use crate::user::linux::abi::{DEFAULT_STACK_LIMIT, LinuxAbi, vma_flags};
use crate::user::linux::stack::{
    AuxInfo, RSEQ_ALIGN, RSEQ_FEATURE_SIZE, StackError, USER_HZ, at, map_stack, write_initial_stack,
};
use crate::user::mm::{AddressSpace, SpaceConfig};

fn aux(platform: Option<&'static str>, hwcap2: Option<u64>) -> AuxInfo {
    AuxInfo {
        phdr: 0x400040,
        phent: 56,
        phnum: 9,
        base: 0x7fff_f7fc_0000,
        entry: 0x401000,
        uid: (1000, 1001),
        gid: (100, 101),
        secure: false,
        hwcap: 0xabcd,
        hwcap2,
        platform,
        minsigstksz: 3216,
        vdso: None,
    }
}

fn build(
    abi: LinuxAbi,
    argv: &[&str],
    envp: &[&str],
    execfn: &str,
    a: &AuxInfo,
) -> (AddressSpace, crate::user::linux::stack::InitialStack) {
    let s = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 64 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    map_stack(abi, &s, DEFAULT_STACK_LIMIT, false).unwrap();
    let argv: Vec<Vec<u8>> = argv.iter().map(|x| x.as_bytes().to_vec()).collect();
    let envp: Vec<Vec<u8>> = envp.iter().map(|x| x.as_bytes().to_vec()).collect();
    let st = write_initial_stack(
        abi,
        &s,
        DEFAULT_STACK_LIMIT,
        &argv,
        &envp,
        execfn.as_bytes(),
        a,
        [0x11; 16],
    )
    .unwrap();
    (s, st)
}

fn u64_at(s: &AddressSpace, a: u64) -> u64 {
    let mut b = [0u8; 8];
    s.read(a, &mut b).unwrap();
    u64::from_le_bytes(b)
}

fn cstr_at(s: &AddressSpace, a: u64) -> String {
    String::from_utf8(s.read_cstr(a, 4096).unwrap().unwrap()).unwrap()
}

#[test]
fn x86_64_layout_matches_create_elf_tables() {
    let a = aux(Some("x86_64"), Some(2));
    let (s, st) = build(LinuxAbi::X86_64, &["a"], &["B=1"], "/x", &a);
    // bprm->p = 0x7ffffffff000 - 8 = 0x7fffffffeff8.
    // "/x\0" -> 0x7fffffffeff5; "B=1\0" -> 0x7fffffffeff1; "a\0" -> 0x7fffffffefef.
    assert_eq!(st.execfn, 0x7fff_ffff_eff5);
    assert_eq!(st.env_start, 0x7fff_ffff_eff1);
    assert_eq!(st.arg_start, 0x7fff_ffff_efef);
    assert_eq!(st.arg_end, st.env_start);
    assert_eq!(st.env_end, st.execfn);
    // arch_align_stack: 0x7fffffffefe0; "x86_64\0" -> 0x7fffffffefd9;
    // AT_RANDOM -> 0x7fffffffefc9.
    assert_eq!(st.random, 0x7fff_ffff_efc9);
    // auxv: AT_MINSIGSTKSZ + 15 generic + HWCAP2 + EXECFN + PLATFORM + two
    // RSEQ entries + AT_NULL = 22 pairs; items = 2 + 2 + 1 = 5 words.
    assert_eq!(st.auxv.len(), 22);
    // sp = (0x7fffffffefc9 - 22*16 - 5*8) & ~15 = 0x7fffffffee40.
    assert_eq!(st.sp, 0x7fff_ffff_ee40);
    assert_eq!(u64_at(&s, 0x7fff_ffff_eff8), 0, "the top 8 bytes are zero");
    // setup_arg_pages(): the stack VMA is VM_GROWSDOWN and ends at the top.
    let vma = s.vma_at(st.sp).unwrap();
    assert_eq!(vma.flags & vma_flags::GROWSDOWN, vma_flags::GROWSDOWN);
    assert_eq!(vma.end, LinuxAbi::X86_64.stack_top());
    assert_eq!(vma.name.as_deref(), Some("[stack]"));
    assert_eq!(cstr_at(&s, st.execfn), "/x");
    assert_eq!(cstr_at(&s, 0x7fff_ffff_efd9), "x86_64");
    let mut rnd = [0u8; 16];
    s.read(st.random, &mut rnd).unwrap();
    assert_eq!(rnd, [0x11; 16]);

    // argc, argv[], NULL, envp[], NULL, auxv.
    assert_eq!(u64_at(&s, st.sp), 1);
    assert_eq!(u64_at(&s, st.sp + 8), st.arg_start);
    assert_eq!(u64_at(&s, st.sp + 16), 0);
    assert_eq!(u64_at(&s, st.sp + 24), st.env_start);
    assert_eq!(u64_at(&s, st.sp + 32), 0);
    let mut words = Vec::new();
    for i in 0..44 {
        words.push(u64_at(&s, st.sp + 40 + i * 8));
    }
    let pairs: Vec<(u64, u64)> = words.chunks(2).map(|p| (p[0], p[1])).collect();
    assert_eq!(pairs, st.auxv);
    use at::*;
    assert_eq!(
        pairs,
        vec![
            (AT_MINSIGSTKSZ, 3216),
            (AT_HWCAP, 0xabcd),
            (AT_PAGESZ, 4096),
            (AT_CLKTCK, USER_HZ),
            (AT_PHDR, 0x400040),
            (AT_PHENT, 56),
            (AT_PHNUM, 9),
            (AT_BASE, 0x7fff_f7fc_0000),
            (AT_FLAGS, 0),
            (AT_ENTRY, 0x401000),
            (AT_UID, 1000),
            (AT_EUID, 1001),
            (AT_GID, 100),
            (AT_EGID, 101),
            (AT_SECURE, 0),
            (AT_RANDOM, st.random),
            (AT_HWCAP2, 2),
            (AT_EXECFN, st.execfn),
            (AT_PLATFORM, 0x7fff_ffff_efd9),
            (AT_RSEQ_FEATURE_SIZE, RSEQ_FEATURE_SIZE),
            (AT_RSEQ_ALIGN, RSEQ_ALIGN),
            (AT_NULL, 0),
        ]
    );
}

#[test]
fn string_order_and_alignment_hold_for_many_arguments() {
    let argv: Vec<String> = (0..50)
        .map(|i| format!("arg-{i}-{}", "x".repeat(i)))
        .collect();
    let envp: Vec<String> = (0..30).map(|i| format!("V{i}={i}")).collect();
    let argv_ref: Vec<&str> = argv.iter().map(String::as_str).collect();
    let envp_ref: Vec<&str> = envp.iter().map(String::as_str).collect();
    let a = aux(Some("aarch64"), Some(0));
    let (s, st) = build(LinuxAbi::Aarch64, &argv_ref, &envp_ref, "/bin/prog", &a);
    assert_eq!(st.sp % 16, 0);
    assert_eq!(u64_at(&s, st.sp), 50);
    let mut prev = 0;
    for (i, want) in argv.iter().enumerate() {
        let p = u64_at(&s, st.sp + 8 + 8 * i as u64);
        assert!(p > prev, "argv strings ascend in memory");
        prev = p;
        assert_eq!(&cstr_at(&s, p), want);
    }
    assert_eq!(u64_at(&s, st.sp + 8 + 8 * 50), 0);
    let env_base = st.sp + 8 + 8 * 51;
    for (i, want) in envp.iter().enumerate() {
        assert_eq!(&cstr_at(&s, u64_at(&s, env_base + 8 * i as u64)), want);
    }
    assert_eq!(u64_at(&s, env_base + 8 * 30), 0);
    assert_eq!(st.arg_start, u64_at(&s, st.sp + 8));
    assert_eq!(cstr_at(&s, st.execfn), "/bin/prog");
}

#[test]
fn riscv_has_cache_entries_and_no_platform() {
    let a = aux(None, None);
    let (_, st) = build(LinuxAbi::Riscv64, &["p"], &[], "p", &a);
    let tags: Vec<u64> = st.auxv.iter().map(|&(t, _)| t).collect();
    use at::*;
    // ARCH_DLINFO: eight cache entries, then AT_MINSIGSTKSZ.
    assert_eq!(
        &tags[..9],
        &[
            AT_L1I_CACHESIZE,
            AT_L1I_CACHEGEOMETRY,
            AT_L1D_CACHESIZE,
            AT_L1D_CACHEGEOMETRY,
            AT_L2_CACHESIZE,
            AT_L2_CACHEGEOMETRY,
            AT_L3_CACHESIZE,
            AT_L3_CACHEGEOMETRY,
            AT_MINSIGSTKSZ
        ]
    );
    assert!(!tags.contains(&AT_PLATFORM));
    assert!(!tags.contains(&AT_HWCAP2));
    assert_eq!(*tags.last().unwrap(), AT_NULL);
}

#[test]
fn oversized_arguments_are_e2big() {
    let big = "y".repeat(3 << 20);
    let s = AddressSpace::new(SpaceConfig {
        va_limit: LinuxAbi::X86_64.task_size(),
        arena_bytes: 64 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    map_stack(LinuxAbi::X86_64, &s, DEFAULT_STACK_LIMIT, false).unwrap();
    let err = write_initial_stack(
        LinuxAbi::X86_64,
        &s,
        DEFAULT_STACK_LIMIT,
        &[big.into_bytes()],
        &[],
        b"p",
        &aux(None, None),
        [0; 16],
    )
    .unwrap_err();
    assert!(matches!(err, StackError::TooBig));
}
