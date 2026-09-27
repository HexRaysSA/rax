use super::*;
use crate::error::MemoryAccessKind;
use crate::isa::x86_64::X86UserEvent;
use crate::user::cpu::AccessFault;
use crate::user::darwin::abi::DarwinAbi;

fn fault(kind: AccessFaultKind) -> Exception {
    Exception::Access(AccessFault {
        addr: 0x1234,
        access: MemoryAccessKind::Write,
        kind,
        pc: 0,
    })
}

fn x86(vector: u8, source: X86EventSource) -> Exception {
    Exception::X86(X86UserEvent {
        vector,
        error_code: None,
        source,
        insn_rip: 0,
        return_rip: 0,
    })
}

#[test]
fn exceptions_translate_as_ux_exception_does() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let sig = |e: &Exception| exception_signal(abi, e);
        // KERN_INVALID_ADDRESS is SIGSEGV; every other bad access SIGBUS.
        assert_eq!(sig(&fault(AccessFaultKind::Unmapped)), SIGSEGV);
        assert_eq!(sig(&fault(AccessFaultKind::Permission)), SIGBUS);
        assert_eq!(sig(&fault(AccessFaultKind::Alignment)), SIGBUS);
        assert_eq!(sig(&fault(AccessFaultKind::Bus)), SIGBUS);
        assert_eq!(
            sig(&Exception::Undefined {
                pc: 0,
                reason: String::new()
            }),
            SIGILL
        );
        assert_eq!(sig(&Exception::Breakpoint { pc: 0, imm: 1 }), SIGTRAP);
    }
    let sig = |v, s| exception_signal(DarwinAbi::X86_64, &x86(v, s));
    use X86EventSource::{Exception as Ex, SoftwareInterrupt as Soft};
    assert_eq!(sig(0, Ex), SIGFPE); // #DE
    assert_eq!(sig(1, Ex), SIGTRAP); // #DB
    assert_eq!(sig(3, Ex), SIGTRAP); // #BP
    assert_eq!(sig(5, Ex), SIGTRAP); // #BR: EXC_SOFTWARE/EXC_I386_BOUND
    assert_eq!(sig(6, Ex), SIGILL); // #UD
    assert_eq!(sig(11, Ex), SIGILL); // #NP
    assert_eq!(sig(12, Ex), SIGILL); // #SS
    assert_eq!(sig(13, Ex), SIGSEGV); // #GP: EXC_BAD_ACCESS/EXC_I386_GPFLT
    assert_eq!(sig(16, Ex), SIGFPE); // #MF
    assert_eq!(sig(19, Ex), SIGFPE); // #XM
    assert_eq!(sig(0x80, Soft), SIGSEGV); // INT n without a user gate
    // EXC_SYSCALL (an invalid system call class or trap number).
    assert_eq!(ux_exception(DarwinAbi::Arm64, exc::SYSCALL, 0x1234), SIGSYS);
    // The machine hook of one architecture is not the other's.
    assert_eq!(
        ux_exception(DarwinAbi::Arm64, exc::BAD_ACCESS, exc::I386_GPFLT),
        SIGBUS
    );
}

#[test]
fn mach_exception_codes() {
    assert_eq!(
        mach_exception(&fault(AccessFaultKind::Unmapped)),
        (exc::BAD_ACCESS, exc::KERN_INVALID_ADDRESS, 0x1234)
    );
    assert_eq!(
        mach_exception(&fault(AccessFaultKind::Permission)),
        (exc::BAD_ACCESS, exc::KERN_PROTECTION_FAILURE, 0x1234)
    );
    assert_eq!(
        mach_exception(&fault(AccessFaultKind::Alignment)).1,
        exc::ARM_DA_ALIGN
    );
    assert_eq!(
        mach_exception(&x86(0, X86EventSource::Exception)),
        (exc::ARITHMETIC, 1, 0)
    );
    assert_eq!(
        mach_exception(&x86(6, X86EventSource::Exception)),
        (exc::BAD_INSTRUCTION, 1, 0)
    );
}

#[test]
fn exception_state_of_a_data_abort() {
    let e = entry_state(&fault(AccessFaultKind::Unmapped));
    // EC 0x24 (data abort from EL0), IL, WnR, level-3 translation fault.
    assert_eq!(e.esr, (0x24 << 26) | (1 << 25) | (1 << 6) | 0x07);
    assert_eq!(e.far, 0x1234);
    // Page fault: not present, write, user.
    assert_eq!((e.trapno, e.err), (14, 0b110));
    let p = entry_state(&fault(AccessFaultKind::Permission));
    assert_eq!(p.err, 0b111);
    assert_eq!(p.esr & 0x3f, 0x0f);
}

#[test]
fn signal_properties_follow_sigprop() {
    assert_eq!(default_action(SIGSEGV), DefaultAction::Core);
    assert_eq!(default_action(SIGTERM), DefaultAction::Kill);
    // Unlike other BSDs, XNU's SIGXCPU and SIGXFSZ do not dump core.
    assert_eq!(default_action(SIGXCPU), DefaultAction::Kill);
    assert_eq!(default_action(SIGXFSZ), DefaultAction::Kill);
    assert_eq!(default_action(SIGCHLD), DefaultAction::Ignore);
    assert_eq!(default_action(SIGTSTP), DefaultAction::Stop);
    assert_eq!(default_action(SIGCONT), DefaultAction::Continue);
    assert_eq!(name(SIGUSR2), "SIGUSR2");
    assert_eq!(name(40), "signal 40");
    assert_eq!(CANTMASK, 0x0001_0100);
}

#[test]
fn siginit_ignores_default_ignored_signals_but_sigcont() {
    let acts = SigActs::default();
    for s in [SIGURG, SIGCHLD, SIGIO, SIGWINCH, SIGINFO] {
        assert_ne!(acts.ignore & bit(s), 0, "{}", name(s));
    }
    assert_eq!(acts.ignore & bit(SIGCONT), 0);
    assert_eq!(acts.ignore & bit(SIGTERM), 0);
    // A never-set action restarts calls.
    assert_ne!(acts.get(SIGALRM).flags & sa::RESTART, 0);
}

#[test]
fn setsigvec_and_the_reported_action() {
    let mut acts = SigActs::default();
    let handler = SigAction {
        handler: 0x1000,
        tramp: 0x2000,
        mask: bit(SIGUSR2) | CANTMASK,
        flags: sa::SIGINFO | sa::RESETHAND | sa::NODEFER | sa::ONSTACK,
    };
    assert!(!acts.set(SIGUSR1, &handler));
    let got = acts.get(SIGUSR1);
    assert_eq!(got.handler, 0x1000);
    assert_eq!(
        got.mask,
        bit(SIGUSR2),
        "SIGKILL and SIGSTOP cannot be masked"
    );
    // SA_RESETHAND is kept but not reported; no SA_RESTART means EINTR.
    assert_eq!(got.flags, sa::SIGINFO | sa::NODEFER | sa::ONSTACK);
    assert_ne!(acts.reset & bit(SIGUSR1), 0);
    assert_ne!(acts.intr & bit(SIGUSR1), 0);
    assert_ne!(acts.catch & bit(SIGUSR1), 0);
    // SIG_IGN, or SIG_DFL for a default-ignored signal, discards.
    let ign = SigAction {
        handler: SIG_IGN,
        ..Default::default()
    };
    assert!(acts.set(SIGUSR1, &ign));
    assert_ne!(acts.ignore & bit(SIGUSR1), 0);
    assert_eq!(acts.catch & bit(SIGUSR1), 0);
    assert!(acts.set(SIGWINCH, &SigAction::default()));
    // SIGCONT is never in the ignored set.
    assert!(acts.set(SIGCONT, &ign));
    assert_eq!(acts.ignore & bit(SIGCONT), 0);
    // SIGCHLD's process flags.
    acts.set(
        SIGCHLD,
        &SigAction {
            handler: 0x1000,
            flags: sa::NOCLDSTOP,
            ..Default::default()
        },
    );
    assert!(acts.nocldstop && !acts.nocldwait);
    acts.set(SIGCHLD, &ign);
    assert!(acts.nocldwait);
    assert_eq!(acts.get(SIGCHLD).flags & sa::NOCLDWAIT, sa::NOCLDWAIT);
}
