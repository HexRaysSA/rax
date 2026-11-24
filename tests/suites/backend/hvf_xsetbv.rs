//! Host-independent execution of the actual HVF XSETBV decision/commit boundary.
#[path = "../../../src/backend/hvf/xsetbv.rs"]
mod xsetbv;
use xsetbv::{XsetbvAccess, XsetbvFault, XsetbvInput, handle_xsetbv, xsetbv_value};

fn input() -> XsetbvInput {
    XsetbvInput {
        xsave_supported: true,
        supported_xcr0: 7,
        cr0: 1,
        cr4: 1 << 18,
        rflags: 2,
        cs_selector: 8,
        rax: 7,
        rcx: 0,
        rdx: 0,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Read,
    Write(u64),
    Advance,
    Fault(XsetbvFault),
}
struct Mock {
    input: XsetbvInput,
    xcr0: u64,
    rip: u64,
    events: Vec<Event>,
    fail: Option<usize>,
}
impl Mock {
    fn new(input: XsetbvInput) -> Self {
        Self {
            input,
            xcr0: 3,
            rip: 0x1234_5678,
            events: vec![],
            fail: None,
        }
    }
    fn event(&mut self, event: Event) -> Result<(), &'static str> {
        self.events.push(event);
        if self.fail == Some(self.events.len()) {
            Err("injected host API failure")
        } else {
            Ok(())
        }
    }
}
impl XsetbvAccess for Mock {
    type Error = &'static str;
    fn input(&mut self) -> Result<XsetbvInput, Self::Error> {
        self.event(Event::Read)?;
        Ok(self.input)
    }
    fn write_xcr0(&mut self, value: u64) -> Result<(), Self::Error> {
        self.event(Event::Write(value))?;
        self.xcr0 = value;
        Ok(())
    }
    fn advance_rip(&mut self) -> Result<(), Self::Error> {
        self.event(Event::Advance)?;
        self.rip += 3;
        Ok(())
    }
    fn inject_fault(&mut self, fault: XsetbvFault) -> Result<(), Self::Error> {
        self.event(Event::Fault(fault))
    }
}

#[test]
fn successful_exit_commits_xcr0_before_advancing() {
    for value in [1, 3, 7] {
        let mut state = input();
        state.rax = value;
        let mut io = Mock::new(state);
        handle_xsetbv(&mut io).unwrap();
        assert_eq!(io.xcr0, value);
        assert_eq!(io.rip, 0x1234_567b);
        assert_eq!(
            io.events,
            [Event::Read, Event::Write(value), Event::Advance]
        );
    }
}

#[test]
fn unsupported_or_disabled_xsave_faults_before_contents_and_privilege() {
    for supported in [false, true] {
        for enabled in [false, true] {
            for cpl in 0..4 {
                let mut state = input();
                state.xsave_supported = supported;
                state.cr4 = if enabled { 1 << 18 } else { 0 };
                state.cs_selector = 8 | cpl;
                state.rcx = 0xffff_ffff;
                state.rax = 0;
                let expected = if !supported || !enabled {
                    XsetbvFault::UndefinedOpcode
                } else {
                    XsetbvFault::GeneralProtection
                };
                let mut io = Mock::new(state);
                handle_xsetbv(&mut io).unwrap();
                assert_eq!(io.events, [Event::Read, Event::Fault(expected)]);
                assert_eq!((io.xcr0, io.rip), (3, 0x1234_5678));
            }
        }
    }
}

#[test]
fn privilege_and_virtual8086_faults_preserve_instruction_boundary() {
    for cpl in 0..4 {
        for vm in [false, true] {
            let mut state = input();
            state.cs_selector = 8 | cpl;
            state.rflags |= if vm { 1 << 17 } else { 0 };
            let mut io = Mock::new(state);
            handle_xsetbv(&mut io).unwrap();
            if cpl != 0 || vm {
                assert_eq!(
                    io.events,
                    [Event::Read, Event::Fault(XsetbvFault::GeneralProtection)]
                );
                assert_eq!((io.xcr0, io.rip), (3, 0x1234_5678));
            } else {
                assert_eq!(io.xcr0, 7);
            }
        }
    }
    let mut state = input();
    state.cr0 = 0;
    state.cs_selector = 0xffff;
    assert_eq!(xsetbv_value(state), Ok(7));
}

#[test]
fn all_profile_values_and_each_reserved_bit_have_exact_faults() {
    for value in 0..256 {
        let mut state = input();
        state.rax = value;
        let expected = match value {
            1 | 3 | 7 => Ok(value),
            _ => Err(XsetbvFault::GeneralProtection),
        };
        assert_eq!(xsetbv_value(state), expected, "value={value:x}");
    }
    for bit in 3..64 {
        let value = 7 | (1u64 << bit);
        let mut state = input();
        state.rax = value as u32 as u64;
        state.rdx = value >> 32;
        assert_eq!(
            xsetbv_value(state),
            Err(XsetbvFault::GeneralProtection),
            "bit={bit}"
        );
    }
    for index in [1, 2, 0x8000_0000, 0xffff_ffff] {
        let mut state = input();
        state.rcx = index;
        assert_eq!(xsetbv_value(state), Err(XsetbvFault::GeneralProtection));
    }
}

#[test]
fn upper_gpr_halves_are_ignored_without_changing_inputs() {
    for high in [0, 1, 0x8000_0000, 0xffff_ffff] {
        let mut state = input();
        state.rax |= high << 32;
        state.rcx = high << 32;
        state.rdx = high << 32;
        assert_eq!(xsetbv_value(state), Ok(7));
    }
}

#[test]
fn component_dependencies_hold_for_mpx_avx512_and_amx() {
    let mut state = input();
    state.supported_xcr0 = 7 | 0x18 | 0xe0 | (3 << 17);
    for mpx in 0..4 {
        for avx512 in 0..8 {
            for amx in 0..4 {
                let value = 7 | (mpx << 3) | (avx512 << 5) | (amx << 17);
                state.rax = value;
                let valid = (mpx == 0 || mpx == 3)
                    && (avx512 == 0 || avx512 == 7)
                    && (amx == 0 || amx == 3);
                assert_eq!(xsetbv_value(state).is_ok(), valid, "value={value:x}");
            }
        }
    }
    state.rax = 1 | 0xe0;
    assert_eq!(xsetbv_value(state), Err(XsetbvFault::GeneralProtection));
}

#[test]
fn host_api_failures_do_not_fabricate_retirement_or_swallow_errors() {
    for fail in 1..=3 {
        let mut io = Mock::new(input());
        io.fail = Some(fail);
        assert_eq!(handle_xsetbv(&mut io), Err("injected host API failure"));
        assert_eq!(io.events.len(), fail);
        assert_eq!(io.rip, 0x1234_5678);
        assert_eq!(io.xcr0, if fail <= 2 { 3 } else { 7 });
    }
    let mut state = input();
    state.rax = 0;
    let mut io = Mock::new(state);
    io.fail = Some(2);
    assert_eq!(handle_xsetbv(&mut io), Err("injected host API failure"));
    assert_eq!((io.xcr0, io.rip), (3, 0x1234_5678));
}

#[test]
fn cpuid_osxsave_tracks_control_state_and_xsave_capability() {
    for available in [false, true] {
        for enabled in [false, true] {
            let reply = (
                0x1234,
                0x5678,
                (1 << 27) | if available { 1 << 26 } else { 0 },
                0x9abc,
            );
            let got = xsetbv::xsave_cpuid(1, 17, reply, if enabled { 1 << 18 } else { 0 }, 7);
            assert_eq!(got.2 & (1 << 27) != 0, available && enabled);
            assert_eq!((got.0, got.1, got.3), (reply.0, reply.1, reply.3));
            assert_eq!(got.2 & !(1 << 27), reply.2 & !(1 << 27));
        }
    }
}

#[test]
fn cpuid_standard_xsave_size_tracks_enabled_avx_and_preserves_capabilities() {
    for (xcr0, bytes) in [(1, 576), (3, 576), (7, 832)] {
        assert_eq!(
            xsetbv::xsave_cpuid(0x0d, 0, (7, 832, 832, 0), 1 << 18, xcr0),
            (7, bytes, 832, 0)
        );
    }
    assert_eq!(
        xsetbv::xsave_cpuid(0x0d, 2, (256, 576, 0, 0), 0, 0),
        (256, 576, 0, 0)
    );
    assert_eq!(xsetbv::xsave_cpuid(7, 0, (1, 2, 3, 4), 0, 0), (1, 2, 3, 4));
}

#[test]
fn hardware_fault_injection_uses_the_error_code_for_the_guest_mode() {
    for protected_mode in [false, true] {
        assert_eq!(
            XsetbvFault::UndefinedOpcode.injection(protected_mode),
            (0x8000_0306, None)
        );
    }
    assert_eq!(
        XsetbvFault::GeneralProtection.injection(true),
        (0x8000_0b0d, Some(0))
    );
    assert_eq!(
        XsetbvFault::GeneralProtection.injection(false),
        (0x8000_030d, None)
    );
}
