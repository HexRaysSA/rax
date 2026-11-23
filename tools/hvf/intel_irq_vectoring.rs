//! Native IRQ delivery interrupted by an EPT violation on the IDT gate.
use super::*;
use rax::devices::{
    bus::{IoDevice, MmioDevice},
    pci::{Bar, ConfigSpace, PciStub},
};
use std::sync::Mutex;

const IDT: u64 = 0xc000;
const HANDLER: u64 = 0x1_2000;
const VECTOR: u8 = 0x40;
const GATE: u64 = IDT + 16 * VECTOR as u64;
const START_PORT: u16 = 0x80;

struct GatePageBar;

impl MmioDevice for GatePageBar {
    fn read(&mut self, _: u64, _: &mut [u8]) {
        panic!("an IDT gate read reached the BAR handler");
    }

    fn write(&mut self, _: u64, _: &[u8]) {
        panic!("an event delivery write reached the BAR handler");
    }
}

fn covered_idt() -> Arc<Mutex<PciStub>> {
    let mut pci = PciStub::new();
    let mut config =
        ConfigSpace::device(0x1234, 0x1234, 0xff_00_00, 0).with_bar(0, Bar::mem32(0x1000));
    config.set_u16(4, 2); // Enable memory decoding.
    config.set_u32(0x10, IDT as u32);
    pci.attach_mmio(0, 1, 0, config, 0, Box::new(GatePageBar));
    assert_eq!(pci.mmio_ranges()[0].base, IDT);
    Arc::new(Mutex::new(pci))
}

fn expose_idt(pci: &Mutex<PciStub>) {
    let mut pci = pci.lock().unwrap();
    for (offset, byte) in 0x8000_0804u32.to_le_bytes().into_iter().enumerate() {
        pci.write(0xcf8 + offset as u16, byte);
    }
    pci.write(0xcfc, 0); // Clear PCI COMMAND.MEMORY on bus 0, device 1.
    assert!(pci.mmio_ranges().is_empty());
}

fn machine(memory: &GuestMemoryWrapper, pci: &Arc<Mutex<PciStub>>) -> (Box<dyn Vm>, Box<dyn VCpu>) {
    let vm = HvfBackend::new().unwrap().create_vm().unwrap();
    vm.as_any()
        .downcast_ref::<HvfVm>()
        .unwrap()
        .register_memory_with_mmio(memory, &[], Some(pci.clone()))
        .unwrap();
    vm.configure_cpu_topology(1, RAM).unwrap();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    (vm, cpu)
}

fn enter(cpu: &mut dyn VCpu) -> rax::error::Result<VcpuExit> {
    for _ in 0..50 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100))? {
            return Ok(exit);
        }
    }
    Err(rax::error::Error::Emulator(
        "IRQ vectoring probe exhausted 50 host slices".into(),
    ))
}

fn trial(output: &Path, case: usize, recreate: bool) {
    let memory = guest_memory(&[0xe6, START_PORT as u8]); // OUT 0x80,AL
    word(
        &memory,
        GATE,
        (HANDLER & 0xffff) | (8 << 16) | (0x8e << 40) | ((HANDLER & 0xffff_0000) << 32),
    );
    word(&memory, GATE + 8, HANDLER >> 32);
    // INC R11; IRETQ.
    memory
        .memory()
        .write_slice(&[0x49, 0xff, 0xc3, 0x48, 0xcf], GuestAddress(HANDLER))
        .unwrap();

    let mut pci = covered_idt();
    let (mut vm, mut cpu) = machine(&memory, &pci);
    let CpuState::X86_64(mut initial) = initial() else {
        unreachable!()
    };
    initial.sregs.idt.base = IDT;
    initial.sregs.idt.limit = 0x0fff;
    initial.regs.rflags = 0x202;
    cpu.set_state(&CpuState::X86_64(initial)).unwrap();
    eprintln!("IRQ vectoring case {case}: enter to the port marker");
    assert!(matches!(
        enter(cpu.as_mut()).unwrap(),
        VcpuExit::IoOut {
            port: START_PORT,
            ..
        }
    ));
    cpu.complete_io_out().unwrap();
    assert!(cpu.inject_interrupt(VECTOR).unwrap());
    let before = state(cpu.as_ref()).regs;
    eprintln!("IRQ vectoring case {case}: deliver to the covered gate");
    let error = enter(cpu.as_mut()).unwrap_err().to_string();
    assert!(error.contains("event retained for retry"), "{error}");
    let gpa_hex = error
        .split("EPT GPA 0x")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let gpa = u64::from_str_radix(gpa_hex, 16).unwrap();
    assert!((GATE..GATE + 16).contains(&gpa), "EPT GPA {gpa:#x}");
    let stopped = state(cpu.as_ref()).regs;
    assert_eq!(
        (stopped.rip, stopped.rsp, stopped.r11),
        (before.rip, before.rsp, 0)
    );
    assert_eq!(enter(cpu.as_mut()).unwrap_err().to_string(), error);
    assert!(!cpu.inject_interrupt(VECTOR + 1).unwrap());

    if recreate {
        let (saved, context) = {
            let boundary = vm.checkpoint_boundary().unwrap();
            cpu.capture_checkpoint_record(&boundary, None).unwrap()
        };
        assert!(context.is_some());
        drop(cpu);
        drop(vm);
        pci = covered_idt();
        (vm, cpu) = machine(&memory, &pci);
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
            .unwrap();
        let restored = state(cpu.as_ref()).regs;
        assert_eq!(
            (restored.rip, restored.rsp, restored.rflags, restored.r11),
            (stopped.rip, stopped.rsp, stopped.rflags, stopped.r11)
        );
        assert!(!cpu.inject_interrupt(VECTOR + 1).unwrap());
    }
    expose_idt(&pci);
    eprintln!("IRQ vectoring case {case}: repaired gate and resume");
    assert!(matches!(enter(cpu.as_mut()).unwrap(), VcpuExit::Hlt));
    let after = state(cpu.as_ref()).regs;
    assert_eq!((after.rip, after.rsp), (CODE + 13, before.rsp));
    assert_eq!(
        (after.r10, after.r11, after.rflags),
        (MARKER, 1, before.rflags)
    );
    drop(cpu);
    drop(vm);

    writeln!(
        OpenOptions::new().append(true).create(true).open(output).unwrap(),
        "{{\"case\":{case},\"name\":\"irq-vectoring\",\"gpa\":{gpa},\"fresh_owner\":{recreate},\"stopped_rip\":{},\"stopped_rsp\":{},\"resumed_rip\":{},\"resumed_rsp\":{},\"handler_visits\":{},\"passed\":true}}",
        stopped.rip, stopped.rsp, after.rip, after.rsp, after.r11,
    ).unwrap();
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    for (case, recreate) in [false, true].into_iter().enumerate() {
        trial(output, case, recreate);
    }
    println!("{{\"cases\":2,\"failed\":0,\"guest_execution_performed\":true}}");
}
