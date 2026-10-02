//! Closed ELF process adapter. Register images use the guest Linux UAPI.
use super::runtime::{Boundary, Termination};
use super::*;
use rax_engine::user::linux::{ExitStatus, LinuxConfig, LinuxProcess, RunStatus, SpawnError};
use rax_engine::user::linux::{
    abi::LinuxAbi,
    loader::ImageFile,
    process::Thread,
    ptrace::{regs, regs_a32},
};
use rax_engine::user::mm::AddressSpace;
use serde_json::{Value, json};

pub(super) struct Process(LinuxProcess);

impl Process {
    pub(super) fn new(config: LinuxConfig, image: Vec<u8>) -> Result<Self> {
        let name = config.exec_path.clone();
        LinuxProcess::spawn(config, ImageFile::new(image, name))
            .map(Self)
            .map_err(|e| {
                let status = match &e {
                    SpawnError::Unsupported(_) => RaxStatus::Unsupported,
                    SpawnError::Memory(_) => RaxStatus::NoMem,
                    SpawnError::Load(_) | SpawnError::Stack(_) => RaxStatus::Format,
                };
                Failure(status, e.to_string())
            })
    }
    // The shared worker budget/cancellation loop uses this normalized outcome.
    // Signal details remain in LinuxProcess::state.exit and the JSON inspection.
    pub(super) fn run_slice(&mut self, cancelled: &AtomicBool) -> Boundary {
        match self.0.run_slice(1, cancelled) {
            RunStatus::BudgetExhausted => Boundary::BudgetExhausted,
            RunStatus::Blocked => Boundary::Blocked,
            RunStatus::Cancelled => Boundary::Cancelled,
            RunStatus::Complete(status) => Boundary::Complete(Termination {
                code: match &status {
                    ExitStatus::Exited(code) => Some((code & 255) as u32),
                    _ => None,
                },
                diagnostic: status.to_string(),
            }),
        }
    }
    pub(super) fn space(&self) -> &AddressSpace {
        self.0.space()
    }
    pub(super) fn invalidate_code(&mut self) {
        for t in &mut self.0.threads {
            t.cpu.discard_native_code();
        }
    }
    fn context(t: &Thread) -> Result<Vec<u8>> {
        if t.cpu.abi() == LinuxAbi::Arm {
            Ok(regs_a32::gregs(&t.cpu, t.syscall))
        } else {
            regs::get(&t.cpu, t.syscall, regs::NT_PRSTATUS)
                .map_err(|e| internal(format!("Linux register read: {e}")))
        }
    }
    pub(super) fn read_context(&self, tid: u32) -> Result<Vec<u8>> {
        let t = self
            .0
            .threads
            .iter()
            .find(|t| t.tid as u32 == tid)
            .ok_or_else(|| bad("unknown process thread"))?;
        Self::context(t)
    }
    pub(super) fn write_context(&mut self, tid: u32, bytes: &[u8]) -> Result<()> {
        let t = self
            .0
            .threads
            .iter_mut()
            .find(|t| t.tid as u32 == tid)
            .ok_or_else(|| bad("unknown process thread"))?;
        if bytes.len() != Self::context(t)?.len() {
            return Err(bad("incorrect Linux NT_PRSTATUS byte size"));
        }
        // Some Linux regset decoders can modify a prefix before rejecting a
        // later selector. Keep both CPU and syscall-entry changes transactional.
        let mut cpu = t.cpu.clone_thread();
        let mut syscall = t.syscall;
        let applied = if cpu.abi() == LinuxAbi::Arm {
            regs_a32::set_gregs(&mut cpu, &mut syscall, 0, bytes)
        } else {
            regs::set(&mut cpu, &mut syscall, regs::NT_PRSTATUS, bytes)
        };
        applied.map_err(|e| bad(format!("invalid Linux NT_PRSTATUS: {e}")))?;
        cpu.discard_native_code();
        t.cpu = cpu;
        t.syscall = syscall;
        Ok(())
    }
    pub(super) fn info(&self) -> Result<Value> {
        let p = &self.0.state;
        let hx = |v: u64| format!("0x{v:x}");
        let mut threads = Vec::new();
        for t in &self.0.threads {
            threads.push(json!({"id":t.tid,"pc":hx(t.cpu.pc()),"sp":hx(t.cpu.sp()),
                "state":if t.ptrace.as_ref().is_some_and(|p| p.stopped()) {"stopped"} else if t.blocked.is_some() {"waiting"} else {"ready"},
                "context_format":"linux_prstatus","context_bytes":Self::context(t)?.len()}));
        }
        let mappings: Vec<_> = p.space.vma_snapshot().into_iter().map(|v| json!({"start":hx(v.start),"end":hx(v.end),"permissions":v.perms.bits(),"name":v.name.as_deref()})).collect();
        let architecture = match p.abi {
            LinuxAbi::X86_64 => "x86_64",
            LinuxAbi::I386 => "x86",
            LinuxAbi::Aarch64 => "aarch64",
            LinuxAbi::Arm => "arm",
            LinuxAbi::Riscv64 => "riscv64",
        };
        let signal = match &p.exit {
            Some(ExitStatus::Signaled { info, pc, core }) => {
                use rax_engine::user::linux::signal::{code::SI_KERNEL, si_code_name, signal_name};
                json!({"number":info.signo,"name":signal_name(info.signo),"code":info.code,
                    "code_name":si_code_name(info.signo, info.code),"pc":hx(*pc),
                    "address":if info.code > 0 && info.code != SI_KERNEL {Some(hx(info.addr()))} else {None},"core":core})
            }
            _ => Value::Null,
        };
        Ok(
            json!({"schema_version":1,"personality":"linux","architecture":architecture,
            "exit_code":match &p.exit {Some(ExitStatus::Exited(code))=>Some(code & 255),_=>None},
            "diagnostic":p.exit.as_ref().map(ToString::to_string),"signal":signal,"threads":threads,"mappings":mappings,
            "loaded_program":{"path":p.exe_path,"entry":hx(p.mm.program.program_entry),"load_bias":hx(p.mm.program.load_bias),"interpreter_base":hx(p.mm.program.interp_base)},
            "resident_bytes":p.space.resident_pages()*4096,"memory_limit_bytes":p.config.arena_bytes,
            "capabilities":{"host_filesystem":false,"host_services":false,"captured_console":true,"context_format":"linux_prstatus","checkpoint":false}}),
        )
    }
}
