//! Closed Mach-O process adapter. Context bytes are Mach integer thread states.
use super::runtime::{Boundary, Termination};
use super::*;
use rax_engine::user::darwin::abi::DarwinAbi;
use rax_engine::user::darwin::arch::DarwinCpu;
use rax_engine::user::darwin::loader::ImageFile;
use rax_engine::user::darwin::process::Thread;
use rax_engine::user::darwin::thread_status::{self, arm, x86};
use rax_engine::user::darwin::{DarwinConfig, DarwinProcess, ExitStatus, RunStatus, SpawnError};
use rax_engine::user::mm::AddressSpace;
use serde_json::{Value, json};

pub(super) struct Process(DarwinProcess);

fn context_flavor(abi: DarwinAbi) -> (i32, u32) {
    match abi {
        DarwinAbi::X86_64 => (x86::THREAD_STATE64, x86::THREAD_STATE64_COUNT),
        DarwinAbi::Arm64 => (arm::THREAD_STATE64, arm::THREAD_STATE64_COUNT),
    }
}

impl Process {
    pub(super) fn new(mut config: DarwinConfig, image: Vec<u8>) -> Result<Self> {
        if config.abi.is_none() {
            // Deterministic selection for fat images, independent of the host.
            // A caller can explicitly select the other supported guest slice.
            use rax_engine::user::darwin::loader::choose_abi;
            use rax_engine::user::image::macho::{Identity, identify};
            let selected = match identify(&image) {
                Ok(Identity::Fat) => choose_abi(&image, Some(DarwinAbi::X86_64))
                    .or_else(|_| choose_abi(&image, Some(DarwinAbi::Arm64))),
                Ok(Identity::Thin(_)) => choose_abi(&image, None),
                Err(error) => Err(error),
            };
            config.abi = Some(selected.map_err(|e| Failure(RaxStatus::Format, e.to_string()))?);
        }
        let name = config.exec_path.clone();
        DarwinProcess::spawn(config, ImageFile::new(image, name))
            .map(Self)
            .map_err(|e| {
                let status = match &e {
                    SpawnError::Configuration(_) => RaxStatus::Arg,
                    SpawnError::Memory(_) => RaxStatus::NoMem,
                    SpawnError::Load(_) | SpawnError::Io(_, _) => RaxStatus::Format,
                };
                Failure(status, e.to_string())
            })
    }

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
        &self.0.proc.space
    }

    pub(super) fn invalidate_code(&mut self) {
        for t in self.0.proc.threads.values_mut() {
            t.cpu.discard_native_code();
        }
    }

    fn context(&self, t: &Thread) -> Result<Vec<u8>> {
        let (flavor, count) = context_flavor(self.0.proc.abi);
        let view = thread_status::View {
            cpu: &t.cpu,
            entry: &t.sig.entry,
            debug: &t.mach.debug_state,
            ptrauth: rax_engine::user::darwin::signal::frame::uses_ptrauth(&self.0.proc),
        };
        thread_status::get(&view, flavor, count)
            .map(|words| words.into_iter().flat_map(u32::to_le_bytes).collect())
            .map_err(|e| internal(format!("Darwin thread-state read: {e}")))
    }

    pub(super) fn read_context(&self, tid: u32) -> Result<Vec<u8>> {
        let t = self
            .0
            .proc
            .threads
            .get(&u64::from(tid))
            .ok_or_else(|| bad("unknown process thread"))?;
        self.context(t)
    }

    pub(super) fn write_context(&mut self, tid: u32, bytes: &[u8]) -> Result<()> {
        let (flavor, count) = context_flavor(self.0.proc.abi);
        if bytes.len() != count as usize * 4 {
            return Err(bad("incorrect Darwin THREAD_STATE64 byte size"));
        }
        let t = self
            .0
            .proc
            .threads
            .get_mut(&u64::from(tid))
            .ok_or_else(|| bad("unknown process thread"))?;
        let mut cpu = match &t.cpu {
            DarwinCpu::X86_64(cpu) => DarwinCpu::X86_64(cpu.clone_thread()),
            DarwinCpu::Arm64(cpu) => DarwinCpu::Arm64(cpu.clone_thread()),
        };
        let words: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("four bytes")))
            .collect();
        let mut debug = t.mach.debug_state.clone();
        thread_status::set(&mut cpu, &mut debug, flavor, &words)
            .map_err(|e| bad(format!("invalid Darwin THREAD_STATE64: {e}")))?;
        cpu.discard_native_code();
        // Commit only after validation. Pending syscall/exception continuations
        // and all other thread state remain owned by the personality.
        t.cpu = cpu;
        t.mach.debug_state = debug;
        Ok(())
    }

    pub(super) fn info(&self) -> Result<Value> {
        let p = &self.0.proc;
        let hx = |v: u64| format!("0x{v:x}");
        let (flavor, count) = context_flavor(p.abi);
        let mut threads = Vec::new();
        for t in p.threads.values() {
            let id = u32::try_from(t.tid).map_err(|_| {
                Failure(
                    RaxStatus::Bounds,
                    "Darwin thread ID exceeds the process context API's 32-bit range".into(),
                )
            })?;
            threads.push(json!({"id":id,"pc":hx(t.cpu.pc()),"sp":hx(t.cpu.sp()),
                "state":if t.exited {"exited"} else if t.mach.suspend_count != 0 {"suspended"} else if !t.runnable() {"waiting"} else {"ready"},
                "suspend_count":t.mach.suspend_count,"thread_port":t.port,
                "context_format":"darwin_thread_state64","context_flavor":flavor,
                "context_bytes":count * 4}));
        }
        let mappings: Vec<_> = p.space.vma_snapshot().into_iter().map(|v| json!({
            "start":hx(v.start),"end":hx(v.end),"permissions":v.perms.bits(),"name":v.name.as_deref()})).collect();
        let signal = match &p.exit {
            Some(ExitStatus::Signaled { signo, core, pc }) => {
                json!({"number":signo,"name":rax_engine::user::darwin::signal::name(*signo),"core":core,"pc":hx(*pc)})
            }
            _ => Value::Null,
        };
        Ok(json!({"schema_version":1,"personality":"darwin",
            "architecture":match p.abi { DarwinAbi::X86_64=>"x86_64", DarwinAbi::Arm64=>"aarch64" },
            "exit_code":match &p.exit {Some(ExitStatus::Exited(code))=>Some(code & 255),_=>None},
            "diagnostic":p.exit.as_ref().map(ToString::to_string),"signal":signal,
            "threads":threads,"mappings":mappings,
            "loaded_program":{"path":p.program.path,"entry":hx(p.program.entry),
                "mach_header":hx(p.program.mach_header),"has_dyld":p.program.dyld.is_some()},
            "resident_bytes":p.space.resident_pages()*4096,"memory_limit_bytes":p.config.arena_bytes,
            "capabilities":{"host_filesystem":false,"host_services":false,"captured_console":true,
                "context_format":"darwin_thread_state64","checkpoint":false}}))
    }
}
