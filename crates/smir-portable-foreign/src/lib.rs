//! A processor for the foreign code of Portable SMIR programs.
//!
//! A program may call machine code of another processor through bridges
//! (chapter 07 of the specification). The engine that runs the program has
//! no such processor; it asks its host for one, a
//! [`Foreign`](rax_smir_portable::interp::Foreign). This crate has one: a
//! [`Processor`], which runs x86-64 or AArch64 code on the emulator's
//! user-mode cores, in an address space of its own, on whatever machine the
//! engine runs on.
//!
//! ```no_run
//! use rax_smir_portable::interp::NoHost;
//! use rax_smir_portable::ir::ForeignIsa;
//! use rax_smir_portable_foreign::{Hosting, Limits, Processor};
//!
//! let image = std::fs::read("library.elf")?;
//! let mut processor = Processor::new(ForeignIsa::X86_64, Limits::default())?;
//! processor.load(&image)?;
//! // A host for `run_on` or `Instance::start`: under it a module runs whose
//! // bridges name code of that image.
//! let host = Hosting::new(NoHost, processor);
//! # let _ = host;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # What foreign code has here
//!
//! - **Its images**, each at the addresses the image says. An image is a
//!   static ELF executable ([`Processor::load`]); a module names it by the
//!   SHA-256 of the file and names code in it by where in the file the code
//!   is.
//! - **Memory for calls**, in which the engine puts each crossing's frame,
//!   arguments and result.
//! - **A stack for each thread** of the program that crosses, with nothing
//!   mapped below it for a long way, so that code which runs out of stack
//!   faults. Calls of one thread that are inside one another, because the
//!   code called portable code back and that called foreign code again,
//!   are on the one stack.
//! - **The entries of callbacks** taken over: where the code goes to call
//!   a function of the program, it stops, and goes on when the engine has
//!   run the function.
//!
//! It has no operating system. Code that makes a system call, faults, or
//! runs longer than [`Limits::time`] allows has not returned, and the
//! program that called it ends with the trap `foreign_fault`; a [`Record`]
//! says why.
//!
//! The address space, from the bottom: images below 2^46; the memory for
//! calls from there; the stacks from `0x6000_0000_0000`; and one address
//! near the top at which nothing ever is, which is where code returns to
//! when it returns to the engine.

mod cpu;
mod hosting;
mod image;
mod memory;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rax::user::cpu::x86_64::RESERVED_PHYS;
use rax::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};
use rax_smir_portable::interp::{Crossing, Foreign, ForeignFault};
use rax_smir_portable::ir::{BridgeConvention, ForeignIsa};

use cpu::{Core, RETURN_AT, Stop, Waiting};
pub use hosting::Hosting;
use image::{Image, MAY_EXECUTE, MAY_READ, MAY_WRITE};
use memory::Heap;

/// The lowest address an image may have, and the end of where images are.
const IMAGES_AT: u64 = 0x1_0000;
const IMAGES_END: u64 = 1 << 46;
/// Where the memory for calls begins, and the stacks.
const HEAP_AT: u64 = IMAGES_END;
const STACKS_AT: u64 = 0x6000_0000_0000;
/// How far apart the stacks are: what is unmapped below each.
const STACK_GAP: u64 = 256 << 20;
/// How far below the stack pointer of code that waits the next call's
/// stack begins: more than any convention lets code keep there.
const BELOW: u64 = 256;
/// How many reasons a record keeps: the last ones.
const REASONS: usize = 32;

/// What a processor may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Bytes of memory, for everything: images, calls and stacks.
    pub memory: u64,
    /// Bytes of each thread's stack.
    pub stack: u64,
    /// How long one call of foreign code may run before it counts as code
    /// that does not return. Without a limit, code that never returns
    /// keeps the program's thread for ever, as it would on its own machine.
    pub time: Option<Duration>,
}

impl Default for Limits {
    /// 64 MiB of memory, a stack of 1 MiB, and no limit of time.
    fn default() -> Self {
        Self {
            memory: 64 << 20,
            stack: 1 << 20,
            time: None,
        }
    }
}

/// Why there is no processor, or why it has not taken an image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The file is no image this processor loads.
    Format(&'static str),
    /// The image is for another processor.
    Machine,
    /// The image belongs at this address, which is not an image's to have:
    /// another image is there, or it is outside of where images are.
    Place(u64),
    /// The limits leave no memory for it.
    Memory,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(what) => write!(f, "the file is {what}"),
            Self::Machine => f.write_str("the image is for another processor"),
            Self::Place(address) => {
                write!(f, "the image belongs at {address:#x}, which it cannot have")
            }
            Self::Memory => f.write_str("the processor has not the memory"),
        }
    }
}

impl std::error::Error for Refusal {}

#[derive(Default)]
struct Kept {
    crossings: u64,
    held: u64,
    reasons: Vec<String>,
}

/// What a processor has done, for whoever kept this when the processor
/// went to a process.
#[derive(Clone, Default)]
pub struct Record(Arc<Mutex<Kept>>);

impl Record {
    fn kept(&self) -> std::sync::MutexGuard<'_, Kept> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many calls of foreign code returned.
    pub fn crossings(&self) -> u64 {
        self.kept().crossings
    }

    /// How many bytes of the memory for calls are held now.
    pub fn held(&self) -> u64 {
        self.kept().held
    }

    /// Why the processor could not do what it was asked, each time it could
    /// not, the latest last.
    pub fn reasons(&self) -> Vec<String> {
        self.kept().reasons.clone()
    }
}

/// A call of foreign code that has not returned: how it was entered, where
/// its stack is when it has returned, and, while it waits at the entry of a
/// callback, what it waits with.
struct Call {
    convention: BridgeConvention,
    returns: u64,
    waiting: Option<Waiting>,
}

/// A thread's stack, which ends at `top`, its processor while none of its
/// code runs, and its calls that have not returned, the innermost last:
/// all but that one wait, and that one waits unless it runs.
struct Thread {
    top: u64,
    core: Option<Core>,
    calls: Vec<Call>,
}

/// A processor for foreign code of one kind, with its memory.
pub struct Processor {
    isa: ForeignIsa,
    space: AddressSpace,
    images: Vec<Image>,
    /// The pages images have.
    taken: BTreeSet<u64>,
    /// The entries of callbacks: the addresses that were taken over.
    entries: BTreeSet<u64>,
    heap: Heap,
    /// The program's threads that have crossed, by their numbers.
    threads: BTreeMap<u64, Thread>,
    /// The limits: bytes of memory, bytes of a stack, and time for a call.
    memory: u64,
    stack: u64,
    time: Option<Duration>,
    record: Record,
}

fn pages(bytes: u64) -> Option<u64> {
    bytes.checked_next_multiple_of(PAGE_SIZE)
}

impl Processor {
    /// A processor for code of `isa`, with no image yet.
    pub fn new(isa: ForeignIsa, limits: Limits) -> Result<Self, Refusal> {
        let memory = pages(limits.memory).ok_or(Refusal::Memory)?;
        let stack = pages(limits.stack.max(1)).ok_or(Refusal::Memory)?;
        if memory == 0 || stack > memory {
            return Err(Refusal::Memory);
        }
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: memory,
            // What the x86-64 core keeps of physical memory for itself.
            reserved_phys: match isa {
                ForeignIsa::X86_64 => RESERVED_PHYS.to_vec(),
                ForeignIsa::Aarch64 => Vec::new(),
            },
        })
        .map_err(|_| Refusal::Memory)?;
        Ok(Self {
            isa,
            space,
            images: Vec::new(),
            taken: BTreeSet::new(),
            entries: BTreeSet::new(),
            // No more of it can be in use than there is memory.
            heap: Heap::new(HEAP_AT, HEAP_AT + memory),
            threads: BTreeMap::new(),
            memory,
            stack,
            time: limits.time,
            record: Record::default(),
        })
    }

    /// What this processor does, to keep when the processor is given away.
    pub fn record(&self) -> Record {
        self.record.clone()
    }

    /// Take the image `file` is, put it where it says it belongs, and
    /// return its identity, the SHA-256 of the file, by which modules name
    /// it. An image the processor has already is not loaded again.
    pub fn load(&mut self, file: &[u8]) -> Result<[u8; 32], Refusal> {
        let image = Image::read(self.isa, file)?;
        if self
            .images
            .iter()
            .any(|have| have.identity == image.identity)
        {
            return Ok(image.identity);
        }
        // What each page of the image allows: all that any segment in it
        // allows.
        let mut wanted: BTreeMap<u64, Perms> = BTreeMap::new();
        // An image larger than all the memory there is has no place, and is
        // not looked at page by page.
        let mut budget = self.memory;
        for segment in &image.segments {
            let start = segment.address & !(PAGE_SIZE - 1);
            let end = pages(segment.address + segment.in_memory)
                .filter(|end| start >= IMAGES_AT && *end <= IMAGES_END)
                .ok_or(Refusal::Place(segment.address))?;
            budget = budget.checked_sub(end - start).ok_or(Refusal::Memory)?;
            let mut allowed = Perms::empty();
            for (flag, permission) in [
                (MAY_READ, Perms::READ),
                (MAY_WRITE, Perms::WRITE),
                (MAY_EXECUTE, Perms::EXEC),
            ] {
                if segment.flags & flag != 0 {
                    allowed |= permission;
                }
            }
            for page in (start..end).step_by(PAGE_SIZE as usize) {
                if self.taken.contains(&page) {
                    return Err(Refusal::Place(page));
                }
                *wanted.entry(page).or_insert(Perms::empty()) |= allowed;
            }
        }
        if let Err(refusal) = self.place(&image, file, &wanted) {
            for page in wanted.keys() {
                // What is not mapped is not unmapped; nothing else can fail.
                let _ = self.space.unmap(*page, PAGE_SIZE);
            }
            return Err(refusal);
        }
        self.taken.extend(wanted.keys());
        let identity = image.identity;
        self.images.push(image);
        Ok(identity)
    }

    /// Map the pages of an image and fill them from the file.
    fn place(
        &self,
        image: &Image,
        file: &[u8],
        wanted: &BTreeMap<u64, Perms>,
    ) -> Result<(), Refusal> {
        for (page, allowed) in wanted {
            self.space
                .map(*page, PAGE_SIZE, Mapping::anonymous(*allowed))
                .map_err(|_| Refusal::Memory)?;
        }
        for segment in &image.segments {
            // Within the file, as the image was read.
            let bytes = &file[segment.offset as usize..(segment.offset + segment.in_file) as usize];
            self.space
                .write_raw(segment.address, bytes)
                .map_err(|_| Refusal::Memory)?;
        }
        Ok(())
    }

    /// Note why something could not be done, and return the fault it is.
    fn fault(&self, reason: String) -> ForeignFault {
        let mut kept = self.record.kept();
        if kept.reasons.len() == REASONS {
            kept.reasons.remove(0);
        }
        kept.reasons.push(reason);
        ForeignFault
    }

    /// The top of the stack of `thread`, which it gets when it first
    /// crosses.
    fn stack(&mut self, thread: u64) -> Result<u64, ForeignFault> {
        if let Some(state) = self.threads.get(&thread) {
            return Ok(state.top);
        }
        // Stacks are apart by more than any one function's frame, so that
        // a thread that runs out of its own does not reach another's.
        let top = (self.threads.len() as u64)
            .checked_mul(self.stack + STACK_GAP)
            .and_then(|above| STACKS_AT.checked_add(above + STACK_GAP + self.stack))
            .filter(|top| *top <= RETURN_AT - STACK_GAP);
        let mapped = top.and_then(|top| {
            let stack = Mapping::anonymous(Perms::READ | Perms::WRITE);
            self.space
                .map(top - self.stack, self.stack, stack)
                .ok()
                .map(|()| top)
        });
        let Some(top) = mapped else {
            return Err(self.fault(format!("thread {thread}: no memory for a stack")));
        };
        let state = Thread {
            top,
            core: None,
            calls: Vec::new(),
        };
        self.threads.insert(thread, state);
        Ok(top)
    }

    /// Run the innermost call of `thread`, on `core`, until it returns or
    /// gets to the entry of a callback. Code that does neither leaves the
    /// thread without calls and without that core: nothing of it can be
    /// gone on with.
    fn run(&mut self, thread: u64, mut core: Core) -> Result<Crossing, ForeignFault> {
        let deadline = self.time.and_then(|time| Instant::now().checked_add(time));
        let state = self
            .threads
            .get_mut(&thread)
            .expect("the thread has a stack");
        let call = state.calls.last_mut().expect("the thread has a call");
        // Code that returns leaves the stack as a return leaves it.
        let stopped = match core.run(call.convention, &self.entries, deadline) {
            Ok(Stop::Returned) if core.sp() != call.returns => Err(format!(
                "the code returned with its stack at {:#x}, not at {:#x}",
                core.sp(),
                call.returns
            )),
            stopped => stopped,
        };
        match stopped {
            Ok(Stop::Returned) => {
                state.calls.pop();
                // What the code left in the processor is the thread's, for
                // its next call or for the call that waits for this one.
                state.core = Some(core);
                self.record.kept().crossings += 1;
                Ok(Crossing::Returned)
            }
            Ok(Stop::Called { entry, frame }) => {
                call.waiting = Some(core.waiting());
                state.core = Some(core);
                Ok(Crossing::Called { entry, frame })
            }
            Err(reason) => {
                state.calls.clear();
                Err(self.fault(format!("thread {thread}: {reason}")))
            }
        }
    }
}

impl Foreign for Processor {
    fn isa(&self) -> ForeignIsa {
        self.isa
    }

    fn code(&mut self, image: &[u8; 32], offset: u64, size: u64) -> Option<u64> {
        self.images
            .iter()
            .find(|have| have.identity == *image)?
            .code(offset, size)
    }

    fn intercept(&mut self, image: &[u8; 32], offset: u64, size: u64) -> Option<u64> {
        // The first instruction there becomes a breakpoint, which the code
        // has to have room for; what was there never runs.
        let breakpoint = cpu::breakpoint(self.isa);
        let entry = self.code(image, offset, size)?;
        if size < breakpoint.len() as u64 || entry % breakpoint.len() as u64 != 0 {
            return None;
        }
        self.space.write_raw(entry, breakpoint).ok()?;
        self.entries.insert(entry);
        Some(entry)
    }

    fn allocate(&mut self, bytes: u64) -> Result<u64, ForeignFault> {
        let allocated = self.heap.allocate(&self.space, bytes);
        self.record.kept().held = self.heap.in_use();
        allocated.map_err(|_| self.fault(format!("no memory for a call that needs {bytes} bytes")))
    }

    fn release(&mut self, address: u64) {
        self.heap.release(address);
        self.record.kept().held = self.heap.in_use();
    }

    // The engine reads and writes what the foreign code itself may: the
    // memory of calls, and the frames and arguments of callbacks, which the
    // code has on its stack. Not, in particular, code.
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ForeignFault> {
        self.space
            .write(address, bytes)
            .map_err(|_| self.fault(format!("{address:#x} is no memory to write")))
    }

    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), ForeignFault> {
        self.space
            .read(address, buffer)
            .map_err(|_| self.fault(format!("{address:#x} is no memory to read")))
    }

    fn enter(
        &mut self,
        thread: u64,
        convention: BridgeConvention,
        entry: u64,
        frame: u64,
    ) -> Result<Crossing, ForeignFault> {
        if !cpu::takes(self.isa, convention) {
            return Err(self.fault(format!(
                "{convention:?} is no convention of {} code",
                self.isa.name()
            )));
        }
        let top = self.stack(thread)?;
        let state = self
            .threads
            .get_mut(&thread)
            .expect("the thread has a stack");
        // A call inside one that waits is below it on the same stack, with
        // room between for what the code that waits may keep below its
        // stack pointer.
        let top = match state.calls.last().map(|call| call.waiting) {
            None => top,
            Some(Some(waiting)) => (waiting.sp - BELOW) & !15,
            Some(None) => {
                return Err(self.fault(format!("thread {thread}: its foreign code is running")));
            }
        };
        let mut core = state
            .core
            .take()
            .unwrap_or_else(|| Core::new(self.isa, &self.space));
        match core.call(&self.space, convention, entry, frame, top) {
            Ok(returns) => state.calls.push(Call {
                convention,
                returns,
                waiting: None,
            }),
            Err(reason) => {
                state.calls.clear();
                return Err(self.fault(format!("thread {thread}: {reason}")));
            }
        }
        self.run(thread, core)
    }

    fn resume(&mut self, thread: u64) -> Result<Crossing, ForeignFault> {
        let waits = self.threads.get_mut(&thread).and_then(|state| {
            let waiting = state.calls.last_mut()?.waiting.take()?;
            Some((state.core.take()?, waiting))
        });
        let Some((mut core, waiting)) = waits else {
            return Err(self.fault(format!("thread {thread}: none of its foreign code waits")));
        };
        if let Err(reason) = core.go_on(&self.space, waiting) {
            return Err(self.fault(format!("thread {thread}: {reason}")));
        }
        self.run(thread, core)
    }
}
