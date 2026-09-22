//! Context save/restore: a self-contained snapshot of CPU state, extended
//! emulator state, and all mapped memory and its contents.
//!
//! The blob format is versioned and little-endian:
//! ```text
//!   magic   u32  = 0x52415843 ("RAXC")
//!   version u32  = 1
//!   arch    i32
//!   mode    u32
//!   flags   u32  (bit0: extended emulator state present)
//!   cpu_len u64; cpu_bytes[cpu_len]      (bincode of CpuState)
//!   emu_len u64; emu_bytes[emu_len]      (bincode of EmulatorState; if flag)
//!   nregion u64
//!   per region: base u64, size u64, perms u32, _pad u32, bytes[size]
//! ```

use rax_engine::cpu::CpuState;
use rax_engine::memory::vm::GuestAddress;
use rax_engine::snapshot::EmulatorState;

use crate::arch::RaxArch;
use crate::engine::{Engine, engine_mut};
use crate::guard;
use crate::status::RaxStatus;

const CTX_MAGIC: u32 = 0x5241_5843; // "RAXC"
const CTX_VERSION: u32 = 1;
const FLAG_HAS_EMU: u32 = 1 << 0;

struct Writer {
    buf: Vec<u8>,
}
impl Writer {
    fn new() -> Self {
        Writer { buf: Vec::new() }
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        let mut t = [0u8; 8];
        t.copy_from_slice(b);
        Some(u64::from_le_bytes(t))
    }
}

impl Engine {
    /// Serializes the full engine context into a byte vector.
    fn serialize_context(&self) -> Result<Vec<u8>, RaxStatus> {
        let mut w = Writer::new();
        w.u32(CTX_MAGIC);
        w.u32(CTX_VERSION);
        w.i32(self.arch as i32);
        w.u32(self.mode);

        let cpu = self
            .vcpu
            .get_state()
            .map_err(|e| crate::status::status_from_engine_error(&e))?;
        let cpu_bytes = bincode::serialize(&cpu).map_err(|_| RaxStatus::Format)?;
        let emu = self.vcpu.get_emulator_state();
        let mut flags = 0u32;
        if emu.is_some() {
            flags |= FLAG_HAS_EMU;
        }
        w.u32(flags);
        w.u64(cpu_bytes.len() as u64);
        w.bytes(&cpu_bytes);
        if let Some(es) = &emu {
            let eb = bincode::serialize(es).map_err(|_| RaxStatus::Format)?;
            w.u64(eb.len() as u64);
            w.bytes(&eb);
        } else {
            w.u64(0);
        }

        w.u64(self.regions.len() as u64);
        for r in &self.regions {
            w.u64(r.base);
            w.u64(r.size);
            w.u32(r.perms);
            w.u32(0);
            let mut bytes = vec![0u8; r.size as usize];
            // Read region contents from the backing store.
            use rax_engine::memory::vm::Bytes;
            if self
                .mem
                .read_slice(&mut bytes, GuestAddress(r.base))
                .is_err()
            {
                return Err(RaxStatus::Map);
            }
            w.bytes(&bytes);
        }
        Ok(w.buf)
    }

    /// Restores engine context from a byte slice produced by
    /// [`serialize_context`].
    fn deserialize_context(&mut self, data: &[u8]) -> RaxStatus {
        let mut r = Reader::new(data);
        let magic = match r.u32() {
            Some(v) => v,
            None => return self.fail(RaxStatus::Format, "context too short"),
        };
        if magic != CTX_MAGIC {
            return self.fail(RaxStatus::Format, "bad context magic");
        }
        let version = r.u32().unwrap_or(0);
        if version != CTX_VERSION {
            return self.fail(RaxStatus::Format, "unsupported context version");
        }
        let arch = r.i32().unwrap_or(-1);
        let mode = r.u32().unwrap_or(0);
        if RaxArch::from_i32(arch) != Some(self.arch) {
            return self.fail(RaxStatus::Arch, "context architecture mismatch");
        }
        let flags = match r.u32() {
            Some(v) => v,
            None => return self.fail(RaxStatus::Format, "truncated context"),
        };
        let cpu_len = match r.u64() {
            Some(v) => v as usize,
            None => return self.fail(RaxStatus::Format, "truncated context"),
        };
        let cpu_bytes = match r.take(cpu_len) {
            Some(b) => b,
            None => return self.fail(RaxStatus::Format, "truncated cpu state"),
        };
        let cpu: CpuState = match bincode::deserialize(cpu_bytes) {
            Ok(c) => c,
            Err(_) => return self.fail(RaxStatus::Format, "bad cpu state encoding"),
        };
        let emu_len = match r.u64() {
            Some(v) => v as usize,
            None => return self.fail(RaxStatus::Format, "truncated context"),
        };
        let emu: Option<EmulatorState> = if flags & FLAG_HAS_EMU != 0 {
            let eb = match r.take(emu_len) {
                Some(b) => b,
                None => return self.fail(RaxStatus::Format, "truncated emulator state"),
            };
            match bincode::deserialize(eb) {
                Ok(e) => Some(e),
                Err(_) => return self.fail(RaxStatus::Format, "bad emulator state encoding"),
            }
        } else {
            None
        };

        let nregion = match r.u64() {
            Some(v) => v as usize,
            None => return self.fail(RaxStatus::Format, "truncated region count"),
        };
        let mut specs: Vec<(u64, u64, u32, Vec<u8>)> = Vec::with_capacity(nregion);
        for _ in 0..nregion {
            let base = match r.u64() {
                Some(v) => v,
                None => return self.fail(RaxStatus::Format, "truncated region"),
            };
            let size = match r.u64() {
                Some(v) => v,
                None => return self.fail(RaxStatus::Format, "truncated region"),
            };
            let perms = r.u32().unwrap_or(0);
            let _pad = r.u32();
            let bytes = match r.take(size as usize) {
                Some(b) => b.to_vec(),
                None => return self.fail(RaxStatus::Format, "truncated region data"),
            };
            specs.push((base, size, perms, bytes));
        }
        if specs.is_empty() {
            return self.fail(RaxStatus::Format, "context has no memory regions");
        }

        // Rebuild memory: fresh backings for every region, then write bytes.
        let mut regions = Vec::with_capacity(specs.len());
        for (base, size, perms, _) in &specs {
            let backing = match crate::mem::alloc_backing(*base, *size) {
                Ok(b) => b,
                Err(_) => return self.fail(RaxStatus::NoMem, "failed to allocate region"),
            };
            regions.push(crate::mem::Region {
                base: *base,
                size: *size,
                perms: *perms,
                backing,
            });
        }
        regions.sort_by_key(|r| r.base);
        let arcs: Vec<_> = regions.iter().map(|r| r.backing.clone()).collect();
        let new_mem = match rax_engine::memory::vm::GuestMemoryMmap::from_arc_regions(arcs) {
            Ok(m) => std::sync::Arc::new(m),
            Err(_) => return self.fail(RaxStatus::Map, "failed to assemble memory map"),
        };
        {
            use rax_engine::memory::vm::Bytes;
            for (base, _size, _perms, bytes) in &specs {
                if new_mem.write_slice(bytes, GuestAddress(*base)).is_err() {
                    return self.fail(RaxStatus::Map, "failed to restore region contents");
                }
            }
        }

        // Reconstruct the vCPU over the restored memory and load CPU state.
        let mut vcpu =
            match crate::arch::build_vcpu(self.arch, mode, new_mem.clone(), self.riscv_config) {
                Ok(v) => v,
                Err(err) => return self.fail_engine(&err),
            };
        if let Err(err) = vcpu.set_state(&cpu) {
            return self.fail_engine(&err);
        }
        if let Some(es) = &emu {
            let _ = vcpu.set_emulator_state(es);
        }

        self.mode = mode;
        self.vcpu = vcpu;
        self.mem = new_mem;
        self.regions = regions;
        self.last_exit = crate::run::ExitInfo::none();
        self.last_fault = crate::fault::RaxFaultInfo::default();
        self.icount_base = 0;
        self.stop_flag.set(false);
        RaxStatus::Ok
    }
}

// ===========================================================================
// FFI
// ===========================================================================

/// Saves a complete engine context (CPU + extended state + all memory) to a
/// caller buffer. Two-call pattern: pass `buf == NULL` (or too-small `cap`) to
/// learn the required size via `*out_len`, then call again with a buffer of at
/// least that size.
///
/// Returns `RAX_OK` when the context was written (or when only the size was
/// queried with `buf == NULL`), or `RAX_ERR_BOUNDS` if `buf` is non-NULL but
/// `cap` is too small.
#[unsafe(no_mangle)]
pub extern "C" fn rax_context_save(
    engine: *const Engine,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { crate::engine::engine_ref(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        let blob = match e.serialize_context() {
            Ok(b) => b,
            Err(s) => return s,
        };
        if !out_len.is_null() {
            unsafe {
                *out_len = blob.len();
            }
        }
        if buf.is_null() {
            return RaxStatus::Ok;
        }
        if cap < blob.len() {
            return RaxStatus::Bounds;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(blob.as_ptr(), buf, blob.len());
        }
        RaxStatus::Ok
    })
}

/// Restores an engine context previously produced by [`rax_context_save`].
#[unsafe(no_mangle)]
pub extern "C" fn rax_context_restore(
    engine: *mut Engine,
    data: *const u8,
    len: usize,
) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        if e.running {
            return e.fail(RaxStatus::State, "cannot restore while running");
        }
        e.clear_err();
        if data.is_null() || len == 0 {
            return e.fail(RaxStatus::Arg, "null or empty context");
        }
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        e.deserialize_context(slice)
    })
}
