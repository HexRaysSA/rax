//! Region-level analysis of a `.raxtrace` file.
//!
//! The output groups touched pages into contiguous regions, classifies each
//! region from its access pattern, and attributes writes to the code pages
//! that issued them. The classifications are heuristics, not declarations:
//! they are named so that a reader can check the evidence in the same report.

use crate::host::time::{Duration, Instant};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use super::{
    ARCH_X86_64, HEADER_LEN, MAGIC, RECORD_LEN, TAG_EXEC, TAG_MAP, TAG_READ, TAG_SNAPSHOT,
    TAG_WRITE, VERSION,
};

const PAGE: u64 = 4096;
const PAGE_MASK: u64 = PAGE - 1;
const WRITE_SIZE_BUCKETS: usize = 9;
const MAX_SAMPLES: usize = 16;
const MAX_WRITERS: usize = 8;
const MAX_TARGETS: usize = 8;
/// Ceiling on tracked instruction addresses (about 100 MiB at capacity).
const MAX_INSTR: usize = 1 << 21;
/// Ceiling on tracked page-to-page execution edges.
const MAX_EDGES: usize = 1 << 20;
/// Instruction addresses sampled for the hot-run ranking.
const HOT_ADDRESSES: usize = 4096;
/// Bytes within which two sampled addresses belong to one straight-line run.
const RUN_GAP: u64 = 24;

/// Analysis and rendering options.
#[derive(Clone, Debug)]
pub struct Options {
    /// Regions shown in the table (the rest are summarised).
    pub top: usize,
    /// Show every region.
    pub all: bool,
    /// Hide regions with fewer writes than this.
    pub min_writes: u64,
    /// Detailed region containing this address.
    pub region: Option<u64>,
    /// Detailed page containing this address.
    pub page: Option<u64>,
    /// Print the address-space character map.
    pub show_map: bool,
    /// Write a JSON report here.
    pub json: Option<std::path::PathBuf>,
    /// Print parse progress on stderr.
    pub progress: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            top: 40,
            all: false,
            min_writes: 0,
            region: None,
            page: None,
            show_map: true,
            json: None,
            progress: false,
        }
    }
}

/// One contiguous region of touched pages.
#[derive(Clone, Debug, Default)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub pages: u64,
    pub reads: u64,
    pub writes: u64,
    pub execs: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub write_sizes: [u64; WRITE_SIZE_BUCKETS],
    pub read_sizes: [u64; WRITE_SIZE_BUCKETS],
    pub zero_writes: u64,
    pub map_name: String,
    pub first_perms: u8,
    pub last_perms: u8,
    pub first_write_seq: Option<u64>,
    pub first_exec_seq: Option<u64>,
    pub last_exec_seq: Option<u64>,
    pub distinct_writers: usize,
    pub writers: Vec<(u64, u64)>,
    pub distinct_readers: usize,
    pub readers: Vec<(u64, u64)>,
    pub labels: Vec<&'static str>,
    pub pointer_percent: f32,
    pub write_coverage: f32,
    pub kind: &'static str,
    pub kind_id: u8,
}

/// Aggregate counts.
#[derive(Clone, Debug, Default)]
pub struct Totals {
    pub accesses: u64,
    pub reads: u64,
    pub writes: u64,
    pub execs: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub pages_touched: u64,
    pub pages_executed: u64,
    pub pages_written: u64,
    pub pages_self_modifying: u64,
    pub snapshots: u64,
    pub trace_bytes: u64,
}

/// The result of analysing one trace.
pub struct Report {
    pub totals: Totals,
    pub findings: Vec<String>,
    pub regions: Vec<Region>,
    pages: BTreeMap<u64, PageStats>,
    snapshots: Vec<Snapshot>,
    srcs: HashMap<u64, SrcStats>,
    instr: HashMap<u64, u64>,
    instr_dropped: u64,
    edges: HashMap<(u64, u64), u64>,
    arch: u32,
    pub trace_path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Code,
    SelfMod,
    Bytecode,
    PointerData,
    ReadData,
    WrittenData,
    Context,
    Stack,
    Heap,
    Other,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Code => "executable code",
            Kind::SelfMod => "self-modifying code",
            Kind::Bytecode => "opcode stream",
            Kind::PointerData => "pointer / dispatch table",
            Kind::ReadData => "read-only data",
            Kind::WrittenData => "written data",
            Kind::Context => "multi-writer context",
            Kind::Stack => "stack",
            Kind::Heap => "heap",
            Kind::Other => "other",
        }
    }

    fn order(self) -> u8 {
        match self {
            Kind::Code => 0,
            Kind::SelfMod => 1,
            Kind::Bytecode => 2,
            Kind::PointerData => 3,
            Kind::Context => 4,
            Kind::Stack => 5,
            Kind::Heap => 6,
            Kind::WrittenData => 7,
            Kind::ReadData => 8,
            Kind::Other => 9,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PageStats {
    reads: u64,
    writes: u64,
    execs: u64,
    bytes_read: u64,
    bytes_written: u64,
    write_sizes: [u64; WRITE_SIZE_BUCKETS],
    read_sizes: [u64; WRITE_SIZE_BUCKETS],
    zero_writes: u64,
    first: u64,
    last: u64,
    first_read: Option<u64>,
    first_write: Option<u64>,
    last_write: Option<u64>,
    first_exec: Option<u64>,
    last_exec: Option<u64>,
    writes_after_exec: u64,
    writes_before_exec: u64,
    write_coverage: u64,
    exec_coverage: u64,
    writers: [(u64, u64); MAX_WRITERS],
    writer_len: usize,
    distinct_writers: usize,
    readers: [(u64, u64); MAX_WRITERS],
    reader_len: usize,
    distinct_readers: usize,
    read_samples: [u64; MAX_SAMPLES],
    write_samples: [u64; MAX_SAMPLES],
    read_sample_len: usize,
    write_sample_len: usize,
    read_sample_total: u64,
    write_sample_total: u64,
    pointer_reads: u64,
    pointer_writes: u64,
    last_value: u64,
}

impl PageStats {
    fn note_reader(&mut self, source_page: u64) {
        for i in 0..self.reader_len {
            if self.readers[i].0 == source_page {
                self.readers[i].1 += 1;
                return;
            }
        }
        if self.reader_len < MAX_WRITERS {
            self.readers[self.reader_len] = (source_page, 1);
            self.reader_len += 1;
            self.distinct_readers += 1;
        } else {
            self.distinct_readers += 1;
        }
    }

    fn note_writer(&mut self, source_page: u64) {
        for i in 0..self.writer_len {
            if self.writers[i].0 == source_page {
                self.writers[i].1 += 1;
                return;
            }
        }
        if self.writer_len < MAX_WRITERS {
            self.writers[self.writer_len] = (source_page, 1);
            self.writer_len += 1;
            self.distinct_writers += 1;
        } else {
            // Track the count even when the table is full; the top entries are
            // still meaningful, and `distinct_writers` stays a lower bound.
            self.distinct_writers += 1;
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SrcStats {
    writes: u64,
    targets: [(u64, u64); MAX_TARGETS],
    target_len: usize,
}

impl SrcStats {
    fn note_target(&mut self, page: u64) {
        for i in 0..self.target_len {
            if self.targets[i].0 == page {
                self.targets[i].1 += 1;
                return;
            }
        }
        if self.target_len < MAX_TARGETS {
            self.targets[self.target_len] = (page, 1);
            self.target_len += 1;
        }
    }
}

#[derive(Clone, Debug)]
struct MapRange {
    start: u64,
    end: u64,
    perms: u8,
    name: String,
}

#[derive(Clone, Debug, Default)]
struct Snapshot {
    at: u64,
    ranges: BTreeMap<u64, MapRange>,
}

impl Snapshot {
    fn get(&self, addr: u64) -> Option<&MapRange> {
        self.ranges
            .range(..=addr)
            .next_back()
            .map(|(_, range)| range)
            .filter(|range| addr < range.end)
    }
}

struct Analyzer {
    seq: u64,
    pages: BTreeMap<u64, PageStats>,
    srcs: HashMap<u64, SrcStats>,
    snapshots: Vec<Snapshot>,
    current_maps: BTreeMap<u64, MapRange>,
    /// Fetch counts per instruction address (heap-adjacent code is rare, so
    /// the map stays near the number of distinct executed instructions).
    instr: HashMap<u64, u64>,
    /// Executions of instructions not tracked because the table was full.
    instr_dropped: u64,
    /// Page-to-page execution edges, recorded when control changes page.
    edges: HashMap<(u64, u64), u64>,
    /// Page of the previous executed instruction, for [`Self::edges`].
    last_exec_page: Option<u64>,
    totals: Totals,
    header_ok: bool,
    arch: u32,
}

/// Reads `path` and renders the requested report. A JSON output is written as
/// a side effect when requested.
pub fn run(path: &Path, opts: &Options) -> io::Result<String> {
    let report = analyze_path_with_progress(path, opts.progress)?;
    if let Some(json) = &opts.json {
        std::fs::write(json, report.to_json())?;
    }
    Ok(report.render(opts))
}

/// Parses and analyses a trace file.
pub fn analyze_path(path: &Path) -> io::Result<Report> {
    analyze_path_with_progress(path, false)
}

/// Parses and analyses a trace file, optionally reporting progress on stderr.
///
/// A multi-gigabyte capture takes minutes to parse, so an interactive run can
/// show how far it has read and how fast.
pub fn analyze_path_with_progress(path: &Path, progress: bool) -> io::Result<Report> {
    let file = File::open(path)?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut meter = Progress::new(progress, len);
    let mut report = analyze_stream(&mut reader, &mut meter)?;
    meter.finish(len);
    report.totals.trace_bytes = len;
    report.trace_path = path.display().to_string();
    Ok(report)
}

/// Parses and analyses a trace stream.
pub fn analyze_reader<R: Read>(reader: &mut R) -> io::Result<Report> {
    let mut meter = Progress::new(false, 0);
    analyze_stream(reader, &mut meter)
}

fn analyze_stream<R: Read>(reader: &mut R, meter: &mut Progress) -> io::Result<Report> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;
    let mut analyzer = Analyzer {
        seq: 0,
        pages: BTreeMap::new(),
        srcs: HashMap::new(),
        snapshots: Vec::new(),
        current_maps: BTreeMap::new(),
        instr: HashMap::new(),
        instr_dropped: 0,
        edges: HashMap::new(),
        last_exec_page: None,
        totals: Totals::default(),
        header_ok: header[..8] == MAGIC[..],
        arch: u32::from_le_bytes(header[12..16].try_into().unwrap()),
    };
    if !analyzer.header_ok {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a rax memory trace (bad magic)",
        ));
    }
    let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported rax memory trace version {version}"),
        ));
    }
    if analyzer.arch != ARCH_X86_64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported trace architecture {}", analyzer.arch),
        ));
    }

    let mut record = [0u8; RECORD_LEN];
    loop {
        match reader.read_exact(&mut record) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }
        let tag = record[0];
        let aux = record[1];
        let name_len = u16::from_le_bytes([record[2], record[3]]) as usize;
        let a = u64::from_le_bytes(record[4..12].try_into().unwrap());
        let b = u64::from_le_bytes(record[12..20].try_into().unwrap());
        let c = u64::from_le_bytes(record[20..28].try_into().unwrap());
        let mut name = Vec::new();
        if name_len > 0 {
            name.resize(name_len, 0);
            reader.read_exact(&mut name)?;
        }
        meter.advance(RECORD_LEN as u64 + name_len as u64);
        match tag {
            TAG_READ => analyzer.access(a, b, aux, c, false),
            TAG_WRITE => analyzer.access(a, b, aux, c, true),
            TAG_EXEC => analyzer.exec(a, aux),
            TAG_SNAPSHOT => analyzer.begin_snapshot(),
            TAG_MAP => {
                let start = a;
                let end = b;
                if end > start {
                    analyzer.current_maps.insert(
                        start,
                        MapRange {
                            start,
                            end,
                            perms: aux,
                            name: String::from_utf8_lossy(&name).into_owned(),
                        },
                    );
                }
            }
            _ => {}
        }
    }
    analyzer.finish_snapshot();
    analyzer.finish()
}

/// Throttled parse progress for long captures.
///
/// There is no per-record clock: the meter only looks at the wall clock after
/// a fixed amount of input, so a fast small trace never pays for it.
struct Progress {
    enabled: bool,
    tty: bool,
    /// Total capture size, when known. Zero suppresses the percentage.
    total: u64,
    consumed: u64,
    next_check: u64,
    next_report: Option<Instant>,
    /// Bytes per report, chosen so a report appears at most every few seconds.
    stride: u64,
    printed: bool,
}

impl Progress {
    fn new(enabled: bool, total: u64) -> Self {
        Self {
            enabled,
            tty: std::io::IsTerminal::is_terminal(&std::io::stderr()),
            total,
            consumed: 0,
            next_check: 0,
            next_report: None,
            stride: 8 << 20,
            printed: false,
        }
    }

    #[inline]
    fn advance(&mut self, bytes: u64) {
        if !self.enabled {
            return;
        }
        self.consumed += bytes;
        if self.consumed < self.next_check {
            return;
        }
        // Back off when records are small: 8 MiB is a lot of records, but a
        // report every 8 MiB is noisy on a slow host, so time gates it.
        self.next_check = self.consumed + self.stride;
        let now = Instant::now();
        let due = match self.next_report {
            Some(at) => now >= at,
            None => {
                self.next_report = Some(now + Duration::from_secs(2));
                false
            }
        };
        if !due {
            return;
        }
        self.next_report = Some(now + Duration::from_secs(2));
        self.print(now);
    }

    fn print(&mut self, _now: Instant) {
        let percent = if self.total > 0 {
            (self.consumed as f64 / self.total as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        let line = if self.total > 0 {
            format!(
                "parsed {} of {} ({:.0}%)",
                bytes(self.consumed),
                bytes(self.total),
                percent
            )
        } else {
            format!("parsed {}", bytes(self.consumed))
        };
        if self.tty {
            eprint!("\r[{line}]");
        } else {
            eprintln!("[rax-trace-map] {line}");
        }
        self.printed = true;
    }

    fn finish(&mut self, total: u64) {
        if !self.enabled {
            return;
        }
        if !self.printed {
            return;
        }
        let line = if total > 0 {
            format!("parsed {} of {}", bytes(total), bytes(total))
        } else {
            format!("parsed {}", bytes(self.consumed))
        };
        if self.tty {
            eprintln!("\r[{line}]");
        } else {
            eprintln!("[rax-trace-map] {line}");
        }
    }
}

impl Analyzer {
    fn begin_snapshot(&mut self) {
        self.finish_snapshot();
        self.current_maps.clear();
    }

    fn finish_snapshot(&mut self) {
        if self.current_maps.is_empty() {
            return;
        }
        self.snapshots.push(Snapshot {
            at: self.seq,
            ranges: std::mem::take(&mut self.current_maps),
        });
    }

    fn access(&mut self, addr: u64, value: u64, size: u8, rip: u64, write: bool) {
        self.seq += 1;
        self.totals.accesses += 1;
        let page = addr / PAGE;
        let offset = addr & PAGE_MASK;
        let stats = self.pages.entry(page).or_default();
        stats.first = if stats.first == 0 {
            self.seq
        } else {
            stats.first
        };
        stats.last = self.seq;
        stats.last_value = value;
        if write {
            self.totals.writes += 1;
            self.totals.bytes_written += u64::from(size);
            stats.writes += 1;
            stats.bytes_written += u64::from(size);
            stats.write_sizes[size_index(size)] += 1;
            if value == 0 {
                stats.zero_writes += 1;
            }
            stats.first_write.get_or_insert(self.seq);
            stats.last_write = Some(self.seq);
            if stats.first_exec.is_some() {
                stats.writes_after_exec += 1;
            } else {
                stats.writes_before_exec += 1;
            }
            mark_coverage(&mut stats.write_coverage, offset, size);
            if stats.write_sample_total % 16 == 0 {
                if stats.write_sample_len < MAX_SAMPLES {
                    stats.write_samples[stats.write_sample_len] = value;
                    stats.write_sample_len += 1;
                }
            }
            stats.write_sample_total += 1;
            let source_page = rip / PAGE;
            if rip != 0 {
                stats.note_writer(source_page);
                self.srcs.entry(source_page).or_default().writes += 1;
                self.srcs.entry(source_page).or_default().note_target(page);
            }
        } else {
            self.totals.reads += 1;
            self.totals.bytes_read += u64::from(size);
            stats.reads += 1;
            stats.bytes_read += u64::from(size);
            stats.read_sizes[size_index(size)] += 1;
            stats.first_read.get_or_insert(self.seq);
            let source_page = rip / PAGE;
            if rip != 0 {
                stats.note_reader(source_page);
            }
            if stats.first_write.is_none() && stats.first_exec.is_none() {
                // first touch is a read; nothing to do, kept for clarity
            }
            if stats.read_sample_total % 16 == 0 {
                if stats.read_sample_len < MAX_SAMPLES {
                    stats.read_samples[stats.read_sample_len] = value;
                    stats.read_sample_len += 1;
                }
            }
            stats.read_sample_total += 1;
        }
    }

    fn exec(&mut self, addr: u64, size: u8) {
        self.seq += 1;
        self.totals.accesses += 1;
        self.totals.execs += 1;
        let page = addr / PAGE;
        let offset = addr & PAGE_MASK;
        let stats = self.pages.entry(page).or_default();
        stats.first = if stats.first == 0 {
            self.seq
        } else {
            stats.first
        };
        stats.last = self.seq;
        stats.execs += 1;
        stats.first_exec.get_or_insert(self.seq);
        stats.last_exec = Some(self.seq);
        mark_coverage(&mut stats.exec_coverage, offset, size.max(1));
        if let Some(count) = self.instr.get_mut(&addr) {
            *count += 1;
        } else if self.instr.len() < MAX_INSTR {
            self.instr.insert(addr, 1);
        } else {
            self.instr_dropped += 1;
        }
        // Control flow between pages, not between instructions: a handler
        // stays inside its page for many instructions, so page changes are
        // rare and cheap to count.
        if self.last_exec_page != Some(page) {
            if let Some(previous) = self.last_exec_page.replace(page) {
                let edge = (previous, page);
                if let Some(count) = self.edges.get_mut(&edge) {
                    *count += 1;
                } else if self.edges.len() < MAX_EDGES {
                    self.edges.insert(edge, 1);
                }
            }
        }
    }

    fn finish(mut self) -> io::Result<Report> {
        let exec_pages: BTreeSet<u64> = self
            .pages
            .iter()
            .filter(|(_, p)| p.execs > 0)
            .map(|(page, _)| *page)
            .collect();
        let exec_lookup = |value: u64| exec_pages.contains(&(value / PAGE));

        for stats in self.pages.values_mut() {
            for i in 0..stats.read_sample_len {
                if exec_lookup(stats.read_samples[i]) {
                    stats.pointer_reads += 1;
                }
            }
            for i in 0..stats.write_sample_len {
                if exec_lookup(stats.write_samples[i]) {
                    stats.pointer_writes += 1;
                }
            }
        }

        self.totals.pages_touched = self.pages.len() as u64;
        self.totals.pages_executed = self.pages.values().filter(|p| p.execs > 0).count() as u64;
        self.totals.pages_written = self.pages.values().filter(|p| p.writes > 0).count() as u64;
        self.totals.pages_self_modifying = self
            .pages
            .values()
            .filter(|p| p.execs > 0 && p.writes > 0)
            .count() as u64;
        self.totals.snapshots = self.snapshots.len() as u64;

        let final_map = self.snapshots.last().cloned().unwrap_or_default();
        let first_map = self.snapshots.first().cloned().unwrap_or_default();
        let regions = self.build_regions(&final_map, &first_map, &exec_lookup);
        let mut findings = findings(&regions, &self.totals);
        findings.extend(handler_findings(&self.pages, &self.srcs, &final_map));
        Ok(Report {
            totals: self.totals,
            findings,
            regions,
            pages: self.pages,
            snapshots: self.snapshots,
            srcs: self.srcs,
            instr: self.instr,
            instr_dropped: self.instr_dropped,
            edges: self.edges,
            arch: self.arch,
            trace_path: String::new(),
        })
    }

    fn build_regions(
        &self,
        final_map: &Snapshot,
        first_map: &Snapshot,
        _exec_lookup: &dyn Fn(u64) -> bool,
    ) -> Vec<Region> {
        struct Group {
            start: u64,
            end: u64,
            kind: Kind,
            map_name: String,
            pages: Vec<u64>,
        }
        let mut groups: Vec<Group> = Vec::new();
        let mut previous: Option<(u64, Kind, String)> = None;
        for (&page, stats) in &self.pages {
            let name = final_map
                .get(page * PAGE)
                .map(|m| m.name.clone())
                .unwrap_or_default();
            let kind = page_kind(stats, &name);
            let continues = previous
                .as_ref()
                .is_some_and(|(prev, prev_kind, prev_name)| {
                    *prev + 1 == page && *prev_kind == kind && *prev_name == name
                });
            if continues {
                let group = groups.last_mut().unwrap();
                group.end = (page + 1) * PAGE;
                group.pages.push(page);
            } else {
                groups.push(Group {
                    start: page * PAGE,
                    end: (page + 1) * PAGE,
                    kind,
                    map_name: name.clone(),
                    pages: vec![page],
                });
            }
            previous = Some((page, kind, name));
        }

        let mut regions = Vec::new();
        for group in groups {
            let mut region = Region {
                start: group.start,
                end: group.end,
                pages: group.pages.len() as u64,
                map_name: group.map_name.clone(),
                kind: group.kind.label(),
                kind_id: group.kind.order(),
                ..Default::default()
            };
            let first = first_map.get(group.start);
            let last = final_map.get(group.start);
            region.first_perms = first.map(|m| m.perms).unwrap_or(0);
            region.last_perms = last.map(|m| m.perms).unwrap_or(0);
            let mut coverage = 0u64;
            let mut sample_reads = 0u64;
            let mut sample_writes = 0u64;
            let mut pointer_hits = 0u64;
            let mut writer_pages: HashMap<u64, u64> = HashMap::new();
            let mut reader_pages: HashMap<u64, u64> = HashMap::new();
            for page in &group.pages {
                let stats = &self.pages[page];
                region.reads += stats.reads;
                region.writes += stats.writes;
                region.execs += stats.execs;
                region.bytes_read += stats.bytes_read;
                region.bytes_written += stats.bytes_written;
                region.zero_writes += stats.zero_writes;
                for (i, count) in stats.write_sizes.iter().enumerate() {
                    region.write_sizes[i] += count;
                    region.read_sizes[i] += stats.read_sizes[i];
                }
                region.first_write_seq = min_opt(region.first_write_seq, stats.first_write);
                region.first_exec_seq = min_opt(region.first_exec_seq, stats.first_exec);
                region.last_exec_seq = max_opt(region.last_exec_seq, stats.last_exec);
                coverage |= stats.write_coverage;
                sample_reads += stats.read_sample_len as u64;
                sample_writes += stats.write_sample_len as u64;
                pointer_hits += stats.pointer_reads + stats.pointer_writes;
                for &(writer, count) in &stats.writers[..stats.writer_len] {
                    *writer_pages.entry(writer).or_default() += count;
                }
                for &(reader, count) in &stats.readers[..stats.reader_len] {
                    *reader_pages.entry(reader).or_default() += count;
                }
            }
            region.distinct_writers = writer_pages.len();
            let mut writers: Vec<(u64, u64)> = writer_pages.into_iter().collect();
            writers.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
            writers.truncate(6);
            region.writers = writers;
            region.distinct_readers = reader_pages.len();
            let mut readers: Vec<(u64, u64)> = reader_pages.into_iter().collect();
            readers.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
            readers.truncate(6);
            region.readers = readers;
            region.pointer_percent = if sample_reads + sample_writes > 0 {
                pointer_hits as f32 * 100.0 / (sample_reads + sample_writes) as f32
            } else {
                0.0
            };
            let written_bytes = region.pages * PAGE;
            region.write_coverage =
                (coverage.count_ones() as f32 * 64.0 * 100.0 / written_bytes as f32).min(100.0);
            region.labels = labels(&region, &group.kind);
            regions.push(region);
        }

        regions.sort_by(|a, b| {
            let a_key = (a.kind_id, std::cmp::Reverse(a.execs + a.writes));
            let b_key = (b.kind_id, std::cmp::Reverse(b.execs + b.writes));
            a_key.cmp(&b_key)
        });
        regions
    }
}

fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn max_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

fn page_kind(stats: &PageStats, name: &str) -> Kind {
    let exec = stats.execs > 0;
    let write = stats.writes > 0;
    let read = stats.reads > 0;
    let pointer = if stats.read_sample_len + stats.write_sample_len > 0 {
        (stats.pointer_reads + stats.pointer_writes) as f32
            / (stats.read_sample_len + stats.write_sample_len) as f32
    } else {
        0.0
    };
    if exec && write {
        Kind::SelfMod
    } else if exec {
        Kind::Code
    } else if is_stack(name) {
        Kind::Stack
    } else if is_heap(name) {
        Kind::Heap
    } else if write {
        if stats.distinct_writers >= 2
            && stats.writes >= 16
            && (stats.write_sizes[3] + stats.write_sizes[4..8].iter().sum::<u64>()) * 2
                >= stats.writes
        {
            Kind::Context
        } else {
            Kind::WrittenData
        }
    } else if read {
        if opcode_stream(stats) {
            Kind::Bytecode
        } else if pointer >= 0.25 {
            Kind::PointerData
        } else {
            Kind::ReadData
        }
    } else {
        Kind::Other
    }
}

/// A page consumed mostly as one-byte reads by several code pages looks like
/// a VM opcode stream: the dispatcher fetches handlers, and the handlers read
/// opcode/displacement bytes from a compact data page.
fn opcode_stream(stats: &PageStats) -> bool {
    if stats.writes != 0 || stats.execs != 0 || stats.reads < 512 {
        return false;
    }
    if stats.distinct_readers < 2 {
        return false;
    }
    let one_byte = stats.read_sizes[0];
    if one_byte * 10 < stats.reads * 8 {
        return false;
    }
    let sampled = stats.read_sample_len + stats.write_sample_len;
    let pointer = if sampled > 0 {
        (stats.pointer_reads + stats.pointer_writes) as f32 / sampled as f32
    } else {
        0.0
    };
    pointer < 0.2
}

fn labels(region: &Region, kind: &Kind) -> Vec<&'static str> {
    let mut out = Vec::new();
    match kind {
        Kind::Code => out.push("executed, never written"),
        Kind::SelfMod => {
            if let (Some(w), Some(x)) = (region.first_write_seq, region.first_exec_seq) {
                if w < x {
                    out.push("written before first execution (unpacked)");
                } else {
                    out.push("written after first execution (patched)");
                }
            }
            out.push("executed and written");
        }
        Kind::Bytecode => out.push("one-byte reads from multiple code pages"),
        Kind::PointerData => out.push("read values point into executable pages"),
        Kind::Context => out.push("many code pages write this region"),
        Kind::Stack => out.push("map name identifies a stack"),
        Kind::Heap => out.push("map name identifies a heap"),
        Kind::WrittenData => out.push("written, never executed"),
        Kind::ReadData => out.push("read, never written or executed"),
        Kind::Other => out.push("touched without a data or fetch access"),
    }
    if region.zero_writes > 0 && region.writes > 0 {
        out.push("contains zero-valued writes");
    }
    if region.write_sizes[3] > 0 {
        out.push("8-byte stores");
    }
    if region.write_sizes[4] + region.write_sizes[5] + region.write_sizes[6] > 0 {
        out.push("vector stores");
    }
    out
}

impl Region {
    // The stable `kind_id` set at construction orders regions by kind.
}

fn findings(regions: &[Region], totals: &Totals) -> Vec<String> {
    let mut out = Vec::new();
    let code: Vec<&Region> = regions
        .iter()
        .filter(|r| r.kind == "executable code")
        .collect();
    if let Some(biggest) = code.iter().max_by_key(|r| r.execs) {
        out.push(format!(
            "largest executable region: {} ({} pages, {} fetches, {} writes){}",
            range(biggest.start, biggest.end),
            biggest.pages,
            count(biggest.execs),
            count(biggest.writes),
            name_suffix(&biggest.map_name)
        ));
    }
    let self_mod: Vec<&Region> = regions
        .iter()
        .filter(|r| r.kind == "self-modifying code")
        .collect();
    for region in self_mod.iter().take(4) {
        out.push(format!(
            "self-modifying/unpacking candidate: {} ({} writes, first write {}, first fetch {})",
            range(region.start, region.end),
            count(region.writes),
            seq(region.first_write_seq),
            seq(region.first_exec_seq)
        ));
    }
    for region in regions
        .iter()
        .filter(|r| r.kind == "pointer / dispatch table")
        .take(4)
    {
        out.push(format!(
            "pointer/dispatch table candidate: {} ({:.0}% of sampled values point into executable pages)",
            range(region.start, region.end),
            region.pointer_percent
        ));
    }
    for region in regions
        .iter()
        .filter(|r| r.kind == "multi-writer context")
        .take(4)
    {
        out.push(format!(
            "writable context candidate: {} ({} writes from {} code pages, {:.0}% byte coverage)",
            range(region.start, region.end),
            count(region.writes),
            region.distinct_writers,
            region.write_coverage
        ));
    }
    for region in regions.iter().filter(|r| r.kind == "opcode stream").take(4) {
        out.push(format!(
            "opcode-stream candidate: {} ({} single-byte reads from {} code pages)",
            range(region.start, region.end),
            count(region.read_sizes[0]),
            region.distinct_readers
        ));
    }
    if totals.pages_self_modifying > 0 {
        out.push(format!(
            "{} page(s) were both executed and written; those pages hold unpackers or patches",
            totals.pages_self_modifying
        ));
    }
    out
}

fn opcode_regions<'a>(report: &'a Report) -> Vec<&'a Region> {
    report
        .regions
        .iter()
        .filter(|region| region.kind_id == 2)
        .collect()
}

fn opcode_readers(report: &Report, regions: &[&Region]) -> Vec<(u64, u64)> {
    let mut counts: HashMap<u64, u64> = HashMap::new();
    for region in regions {
        for page in region.start / PAGE..region.end / PAGE {
            if let Some(stats) = report.pages.get(&page) {
                for &(source, count) in &stats.readers[..stats.reader_len] {
                    *counts.entry(source).or_default() += count;
                }
            }
        }
    }
    let mut readers: Vec<(u64, u64)> = counts.into_iter().collect();
    readers.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
    readers
}

fn handler_findings(
    pages: &BTreeMap<u64, PageStats>,
    srcs: &HashMap<u64, SrcStats>,
    map: &Snapshot,
) -> Vec<String> {
    let mut candidates: Vec<(&u64, &SrcStats)> = srcs
        .iter()
        .filter(|(page, src)| {
            src.writes >= 32 && pages.get(page).is_some_and(|stats| stats.execs > 0)
        })
        .collect();
    candidates.sort_by_key(|(_, src)| std::cmp::Reverse(src.writes));
    let mut out = Vec::new();
    for (page, src) in candidates.into_iter().take(6) {
        // A handler's busiest target is often the stack. Prefer its busiest
        // target that looks like a context, a pointer table, or code: those are
        // the writes that identify a virtual machine's handler set.
        let mut best: Option<(u64, u64, Kind)> = None;
        for &(target, count) in &src.targets[..src.target_len] {
            let name = map
                .get(target * PAGE)
                .map(|m| m.name.as_str())
                .unwrap_or("");
            let kind = pages
                .get(&target)
                .map(|stats| page_kind(stats, name))
                .unwrap_or(Kind::Other);
            if !matches!(kind, Kind::PointerData | Kind::Context | Kind::SelfMod) {
                continue;
            }
            if best.is_none_or(|(_, best_count, _)| count > best_count) {
                best = Some((target, count, kind));
            }
        }
        let Some((target, count, kind)) = best else {
            continue;
        };
        let what = match kind {
            Kind::PointerData => "writes a pointer table",
            Kind::Context => "writes a shared context",
            Kind::Stack => "writes the stack",
            Kind::Heap => "writes the heap",
            Kind::SelfMod => "writes executable code",
            _ => "writes data",
        };
        out.push(format!(
            "handler candidate: {:#x} {what} at {} ({} of {} writes, {} distinct target page(s))",
            page * PAGE,
            range(target * PAGE, (target + 1) * PAGE),
            count,
            src.writes,
            src.target_len
        ));
    }
    out
}

fn name_suffix(name: &str) -> String {
    if name.is_empty() {
        String::new()
    } else {
        format!(" [{name}]")
    }
}

fn is_stack(name: &str) -> bool {
    name.contains("stack")
}

fn is_heap(name: &str) -> bool {
    name.contains("heap")
}

fn mark_coverage(mask: &mut u64, offset: u64, size: u8) {
    if size == 0 {
        return;
    }
    let first = (offset / 64).min(63);
    let last = ((offset + u64::from(size) - 1) / 64).min(63);
    for bit in first..=last {
        *mask |= 1u64 << bit;
    }
}

fn size_index(size: u8) -> usize {
    match size {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        16 => 4,
        32 => 5,
        64 => 6,
        128 => 7,
        _ => 8,
    }
}

fn range(start: u64, end: u64) -> String {
    format!("{start:#x}-{end:#x}")
}

fn seq(value: Option<u64>) -> String {
    value.map_or_else(|| "never".to_string(), |v| format!("#{v}"))
}

fn count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

fn bytes(n: u64) -> String {
    if n >= 1 << 30 {
        format!("{:.2} GiB", n as f64 / (1u64 << 30) as f64)
    } else if n >= 1 << 20 {
        format!("{:.2} MiB", n as f64 / (1u64 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn perms(bits: u8) -> String {
    format!(
        "{}{}{}",
        if bits & 1 != 0 { 'r' } else { '-' },
        if bits & 2 != 0 { 'w' } else { '-' },
        if bits & 4 != 0 { 'x' } else { '-' }
    )
}

fn size_summary(sizes: &[u64; WRITE_SIZE_BUCKETS]) -> String {
    let names = ["1B", "2B", "4B", "8B", "16B", "32B", "64B", "128B", "wide"];
    let mut parts = Vec::new();
    for (i, &n) in sizes.iter().enumerate() {
        if n > 0 {
            parts.push(format!("{}×{}", names[i], count(n)));
        }
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

impl Report {
    /// Renders the terminal report.
    pub fn render(&self, opts: &Options) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "rax trace map — {} accesses, {} pages, {}",
            count(self.totals.accesses),
            self.totals.pages_touched,
            bytes(self.totals.trace_bytes)
        );
        let _ = writeln!(
            out,
            "  reads {} ({}), writes {} ({}), fetches {}",
            count(self.totals.reads),
            bytes(self.totals.bytes_read),
            count(self.totals.writes),
            bytes(self.totals.bytes_written),
            count(self.totals.execs)
        );
        let _ = writeln!(
            out,
            "  pages: executed {}, written {}, both {}; map snapshots {}",
            self.totals.pages_executed,
            self.totals.pages_written,
            self.totals.pages_self_modifying,
            self.totals.snapshots
        );
        if !self.trace_path.is_empty() {
            let _ = writeln!(out, "  trace: {}", self.trace_path);
        }
        let _ = writeln!(out);

        let opcode_regions = opcode_regions(self);
        let readers = opcode_readers(self, &opcode_regions);
        let stream = opcode_regions
            .iter()
            .copied()
            .max_by_key(|region| region.read_sizes[0]);
        let dispatcher = readers.first().copied();
        let unpacker = self
            .regions
            .iter()
            .filter(|region| region.kind_id == 1)
            .max_by_key(|region| region.writes);
        if stream.is_some() || self.vm_cluster().is_some() {
            let _ = writeln!(out, "VM PROFILE");
            if let Some((start, end, pages, fetches, reads)) = self.vm_cluster() {
                let _ = writeln!(
                    out,
                    "  code cluster   {}  {} exec pages, {} fetches, {} reads",
                    range(start, end),
                    pages,
                    count(fetches),
                    count(reads)
                );
            }
            if let Some(region) = stream {
                let _ = writeln!(
                    out,
                    "  opcode stream  {}  {}, {} single-byte reads ({} of reads), {} code pages",
                    range(region.start, region.end),
                    bytes(region.end - region.start),
                    count(region.read_sizes[0]),
                    percent(region.read_sizes[0], region.reads),
                    region.distinct_readers
                );
            }
            if let Some((page, hits)) = dispatcher {
                let fetches = self
                    .pages
                    .get(&page)
                    .map_or_else(|| "0".into(), |stats| count(stats.execs));
                let _ = writeln!(
                    out,
                    "  dispatch       {:#x}  {} reads into the stream, {} fetches",
                    page * PAGE,
                    count(hits),
                    fetches
                );
            }
            if let Some(region) = unpacker {
                let _ = writeln!(
                    out,
                    "  unpacker       {}  {} writes, first write {}, first fetch {}",
                    range(region.start, region.end),
                    count(region.writes),
                    seq(region.first_write_seq),
                    seq(region.first_exec_seq)
                );
            }
            if !readers.is_empty() {
                let _ = writeln!(out, "  stream readers:");
                for (page, hits) in readers.iter().take(12) {
                    let stats = self.pages.get(page);
                    let _ = writeln!(
                        out,
                        "    {:#016x}  {:>9} reads  {:>9} fetches  {:>9} writes{}",
                        page * PAGE,
                        count(*hits),
                        stats.map_or_else(|| "0".into(), |stats| count(stats.execs)),
                        stats.map_or_else(|| "0".into(), |stats| count(stats.writes)),
                        if Some(*page) == dispatcher.map(|(page, _)| page) {
                            "  <- dispatch candidate"
                        } else {
                            ""
                        }
                    );
                }
            }
            let _ = writeln!(out);
        }

        if !self.edges.is_empty() {
            out.push_str(&self.render_edges());
        }

        if !self.instr.is_empty() {
            out.push_str(&self.render_hot_instructions());
        }

        if !self.findings.is_empty() {
            let _ = writeln!(out, "FINDINGS");
            for finding in &self.findings {
                let _ = writeln!(out, "  • {finding}");
            }
            let _ = writeln!(out);
        }

        if opts.show_map {
            out.push_str(&self.render_map());
            out.push('\n');
        }

        let _ = writeln!(
            out,
            "{:<4} {:<37} {:>9} {:<22} {:>9} {:>9} {:>9} {:<10} {}",
            "#", "range", "size", "map", "fetches", "reads", "writes", "pattern", "writers"
        );
        let _ = writeln!(out, "{}", "-".repeat(150));
        let mut shown = 0usize;
        for (index, region) in self.regions.iter().enumerate() {
            if region.writes < opts.min_writes {
                continue;
            }
            if !opts.all && shown >= opts.top {
                continue;
            }
            shown += 1;
            let _ = writeln!(
                out,
                "{:<4} {:<37} {:>9} {:<22} {:>9} {:>9} {:>9} {:<10} {}",
                index,
                range(region.start, region.end),
                bytes(region.end - region.start),
                trimmed_left(&region.map_name, 22),
                count(region.execs),
                count(region.reads),
                count(region.writes),
                region.kind,
                writer_summary(region)
            );
        }
        if shown < self.regions.len() {
            let _ = writeln!(
                out,
                "... {} more region(s); use --all or raise --top",
                self.regions.len() - shown
            );
        }

        if let Some(addr) = opts.region {
            out.push('\n');
            out.push_str(&self.render_region(addr));
        }
        if let Some(addr) = opts.page {
            out.push('\n');
            out.push_str(&self.render_page(addr));
        }
        out
    }

    /// Ranks individual instruction addresses by fetch count.
    ///
    /// Page-level counts say where code lives; this says which instruction in
    /// that code is the loop. A virtualised binary shows its dispatcher as one
    /// or two very hot addresses and each handler as a much colder entry.
    /// Ranks page-to-page execution changes out of the dispatch page.
    ///
    /// One bytecode dispatch produces one change into the selected handler
    /// page, so these counts approximate how often each handler ran: the shape
    /// of a virtual machine's instruction mix, read from control flow instead
    /// of from the bytecode itself.
    fn render_edges(&self) -> String {
        let readers = opcode_readers(self, &opcode_regions(self));
        let dispatcher = readers.first().map(|&(page, _)| page);
        let mut edges: Vec<((u64, u64), u64)> = self
            .edges
            .iter()
            .filter(|((from, to), _)| from != to && dispatcher.is_none_or(|page| *from == page))
            .map(|(&edge, &count)| (edge, count))
            .collect();
        if edges.is_empty() {
            return String::new();
        }
        let transitions: u64 = self.edges.values().sum();
        edges.sort_by_key(|&((from, to), count)| (std::cmp::Reverse(count), from, to));
        let mut out = String::new();
        let _ = writeln!(
            out,
            "DISPATCH EDGES ({} page-to-page transitions over {} edges{})",
            count(transitions),
            count(self.edges.len() as u64),
            if dispatcher.is_some() {
                "; entries out of the dispatch candidate"
            } else {
                ""
            }
        );
        let _ = writeln!(
            out,
            "  {:<6} {:<20} {:<20} {:>10} {:>7}  {}",
            "#", "from", "to", "entries", "share", "target"
        );
        for (index, ((from, to), entries)) in edges.iter().take(12).enumerate() {
            let note = if let Some(&(_, reads)) = readers.iter().find(|&&(page, _)| page == *to) {
                format!("{} stream reads", count(reads))
            } else {
                let role = self.page_role(*to);
                if self.pages.get(to).is_some_and(|stats| stats.writes > 0) {
                    format!("{role}, writes data")
                } else {
                    role
                }
            };
            let _ = writeln!(
                out,
                "  {:<6} {:#018x} {:#018x} {:>10} {:>7}  {}",
                index,
                from * PAGE,
                to * PAGE,
                count(*entries),
                percent1(*entries, transitions),
                note
            );
        }
        let _ = writeln!(out);
        out
    }

    /// Shows where execution mass sits at instruction granularity.
    ///
    /// A virtualised binary executes long straight-line runs inside one page
    /// (its handlers) and short loops in another (its dispatcher), so a flat
    /// per-address ranking degenerates into sixteen identical counts. Grouping
    /// addresses into runs keeps a loop body on one line and leaves branched-to
    /// entries standing alone, which is what a reader is looking for.
    fn render_hot_instructions(&self) -> String {
        let hot = self.hot_instructions(HOT_ADDRESSES);
        if hot.is_empty() {
            return String::new();
        }
        let runs = instruction_runs(&hot);
        let mut out = String::new();
        let tracked: u64 = self.instr.values().sum();
        let _ = writeln!(
            out,
            "HOT INSTRUCTIONS ({} distinct addresses, {} fetches; top {} runs)",
            count(self.instr.len() as u64),
            count(tracked),
            runs.len()
        );
        let _ = writeln!(
            out,
            "  {:<4} {:<44} {:>5} {:>10} {:>7}  {}",
            "#", "run", "insns", "fetches", "share", "page"
        );
        let readers = opcode_readers(self, &opcode_regions(self));
        let dispatcher = readers.first().map(|&(page, _)| page);
        for (index, run) in runs.iter().enumerate() {
            let page = run.start / PAGE;
            let note = if Some(page) == dispatcher {
                "dispatch candidate".to_string()
            } else if let Some(&(_, reads)) = readers.iter().find(|&&(p, _)| p == page) {
                format!("{} stream reads", count(reads))
            } else {
                self.page_role(page)
            };
            let span = if run.start == run.end {
                format!("{:#018x}", run.start)
            } else {
                format!("{:#018x}-{:x}", run.start, run.end)
            };
            let _ = writeln!(
                out,
                "  {:<4} {:<44} {:>5} {:>10} {:>7}  {}",
                index,
                span,
                run.insns,
                count(run.fetches),
                percent1(run.fetches, self.totals.execs),
                note
            );
        }
        if self.instr_dropped > 0 {
            let _ = writeln!(
                out,
                "  ({} fetches at untracked addresses; table capped at {})",
                count(self.instr_dropped),
                count(MAX_INSTR as u64)
            );
        }
        let _ = writeln!(out);
        out
    }

    fn hot_instructions(&self, limit: usize) -> Vec<(u64, u64)> {
        let mut hot: Vec<(u64, u64)> = self.instr.iter().map(|(&a, &c)| (a, c)).collect();
        hot.sort_by_key(|&(addr, count)| (std::cmp::Reverse(count), addr));
        hot.truncate(limit);
        hot
    }

    fn render_map(&self) -> String {
        let mut out = String::new();
        if self.pages.is_empty() {
            return out;
        }
        let pages: Vec<u64> = self.pages.keys().copied().collect();
        // Cluster touched pages so sparse address spaces (image at 0x1000000,
        // stack near 0x7fff_ffff...) do not waste thousands of empty rows. A
        // gap of more than 2 MiB starts a new cluster.
        const GAP: u64 = 512;
        let mut clusters: Vec<(u64, u64)> = Vec::new();
        let mut first = pages[0];
        let mut previous = pages[0];
        for &page in &pages[1..] {
            if page - previous > GAP {
                clusters.push((first, previous));
                first = page;
            }
            previous = page;
        }
        clusters.push((first, previous));

        let opcode = opcode_regions(self);
        let opcode_pages: BTreeSet<u64> = opcode
            .iter()
            .flat_map(|region| region.start / PAGE..region.end / PAGE)
            .collect();
        let dispatcher = opcode_readers(self, &opcode).first().map(|&(page, _)| page);
        let _ = writeln!(
            out,
            "ADDRESS-SPACE MAP (X=code  S=code+write  O=opcode stream  *=dispatch  W=write  r=read)"
        );
        for (start_page, end_page) in clusters {
            let span = end_page - start_page + 1;
            // At most 20 rows of 100 characters for this cluster.
            let mut cell_pages = ((span + 1999) / 2000).max(1);
            cell_pages = cell_pages.next_power_of_two();
            let cells = ((span + cell_pages - 1) / cell_pages) as usize;
            let mut buckets = vec![(0u64, 0u64, 0u64, 0u64); cells];
            let mut special = vec![0u8; cells];
            for &page in &opcode_pages {
                if page >= start_page && page <= end_page {
                    let idx = ((page - start_page) / cell_pages) as usize;
                    if idx < special.len() {
                        special[idx] = 1;
                    }
                }
            }
            if let Some(page) = dispatcher {
                if page >= start_page && page <= end_page {
                    let idx = ((page - start_page) / cell_pages) as usize;
                    if idx < special.len() {
                        special[idx] = 2;
                    }
                }
            }
            for (&page, stats) in self.pages.range(start_page..=end_page) {
                let idx = ((page - start_page) / cell_pages) as usize;
                if idx < buckets.len() {
                    buckets[idx].0 += stats.execs;
                    buckets[idx].1 += stats.writes;
                    buckets[idx].2 += stats.reads;
                    buckets[idx].3 += 1;
                }
            }
            let _ = writeln!(
                out,
                "-- {:#x}-{:#x}  (1 char = {})",
                start_page * PAGE,
                (end_page + 1) * PAGE,
                bytes(cell_pages * PAGE)
            );
            for (row, chunk) in buckets.chunks(100).enumerate() {
                let addr = (start_page + row as u64 * 100 * cell_pages) * PAGE;
                let mut line = String::new();
                for (offset, &(exec, write, read, _)) in chunk.iter().enumerate() {
                    let special = special.get(row * 100 + offset).copied().unwrap_or(0);
                    line.push(if special == 2 {
                        '*'
                    } else if special == 1 {
                        'O'
                    } else if exec > 0 && write > 0 {
                        'S'
                    } else if exec > 0 {
                        'X'
                    } else if write > 0 {
                        'W'
                    } else if read > 0 {
                        'r'
                    } else {
                        '.'
                    });
                }
                let _ = writeln!(out, "{addr:#018x} {line}");
            }
        }
        out
    }

    fn render_region(&self, addr: u64) -> String {
        let Some(region) = self
            .regions
            .iter()
            .find(|r| addr >= r.start && addr < r.end)
        else {
            return format!("no region contains {addr:#x}\n");
        };
        let mut out = String::new();
        let _ = writeln!(
            out,
            "REGION {}  {}  ({} pages, {})",
            range(region.start, region.end),
            region.kind,
            region.pages,
            bytes(region.end - region.start)
        );
        let _ = writeln!(
            out,
            "  map: {}  perms: {} -> {}",
            if region.map_name.is_empty() {
                "<anonymous>"
            } else {
                &region.map_name
            },
            perms(region.first_perms),
            perms(region.last_perms)
        );
        let _ = writeln!(
            out,
            "  accesses: {} fetches, {} reads ({}), {} writes ({})",
            count(region.execs),
            count(region.reads),
            bytes(region.bytes_read),
            count(region.writes),
            bytes(region.bytes_written)
        );
        let _ = writeln!(
            out,
            "  write widths: {}  zero-valued: {}  coverage: {:.0}%",
            size_summary(&region.write_sizes),
            count(region.zero_writes),
            region.write_coverage
        );
        let _ = writeln!(
            out,
            "  ordering: first write {}, first fetch {}, last fetch {}",
            seq(region.first_write_seq),
            seq(region.first_exec_seq),
            seq(region.last_exec_seq)
        );
        let _ = writeln!(
            out,
            "  sampled values pointing into executable pages: {:.0}%",
            region.pointer_percent
        );
        for label in &region.labels {
            let _ = writeln!(out, "  • {label}");
        }
        if !region.writers.is_empty() {
            let _ = writeln!(out, "  top writers:");
            for (page, count) in &region.writers {
                let name = self.map_name(*page * PAGE);
                let _ = writeln!(
                    out,
                    "    {:#x} {:<28} {} writes",
                    page * PAGE,
                    trimmed_left(&name, 28),
                    count,
                );
            }
        }
        let _ = writeln!(out, "  pages:");
        for page in (region.start / PAGE)..(region.end / PAGE) {
            if let Some(stats) = self.pages.get(&page) {
                let _ = writeln!(
                    out,
                    "    {:#x}  X {:>8}  R {:>8}  W {:>8}  {}",
                    page * PAGE,
                    count(stats.execs),
                    count(stats.reads),
                    count(stats.writes),
                    page_flags(stats)
                );
            }
        }
        out
    }

    fn render_page(&self, addr: u64) -> String {
        let page = addr / PAGE;
        let Some(stats) = self.pages.get(&page) else {
            return format!("page {:#x} was never touched\n", page * PAGE);
        };
        let mut out = String::new();
        let _ = writeln!(out, "PAGE {:#x}", page * PAGE);
        let _ = writeln!(
            out,
            "  fetches {}  reads {}  writes {}  ({})",
            count(stats.execs),
            count(stats.reads),
            count(stats.writes),
            self.map_name(page * PAGE)
        );
        let _ = writeln!(
            out,
            "  first write {}  first fetch {}  last write {}",
            seq(stats.first_write),
            seq(stats.first_exec),
            seq(stats.last_write)
        );
        let _ = writeln!(
            out,
            "  write widths: {}  zero-valued: {}",
            size_summary(&stats.write_sizes),
            count(stats.zero_writes)
        );
        let _ = writeln!(
            out,
            "  coverage: writes {:.0}%  fetch {:.0}%",
            stats.write_coverage.count_ones() as f32 / 64.0 * 100.0,
            stats.exec_coverage.count_ones() as f32 / 64.0 * 100.0
        );
        if stats.writer_len > 0 {
            let _ = writeln!(out, "  writers:");
            for &(writer, count) in &stats.writers[..stats.writer_len] {
                let _ = writeln!(
                    out,
                    "    {:#x}  {} writes  {}",
                    writer * PAGE,
                    count,
                    self.map_name(writer * PAGE)
                );
            }
        }
        let hot = self.page_hot_instructions(page, 8);
        if !hot.is_empty() {
            let _ = writeln!(out, "  instruction fetches:");
            for (addr, fetches) in hot {
                let _ = writeln!(
                    out,
                    "    {:#018x}  {:>12}  {:.1}% of page",
                    addr,
                    count(fetches),
                    fetches as f64 / stats.execs.max(1) as f64 * 100.0
                );
            }
        }
        out
    }

    /// Ranks instruction addresses inside `page` by fetch count.
    fn page_hot_instructions(&self, page: u64, limit: usize) -> Vec<(u64, u64)> {
        let mut hot: Vec<(u64, u64)> = self
            .instr
            .iter()
            .filter(|(addr, _)| **addr / PAGE == page)
            .map(|(&addr, &count)| (addr, count))
            .collect();
        hot.sort_by_key(|&(addr, count)| (std::cmp::Reverse(count), addr));
        hot.truncate(limit);
        hot
    }

    /// Short role of the page, for one-line annotations: the region kind when
    /// the page belongs to one, otherwise the mapping name.
    fn page_role(&self, page: u64) -> String {
        let start = page * PAGE;
        if let Some(region) = self
            .regions
            .iter()
            .find(|region| region.start <= start && start < region.end)
        {
            return region.kind.to_string();
        }
        trimmed_left(&self.map_name(start), 28)
    }

    fn map_name(&self, addr: u64) -> String {
        if let Some(snapshot) = self.snapshots.last() {
            if let Some(range) = snapshot.get(addr) {
                if !range.name.is_empty() {
                    return range.name.clone();
                }
            }
        }
        String::new()
    }

    fn to_json(&self) -> String {
        let regions: Vec<serde_json::Value> = self
            .regions
            .iter()
            .map(|r| {
                serde_json::json!({
                    "start": format!("{:#x}", r.start),
                    "end": format!("{:#x}", r.end),
                    "pages": r.pages,
                    "kind": r.kind,
                    "map": r.map_name,
                    "first_perms": perms(r.first_perms),
                    "last_perms": perms(r.last_perms),
                    "execs": r.execs,
                    "reads": r.reads,
                    "writes": r.writes,
                    "bytes_read": r.bytes_read,
                    "bytes_written": r.bytes_written,
                    "write_widths": size_summary(&r.write_sizes),
                    "zero_writes": r.zero_writes,
                    "pointer_percent": r.pointer_percent,
                    "write_coverage_percent": r.write_coverage,
                    "distinct_writers": r.distinct_writers,
                    "top_writers": r.writers.iter().map(|(p, c)| serde_json::json!({
                        "page": format!("{:#x}", p * PAGE),
                        "writes": c,
                    })).collect::<Vec<_>>(),
                    "labels": r.labels,
                })
            })
            .collect();
        let mut edges: Vec<((u64, u64), u64)> = self
            .edges
            .iter()
            .map(|(&edge, &count)| (edge, count))
            .collect();
        edges.sort_by_key(|&((from, to), count)| (std::cmp::Reverse(count), from, to));
        let dispatch_edges: Vec<serde_json::Value> = edges
            .iter()
            .take(64)
            .map(|&((from, to), entries)| {
                serde_json::json!({
                    "from": format!("{:#x}", from * PAGE),
                    "to": format!("{:#x}", to * PAGE),
                    "entries": entries,
                })
            })
            .collect();
        let hot_instructions: Vec<serde_json::Value> = self
            .hot_instructions(64)
            .into_iter()
            .map(|(addr, fetches)| {
                serde_json::json!({
                    "address": format!("{:#x}", addr),
                    "page": format!("{:#x}", addr / PAGE * PAGE),
                    "fetches": fetches,
                })
            })
            .collect();
        let json = serde_json::json!({
            "format": "raxtrace",
            "arch": if self.arch == ARCH_X86_64 { "x86_64" } else { "unknown" },
            "totals": {
                "accesses": self.totals.accesses,
                "reads": self.totals.reads,
                "writes": self.totals.writes,
                "execs": self.totals.execs,
                "bytes_read": self.totals.bytes_read,
                "bytes_written": self.totals.bytes_written,
                "pages_touched": self.totals.pages_touched,
                "pages_executed": self.totals.pages_executed,
                "pages_written": self.totals.pages_written,
                "pages_self_modifying": self.totals.pages_self_modifying,
            },
            "findings": self.findings,
            "distinct_instructions": self.instr.len(),
            "hot_instructions": hot_instructions,
            "dispatch_edges": dispatch_edges,
            "regions": regions,
        });
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| json.to_string())
    }

    fn vm_cluster(&self) -> Option<(u64, u64, u64, u64, u64)> {
        let anchor = self
            .regions
            .iter()
            .filter(|region| region.kind_id == 0)
            .max_by_key(|region| region.execs)?;
        let name = anchor.map_name.clone();
        let anchor_page = anchor.start / PAGE;
        let mut first = u64::MAX;
        let mut last = 0u64;
        let mut pages = 0u64;
        let mut fetches = 0u64;
        let mut reads = 0u64;
        for (&page, stats) in &self.pages {
            if stats.execs == 0 {
                continue;
            }
            let page_name = self.map_name(page * PAGE);
            if !name.is_empty() && page_name != name {
                continue;
            }
            if name.is_empty() && page.abs_diff(anchor_page) > 8192 {
                continue;
            }
            first = first.min(page);
            last = last.max(page);
            pages += 1;
            fetches += stats.execs;
            reads += stats.reads;
        }
        (pages > 0).then(|| (first * PAGE, (last + 1) * PAGE, pages, fetches, reads))
    }
}

/// One straight-line stretch of executed instructions.
struct InstructionRun {
    start: u64,
    end: u64,
    insns: u64,
    fetches: u64,
}

/// Groups sampled instruction addresses into straight-line runs.
///
/// Addresses are already ranked by count; sorting them by address and joining
/// neighbours within [`RUN_GAP`] reconstructs the loop bodies and handler
/// stretches they came from. Branched-to entries stay on their own line.
fn instruction_runs(hot: &[(u64, u64)]) -> Vec<InstructionRun> {
    let mut sorted: Vec<(u64, u64)> = hot.to_vec();
    sorted.sort_by_key(|&(addr, _)| addr);
    let mut runs: Vec<InstructionRun> = Vec::new();
    for (addr, fetches) in sorted {
        let joins = runs.last().is_some_and(|run| {
            addr > run.end && addr - run.end <= RUN_GAP && addr / PAGE == run.start / PAGE
        });
        if joins {
            let run = runs.last_mut().unwrap();
            run.end = addr;
            run.insns += 1;
            run.fetches += fetches;
        } else {
            runs.push(InstructionRun {
                start: addr,
                end: addr,
                insns: 1,
                fetches,
            });
        }
    }
    runs.sort_by_key(|run| std::cmp::Reverse(run.fetches));
    runs.truncate(8);
    runs
}

fn percent1(part: u64, total: u64) -> String {
    if total == 0 {
        return "-".into();
    }
    format!("{:.1}%", part as f64 / total as f64 * 100.0)
}

fn percent(part: u64, total: u64) -> String {
    if total == 0 {
        "0%".into()
    } else {
        format!("{:.0}%", part as f64 * 100.0 / total as f64)
    }
}

fn trimmed_left(text: &str, width: usize) -> String {
    if text.is_empty() {
        return "-".into();
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.into();
    }
    let start = chars.len() - width.saturating_sub(1);
    format!("…{}", chars[start..].iter().collect::<String>())
}

fn writer_summary(region: &Region) -> String {
    let mut parts = Vec::new();
    for (page, count) in region.writers.iter().take(2) {
        parts.push(format!("{:#x}×{}", page * PAGE, count));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(", ")
    }
}

fn page_flags(stats: &PageStats) -> String {
    let mut flags = Vec::new();
    if stats.writes > 0 {
        if stats.execs == 0 {
            flags.push("written, never fetched");
        } else {
            flags.push(if stats.writes_after_exec > 0 {
                "written after fetch"
            } else {
                "written before fetch"
            });
        }
    }
    if stats.pointer_reads + stats.pointer_writes > 0 {
        flags.push("pointer-like values");
    }
    if stats.writes == 0 && stats.first_read.is_some() {
        flags.push("read-only in this page");
    }
    if flags.is_empty() {
        "-".into()
    } else {
        flags.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn header() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&ARCH_X86_64.to_le_bytes());
        out
    }

    fn record(out: &mut Vec<u8>, tag: u8, aux: u8, a: u64, b: u64, c: u64) {
        out.push(tag);
        out.push(aux);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(&b.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }

    #[test]
    fn classifies_code_context_and_pointer_table() {
        let mut bytes = header();
        bytes.push(TAG_SNAPSHOT);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        // code page 0x1000
        record(&mut bytes, TAG_EXEC, 4, 0x1000, 0, 0x1000);
        record(&mut bytes, TAG_EXEC, 4, 0x1010, 0, 0x1010);
        // context page 0x8000 written from code pages 0x1000 and 0x2000
        for i in 0..32u64 {
            let rip = if i % 2 == 0 { 0x1000 } else { 0x2000 };
            record(&mut bytes, TAG_WRITE, 8, 0x8000 + i * 8, 0x1000 + i, rip);
        }
        record(&mut bytes, TAG_EXEC, 4, 0x2000, 0, 0x2000);
        record(&mut bytes, TAG_EXEC, 4, 0x2010, 0, 0x2010);
        // self-modifying page 0x7000: fetched, patched, fetched again
        record(&mut bytes, TAG_EXEC, 4, 0x7000, 0, 0x7000);
        record(&mut bytes, TAG_WRITE, 8, 0x7010, 0xdead_beef, 0x7000);
        record(&mut bytes, TAG_EXEC, 4, 0x7000, 0, 0x7000);
        // pointer table page 0x9000 read from a third code page
        record(&mut bytes, TAG_EXEC, 4, 0x3000, 0, 0x3000);
        for i in 0..8u64 {
            record(
                &mut bytes,
                TAG_READ,
                8,
                0x9000 + i * 8,
                0x1000 + i * 0x10,
                0x3000,
            );
        }
        let mut cursor = Cursor::new(bytes);
        let report = analyze_reader(&mut cursor).unwrap();
        assert_eq!(report.totals.execs, 7);
        assert_eq!(report.totals.writes, 33);
        assert!(report.regions.iter().any(|r| r.kind == "executable code"));
        assert!(
            report
                .regions
                .iter()
                .any(|r| r.kind == "multi-writer context")
        );
        assert!(
            report
                .regions
                .iter()
                .any(|r| r.kind == "pointer / dispatch table")
        );
        assert!(
            report
                .regions
                .iter()
                .any(|r| r.kind == "self-modifying code")
        );
    }
}
