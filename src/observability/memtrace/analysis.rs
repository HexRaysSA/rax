//! Region-level analysis of a `.raxtrace` file.
//!
//! The output groups touched pages into contiguous regions, classifies each
//! region from its access pattern, and attributes writes to the code pages
//! that issued them. The classifications are heuristics, not declarations:
//! they are named so that a reader can check the evidence in the same report.

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
    /// Write an HTML report here.
    pub html: Option<std::path::PathBuf>,
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
            html: None,
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
    read_heat: Vec<u32>,
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
    reads: u64,
    read_targets: [(u64, u64); MAX_TARGETS],
    read_target_len: usize,
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

    fn note_read_target(&mut self, page: u64) {
        for i in 0..self.read_target_len {
            if self.read_targets[i].0 == page {
                self.read_targets[i].1 += 1;
                return;
            }
        }
        if self.read_target_len < MAX_TARGETS {
            self.read_targets[self.read_target_len] = (page, 1);
            self.read_target_len += 1;
        }
    }

    fn top_target(&self) -> Option<(u64, u64)> {
        self.targets[..self.target_len]
            .iter()
            .copied()
            .max_by_key(|&(_, count)| count)
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
    totals: Totals,
    header_ok: bool,
    arch: u32,
}

/// Reads `path` and renders the requested report. JSON and HTML outputs are
/// written as a side effect.
pub fn run(path: &Path, opts: &Options) -> io::Result<String> {
    let report = analyze_path(path)?;
    if let Some(json) = &opts.json {
        std::fs::write(json, report.to_json())?;
    }
    if let Some(html) = &opts.html {
        std::fs::write(html, report.to_html())?;
    }
    Ok(report.render(opts))
}

/// Parses and analyses a trace file.
pub fn analyze_path(path: &Path) -> io::Result<Report> {
    let file = File::open(path)?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut report = analyze_reader(&mut reader)?;
    report.totals.trace_bytes = len;
    report.trace_path = path.display().to_string();
    Ok(report)
}

/// Parses and analyses a trace stream.
pub fn analyze_reader<R: Read>(reader: &mut R) -> io::Result<Report> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;
    let mut analyzer = Analyzer {
        seq: 0,
        pages: BTreeMap::new(),
        srcs: HashMap::new(),
        snapshots: Vec::new(),
        current_maps: BTreeMap::new(),
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
            if stats.read_heat.is_empty() {
                stats.read_heat.resize(64, 0);
            }
            stats.read_heat[((offset / 64) as usize).min(63)] += 1;
            stats.first_read.get_or_insert(self.seq);
            let source_page = rip / PAGE;
            if rip != 0 {
                stats.note_reader(source_page);
                let source = self.srcs.entry(source_page).or_default();
                source.reads += 1;
                source.note_read_target(page);
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
        let _ = writeln!(out);

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

        let _ = writeln!(
            out,
            "ADDRESS-SPACE MAP (X=code  S=code+write  W=write  r=read; one character per cell)"
        );
        for (start_page, end_page) in clusters {
            let span = end_page - start_page + 1;
            // At most 20 rows of 100 characters for this cluster.
            let mut cell_pages = ((span + 1999) / 2000).max(1);
            cell_pages = cell_pages.next_power_of_two();
            let cells = ((span + cell_pages - 1) / cell_pages) as usize;
            let mut buckets = vec![(0u64, 0u64, 0u64, 0u64); cells];
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
                for &(exec, write, read, _) in chunk {
                    line.push(if exec > 0 && write > 0 {
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
        out
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
            "regions": regions,
        });
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| json.to_string())
    }

    fn to_html(&self) -> String {
        let opcode_regions: Vec<&Region> = self
            .regions
            .iter()
            .filter(|region| region.kind_id == 2)
            .collect();
        let vm_code = self
            .regions
            .iter()
            .filter(|region| region.kind_id == 0)
            .max_by_key(|region| region.execs);
        let vm_cluster = self.vm_cluster();
        let unpacker = self
            .regions
            .iter()
            .filter(|region| region.kind_id == 1)
            .max_by_key(|region| region.writes);
        let stream = opcode_regions
            .iter()
            .copied()
            .max_by_key(|region| region.read_sizes[0]);

        let mut reader_counts: HashMap<u64, u64> = HashMap::new();
        for region in &opcode_regions {
            for page in region.start / PAGE..region.end / PAGE {
                if let Some(stats) = self.pages.get(&page) {
                    for &(source, count) in &stats.readers[..stats.reader_len] {
                        *reader_counts.entry(source).or_default() += count;
                    }
                }
            }
        }
        let mut readers: Vec<(u64, u64)> = reader_counts.into_iter().collect();
        readers.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
        let dispatcher = readers.first().copied();

        let mut out = String::new();
        out.push_str(
            "<!doctype html><html><head><meta charset=\"utf-8\">
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
             <title>rax trace map</title>",
        );
        out.push_str(HTML_CSS);
        out.push_str("</head><body>");
        let _ = writeln!(
            out,
            "<header class=\"topbar\"><span class=\"wordmark\">rax trace map</span><span class=\"ver\">v1</span><span class=\"file\">{}</span><span class=\"spacer\"></span><span class=\"meta\">{} accesses · {} pages · {}</span></header><main>",
            escape_html(&short_path(&self.trace_path)),
            count(self.totals.accesses),
            self.totals.pages_touched,
            bytes(self.totals.trace_bytes),
        );
        out.push_str("<section class=\"summary\"><div class=\"statgrid\">");
        for (label, value) in [
            ("fetches", count(self.totals.execs)),
            ("reads", count(self.totals.reads)),
            ("writes", count(self.totals.writes)),
            ("code pages", self.totals.pages_executed.to_string()),
            (
                "opcode pages",
                opcode_regions
                    .iter()
                    .map(|r| r.pages)
                    .sum::<u64>()
                    .to_string(),
            ),
        ] {
            let _ = writeln!(
                out,
                "<div class=\"stat\"><span>{label}</span><b>{value}</b></div>"
            );
        }
        out.push_str("</div></section>");

        out.push_str("<section class=\"signals\"><h2>Signal</h2><div class=\"cards\">");
        let _ = writeln!(
            out,
            "<div class=\"card code\"><span>CODE CLUSTER</span><b>{}</b><p>{} pages · {} fetches · {} reads</p><small>{}</small></div>",
            vm_cluster.map_or_else(|| "—".into(), |(start, end, _, _, _)| range(start, end)),
            vm_cluster.map_or(0, |(_, _, pages, _, _)| pages),
            vm_cluster.map_or_else(|| "0".into(), |(_, _, _, fetches, _)| count(fetches)),
            vm_cluster.map_or_else(|| "0".into(), |(_, _, _, _, reads)| count(reads)),
            vm_code.map_or_else(String::new, |r| short_path(&r.map_name)),
        );
        let _ = writeln!(
            out,
            "<div class=\"card stream\"><span>OPCODE STREAM</span><b>{}</b><p>{} single-byte reads · {} readers</p><small>{}</small></div>",
            stream.map_or_else(|| "—".into(), |r| range(r.start, r.end)),
            stream.map_or_else(|| "0".into(), |r| count(r.read_sizes[0])),
            stream.map_or(0, |r| r.distinct_readers),
            stream.map_or_else(String::new, |r| format!(
                "{} of reads are 1-byte",
                percent(r.read_sizes[0], r.reads)
            )),
        );
        let _ = writeln!(
            out,
            "<div class=\"card dispatch\"><span>DISPATCH CANDIDATE</span><b>{}</b><p>{} reads into the opcode stream</p><small>{}</small></div>",
            dispatcher.map_or_else(|| "—".into(), |(page, _)| format!("{:#x}", page * PAGE)),
            dispatcher.map_or_else(|| "0".into(), |(_, hits)| count(hits)),
            dispatcher
                .map(|(page, _)| short_path(&self.map_name(page * PAGE)))
                .unwrap_or_default(),
        );
        let _ = writeln!(
            out,
            "<div class=\"card patch\"><span>UNPACKER / PATCHER</span><b>{}</b><p>{} writes · first write {} · first fetch {}</p><small>{}</small></div>",
            unpacker.map_or_else(|| "—".into(), |r| range(r.start, r.end)),
            unpacker.map_or_else(|| "0".into(), |r| count(r.writes)),
            unpacker.map_or_else(|| "never".into(), |r| seq(r.first_write_seq)),
            unpacker.map_or_else(|| "never".into(), |r| seq(r.first_exec_seq)),
            unpacker
                .map(|r| r
                    .writers
                    .iter()
                    .take(2)
                    .map(|(p, c)| format!("{:#x}×{c}", p * PAGE))
                    .collect::<Vec<_>>()
                    .join(" · "))
                .unwrap_or_default(),
        );
        out.push_str("</div>");

        if !self.findings.is_empty() {
            out.push_str("<div class=\"findings\">");
            for finding in &self.findings {
                let _ = writeln!(out, "<div class=\"finding\">{}</div>", escape_html(finding));
            }
            out.push_str("</div>");
        }
        out.push_str("</section>");

        out.push_str("<section><h2>Address-space activity</h2><p class=\"sub\">Each cell is a touched page. Cyan intensity is fetch volume; gold is code that was written; magenta is an opcode-stream candidate; red is written data. Hover any cell for its counts.</p><div class=\"bandlist\">");
        let max_exec = self
            .pages
            .values()
            .map(|stats| stats.execs)
            .max()
            .unwrap_or(1) as f64;
        let max_activity = self
            .pages
            .values()
            .map(|stats| stats.execs + stats.reads + stats.writes)
            .max()
            .unwrap_or(1) as f64;
        let opcode_pages: BTreeSet<u64> = opcode_regions
            .iter()
            .flat_map(|region| region.start / PAGE..region.end / PAGE)
            .collect();
        for band in html_bands(self, max_exec, max_activity) {
            let span = band.end - band.start + 1;
            let cells = span.min(1100) as usize;
            let mut buckets: Vec<Option<(Kind, f32, u64)>> = vec![None; cells];
            for &(page, kind, ratio) in &band.pages {
                let index = (((page - band.start) as usize) * cells / span as usize).min(cells - 1);
                let replace = match buckets[index] {
                    Some((current, current_ratio, _)) => {
                        kind_priority(kind) > kind_priority(current)
                            || (kind_priority(kind) == kind_priority(current)
                                && ratio > current_ratio)
                    }
                    None => true,
                };
                if replace {
                    buckets[index] = Some((kind, ratio, page));
                }
            }
            let contains_stream = band
                .pages
                .iter()
                .any(|(page, _, _)| opcode_pages.contains(page));
            let mut svg = String::new();
            let cell_w = 1100.0 / cells as f32;
            let _ = write!(
                svg,
                "<svg viewBox=\"0 0 1100 28\" preserveAspectRatio=\"none\" class=\"band\">
                 <rect width=\"1100\" height=\"28\" fill=\"#0a1018\"/>"
            );
            // Annotation rail: brackets for the opcode stream, ticks for the
            // dispatcher and unpacker. This is what turns the page strip into
            // a readable VM map instead of a generic heatmap.
            if let Some(region) = opcode_regions
                .iter()
                .find(|region| region.end / PAGE > band.start && region.start / PAGE <= band.end)
            {
                let start_page = (region.start / PAGE).max(band.start);
                let end_page = (region.end / PAGE).min(band.end + 1);
                let x = (start_page - band.start) as f32 * cell_w;
                let width = ((end_page - start_page) as f32 * cell_w).max(1.0);
                let _ = write!(
                    svg,
                    "<rect x=\"{x:.2}\" y=\"0\" width=\"{width:.2}\" height=\"8\" fill=\"#ff5696\" opacity=\"0.28\"/>
                     <line x1=\"{x:.2}\" y1=\"0\" x2=\"{x:.2}\" y2=\"28\" stroke=\"#ff5696\" stroke-width=\"0.8\" stroke-dasharray=\"2 2\" opacity=\"0.9\"/>
                     <line x1=\"{x2:.2}\" y1=\"0\" x2=\"{x2:.2}\" y2=\"28\" stroke=\"#ff5696\" stroke-width=\"0.8\" stroke-dasharray=\"2 2\" opacity=\"0.9\"/>",
                    x2 = x + width
                );
                if width > 110.0 {
                    let _ = write!(
                        svg,
                        "<text x=\"{:.2}\" y=\"6.2\" font-size=\"6.4\" fill=\"#ffd1e4\" letter-spacing=\"0.8\">OPCODE STREAM</text>",
                        x + 3.0
                    );
                }
            }
            if let Some((page, _)) = dispatcher {
                if page >= band.start && page <= band.end {
                    let x = (page - band.start) as f32 * cell_w + cell_w * 0.5;
                    let _ = write!(
                        svg,
                        "<line x1=\"{x:.2}\" y1=\"0\" x2=\"{x:.2}\" y2=\"28\" stroke=\"#ffffff\" stroke-width=\"1.2\" opacity=\"0.9\"><title>dispatch candidate {:#x}</title></line>
                         <circle cx=\"{x:.2}\" cy=\"3\" r=\"1.6\" fill=\"#ffffff\"/>",
                        page * PAGE
                    );
                }
            }
            if let Some(region) = unpacker {
                let page = region.start / PAGE;
                if page >= band.start && page <= band.end {
                    let x = (page - band.start) as f32 * cell_w + cell_w * 0.5;
                    let _ = write!(
                        svg,
                        "<line x1=\"{x:.2}\" y1=\"0\" x2=\"{x:.2}\" y2=\"28\" stroke=\"#ffd666\" stroke-width=\"1.0\" opacity=\"0.85\"><title>unpacker {:#x}</title></line>",
                        page * PAGE
                    );
                }
            }
            for (index, bucket) in buckets.iter().enumerate() {
                let Some((kind, ratio, page)) = bucket else {
                    continue;
                };
                let x = index as f32 * cell_w;
                let width = (cell_w + 0.35).max(0.7);
                let fill = heat_color(*kind, *ratio);
                let stats = self.pages.get(page);
                let title = stats.map_or_else(
                    || format!("{:#x}", page * PAGE),
                    |stats| {
                        format!(
                            "{:#x}  {}  fetches {}  reads {}  writes {}",
                            page * PAGE,
                            kind.label(),
                            count(stats.execs),
                            count(stats.reads),
                            count(stats.writes)
                        )
                    },
                );
                let opacity = if *kind == Kind::Code {
                    0.55 + ratio * 0.45
                } else {
                    0.9
                };
                let _ = write!(
                    svg,
                    "<rect x=\"{x:.2}\" y=\"9\" width=\"{width:.2}\" height=\"18\" fill=\"{fill}\" opacity=\"{opacity:.2}\"><title>{}</title></rect>",
                    escape_html(&title)
                );
            }
            svg.push_str("</svg>");
            let _ = writeln!(
                out,
                "<div class=\"bandrow\"><div class=\"bandmeta\"><span class=\"mapname\">{}</span><span class=\"addr\">{}</span>{}</div><div class=\"bandplot\">{svg}</div></div>",
                escape_html(&short_path(&band.map)),
                range(band.start * PAGE, (band.end + 1) * PAGE),
                if contains_stream {
                    "<i class=\"tag streamtag\">STREAM</i>"
                } else {
                    ""
                }
            );
        }
        out.push_str("</div><div class=\"legend\"><span class=\"sw code\"></span>code <span class=\"sw patch\"></span>code+write <span class=\"sw stream\"></span>opcode stream <span class=\"sw data\"></span>written data <span class=\"sw read\"></span>read-only</div></section>");

        if let Some((start, end, pages, fetches, _)) = vm_cluster {
            out.push_str("<section><h2>Executable cluster layout</h2>");
            let _ = writeln!(
                out,
                "<p class=\"sub\">Zoom on the hottest executable cluster at {} — {} executable pages, {} fetches. In a virtualised binary this is the VM code footprint. Each cell is one 4 KiB page; the magenta bracket is the opcode stream, the white marker is the dispatch candidate, and the gold marker is the page that is both written and executed.</p>",
                range(start, end),
                pages,
                count(fetches)
            );
            out.push_str(&self.render_vm_layout(start, end, stream, dispatcher, unpacker));
            out.push_str("</section>");
        }

        if let Some(stream) = stream {
            out.push_str("<section><h2>Opcode stream</h2>");
            let _ = writeln!(
                out,
                "<p class=\"sub\">Read heat across {} — each cell is 64 bytes, brightness is the number of single-byte reads. This is the data the virtual machine is consuming as instructions.</p>",
                range(stream.start, stream.end)
            );
            out.push_str("<div class=\"spectro\">");
            out.push_str(&self.render_stream_spectrogram(stream));
            out.push_str("</div>");
            if !readers.is_empty() {
                out.push_str("<h3>Code that reads the stream</h3><div class=\"readers\">");
                let max = readers[0].1.max(1);
                for (index, &(page, hits)) in readers.iter().take(14).enumerate() {
                    let stats = self.pages.get(&page);
                    let width = (hits as f64 / max as f64 * 100.0).max(2.0);
                    let _ = writeln!(
                        out,
                        "<div class=\"reader\"><span class=\"readeraddr\">{:#x}</span><span class=\"readerbar\"><i style=\"width:{width:.1}%\"></i></span><span class=\"readercount\">{} reads</span><span class=\"readermeta\">{} fetches · {} writes</span>{}</div>",
                        page * PAGE,
                        count(hits),
                        stats.map_or_else(|| "0".into(), |s| count(s.execs)),
                        stats.map_or_else(|| "0".into(), |s| count(s.writes)),
                        if index == 0 {
                            "<i class=\"tag dispatchtag\">DISPATCH?</i>"
                        } else {
                            ""
                        }
                    );
                }
                out.push_str("</div>");
            }
            out.push_str("</section>");
        }

        out.push_str("<section><h2>Hottest code pages</h2><p class=\"sub\">Ranked by instruction fetches. In a virtualised binary the dispatcher and its handler pages dominate this list; the reads column shows which pages consume the opcode stream.</p><div class=\"tablewrap\"><table class=\"hot\"><tr><th>#</th><th>page</th><th>map</th><th>fetches</th><th>reads</th><th>writes</th><th>top write target</th></tr>");
        let mut hot: Vec<(&u64, &PageStats)> = self
            .pages
            .iter()
            .filter(|(_, stats)| stats.execs > 0)
            .collect();
        hot.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.execs));
        for (index, (page, stats)) in hot.iter().take(18).enumerate() {
            let target = stats.writers[..stats.writer_len]
                .iter()
                .max_by_key(|&&(_, count)| count)
                .map(|&(target, hits)| {
                    format!(
                        "{} <span class=\"dim\">×{}</span>",
                        range(target * PAGE, (target + 1) * PAGE),
                        count(hits)
                    )
                })
                .unwrap_or_else(|| "—".into());
            let _ = writeln!(
                out,
                "<tr><td class=\"num\">{}</td><td class=\"addr\">{:#x}</td><td>{}</td><td class=\"num hotnum\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{target}</td></tr>",
                index + 1,
                *page * PAGE,
                escape_html(&short_path(&self.map_name(*page * PAGE))),
                count(stats.execs),
                count(stats.reads),
                count(stats.writes),
            );
        }
        out.push_str("</table></div></section>");

        out.push_str("<section><h2>Write flow</h2><p class=\"sub\">The busiest data targets and the code pages that write them. Handler sets converge on one or a few rows here.</p><div class=\"tablewrap\"><table class=\"flow\"><tr><th>source</th><th>target</th><th>kind</th><th>writes</th><th>share</th></tr>");
        let mut edges: Vec<(u64, u64, u64, Kind)> = Vec::new();
        for (&page, stats) in &self.pages {
            let name = self.map_name(page * PAGE);
            let kind = page_kind(stats, &name);
            if !matches!(
                kind,
                Kind::Context | Kind::Bytecode | Kind::PointerData | Kind::SelfMod | Kind::Stack
            ) {
                continue;
            }
            for &(source, count) in &stats.writers[..stats.writer_len] {
                if self
                    .pages
                    .get(&source)
                    .is_some_and(|source| source.execs > 0)
                {
                    edges.push((source, page, count, kind));
                }
            }
        }
        edges.sort_by_key(|&(_, _, count, _)| std::cmp::Reverse(count));
        let edge_max = edges.first().map_or(1, |edge| edge.2);
        for &(source, target, hits, kind) in edges.iter().take(16) {
            let width = (hits as f64 / edge_max as f64 * 100.0).max(1.0);
            let _ = writeln!(
                out,
                "<tr><td class=\"addr\">{:#x}</td><td class=\"addr\">{:#x}</td><td><i class=\"tag {}\">{}</i></td><td class=\"num\">{}</td><td><span class=\"flowbar\"><i style=\"width:{width:.1}%\"></i></span></td></tr>",
                source * PAGE,
                target * PAGE,
                kind_class(kind),
                kind.label(),
                count(hits),
            );
        }
        out.push_str("</table></div></section>");

        out.push_str("<section><h2>Region inventory</h2><div class=\"tablewrap\"><table class=\"regions\"><tr><th>#</th><th>range</th><th>size</th><th>kind</th><th>map</th><th>fetch</th><th>read</th><th>write</th><th>write width</th></tr>");
        for (index, region) in self.regions.iter().take(60).enumerate() {
            let _ = writeln!(
                out,
                "<tr><td class=\"num\">{index}</td><td class=\"addr\">{}</td><td>{}</td><td><i class=\"tag {}\">{}</i></td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"dim\">{}</td></tr>",
                range(region.start, region.end),
                bytes(region.end - region.start),
                kind_class_by_id(region.kind_id),
                region.kind,
                escape_html(&short_path(&region.map_name)),
                count(region.execs),
                count(region.reads),
                count(region.writes),
                escape_html(&size_summary(&region.write_sizes)),
            );
        }
        out.push_str("</table></div>");
        if self.regions.len() > 60 {
            let _ = writeln!(
                out,
                "<p class=\"sub\">… {} more regions omitted from the HTML table; the JSON report contains all of them.</p>",
                self.regions.len() - 60
            );
        }
        out.push_str("</section>");

        out.push_str("<footer>Classifications are evidence labels, not declarations. <b>opcode stream</b> = read-only pages consumed mostly as one-byte reads from several code pages; <b>dispatch candidate</b> = the code page with the most reads into that stream; <b>unpacker</b> = the page that is both written and executed. Fetch records identify decoded addresses, not execution frequency.</footer>");
        out.push_str("</main></body></html>");
        out
    }

    /// The executable pages of the map that contains the hottest code region.
    /// This is the virtual machine's code footprint, not a single classified
    /// region fragment.
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

    fn render_vm_layout(
        &self,
        start: u64,
        end: u64,
        stream: Option<&Region>,
        dispatcher: Option<(u64, u64)>,
        unpacker: Option<&Region>,
    ) -> String {
        let mut out = String::new();
        let start_page = start / PAGE;
        let end_page = end / PAGE;
        let span = (end_page - start_page).max(1);
        let per_row = 220u64;
        let cell = 5.0f32;
        let rows = span.div_ceil(per_row);
        let max_exec = self
            .pages
            .values()
            .map(|stats| stats.execs)
            .max()
            .unwrap_or(1) as f64;
        let max_activity = self
            .pages
            .values()
            .map(|stats| stats.execs + stats.reads + stats.writes)
            .max()
            .unwrap_or(1) as f64;
        for row in 0..rows {
            let row_start = start_page + row * per_row;
            let row_end = (row_start + per_row - 1).min(end_page);
            let mut svg = String::from(
                "<svg viewBox=\"0 0 1100 58\" preserveAspectRatio=\"none\" class=\"zoomband\"><rect width=\"1100\" height=\"58\" fill=\"#080d14\"/></svg>",
            );
            // Replace the closing tag after drawing.
            svg.truncate(svg.len() - 6);
            let _ = write!(
                svg,
                "<text x=\"0\" y=\"10\" class=\"zoomruler\">{row_start:#x}</text><text x=\"1100\" y=\"10\" text-anchor=\"end\" class=\"zoomruler\">{row_end:#x}</text>"
            );
            if let Some(region) = stream {
                let lo = (region.start / PAGE).max(row_start);
                let hi = (region.end / PAGE).min(row_end + 1);
                if hi > lo {
                    let x = (lo - row_start) as f32 * cell;
                    let width = ((hi - lo) as f32 * cell).max(2.0);
                    let _ = write!(
                        svg,
                        "<rect x=\"{x:.1}\" y=\"14\" width=\"{width:.1}\" height=\"36\" fill=\"none\" stroke=\"#ff5696\" stroke-width=\"1.2\" stroke-dasharray=\"4 3\"/><rect x=\"{x:.1}\" y=\"14\" width=\"{width:.1}\" height=\"5\" fill=\"#ff5696\" opacity=\"0.85\"/>"
                    );
                    if width > 120.0 {
                        let _ = write!(
                            svg,
                            "<text x=\"{:.1}\" y=\"25\" class=\"zoomanntext\">OPCODE STREAM</text>",
                            x + 4.0
                        );
                    }
                }
            }
            for page in row_start..=row_end {
                let Some(stats) = self.pages.get(&page) else {
                    continue;
                };
                let name = self.map_name(page * PAGE);
                let kind = page_kind(stats, &name);
                let ratio = if kind == Kind::Code {
                    ((stats.execs as f64 + 1.0).ln() / (max_exec + 1.0).ln()) as f32
                } else {
                    (((stats.execs + stats.reads + stats.writes) as f64 + 1.0).ln()
                        / (max_activity + 1.0).ln()) as f32
                };
                let fill = heat_color(kind, ratio);
                let x = (page - row_start) as f32 * cell;
                let title = format!(
                    "{:#x}  {}  fetches {}  reads {}  writes {}",
                    page * PAGE,
                    kind.label(),
                    count(stats.execs),
                    count(stats.reads),
                    count(stats.writes)
                );
                let _ = write!(
                    svg,
                    "<rect x=\"{x:.1}\" y=\"14\" width=\"{:.2}\" height=\"36\" fill=\"{fill}\"><title>{}</title></rect>",
                    (cell - 0.35).max(0.8),
                    escape_html(&title)
                );
            }
            if let Some((page, _)) = dispatcher {
                if page >= row_start && page <= row_end {
                    let x = (page - row_start) as f32 * cell + cell * 0.5;
                    let _ = write!(
                        svg,
                        "<line x1=\"{x:.1}\" y1=\"14\" x2=\"{x:.1}\" y2=\"50\" stroke=\"#ffffff\" stroke-width=\"2\"/><circle cx=\"{x:.1}\" cy=\"14\" r=\"3\" fill=\"#ffffff\"/><text x=\"{:.1}\" y=\"56\" class=\"zoommark\">DISPATCH</text>",
                        (x + 4.0).min(1040.0)
                    );
                }
            }
            if let Some(region) = unpacker {
                let page = region.start / PAGE;
                if page >= row_start && page <= row_end {
                    let x = (page - row_start) as f32 * cell + cell * 0.5;
                    let _ = write!(
                        svg,
                        "<line x1=\"{x:.1}\" y1=\"14\" x2=\"{x:.1}\" y2=\"50\" stroke=\"#ffd666\" stroke-width=\"1.6\"/><circle cx=\"{x:.1}\" cy=\"50\" r=\"3\" fill=\"#ffd666\"/>"
                    );
                }
            }
            svg.push_str("</svg>");
            let _ = writeln!(
                out,
                "<div class=\"zoomrow\"><div class=\"zoommeta\">{}</div>{svg}</div>",
                range(row_start * PAGE, (row_end + 1) * PAGE)
            );
        }
        out.push_str("<div class=\"callouts\">");
        if let Some(region) = stream {
            let _ = writeln!(
                out,
                "<span class=\"callout streamc\">OPCODE STREAM <b>{}</b> · {} single-byte reads</span>",
                range(region.start, region.end),
                count(region.read_sizes[0])
            );
        }
        if let Some((page, hits)) = dispatcher {
            let _ = writeln!(
                out,
                "<span class=\"callout dispatchc\">DISPATCH CANDIDATE <b>{:#x}</b> · {} reads into the stream</span>",
                page * PAGE,
                count(hits)
            );
        }
        if let Some(region) = unpacker {
            let _ = writeln!(
                out,
                "<span class=\"callout patchc\">WRITTEN + EXECUTED <b>{}</b> · {} writes</span>",
                range(region.start, region.end),
                count(region.writes)
            );
        }
        out.push_str("</div>");
        out
    }

    fn render_stream_spectrogram(&self, stream: &Region) -> String {
        let pages = (stream.end - stream.start) / PAGE;
        let chunks = pages as usize * 64;
        let per_row = 256usize;
        let rows = (chunks + per_row - 1) / per_row;
        let mut values = vec![0u32; chunks];
        for page in stream.start / PAGE..stream.end / PAGE {
            if let Some(stats) = self.pages.get(&page) {
                let base = ((page - stream.start / PAGE) as usize) * 64;
                for (chunk, &value) in stats.read_heat.iter().take(64).enumerate() {
                    values[base + chunk] = value;
                }
            }
        }
        let mut nonzero: Vec<u32> = values.iter().copied().filter(|&value| value > 0).collect();
        nonzero.sort_unstable();
        let samples = nonzero.len().max(1) as f64;
        let cell_w = 3.6f32;
        let cell_h = 3.0f32;
        let left = 132.0f32;
        let top = 14.0f32;
        let width = left + per_row as f32 * cell_w + 8.0;
        let height = top + rows as f32 * cell_h + 22.0;
        let mut out = String::new();
        let _ = write!(
            out,
            "<svg viewBox=\"0 0 {width:.0} {height:.0}\" class=\"spectrosvg\" shape-rendering=\"crispEdges\">
             <rect width=\"{width:.0}\" height=\"{height:.0}\" fill=\"#08060d\"/>"
        );
        for row in 0..rows {
            let addr = stream.start + row as u64 * per_row as u64 * 64;
            if row % 8 == 0 {
                let _ = write!(
                    out,
                    "<text x=\"0\" y=\"{:.1}\" class=\"spectrolabel\">{addr:#x}</text>",
                    top + row as f32 * cell_h + 2.6
                );
            }
            for col in 0..per_row {
                let index = row * per_row + col;
                if index >= values.len() {
                    break;
                }
                let value = values[index];
                if value == 0 {
                    continue;
                }
                // Rank-based heat: a uniform read stream must not turn into a
                // white rectangle, and rare hot spots still stand out.
                let below = nonzero.partition_point(|&sample| sample < value);
                let through = nonzero.partition_point(|&sample| sample <= value);
                let ratio = ((below + through) as f64 / (2.0 * samples)).min(1.0);
                let fill = heat_color(Kind::Bytecode, ratio as f32);
                let x = left + col as f32 * cell_w;
                let y = top + row as f32 * cell_h;
                let addr = stream.start + index as u64 * 64;
                let _ = write!(
                    out,
                    "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{:.2}\" height=\"{:.1}\" fill=\"{fill}\"><title>{addr:#x}: {value} reads</title></rect>",
                    (cell_w - 0.25).max(0.8),
                    (cell_h - 0.35).max(0.8)
                );
            }
        }
        let _ = write!(
            out,
            "<text x=\"{left:.1}\" y=\"{height:.0}\" class=\"spectrolabel\">64 bytes/cell · read heat rank</text></svg>"
        );
        out
    }
}

#[derive(Clone)]
struct HtmlBand {
    start: u64,
    end: u64,
    map: String,
    pages: Vec<(u64, Kind, f32)>,
}

fn html_bands(report: &Report, max_exec: f64, max_activity: f64) -> Vec<HtmlBand> {
    let mut bands: Vec<HtmlBand> = Vec::new();
    let mut current: Option<HtmlBand> = None;
    let final_map = report.snapshots.last();
    for (&page, stats) in &report.pages {
        let name = final_map
            .and_then(|snapshot| snapshot.get(page * PAGE))
            .map(|range| range.name.clone())
            .unwrap_or_default();
        let kind = page_kind(stats, &name);
        let ratio = if kind == Kind::Code {
            ((stats.execs as f64 + 1.0).ln() / (max_exec + 1.0).ln()) as f32
        } else {
            (((stats.execs + stats.reads + stats.writes) as f64 + 1.0).ln()
                / (max_activity + 1.0).ln()) as f32
        };
        let continues = current
            .as_ref()
            .is_some_and(|band| band.map == name && page >= band.end + 1 && page <= band.end + 512);
        if continues {
            let band = current.as_mut().unwrap();
            band.end = page;
            band.pages.push((page, kind, ratio));
        } else {
            if let Some(band) = current.take() {
                bands.push(band);
            }
            current = Some(HtmlBand {
                start: page,
                end: page,
                map: name,
                pages: vec![(page, kind, ratio)],
            });
        }
    }
    if let Some(band) = current {
        bands.push(band);
    }
    bands.sort_by_key(|band| {
        std::cmp::Reverse(
            band.pages
                .iter()
                .map(|(page, kind, _)| {
                    report.pages.get(page).map_or(0, |stats| {
                        stats.execs + stats.reads + stats.writes + kind_priority(*kind) as u64 * 10
                    })
                })
                .sum::<u64>(),
        )
    });
    bands.truncate(80);
    bands.sort_by_key(|band| band.start);
    bands
}

fn kind_priority(kind: Kind) -> u8 {
    match kind {
        Kind::SelfMod => 10,
        Kind::Bytecode => 9,
        Kind::Code => 8,
        Kind::Context => 7,
        Kind::PointerData => 6,
        Kind::Stack => 5,
        Kind::Heap => 4,
        Kind::WrittenData => 3,
        Kind::ReadData => 2,
        Kind::Other => 1,
    }
}

fn kind_class(kind: Kind) -> &'static str {
    match kind {
        Kind::Code => "code",
        Kind::SelfMod => "patch",
        Kind::Bytecode => "stream",
        Kind::PointerData => "pointer",
        Kind::Context => "context",
        Kind::Stack => "stack",
        Kind::Heap => "heap",
        Kind::WrittenData => "data",
        Kind::ReadData => "read",
        Kind::Other => "other",
    }
}

fn kind_class_by_id(id: u8) -> &'static str {
    match id {
        0 => "code",
        1 => "patch",
        2 => "stream",
        3 => "pointer",
        4 => "context",
        5 => "stack",
        6 => "heap",
        7 => "data",
        8 => "read",
        _ => "other",
    }
}

fn heat_color(kind: Kind, ratio: f32) -> String {
    let linear = ratio.clamp(0.0, 1.0);
    let (r, g, b) = if kind == Kind::Bytecode {
        // Three-stop ramp keeps low read counts visibly purple instead of
        // collapsing the whole stream into one saturated pink block.
        if linear < 0.55 {
            mix([14, 4, 20], [126, 12, 76], linear / 0.55)
        } else {
            mix([126, 12, 76], [255, 240, 248], (linear - 0.55) / 0.45)
        }
    } else {
        let t = linear.powf(0.42);
        match kind {
            Kind::Code => mix([6, 38, 52], [125, 249, 255], t),
            Kind::SelfMod => mix([70, 44, 6], [255, 214, 102], t),
            Kind::Bytecode => mix([34, 5, 24], [255, 86, 150], t),
            Kind::PointerData => mix([22, 16, 52], [179, 136, 255], t),
            Kind::Context => mix([44, 10, 16], [255, 111, 97], t),
            Kind::Stack => mix([40, 26, 15], [217, 160, 107], t),
            Kind::Heap => mix([12, 32, 36], [80, 190, 190], t),
            Kind::WrittenData => mix([40, 18, 8], [255, 159, 67], t),
            Kind::ReadData => mix([7, 18, 36], [58, 120, 220], t),
            Kind::Other => (45, 55, 70),
        }
    };
    format!("rgb({r},{g},{b})")
}

fn mix(a: [u8; 3], b: [u8; 3], t: f32) -> (u8, u8, u8) {
    (
        (a[0] as f32 + (b[0] as f32 - a[0] as f32) * t).round() as u8,
        (a[1] as f32 + (b[1] as f32 - a[1] as f32) * t).round() as u8,
        (a[2] as f32 + (b[2] as f32 - a[2] as f32) * t).round() as u8,
    )
}

fn short_path(path: &str) -> String {
    if path.is_empty() {
        return "anonymous".into();
    }
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn percent(part: u64, total: u64) -> String {
    if total == 0 {
        "0%".into()
    } else {
        format!("{:.0}%", part as f64 * 100.0 / total as f64)
    }
}

const HTML_CSS: &str = r#"<style>
:root{
--void:#080706;--ink-900:#12100e;--ink-800:#1a1714;--ink-700:#241f1b;--ink-600:#2e2823;--ink-500:#3d352e;--ink-400:#4d443c;--ink-300:#6b6058;
--paper-000:#fff;--paper-100:#f5efe8;--paper-200:#d8cec3;--paper-300:#b8ada1;--paper-400:#8c8177;--paper-500:#6b6058;
--mag-100:#ffd0e2;--mag-300:#ff6aa5;--mag-500:#ff3d8b;--mag-700:#d92b71;--mag-900:#3d0f24;
--ok:#4ade5e;--warn:#ffb000;--err:#ff4d3d;--info:#4dc4ff;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"DM Mono",monospace;
--line-hairline:#2e2823;--line-default:#3d352e;--line-strong:#6b6058
}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--void);color:var(--paper-100);font:400 13px/1.55 var(--mono);font-variant-ligatures:none;-webkit-font-smoothing:antialiased}
::selection{background:var(--mag-500);color:var(--void)}
a{color:var(--mag-300);text-decoration:none;border-bottom:1px solid currentColor}
.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:12px;height:40px;padding:0 16px;background:var(--ink-900);border-bottom:1px solid var(--line-strong)}
.wordmark{font-weight:500;font-size:13px;letter-spacing:-.02em;color:var(--paper-100)}
.ver{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--paper-400);border:1px solid var(--line-hairline);padding:0 4px}
.file{font-size:12px;color:var(--paper-300);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.spacer{flex:1}
.meta{font-size:11px;color:var(--paper-400);font-variant-numeric:tabular-nums;white-space:nowrap}
main{max-width:1440px;margin:0 auto;padding:0 16px 64px}
section{padding:18px 0 24px;border-top:1px solid var(--line-hairline);margin-top:18px}
section:first-of-type{border-top:0;margin-top:0;padding-top:16px}
h2{font:500 11px/1.3 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--paper-300);margin:0 0 10px;padding-bottom:8px;border-bottom:1px solid var(--line-default)}
h3{font:500 10px/1.3 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--paper-400);margin:18px 0 8px}
.sub{color:var(--paper-400);font-size:12px;max-width:1050px;margin:0 0 14px}
.dim{color:var(--paper-400)}
.statgrid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line-default)}
.stat{padding:10px 12px;border-right:1px solid var(--line-hairline)}
.stat:last-child{border-right:0}
.stat span{display:block;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--paper-400)}
.stat b{display:block;font-size:17px;font-weight:500;color:var(--paper-100);font-variant-numeric:tabular-nums;margin-top:2px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid var(--line-default)}
.card{padding:12px 14px;border-right:1px solid var(--line-hairline);border-left:3px solid var(--line-strong);min-width:0}
.card:last-child{border-right:0}
.card.code{border-left-color:var(--info)}
.card.stream{border-left-color:var(--mag-500)}
.card.dispatch{border-left-color:var(--warn)}
.card.patch{border-left-color:var(--err)}
.card span{display:block;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--paper-400)}
.card b{display:block;font-size:16px;font-weight:500;color:var(--paper-100);margin:5px 0 3px;overflow-wrap:anywhere}
.card p{margin:0;font-size:12px;color:var(--paper-200)}
.card small{display:block;margin-top:6px;font-size:11px;color:var(--paper-400);overflow-wrap:anywhere}
.findings{margin-top:12px;border-left:1px solid var(--line-default);padding-left:12px}
.finding{font-size:12px;color:var(--paper-400);padding:1px 0}
.finding::before{content:"› ";color:var(--mag-300)}
.bandlist{display:flex;flex-direction:column}
.bandrow{display:grid;grid-template-columns:290px 1fr;gap:12px;align-items:center;padding:3px 0;border-top:1px solid var(--line-hairline)}
.bandrow:first-child{border-top:0}
.bandmeta{display:flex;flex-direction:column;gap:0;min-width:0}
.mapname{font-size:12px;color:var(--paper-200);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.addr{font-size:11px;color:var(--paper-400);white-space:nowrap;font-variant-numeric:tabular-nums}
.bandplot{min-width:0}
.band{display:block;width:100%;height:28px;background:var(--ink-900)}
.tag{display:inline-block;font-style:normal;font-size:9px;letter-spacing:.1em;text-transform:uppercase;padding:1px 5px;border:1px solid currentColor;margin-left:8px;white-space:nowrap}
.streamtag{color:var(--mag-300)}
.dispatchtag{color:var(--paper-100)}
.legend{margin-top:12px;color:var(--paper-400);font-size:11px;display:flex;gap:14px;flex-wrap:wrap}
.sw{display:inline-block;width:9px;height:9px;margin-right:5px;vertical-align:-1px;border:1px solid rgba(255,255,255,.12)}
.sw.code{background:var(--info)}.sw.patch{background:var(--warn)}.sw.stream{background:var(--mag-500)}.sw.data{background:var(--err)}.sw.read{background:var(--ink-400)}
.spectro{overflow-x:auto;border:1px solid var(--line-default);background:var(--void);padding:6px}
.spectrosvg{display:block;width:100%;min-width:900px;height:auto}
.spectrolabel{fill:var(--paper-500);font:9px var(--mono)}
.readers{margin-top:6px;border:1px solid var(--line-default)}
.reader{display:grid;grid-template-columns:122px 1fr 104px 190px;gap:10px;align-items:center;padding:6px 10px;border-top:1px solid var(--line-hairline)}
.reader:first-child{border-top:0}
.readeraddr{color:var(--paper-200);font-variant-numeric:tabular-nums}
.readerbar{height:7px;background:var(--ink-700)}
.readerbar i{display:block;height:100%;background:var(--mag-500)}
.readercount{text-align:right;color:var(--paper-100);font-variant-numeric:tabular-nums}
.readermeta{color:var(--paper-400);font-size:11px;text-align:right}
.tablewrap{overflow-x:auto;border:1px solid var(--line-default)}
table{border-collapse:collapse;width:100%}
th{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--paper-400);font-weight:500;text-align:left;padding:7px 10px;border-bottom:1px solid var(--line-default);background:var(--ink-800)}
td{padding:6px 10px;border-bottom:1px solid var(--line-hairline);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr:hover,table tr:hover{background:var(--ink-800)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.hotnum{color:var(--info)}
.flowbar{display:block;width:180px;height:6px;background:var(--ink-700)}
.flowbar i{display:block;height:100%;background:var(--warn)}
.tag.code{color:var(--info)}.tag.patch{color:var(--warn)}.tag.stream{color:var(--mag-300)}.tag.pointer{color:#b8ada1}.tag.context{color:var(--err)}.tag.stack{color:var(--paper-300)}.tag.heap{color:var(--ok)}.tag.data{color:var(--err)}.tag.read{color:var(--info)}.tag.other{color:var(--paper-400)}
.zoomrow{margin:4px 0 12px}
.zoommeta{color:var(--paper-400);font-size:10px;margin:0 0 3px;font-variant-numeric:tabular-nums}
.zoomband{display:block;width:100%;height:auto;background:var(--void)}
.zoomruler{fill:var(--paper-500);font:9px var(--mono)}
.zoomanntext{fill:var(--mag-100);font:8px var(--mono);letter-spacing:.16em}
.zoommark{fill:var(--paper-100);font:7px var(--mono);letter-spacing:.14em}
.callouts{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.callout{font-size:11px;padding:5px 8px;border:1px solid var(--line-default);color:var(--paper-400)}
.callout b{color:var(--paper-100);font-weight:500}
.streamc{border-color:var(--mag-700)}.dispatchc{border-color:var(--line-strong)}.patchc{border-color:#7a5a00}
footer{max-width:1440px;margin:28px auto 0;padding:14px 16px 0;border-top:1px solid var(--line-default);color:var(--paper-400);font-size:11px;line-height:1.7}
@media(max-width:900px){.statgrid{grid-template-columns:repeat(2,1fr)}.stat:nth-child(2n){border-right:0}.cards{grid-template-columns:1fr 1fr}.card:nth-child(2n){border-right:0}.bandrow{grid-template-columns:1fr}.reader{grid-template-columns:110px 1fr 90px}.readermeta{display:none}.topbar .meta{display:none}}
@media print{body{background:#fff;color:#111}.topbar{position:static;background:#fff;color:#111}.band{background:#eee}}
</style>"#;

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

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
