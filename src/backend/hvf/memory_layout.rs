//! Intel HVF RAM admission and transactional native map changes.
//! Addresses and lengths are bytes. Native mappings use 4096-byte pages;
//! logical RAM retains bytes outside a subpage device window.

const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Span {
    pub start: u64,
    pub end: u64,
}
impl Span {
    pub(crate) fn new(start: u64, size: u64) -> Result<Self, String> {
        let end = start.checked_add(size).ok_or("HVF memory extent wraps")?;
        if start == end {
            return Err("HVF memory extent is empty".into());
        }
        Ok(Self { start, end })
    }
    pub(crate) fn len(self) -> u64 {
        self.end - self.start
    }
}

fn contains(spans: &[Span], address: u64, size: usize) -> bool {
    size != 0
        && address.checked_add(size as u64).is_some_and(|end| {
            spans
                .iter()
                .any(|span| address >= span.start && end <= span.end)
        })
}

/// Difference of interval sets. Inputs are sorted and disjoint. Work O(n*m),
/// space O(n+m), with n RAM intervals and m exclusions (a few device windows).
fn subtract(input: &[Span], exclusions: &[Span]) -> Vec<Span> {
    let mut result = Vec::new();
    for span in input {
        let mut cursor = span.start;
        for hole in exclusions {
            if hole.end <= cursor || hole.start >= span.end {
                continue;
            }
            if cursor < hole.start {
                result.push(Span {
                    start: cursor,
                    end: hole.start.min(span.end),
                });
            }
            cursor = cursor.max(hole.end).min(span.end);
        }
        if cursor < span.end {
            result.push(Span {
                start: cursor,
                end: span.end,
            });
        }
    }
    result
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Layout {
    pub(crate) mapped: Vec<Span>,
    logical: Vec<Span>,
}
impl Layout {
    pub(crate) fn new(reported: u64, holes: &[Span]) -> Result<Self, String> {
        if reported & (PAGE - 1) != 0 {
            return Err("unaligned HVF reported RAM".into());
        }
        let ram: Vec<_> = crate::machine::pc::ram::Layout::new(reported)
            .map_err(|error| error.to_string())?
            .ranges()
            .map(|range| Span {
                start: range.start,
                end: range.end,
            })
            .collect();
        let mut bytes = Vec::new();
        for hole in holes {
            if hole.start >= hole.end {
                return Err("invalid HVF device extent".into());
            }
            for region in &ram {
                let start = hole.start.max(region.start);
                let end = hole.end.min(region.end);
                if start < end {
                    bytes.push(Span { start, end });
                }
            }
        }
        bytes.sort_by_key(|s| s.start);
        let mut pages = Vec::new();
        for hole in &bytes {
            let end = hole
                .end
                .checked_add(PAGE - 1)
                .ok_or("HVF page extent wraps")?
                & !(PAGE - 1);
            pages.push(Span {
                start: hole.start & !(PAGE - 1),
                end,
            });
        }
        Ok(Self {
            mapped: subtract(&ram, &pages),
            logical: subtract(&ram, &bytes),
        })
    }
    pub(crate) fn contains_mapped(&self, address: u64, size: usize) -> bool {
        contains(&self.mapped, address, size)
    }
    pub(crate) fn contains_logical(&self, address: u64, size: usize) -> bool {
        contains(&self.logical, address, size)
    }
}

pub(crate) trait MapAccess {
    fn map(&mut self, span: Span) -> Result<(), String>;
    fn unmap(&mut self, span: Span) -> Result<(), String>;
    /// A host SDK need not promise that an unsuccessful call changed nothing.
    /// Such an error prohibits entry even when all recorded inverses succeed.
    fn failed_operation_is_atomic(&self) -> bool {
        false
    }
}

#[derive(Default)]
pub(crate) struct Mapping {
    pub(crate) layout: Layout,
    poisoned: bool,
}
impl Mapping {
    pub(crate) fn ready(&self) -> Result<(), String> {
        if self.poisoned {
            Err("HVF native memory rollback failed; guest entry prohibited".into())
        } else {
            Ok(())
        }
    }
    /// Publish after every SDK change succeeds. Undo a failed transaction in
    /// reverse order; a failed undo permanently prohibits further guest entry.
    pub(crate) fn publish(
        &mut self,
        target: Layout,
        access: &mut impl MapAccess,
    ) -> Result<(), String> {
        self.ready()?;
        let remove = subtract(&self.layout.mapped, &target.mapped);
        let add = subtract(&target.mapped, &self.layout.mapped);
        let mut applied = Vec::new();
        for (mapping, span) in remove
            .into_iter()
            .map(|s| (false, s))
            .chain(add.into_iter().map(|s| (true, s)))
        {
            let result = if mapping {
                access.map(span)
            } else {
                access.unmap(span)
            };
            if let Err(error) = result {
                self.poisoned = !access.failed_operation_is_atomic();
                let mut rollback = Vec::new();
                for (mapping, span) in applied.into_iter().rev() {
                    let result = if mapping {
                        access.unmap(span)
                    } else {
                        access.map(span)
                    };
                    if let Err(error) = result {
                        rollback.push(error);
                    }
                }
                if !rollback.is_empty() {
                    self.poisoned = true;
                    return Err(format!(
                        "{error}; HVF memory rollback failures: {rollback:?}"
                    ));
                }
                return Err(error);
            }
            applied.push((mapping, span));
        }
        self.layout = target;
        Ok(())
    }
}
