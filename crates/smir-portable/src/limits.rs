use crate::Error;

/// Host resource policy, separate from portable ABI semantic maxima.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_object_bytes: usize,
    pub max_payload_bytes: usize,
    pub max_record_nodes: usize,
    pub max_record_depth: usize,
    pub max_list_items: usize,
    pub max_string_bytes: usize,
    pub max_semantic_work: u64,
    pub max_graph_edges: usize,
    pub max_derived_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_object_bytes: 64 * 1024 * 1024,
            max_payload_bytes: 16 * 1024 * 1024,
            max_record_nodes: 1_000_000,
            max_record_depth: 64,
            max_list_items: 65_536,
            max_string_bytes: 1024 * 1024,
            max_semantic_work: 100_000_000,
            max_graph_edges: 1_000_000,
            max_derived_bytes: 64 * 1024 * 1024,
        }
    }
}

impl Limits {
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.max_record_depth > 128 {
            return Err(Error::resource(
                "P2_LIMIT_CONFIG",
                "invalid decode resource policy",
            ));
        }
        Ok(())
    }
}

/// One cumulative budget for the entire verification request, including temps.
pub(crate) struct Budget {
    work: u64,
    edges: usize,
    bytes: usize,
}

impl Budget {
    pub(crate) fn new(limits: &Limits) -> Self {
        Self {
            work: limits.max_semantic_work,
            edges: limits.max_graph_edges,
            bytes: limits.max_derived_bytes,
        }
    }

    pub(crate) fn work(&mut self, units: u64) -> Result<(), Error> {
        self.work = self
            .work
            .checked_sub(units)
            .ok_or_else(|| Error::resource("P2_WORK_LIMIT", "semantic work exhausted"))?;
        Ok(())
    }

    pub(crate) fn edges(&mut self, count: usize) -> Result<(), Error> {
        self.edges = self
            .edges
            .checked_sub(count)
            .ok_or_else(|| Error::resource("P2_EDGE_LIMIT", "graph edges exhausted"))?;
        Ok(())
    }

    pub(crate) fn reserve_bytes(&mut self, count: usize) -> Result<(), Error> {
        self.bytes = self
            .bytes
            .checked_sub(count)
            .ok_or_else(|| Error::resource("P2_DERIVED_LIMIT", "derived allocation exhausted"))?;
        Ok(())
    }
}
