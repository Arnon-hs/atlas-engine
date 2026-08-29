//! Redacted, bounded intraprocedural flow signals.
//!
//! These records are evidence that the native Python model connected a function
//! parameter to a modeled sink. They are still review signals: aliasing,
//! sanitization, framework routing and exploitability are outside this contract.

use repo_core::{DataFlowFact, DataFlowKind, SourceRange};
use serde::Serialize;

pub const BOUNDED_DATAFLOW_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedDataflowSignal {
    pub schema_version: String,
    pub kind: DataFlowKind,
    pub relative_path: String,
    pub source_range: SourceRange,
    pub sink_range: SourceRange,
    pub assignment_hops: u64,
}

impl BoundedDataflowSignal {
    pub(crate) fn from_fact(relative_path: &str, fact: DataFlowFact) -> Self {
        Self {
            schema_version: BOUNDED_DATAFLOW_SCHEMA_VERSION.into(),
            kind: fact.kind,
            relative_path: relative_path.into(),
            source_range: fact.source_range,
            sink_range: fact.sink_range,
            assignment_hops: fact.assignment_hops,
        }
    }
}
