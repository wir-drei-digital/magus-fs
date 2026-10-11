//! FS2-B additive collaboration protocol, advertised as capability `collaboration-v1` by
//! `GET /capabilities`. The closed service-v1 DTOs and their request digests are unchanged;
//! new requests use the same rule: the service digests the compact struct-order JSON.
use crate::{protocol::*, ConflictReason, EntryId, FsError, OperationId, ReplicaId};
use serde::{Deserialize, Serialize};

pub const COLLABORATION_CAPABILITY: &str = "collaboration-v1";
/// Listing pages carry at most this many items and serialize within `MAX_CONTROL`.
pub const MAX_PAGE_ITEMS: usize = 32;
/// Conflicts named by one resolution, and entry-conflict records retained per integration.
pub const MAX_RESOLUTION_CONFLICTS: usize = 128;
/// The 409 body code for an integration whose candidate retained immutable conflicts.
pub const CONFLICTED: &str = "conflicted";

opaque_id!(
    ConflictId,
    AlternativeId,
    HistoryId,
    DeclarationId,
    ValidationId
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySummary {
    pub id: HistoryId,
    pub entry: EntryId,
    pub change: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub items: Vec<HistorySummary>,
    pub next: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub history: HistoryId,
    pub expected_head: HeadToken,
    pub restore_metadata: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub protocol: String,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictState {
    Open,
    Resolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictSummary {
    pub id: ConflictId,
    /// The original private candidate receipt whose integration retained this conflict.
    pub receipt: ReceiptId,
    pub reason: ConflictReason,
    pub state: ConflictState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictPage {
    pub items: Vec<ConflictSummary>,
    /// Opaque namespace/principal/query-bound continuation.
    pub next: Option<String>,
}

/// base = the candidate's recorded base, current = the destination head at integration,
/// candidate = the original private candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlternativeSide {
    Base,
    Current,
    Candidate,
}

/// `entry: None` selects the whole immutable tree of that side. A present `entry` with
/// `path: None` is an explicit absent (or currently unauthorized) selector, never an empty file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternativeRef {
    pub id: AlternativeId,
    pub side: AlternativeSide,
    pub entry: Option<EntryId>,
    pub path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictDetail {
    pub summary: ConflictSummary,
    pub alternatives: Vec<AlternativeRef>,
    /// The destination head a resolution must currently be based on.
    pub expected_head: HeadToken,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRequest {
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub conflicts: Vec<ConflictId>,
    pub expected_head: HeadToken,
    /// A complete private replacement candidate based on `expected_head`.
    pub replacement: ReceiptId,
}
impl ResolutionRequest {
    pub fn validate(&self) -> Result<(), FsError> {
        let unique = self
            .conflicts
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if self.conflicts.is_empty()
            || self.conflicts.len() > MAX_RESOLUTION_CONFLICTS
            || unique.len() != self.conflicts.len()
        {
            return Err(FsError::InvalidDescriptor);
        }
        Ok(())
    }
}

/// Body of `409` for an integration that retained conflicts instead of publishing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictedIntegration {
    pub code: String,
    pub conflicts: Vec<ConflictId>,
}

/// Coverage is an explicit statement about only the declared set, never inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyCoverage {
    CompleteDeclared,
    Partial,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadDependency {
    pub view: ViewId,
    pub revision: crate::RevisionId,
    pub entry: EntryId,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingPathAssertion {
    pub view: ViewId,
    pub revision: crate::RevisionId,
    pub path: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclareRequest {
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub candidate: ReceiptId,
    pub reads: Vec<ReadDependency>,
    pub missing: Vec<MissingPathAssertion>,
    pub coverage: DependencyCoverage,
    pub validator: Option<String>,
}
impl DeclareRequest {
    pub fn validate(&self) -> Result<(), FsError> {
        if self.reads.len() + self.missing.len() > 128 {
            return Err(FsError::LimitExceeded);
        }
        for m in &self.missing {
            crate::paths::validate_path(&m.path)?;
        }
        if self
            .validator
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 128)
        {
            return Err(FsError::InvalidDescriptor);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationReceipt {
    pub id: DeclarationId,
    pub candidate: ReceiptId,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedIntegrationRequest {
    pub integration: crate::IntegrationRequest,
    pub declaration: DeclarationId,
    pub validation: Option<ValidationId>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    Pass,
    Fail,
    Timeout,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRecord {
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub declaration: DeclarationId,
    pub expected_head: HeadToken,
    pub validator: String,
    pub version: String,
    pub executable_hash: crate::ObjectId,
    pub inputs: ViewBinding,
    pub output: ReceiptId,
    pub outcome: ValidationOutcome,
}
