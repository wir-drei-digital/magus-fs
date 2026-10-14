//! Immutable conflict records, authorized alternative export and explicit resolution.
//! Records bind the original candidate receipt, its full base, the destination head at
//! integration and the integrating operation; resolution is a separate link row.
use crate::{
    auth::{digest, AuthContext},
    publication::barrier,
    revisions as r,
    submission::{self, save_operation, NewOperation},
    views::{self, core_error},
    Error, Result, ServiceState,
};
use axum::{
    body::Body,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use magus_fs_core::{protocol::*, *};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::Transaction;

/// The immutable inputs a retained conflict is bound to.
pub(crate) struct Retained<'a> {
    pub branch: &'a str,
    pub receipt: &'a ReceiptId,
    pub integration: &'a OperationId,
    pub root: &'a EntryId,
    pub base: &'a RevisionId,
    pub candidate: &'a RevisionId,
    pub current: &'a RevisionId,
    pub original_head: &'a str,
    pub current_head: &'a str,
}
#[derive(Clone)]
pub(crate) enum Retain {
    Entries(Vec<EntryConflict>),
    /// A whole-candidate conflict: unknown causality or an exhausted record budget.
    Whole(ConflictReason),
}
#[derive(Serialize)]
struct Payload<'a> {
    receipt: &'a ReceiptId,
    integration: &'a OperationId,
    base: &'a RevisionId,
    candidate: &'a RevisionId,
    current: &'a RevisionId,
    original_head: &'a str,
    current_head: &'a str,
    reason: ConflictReason,
    policy: MergeMode,
    conflict: Option<&'a EntryConflict>,
}
fn code(policy: MergeMode) -> &'static str {
    match policy {
        MergeMode::Opaque => "opaque",
        MergeMode::Text => "text",
    }
}
fn side_code(side: AlternativeSide) -> &'static str {
    match side {
        AlternativeSide::Base => "base",
        AlternativeSide::Current => "current",
        AlternativeSide::Candidate => "candidate",
    }
}
fn side_parse(side: &str) -> Result<AlternativeSide> {
    match side {
        "base" => Ok(AlternativeSide::Base),
        "current" => Ok(AlternativeSide::Current),
        "candidate" => Ok(AlternativeSide::Candidate),
        _ => Err(Error::backend()),
    }
}

/// Inserts immutable records (at most `MAX_RESOLUTION_CONFLICTS`) in the caller's commit.
pub(crate) async fn record(
    tx: &Transaction<'_>,
    c: &AuthContext,
    x: &Retained<'_>,
    retain: Retain,
) -> Result<Vec<ConflictId>> {
    let items: Vec<(ConflictReason, MergeMode, Option<EntryConflict>)> = match retain {
        Retain::Entries(list) if list.len() <= MAX_RESOLUTION_CONFLICTS => list
            .into_iter()
            .map(|e| (e.reason, e.policy, Some(e)))
            .collect(),
        Retain::Entries(_) => vec![(ConflictReason::MergeBudget, MergeMode::Opaque, None)],
        Retain::Whole(reason) => vec![(reason, MergeMode::Opaque, None)],
    };
    let mut ids = vec![];
    for (reason, policy, conflict) in items {
        let id = ConflictId::random().map_err(core_error)?;
        let entry = conflict
            .as_ref()
            .map(|e| &e.id)
            .filter(|e| *e != x.root)
            .map(|e| e.as_str().to_owned());
        let payload = r::json(&Payload {
            receipt: x.receipt,
            integration: x.integration,
            base: x.base,
            candidate: x.candidate,
            current: x.current,
            original_head: x.original_head,
            current_head: x.current_head,
            reason,
            policy,
            conflict: conflict.as_ref(),
        })?;
        tx.execute("INSERT INTO conflicts(id,namespace,branch,principal,replica,receipt,integration,base_revision,candidate_revision,current_revision,original_head,current_head,reason,policy,entry,payload,digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
            &[&id.as_str(),&c.namespace,&x.branch,&c.principal,&c.replica,&x.receipt.as_str(),&x.integration.as_str(),&x.base.as_str(),&x.candidate.as_str(),&x.current.as_str(),&x.original_head,&x.current_head,&reason.code(),&code(policy),&entry,&payload,&digest(payload.as_bytes())]).await?;
        for (side, revision) in [
            (AlternativeSide::Base, x.base),
            (AlternativeSide::Current, x.current),
            (AlternativeSide::Candidate, x.candidate),
        ] {
            let alternative = AlternativeId::random().map_err(core_error)?;
            tx.execute("INSERT INTO conflict_alternatives(id,conflict,side,revision,entry) VALUES($1,$2,$3,$4,$5)",
                &[&alternative.as_str(),&id.as_str(),&side_code(side),&revision.as_str(),&entry]).await?;
        }
        ids.push(id);
    }
    Ok(ids)
}

/// Whether the candidate or its unpublished ancestry carried unknown native causality.
/// Candidates committed before migration004 fall back to their own descriptor provenance.
pub(crate) async fn unknown_causality(
    state: &ServiceState,
    c: &AuthContext,
    receipt: &ReceiptId,
    derived: &Revision,
) -> Result<bool> {
    let recorded = state
        .db
        .acquire()
        .await?
        .run(|db| {
            Box::pin(async move {
                Ok(db
                    .query_opt(
                        "SELECT unknown FROM candidate_causality WHERE namespace=$1 AND receipt=$2",
                        &[&c.namespace, &receipt.as_str()],
                    )
                    .await?
                    .map(|r| r.get::<_, bool>(0)))
            })
        })
        .await?;
    Ok(recorded.unwrap_or(false) || derived.provenance == UNKNOWN_CAUSALITY_PROVENANCE)
}

struct Row {
    id: String,
    branch: String,
    receipt: String,
    integration: String,
    reason: String,
    candidate: String,
    sequence: i64,
    resolved: bool,
    replica: String,
    entry: Option<String>,
}
const SELECT: &str = "SELECT c.id,c.branch,c.receipt,c.integration,c.reason,c.candidate_revision,c.sequence,(EXISTS(SELECT 1 FROM conflict_resolutions x WHERE x.conflict=c.id)),c.replica,c.entry FROM conflicts c";
fn row(r: &tokio_postgres::Row) -> Row {
    Row {
        id: r.get(0),
        branch: r.get(1),
        receipt: r.get(2),
        integration: r.get(3),
        reason: r.get(4),
        candidate: r.get(5),
        sequence: r.get(6),
        resolved: r.get(7),
        replica: r.get(8),
        entry: r.get(9),
    }
}
fn summary(row: &Row) -> Result<ConflictSummary> {
    Ok(ConflictSummary {
        id: ConflictId::parse(row.id.clone()).map_err(|_| Error::backend())?,
        receipt: ReceiptId::parse(row.receipt.clone()).map_err(|_| Error::backend())?,
        reason: ConflictReason::parse(&row.reason).map_err(|_| Error::backend())?,
        state: if row.resolved {
            ConflictState::Resolved
        } else {
            ConflictState::Open
        },
    })
}
/// Conflicts retained for candidates of the caller's own replica (the holder of the
/// original private receipt) on a branch its current grant names.
async fn load(state: &ServiceState, c: &AuthContext, id: &str) -> Result<Row> {
    let id = ConflictId::parse(id).map_err(|_| Error::not_found())?;
    let row = state.db.acquire().await?.run(|db| Box::pin(async move {
        Ok(db.query_opt(&format!("{SELECT} WHERE c.namespace=$1 AND c.id=$2 AND c.principal=$3 AND c.replica=$4 AND c.branch=ANY($5)"),&[&c.namespace,&id.as_str(),&c.principal,&c.replica,&c.branches]).await?.map(|r| row(&r)))
    })).await?;
    row.ok_or(Error::not_found())
}
/// Per-request caches of current branch snapshots and side descriptors.
#[derive(Default)]
struct Visibility {
    snapshots: BTreeMap<String, r::Snapshot>,
    revisions: BTreeMap<String, Revision>,
}
impl Visibility {
    async fn snapshot(
        &mut self,
        state: &ServiceState,
        c: &AuthContext,
        branch: &str,
    ) -> Result<&r::Snapshot> {
        if !self.snapshots.contains_key(branch) {
            let s = r::snapshot(&state.db, c, branch, None).await?;
            self.snapshots.insert(branch.to_owned(), s);
        }
        Ok(&self.snapshots[branch])
    }
    async fn revision(
        &mut self,
        state: &ServiceState,
        c: &AuthContext,
        id: &str,
    ) -> Result<&Revision> {
        if !self.revisions.contains_key(id) {
            let r = descriptor(state, c, id).await?;
            self.revisions.insert(id.to_owned(), r);
        }
        Ok(&self.revisions[id])
    }
    /// Disclosed paths per alternative under the caller's current grant, scope and entry
    /// authorization. An entry conflict whose identity is authorized on no side is hidden.
    async fn paths(
        &mut self,
        state: &ServiceState,
        c: &AuthContext,
        row: &Row,
        alternatives: &[Alternative],
    ) -> Result<Option<Vec<Option<String>>>> {
        self.snapshot(state, c, &row.branch).await?;
        let s = self.snapshots.remove(&row.branch).ok_or(Error::backend())?;
        let result = self.paths_at(state, c, &s, row, alternatives).await;
        self.snapshots.insert(row.branch.clone(), s);
        result
    }
    /// The same rule against an explicit snapshot (R16: the snapshot whose head the
    /// resolution's expected-head check and commit recheck use).
    async fn paths_at(
        &mut self,
        state: &ServiceState,
        c: &AuthContext,
        s: &r::Snapshot,
        row: &Row,
        alternatives: &[Alternative],
    ) -> Result<Option<Vec<Option<String>>>> {
        let mut paths = vec![];
        for alt in alternatives {
            self.revision(state, c, &alt.revision).await?;
        }
        let current = s.current.as_ref().ok_or(Error::not_found())?;
        for alt in alternatives {
            paths.push(disclosed(
                s,
                &self.revisions[&alt.revision],
                current,
                alt.entry.as_ref(),
            ));
        }
        if row.entry.is_some() && paths.iter().all(Option::is_none) {
            return Ok(None);
        }
        Ok(Some(paths))
    }
}
async fn descriptor(state: &ServiceState, c: &AuthContext, revision: &str) -> Result<Revision> {
    let bytes = state
        .db
        .acquire()
        .await?
        .run(|db| {
            Box::pin(async move {
                Ok(db
                    .query_opt(
                        "SELECT descriptor FROM revisions WHERE namespace=$1 AND revision=$2",
                        &[&c.namespace, &revision],
                    )
                    .await?
                    .map(|r| r.get::<_, Vec<u8>>(0)))
            })
        })
        .await?;
    r::decode(&bytes.ok_or(Error::backend())?)
}
struct Alternative {
    id: String,
    side: AlternativeSide,
    revision: String,
    entry: Option<EntryId>,
}
async fn alternatives(state: &ServiceState, conflict: &str) -> Result<Vec<Alternative>> {
    let rows = state.db.acquire().await?.run(|db| Box::pin(async move {
        Ok(db.query("SELECT id,side,revision,entry FROM conflict_alternatives WHERE conflict=$1 ORDER BY side",&[&conflict]).await?.iter().map(|r| (r.get::<_, String>(0),r.get::<_, String>(1),r.get::<_, String>(2),r.get::<_, Option<String>>(3))).collect::<Vec<_>>())
    })).await?;
    rows.into_iter()
        .map(|(id, side, revision, entry)| {
            Ok(Alternative {
                id,
                side: side_parse(&side)?,
                revision,
                entry: entry
                    .map(|e| EntryId::parse(e).map_err(|_| Error::backend()))
                    .transpose()?,
            })
        })
        .collect()
}

fn token(c: &AuthContext, sequence: i64) -> String {
    let mac = digest(format!("{}|{}|conflicts|{sequence}", c.namespace, c.principal).as_bytes());
    format!("{sequence:016x}{}", &mac[..16])
}
fn cursor(c: &AuthContext, raw: Option<String>) -> Result<i64> {
    let raw = raw.unwrap_or_default();
    if raw.is_empty() {
        return Ok(0);
    }
    let value = raw
        .strip_prefix("cursor=")
        .filter(|v| v.len() == 32 && !v.contains('&'))
        .ok_or(Error::invalid("invalid_request"))?;
    let sequence = i64::from_str_radix(&value[..16], 16)
        .ok()
        .filter(|s| *s > 0)
        .ok_or(Error::invalid("invalid_cursor"))?;
    if token(c, sequence) != value {
        return Err(Error::invalid("invalid_cursor"));
    }
    Ok(sequence)
}

pub(crate) async fn list(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Result<Json<ConflictPage>> {
    let c = state.auth(&headers, &ns, "read").await?;
    let after = cursor(&c, raw)?;
    let limit = MAX_PAGE_ITEMS as i64 + 1;
    let rows = state.db.acquire().await?.run(|db| { let c=&c; Box::pin(async move {
        Ok(db.query(&format!("{SELECT} WHERE c.namespace=$1 AND c.principal=$2 AND c.replica=$3 AND c.branch=ANY($4) AND c.sequence>$5 ORDER BY c.sequence LIMIT $6"),&[&c.namespace,&c.principal,&c.replica,&c.branches,&after,&limit]).await?.iter().map(row).collect::<Vec<_>>())
    })}).await?;
    let more = rows.len() > MAX_PAGE_ITEMS;
    let rows = &rows[..rows.len().min(MAX_PAGE_ITEMS)];
    // A filtered page may be short or empty; the cursor still advances past scanned rows.
    let mut visibility = Visibility::default();
    let mut items = vec![];
    for row in rows {
        let alternatives = alternatives(&state, &row.id).await?;
        if visibility
            .paths(&state, &c, row, &alternatives)
            .await?
            .is_some()
        {
            items.push(summary(row)?);
        }
    }
    // R17: the same final current-credential recheck as detail before anything is returned.
    for s in visibility.snapshots.values() {
        r::final_read(&state.db, s).await?;
    }
    Ok(Json(ConflictPage {
        items,
        next: if more {
            rows.last().map(|r| token(&c, r.sequence))
        } else {
            None
        },
    }))
}

/// Path of an alternative identity only when it is present and currently authorized.
fn disclosed(
    s: &r::Snapshot,
    side: &Revision,
    current: &Revision,
    entry: Option<&EntryId>,
) -> Option<String> {
    let entry = entry?;
    let projected = views::alternative(
        side,
        &current.tree,
        s.authority().ok()?,
        &s.context.prefixes,
        s.context.action("history").is_ok(),
        Some(entry),
    )
    .ok()?;
    projected
        .tree
        .entries
        .iter()
        .find(|e| &e.id == entry)
        .map(|e| e.path.clone())
}

pub(crate) async fn detail(
    State(state): State<ServiceState>,
    Path((ns, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<ConflictDetail>> {
    let c = state.auth(&headers, &ns, "read").await?;
    let row = load(&state, &c, &id).await?;
    let alternatives = alternatives(&state, &row.id).await?;
    let mut visibility = Visibility::default();
    let paths = visibility
        .paths(&state, &c, &row, &alternatives)
        .await?
        .ok_or(Error::not_found())?;
    let s = visibility
        .snapshots
        .remove(&row.branch)
        .ok_or(Error::backend())?;
    let mut refs = vec![];
    for (alt, path) in alternatives.into_iter().zip(paths) {
        // `path: None` is the explicit selector for absent *or* currently unauthorized.
        refs.push(AlternativeRef {
            id: AlternativeId::parse(alt.id).map_err(|_| Error::backend())?,
            side: alt.side,
            path,
            entry: alt.entry,
        });
    }
    let head = HeadToken::parse(s.head.clone().ok_or(Error::not_found())?).map_err(core_error)?;
    r::final_read(&state.db, &s).await?;
    Ok(Json(ConflictDetail {
        summary: summary(&row)?,
        alternatives: refs,
        expected_head: head,
    }))
}

/// Creates (or reuses) an authorized pinned view of one immutable alternative for the
/// ordinary descriptor/object export routes, which re-authorize it on every use.
pub(crate) async fn alternative(
    State(state): State<ServiceState>,
    Path((ns, id, alternative)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<ViewBinding>> {
    let c = state.auth(&headers, &ns, "read").await?;
    let row = load(&state, &c, &id).await?;
    let alternative = AlternativeId::parse(alternative).map_err(|_| Error::not_found())?;
    let alt = alternatives(&state, &row.id)
        .await?
        .into_iter()
        .find(|a| a.id == alternative.as_str())
        .ok_or(Error::not_found())?;
    let s = r::snapshot(&state.db, &c, &row.branch, None).await?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let side = descriptor(&state, &c, &alt.revision).await?;
    // Authorization first: an absent identity and a present-but-unauthorized one are the
    // same `404 not_found` (views::alternative requires the identity in the projection).
    let projected = views::alternative(
        &side,
        &current.tree,
        s.authority()?,
        &s.context.prefixes,
        s.context.action("history").is_ok(),
        alt.entry.as_ref(),
    )?;
    let bytes = r::encode(&projected)?;
    let projected_id = r::rid(&projected)?;
    let head = HeadToken::parse(s.head.clone().ok_or(Error::not_found())?).map_err(core_error)?;
    let entry = alt.entry.as_ref().map(|e| e.as_str().to_owned());
    let branch = row.branch.clone();
    state.db.acquire().await?.run(|db| Box::pin(async move {
        let tx = db.transaction().await?;
        let c = r::recheck(&tx, &s, "read").await?;
        let existing = tx.query_opt("SELECT id FROM views WHERE namespace=$1 AND branch=$2 AND credential=$3 AND principal=$4 AND replica=$5 AND full_revision=$6 AND head=$7 AND projected_revision=$8 AND descriptor=$9 AND credential_generation=$10 AND grant_actions=$11 AND grant_branches=$12 AND grant_prefixes=$13 AND alternative=$14 ORDER BY id LIMIT 1",
            &[&ns,&branch,&c.credential,&c.principal,&c.replica,&alt.revision,&head.as_str(),&projected_id.as_str(),&bytes,&c.generation,&c.actions,&c.branches,&c.prefixes,&alternative.as_str()]).await?;
        let view = match existing {
            Some(row) => ViewId::parse(row.get::<_, String>(0)).map_err(core_error)?,
            None => {
                let view = ViewId::random().map_err(core_error)?;
                tx.execute("INSERT INTO views(id,namespace,branch,credential,principal,replica,full_revision,head,projected_revision,descriptor,credential_generation,grant_actions,grant_branches,grant_prefixes,alternative,alternative_entry) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
                    &[&view.as_str(),&ns,&branch,&c.credential,&c.principal,&c.replica,&alt.revision,&head.as_str(),&projected_id.as_str(),&bytes,&c.generation,&c.actions,&c.branches,&c.prefixes,&alternative.as_str(),&entry]).await?;
                view
            }
        };
        tx.commit().await?;
        Ok(Json(ViewBinding { view, head, revision: projected_id }))
    })).await
}

/// Explicit resolution: a complete private replacement candidate based on the current
/// head replaces every conflict retained for the named candidate integrations at once.
pub(crate) async fn resolve(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let c = state.auth(&headers, &ns, "integrate").await?;
    let req: ResolutionRequest = crate::json_body(body, &headers).await?;
    req.validate()
        .map_err(|_| Error::invalid("invalid_request"))?;
    if req.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    let serialized = r::json(&req)?;
    for attempt in 0..3 {
        if let Some(op) =
            submission::operation(&state, &c, req.replica.as_str(), req.operation.as_str()).await?
        {
            submission::replay(&state, &c, &op).await?;
            if op.kind != "resolution" || op.digest != digest(serialized.as_bytes()) {
                return Err(Error::conflict());
            }
            return op.response();
        }
        let candidate_id = state.db.acquire().await?.run(|db| { let req=&req; let c=&c; let ns=&ns; Box::pin(async move {
            db.query_opt("SELECT operation FROM operations WHERE namespace=$1 AND receipt=$2 AND replica=$3 AND principal=$4 AND credential=$5 AND kind='candidate'",&[&ns,&req.replacement.as_str(),&c.replica,&c.principal,&c.credential]).await?.map(|r| r.get::<_, String>(0)).ok_or(Error::not_found())
        })}).await?;
        let candidate = submission::operation(&state, &c, &c.replica, &candidate_id)
            .await?
            .ok_or(Error::not_found())?;
        let ids: Vec<String> = req
            .conflicts
            .iter()
            .map(|i| i.as_str().to_owned())
            .collect();
        let targets = state.db.acquire().await?.run(|db| { let c=&c; let ids=&ids; Box::pin(async move {
            Ok(db.query(&format!("{SELECT} WHERE c.namespace=$1 AND c.principal=$2 AND c.id=ANY($3) AND c.branch=ANY($4)"),&[&c.namespace,&c.principal,ids,&c.branches]).await?.iter().map(row).collect::<Vec<_>>())
        })}).await?;
        // R12: only the replica holding the conflicted candidates' original private receipts
        // (the source of this replacement) can close them, on the same branch.
        if targets.len() != req.conflicts.len()
            || targets
                .iter()
                .any(|t| t.branch != candidate.branch || t.replica != c.replica)
        {
            return Err(Error::not_found());
        }
        if targets.iter().any(|t| t.resolved) {
            return Err(Error {
                status: StatusCode::CONFLICT,
                code: "already_resolved",
            });
        }
        // Every conflict retained by the same integration blocks that candidate together.
        let integrations: Vec<String> = targets
            .iter()
            .map(|t| t.integration.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let siblings = state
            .db
            .acquire()
            .await?
            .run(|db| {
                let c = &c;
                let integrations = &integrations;
                Box::pin(async move {
                    Ok(db
                        .query(
                            &format!("{SELECT} WHERE c.namespace=$1 AND c.integration=ANY($2)"),
                            &[&c.namespace, integrations],
                        )
                        .await?
                        .iter()
                        .map(row)
                        .collect::<Vec<_>>())
                })
            })
            .await?;
        let s = r::snapshot(&state.db, &c, &candidate.branch, candidate.view.as_deref()).await?;
        s.context.action("integrate")?;
        // Ruling R16 (R19: on the same snapshot whose head is checked against
        // `expected_head` and re-checked at commit): named conflicts must be visible to the
        // caller; an unnamed sibling is acceptable only when it is hidden from the caller (it
        // is then superseded, provided the replacement leaves its entry at the head value).
        let mut visibility = Visibility::default();
        for t in &targets {
            let alternatives = alternatives(&state, &t.id).await?;
            if visibility
                .paths_at(&state, &c, &s, t, &alternatives)
                .await?
                .is_none()
            {
                return Err(Error::not_found());
            }
        }
        let named: BTreeSet<String> = ids.iter().cloned().collect();
        let mut hidden = vec![];
        for sibling in siblings.iter().filter(|x| !named.contains(&x.id)) {
            let alternatives = alternatives(&state, &sibling.id).await?;
            if sibling.resolved
                || visibility
                    .paths_at(&state, &c, &s, sibling, &alternatives)
                    .await?
                    .is_some()
            {
                return Err(Error::invalid("incomplete_resolution"));
            }
            hidden.push(sibling);
        }
        let derived = candidate.derived.as_ref().ok_or(Error::not_found())?;
        let original: submission::CandidateRequest = r::parse(&candidate.request)?;
        let view = s.view.as_ref().ok_or(Error::not_found())?;
        // Never reinterpret a resolution prepared for an older destination head.
        let stale = s.head.as_deref() != Some(req.expected_head.as_str())
            || view.head != req.expected_head.as_str();
        let current = s.current.as_ref().ok_or(Error::not_found())?;
        let mut resolved = derived.clone();
        if !stale {
            if unknown_causality(&state, &c, &req.replacement, derived).await? {
                return Err(Error::invalid("invalid_resolution"));
            }
            // Ruling R21: never revive a published identity absent from the projection.
            submission::refuse_revived(&state, &s, &submission::entry_ids([&derived.tree])).await?;
            // Current rights and scope over the complete replacement; never broadens access.
            submission::authorize_candidate(&s, derived)?;
            let mut candidates = targets
                .iter()
                .map(|t| RevisionId::parse(t.candidate.clone()).map_err(|_| Error::backend()))
                .collect::<Result<Vec<_>>>()?;
            candidates.sort();
            for id in candidates {
                if !resolved.parents.contains(&id) {
                    resolved.parents.push(id);
                }
            }
        }
        if !stale {
            // R16: hidden entries stay exactly at the current head values.
            let at = |t: &Tree, id: &str| t.entries.iter().find(|e| e.id.as_str() == id).cloned();
            for h in &hidden {
                if let Some(entry) = &h.entry {
                    if at(&resolved.tree, entry) != at(&current.tree, entry) {
                        return Err(Error::invalid("invalid_resolution"));
                    }
                }
            }
        }
        let superseded: Vec<String> = hidden.iter().map(|h| h.id.clone()).collect();
        let resolved_id = r::rid(&resolved)?;
        let derived_id = r::rid(derived)?;
        let required = r::objects(&resolved)?;
        let paths = crate::reconciliation::changed_paths(&current.tree, &resolved.tree);
        let receipt = SharedReceipt {
            receipt: ReceiptId::random().map_err(core_error)?,
            operation: req.operation.clone(),
            replica: req.replica.clone(),
            submitted_revision: original.revision.clone(),
            branch: BranchName::parse(candidate.branch.clone()).map_err(core_error)?,
            head: HeadToken::random().map_err(core_error)?,
        };
        let result = if stale {
            "{\"code\":\"stale_head\"}".to_owned()
        } else {
            r::json(&receipt)?
        };
        let provenance = r::json(&serde_json::json!({
            "kind":"resolution","operation":req.operation,"conflicts":req.conflicts,
            "replacement":req.replacement,"submitted":original.revision,"superseded":superseded,
            "current":r::rid(current)?,"candidates":resolved.parents,
        }))?;
        let bytes = r::encode(&resolved)?;
        let resolved_tree = resolved.tree.clone();
        barrier("resolution").await;
        let commit = state.db.acquire().await?.run(|db| { let state=&state; let req=&req; let serialized=&serialized; let ids=&ids; let candidate=&candidate; let original=&original; let receipt=&receipt; let result=&result; let paths=&paths; let required=&required; let bytes=&bytes; let resolved_id=&resolved_id; let derived_id=&derived_id; let provenance=&provenance; let s=&s; let superseded=&superseded; let resolved_tree=&resolved_tree; Box::pin(async move {
            let tx = db.transaction().await?;
            let current = r::recheck(&tx, s, "integrate").await?;
            if tx.query_opt("SELECT operation FROM operations WHERE namespace=$1 AND replica=$2 AND operation=$3",&[&current.namespace,&current.replica,&req.operation.as_str()]).await?.is_some() {
                return Err(Error::conflict());
            }
            if !stale {
                crate::dependencies::check_publication(&tx,s,Some(&req.replacement),resolved_tree,None).await?;
                let all: Vec<String> = ids.iter().chain(superseded.iter()).cloned().collect();
                let open: i64 = tx.query_one("SELECT count(*) FROM conflicts c WHERE c.namespace=$1 AND c.id=ANY($2) AND NOT EXISTS(SELECT 1 FROM conflict_resolutions x WHERE x.conflict=c.id)",&[&current.namespace,&all]).await?.get(0);
                if open != all.len() as i64 {
                    return Err(Error { status: StatusCode::CONFLICT, code: "already_resolved" });
                }
                let generations = r::ready(&tx, &current, required, None, required).await?;
                r::save_revision(&tx, &current.namespace, resolved_id, bytes, &generations).await?;
                r::register_entries(&tx, &current.namespace, s.current.as_ref().map(|c| &c.tree), resolved_tree).await?;
                r::publish_history(&tx,&current.namespace,&candidate.branch,&r::decode(bytes)?).await?;
                tx.execute("UPDATE branches SET revision=$3,head=$4 WHERE namespace=$1 AND name=$2",&[&current.namespace,&candidate.branch,&resolved_id.as_str(),&receipt.head.as_str()]).await?;
                tx.execute("INSERT INTO changes(namespace,branch,head,paths) VALUES($1,$2,$3,$4)",&[&current.namespace,&candidate.branch,&receipt.head.as_str(),paths]).await?;
            }
            save_operation(&tx, &current, NewOperation {
                operation: &req.operation, kind: "resolution", request: serialized, result,
                status: if stale { 409 } else { 200 }, branch: &candidate.branch,
                view: Some(original.original_view.as_str()), receipt: &receipt.receipt,
                submitted: &original.revision,
                derived: if stale { derived_id } else { resolved_id },
            }).await?;
            if !stale {
                crate::continuation::record_publication(&tx,&current.namespace,receipt,resolved_id).await?;
                for (id, hidden) in ids.iter().map(|i| (i, false)).chain(superseded.iter().map(|i| (i, true))) {
                    tx.execute("INSERT INTO conflict_resolutions(conflict,namespace,replica,operation,revision,superseded) VALUES($1,$2,$3,$4,$5,$6)",&[id,&current.namespace,&current.replica,&req.operation.as_str(),&resolved_id.as_str(),&hidden]).await?;
                }
                tx.execute("INSERT INTO revision_provenance(namespace,revision,kind,operation,payload,digest) VALUES($1,$2,'resolution',$3,$4,$5)",&[&current.namespace,&resolved_id.as_str(),&req.operation.as_str(),provenance,&digest(provenance.as_bytes())]).await?;
            }
            tx.commit().await?;
            if !stale { state.shared_committed(receipt, resolved_id); }
            Ok((if stale { StatusCode::CONFLICT } else { StatusCode::OK }, [("content-type","application/json")], result.clone()).into_response())
        })}).await;
        match commit {
            Err(e) if e.code == "conflict" && attempt < 2 => {
                tokio::time::sleep(std::time::Duration::from_millis(if attempt == 0 {
                    100
                } else {
                    300
                }))
                .await;
            }
            other => return other,
        }
    }
    Err(Error::conflict())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(principal: &str) -> AuthContext {
        AuthContext {
            credential: "c".into(),
            namespace: "n".repeat(32),
            principal: principal.into(),
            replica: "r".into(),
            generation: 1,
            token_hash: String::new(),
            actions: vec!["read".into()],
            branches: vec!["main".into()],
            prefixes: vec!["".into()],
            depth: 0,
        }
    }
    #[test]
    fn absent_and_unauthorized_alternatives_are_indistinguishable() {
        let principal = PrincipalId::parse(format!("principal:{:032x}", 1)).unwrap();
        let group = GroupId::parse(format!("group:{:032x}", 1)).unwrap();
        let authority = Authority {
            principal: principal.clone(),
            uid: 1001,
            gid: 1001,
            primary_group: group.clone(),
            groups: vec![group.clone()],
            dac_override: false,
            ownership_transfer: false,
        };
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o755,
        };
        let entry = |mode| Entry {
            path: "f".into(),
            id: EntryId::parse(format!("entry:{:032x}", 7)).unwrap(),
            parent: root.id.clone(),
            owner: principal.clone(),
            group: group.clone(),
            mode,
            content: EntryContent::Directory,
        };
        let revision = |entries| Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            principal: principal.clone(),
            captured_at_ns: 0,
            coverage: vec!["".into()],
            provenance: "explicit".into(),
            restoration: None,
            tree: Tree {
                root: root.clone(),
                entries,
            },
        };
        let id = entry(0).id;
        let unauthorized = revision(vec![entry(0)]);
        let absent = revision(vec![]);
        let readable = revision(vec![entry(0o755)]);
        let check = |side: &Revision, current: &Revision| {
            views::alternative(
                side,
                &current.tree,
                &authority,
                &["".into()],
                true,
                Some(&id),
            )
            .map(|_| ())
            .map_err(|e| (e.status, e.code))
        };
        // Current metadata governs a present identity: mode 0 now hides the side's entry.
        let denied = check(&readable, &unauthorized).unwrap_err();
        assert_eq!(check(&absent, &unauthorized).unwrap_err(), denied);
        assert_eq!(denied, (StatusCode::NOT_FOUND, "not_found"));
        assert!(check(&readable, &readable).is_ok());
    }
    #[test]
    fn identity_moved_out_of_scope_is_indistinguishable_from_deleted() {
        let principal = PrincipalId::parse(format!("principal:{:032x}", 1)).unwrap();
        let group = GroupId::parse(format!("group:{:032x}", 1)).unwrap();
        let authority = Authority {
            principal: principal.clone(),
            uid: 1001,
            gid: 1001,
            primary_group: group.clone(),
            groups: vec![group.clone()],
            dac_override: false,
            ownership_transfer: false,
        };
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o755,
        };
        let dir = |path: &str, n: u32| Entry {
            path: path.into(),
            id: EntryId::parse(format!("entry:{n:032x}")).unwrap(),
            parent: root.id.clone(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o755,
            content: EntryContent::Directory,
        };
        let file = |path: &str, parent: &Entry| Entry {
            path: path.into(),
            id: EntryId::parse(format!("entry:{:032x}", 9)).unwrap(),
            parent: parent.id.clone(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o755,
            content: EntryContent::Directory,
        };
        let (reports, secret) = (dir("reports", 1), dir("secret", 2));
        let tree = |entries| Tree {
            root: root.clone(),
            entries,
        };
        let side = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            principal: principal.clone(),
            captured_at_ns: 0,
            coverage: vec!["".into()],
            provenance: "explicit".into(),
            restoration: None,
            tree: tree(vec![
                reports.clone(),
                secret.clone(),
                file("reports/f", &reports),
            ]),
        };
        let moved = tree(vec![
            reports.clone(),
            secret.clone(),
            file("secret/f", &secret),
        ]);
        let deleted = tree(vec![reports.clone(), secret.clone()]);
        let id = file("x", &reports).id;
        let scope = ["reports".to_string()];
        let check = |current: &Tree, history: bool| {
            views::alternative(&side, current, &authority, &scope, history, Some(&id))
                .map(|r| r.tree.entries.len())
                .map_err(|e| e.code)
        };
        for history in [false, true] {
            assert_eq!(
                check(&moved, history),
                check(&deleted, history),
                "history={history}"
            );
        }
        assert_eq!(check(&moved, false), Err("not_found"));
        assert_eq!(
            check(&moved, true),
            Ok(2),
            "retained history at the in-scope historic path"
        );
        // R19-C: others also make the moved-out identity unreadable: still exactly like
        // a deleted one (its out-of-scope current permissions never apply).
        let mut unreadable = moved.clone();
        unreadable.entries[2].mode = 0;
        for history in [false, true] {
            assert_eq!(
                check(&unreadable, history),
                check(&deleted, history),
                "unreadable history={history}"
            );
        }
        // The same move stays IN a root-scoped reader's authority. The real current
        // ancestor must authorize access even when the old ancestor remains readable.
        let root_scope = [String::new()];
        let check_current = |current: &Tree, history| {
            views::alternative(&side, current, &authority, &root_scope, history, Some(&id))
                .map(|_| ())
                .map_err(|e| e.code)
        };
        let mut denied_parent = moved.clone();
        denied_parent.entries[1].mode = 0o644;
        for history in [false, true] {
            assert_eq!(check_current(&moved, history), Ok(()));
            assert_eq!(check_current(&denied_parent, history), Err("not_found"));
            assert_eq!(check_current(&moved, history), Ok(()));
        }
        // The current side at the out-of-scope location is never disclosed.
        let mut current_side = side.clone();
        current_side.tree = moved.clone();
        assert!(
            views::alternative(&current_side, &moved, &authority, &scope, true, Some(&id)).is_err()
        );
    }
    #[test]
    fn continuation_tokens_are_namespace_principal_and_query_bound() {
        let alice = context("principal:a");
        let bob = context("principal:b");
        let t = token(&alice, 42);
        assert_eq!(t.len(), 32);
        assert_eq!(cursor(&alice, Some(format!("cursor={t}"))).unwrap(), 42);
        assert!(cursor(&bob, Some(format!("cursor={t}"))).is_err());
        let flipped = if t.ends_with('0') { '1' } else { '0' };
        assert!(cursor(&alice, Some(format!("cursor={}{flipped}", &t[..31]))).is_err());
        assert!(cursor(&alice, Some(format!("cursor={t}&x=1"))).is_err());
        assert!(cursor(&alice, Some("after=1".into())).is_err());
        assert_eq!(cursor(&alice, None).unwrap(), 0);
    }
}
