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
}
const SELECT: &str = "SELECT c.id,c.branch,c.receipt,c.integration,c.reason,c.candidate_revision,c.sequence,(EXISTS(SELECT 1 FROM conflict_resolutions x WHERE x.conflict=c.id)) FROM conflicts c";
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
/// The caller's own conflicts on a branch its current grant names.
async fn load(state: &ServiceState, c: &AuthContext, id: &str) -> Result<Row> {
    let id = ConflictId::parse(id).map_err(|_| Error::not_found())?;
    let row = state.db.acquire().await?.run(|db| Box::pin(async move {
        Ok(db.query_opt(&format!("{SELECT} WHERE c.namespace=$1 AND c.id=$2 AND c.principal=$3 AND c.branch=ANY($4)"),&[&c.namespace,&id.as_str(),&c.principal,&c.branches]).await?.map(|r| row(&r)))
    })).await?;
    row.ok_or(Error::not_found())
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
async fn alternatives(
    state: &ServiceState,
    c: &AuthContext,
    conflict: &str,
) -> Result<Vec<Alternative>> {
    let rows = state.db.acquire().await?.run(|db| Box::pin(async move {
        Ok(db.query("SELECT id,side,revision,entry FROM conflict_alternatives WHERE conflict=$1 ORDER BY side",&[&conflict]).await?.iter().map(|r| (r.get::<_, String>(0),r.get::<_, String>(1),r.get::<_, String>(2),r.get::<_, Option<String>>(3))).collect::<Vec<_>>())
    })).await?;
    let _ = c;
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
        Ok(db.query(&format!("{SELECT} WHERE c.namespace=$1 AND c.principal=$2 AND c.branch=ANY($3) AND c.sequence>$4 ORDER BY c.sequence LIMIT $5"),&[&c.namespace,&c.principal,&c.branches,&after,&limit]).await?.iter().map(row).collect::<Vec<_>>())
    })}).await?;
    let more = rows.len() > MAX_PAGE_ITEMS;
    let rows = &rows[..rows.len().min(MAX_PAGE_ITEMS)];
    Ok(Json(ConflictPage {
        items: rows.iter().map(summary).collect::<Result<_>>()?,
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
    let s = r::snapshot(&state.db, &c, &row.branch, None).await?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let mut refs = vec![];
    let mut cache: BTreeMap<String, Revision> = BTreeMap::new();
    for alt in alternatives(&state, &c, &row.id).await? {
        if !cache.contains_key(&alt.revision) {
            let revision = descriptor(&state, &c, &alt.revision).await?;
            cache.insert(alt.revision.clone(), revision);
        }
        refs.push(AlternativeRef {
            id: AlternativeId::parse(alt.id).map_err(|_| Error::backend())?,
            side: alt.side,
            path: disclosed(&s, &cache[&alt.revision], current, alt.entry.as_ref()),
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
    let alt = alternatives(&state, &c, &row.id)
        .await?
        .into_iter()
        .find(|a| a.id == alternative.as_str())
        .ok_or(Error::not_found())?;
    let s = r::snapshot(&state.db, &c, &row.branch, None).await?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let side = descriptor(&state, &c, &alt.revision).await?;
    if let Some(entry) = &alt.entry {
        if !side.tree.entries.iter().any(|e| &e.id == entry) {
            return Err(Error {
                status: StatusCode::NOT_FOUND,
                code: "absent_alternative",
            });
        }
    }
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
        if targets.len() != req.conflicts.len()
            || targets.iter().any(|t| t.branch != candidate.branch)
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
                            "SELECT id FROM conflicts WHERE namespace=$1 AND integration=ANY($2)",
                            &[&c.namespace, integrations],
                        )
                        .await?
                        .iter()
                        .map(|r| r.get::<_, String>(0))
                        .collect::<BTreeSet<_>>())
                })
            })
            .await?;
        if !siblings.is_subset(&ids.iter().cloned().collect()) {
            return Err(Error::invalid("incomplete_resolution"));
        }
        let s = r::snapshot(&state.db, &c, &candidate.branch, candidate.view.as_deref()).await?;
        s.context.action("integrate")?;
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
            // Current rights and scope over the complete replacement; never broadens access.
            submission::authorize_candidate(&s, derived)?;
            for t in &targets {
                let id = RevisionId::parse(t.candidate.clone()).map_err(|_| Error::backend())?;
                if !resolved.parents.contains(&id) {
                    resolved.parents.push(id);
                }
            }
        }
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
            "replacement":req.replacement,"submitted":original.revision,
            "current":r::rid(current)?,"candidates":resolved.parents,
        }))?;
        let bytes = r::encode(&resolved)?;
        barrier("resolution").await;
        let commit = state.db.acquire().await?.run(|db| { let req=&req; let serialized=&serialized; let ids=&ids; let candidate=&candidate; let original=&original; let receipt=&receipt; let result=&result; let paths=&paths; let required=&required; let bytes=&bytes; let resolved_id=&resolved_id; let derived_id=&derived_id; let provenance=&provenance; let s=&s; Box::pin(async move {
            let tx = db.transaction().await?;
            let current = r::recheck(&tx, s, "integrate").await?;
            if tx.query_opt("SELECT operation FROM operations WHERE namespace=$1 AND replica=$2 AND operation=$3",&[&current.namespace,&current.replica,&req.operation.as_str()]).await?.is_some() {
                return Err(Error::conflict());
            }
            if !stale {
                let open: i64 = tx.query_one("SELECT count(*) FROM conflicts c WHERE c.namespace=$1 AND c.id=ANY($2) AND NOT EXISTS(SELECT 1 FROM conflict_resolutions x WHERE x.conflict=c.id)",&[&current.namespace,ids]).await?.get(0);
                if open != ids.len() as i64 {
                    return Err(Error { status: StatusCode::CONFLICT, code: "already_resolved" });
                }
                let generations = r::ready(&tx, &current, required, None, required).await?;
                r::save_revision(&tx, &current.namespace, resolved_id, bytes, &generations).await?;
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
                for id in ids {
                    tx.execute("INSERT INTO conflict_resolutions(conflict,namespace,replica,operation,revision) VALUES($1,$2,$3,$4,$5)",&[id,&current.namespace,&current.replica,&req.operation.as_str(),&resolved_id.as_str()]).await?;
                }
                tx.execute("INSERT INTO revision_provenance(namespace,revision,kind,operation,payload,digest) VALUES($1,$2,'resolution',$3,$4,$5)",&[&current.namespace,&resolved_id.as_str(),&req.operation.as_str(),provenance,&digest(provenance.as_bytes())]).await?;
            }
            tx.commit().await?;
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
