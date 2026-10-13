//! Explicit authorized published history. Private DAG ancestry is not a history grant.
use crate::{
    auth, revisions as r,
    submission::{self, NewOperation},
    views::core_error,
    Error, Result, ServiceState,
};
use axum::{
    body::Body,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use magus_fs_core::{protocol::*, *};
use std::collections::{BTreeMap, BTreeSet};

fn readable_scaffold(s: &r::Snapshot, e: &Entry) -> bool {
    s.context.permits("read", &s.branch, &e.path)
        || (e.content == EntryContent::Directory
            && s.context.prefixes.iter().any(|p| auth::within(p, &e.path)))
}

fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Retained access follows the historical scoped path, not a relocated ancestor ID.
/// Missing directory prefixes use the nearest existing enclosing directory. A present
/// denied/non-directory component is authoritative and may never be skipped.
fn historical_directory(s: &r::Snapshot, path: &str) -> Result<Entry> {
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let mut enclosing = path;
    loop {
        if enclosing.is_empty() {
            return authorize_tree_read(&current.tree, &current.tree.root.id, s.authority()?)
                .map_err(core_error);
        }
        if let Some(e) = current.tree.entries.iter().find(|e| e.path == enclosing) {
            if e.content != EntryContent::Directory || !readable_scaffold(s, e) {
                return Err(Error::not_found());
            }
            return authorize_tree_read(&current.tree, &e.id, s.authority()?).map_err(core_error);
        }
        enclosing = parent_path(enclosing);
    }
}

fn historical_parent_write(s: &r::Snapshot, path: &str) -> Result<()> {
    if !s.context.permits("write", &s.branch, path) {
        return Err(Error::not_found());
    }
    let enclosing = historical_directory(s, parent_path(path))?;
    // Original scope was checked above. This pure permission probe uses the current
    // enclosing directory without admitting a name or inventing missing directories.
    let leaf = path.rsplit('/').next().ok_or(Error::not_found())?;
    let policy_path = if enclosing.path.is_empty() {
        leaf.to_owned()
    } else {
        format!("{}/{}", enclosing.path, leaf)
    };
    let mut scope = s.scope();
    scope.write_prefixes = vec!["".into()];
    authorize_tree_parent_write(
        &s.current.as_ref().ok_or(Error::not_found())?.tree,
        &policy_path,
        s.authority()?,
        &scope,
    )
    .map_err(core_error)
}

fn restore_parent(s: &r::Snapshot, path: &str) -> Result<EntryId> {
    let parent = parent_path(path);
    let current = historical_directory(s, parent)?;
    if current.path != parent {
        return Err(Error::not_found());
    }
    Ok(current.id)
}

/// Current metadata and complete current ancestor permissions govern extant identities.
/// Deleted/moved-out identities require explicit retained-history administration and a
/// presently readable destination parent. A selected view exposes only its ancestor chain.
pub(crate) fn projection(s: &r::Snapshot, source: &Revision, entry: &EntryId) -> Result<Revision> {
    s.context.action("read")?;
    s.context.action("history")?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let a = s.authority()?;
    let old = source
        .tree
        .entries
        .iter()
        .find(|e| &e.id == entry)
        .ok_or(Error::not_found())?;
    if source.tree.root.id != current.tree.root.id
        || !s.context.permits("history", &s.branch, &old.path)
    {
        return Err(Error::not_found());
    }
    let now = current
        .tree
        .entries
        .iter()
        .find(|e| &e.id == entry && s.context.permits("read", &s.branch, &e.path));
    if let Some(now) = now {
        authorize_tree_read(&current.tree, &now.id, a).map_err(core_error)?;
    } else {
        s.context.action("admin")?;
        s.context.action("retained_history")?;
    }
    historical_directory(s, parent_path(&old.path))?;
    let by_id = source
        .tree
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<BTreeMap<_, _>>();
    let mut chain = vec![old.clone()];
    let mut parent = &old.parent;
    let mut seen = BTreeSet::new();
    while parent != &source.tree.root.id {
        if !seen.insert(parent) {
            return Err(Error::backend());
        }
        let e = by_id.get(parent).ok_or(Error::not_found())?;
        historical_directory(s, &e.path)?;
        chain.push((*e).clone());
        parent = &e.parent;
    }
    authorize_tree_read(&current.tree, &current.tree.root.id, a).map_err(core_error)?;
    let mut result = source.clone();
    result.format = FORMAT.into();
    result.parents.clear();
    result.restoration = None;
    result.coverage = vec!["".into()];
    result.tree.root = current.tree.root.clone();
    for e in &mut chain {
        let now = current.tree.entries.iter().find(|n| {
            if e.content == EntryContent::Directory {
                n.path == e.path && n.content == EntryContent::Directory && readable_scaffold(s, n)
            } else {
                n.id == e.id && s.context.permits("read", &s.branch, &n.path)
            }
        });
        if let Some(n) = now {
            e.owner = n.owner.clone();
            e.group = n.group.clone();
            e.mode = n.mode;
        } else {
            e.owner = a.principal.clone();
            e.group = a.primary_group.clone();
            e.mode = if e.content == EntryContent::Directory {
                0o755
            } else {
                0o644
            };
        }
    }
    chain.sort_by(|a, b| a.path.cmp(&b.path));
    result.tree.entries = chain;
    validate_tree(&result.tree).map_err(core_error)?;
    Ok(result)
}
struct Record {
    branch: String,
    revision: Revision,
    entry: EntryId,
}
async fn record(state: &ServiceState, c: &auth::AuthContext, id: &str) -> Result<Record> {
    let row=state.db.acquire().await?.run(|db|Box::pin(async move {
        db.query_opt("SELECT h.branch,r.descriptor,h.entry FROM history_bindings h JOIN revisions r ON r.namespace=h.namespace AND r.revision=h.revision WHERE h.id=$1 AND h.namespace=$2 AND h.credential=$3 AND h.principal=$4 AND h.replica=$5",&[&id,&c.namespace,&c.credential,&c.principal,&c.replica]).await?.ok_or(Error::not_found())
    })).await?;
    Ok(Record {
        branch: row.get(0),
        revision: r::decode(&row.get::<_, Vec<u8>>(1))?,
        entry: EntryId::parse(row.get::<_, String>(2)).map_err(core_error)?,
    })
}
fn query(raw: Option<String>) -> Result<(ViewId, Option<String>)> {
    let mut q = BTreeMap::new();
    for pair in raw.unwrap_or_default().split('&') {
        let (k, v) = pair
            .split_once('=')
            .ok_or(Error::invalid("invalid_request"))?;
        if !["view", "cursor"].contains(&k) || q.insert(k.to_owned(), v.to_owned()).is_some() {
            return Err(Error::invalid("invalid_request"));
        }
    }
    let view = ViewId::parse(q.remove("view").ok_or(Error::invalid("invalid_request"))?)
        .map_err(core_error)?;
    let cursor = q.remove("cursor");
    if cursor
        .as_ref()
        .is_some_and(|s| HistoryId::parse(s).is_err())
    {
        return Err(Error::invalid("invalid_cursor"));
    }
    Ok((view, cursor))
}
pub(crate) async fn list(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Result<Json<HistoryPage>> {
    let c = state.auth(&headers, &ns, "history").await?;
    let (view, cursor) = query(raw)?;
    let branch = r::branch_for_view(&state.db, &c, view.as_str()).await?;
    let s = r::snapshot(&state.db, &c, &branch, Some(view.as_str())).await?;
    s.validate_view()?;
    let offset = if let Some(cursor) = cursor {
        let view = &view;
        let c = &c;
        let ns = &ns;
        state.db.acquire().await?.run(|db|Box::pin(async move {
        db.query_opt("SELECT offset_value FROM history_cursors WHERE id=$1 AND namespace=$2 AND credential=$3 AND principal=$4 AND replica=$5 AND view_id=$6",&[&cursor,&ns,&c.credential,&c.principal,&c.replica,&view.as_str()]).await?.map(|r|r.get::<_,i64>(0)).ok_or(Error::invalid("invalid_cursor"))
    })).await?
    } else {
        0
    };
    // Bound the database page before descriptor decoding; continue through denied rows
    // without exposing them. Sequence is immutable, so new publications do not shift pages.
    let rows=state.db.acquire().await?.run(|db| { let s=&s; let branch=&branch; Box::pin(async move {
        db.query("SELECT p.sequence,p.revision,p.entry,r.descriptor FROM published_entries p JOIN revisions r ON r.namespace=p.namespace AND r.revision=p.revision WHERE p.namespace=$1 AND p.branch=$2 AND p.sequence>$3 ORDER BY p.sequence LIMIT 33",&[&s.context.namespace,&branch,&offset]).await.map_err(Error::from)
    })}).await?;
    let more = rows.len() > MAX_PAGE_ITEMS;
    let rows = rows.into_iter().take(MAX_PAGE_ITEMS).collect::<Vec<_>>();
    let end = rows.last().map(|r| r.get::<_, i64>(0)).unwrap_or(offset);
    let mut authorized = vec![];
    for row in rows {
        let revision = r::decode(&row.get::<_, Vec<u8>>(3))?;
        let entry = EntryId::parse(row.get::<_, String>(2)).map_err(core_error)?;
        if projection(&s, &revision, &entry).is_ok() {
            authorized.push((row.get::<_, String>(1), entry));
        }
    }
    let selected = &authorized;
    let result=state.db.acquire().await?.run(|db|Box::pin(async move {
        let tx=db.transaction().await?;let c=r::recheck(&tx,&s,"history").await?;let mut items=vec![];
        for (revision,entry) in selected {let fresh=HistoryId::random().map_err(core_error)?;
            tx.execute("INSERT INTO history_bindings(id,namespace,branch,credential,principal,replica,revision,entry,change) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'version') ON CONFLICT(namespace,branch,credential,revision,entry) DO NOTHING",&[&fresh.as_str(),&c.namespace,&s.branch,&c.credential,&c.principal,&c.replica,revision,&entry.as_str()]).await?;
            let id=tx.query_one("SELECT id FROM history_bindings WHERE namespace=$1 AND branch=$2 AND credential=$3 AND revision=$4 AND entry=$5",&[&c.namespace,&s.branch,&c.credential,revision,&entry.as_str()]).await?.get::<_,String>(0);
            items.push(HistorySummary{id:HistoryId::parse(id).map_err(core_error)?,entry:entry.clone(),change:"version".into()});
        }
        let next=if more {let id=HistoryId::random().map_err(core_error)?;tx.execute("INSERT INTO history_cursors(id,namespace,credential,principal,replica,view_id,offset_value) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&id.as_str(),&c.namespace,&c.credential,&c.principal,&c.replica,&view.as_str(),&end]).await?;Some(id.as_str().to_owned())}else{None};
        let page=HistoryPage{items,next};if r::json(&page)?.len()>MAX_CONTROL{return Err(Error::limit());}tx.commit().await?;Ok(page)
    })).await?;
    Ok(Json(result))
}
pub(crate) async fn view(
    State(state): State<ServiceState>,
    Path((ns, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<ViewBinding>> {
    let c = state.auth(&headers, &ns, "history").await?;
    let _: crate::Empty = crate::json_body(body, &headers).await?;
    let source = record(&state, &c, &id).await?;
    let s = r::snapshot(&state.db, &c, &source.branch, None).await?;
    let projected = projection(&s, &source.revision, &source.entry)?;
    let bytes = r::encode(&projected)?;
    let revision = r::rid(&projected)?;
    let full = r::rid(&source.revision)?;
    let head = HeadToken::parse(s.head.clone().ok_or(Error::not_found())?).map_err(core_error)?;
    state.db.acquire().await?.run(|db|Box::pin(async move {
        let tx=db.transaction().await?;let c=r::recheck(&tx,&s,"history").await?;let view=ViewId::random().map_err(core_error)?;
        tx.execute("INSERT INTO views(id,namespace,branch,credential,principal,replica,full_revision,head,projected_revision,descriptor,history,history_entry) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",&[&view.as_str(),&c.namespace,&s.branch,&c.credential,&c.principal,&c.replica,&full.as_str(),&head.as_str(),&revision.as_str(),&bytes,&id,&source.entry.as_str()]).await?;
        tx.commit().await?;Ok(Json(ViewBinding{view,head,revision}))
    })).await
}
pub(crate) async fn replay(
    state: &ServiceState,
    c: &auth::AuthContext,
    op: &submission::Operation,
) -> Result<()> {
    let req: RestoreRequest = r::parse(&op.request)?;
    let source = record(state, c, req.history.as_str()).await?;
    let s = r::snapshot(&state.db, c, &source.branch, None).await?;
    s.context.action("write")?;
    projection(&s, &source.revision, &source.entry)?;
    if req.restore_metadata {
        s.context.action("admin")?;
    }
    let result = op.derived.as_ref().ok_or(Error::not_found())?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let payload = state
        .db
        .acquire()
        .await?
        .run(|db| {
            Box::pin(async move {
                db.query_opt(
                    "SELECT payload FROM restoration_provenance WHERE namespace=$1 AND revision=$2",
                    &[&c.namespace, &r::rid(result)?.as_str()],
                )
                .await?
                .map(|r| r.get::<_, String>(0))
                .ok_or(Error::not_found())
            })
        })
        .await?;
    let payload: serde_json::Value = r::parse(&payload)?;
    let destination = EntryId::parse(payload["destination"].as_str().ok_or(Error::backend())?)
        .map_err(core_error)?;
    let restored = result
        .tree
        .entries
        .iter()
        .find(|e| e.id == destination)
        .ok_or(Error::backend())?;
    if let Some(now) = current.tree.entries.iter().find(|e| e.id == destination) {
        if !s.context.permits("write", &s.branch, &now.path) {
            return Err(Error::not_found());
        }
        let mut check = current.tree.clone();
        check
            .entries
            .iter_mut()
            .find(|e| e.id == destination)
            .ok_or(Error::backend())?
            .content = restored.content.clone();
        authorize_tree_transition(
            &current.tree,
            &check,
            s.authority()?,
            &s.authorities,
            &s.scope(),
        )
        .map_err(core_error)?;
    } else {
        // Recover the immutable result after current policy checks. A fresh occupant
        // at the old name cannot turn lookup/replay into another create admission.
        historical_parent_write(&s, &restored.path)?;
    }
    r::final_read(&state.db, &s).await
}
pub(crate) async fn restore(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let c = state.auth(&headers, &ns, "write").await?;
    let req: RestoreRequest = crate::json_body(body, &headers).await?;
    if req.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    let serialized = r::json(&req)?;
    if let Some(op) =
        submission::operation(&state, &c, req.replica.as_str(), req.operation.as_str()).await?
    {
        if op.kind != "restore" || op.digest != auth::digest(serialized.as_bytes()) {
            return Err(Error::conflict());
        }
        replay(&state, &c, &op).await?;
        return op.response();
    }
    let source = record(&state, &c, req.history.as_str()).await?;
    let s = r::snapshot(&state.db, &c, &source.branch, None).await?;
    projection(&s, &source.revision, &source.entry)?;
    if s.head.as_deref() != Some(req.expected_head.as_str()) {
        return Err(Error {
            status: axum::http::StatusCode::CONFLICT,
            code: "stale_head",
        });
    }
    if req.restore_metadata {
        s.context.action("admin")?;
    }
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let original = source
        .revision
        .tree
        .entries
        .iter()
        .find(|e| e.id == source.entry)
        .ok_or(Error::not_found())?;
    if matches!(original.content, EntryContent::Directory) {
        return Err(Error::invalid("unsupported_operation"));
    }
    let mut derived = current.clone();
    derived.operation = req.operation.clone();
    derived.replica = req.replica.clone();
    derived.principal = s.authority()?.principal.clone();
    derived.parents = vec![r::rid(current)?];
    derived.restoration = None;
    derived.captured_at_ns = crate::publication::now_ns();
    derived.provenance = "explicit".into();
    let destination = if let Some(e) = derived
        .tree
        .entries
        .iter_mut()
        .find(|e| e.id == original.id && s.context.permits("write", &s.branch, &e.path))
    {
        e.content = original.content.clone();
        if req.restore_metadata {
            e.owner = original.owner.clone();
            e.group = original.group.clone();
            e.mode = original.mode;
        }
        e.id.clone()
    } else {
        if derived
            .tree
            .entries
            .iter()
            .any(|e| e.id == original.id || e.path == original.path)
        {
            return Err(Error::not_found());
        }
        let mut entry = original.clone();
        entry.id = EntryId::random().map_err(core_error)?;
        entry.parent = restore_parent(&s, &entry.path)?;
        entry.owner = s.authority()?.principal.clone();
        entry.group = s.authority()?.primary_group.clone();
        entry.mode = 0o644;
        let destination = entry.id.clone();
        derived.tree.entries.push(entry);
        destination
    };
    derived.tree.entries.sort_by(|a, b| a.path.cmp(&b.path));
    authorize_tree_transition(
        &current.tree,
        &derived.tree,
        s.authority()?,
        &s.authorities,
        &s.scope(),
    )
    .map_err(core_error)?;
    let required = r::objects(&derived)?;
    for (id, size) in &required {
        state
            .objects
            .read_ready(&ns, &ObjectId::parse(id).map_err(core_error)?, *size as u64)
            .await?;
    }
    let id = r::rid(&derived)?;
    let bytes = r::encode(&derived)?;
    let receipt = SharedReceipt {
        receipt: ReceiptId::random().map_err(core_error)?,
        operation: req.operation.clone(),
        submitted_revision: r::rid(&projection(&s, &source.revision, &source.entry)?)?,
        replica: req.replica.clone(),
        branch: BranchName::parse(s.branch.clone()).map_err(core_error)?,
        head: HeadToken::random().map_err(core_error)?,
    };
    let payload = r::json(
        &serde_json::json!({"source_revision":r::rid(&source.revision)?,"history":req.history,"source_entry":source.entry,"destination":destination,"restore_metadata":req.restore_metadata,"operation":req.operation}),
    )?;
    let result = r::json(&receipt)?;
    let paths = crate::reconciliation::changed_paths(&current.tree, &derived.tree);
    crate::publication::barrier("restore").await;
    state.db.acquire().await?.run(|db|{let state=&state;Box::pin(async move {
        let tx=db.transaction().await?;let c=r::recheck(&tx,&s,"write").await?;crate::dependencies::check_publication(&tx,&s,None,&derived.tree,None).await?;let generations=r::ready(&tx,&c,&required,None,&required).await?;r::save_revision(&tx,&ns,&id,&bytes,&generations).await?;r::register_entries(&tx,&ns,s.current.as_ref().map(|r|&r.tree),&derived.tree).await?;r::publish_history(&tx,&ns,&s.branch,&derived).await?;
        tx.execute("INSERT INTO restoration_provenance(namespace,revision,history,operation,payload,digest) VALUES($1,$2,$3,$4,$5,$6)",&[&ns,&id.as_str(),&req.history.as_str(),&req.operation.as_str(),&payload,&auth::digest(payload.as_bytes())]).await?;
        tx.execute("UPDATE branches SET revision=$3,head=$4 WHERE namespace=$1 AND name=$2",&[&ns,&s.branch,&id.as_str(),&receipt.head.as_str()]).await?;tx.execute("INSERT INTO changes(namespace,branch,head,paths) VALUES($1,$2,$3,$4)",&[&ns,&s.branch,&receipt.head.as_str(),&paths]).await?;
        submission::save_operation(&tx,&c,NewOperation{operation:&req.operation,kind:"restore",request:&serialized,result:&result,status:200,branch:&s.branch,view:None,receipt:&receipt.receipt,submitted:&receipt.submitted_revision,derived:&id}).await?;tx.commit().await?;state.shared_committed(&receipt,&id);Ok(Json(receipt).into_response())
    })}).await
}
use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (r::Snapshot, Revision, EntryId) {
        let p = PrincipalId::random().unwrap();
        let g = GroupId::random().unwrap();
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: p.clone(),
            group: g.clone(),
            mode: 0o700,
        };
        let directory = Entry {
            id: EntryId::random().unwrap(),
            path: "reports".into(),
            parent: root.id.clone(),
            owner: p.clone(),
            group: g.clone(),
            mode: 0o700,
            content: EntryContent::Directory,
        };
        let file = Entry {
            id: EntryId::random().unwrap(),
            path: "reports/live".into(),
            parent: directory.id.clone(),
            owner: p.clone(),
            group: g.clone(),
            mode: 0o600,
            content: EntryContent::File {
                version: FileVersion {
                    size: 0,
                    extents: vec![],
                },
            },
        };
        let revision = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            operation: OperationId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            principal: p.clone(),
            captured_at_ns: 0,
            coverage: vec!["".into()],
            provenance: "explicit".into(),
            restoration: None,
            parents: vec![],
            tree: Tree {
                root: root.clone(),
                entries: vec![directory, file.clone()],
            },
        };
        let s = r::Snapshot {
            context: auth::AuthContext {
                credential: "fixture".into(),
                namespace: "1".repeat(32),
                principal: p.as_str().into(),
                replica: revision.replica.as_str().into(),
                generation: 1,
                token_hash: "fixture".into(),
                actions: vec!["read".into(), "history".into()],
                branches: vec!["main".into()],
                prefixes: vec!["reports/live".into()],
                depth: 0,
            },
            branch: "main".into(),
            authorities: vec![Authority {
                principal: p,
                uid: 1001,
                primary_group: g.clone(),
                gid: 1001,
                groups: vec![g],
                dac_override: false,
                ownership_transfer: false,
            }],
            root,
            current: Some(revision.clone()),
            head: Some("1".repeat(32)),
            view: None,
        };
        (s, revision, file.id)
    }
    #[test]
    fn file_scope_history_keeps_authorized_ancestor_scaffolding() {
        let (s, revision, file) = fixture();
        let projected = projection(&s, &revision, &file).unwrap();
        assert_eq!(
            projected
                .tree
                .entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["reports", "reports/live"]
        );
    }
    #[test]
    fn retained_history_uses_current_historical_path_and_enclosing_policy() {
        let (mut s, source, file) = fixture();
        s.context
            .actions
            .extend(["admin".into(), "retained_history".into()]);
        s.context.prefixes = vec!["".into()];
        let mut relocated = source.tree.entries[0].clone();
        relocated.path = "archive".into();
        relocated.mode = 0o777;
        let mut replacement = source.tree.entries[0].clone();
        replacement.id = EntryId::random().unwrap();
        replacement.mode = 0;
        s.current.as_mut().unwrap().tree.entries = vec![relocated, replacement.clone()];
        assert_eq!(
            projection(&s, &source, &file).unwrap_err().code,
            "not_found"
        );
        s.current.as_mut().unwrap().tree.entries[1].mode = 0o700;
        let permitted = projection(&s, &source, &file).unwrap();
        assert_eq!(permitted.tree.entries[0].mode, 0o700);
        assert_eq!(restore_parent(&s, "reports/live").unwrap(), replacement.id);
        s.current.as_mut().unwrap().tree.entries.pop();
        assert!(projection(&s, &source, &file).is_ok());
        s.context.actions.push("write".into());
        s.context.prefixes = vec!["reports/live".into()];
        historical_parent_write(&s, "reports/live").unwrap();
        s.current.as_mut().unwrap().tree.root.mode = 0o555;
        assert_eq!(
            historical_parent_write(&s, "reports/live")
                .unwrap_err()
                .code,
            "not_found"
        );
        s.current.as_mut().unwrap().tree.root.mode = 0o700;
        s.context.actions.retain(|action| action != "write");
        assert_eq!(
            historical_parent_write(&s, "reports/live")
                .unwrap_err()
                .code,
            "not_found"
        );
        assert_eq!(
            restore_parent(&s, "reports/live").unwrap_err().code,
            "not_found"
        );
        s.current.as_mut().unwrap().tree.root.mode = 0;
        assert_eq!(
            projection(&s, &source, &file).unwrap_err().code,
            "not_found"
        );
        s.current.as_mut().unwrap().tree.root.mode = 0o700;
        replacement.content = source.tree.entries[1].content.clone();
        s.current.as_mut().unwrap().tree.entries.push(replacement);
        assert_eq!(
            projection(&s, &source, &file).unwrap_err().code,
            "not_found"
        );
    }
}
