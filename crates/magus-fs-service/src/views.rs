use crate::{Error, Result};
use magus_fs_core::*;
use std::collections::{BTreeMap, BTreeSet};
pub(crate) fn core_error(e: FsError) -> Error {
    match e {
        FsError::LimitExceeded => Error::limit(),
        FsError::PermissionDenied | FsError::ReadOnly | FsError::UnknownPrincipal => {
            Error::not_found()
        }
        _ => Error::invalid(e.code()),
    }
}
/// Standalone canonical projected snapshot. No server ancestry or hidden refs.
pub fn project(
    full: &Revision,
    current: &Tree,
    a: &Authority,
    prefixes: &[String],
) -> Result<Revision> {
    if full.format != FORMAT {
        return Err(Error::invalid("unsupported_operation"));
    }
    authorize_tree_read(current, &full.tree.root.id, a).map_err(core_error)?;
    let mut result = full.clone();
    result.parents.clear();
    result.coverage = vec!["".into()];
    result.tree.entries.retain(|e| {
        let Ok(now) = authorize_tree_read(current, &e.id, a) else {
            return false;
        };
        // Ancestor directories are necessary structural scaffolding, never file refs.
        let allowed = |path: &str| {
            prefixes.iter().any(|p| {
                crate::auth::within(path, p)
                    || (e.content == EntryContent::Directory && crate::auth::within(p, path))
            })
        };
        allowed(&e.path) && allowed(&now.path)
    });
    // Parents sort before descendants in canonical path order. Add an identity
    // only after its complete structural chain survived authorization; a denied
    // ancestor must not leave an orphan or be disclosed as scaffolding.
    result.tree.entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut visible = BTreeSet::from([result.tree.root.id.clone()]);
    result.tree.entries.retain(|e| {
        if !visible.contains(&e.parent) {
            return false;
        }
        visible.insert(e.id.clone());
        true
    });
    validate_tree(&result.tree).map_err(core_error)?;
    Ok(result)
}
/// Authorized projection of an immutable conflict alternative. Current metadata governs
/// identities that still exist (a historic owner/mode never reopens access); identities
/// absent from the current head need the explicit `history` action. `entry` narrows the
/// projection to that identity and its structural ancestors.
pub fn alternative(
    side: &Revision,
    current: &Tree,
    a: &Authority,
    prefixes: &[String],
    history: bool,
    entry: Option<&EntryId>,
) -> Result<Revision> {
    let now = current
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<BTreeMap<_, _>>();
    let mut authority = side.tree.clone();
    authority.root = current.root.clone();
    authority.root.id = side.tree.root.id.clone();
    if side.tree.root.id != current.root.id {
        return Err(Error::not_found());
    }
    // An identity counts as currently present only at a current location inside the
    // caller's scope. One moved out of scope after the alternative was recorded is treated
    // exactly like a deleted one (retained history only): stable identity is never a scope
    // escape, and the caller cannot tell "moved out of scope" from "deleted".
    let in_scope = |e: &Entry| {
        prefixes.iter().any(|p| {
            crate::auth::within(&e.path, p)
                || (e.content == EntryContent::Directory && crate::auth::within(p, &e.path))
        })
    };
    authority
        .entries
        .retain(|e| history || now.get(&e.id).is_some_and(|p| in_scope(p)));
    for e in &mut authority.entries {
        // Current permissions apply only where the identity currently lies in scope; one
        // moved out of scope keeps its historic metadata exactly like a deleted one (R19-C).
        if let Some(present) = now.get(&e.id).filter(|p| in_scope(p)) {
            e.owner = present.owner.clone();
            e.group = present.group.clone();
            e.mode = present.mode;
        }
    }
    let mut result = project(side, &authority, a, prefixes)?;
    if let Some(id) = entry {
        let ids = result
            .tree
            .entries
            .iter()
            .map(|e| (e.id.clone(), e.parent.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut keep = BTreeSet::new();
        let mut cursor = ids.get(id).map(|_| id.clone()).ok_or(Error::not_found())?;
        while let Some(parent) = ids.get(&cursor) {
            keep.insert(cursor.clone());
            cursor = parent.clone();
        }
        result.tree.entries.retain(|e| keep.contains(&e.id));
    }
    Ok(result)
}
/// Only visible identities are replaced; omission never deletes unseen entries.
pub fn lift(full: &Revision, visible: &Revision, submitted: &Revision) -> Result<Revision> {
    if submitted.format != FORMAT || visible.format != FORMAT {
        return Err(Error::invalid("unsupported_operation"));
    }
    if submitted.tree.root.id != visible.tree.root.id {
        return Err(Error::not_found());
    }
    let seen = visible
        .tree
        .entries
        .iter()
        .map(|e| &e.id)
        .collect::<BTreeSet<_>>();
    let new = submitted
        .tree
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<BTreeMap<_, _>>();
    for before in &visible.tree.entries {
        if before.content == EntryContent::Directory
            && new
                .get(&before.id)
                .is_none_or(|e| e.path != before.path || e.parent != before.parent)
            && full
                .tree
                .entries
                .iter()
                .any(|e| crate::auth::within(&e.path, &before.path) && !seen.contains(&e.id))
        {
            return Err(Error::not_found());
        }
    }
    let hidden = full
        .tree
        .entries
        .iter()
        .filter(|e| !seen.contains(&e.id))
        .collect::<Vec<_>>();
    if submitted
        .tree
        .entries
        .iter()
        .any(|e| hidden.iter().any(|h| h.id == e.id || h.path == e.path))
    {
        return Err(Error::not_found());
    }
    let mut derived = submitted.clone();
    derived.parents = vec![revision_id(full).map_err(core_error)?];
    derived.tree.entries.extend(hidden.into_iter().cloned());
    validate_tree(&derived.tree).map_err(core_error)?;
    Ok(derived)
}

use crate::{auth, db, revisions as r, ServiceState};
use axum::{
    body::Body,
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use magus_fs_core::protocol::*;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewRequest {
    pub branch: BranchName,
}
pub(crate) async fn create(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<ViewBinding>> {
    let c = state.auth(&headers, &ns, "read").await?;
    let req: ViewRequest = crate::json_body(body, &headers).await?;
    let s = r::snapshot(&state.db, &c, req.branch.as_str(), None).await?;
    let full = s.current.as_ref().ok_or(Error::not_found())?;
    let projected = project(full, &full.tree, s.authority()?, &s.context.prefixes)?;
    let bytes = r::encode(&projected)?;
    let id = r::rid(&projected)?;
    let full_id = r::rid(full)?;
    let head = HeadToken::parse(s.head.clone().ok_or(Error::not_found())?).map_err(core_error)?;
    state.db.acquire().await?.run(|db| Box::pin(async move {
        let tx = db.transaction().await?;
        // Current authority and projection must always be computed and rechecked.
        // This namespace lock serializes selection/insertion across service owners.
        let c = r::recheck(&tx, &s, "read").await?;
        let fields: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &ns, &req.branch.as_str(), &c.credential, &c.principal, &c.replica,
            &full_id.as_str(), &head.as_str(), &id.as_str(), &bytes,
            &c.generation, &c.actions, &c.branches, &c.prefixes,
        ];
        let existing = tx.query_opt(
            "SELECT id FROM views WHERE namespace=$1 AND branch=$2 AND credential=$3 AND principal=$4 AND replica=$5 AND full_revision=$6 AND head=$7 AND projected_revision=$8 AND descriptor=$9 AND credential_generation=$10 AND grant_actions=$11 AND grant_branches=$12 AND grant_prefixes=$13 AND alternative IS NULL ORDER BY id LIMIT 1",
            fields,
        ).await?;
        let view = if let Some(row) = existing {
            ViewId::parse(row.get::<_, String>(0)).map_err(core_error)?
        } else {
            let view = ViewId::random().map_err(core_error)?;
            let mut values = fields.to_vec();
            let view_id = view.as_str();
            values.push(&view_id);
            tx.execute(
                "INSERT INTO views(namespace,branch,credential,principal,replica,full_revision,head,projected_revision,descriptor,credential_generation,grant_actions,grant_branches,grant_prefixes,id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
                &values,
            ).await?;
            view
        };
        tx.commit().await?;
        Ok(Json(ViewBinding { view, head, revision: id }))
    })).await
}
pub(crate) async fn descriptor(
    State(state): State<ServiceState>,
    Path((ns, view)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;
    let c = state.auth(&headers, &ns, "read").await?;
    let branch = r::branch_for_view(&state.db, &c, &view).await?;
    let s = r::snapshot(&state.db, &c, &branch, Some(&view)).await?;
    let view = s.validate_view()?;
    let bytes = r::encode(&view.projected)?;
    r::final_read(&state.db, &s).await?;
    Ok(([("content-type", "application/json")], bytes).into_response())
}
pub(crate) async fn object(
    State(state): State<ServiceState>,
    Path((ns, view, object)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Vec<u8>> {
    let c = state.auth(&headers, &ns, "read").await?;
    let view = ViewId::parse(view).map_err(|_| Error::not_found())?;
    let id = ObjectId::parse(object).map_err(|_| Error::not_found())?;
    Ok(state
        .objects
        .read_authorized(&c, &view, &id)
        .await?
        .to_vec())
}
pub(crate) async fn object_record(
    database: &db::Database,
    c: &auth::AuthContext,
    view: &ViewId,
    id: &ObjectId,
) -> Result<(r::Snapshot, String, String, usize)> {
    let branch = r::branch_for_view(database, c, view.as_str()).await?;
    let s = r::snapshot(database, c, &branch, Some(view.as_str())).await?;
    let bound = s.validate_view()?;
    let objects = r::objects(&bound.projected)?;
    let size = *objects.get(id.as_str()).ok_or(Error::not_found())?;
    let (key,generation)=database.acquire().await?.run(|db|Box::pin(async move {
  let tx=db.transaction().await?;db::lock_namespace(&tx,&c.namespace).await?;let current=auth::authenticate(&tx,&c.token_hash,&c.namespace).await?;current.action("read")?;
  let row=tx.query_opt("SELECT storage_key,generation FROM objects WHERE namespace=$1 AND object_id=$2 AND size=$3 AND state='ready'",&[&c.namespace,&id.as_str(),&size]).await?.ok_or(Error::not_found())?;let out=(row.get(0),row.get(1));tx.commit().await?;Ok(out)
 })).await?;
    Ok((s, key, generation, size as usize))
}
