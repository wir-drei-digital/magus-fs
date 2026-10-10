use crate::{
    auth, db, revisions as r,
    views::{self, core_error},
    Error, Result, ServiceState,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use magus_fs_core::{protocol::*, *};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateRequest {
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub original_view: ViewId,
    pub original_head: HeadToken,
    pub revision: RevisionId,
    pub upload: UploadId,
}
pub(crate) async fn stage(
    State(state): State<ServiceState>,
    Path((ns, upload, revision)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<serde_json::Value>> {
    let c = state.auth(&headers, &ns, "write").await?;
    let upload = UploadId::parse(upload).map_err(|_| Error::not_found())?;
    let id = RevisionId::parse(revision).map_err(core_error)?;
    let bytes = crate::body_bytes(body, &headers, MAX_DESCRIPTOR).await?;
    let descriptor = r::decode(&bytes)?;
    if r::encode(&descriptor)?.as_slice() != bytes || r::rid(&descriptor)? != id {
        return Err(Error::invalid("hash_mismatch"));
    }
    if descriptor.principal.as_str() != c.principal || descriptor.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    state.db.acquire().await?.run(|db|Box::pin(async move {
  let tx=db.transaction().await?;db::lock_namespace(&tx,&ns).await?;let current=auth::authenticate(&tx,&c.token_hash,&ns).await?;current.action("write")?;crate::storage::check_session(&tx,&current,&upload).await?;
  let counts=tx.query_one("SELECT count(*),COALESCE(sum(octet_length(descriptor)),0)::bigint FROM staged_revisions WHERE upload=$1 AND revision<>$2",&[&upload.as_str(),&id.as_str()]).await?;
  if counts.get::<_,i64>(0)>=128 || counts.get::<_,i64>(1)+bytes.len() as i64>64*1024*1024{return Err(Error::limit())}
  tx.execute("INSERT INTO staged_revisions(upload,revision,descriptor) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",&[&upload.as_str(),&id.as_str(),&&bytes[..]]).await?;tx.commit().await?;Ok(Json(serde_json::json!({"revision":id,"staged":true})))
 })).await
}
pub(crate) async fn staged(
    state: &ServiceState,
    c: &auth::AuthContext,
    upload: &UploadId,
) -> Result<BTreeMap<RevisionId, Revision>> {
    let rows=state.db.acquire().await?.run(|db|Box::pin(async move {
  let tx=db.transaction().await?;db::lock_namespace(&tx,&c.namespace).await?;let current=auth::authenticate(&tx,&c.token_hash,&c.namespace).await?;current.action("write")?;crate::storage::check_session(&tx,&current,upload).await?;
  let rows=tx.query("SELECT revision,descriptor FROM staged_revisions WHERE upload=$1 ORDER BY revision",&[&upload.as_str()]).await?.into_iter().map(|r|(r.get::<_,String>(0),r.get::<_,Vec<u8>>(1))).collect::<Vec<_>>();tx.commit().await?;Ok(rows)
 })).await?;
    rows.into_iter()
        .map(|(id, b)| Ok((RevisionId::parse(id).map_err(core_error)?, r::decode(&b)?)))
        .collect()
}
pub(crate) struct Operation {
    pub kind: String,
    pub digest: String,
    pub result: String,
    pub status: i32,
    pub branch: String,
    pub view: Option<String>,
    pub derived: Option<Revision>,
    pub request: String,
}
impl Operation {
    pub fn response(&self) -> Result<Response> {
        Ok((
            StatusCode::from_u16(self.status as u16).map_err(|_| Error::backend())?,
            [("content-type", "application/json")],
            self.result.clone(),
        )
            .into_response())
    }
}
pub(crate) async fn operation(
    state: &ServiceState,
    c: &auth::AuthContext,
    replica: &str,
    operation: &str,
) -> Result<Option<Operation>> {
    if replica != c.replica {
        return Err(Error::not_found());
    }
    let row=state.db.acquire().await?.run(|db|Box::pin(async move {
  let row=db.query_opt("SELECT o.*,r.descriptor FROM operations o LEFT JOIN revisions r ON r.namespace=o.namespace AND r.revision=o.derived_revision WHERE o.namespace=$1 AND o.replica=$2 AND o.operation=$3",&[&c.namespace,&replica,&operation]).await?;
  if row.as_ref().is_some_and(|r|r.get::<_,String>("principal")!=c.principal || r.get::<_,String>("credential")!=c.credential){return Err(Error::not_found())}Ok(row)
 })).await?;
    row.map(|row| {
        Ok(Operation {
            kind: row.get("kind"),
            digest: row.get("digest"),
            result: row.get("result"),
            status: row.get("status"),
            branch: row.get("branch"),
            view: row.get("view_id"),
            derived: row
                .get::<_, Option<Vec<u8>>>("descriptor")
                .map(|v| r::decode(&v))
                .transpose()?,
            request: row.get("request"),
        })
    })
    .transpose()
}
pub(crate) fn authorize_candidate(s: &r::Snapshot, derived: &Revision) -> Result<()> {
    authorize(s, derived, true)
}
/// Ruling R12: before a stale or unknown-causality outcome is recorded, the candidate is
/// re-authorized under current rights (credential, grant, base read rights, current
/// metadata and scope of its delta) without requiring unrelated path stability, so a
/// later merge can still handle concurrent moves.
pub(crate) fn authorize_retained(s: &r::Snapshot, derived: &Revision) -> Result<()> {
    authorize(s, derived, false)
}
fn authorize(s: &r::Snapshot, derived: &Revision, stable_paths: bool) -> Result<()> {
    let view = if stable_paths {
        s.validate_base()?
    } else {
        // Retained outcomes: current credential/read action and an issued (non-alternative)
        // base; deletions elsewhere in the base projection do not deny the record.
        s.context.action("read")?;
        let view = s.view.as_ref().ok_or(Error::not_found())?;
        if view.alternative.is_some() {
            return Err(Error::not_found());
        }
        view
    };
    let a = s.authority()?;
    let delta = authorize_tree_transition(
        &view.full.tree,
        &derived.tree,
        a,
        &s.authorities,
        &s.scope(),
    )
    .map_err(core_error)?;
    // Only the authorized change and its structural ancestors require stable
    // current paths. Unchanged hidden siblings are not caller mutations.
    let mut required = std::collections::BTreeSet::from([view.full.tree.root.id.clone()]);
    for tree in [&view.full.tree, &derived.tree] {
        let entries = tree
            .entries
            .iter()
            .map(|e| (&e.id, e))
            .collect::<BTreeMap<_, _>>();
        for endpoint in delta
            .operations
            .iter()
            .flat_map(|op| op.old.iter().chain(op.new.iter()))
        {
            let mut id = endpoint;
            while let Some(entry) = entries.get(id) {
                required.insert(entry.id.clone());
                id = &entry.parent;
            }
        }
    }
    // Recheck current permissions without treating unrelated path changes as
    // edits or restoring their old metadata.
    let current = &s.current.as_ref().ok_or(Error::not_found())?.tree;
    let mut now = view.full.tree.clone();
    now.root = current.root.clone();
    for old in &mut now.entries {
        if let Some(present) = current.entries.iter().find(|e| e.id == old.id) {
            if stable_paths
                && required.contains(&old.id)
                && (present.path != old.path || present.parent != old.parent)
            {
                return Err(Error::not_found());
            }
            old.owner = present.owner.clone();
            old.group = present.group.clone();
            old.mode = present.mode;
        } else if stable_paths && required.contains(&old.id) {
            return Err(Error::not_found());
        }
    }
    let mut checked = derived.tree.clone();
    // Unchanged metadata is not a request to restore old permissions.
    if derived.tree.root == view.full.tree.root {
        checked.root = now.root.clone()
    }
    for e in &mut checked.entries {
        if let Some(old) = view.full.tree.entries.iter().find(|o| o.id == e.id) {
            if (e.owner.clone(), e.group.clone(), e.mode)
                == (old.owner.clone(), old.group.clone(), old.mode)
            {
                if let Some(p) = now.entries.iter().find(|p| p.id == e.id) {
                    e.owner = p.owner.clone();
                    e.group = p.group.clone();
                    e.mode = p.mode;
                }
            }
        }
    }
    authorize_tree_transition(&now, &checked, a, &s.authorities, &s.scope()).map_err(core_error)?;
    Ok(())
}
pub(crate) async fn replay(
    state: &ServiceState,
    c: &auth::AuthContext,
    op: &Operation,
) -> Result<()> {
    let s = r::snapshot(&state.db, c, &op.branch, op.view.as_deref()).await?;
    s.context.action(if op.kind == "candidate" {
        "write"
    } else {
        "integrate"
    })?;
    if let Some(derived) = &op.derived {
        if op.view.is_some() {
            authorize_candidate(&s, derived)?;
        }
    }
    if op.view.is_none() && !s.context.permits("admin", &op.branch, "") {
        return Err(Error::not_found());
    }
    r::final_read(&state.db, &s).await
}
pub(crate) async fn get_operation(
    State(state): State<ServiceState>,
    Path((ns, replica, id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response> {
    let c = state.auth(&headers, &ns, "read").await?;
    let op = operation(&state, &c, &replica, &id)
        .await?
        .ok_or(Error::not_found())?;
    replay(&state, &c, &op).await?;
    op.response()
}
pub(crate) struct NewOperation<'a> {
    pub operation: &'a OperationId,
    pub kind: &'a str,
    pub request: &'a str,
    pub result: &'a str,
    pub status: i32,
    pub branch: &'a str,
    pub view: Option<&'a str>,
    pub receipt: &'a ReceiptId,
    pub submitted: &'a RevisionId,
    pub derived: &'a RevisionId,
}
pub(crate) async fn save_operation(
    tx: &tokio_postgres::Transaction<'_>,
    c: &auth::AuthContext,
    record: NewOperation<'_>,
) -> Result<()> {
    let NewOperation {
        operation,
        kind,
        request,
        result,
        status,
        branch,
        view,
        receipt,
        submitted,
        derived,
    } = record;
    tx.execute("INSERT INTO operations(namespace,replica,operation,principal,credential,kind,digest,request,result,status,branch,view_id,receipt,submitted_revision,derived_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",&[&c.namespace,&c.replica,&operation.as_str(),&c.principal,&c.credential,&kind,&auth::digest(request.as_bytes()),&request,&result,&status,&branch,&view,&receipt.as_str(),&submitted.as_str(),&derived.as_str()]).await?;
    Ok(())
}
pub(crate) async fn candidate(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let c = state.auth(&headers, &ns, "write").await?;
    let request: CandidateRequest = crate::json_body(body, &headers).await?;
    let serialized = r::json(&request)?;
    if request.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    if let Some(op) = operation(
        &state,
        &c,
        request.replica.as_str(),
        request.operation.as_str(),
    )
    .await?
    {
        replay(&state, &c, &op).await?;
        if op.kind != "candidate" || op.digest != auth::digest(serialized.as_bytes()) {
            return Err(Error::conflict());
        }
        return op.response();
    }
    let branch = r::branch_for_view(&state.db, &c, request.original_view.as_str()).await?;
    let s = r::snapshot(&state.db, &c, &branch, Some(request.original_view.as_str())).await?;
    let view = s.validate_base()?;
    // An alternative export binding is read-only evidence, never a candidate base.
    if request.original_head.as_str() != view.head || view.alternative.is_some() {
        return Err(Error::not_found());
    }
    let descriptors = staged(&state, &c, &request.upload).await?;
    let submitted = descriptors
        .get(&request.revision)
        .ok_or(Error::not_found())?;
    if submitted.operation != request.operation
        || submitted.replica != request.replica
        || submitted.principal.as_str() != c.principal
    {
        return Err(Error::not_found());
    }
    let base = r::rid(&view.projected)?;
    let mut id = request.revision.clone();
    let mut chain = vec![];
    let mut total = 0;
    while id != base {
        if chain.len() >= 128 || chain.iter().any(|(seen, _)| seen == &id) {
            return Err(Error::limit());
        }
        let revision = descriptors.get(&id).ok_or(Error::not_found())?;
        if revision.format != FORMAT {
            return Err(Error::invalid("unsupported_operation"));
        }
        if revision.parents.len() != 1 {
            return Err(Error::invalid("invalid_ancestry"));
        }
        total += r::encode(revision)?.len();
        if total > 64 * 1024 * 1024 {
            return Err(Error::limit());
        }
        chain.push((id.clone(), revision));
        id = revision.parents[0].clone();
    }
    let mut required = BTreeMap::new();
    for (_, revision) in chain.iter().rev() {
        let derived = views::lift(&view.full, &view.projected, revision)?;
        authorize_candidate(&s, &derived)?;
        for (object, size) in r::objects(revision)? {
            if required
                .insert(object, size)
                .is_some_and(|previous| previous != size)
            {
                return Err(Error::invalid("invalid_descriptor"));
            }
        }
    }
    if required.values().sum::<i64>() > MAX_SESSION_BYTES {
        return Err(Error::limit());
    }
    // Rulings R1/R6/R10: unknown native causality anywhere in the unpublished chain is
    // recorded with the receipt so integration never merges or fast-forwards it.
    let unknown = chain
        .iter()
        .any(|(_, r)| r.provenance == UNKNOWN_CAUSALITY_PROVENANCE);
    let derived = views::lift(&view.full, &view.projected, submitted)?;
    let derived_id = r::rid(&derived)?;
    let derived_bytes = r::encode(&derived)?;
    let derived_objects = r::objects(&derived)?;
    let reusable = r::objects(&view.projected)?;
    let full_objects = r::objects(&view.full)?;
    let receipt = PrivateReceipt {
        receipt: ReceiptId::random().map_err(core_error)?,
        operation: request.operation.clone(),
        replica: request.replica.clone(),
        submitted_revision: request.revision.clone(),
        original_view: request.original_view.clone(),
        original_head: request.original_head.clone(),
    };
    let result = r::json(&receipt)?;
    crate::publication::barrier("candidate").await;
    state.db.acquire().await?.run(|db|Box::pin(async move {
  let tx=db.transaction().await?;let current=r::recheck(&tx,&s,"write").await?;
  if let Some(row)=tx.query_opt("SELECT digest,result,credential,kind FROM operations WHERE namespace=$1 AND replica=$2 AND operation=$3",&[&ns,&current.replica,&request.operation.as_str()]).await?{
   if row.get::<_,String>(2)!=current.credential{return Err(Error::not_found())}
   if row.get::<_,String>(0)!=auth::digest(serialized.as_bytes())||row.get::<_,String>(3)!="candidate"{return Err(Error::conflict())}return Ok(([("content-type","application/json")],row.get::<_,String>(1)).into_response())
  }
  r::ready(&tx,&current,&required,Some(&request.upload),&reusable).await?;
  let generations=r::ready(&tx,&current,&derived_objects,Some(&request.upload),&full_objects).await?;
  r::save_revision(&tx,&ns,&derived_id,&derived_bytes,&generations).await?;
  save_operation(&tx,&current,NewOperation{operation:&request.operation,kind:"candidate",request:&serialized,result:&result,status:200,branch:&branch,view:Some(request.original_view.as_str()),receipt:&receipt.receipt,submitted:&request.revision,derived:&derived_id}).await?;
  tx.execute("INSERT INTO candidate_causality(namespace,receipt,unknown) VALUES($1,$2,$3)",&[&ns,&receipt.receipt.as_str(),&unknown]).await?;
  tx.commit().await?;Ok(([("content-type","application/json")],result).into_response())
 })).await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (r::Snapshot, Revision) {
        let principal = PrincipalId::parse(format!("principal:{:032x}", 1)).unwrap();
        let group = GroupId::parse(format!("group:{:032x}", 1)).unwrap();
        let replica = ReplicaId::random().unwrap();
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o700,
        };
        let authority = Authority {
            principal: principal.clone(),
            uid: 1001,
            gid: 1001,
            primary_group: group.clone(),
            groups: vec![group.clone()],
            dac_override: false,
            ownership_transfer: false,
        };
        let entries = ["reports", "secret"]
            .into_iter()
            .map(|path| Entry {
                path: path.into(),
                id: EntryId::random().unwrap(),
                parent: root.id.clone(),
                owner: principal.clone(),
                group: group.clone(),
                mode: 0o700,
                content: EntryContent::Directory,
            })
            .collect();
        let full = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: replica.clone(),
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
        let projected = views::project(&full, &full.tree, &authority, &["reports".into()]).unwrap();
        let mut derived = full.clone();
        let mut child = derived.tree.entries[0].clone();
        child.id = EntryId::random().unwrap();
        child.path = "reports/new".into();
        child.parent = derived.tree.entries[0].id.clone();
        derived.tree.entries.push(child);
        let context = auth::AuthContext {
            credential: "fixture".into(),
            namespace: "fixture".into(),
            principal: principal.as_str().into(),
            replica: replica.as_str().into(),
            generation: 1,
            token_hash: String::new(),
            actions: vec![
                "read".into(),
                "write".into(),
                "history".into(),
                "integrate".into(),
            ],
            branches: vec!["main".into()],
            prefixes: vec!["reports".into()],
            depth: 0,
        };
        (
            r::Snapshot {
                context,
                branch: "main".into(),
                authorities: vec![authority],
                root,
                current: Some(full.clone()),
                head: Some("new-head".into()),
                view: Some(r::BoundView {
                    full,
                    projected,
                    head: "original-head".into(),
                    alternative: None,
                }),
            },
            derived,
        )
    }
    #[test]
    fn unchanged_hidden_move_does_not_invalidate_authorized_candidate() {
        let (mut s, derived) = fixture();
        s.current.as_mut().unwrap().tree.entries[1].path = "renamed-secret".into();
        assert!(s.validate_view().is_ok());
        assert!(authorize_candidate(&s, &derived).is_ok());
    }
    #[test]
    fn writer_without_history_uses_its_own_stale_base_but_not_old_reads() {
        // Ruling R11: the recorded base of a write needs no history; reading an old view does.
        let (mut s, derived) = fixture();
        s.context.actions.retain(|a| a != "history");
        assert!(s.validate_view().is_err_and(|e| e.code == "not_found"));
        assert!(s.validate_base().is_ok());
        assert!(authorize_candidate(&s, &derived).is_ok());
        assert!(authorize_retained(&s, &derived).is_ok());
    }
    #[test]
    fn retained_outcomes_reauthorize_current_rights_without_path_stability() {
        // Ruling R12: narrowed rights deny before anything is recorded; a concurrent move of a
        // required ancestor does not (a later merge handles it).
        let (mut s, derived) = fixture();
        s.current.as_mut().unwrap().tree.entries[0].path = "renamed-reports".into();
        s.context.prefixes = vec!["".into()];
        assert_eq!(
            authorize_candidate(&s, &derived).unwrap_err().code,
            "not_found"
        );
        assert!(authorize_retained(&s, &derived).is_ok());
        s.current.as_mut().unwrap().tree.entries[0].mode = 0o500;
        assert_eq!(
            authorize_retained(&s, &derived).unwrap_err().code,
            "not_found"
        );
        let (mut s, derived) = fixture();
        s.context.actions.retain(|a| a != "write");
        assert_eq!(
            authorize_retained(&s, &derived).unwrap_err().code,
            "not_found"
        );
    }
    #[test]
    fn candidate_still_requires_current_parent_write_and_stable_required_path() {
        let (mut s, derived) = fixture();
        s.current.as_mut().unwrap().tree.entries[0].mode = 0o500;
        assert!(s.validate_view().is_ok());
        assert_eq!(
            authorize_candidate(&s, &derived).unwrap_err().code,
            "not_found"
        );
        s.current.as_mut().unwrap().tree.entries[0].mode = 0o700;
        s.current.as_mut().unwrap().tree.entries[0].path = "renamed-reports".into();
        s.context.prefixes = vec!["".into()];
        assert!(s.validate_view().is_ok());
        assert_eq!(
            authorize_candidate(&s, &derived).unwrap_err().code,
            "not_found"
        );
    }
}
