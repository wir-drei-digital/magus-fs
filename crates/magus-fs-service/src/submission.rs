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
/// Current-rights authorization of a candidate against its recorded base (ruling R14,
/// also used before every retained outcome per R12/R17 and for fast-forward/replay):
/// - read action and the caller's own issued, non-alternative base (no `history`, R11);
/// - the delta at base locations, with *current* metadata for identities the caller can
///   still see at their current location (hidden ones keep base metadata, never current
///   access), within the current grant;
/// - the delta's effect at the *current* locations of what it touches (current scope and
///   current write permission); visible changes by others to untouched entries never deny,
///   and touched identities deleted or moved out of scope by others are presented as
///   absent (reconciled as retained edit/delete at integration).
pub(crate) fn authorize_candidate(s: &r::Snapshot, derived: &Revision) -> Result<()> {
    s.context.action("read")?;
    let view = s.view.as_ref().ok_or(Error::not_found())?;
    if view.alternative.is_some() {
        return Err(Error::not_found());
    }
    let a = s.authority()?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let visible = crate::reconciliation::caller_visible(current, a, &s.context.prefixes)?;
    let present = current
        .tree
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<BTreeMap<_, _>>();
    let mut now = view.full.tree.clone();
    now.root = current.tree.root.clone();
    for old in &mut now.entries {
        if let Some(p) = present.get(&old.id).filter(|_| visible.contains(&old.id)) {
            old.owner = p.owner.clone();
            old.group = p.group.clone();
            old.mode = p.mode;
        }
    }
    let mut checked = derived.tree.clone();
    // Unchanged metadata is not a request to restore old permissions.
    if derived.tree.root == view.full.tree.root {
        checked.root = now.root.clone()
    }
    let base = view
        .full
        .tree
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<BTreeMap<_, _>>();
    let overlay = now
        .entries
        .iter()
        .map(|e| (e.id.clone(), e.clone()))
        .collect::<BTreeMap<_, _>>();
    for e in &mut checked.entries {
        if let Some(old) = base.get(&e.id) {
            if (&e.owner, &e.group, e.mode) == (&old.owner, &old.group, old.mode) {
                if let Some(p) = overlay.get(&e.id) {
                    e.owner = p.owner.clone();
                    e.group = p.group.clone();
                    e.mode = p.mode;
                }
            }
        }
    }
    authorize_tree_transition(&now, &checked, a, &s.authorities, &s.scope()).map_err(core_error)?;
    let presented =
        crate::reconciliation::present(&view.full.tree, &current.tree, &derived.tree, &visible);
    // R19: an effect that cannot be composed at current locations is denied, never skipped.
    let effect =
        crate::reconciliation::effect(&view.full.tree, &presented).ok_or(Error::not_found())?;
    authorize_tree_transition(&presented.left, &effect, a, &s.authorities, &s.scope())
        .map_err(core_error)?;
    Ok(())
}
/// Rulings R12/R17: the same current-location authorization before a retained outcome.
pub(crate) fn authorize_retained(s: &r::Snapshot, derived: &Revision) -> Result<()> {
    authorize_candidate(s, derived)
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
    // R14: untouched visible changes by others never deny a private submission; the
    // touched entries are authorized at their current locations below.
    s.context.action("read")?;
    let view = s.view.as_ref().ok_or(Error::not_found())?;
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
    // Ruling R18: an identity absent from the caller's authorized base view may not be
    // re-used: hidden head identities are refused by `lift`, and identities named by a
    // recorded conflict (e.g. deleted or moved out of scope by others) are refused here
    // with the same response, so a resolution cannot tell the two apart.
    let issued: std::collections::BTreeSet<&EntryId> =
        view.projected.tree.entries.iter().map(|e| &e.id).collect();
    let introduced: Vec<String> = chain
        .iter()
        .flat_map(|(_, r)| r.tree.entries.iter())
        .filter(|e| !issued.contains(&e.id))
        .map(|e| e.id.as_str().to_owned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !introduced.is_empty() {
        let reused = state
            .db
            .acquire()
            .await?
            .run(|db| {
                let ns = &ns;
                let introduced = &introduced;
                Box::pin(async move {
                    Ok(db
                        .query_opt(
                            "SELECT 1 FROM conflicts WHERE namespace=$1 AND entry=ANY($2) LIMIT 1",
                            &[ns, introduced],
                        )
                        .await?
                        .is_some())
                })
            })
            .await?;
        if reused {
            return Err(Error::not_found());
        }
    }
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
    use std::collections::BTreeSet;
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
        assert!(authorize_candidate(&s, &derived).is_ok());
        assert!(authorize_retained(&s, &derived).is_ok());
    }
    #[test]
    fn touched_entries_need_current_write_and_scope_at_current_locations() {
        // R14/R17: a narrowed current parent or a lost write action denies.
        let (mut s, derived) = fixture();
        s.current.as_mut().unwrap().tree.entries[0].mode = 0o500;
        assert!(s.validate_view().is_ok());
        assert_eq!(
            authorize_candidate(&s, &derived).unwrap_err().code,
            "not_found"
        );
        let (mut s, derived) = fixture();
        s.context.actions.retain(|a| a != "write");
        assert_eq!(
            authorize_retained(&s, &derived).unwrap_err().code,
            "not_found"
        );
        // R19-B: the parent moved out of the caller's scope by others is presented as absent
        // (exactly like a deleted parent): the private submission is accepted and nothing is
        // ever placed at the out-of-scope location (integration retains a conflict).
        let (mut s, derived) = fixture();
        s.current.as_mut().unwrap().tree.entries[0].path = "outside".into();
        assert!(authorize_candidate(&s, &derived).is_ok());
        let (mut s, derived2) = fixture();
        s.current.as_mut().unwrap().tree.entries.remove(0);
        assert!(authorize_candidate(&s, &derived2).is_ok());
    }
    #[test]
    fn untouched_visible_changes_and_in_scope_ancestor_moves_never_deny() {
        // R14: a rename of the touched entry's ancestor inside scope is handled by the merge,
        // and an unrelated visible deletion does not deny the private submission.
        let (mut s, derived) = fixture();
        s.context.prefixes = vec!["".into()];
        s.current.as_mut().unwrap().tree.entries[0].path = "renamed-reports".into();
        assert!(authorize_candidate(&s, &derived).is_ok());
        let (mut s, derived) = fixture();
        s.context.prefixes = vec!["".into()];
        s.current.as_mut().unwrap().tree.entries.remove(1);
        assert!(authorize_candidate(&s, &derived).is_ok());
    }
    #[test]
    fn creation_under_moved_out_or_deleted_folder_is_presented_identically() {
        // R19-B: base has dir `secret`; the candidate creates `secret/new`; others either
        // deleted `secret` or moved it out of the caller's scope (invisible).
        let (s, _) = fixture();
        let base = s.view.as_ref().unwrap().full.tree.clone();
        let folder = base.entries[1].clone();
        let mut derived = base.clone();
        let mut child = folder.clone();
        child.id = EntryId::random().unwrap();
        child.path = "secret/new".into();
        child.parent = folder.id.clone();
        derived.entries.push(child);
        let visible = BTreeSet::from([base.root.id.clone(), base.entries[0].id.clone()]);
        let mut moved = base.clone();
        moved.entries[1].path = "elsewhere".into();
        let mut deleted = base.clone();
        deleted.entries.remove(1);
        let a = crate::reconciliation::present(&base, &moved, &derived, &visible);
        let b = crate::reconciliation::present(&base, &deleted, &derived, &visible);
        assert_eq!(a.left, b.left);
        assert_eq!(a.right, b.right);
        assert_eq!(
            crate::reconciliation::effect(&base, &a),
            crate::reconciliation::effect(&base, &b)
        );
    }
    #[test]
    fn uncomposable_effect_fails_closed() {
        // R19: the current head turned the touched parent identity into a file; the
        // candidate's child cannot be placed, so authorization denies instead of skipping.
        let (mut s, derived) = fixture();
        s.context.prefixes = vec!["".into()];
        let current = s.current.as_mut().unwrap();
        current.tree.entries[0].content = EntryContent::File {
            version: FileVersion {
                size: 0,
                extents: vec![],
            },
        };
        assert_eq!(
            authorize_candidate(&s, &derived).unwrap_err().code,
            "not_found"
        );
    }
    #[test]
    fn hidden_touched_identities_are_presented_as_absent() {
        // R14: edit vs moved-out-of-scope becomes edit/delete (head side absent); delete vs
        // moved-out-of-scope is moot and keeps the hidden head entry.
        let (s, _) = fixture();
        let base = s.view.as_ref().unwrap().full.tree.clone();
        let mut current = base.clone();
        current.entries[1].path = "elsewhere".into();
        let visible = BTreeSet::from([current.root.id.clone(), current.entries[0].id.clone()]);
        let mut edited = base.clone();
        edited.entries[1].mode = 0o750;
        let p = crate::reconciliation::present(&base, &current, &edited, &visible);
        assert_eq!(p.hidden_edits, BTreeSet::from([base.entries[1].id.clone()]));
        assert!(!p.left.entries.iter().any(|e| e.id == base.entries[1].id));
        let mut deleted = base.clone();
        deleted.entries.remove(1);
        let p = crate::reconciliation::present(&base, &current, &deleted, &visible);
        assert!(p.hidden_edits.is_empty());
        assert_eq!(p.left, current);
        assert!(p.right.entries.iter().any(|e| e == &base.entries[1]));
    }
}
