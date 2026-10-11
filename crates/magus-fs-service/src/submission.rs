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
    if view.alternative.is_some() || view.history.is_some() {
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
    let merge = crate::reconciliation::CallerMerge::new(
        view,
        current,
        &derived.tree,
        a,
        &s.context.prefixes,
    )?;
    // R19: an effect that cannot be composed at current locations is denied, never skipped.
    let effect = merge.effect()?;
    authorize_tree_transition(&merge.current, &effect, a, &s.authorities, &s.scope())
        .map_err(core_error)?;
    Ok(())
}
/// Rulings R12/R17: the same current-location authorization before a retained outcome.
pub(crate) fn authorize_retained(s: &r::Snapshot, derived: &Revision) -> Result<()> {
    authorize_candidate(s, derived)
}
/// Distinct identities of the given trees, for `refuse_revived`.
pub(crate) fn entry_ids<'a>(trees: impl IntoIterator<Item = &'a Tree>) -> Vec<String> {
    trees
        .into_iter()
        .flat_map(|t| t.entries.iter().map(|e| e.id.as_str().to_owned()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}
/// Ruling R21: the namespace identity registry (`namespace_entries`: every identity ever
/// published in a shared revision of the namespace). An identity a candidate introduces
/// beyond its issued base view that the registry knows but that is absent from the caller's
/// current authorized projection (deleted, moved out of scope or made unreadable alike) is
/// refused with the same `404 not_found` a hidden identity gets, at submission, integration,
/// resolution admission. Recorded-result replay never admits identities (R23).
/// Identities hidden at the base are `lift`'s concern (same response).
/// The lookup reads published identities only; it never consults conflicts of anyone.
pub(crate) async fn refuse_revived(
    state: &ServiceState,
    s: &r::Snapshot,
    ids: &[String],
) -> Result<()> {
    let view = s.view.as_ref().ok_or(Error::not_found())?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let visible =
        crate::reconciliation::caller_visible(current, s.authority()?, &s.context.prefixes)?;
    let known: std::collections::BTreeSet<&str> = view
        .full
        .tree
        .entries
        .iter()
        .map(|e| e.id.as_str())
        .chain(visible.iter().map(|id| id.as_str()))
        .collect();
    let introduced: Vec<String> = ids
        .iter()
        .filter(|id| !known.contains(id.as_str()))
        .cloned()
        .collect();
    if introduced.is_empty() {
        return Ok(());
    }
    let ns = &s.context.namespace;
    let published = state
        .db
        .acquire()
        .await?
        .run(|db| {
            let introduced = &introduced;
            Box::pin(async move {
                Ok(db
                    .query_opt(
                        "SELECT 1 FROM namespace_entries WHERE namespace=$1 AND entry=ANY($2) LIMIT 1",
                        &[ns, introduced],
                    )
                    .await?
                    .is_some())
            })
        })
        .await?;
    if published {
        return Err(Error::not_found());
    }
    Ok(())
}
pub(crate) async fn replay(
    state: &ServiceState,
    c: &auth::AuthContext,
    op: &Operation,
) -> Result<()> {
    if op.kind == "restore" {
        return crate::history::replay(state, c, op).await;
    }
    let s = r::snapshot(&state.db, c, &op.branch, op.view.as_deref()).await?;
    s.context.action(if op.kind == "candidate" {
        "write"
    } else {
        "integrate"
    })?;
    if let Some(derived) = &op.derived {
        if op.view.is_some() {
            if op.kind == "candidate" {
                // A private receipt replay *reads* the caller's own base: the A rule that
                // every formerly visible identity of it is still readable applies (deleted,
                // moved-out or unreadable alike).
                s.validate_receipt_base()?;
            }
            // R22/R23: lookup/exact replay returns immutable operation metadata, never
            // admits a new effect. An introduced identity may since have been deleted or
            // moved out of scope; the registry's revival check belongs only to admission.
            // Keep current credential, scope and permission checks for every result kind.
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
    // Rulings R18/R21: an identity the chain introduces beyond the issued base that the
    // namespace has published but that is absent from the caller's current projection is
    // refused exactly like a hidden one (`lift`), whether deleted, moved out or unreadable.
    refuse_revived(&state, &s, &entry_ids(chain.iter().map(|(_, r)| &r.tree))).await?;
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
                    history: None,
                }),
            },
            derived,
        )
    }
    type Outcome = std::result::Result<(u16, Vec<ConflictReason>, Tree), &'static str>;
    type Shown = std::result::Result<
        (u16, Vec<ConflictReason>, Vec<(String, u16, EntryContent)>),
        &'static str,
    >;
    fn hole(size: u64) -> EntryContent {
        EntryContent::File {
            version: FileVersion {
                size,
                extents: vec![Extent::Hole { length: size }],
            },
        }
    }
    /// The fixture plus `reports/F` holding `old.txt` and `z.txt`, all visible to the
    /// `reports`-scoped caller; the current head equals the issued base.
    fn folder_fixture() -> r::Snapshot {
        let (mut s, _) = fixture();
        let authority = s.authorities[0].clone();
        let view = s.view.as_mut().unwrap();
        let reports = view.full.tree.entries[0].clone();
        let dir = Entry {
            path: "reports/F".into(),
            id: EntryId::random().unwrap(),
            parent: reports.id.clone(),
            ..reports.clone()
        };
        let file = |name: &str, size| Entry {
            path: format!("reports/F/{name}"),
            id: EntryId::random().unwrap(),
            parent: dir.id.clone(),
            mode: 0o600,
            content: hole(size),
            ..reports.clone()
        };
        let files = [file("old.txt", 1), file("z.txt", 2)];
        view.full.tree.entries.push(dir.clone());
        view.full.tree.entries.extend(files);
        view.full.tree.entries.sort_by(|x, y| x.path.cmp(&y.path));
        view.projected =
            views::project(&view.full, &view.full.tree, &authority, &["reports".into()]).unwrap();
        s.current = Some(view.full.clone());
        s
    }
    fn at<'a>(t: &'a mut Tree, path: &str) -> &'a mut Entry {
        t.entries.iter_mut().find(|e| e.path == path).unwrap()
    }
    /// The caller's offline change of its issued projection, lifted as at submission.
    fn offline(s: &r::Snapshot, change: impl FnOnce(&mut Tree)) -> Revision {
        let view = s.view.as_ref().unwrap();
        let mut submitted = view.projected.clone();
        change(&mut submitted.tree);
        views::lift(&view.full, &view.projected, &submitted).unwrap()
    }
    /// Others delete `path` (with its subtree) or move it beneath `secret`, out of scope.
    fn others(s: &mut r::Snapshot, variant: &str, path: &str) {
        let tree = &mut s.current.as_mut().unwrap().tree;
        let inside = |p: &str| p == path || p.starts_with(&format!("{path}/"));
        if variant == "deleted" {
            tree.entries.retain(|e| !inside(&e.path));
        } else {
            let secret = tree
                .entries
                .iter()
                .find(|e| e.path == "secret")
                .unwrap()
                .id
                .clone();
            for e in &mut tree.entries {
                if e.path == path {
                    e.parent = secret.clone();
                }
                if inside(&e.path) {
                    e.path = format!("secret/{}", e.path.trim_start_matches("reports/"));
                }
            }
            tree.entries.sort_by(|x, y| x.path.cmp(&y.path));
        }
    }
    /// The service integration outcome of a stale candidate with an opaque policy: current
    /// rights first, then the merge, completion and the reauthorized resulting delta.
    fn integration(s: &r::Snapshot, derived: &Revision) -> Outcome {
        authorize_retained(s, derived).map_err(|e| e.code)?;
        let view = s.view.as_ref().unwrap();
        let current = s.current.as_ref().unwrap();
        let a = s.authority().unwrap();
        let merge = crate::reconciliation::CallerMerge::new(
            view,
            current,
            &derived.tree,
            a,
            &s.context.prefixes,
        )
        .map_err(|e| e.code)?;
        match reconcile_trees(
            &merge.base,
            &merge.current,
            &merge.candidate,
            &MergePolicy::opaque(),
            &crate::reconciliation::NoContent,
        )
        .map_err(|_| "invalid")?
        {
            MergeOutcome::Clean { tree, .. } => {
                let tree = merge.complete(tree).map_err(|e| e.code)?;
                authorize_tree_transition(&current.tree, &tree, a, &s.authorities, &s.scope())
                    .map_err(|e| core_error(e).code)?;
                Ok((200, vec![], tree))
            }
            MergeOutcome::Conflicted { alternatives } => {
                crate::reconciliation::conflicts_visible(s, view, current, &alternatives)
                    .map_err(|e| e.code)?;
                let mut reasons: Vec<_> = alternatives.iter().map(|c| c.reason).collect();
                reasons.sort();
                Ok((409, reasons, current.tree.clone()))
            }
        }
    }
    /// Only the caller-visible part of an outcome may be compared across variants.
    fn in_scope(outcome: &Outcome) -> Shown {
        // Each variant uses its own fixture (fresh identities): compare locations and values.
        outcome.clone().map(|(status, reasons, tree)| {
            let shown = tree
                .entries
                .into_iter()
                .filter(|e| e.path.starts_with("reports"))
                .map(|e| (e.path, e.mode, e.content))
                .collect();
            (status, reasons, shown)
        })
    }
    #[test]
    fn r20_delete_beneath_a_deleted_or_moved_out_folder_is_identical() {
        // The caller deletes F/old.txt offline; others delete F, or move F out of scope.
        let mut outcomes = vec![];
        for variant in ["deleted", "moved"] {
            let mut s = folder_fixture();
            let derived = offline(&s, |t| t.entries.retain(|e| e.path != "reports/F/old.txt"));
            others(&mut s, variant, "reports/F");
            outcomes.push(integration(&s, &derived));
        }
        assert_eq!(in_scope(&outcomes[0]), in_scope(&outcomes[1]));
        assert_eq!(outcomes[0].as_ref().map(|o| o.0), Ok(200));
        // Nothing is written out of scope: the moved folder keeps old.txt unchanged.
        let moved = &outcomes[1].as_ref().unwrap().2;
        assert!(moved.entries.iter().any(|e| e.path == "secret/F/old.txt"));
    }
    #[test]
    fn r20_edit_of_an_entry_moved_out_of_a_deleted_or_moved_out_folder_is_identical() {
        // Others move F/z.txt to reports/z.txt, then delete F or move F out of scope; the
        // caller edits z at its old location offline.
        let mut outcomes = vec![];
        for variant in ["deleted", "moved"] {
            let mut s = folder_fixture();
            let derived = offline(&s, |t| at(t, "reports/F/z.txt").content = hole(5));
            let current = &mut s.current.as_mut().unwrap().tree;
            let reports = current.entries[0].id.clone();
            let z = at(current, "reports/F/z.txt");
            z.path = "reports/z.txt".into();
            z.parent = reports;
            current.entries.sort_by(|x, y| x.path.cmp(&y.path));
            others(&mut s, variant, "reports/F");
            outcomes.push(integration(&s, &derived));
        }
        assert_eq!(in_scope(&outcomes[0]), in_scope(&outcomes[1]));
        let (status, _, mut tree) = outcomes[0].clone().unwrap();
        assert_eq!(status, 200);
        assert_eq!(at(&mut tree, "reports/z.txt").content, hole(5));
        let moved = &outcomes[1].as_ref().unwrap().2;
        assert!(!moved.entries.iter().any(|e| e.path == "secret/F/z.txt"));
    }
    #[test]
    fn r20_edit_and_creation_beneath_a_deleted_or_moved_out_folder_are_identical() {
        // R14 edit/delete and R19-B creation beneath the folder: identical retained conflicts.
        for change in [0, 1] {
            let mut outcomes = vec![];
            for variant in ["deleted", "moved"] {
                let mut s = folder_fixture();
                let derived = offline(&s, |t| {
                    if change == 0 {
                        at(t, "reports/F/old.txt").content = hole(7);
                    } else {
                        let mut new = at(t, "reports/F/old.txt").clone();
                        new.id = EntryId::random().unwrap();
                        new.path = "reports/F/new.txt".into();
                        t.entries.push(new);
                    }
                });
                others(&mut s, variant, "reports/F");
                outcomes.push(integration(&s, &derived));
            }
            assert_eq!(
                in_scope(&outcomes[0]),
                in_scope(&outcomes[1]),
                "change {change}"
            );
            let reasons = outcomes[0].as_ref().unwrap().1.clone();
            assert!(
                reasons.contains(&if change == 0 {
                    ConflictReason::EditDelete
                } else {
                    ConflictReason::DirectoryDelete
                }),
                "{reasons:?}"
            );
        }
    }
    #[test]
    fn r20_collision_with_an_entry_hidden_after_the_base_is_denied_at_integration() {
        // Others create an entry the caller cannot read at the path the caller creates
        // offline: the private submission is accepted (only touched visible entries are
        // checked) and integration is denied without disclosure; nothing is replaced.
        let mut s = folder_fixture();
        let derived = offline(&s, |t| {
            let mut new = at(t, "reports/F/old.txt").clone();
            new.id = EntryId::random().unwrap();
            new.path = "reports/F/x".into();
            t.entries.push(new);
        });
        let current = &mut s.current.as_mut().unwrap().tree;
        let mut hidden = at(current, "reports/F/old.txt").clone();
        hidden.id = EntryId::random().unwrap();
        hidden.path = "reports/F/x".into();
        hidden.mode = 0;
        current.entries.push(hidden);
        current.entries.sort_by(|x, y| x.path.cmp(&y.path));
        assert!(authorize_candidate(&s, &derived).is_ok());
        assert_eq!(integration(&s, &derived).map(|o| o.0), Err("not_found"));
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
}
