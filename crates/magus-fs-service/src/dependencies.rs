//! Immutable declared observations and configured result authority. All new shared effects
//! call `check_publication` while holding the namespace transaction lock. Results alone
//! never confer publication rights. Old result replay is deliberately a separate path.
use crate::{
    auth::{self, AuthContext},
    db, policy, revisions as r, submission,
    views::core_error,
    Error, Result, ServiceState,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use magus_fs_core::{protocol::*, *};
use serde::{Deserialize, Serialize};
use tokio_postgres::Transaction;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorPolicy {
    pub branch: BranchName,
    pub validator: String,
    pub version: String,
    pub executable_hash: ObjectId,
    pub image_digest: ObjectId,
    pub worker_principal: PrincipalId,
    pub worker_replica: ReplicaId,
    pub output_paths: Vec<String>,
}
impl ValidatorPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.validator.is_empty()
            || self.validator.len() > 128
            || self.version.is_empty()
            || self.version.len() > 128
            || self.output_paths.is_empty()
            || self.output_paths.len() > 128
        {
            return Err(Error::invalid("invalid_policy"));
        }
        for p in &self.output_paths {
            if p.is_empty()
                || p.len() > 4096
                || p.split('/')
                    .any(|c| c.is_empty() || c == "." || c == ".." || c.contains('\0'))
            {
                return Err(Error::invalid("invalid_policy"));
            }
        }
        Ok(())
    }
    fn protects(&self, before: &Tree, after: &Tree) -> bool {
        self.output_paths.iter().any(|p| {
            before.entries.iter().find(|e| &e.path == p)
                != after.entries.iter().find(|e| &e.path == p)
        })
    }
    fn worker(&self, c: &AuthContext) -> Result<()> {
        c.action("validate")?;
        if c.principal != self.worker_principal.as_str()
            || c.replica != self.worker_replica.as_str()
            || self
                .output_paths
                .iter()
                .any(|p| !c.permits("validate", self.branch.as_str(), p))
        {
            return Err(Error::not_found());
        }
        Ok(())
    }
}
fn held(code: &'static str) -> Error {
    Error {
        status: StatusCode::CONFLICT,
        code,
    }
}
async fn policy(tx: &Transaction<'_>, ns: &str, branch: &str) -> Result<Option<ValidatorPolicy>> {
    tx.query_opt(
        "SELECT policy FROM branch_validator_policy WHERE namespace=$1 AND branch=$2",
        &[&ns, &branch],
    )
    .await?
    .map(|row| r::parse(&row.get::<_, String>(0)))
    .transpose()
}
/// Snapshot loader for callers already holding the namespace lock. No nested DB owner.
async fn snapshot(tx: &Transaction<'_>, c: &AuthContext, view: &str) -> Result<r::Snapshot> {
    let row=tx.query_opt("SELECT v.branch,v.head,v.descriptor,r.descriptor FROM views v JOIN revisions r ON r.namespace=v.namespace AND r.revision=v.full_revision WHERE v.id=$1 AND v.namespace=$2 AND v.credential=$3 AND v.principal=$4 AND v.replica=$5 AND v.alternative IS NULL AND v.history IS NULL",&[&view,&c.namespace,&c.credential,&c.principal,&c.replica]).await?.ok_or(Error::not_found())?;
    let branch: String = row.get(0);
    if !c.branches.contains(&branch) {
        return Err(Error::not_found());
    }
    let current=tx.query_one("SELECT b.head,r.descriptor FROM branches b JOIN revisions r ON r.namespace=b.namespace AND r.revision=b.revision WHERE b.namespace=$1 AND b.name=$2",&[&c.namespace,&branch]).await?;
    let authorities = tx
        .query(
            "SELECT authority FROM principal_authorities WHERE namespace=$1 ORDER BY principal",
            &[&c.namespace],
        )
        .await?
        .iter()
        .map(|v| r::parse::<policy::AuthorityConfig>(&v.get::<_, String>(0)).map(|a| a.logical()))
        .collect::<Result<Vec<_>>>()?;
    let root: policy::RootPolicy = r::parse(
        &tx.query_one(
            "SELECT root_policy FROM namespace_policy WHERE namespace=$1",
            &[&c.namespace],
        )
        .await?
        .get::<_, String>(0),
    )?;
    Ok(r::Snapshot {
        context: c.clone(),
        branch,
        authorities,
        root: root.root(),
        head: Some(current.get(0)),
        current: Some(r::decode(&current.get::<_, Vec<u8>>(1))?),
        view: Some(r::BoundView {
            head: row.get(1),
            projected: r::decode(&row.get::<_, Vec<u8>>(2))?,
            full: r::decode(&row.get::<_, Vec<u8>>(3))?,
            alternative: None,
            history: None,
        }),
    })
}
async fn candidate(
    tx: &Transaction<'_>,
    c: &AuthContext,
    id: &ReceiptId,
    replay: bool,
) -> Result<(r::Snapshot, Revision)> {
    c.action("write")?;
    let row=tx.query_opt("SELECT o.view_id,r.descriptor FROM operations o JOIN revisions r ON r.namespace=o.namespace AND r.revision=o.derived_revision WHERE o.namespace=$1 AND o.receipt=$2 AND o.credential=$3 AND o.principal=$4 AND o.replica=$5 AND o.kind='candidate'",&[&c.namespace,&id.as_str(),&c.credential,&c.principal,&c.replica]).await?.ok_or(Error::not_found())?;
    let s = snapshot(tx, c, &row.get::<_, String>(0)).await?;
    let output = r::decode(&row.get::<_, Vec<u8>>(1))?;
    if replay {
        s.validate_receipt_base()?;
    }
    submission::authorize_candidate(&s, &output)?;
    Ok((s, output))
}
#[derive(Serialize, Deserialize)]
struct Observed {
    reads: Vec<ObservedRead>,
    missing: Vec<ObservedMissing>,
}
#[derive(Serialize, Deserialize)]
struct ObservedRead {
    branch: String,
    full: RevisionId,
    entry: Entry,
}
#[derive(Serialize, Deserialize)]
struct ObservedMissing {
    branch: String,
    full: RevisionId,
    path: String,
}
fn absent(s: &r::Snapshot, tree: &Tree, path: &str) -> Result<bool> {
    if !s.context.permits("read", &s.branch, path) {
        return Err(Error::not_found());
    }
    // Prove readable traversal down to the closest existing parent, including root;
    // a hidden existing path never becomes an assertion of absence.
    authorize_tree_read(tree, &tree.root.id, s.authority()?).map_err(core_error)?;
    let mut prefix = String::new();
    for part in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        match tree.entries.iter().find(|e| e.path == prefix) {
            Some(e) => {
                authorize_tree_read(tree, &e.id, s.authority()?).map_err(core_error)?;
                if prefix == path {
                    return Ok(false);
                }
                if e.content != EntryContent::Directory {
                    return Err(Error::not_found());
                }
            }
            None => return Ok(true),
        }
    }
    Ok(false)
}
async fn observations(
    tx: &Transaction<'_>,
    c: &AuthContext,
    req: &DeclareRequest,
    replay: bool,
) -> Result<Observed> {
    let mut reads = vec![];
    let mut missing = vec![];
    for d in &req.reads {
        let s = snapshot(tx, c, d.view.as_str()).await?;
        let v = if replay {
            s.validate_receipt_base()?
        } else {
            s.validate_view()?
        };
        if r::rid(&v.projected)? != d.revision {
            return Err(Error::not_found());
        }
        let e = v
            .projected
            .tree
            .entries
            .iter()
            .find(|e| e.id == d.entry)
            .ok_or(Error::not_found())?;
        if !c.permits("read", &s.branch, &e.path) {
            return Err(Error::not_found());
        }
        reads.push(ObservedRead {
            branch: s.branch.clone(),
            full: r::rid(&v.full)?,
            entry: e.clone(),
        });
    }
    for m in &req.missing {
        let s = snapshot(tx, c, m.view.as_str()).await?;
        let v = if replay {
            s.validate_receipt_base()?
        } else {
            s.validate_view()?
        };
        if r::rid(&v.projected)? != m.revision || !absent(&s, &v.full.tree, &m.path)? {
            return Err(Error::not_found());
        }
        // Reauthorize the current enclosing path, but do not require it still absent.
        absent(
            &s,
            &s.current.as_ref().ok_or(Error::not_found())?.tree,
            &m.path,
        )?;
        missing.push(ObservedMissing {
            branch: s.branch.clone(),
            full: r::rid(&v.full)?,
            path: m.path.clone(),
        });
    }
    Ok(Observed { reads, missing })
}
async fn replay(
    tx: &Transaction<'_>,
    c: &AuthContext,
    op: &OperationId,
    kind: &str,
    request: &str,
) -> Result<Option<String>> {
    let row=tx.query_opt("SELECT credential,principal,kind,digest,result FROM dependency_operations WHERE namespace=$1 AND replica=$2 AND operation=$3",&[&c.namespace,&c.replica,&op.as_str()]).await?;
    if let Some(row) = row {
        if row.get::<_, String>(0) != c.credential || row.get::<_, String>(1) != c.principal {
            return Err(Error::not_found());
        }
        if row.get::<_, String>(2) != kind
            || row.get::<_, String>(3) != auth::digest(request.as_bytes())
        {
            return Err(Error::conflict());
        }
        return Ok(Some(row.get(4)));
    }
    Ok(None)
}
async fn save(
    tx: &Transaction<'_>,
    c: &AuthContext,
    op: &OperationId,
    kind: &str,
    request: &str,
    result: &str,
) -> Result<()> {
    tx.execute("INSERT INTO dependency_operations(namespace,replica,operation,credential,principal,kind,digest,request,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&c.namespace,&c.replica,&op.as_str(),&c.credential,&c.principal,&kind,&auth::digest(request.as_bytes()),&request,&result]).await?;
    Ok(())
}
pub(crate) async fn declare(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<DeclarationReceipt>> {
    let c = state.auth(&headers, &ns, "write").await?;
    let req: DeclareRequest = crate::json_body(body, &headers).await?;
    req.validate().map_err(core_error)?;
    if req.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    let serialized = r::json(&req)?;
    state.db.acquire().await?.run(|db|Box::pin(async move{
  let tx=db.transaction().await?;db::lock_namespace(&tx,&ns).await?;let c=auth::authenticate(&tx,&c.token_hash,&ns).await?;
  let old=replay(&tx,&c,&req.operation,"declaration",&serialized).await?;
  let (s,output)=candidate(&tx,&c,&req.candidate,old.is_some()).await?;
  let observed=observations(&tx,&c,&req,old.is_some()).await?;
  if let Some(old)=old{return Ok(Json(r::parse(&old)?));}
  if tx.query_opt("SELECT id FROM declarations WHERE namespace=$1 AND candidate=$2",&[&ns,&req.candidate.as_str()]).await?.is_some(){return Err(Error::conflict());}
  if let Some(v)=&req.validator {if policy(&tx,&ns,&s.branch).await?.as_ref().is_none_or(|p|&p.validator!=v){return Err(held("recompute_required"));}}
  let receipt=DeclarationReceipt{id:DeclarationId::random().map_err(core_error)?,candidate:req.candidate.clone()};let result=r::json(&receipt)?;
  save(&tx,&c,&req.operation,"declaration",&serialized,&result).await?;
  tx.execute("INSERT INTO declarations(id,namespace,replica,operation,candidate,branch,payload) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&receipt.id.as_str(),&ns,&c.replica,&req.operation.as_str(),&req.candidate.as_str(),&s.branch,&r::json(&observed)?]).await?;
  let mut pins=observed.reads.iter().map(|o|o.full.clone()).chain(observed.missing.iter().map(|o|o.full.clone())).collect::<Vec<_>>();pins.push(r::rid(&output)?);pins.sort();pins.dedup();
  for pin in pins {tx.execute("INSERT INTO dependency_pins(declaration,namespace,revision) VALUES($1,$2,$3)",&[&receipt.id.as_str(),&ns,&pin.as_str()]).await?;}
  tx.commit().await?;Ok(Json(receipt))
 })).await
}
struct Declaration {
    req: DeclareRequest,
    observed: Observed,
    owner: AuthContext,
    branch: String,
}
async fn declaration(tx: &Transaction<'_>, ns: &str, id: &DeclarationId) -> Result<Declaration> {
    let row=tx.query_opt("SELECT o.request,d.payload,d.branch,c.token_hash FROM declarations d JOIN dependency_operations o ON o.namespace=d.namespace AND o.replica=d.replica AND o.operation=d.operation JOIN credentials c ON c.id=o.credential WHERE d.namespace=$1 AND d.id=$2",&[&ns,&id.as_str()]).await?.ok_or(Error::not_found())?;
    Ok(Declaration {
        req: r::parse(&row.get::<_, String>(0))?,
        observed: r::parse(&row.get::<_, String>(1))?,
        branch: row.get(2),
        owner: auth::authenticate(tx, &row.get::<_, String>(3), ns).await?,
    })
}
fn input_binding(req: &DeclareRequest, record: &ValidationRecord, s: &r::Snapshot) -> Result<()> {
    let view = s.view.as_ref().ok_or(Error::not_found())?;
    if record.output != req.candidate
        || req.validator.as_ref() != Some(&record.validator)
        || req.reads.is_empty()
        || req
            .reads
            .iter()
            .any(|d| d.view != record.inputs.view || d.revision != record.inputs.revision)
        || req
            .missing
            .iter()
            .any(|d| d.view != record.inputs.view || d.revision != record.inputs.revision)
        || record.inputs.revision != r::rid(&view.projected)?
        || record.inputs.head.as_str() != view.head
    {
        return Err(Error::not_found());
    }
    Ok(())
}
pub(crate) async fn validate(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<ValidationId>> {
    let c = state.auth(&headers, &ns, "validate").await?;
    let req: ValidationRecord = crate::json_body(body, &headers).await?;
    if req.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    let serialized = r::json(&req)?;
    state.db.acquire().await?.run(|db|Box::pin(async move {
  let tx=db.transaction().await?;db::lock_namespace(&tx,&ns).await?;let c=auth::authenticate(&tx,&c.token_hash,&ns).await?;
  let old=replay(&tx,&c,&req.operation,"validation",&serialized).await?;
  let d=declaration(&tx,&ns,&req.declaration).await?;
  let p=policy(&tx,&ns,&d.branch).await?.ok_or(Error::not_found())?;p.worker(&c)?;
  candidate(&tx,&d.owner,&d.req.candidate,true).await?;
  observations(&tx,&d.owner,&d.req,true).await?;
  if let Some(old)=old{return Ok(Json(r::parse(&old)?));}
  if p.validator!=req.validator||p.version!=req.version||p.executable_hash!=req.executable_hash{return Err(Error::not_found());}
  let s=snapshot(&tx,&d.owner,req.inputs.view.as_str()).await?;s.validate_view()?;input_binding(&d.req,&req,&s)?;
  let id=ValidationId::random().map_err(core_error)?;save(&tx,&c,&req.operation,"validation",&serialized,&r::json(&id)?).await?;
  // Raw outcome retained even when head/input observations have become stale.
  tx.execute("INSERT INTO validations(id,namespace,replica,operation,declaration,policy) VALUES($1,$2,$3,$4,$5,$6)",&[&id.as_str(),&ns,&c.replica,&req.operation.as_str(),&req.declaration.as_str(),&r::json(&p)?]).await?;
  tx.commit().await?;Ok(Json(id))
 })).await
}
/// Central admission for every candidate publication and restore. Caller holds namespace
/// lock and has rechecked current head/credential. Compare both shared inputs and the
/// proposed final tree, so a combined input+output candidate cannot bless stale output.
pub(crate) async fn check_publication(
    tx: &Transaction<'_>,
    s: &r::Snapshot,
    candidate_id: Option<&ReceiptId>,
    final_tree: &Tree,
    explicit: Option<(&DeclarationId, Option<&ValidationId>)>,
) -> Result<()> {
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let p = policy(tx, &s.context.namespace, &s.branch).await?;
    let required = p
        .as_ref()
        .is_some_and(|p| p.protects(&current.tree, final_tree));
    let found = if let Some(candidate) = candidate_id {
        tx.query_opt(
            "SELECT id FROM declarations WHERE namespace=$1 AND candidate=$2",
            &[&s.context.namespace, &candidate.as_str()],
        )
        .await?
        .map(|r| r.get::<_, String>(0))
    } else {
        None
    };
    let Some(id) = found else {
        if required || explicit.is_some() {
            return Err(held("recompute_required"));
        }
        return Ok(());
    };
    let id = DeclarationId::parse(id).map_err(core_error)?;
    if explicit.is_some_and(|(x, _)| x != &id) {
        return Err(Error::not_found());
    }
    let d = declaration(tx, &s.context.namespace, &id).await?;
    if d.owner.credential != s.context.credential {
        return Err(Error::not_found());
    }
    candidate(tx, &d.owner, &d.req.candidate, false).await?;
    observations(tx, &d.owner, &d.req, true).await?;
    for read in &d.observed.reads {
        let tree = if read.branch == s.branch {
            current.tree.clone()
        } else {
            let row=tx.query_one("SELECT r.descriptor FROM branches b JOIN revisions r ON r.namespace=b.namespace AND r.revision=b.revision WHERE b.namespace=$1 AND b.name=$2",&[&s.context.namespace,&read.branch]).await?;
            r::decode(&row.get::<_, Vec<u8>>(0))?.tree
        };
        if tree.entries.iter().find(|e| e.id == read.entry.id) != Some(&read.entry)
            || (read.branch == s.branch
                && final_tree.entries.iter().find(|e| e.id == read.entry.id) != Some(&read.entry))
        {
            return Err(held("dependency_changed"));
        }
    }
    // Observations preserve request order. Same paths may name different branches/views.
    for (missing, view) in d.observed.missing.iter().zip(&d.req.missing) {
        let ms = snapshot(tx, &d.owner, view.view.as_str()).await?;
        if !absent(
            &ms,
            &ms.current.as_ref().ok_or(Error::not_found())?.tree,
            &missing.path,
        )? || (missing.branch == s.branch && !absent(&ms, final_tree, &missing.path)?)
        {
            return Err(held("dependency_changed"));
        }
    }
    if required && d.req.coverage != DependencyCoverage::CompleteDeclared {
        return Err(held("recompute_required"));
    }
    if required || d.req.validator.is_some() {
        let p = p.ok_or(held("recompute_required"))?;
        if d.req.validator.as_ref() != Some(&p.validator) {
            return Err(held("recompute_required"));
        }
        let selected = explicit.and_then(|(_, v)| v).map(|v| v.as_str());
        let rows=tx.query("SELECT o.request,v.policy,c.token_hash FROM validations v JOIN dependency_operations o ON o.namespace=v.namespace AND o.replica=v.replica AND o.operation=v.operation JOIN credentials c ON c.id=o.credential WHERE v.namespace=$1 AND v.declaration=$2 AND ($3::text IS NULL OR v.id=$3)",&[&s.context.namespace,&id.as_str(),&selected]).await?;
        let mut valid = false;
        for row in rows {
            let record: ValidationRecord = r::parse(&row.get::<_, String>(0))?;
            let old: ValidatorPolicy = r::parse(&row.get::<_, String>(1))?;
            if old != p
                || record.outcome != ValidationOutcome::Pass
                || Some(record.expected_head.as_str()) != s.head.as_deref()
            {
                continue;
            }
            let Ok(worker) =
                auth::authenticate(tx, &row.get::<_, String>(2), &s.context.namespace).await
            else {
                continue;
            };
            if p.worker(&worker).is_err() {
                continue;
            }
            let vs = snapshot(tx, &d.owner, record.inputs.view.as_str()).await?;
            input_binding(&d.req, &record, &vs)?;
            valid = true;
            break;
        }
        if !valid {
            return Err(held("recompute_required"));
        }
    }
    Ok(())
}
