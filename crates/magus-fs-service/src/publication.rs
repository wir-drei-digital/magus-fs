use crate::{
    auth, revisions as r,
    submission::{self, save_operation, NewOperation},
    views::core_error,
    Error, Result, ServiceState,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use magus_fs_core::{protocol::*, *};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SeedRequest {
    branch: BranchName,
    revision: RevisionId,
    upload: UploadId,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntegrationRequest {
    operation: OperationId,
    replica: ReplicaId,
    candidate_receipt: ReceiptId,
    expected_head: HeadToken,
    branch: BranchName,
}
pub(crate) async fn barrier(name: &str) {
    #[cfg(feature = "test-faults")]
    if std::path::Path::new(&format!("/control/pause-{name}")).is_file() {
        let _ = std::fs::write(format!("/tmp/fs2-{name}-barrier"), b"prepared");
        while std::path::Path::new(&format!("/control/pause-{name}")).is_file() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    #[cfg(not(feature = "test-faults"))]
    let _ = name;
}
pub(crate) async fn seed(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let c = state.auth(&headers, &ns, "admin").await?;
    let req: SeedRequest = crate::json_body(body, &headers).await?;
    let s = r::snapshot(&state.db, &c, req.branch.as_str(), None).await?;
    if !s.context.permits("admin", req.branch.as_str(), "") {
        return Err(Error::not_found());
    }
    s.authority()?;
    let descriptors = submission::staged(&state, &c, &req.upload).await?;
    let revision = descriptors.get(&req.revision).ok_or(Error::not_found())?;
    let serialized = r::json(&req)?;
    if let Some(op) = submission::operation(
        &state,
        &c,
        revision.replica.as_str(),
        revision.operation.as_str(),
    )
    .await?
    {
        submission::replay(&state, &c, &op).await?;
        if op.kind != "seed" || op.digest != auth::digest(serialized.as_bytes()) {
            return Err(Error::conflict());
        }
        return op.response();
    }
    if s.current.is_some() {
        return Err(Error::conflict());
    }
    if revision.tree.root != s.root || !revision.parents.is_empty() || revision.format != FORMAT {
        return Err(Error::invalid("invalid_seed"));
    }
    let empty = Tree {
        root: s.root.clone(),
        entries: vec![],
    };
    authorize_tree_transition(
        &empty,
        &revision.tree,
        s.authority()?,
        &s.authorities,
        &s.scope(),
    )
    .map_err(core_error)?;
    let bytes = r::encode(revision)?;
    let required = r::objects(revision)?;
    let receipt = SharedReceipt {
        receipt: ReceiptId::random().map_err(core_error)?,
        operation: revision.operation.clone(),
        replica: revision.replica.clone(),
        submitted_revision: req.revision.clone(),
        branch: req.branch.clone(),
        head: HeadToken::random().map_err(core_error)?,
    };
    let result = r::json(&receipt)?;
    let paths = vec![String::new()];
    state
        .db
        .acquire()
        .await?
        .run(|db| {
            Box::pin(async move {
                let tx = db.transaction().await?;
                let current = r::recheck(&tx, &s, "admin").await?;
                let generations = r::ready(
                    &tx,
                    &current,
                    &required,
                    Some(&req.upload),
                    &BTreeMap::new(),
                )
                .await?;
                r::save_revision(&tx, &ns, &req.revision, &bytes, &generations).await?;
                tx.execute(
                    "INSERT INTO branches(namespace,name,revision,head) VALUES($1,$2,$3,$4)",
                    &[
                        &ns,
                        &req.branch.as_str(),
                        &req.revision.as_str(),
                        &receipt.head.as_str(),
                    ],
                )
                .await?;
                save_operation(
                    &tx,
                    &current,
                    NewOperation {
                        operation: &receipt.operation,
                        kind: "seed",
                        request: &serialized,
                        result: &result,
                        status: 200,
                        branch: req.branch.as_str(),
                        view: None,
                        receipt: &receipt.receipt,
                        submitted: &req.revision,
                        derived: &req.revision,
                    },
                )
                .await?;
                tx.execute(
                    "INSERT INTO changes(namespace,branch,head,paths) VALUES($1,$2,$3,$4)",
                    &[&ns, &req.branch.as_str(), &receipt.head.as_str(), &paths],
                )
                .await?;
                tx.commit().await?;
                Ok(([("content-type", "application/json")], result).into_response())
            })
        })
        .await
}
pub(crate) async fn integrate(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let c = state.auth(&headers, &ns, "integrate").await?;
    let req: IntegrationRequest = crate::json_body(body, &headers).await?;
    if req.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    let serialized = r::json(&req)?;
    for attempt in 0..3 {
        if let Some(op) =
            submission::operation(&state, &c, req.replica.as_str(), req.operation.as_str()).await?
        {
            submission::replay(&state, &c, &op).await?;
            if op.kind != "integration" || op.digest != auth::digest(serialized.as_bytes()) {
                return Err(Error::conflict());
            }
            return op.response();
        }
        let candidate_id=state.db.acquire().await?.run(|db|{let req=&req;let c=&c;let ns=&ns;Box::pin(async move {db.query_opt("SELECT operation FROM operations WHERE namespace=$1 AND receipt=$2 AND replica=$3 AND principal=$4 AND credential=$5 AND kind='candidate'",&[&ns,&req.candidate_receipt.as_str(),&c.replica,&c.principal,&c.credential]).await?.map(|r|r.get::<_,String>(0)).ok_or(Error::not_found())})}).await?;
        let candidate = submission::operation(&state, &c, &c.replica, &candidate_id)
            .await?
            .ok_or(Error::not_found())?;
        if candidate.branch != req.branch.as_str() {
            return Err(Error::not_found());
        }
        let s = r::snapshot(
            &state.db,
            &c,
            req.branch.as_str(),
            candidate.view.as_deref(),
        )
        .await?;
        s.context.action("integrate")?;
        let derived = candidate.derived.as_ref().ok_or(Error::not_found())?;
        submission::authorize_candidate(&s, derived)?;
        let original: submission::CandidateRequest = r::parse(&candidate.request)?;
        let view = s.validate_view()?;
        let stale = s.head.as_deref() != Some(req.expected_head.as_str())
            || req.expected_head.as_str() != view.head
            || derived.parents != vec![r::rid(&view.full)?];
        let derived_id = r::rid(derived)?;
        let required = r::objects(derived)?;
        let mut paths = vec![];
        for e in &derived.tree.entries {
            if view.full.tree.entries.iter().find(|old| old.id == e.id) != Some(e) {
                paths.push(e.path.clone());
            }
        }
        for old in &view.full.tree.entries {
            if derived.tree.entries.iter().find(|e| e.id == old.id) != Some(old) {
                paths.push(old.path.clone());
            }
        }
        if derived.tree.root != view.full.tree.root {
            paths.push(String::new())
        }
        let receipt = SharedReceipt {
            receipt: ReceiptId::random().map_err(core_error)?,
            operation: req.operation.clone(),
            replica: req.replica.clone(),
            submitted_revision: original.revision.clone(),
            branch: req.branch.clone(),
            head: HeadToken::random().map_err(core_error)?,
        };
        let result = if stale {
            "{\"code\":\"stale_head\"}".into()
        } else {
            r::json(&receipt)?
        };
        barrier("integration").await;
        let commit=state.db.acquire().await?.run(|db|{let req=&req;let serialized=&serialized;Box::pin(async move {
   let tx=db.transaction().await?;let current=r::recheck(&tx,&s,"integrate").await?;
   if tx.query_opt("SELECT operation FROM operations WHERE namespace=$1 AND replica=$2 AND operation=$3",&[&current.namespace,&current.replica,&req.operation.as_str()]).await?.is_some(){return Err(Error::conflict())}
   if !stale{
    r::ready(&tx,&current,&required,None,&required).await?;
    tx.execute("UPDATE branches SET revision=$3,head=$4 WHERE namespace=$1 AND name=$2",&[&current.namespace,&req.branch.as_str(),&derived_id.as_str(),&receipt.head.as_str()]).await?;
    tx.execute("INSERT INTO changes(namespace,branch,head,paths) VALUES($1,$2,$3,$4)",&[&current.namespace,&req.branch.as_str(),&receipt.head.as_str(),&paths]).await?;
   }
   save_operation(&tx,&current,NewOperation{operation:&req.operation,kind:"integration",request:serialized,result:&result,status:if stale{409}else{200},branch:req.branch.as_str(),view:Some(original.original_view.as_str()),receipt:&receipt.receipt,submitted:&original.revision,derived:&derived_id}).await?;
   tx.commit().await?;Ok((if stale{axum::http::StatusCode::CONFLICT}else{axum::http::StatusCode::OK},[("content-type","application/json")],result).into_response())
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
