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
/// Outcome decided outside the commit transaction; the commit rechecks head and rights.
enum Decision {
    Stale,
    Publish {
        revision: Box<Revision>,
        provenance: Option<String>,
    },
    Conflicted(crate::conflicts::Retain),
}
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
/// Integrates the original private candidate against the current destination with
/// expected-head CAS: fast-forward when its base is the head, otherwise a three-way merge
/// against its recorded full base whose candidate and destination become the parents.
/// Unknown causality and unresolved conflicts retain immutable records instead.
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
        let original: submission::CandidateRequest = r::parse(&candidate.request)?;
        let view = s.view.as_ref().ok_or(Error::not_found())?;
        let current = s.current.as_ref().ok_or(Error::not_found())?;
        let derived_id = r::rid(derived)?;
        let current_id = r::rid(current)?;
        let base_id = r::rid(&view.full)?;
        let receipt = SharedReceipt {
            receipt: ReceiptId::random().map_err(core_error)?,
            operation: req.operation.clone(),
            replica: req.replica.clone(),
            submitted_revision: original.revision.clone(),
            branch: req.branch.clone(),
            head: HeadToken::random().map_err(core_error)?,
        };
        let mut generated = vec![];
        let decision = if s.head.as_deref() != Some(req.expected_head.as_str()) {
            Decision::Stale
        } else if crate::conflicts::unknown_causality(&state, &c, &req.candidate_receipt, derived)
            .await?
        {
            // Rulings R1/R6/R10: never fast-forwarded, rebased or merged automatically.
            s.context.action("read")?;
            Decision::Conflicted(crate::conflicts::Retain::Whole(
                ConflictReason::UnknownCausality,
            ))
        } else if view.head == req.expected_head.as_str()
            && derived.parents == vec![base_id.clone()]
        {
            submission::authorize_candidate(&s, derived)?;
            Decision::Publish {
                revision: Box::new(derived.clone()),
                provenance: None,
            }
        } else {
            // A stale recorded base is historical input: it needs the history action.
            s.context.action("read")?;
            s.context.action("history")?;
            let policy = state
                .db
                .acquire()
                .await?
                .run(|db| {
                    let c = &c;
                    let req = &req;
                    Box::pin(async move {
                        crate::policy::merge_policy(&*db, &c.namespace, req.branch.as_str()).await
                    })
                })
                .await?;
            match crate::reconciliation::reconcile(
                &state,
                &ns,
                &view.full.tree,
                &current.tree,
                &derived.tree,
                &policy,
            )
            .await?
            {
                crate::reconciliation::Planned::Clean {
                    tree,
                    generated: objects,
                    mechanically_merged,
                } => {
                    let merged = Revision {
                        format: FORMAT.into(),
                        hash: HASH.into(),
                        layout: LAYOUT.into(),
                        parents: vec![current_id.clone(), derived_id.clone()],
                        operation: req.operation.clone(),
                        replica: req.replica.clone(),
                        principal: PrincipalId::parse(c.principal.clone()).map_err(core_error)?,
                        captured_at_ns: now_ns(),
                        coverage: vec!["".into()],
                        provenance: "explicit".into(),
                        restoration: None,
                        tree,
                    };
                    // The complete resulting delta under current rights and view scope.
                    authorize_tree_transition(
                        &current.tree,
                        &merged.tree,
                        s.authority()?,
                        &s.authorities,
                        &s.scope(),
                    )
                    .map_err(core_error)?;
                    generated = objects;
                    let provenance = r::json(&serde_json::json!({
                        "kind":"merge","operation":req.operation,"receipt":req.candidate_receipt,
                        "submitted":original.revision,"original_view":original.original_view,
                        "base":base_id,"candidate":derived_id,"current":current_id,
                        "mechanically_merged":mechanically_merged,
                    }))?;
                    Decision::Publish {
                        revision: Box::new(merged),
                        provenance: Some(provenance),
                    }
                }
                crate::reconciliation::Planned::Conflicted(alternatives) => {
                    crate::reconciliation::conflicts_visible(&s, view, current, &alternatives)?;
                    Decision::Conflicted(crate::conflicts::Retain::Entries(alternatives))
                }
            }
        };
        // Generated objects are verified and ready before the single metadata commit.
        for (id, bytes) in generated {
            state
                .objects
                .install_generated(&ns, &id, bytes.into())
                .await?;
        }
        let published = match &decision {
            Decision::Stale | Decision::Conflicted(_) => None,
            Decision::Publish { revision, .. } => {
                let id = r::rid(revision)?;
                let bytes = r::encode(revision)?;
                let required = r::objects(revision)?;
                let paths = crate::reconciliation::changed_paths(&current.tree, &revision.tree);
                Some((id, bytes, required, paths))
            }
        };
        let root = current.tree.root.id.clone();
        barrier("integration").await;
        let commit=state.db.acquire().await?.run(|db|{let req=&req;let serialized=&serialized;let s=&s;let receipt=&receipt;let original=&original;let decision=&decision;let published=&published;let derived_id=&derived_id;let current_id=&current_id;let base_id=&base_id;let root=&root;Box::pin(async move {
   let tx=db.transaction().await?;let current=r::recheck(&tx,s,"integrate").await?;
   if tx.query_opt("SELECT operation FROM operations WHERE namespace=$1 AND replica=$2 AND operation=$3",&[&current.namespace,&current.replica,&req.operation.as_str()]).await?.is_some(){return Err(Error::conflict())}
   let mut result = match decision {
    Decision::Stale => "{\"code\":\"stale_head\"}".to_owned(),
    _ => r::json(receipt)?,
   };
   if let (Decision::Publish{provenance,..},Some((id,bytes,required,paths)))=(decision,published){
    let generations=r::ready(&tx,&current,required,None,required).await?;
    if id != derived_id { r::save_revision(&tx,&current.namespace,id,bytes,&generations).await?; }
    tx.execute("UPDATE branches SET revision=$3,head=$4 WHERE namespace=$1 AND name=$2",&[&current.namespace,&req.branch.as_str(),&id.as_str(),&receipt.head.as_str()]).await?;
    tx.execute("INSERT INTO changes(namespace,branch,head,paths) VALUES($1,$2,$3,$4)",&[&current.namespace,&req.branch.as_str(),&receipt.head.as_str(),paths]).await?;
    if let Some(p)=provenance { tx.execute("INSERT INTO revision_provenance(namespace,revision,kind,operation,payload,digest) VALUES($1,$2,'merge',$3,$4,$5)",&[&current.namespace,&id.as_str(),&req.operation.as_str(),p,&auth::digest(p.as_bytes())]).await?; }
   }
   // The operation row precedes conflict rows that reference it.
   let conflicted = matches!(decision, Decision::Conflicted(_));
   if conflicted { result = "{}".into(); }
   save_operation(&tx,&current,NewOperation{operation:&req.operation,kind:"integration",request:serialized,result:&result,status:if matches!(decision,Decision::Publish{..}){200}else{409},branch:req.branch.as_str(),view:Some(original.original_view.as_str()),receipt:&receipt.receipt,submitted:&original.revision,derived:derived_id}).await?;
   if let Decision::Conflicted(retain)=decision {
    let x=crate::conflicts::Retained{branch:req.branch.as_str(),receipt:&req.candidate_receipt,integration:&req.operation,root,base:base_id,candidate:derived_id,current:current_id,original_head:original.original_head.as_str(),current_head:s.head.as_deref().unwrap_or_default()};
    let ids=crate::conflicts::record(&tx,&current,&x,retain.clone()).await?;
    result=r::json(&ConflictedIntegration{code:CONFLICTED.into(),conflicts:ids})?;
    tx.execute("UPDATE operations SET result=$4 WHERE namespace=$1 AND replica=$2 AND operation=$3",&[&current.namespace,&current.replica,&req.operation.as_str(),&result]).await?;
   }
   tx.commit().await?;Ok((axum::http::StatusCode::from_u16(if matches!(decision,Decision::Publish{..}){200}else{409}).map_err(|_|Error::backend())?,[("content-type","application/json")],result).into_response())
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
