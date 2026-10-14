//! Publication inclusion evidence under fresh current authority, with no history grant.
use crate::{revisions as r, views, Error, Result, ServiceState};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use magus_fs_core::{protocol::*, *};
use std::collections::BTreeSet;
fn unsupported(code: &'static str) -> Error {
    Error {
        status: StatusCode::CONFLICT,
        code,
    }
}
const UNAVAILABLE: &str = "continuation_evidence_unavailable";
/// Called only after the successful operation row, in its publication transaction.
pub(crate) async fn record_publication(
    tx: &tokio_postgres::Transaction<'_>,
    namespace: &str,
    receipt: &SharedReceipt,
    published: &RevisionId,
) -> Result<()> {
    tx.execute("INSERT INTO publication_results(namespace,branch,receipt,head,operation,replica,submitted_revision,published_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
      &[&namespace,&receipt.branch.as_str(),&receipt.receipt.as_str(),&receipt.head.as_str(),&receipt.operation.as_str(),&receipt.replica.as_str(),&receipt.submitted_revision.as_str(),&published.as_str()]).await?;
    Ok(())
}
// DFS active set distinguishes cycles from already verified shared parents in a DAG.
struct Ancestry {
    stack: Vec<(RevisionId, bool)>,
    active: BTreeSet<RevisionId>,
    seen: BTreeSet<RevisionId>,
}
impl Ancestry {
    fn new(current: RevisionId) -> Self {
        Self {
            stack: vec![(current, false)],
            active: BTreeSet::new(),
            seen: BTreeSet::new(),
        }
    }
    fn next(&mut self) -> Result<Option<RevisionId>> {
        while let Some((id, exit)) = self.stack.pop() {
            if exit {
                self.active.remove(&id);
                continue;
            }
            if self.active.contains(&id) {
                return Err(unsupported(UNAVAILABLE));
            }
            if self.seen.contains(&id) {
                continue;
            }
            if self.seen.len() == 256 {
                return Err(unsupported("continuation_evidence_limit"));
            }
            self.seen.insert(id.clone());
            self.active.insert(id.clone());
            return Ok(Some(id));
        }
        Ok(None)
    }
    fn parents(&mut self, id: &RevisionId, parents: &[RevisionId]) -> Result<()> {
        if parents.iter().any(|p| self.active.contains(p)) {
            return Err(unsupported(UNAVAILABLE));
        }
        self.stack.push((id.clone(), true));
        self.stack
            .extend(parents.iter().rev().cloned().map(|p| (p, false)));
        Ok(())
    }
}
fn authorize(s: &r::Snapshot) -> Result<Revision> {
    for action in ["read", "write", "integrate"] {
        s.context.action(action)?;
    }
    let full = s.current.as_ref().ok_or(Error::not_found())?;
    let projected = views::project(full, &full.tree, s.authority()?, &s.context.prefixes)?;
    if projected.tree != full.tree || !s.context.permits("write", &s.branch, "") {
        return Err(unsupported("continuation_scope_unsupported"));
    }
    Ok(projected)
}
fn owned_receipt(recorded: &str, requested: &SharedReceipt) -> Result<()> {
    let recorded: SharedReceipt = r::parse(recorded)?;
    if &recorded != requested {
        return Err(Error::not_found());
    }
    Ok(())
}
/// Internal graph evidence only: callers must authenticate and hold the namespace lock.
/// It grants no read authority and returns no descriptors. Run inside Database::run so
/// wire stalls and all traversal/recheck work share the existing two-second DB bound.
pub async fn verify_ancestry(
    tx: &tokio_postgres::Transaction<'_>,
    namespace: &str,
    current: &RevisionId,
    published: &RevisionId,
) -> Result<()> {
    let mut walk = Ancestry::new(current.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(Error::backend());
        }
        let node = walk
            .next()?
            .ok_or(unsupported("continuation_not_descendant"))?;
        let row = tx
            .query_opt(
                "SELECT descriptor FROM revisions WHERE namespace=$1 AND revision=$2",
                &[&namespace, &node.as_str()],
            )
            .await?
            .ok_or(unsupported(UNAVAILABLE))?;
        let raw: Vec<u8> = row.get(0);
        let revision = r::decode(&raw)?;
        if r::rid(&revision)? != node || r::encode(&revision)? != raw {
            return Err(unsupported(UNAVAILABLE));
        }
        tokio::task::yield_now().await;
        if &node == published {
            break;
        }
        walk.parents(&node, &revision.parents)?;
    }
    Ok(())
}
pub(crate) async fn create(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<ContinuationResponseV1>> {
    let c = state.auth(&headers, &ns, "read").await?;
    let request: ContinuationRequestV1 = crate::json_body(body, &headers).await?;
    if request.receipt.replica.as_str() != c.replica {
        return Err(Error::not_found());
    }
    let s = r::snapshot(&state.db, &c, request.receipt.branch.as_str(), None).await?;
    let descriptor = authorize(&s)?;
    let bytes = r::encode(&descriptor)?;
    let id = r::rid(&descriptor)?;
    let current_id = r::rid(s.current.as_ref().ok_or(Error::not_found())?)?;
    let head =
        HeadToken::parse(s.head.clone().ok_or(Error::not_found())?).map_err(views::core_error)?;
    crate::publication::barrier("continuation").await;
    state.db.acquire().await?.run(|db|Box::pin(async move {
        let tx=db.transaction().await?;
        let current=r::recheck(&tx,&s,"read").await?;
        for action in ["write","integrate"] { current.action(action)?; }
        if current.credential!=s.context.credential || current.principal!=s.context.principal || current.replica!=s.context.replica { return Err(Error::not_found()); }
        let receipt=&request.receipt;
        // Ownership is checked before revealing whether a legacy mapping exists.
        let op=tx.query_opt("SELECT result FROM operations WHERE namespace=$1 AND replica=$2 AND operation=$3 AND principal=$4 AND credential=$5 AND receipt=$6 AND branch=$7 AND submitted_revision=$8 AND status=200 AND kind IN ('seed','integration','resolution','restore')",
            &[&ns,&current.replica,&receipt.operation.as_str(),&current.principal,&current.credential,&receipt.receipt.as_str(),&receipt.branch.as_str(),&receipt.submitted_revision.as_str()]).await?.ok_or(Error::not_found())?;
        owned_receipt(&op.get::<_,String>(0),receipt)?;
        let row=tx.query_opt("SELECT published_revision FROM publication_results WHERE namespace=$1 AND branch=$2 AND receipt=$3 AND head=$4 AND operation=$5 AND replica=$6 AND submitted_revision=$7",
            &[&ns,&receipt.branch.as_str(),&receipt.receipt.as_str(),&receipt.head.as_str(),&receipt.operation.as_str(),&current.replica,&receipt.submitted_revision.as_str()]).await?.ok_or(unsupported(UNAVAILABLE))?;
        let published=RevisionId::parse(row.get::<_,String>(0)).map_err(views::core_error)?;
        verify_ancestry(&tx,&ns,&current_id,&published).await?;
        let view=views::issue_current(&tx,&s,&current,&current_id,&head,&id,&bytes).await?;
        let response=ContinuationResponseV1 { proof: ContinuationProofV1 {
            format:CONTINUATION_PROOF_FORMAT.into(),namespace:NamespaceId::parse(ns).map_err(views::core_error)?,request,
            principal:PrincipalId::parse(current.principal).map_err(views::core_error)?,published_revision:published,
            current_revision:current_id, view:ViewBinding {view,head,revision:id.clone()}, descriptor_digest:id,complete_projection:true,
        },descriptor };
        response.validate().map_err(views::core_error)?;
        if r::json(&response)?.len()>MAX_CONTINUATION_RESPONSE { return Err(Error::limit()); }
        tx.commit().await?;Ok(Json(response))
    })).await
}
#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: usize) -> RevisionId {
        RevisionId::parse(format!("sha256:{n:064x}")).unwrap()
    }
    #[test]
    fn proof_ancestry_budget_is_256() {
        let mut walk = Ancestry::new(id(0));
        for n in 0..256 {
            assert_eq!(walk.next().unwrap(), Some(id(n)));
            walk.parents(&id(n), &[id(n + 1)]).unwrap();
        }
        assert_eq!(walk.next().unwrap_err().code, "continuation_evidence_limit");
    }
    #[test]
    fn proof_ancestry_cycles_fail_closed_and_diamonds_are_unique() {
        let mut walk = Ancestry::new(id(0));
        assert_eq!(walk.next().unwrap(), Some(id(0)));
        walk.parents(&id(0), &[id(1)]).unwrap();
        assert_eq!(walk.next().unwrap(), Some(id(1)));
        assert!(walk.parents(&id(1), &[id(0)]).is_err());
        let mut walk = Ancestry::new(id(0));
        assert_eq!(walk.next().unwrap(), Some(id(0)));
        walk.parents(&id(0), &[id(1), id(2)]).unwrap();
        let first = walk.next().unwrap().unwrap();
        walk.parents(&first, &[id(3)]).unwrap();
        assert_eq!(walk.next().unwrap(), Some(id(3)));
        walk.parents(&id(3), &[]).unwrap();
        let second = walk.next().unwrap().unwrap();
        walk.parents(&second, &[id(3)]).unwrap();
        assert_eq!(walk.next().unwrap(), None);
    }
    #[test]
    fn shared_operation_is_not_local_checkpoint_operation() {
        let local = OperationId::random().unwrap();
        let receipt = SharedReceipt {
            receipt: ReceiptId::random().unwrap(),
            operation: OperationId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            submitted_revision: id(44),
            branch: BranchName::parse("main".into()).unwrap(),
            head: HeadToken::random().unwrap(),
        };
        assert_ne!(local, receipt.operation);
        let durable = r::json(&receipt).unwrap();
        owned_receipt(&durable, &receipt).unwrap();
        let mut forged = receipt.clone();
        forged.operation = local;
        assert_eq!(
            owned_receipt(&durable, &forged).unwrap_err().code,
            "not_found"
        );
        forged = receipt.clone();
        forged.submitted_revision = id(45);
        assert!(owned_receipt(&durable, &forged).is_err());
        forged = receipt;
        forged.head = HeadToken::random().unwrap();
        assert!(owned_receipt(&durable, &forged).is_err());
    }
    #[test]
    fn proof_uses_committed_merge_result() {
        let candidate = id(1);
        let published = id(2);
        let current = id(3);
        let mut walk = Ancestry::new(current.clone());
        assert_eq!(walk.next().unwrap(), Some(current.clone()));
        walk.parents(&current, std::slice::from_ref(&published))
            .unwrap();
        assert_eq!(walk.next().unwrap(), Some(published.clone()));
        assert_ne!(published, candidate);
    }
}
