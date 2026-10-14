//! Conservative PoC retention: every committed revision closure is a root. Expired
//! partial uploads and never-referenced generated generations are reclaimable. There
//! is deliberately no pruning of acknowledged operations, publication_results, or
//! published history. Migration007 foreign keys retain the producing operation and
//! actual published descriptor; revision_objects closures stay protected by ELIGIBLE.
//! submitted_revision is the immutable receipt digest, not a historical read grant.
use crate::{db, publication::barrier, Error, Result, ServiceState};
use magus_fs_core::protocol::NamespaceId;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    pub object: String,
    pub generation: String,
    pub key: String,
}
#[derive(Serialize)]
pub struct Plan {
    pub plan: String,
    pub objects: Vec<Generation>,
}
#[derive(Serialize)]
pub struct Collected {
    pub deleted: Vec<String>,
}
const ELIGIBLE: &str = "o.lease_until<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM revision_objects r WHERE r.namespace=o.namespace AND r.object_id=o.object_id AND r.generation=o.generation) AND NOT EXISTS(SELECT 1 FROM session_objects s JOIN upload_sessions u ON u.id=s.upload WHERE s.namespace=o.namespace AND s.object_id=o.object_id AND s.generation=o.generation AND u.expires>clock_timestamp())";
pub async fn dry_run(state: &ServiceState, namespace: &NamespaceId) -> Result<Plan> {
    state.db.acquire().await?.run(|db|Box::pin(async move {
        let tx=db.transaction().await?;db::lock_namespace(&tx,namespace.as_str()).await?;
        let query=format!("SELECT object_id,generation,storage_key FROM objects o WHERE namespace=$1 AND ({ELIGIBLE}) ORDER BY object_id FOR UPDATE");
        let objects=tx.query(&query,&[&namespace.as_str()]).await?.iter().map(|r|Generation{object:r.get(0),generation:r.get(1),key:r.get(2)}).collect::<Vec<_>>();
        let token=NamespaceId::random().map_err(|_|Error::backend())?.as_str().to_owned();let payload=serde_json::to_string(&objects).map_err(|_|Error::backend())?;
        tx.execute("INSERT INTO gc_plans(token,namespace,payload) VALUES($1,$2,$3)",&[&token,&namespace.as_str(),&payload]).await?;tx.commit().await?;Ok(Plan{plan:token,objects})
    })).await
}
pub async fn execute(
    state: &ServiceState,
    namespace: &NamespaceId,
    token: &str,
) -> Result<Collected> {
    NamespaceId::parse(token).map_err(|_| Error::not_found())?;
    let objects=state.db.acquire().await?.run(|db|Box::pin(async move {
        let tx=db.transaction().await?;db::lock_namespace(&tx,namespace.as_str()).await?;
        let row=tx.query_opt("SELECT payload FROM gc_plans WHERE token=$1 AND namespace=$2",&[&token,&namespace.as_str()]).await?.ok_or(Error::not_found())?;
        let planned:Vec<Generation>=serde_json::from_str(&row.get::<_,String>(0)).map_err(|_|Error::backend())?;let mut objects=vec![];
        for g in planned {
            let query=format!("SELECT storage_key FROM objects o WHERE namespace=$1 AND object_id=$2 AND generation=$3 AND storage_key=$4 AND ({ELIGIBLE}) FOR UPDATE");
            if tx.query_opt(&query,&[&namespace.as_str(),&g.object,&g.generation,&g.key]).await?.is_some(){
                tx.execute("UPDATE objects SET state='deleting' WHERE namespace=$1 AND object_id=$2 AND generation=$3",&[&namespace.as_str(),&g.object,&g.generation]).await?;objects.push(g);
            }
        }
        tx.commit().await?;Ok(objects)
    })).await?;
    // Mark commit forbids publication/install referencing this generation while I/O runs.
    // A crash leaves the same plan and generation re-executable; delete is idempotent.
    barrier("gc").await;
    let mut deleted = vec![];
    for g in objects {
        state.objects.delete_generation(&g.key).await?;
        state.db.acquire().await?.run(|db|{let g=&g;Box::pin(async move {
            let tx=db.transaction().await?;db::lock_namespace(&tx,namespace.as_str()).await?;
            let query=format!("SELECT object_id FROM objects o WHERE namespace=$1 AND object_id=$2 AND generation=$3 AND state='deleting' AND ({ELIGIBLE}) FOR UPDATE");
            if tx.query_opt(&query,&[&namespace.as_str(),&g.object,&g.generation]).await?.is_none(){return Err(Error::conflict());}
            tx.execute("DELETE FROM session_objects WHERE namespace=$1 AND object_id=$2 AND generation=$3",&[&namespace.as_str(),&g.object,&g.generation]).await?;
            tx.execute("DELETE FROM objects WHERE namespace=$1 AND object_id=$2 AND generation=$3 AND state='deleting'",&[&namespace.as_str(),&g.object,&g.generation]).await?;tx.commit().await?;Ok(())
        })}).await?;
        deleted.push(g.object);
    }
    Ok(Collected { deleted })
}
