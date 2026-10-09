//! Short DB snapshots and serialized commits; descriptor work runs between phases.
use crate::{
    auth::{self, AuthContext},
    db,
    policy::{AuthorityConfig, RootPolicy},
    views::core_error,
    Error, Result,
};
use magus_fs_core::{protocol::*, *};
use std::collections::BTreeMap;
use tokio_postgres::Transaction;
pub(crate) fn decode(bytes: &[u8]) -> Result<Revision> {
    decode_revision(bytes).map_err(core_error)
}
pub(crate) fn encode(r: &Revision) -> Result<Vec<u8>> {
    encode_revision(r).map_err(core_error)
}
pub(crate) fn rid(r: &Revision) -> Result<RevisionId> {
    revision_id(r).map_err(core_error)
}
pub(crate) fn json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|_| Error::invalid("invalid_request"))
}
pub(crate) fn parse<T: serde::de::DeserializeOwned>(v: &str) -> Result<T> {
    serde_json::from_str(v).map_err(|_| Error::backend())
}
pub(crate) fn objects(r: &Revision) -> Result<BTreeMap<String, i64>> {
    let mut result = BTreeMap::new();
    for e in &r.tree.entries {
        if let EntryContent::File { version } = &e.content {
            for extent in &version.extents {
                if let Extent::Chunk {
                    object,
                    object_size,
                    ..
                } = extent
                {
                    if result
                        .insert(object.as_str().into(), *object_size as i64)
                        .is_some_and(|n| n != *object_size as i64)
                    {
                        return Err(Error::invalid("invalid_descriptor"));
                    }
                }
            }
        }
    }
    if result.values().sum::<i64>() > MAX_SESSION_BYTES {
        return Err(Error::limit());
    }
    Ok(result)
}
pub(crate) struct BoundView {
    pub full: Revision,
    pub projected: Revision,
    pub head: String,
}
pub(crate) struct Snapshot {
    pub context: AuthContext,
    pub branch: String,
    pub authorities: Vec<Authority>,
    pub root: Root,
    pub current: Option<Revision>,
    pub head: Option<String>,
    pub view: Option<BoundView>,
}
impl Snapshot {
    pub fn authority(&self) -> Result<&Authority> {
        self.authorities
            .iter()
            .find(|a| a.principal.as_str() == self.context.principal)
            .ok_or(Error::not_found())
    }
    pub fn scope(&self) -> TransitionScope {
        TransitionScope {
            read_prefixes: if self.context.actions.iter().any(|a| a == "read") {
                self.context.prefixes.clone()
            } else {
                vec![]
            },
            write_prefixes: self.context.prefixes.clone(),
            read_only: !self.context.actions.iter().any(|a| a == "write"),
        }
    }
    pub fn validate_view(&self) -> Result<&BoundView> {
        self.context.action("read")?;
        let view = self.view.as_ref().ok_or(Error::not_found())?;
        if self.head.as_deref() != Some(&view.head) {
            self.context.action("history")?;
        }
        let current = self.current.as_ref().ok_or(Error::not_found())?;
        let projection = crate::views::project(
            &view.projected,
            &current.tree,
            self.authority()?,
            &self.context.prefixes,
        )?;
        if projection.tree != view.projected.tree {
            return Err(Error::not_found());
        }
        Ok(view)
    }
}
pub(crate) async fn snapshot(
    database: &db::Database,
    c: &AuthContext,
    branch: &str,
    view: Option<&str>,
) -> Result<Snapshot> {
    let mut guard = database.acquire().await?;
    let (context,authorities,root,current,head,bound)=guard.run(|db|Box::pin(async move {
  let tx=db.transaction().await?;db::lock_namespace(&tx,&c.namespace).await?;let context=auth::authenticate(&tx,&c.token_hash,&c.namespace).await?;
  if !context.branches.iter().any(|b|b==branch){return Err(Error::not_found())}
  let authorities=tx.query("SELECT authority FROM principal_authorities WHERE namespace=$1 ORDER BY principal",&[&c.namespace]).await?.iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>();
  let root=tx.query_opt("SELECT root_policy FROM namespace_policy WHERE namespace=$1",&[&c.namespace]).await?.ok_or(Error::not_found())?.get::<_,String>(0);
  let b=tx.query_opt("SELECT r.descriptor,b.head FROM branches b JOIN revisions r ON r.namespace=b.namespace AND r.revision=b.revision WHERE b.namespace=$1 AND b.name=$2",&[&c.namespace,&branch]).await?;
  let current=b.as_ref().map(|r|r.get::<_,Vec<u8>>(0));let head=b.as_ref().map(|r|r.get::<_,String>(1));
  let bound=if let Some(view)=view {let r=tx.query_opt("SELECT v.descriptor,r.descriptor,v.head FROM views v JOIN revisions r ON r.namespace=v.namespace AND r.revision=v.full_revision WHERE v.id=$1 AND v.namespace=$2 AND v.branch=$3 AND v.credential=$4 AND v.principal=$5 AND v.replica=$6",&[&view,&c.namespace,&branch,&context.credential,&context.principal,&context.replica]).await?.ok_or(Error::not_found())?;Some((view.to_owned(),r.get::<_,Vec<u8>>(0),r.get::<_,Vec<u8>>(1),r.get::<_,String>(2)))}else{None};
  tx.commit().await?;Ok((context,authorities,root,current,head,bound))
 })).await?;
    let authorities = authorities
        .iter()
        .map(|s| parse::<AuthorityConfig>(s).map(|a| a.logical()))
        .collect::<Result<Vec<_>>>()?;
    Ok(Snapshot {
        context,
        branch: branch.into(),
        authorities,
        root: parse::<RootPolicy>(&root)?.root(),
        current: current.map(|b| decode(&b)).transpose()?,
        head,
        view: bound
            .map(|(_id, p, f, head)| {
                Ok::<BoundView, Error>(BoundView {
                    projected: decode(&p)?,
                    full: decode(&f)?,
                    head,
                })
            })
            .transpose()?,
    })
}
pub(crate) async fn recheck(
    tx: &Transaction<'_>,
    s: &Snapshot,
    action: &str,
) -> Result<AuthContext> {
    db::lock_namespace(tx, &s.context.namespace).await?;
    let c = auth::authenticate(tx, &s.context.token_hash, &s.context.namespace).await?;
    c.action(action)?;
    if c.generation != s.context.generation
        || c.actions != s.context.actions
        || c.branches != s.context.branches
        || c.prefixes != s.context.prefixes
    {
        return Err(Error::not_found());
    }
    let head = tx
        .query_opt(
            "SELECT head FROM branches WHERE namespace=$1 AND name=$2",
            &[&c.namespace, &s.branch],
        )
        .await?
        .map(|r| r.get::<_, String>(0));
    if head != s.head {
        return Err(Error::conflict());
    }
    Ok(c)
}
pub(crate) async fn ready(
    tx: &Transaction<'_>,
    c: &AuthContext,
    required: &BTreeMap<String, i64>,
    upload: Option<&UploadId>,
    reusable: &BTreeMap<String, i64>,
) -> Result<BTreeMap<String, String>> {
    let ids = required.keys().cloned().collect::<Vec<_>>();
    let rows=tx.query("SELECT object_id,generation,size,state FROM objects WHERE namespace=$1 AND object_id=ANY($2) ORDER BY object_id FOR UPDATE",&[&c.namespace,&ids]).await?;
    if rows.len() != required.len() {
        return Err(Error::not_found());
    }
    let owned = if let Some(upload) = upload {
        crate::storage::check_session(tx, c, upload).await?;
        tx.query(
            "SELECT object_id,generation FROM session_objects WHERE upload=$1 AND completed",
            &[&upload.as_str()],
        )
        .await?
        .iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
        .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    let mut generations = BTreeMap::new();
    for r in rows {
        let id = r.get::<_, String>(0);
        let generation = r.get::<_, String>(1);
        let size = r.get::<_, i64>(2);
        if r.get::<_, &str>(3) != "ready"
            || required.get(&id) != Some(&size)
            || (reusable.get(&id) != Some(&size) && owned.get(&id) != Some(&generation))
        {
            return Err(Error::not_found());
        }
        generations.insert(id, generation);
    }
    Ok(generations)
}
pub(crate) async fn save_revision(
    tx: &Transaction<'_>,
    ns: &str,
    id: &RevisionId,
    bytes: &[u8],
    generations: &BTreeMap<String, String>,
) -> Result<()> {
    tx.execute("INSERT INTO revisions(namespace,revision,descriptor) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",&[&ns,&id.as_str(),&bytes]).await?;
    // One bounded SQL phase, not a round trip per object.
    let ids = generations.keys().cloned().collect::<Vec<_>>();
    let values = generations.values().cloned().collect::<Vec<_>>();
    tx.execute("INSERT INTO revision_objects(namespace,revision,object_id,generation) SELECT $1,$2,unnest($3::text[]),unnest($4::text[]) ON CONFLICT DO NOTHING",&[&ns,&id.as_str(),&ids,&values]).await?;
    Ok(())
}
pub(crate) async fn branch_for_view(
    database: &db::Database,
    c: &AuthContext,
    view: &str,
) -> Result<String> {
    database.acquire().await?.run(|db|Box::pin(async move {db.query_opt("SELECT branch FROM views WHERE id=$1 AND namespace=$2 AND credential=$3 AND principal=$4 AND replica=$5",&[&view,&c.namespace,&c.credential,&c.principal,&c.replica]).await?.map(|r|r.get(0)).ok_or(Error::not_found())})).await
}
pub(crate) async fn final_read(database: &db::Database, s: &Snapshot) -> Result<()> {
    database
        .acquire()
        .await?
        .run(|db| {
            Box::pin(async move {
                let tx = db.transaction().await?;
                recheck(&tx, s, "read").await?;
                tx.commit().await?;
                Ok(())
            })
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issued_view_requires_current_read_action_even_for_noop() {
        let principal = PrincipalId::parse(format!("principal:{:032x}", 1)).unwrap();
        let group = GroupId::parse(format!("group:{:032x}", 1)).unwrap();
        let replica = ReplicaId::random().unwrap();
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o700,
        };
        let revision = Revision {
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
                entries: vec![],
            },
        };
        let context = AuthContext {
            credential: "fixture".into(),
            namespace: "fixture".into(),
            principal: principal.as_str().into(),
            replica: replica.as_str().into(),
            generation: 1,
            token_hash: String::new(),
            actions: vec!["write".into()],
            branches: vec!["main".into()],
            prefixes: vec!["".into()],
            depth: 0,
        };
        let snapshot = Snapshot {
            context,
            branch: "main".into(),
            authorities: vec![Authority {
                principal,
                uid: 1001,
                gid: 1001,
                primary_group: group.clone(),
                groups: vec![group],
                dac_override: false,
                ownership_transfer: false,
            }],
            root,
            current: Some(revision.clone()),
            head: Some("head".into()),
            view: Some(BoundView {
                full: revision.clone(),
                projected: revision,
                head: "head".into(),
            }),
        };
        match snapshot.validate_view() {
            Err(error) => assert_eq!(error.code, "not_found"),
            Ok(_) => panic!("revoked read grant still authorized the issued base"),
        }
    }
}
