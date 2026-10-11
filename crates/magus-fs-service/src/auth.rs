use crate::{db::lock_namespace, Error, Result};
use magus_fs_core::{
    protocol::{BranchName, NamespaceId},
    PrincipalId, ReplicaId,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[derive(Clone)]
pub struct AuthContext {
    pub(crate) credential: String,
    pub(crate) namespace: String,
    pub(crate) principal: String,
    pub(crate) replica: String,
    pub(crate) generation: i64,
    pub(crate) token_hash: String,
    pub(crate) actions: Vec<String>,
    pub(crate) branches: Vec<String>,
    pub(crate) prefixes: Vec<String>,
    pub(crate) depth: usize,
}
impl AuthContext {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn replica(&self) -> &str {
        &self.replica
    }
    pub fn credential(&self) -> &str {
        &self.credential
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
    pub fn permits(&self, action: &str, branch: &str, path: &str) -> bool {
        self.actions.iter().any(|a| a == action)
            && self.branches.iter().any(|b| b == branch)
            && self.prefixes.iter().any(|p| within(path, p))
    }
    pub(crate) fn action(&self, action: &str) -> Result<()> {
        if self.actions.iter().any(|a| a == action) {
            Ok(())
        } else {
            Err(Error::not_found())
        }
    }
}
impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthContext([redacted])")
    }
}
pub fn within(path: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with('/'))
}

pub async fn authenticate<C: GenericClient + Sync>(
    db: &C,
    hash: &str,
    namespace: &str,
) -> Result<AuthContext> {
    let row=db.query_opt("SELECT c.*, g.actions,g.branches,g.prefixes FROM credentials c JOIN grants g ON g.credential=c.id WHERE token_hash=$1 AND NOT revoked AND expires>clock_timestamp()",&[&hash]).await?.ok_or(Error::unauthorized())?;
    let mut parent: Option<String> = row.get("parent");
    let mut generation: Option<i64> = row.get("parent_generation");
    let mut ancestors = 0;
    for depth in 0..=8 {
        let Some(id) = parent else { break };
        if depth == 8 {
            return Err(Error::unauthorized());
        }
        ancestors += 1;
        let p=db.query_opt("SELECT generation,parent,parent_generation FROM credentials WHERE id=$1 AND NOT revoked AND expires>clock_timestamp()",&[&id]).await?.ok_or(Error::unauthorized())?;
        if generation != Some(p.get("generation")) {
            return Err(Error::unauthorized());
        }
        parent = p.get("parent");
        generation = p.get("parent_generation");
    }
    let context = AuthContext {
        credential: row.get("id"),
        namespace: row.get("namespace"),
        principal: row.get("principal"),
        replica: row.get("replica"),
        generation: row.get("generation"),
        token_hash: hash.into(),
        actions: row.get("actions"),
        branches: row.get("branches"),
        prefixes: row.get("prefixes"),
        depth: ancestors,
    };
    if context.namespace != namespace {
        return Err(Error::not_found());
    }
    Ok(context)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provision {
    pub authority: Option<crate::policy::AuthorityConfig>,
    pub root_policy: Option<crate::policy::RootPolicy>,
    /// Optional trusted branch merge policy (FS2-B); absent means opaque.
    #[serde(default)]
    pub merge_policy: Option<crate::policy::BranchMergePolicy>,
    pub namespace: NamespaceId,
    pub principal: PrincipalId,
    pub replica: ReplicaId,
    pub token: String,
    pub expires: i64,
    pub actions: Vec<String>,
    pub branches: Vec<String>,
    pub prefixes: Vec<String>,
}
impl Provision {
    pub fn validate(&self) -> Result<()> {
        crate::policy::validate(self)?;
        if self.token.len() != 64
            || !self
                .token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.actions.is_empty()
            || self.actions.len() > 6
            || self.branches.is_empty()
            || self.branches.len() > 64
            || self.prefixes.is_empty()
            || self.prefixes.len() > 64
        {
            return Err(Error::invalid("invalid_grant"));
        }
        if self.actions.iter().any(|a| {
            !matches!(
                a.as_str(),
                "read" | "write" | "history" | "integrate" | "admin" | "retained_history"
            )
        }) || self
            .branches
            .iter()
            .any(|b| BranchName::parse(b.clone()).is_err())
            || self.prefixes.iter().any(|p| {
                p.len() > 4096
                    || (!p.is_empty()
                        && p.split('/')
                            .any(|c| c.is_empty() || c == "." || c == ".." || c.contains('\0')))
            })
        {
            return Err(Error::invalid("invalid_grant"));
        }
        Ok(())
    }
}

pub async fn provision(db: &crate::db::Database, records: Vec<Provision>) -> Result<()> {
    if records.is_empty() || records.len() > 64 {
        return Err(Error::invalid("invalid_grant"));
    }
    for record in &records {
        record.validate()?;
    }
    let mut connection = db.acquire().await?;
    connection
        .run(|connection| {
            Box::pin(async move {
                let tx = connection.transaction().await?;
                for r in records {
                    let ns = r.namespace.as_str();
                    tx.execute(
                        "INSERT INTO namespaces(id) VALUES($1) ON CONFLICT DO NOTHING",
                        &[&ns],
                    )
                    .await?;
                    lock_namespace(&tx, ns).await?;
                    tx.execute(
                        "INSERT INTO principals(namespace,id) VALUES($1,$2) ON CONFLICT DO NOTHING",
                        &[&ns, &r.principal.as_str()],
                    )
                    .await?;
                    crate::policy::install(&tx, &r).await?;
                    insert_credential(&tx, &r, None).await?;
                }
                tx.commit().await?;
                Ok(())
            })
        })
        .await
}
pub async fn insert_credential(
    tx: &tokio_postgres::Transaction<'_>,
    r: &Provision,
    parent: Option<&AuthContext>,
) -> Result<String> {
    if let Some(parent) = parent {
        check_child_depth(parent.depth)?;
    }
    let id = NamespaceId::random()
        .map_err(|_| Error::backend())?
        .as_str()
        .to_owned();
    let ns = r.namespace.as_str();
    let principal = r.principal.as_str();
    let replica = r.replica.as_str();
    tx.execute(
        "INSERT INTO replicas(namespace,id,principal) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
        &[&ns, &replica, &principal],
    )
    .await?;
    let owner: String = tx
        .query_one(
            "SELECT principal FROM replicas WHERE namespace=$1 AND id=$2",
            &[&ns, &replica],
        )
        .await?
        .get(0);
    if owner != principal {
        return Err(Error::not_found());
    }
    let parent_id = parent.map(|p| p.credential.as_str());
    let parent_generation = parent.map(|p| p.generation);
    tx.execute("INSERT INTO credentials(id,token_hash,namespace,principal,replica,expires,parent,parent_generation) VALUES($1,$2,$3,$4,$5,to_timestamp($6::bigint),$7,$8)",&[&id,&digest(r.token.as_bytes()),&ns,&principal,&replica,&r.expires,&parent_id,&parent_generation]).await?;
    tx.execute(
        "INSERT INTO grants(credential,actions,branches,prefixes) VALUES($1,$2,$3,$4)",
        &[&id, &r.actions, &r.branches, &r.prefixes],
    )
    .await?;
    Ok(id)
}

pub fn check_child_depth(parent_depth: usize) -> Result<()> {
    if parent_depth >= 8 {
        Err(Error::invalid("delegation_depth"))
    } else {
        Ok(())
    }
}
