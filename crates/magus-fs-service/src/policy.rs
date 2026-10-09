use crate::{auth::Provision, Error, Result};
use magus_fs_core::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    pub principal: PrincipalId,
    pub uid: u32,
    pub primary_group: GroupId,
    pub gid: u32,
    pub groups: Vec<GroupId>,
    pub dac_override: bool,
    pub ownership_transfer: bool,
}
impl AuthorityConfig {
    pub fn logical(&self) -> Authority {
        Authority {
            principal: self.principal.clone(),
            uid: self.uid,
            primary_group: self.primary_group.clone(),
            gid: self.gid,
            groups: self.groups.clone(),
            dac_override: self.dac_override,
            ownership_transfer: self.ownership_transfer,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicy {
    pub id: EntryId,
    pub owner: PrincipalId,
    pub group: GroupId,
    pub mode: u16,
}
impl RootPolicy {
    pub fn root(&self) -> Root {
        Root {
            id: self.id.clone(),
            owner: self.owner.clone(),
            group: self.group.clone(),
            mode: self.mode,
        }
    }
}
pub fn validate(r: &Provision) -> Result<()> {
    if let Some(a) = &r.authority {
        if a.principal != r.principal
            || a.groups.is_empty()
            || a.groups.len() > 64
            || !a.groups.contains(&a.primary_group)
            || a.groups
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != a.groups.len()
        {
            return Err(Error::invalid("invalid_policy"));
        }
    }
    if let Some(root) = &r.root_policy {
        if root.owner != r.principal
            || root.mode & !0o777 != 0
            || r.authority
                .as_ref()
                .is_none_or(|a| !a.groups.contains(&root.group))
        {
            return Err(Error::invalid("invalid_policy"));
        }
    }
    Ok(())
}
pub async fn install(tx: &tokio_postgres::Transaction<'_>, r: &Provision) -> Result<()> {
    let ns = r.namespace.as_str();
    if let Some(a) = &r.authority {
        let value = serde_json::to_string(a).map_err(|_| Error::invalid("invalid_policy"))?;
        let previous = tx
            .query_opt(
                "SELECT authority FROM principal_authorities WHERE namespace=$1 AND principal=$2",
                &[&ns, &r.principal.as_str()],
            )
            .await?;
        if previous.is_some_and(|p| p.get::<_, String>(0) != value) {
            return Err(Error::invalid("policy_conflict"));
        }
        tx.execute("INSERT INTO principal_authorities(namespace,principal,authority) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",&[&ns,&r.principal.as_str(),&value]).await?;
        for group in &a.groups {
            tx.execute(
                "INSERT INTO groups(namespace,id) VALUES($1,$2) ON CONFLICT DO NOTHING",
                &[&ns, &group.as_str()],
            )
            .await?;
            tx.execute("INSERT INTO group_members(namespace,group_id,principal) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",&[&ns,&group.as_str(),&r.principal.as_str()]).await?;
        }
    }
    if let Some(root) = &r.root_policy {
        let value = serde_json::to_string(root).map_err(|_| Error::invalid("invalid_policy"))?;
        let previous = tx
            .query_opt(
                "SELECT root_policy FROM namespace_policy WHERE namespace=$1",
                &[&ns],
            )
            .await?;
        if previous.is_some_and(|p| p.get::<_, String>(0) != value) {
            return Err(Error::invalid("policy_conflict"));
        }
        tx.execute("INSERT INTO namespace_policy(namespace,root_policy) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&ns,&value]).await?;
    }
    Ok(())
}
