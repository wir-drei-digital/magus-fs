use crate::{Error, Result};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, MutexGuard};
use tokio_postgres::{Client, NoTls};

struct Connection {
    client: Client,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}
/// One bounded connection; transactions serialize through this guard. Backend
/// I/O never holds it. Closed connections reconnect after a PG process restart.
pub struct Database {
    config: String,
    connection: Mutex<Option<Connection>>,
}
pub struct DbGuard<'a>(MutexGuard<'a, Option<Connection>>);
impl std::ops::Deref for DbGuard<'_> {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.0.as_ref().expect("connected").client
    }
}
impl std::ops::DerefMut for DbGuard<'_> {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.0.as_mut().expect("connected").client
    }
}
impl Database {
    pub async fn open(config: String) -> Result<Arc<Self>> {
        let db = Arc::new(Self {
            config,
            connection: Mutex::new(None),
        });
        db.acquire()
            .await?
            .batch_execute(include_str!("../migrations/001_authority.sql"))
            .await?;
        Ok(db)
    }
    pub async fn acquire(&self) -> Result<DbGuard<'_>> {
        let mut guard = tokio::time::timeout(Duration::from_secs(2), self.connection.lock())
            .await
            .map_err(|_| Error::backend())?;
        if guard.as_ref().is_none_or(|c| c.client.is_closed()) {
            let (client, connection) = tokio::time::timeout(
                Duration::from_secs(2),
                tokio_postgres::connect(&self.config, NoTls),
            )
            .await
            .map_err(|_| Error::backend())??;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            *guard = Some(Connection { client, task });
            guard.as_ref().expect("connected").client.batch_execute("SET statement_timeout='2s';SET lock_timeout='2s';SET idle_in_transaction_session_timeout='5s';").await?;
        }
        Ok(DbGuard(guard))
    }
}
pub async fn lock_namespace(tx: &tokio_postgres::Transaction<'_>, namespace: &str) -> Result<()> {
    if tx
        .query_opt(
            "SELECT id FROM namespaces WHERE id=$1 FOR UPDATE",
            &[&namespace],
        )
        .await?
        .is_none()
    {
        return Err(Error::not_found());
    }
    Ok(())
}
