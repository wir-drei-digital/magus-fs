use crate::{Error, Result};
use futures_util::future::BoxFuture;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{Mutex, MutexGuard};
use tokio_postgres::{Client, NoTls};

struct Connection {
    client: Client,
    task: tokio::task::JoinHandle<()>,
    invalid: Arc<AtomicBool>,
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
// Dropping an in-flight operation (including an outer HTTP cancellation) must
// poison and abort its connection before another request can acquire it.
struct PendingOperation {
    invalid: Arc<AtomicBool>,
    abort: tokio::task::AbortHandle,
    completed: bool,
}
impl Drop for PendingOperation {
    fn drop(&mut self) {
        if !self.completed {
            self.invalid.store(true, Ordering::Release);
            self.abort.abort();
        }
    }
}
impl DbGuard<'_> {
    /// Bounds the entire database phase, including transactions and reply waits.
    /// The client cannot escape this borrow or bypass its deadline via Deref.
    pub async fn run<'a, T: 'static>(
        &'a mut self,
        operation: impl FnOnce(&'a mut Client) -> BoxFuture<'a, Result<T>>,
    ) -> Result<T> {
        let connection = self.0.as_mut().expect("initialized connection");
        if connection.invalid.load(Ordering::Acquire) {
            return Err(Error::backend());
        }
        let mut pending = PendingOperation {
            invalid: connection.invalid.clone(),
            abort: connection.task.abort_handle(),
            completed: false,
        };
        match tokio::time::timeout(Duration::from_secs(2), operation(&mut connection.client)).await
        {
            Ok(result) => {
                pending.completed = true;
                result
            }
            Err(_) => Err(Error::backend()),
        }
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
            .run(|client| {
                Box::pin(async move {
                    client
                        .batch_execute(
                            &[
                                include_str!("../migrations/001_authority.sql"),
                                include_str!("../migrations/002_revisions.sql"),
                                include_str!("../migrations/003_view_reuse.sql"),
                                include_str!("../migrations/004_collaboration.sql"),
                                include_str!("../migrations/005_recovery.sql"),
                                include_str!("../migrations/006_dependencies.sql"),
                            ]
                            .concat(),
                        )
                        .await?;
                    Ok(())
                })
            })
            .await?;
        Ok(db)
    }
    pub async fn acquire(&self) -> Result<DbGuard<'_>> {
        tokio::time::timeout(Duration::from_secs(2), async {
        let mut guard = self.connection.lock().await;
        if guard
            .as_ref()
            .is_none_or(|c| c.client.is_closed() || c.invalid.load(Ordering::Acquire))
        {
            // Remove an invalid predecessor before attempting a replacement.
            guard.take();
            let (client, connection) = tokio_postgres::connect(&self.config, NoTls).await?;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            let candidate = Connection {
                client,
                task,
                invalid: Arc::new(AtomicBool::new(false)),
            };
            candidate.client.batch_execute("SET statement_timeout='2s';SET lock_timeout='2s';SET idle_in_transaction_session_timeout='5s';").await?;
            // Failed/cancelled initialization drops and aborts the candidate.
            *guard = Some(candidate);
        }
        Ok(DbGuard(guard))
        }).await.map_err(|_| Error::backend())?
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
