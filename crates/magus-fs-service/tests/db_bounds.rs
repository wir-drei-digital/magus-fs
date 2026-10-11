//! Wire-level fault injection keeps the real service DB boundary and PG driver.
//! Peers complete authentication, then withhold a selected query response.
use magus_fs_core::{protocol::NamespaceId, PrincipalId, ReplicaId};
use magus_fs_service::{auth, db::Database, Result};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
    time::timeout,
};

const INIT: &str = "SET statement_timeout=";
const MIGRATION: &str = "CREATE TABLE";
const LIMIT: Duration = Duration::from_secs(3);

enum Step {
    Reply(&'static str),
    Stall(&'static str),
}
struct Peer {
    config: String,
    task: JoinHandle<()>,
    stalled: Arc<Notify>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
async fn peer_connection(mut socket: TcpStream, steps: Vec<Step>, stalled: &Notify) {
    let length = socket.read_u32().await.unwrap();
    let mut startup = vec![0; length as usize - 4];
    socket.read_exact(&mut startup).await.unwrap();
    socket
        .write_all(&frame(b'R', &0u32.to_be_bytes()))
        .await
        .unwrap();
    socket.write_all(&frame(b'Z', b"I")).await.unwrap();
    for step in steps {
        assert_eq!(socket.read_u8().await.unwrap(), b'Q');
        let length = socket.read_u32().await.unwrap();
        let mut query = vec![0; length as usize - 4];
        socket.read_exact(&mut query).await.unwrap();
        let (expected, stall) = match step {
            Step::Reply(s) => (s, false),
            Step::Stall(s) => (s, true),
        };
        assert!(String::from_utf8_lossy(&query).contains(expected));
        if stall {
            stalled.notify_one();
            // A timeout must close the actual connection, not merely return an error.
            let mut discarded = Vec::new();
            timeout(Duration::from_secs(4), socket.read_to_end(&mut discarded))
                .await
                .expect("timed-out connection retained")
                .unwrap();
            return;
        }
        socket.write_all(&frame(b'C', b"OK\0")).await.unwrap();
        socket.write_all(&frame(b'Z', b"I")).await.unwrap();
    }
}
impl Peer {
    async fn new(connections: Vec<Vec<Step>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = format!(
            "host=127.0.0.1 port={} user=synthetic dbname=synthetic sslmode=disable",
            listener.local_addr().unwrap().port()
        );
        let stalled = Arc::new(Notify::new());
        let observed = stalled.clone();
        let task = tokio::spawn(async move {
            for steps in connections {
                let (socket, _) = timeout(Duration::from_secs(8), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                peer_connection(socket, steps, &observed).await;
            }
        });
        Self {
            config,
            task,
            stalled,
        }
    }
    async fn finished(&mut self) {
        timeout(LIMIT, &mut self.task).await.unwrap().unwrap();
    }
}
async fn backend_error<T>(operation: impl std::future::Future<Output = Result<T>>) {
    let start = Instant::now();
    let result = timeout(LIMIT, operation)
        .await
        .expect("client database deadline missing");
    assert_eq!(
        result.err().expect("stalled peer succeeded").code,
        "backend_unavailable"
    );
    println!(
        "bounded backend failure after {:.3}s",
        start.elapsed().as_secs_f64()
    );
}
fn records() -> Vec<auth::Provision> {
    vec![auth::Provision {
        validator_policy: None,
        authority: None,
        root_policy: None,
        merge_policy: None,
        namespace: NamespaceId::parse("1".repeat(32)).unwrap(),
        principal: PrincipalId::parse(format!("principal:{}", "a".repeat(32))).unwrap(),
        replica: ReplicaId::parse(format!("replica:{}", "b".repeat(32))).unwrap(),
        token: "c".repeat(64),
        expires: 4_000_000_000,
        actions: vec!["write".into()],
        branches: vec!["main".into()],
        prefixes: vec![String::new()],
    }]
}
#[tokio::test]
async fn startup_initialization_has_client_deadline() {
    let mut peer = Peer::new(vec![vec![Step::Stall(INIT)]]).await;
    backend_error(Database::open(peer.config.clone())).await;
    peer.finished().await;
}
#[tokio::test]
async fn startup_migration_has_client_deadline() {
    let mut peer = Peer::new(vec![vec![Step::Reply(INIT), Step::Stall(MIGRATION)]]).await;
    backend_error(Database::open(peer.config.clone())).await;
    peer.finished().await;
}
#[tokio::test]
async fn provisioning_timeout_discards_connection_and_failed_reconnect_recovers() {
    let mut peer = Peer::new(vec![
        vec![
            Step::Reply(INIT),
            Step::Reply(MIGRATION),
            Step::Stall("START TRANSACTION"),
        ],
        vec![Step::Stall(INIT)],
        vec![Step::Reply(INIT), Step::Reply("SELECT 1")],
    ])
    .await;
    let db = Database::open(peer.config.clone()).await.unwrap();
    backend_error(auth::provision(&db, records())).await;
    backend_error(db.acquire()).await;
    db.acquire()
        .await
        .unwrap()
        .run(|client| {
            Box::pin(async move {
                client.batch_execute("SELECT 1").await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    peer.finished().await;
}

#[tokio::test]
async fn cancelled_provisioning_discards_connection_before_recovery() {
    let mut peer = Peer::new(vec![
        vec![
            Step::Reply(INIT),
            Step::Reply(MIGRATION),
            Step::Stall("START TRANSACTION"),
        ],
        vec![Step::Reply(INIT), Step::Reply("SELECT 1")],
    ])
    .await;
    let db = Database::open(peer.config.clone()).await.unwrap();
    let mut operation = Box::pin(auth::provision(&db, records()));
    tokio::select! {
        _ = peer.stalled.notified() => {},
        _ = &mut operation => panic!("stalled provisioning unexpectedly completed"),
        _ = tokio::time::sleep(LIMIT) => panic!("query never reached peer"),
    }
    drop(operation);
    db.acquire()
        .await
        .unwrap()
        .run(|client| {
            Box::pin(async move {
                client.batch_execute("SELECT 1").await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    peer.finished().await;
}
