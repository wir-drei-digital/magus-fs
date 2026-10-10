#[derive(Clone, Debug)]
pub struct Pragmas {
    pub sqlite_version: String,
    pub journal_mode: String,
    pub synchronous: u32,
    pub foreign_keys: u32,
    pub busy_timeout: u32,
    pub fullfsync: u32,
}
use crate::*;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::{
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};
/// Additive in-place upgrades only: 1 -> 2 adds native recovery tables; 2 -> 3 adds the
/// durable applied-path table for unknown-causality detection; 3 -> 4 lets sync records
/// carry collaboration fields (superseded integrations, resolution targets/requests and
/// resolved links) that an older binary must not misread as ordinary pending work.
pub(crate) const SCHEMA_VERSION: u32 = 4;
pub(crate) struct Journal {
    pub db: Connection,
    control: ObjectStore,
    _lock: File,
    pub(crate) path: PathBuf,
}
impl Journal {
    pub fn open(path: &Path, config: &ReplicaConfig) -> Result<Self, FsError> {
        Self::open_configured(path, Some(config.clone())).map(|v| v.0)
    }
    pub(crate) fn reopen(path: &Path) -> Result<(Self, ReplicaConfig), FsError> {
        Self::open_configured(path, None)
    }
    fn open_configured(
        path: &Path,
        requested: Option<ReplicaConfig>,
    ) -> Result<(Self, ReplicaConfig), FsError> {
        let open = if requested.is_some() {
            ObjectStore::open
        } else {
            ObjectStore::open_existing
        };
        let control = open(
            path,
            ObjectLimits {
                content_roots: requested
                    .as_ref()
                    .map(|c| c.content_roots.clone())
                    .unwrap_or_default(),
                ..ObjectLimits::default()
            },
        )?;
        let lock = control.control_file("owner.lock", requested.is_some())?;
        // SAFETY: lock is a live owned ordinary file. Nonblocking exclusive lock lasts until drop.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::WouldBlock {
                Err(FsError::ReplicaBusy)
            } else {
                Err(e.into())
            };
        }
        let dbfile = control.control_file("journal.sqlite", requested.is_some())?;
        for leaf in [
            "journal.sqlite-wal",
            "journal.sqlite-shm",
            "journal.sqlite-journal",
        ] {
            match control.control_file(leaf, false) {
                Ok(_) => {}
                Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        control.assert_path(path)?;
        let db = Connection::open_with_flags(
            path.join("journal.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        control.assert_path(path)?;
        use std::os::unix::fs::MetadataExt;
        let actual = control.control_file("journal.sqlite", false)?;
        if actual.metadata()?.ino() != dbfile.metadata()?.ino()
            || actual.metadata()?.dev() != dbfile.metadata()?.dev()
        {
            return Err(FsError::UnsafeStorage);
        }
        let config = match requested {
            Some(config) => config,
            None => {
                let encoded: Vec<u8> = db.query_row(
                    "SELECT value FROM configuration WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )?;
                let config: ReplicaConfig =
                    serde_json::from_slice(&encoded).map_err(|_| FsError::ConfigMismatch)?;
                for root in &config.content_roots {
                    control.check_content_path(path, root)?;
                }
                config
            }
        };
        db.busy_timeout(Duration::from_millis(5000))?;
        let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        // Versions 2/3 add native recovery records/captures (GC roots) and applied paths. An older binary
        // must fail closed instead of ignoring them, so every schema addition bumps the version.
        if version > SCHEMA_VERSION {
            return Err(FsError::UnsupportedSchema);
        }
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        #[cfg(target_os = "macos")]
        db.pragma_update(None, "fullfsync", "ON")?;
        let mut result = Self {
            db,
            control,
            _lock: lock,
            path: path.to_path_buf(),
        };
        let p = result.pragmas()?;
        if p.journal_mode != "wal"
            || p.synchronous != 2
            || p.foreign_keys != 1
            || p.busy_timeout != 5000
            || cfg!(target_os = "macos") && p.fullfsync != 1
        {
            return Err(FsError::UnsafeStorage);
        }
        let tx = result
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS configuration (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS revisions (id TEXT PRIMARY KEY, descriptor BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS working (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS sources (object TEXT PRIMARY KEY, size INTEGER NOT NULL, source BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS cache (object TEXT PRIMARY KEY, size INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS pins (revision TEXT PRIMARY KEY REFERENCES revisions(id));
  CREATE TABLE IF NOT EXISTS operations (operation TEXT PRIMARY KEY,digest TEXT NOT NULL,state TEXT NOT NULL,result TEXT REFERENCES revisions(id),error TEXT,candidate BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS capture_attempts (operation TEXT PRIMARY KEY REFERENCES operations(operation), record BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS native (singleton INTEGER PRIMARY KEY CHECK(singleton=1), configuration BLOB NOT NULL, scan BLOB);
  CREATE TABLE IF NOT EXISTS native_incoming (revision TEXT PRIMARY KEY REFERENCES revisions(id));
  CREATE TABLE IF NOT EXISTS native_apply (operation TEXT PRIMARY KEY, record BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS native_status (singleton INTEGER PRIMARY KEY CHECK(singleton=1), record BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS materializations (id TEXT PRIMARY KEY, manifest BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS sync_binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS live_authority_history (generation INTEGER PRIMARY KEY, revision TEXT);
  CREATE TABLE IF NOT EXISTS live_authority (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision TEXT);
  CREATE TABLE IF NOT EXISTS sync_sources (id TEXT PRIMARY KEY, binding BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS revision_sources (revision TEXT PRIMARY KEY, source BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS sync_queue (operation TEXT PRIMARY KEY, record BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS native_recovery (id TEXT PRIMARY KEY, operation TEXT NOT NULL, record BLOB NOT NULL, retained TEXT NOT NULL, UNIQUE(operation, retained));
  CREATE TABLE IF NOT EXISTS native_applied (path TEXT PRIMARY KEY, observation BLOB NOT NULL);
  CREATE TABLE IF NOT EXISTS native_recovery_captures (operation TEXT PRIMARY KEY, id TEXT NOT NULL REFERENCES native_recovery(id), digest TEXT NOT NULL, revision TEXT NOT NULL REFERENCES revisions(id));
  PRAGMA user_version=4;")?;
        let encoded = serde_json::to_vec(&config).map_err(|_| FsError::InvalidDescriptor)?;
        if let Some(existing) = tx
            .query_row(
                "SELECT value FROM configuration WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            if existing != encoded {
                return Err(FsError::ConfigMismatch);
            }
        } else {
            tx.execute("INSERT INTO configuration VALUES(1,?)", [encoded])?;
        }
        tx.commit()?;
        result.guard()?;
        result.control.directory().sync_all()?;
        Ok((result, config))
    }
    pub(crate) fn check_content_path(&self, content: &Path) -> Result<(), FsError> {
        self.guard()?;
        self.control.check_content_path(&self.path, content)
    }
    pub fn guard(&self) -> Result<(), FsError> {
        self.control.assert_path(&self.path)?;
        for leaf in [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-shm",
            "journal.sqlite-journal",
        ] {
            match self.control.control_file(leaf, false) {
                Ok(_) => {}
                Err(FsError::Io(e))
                    if e.kind() == std::io::ErrorKind::NotFound && leaf != "journal.sqlite" => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn pragmas(&self) -> Result<Pragmas, FsError> {
        Ok(Pragmas {
            sqlite_version: self
                .db
                .query_row("SELECT sqlite_version()", [], |r| r.get(0))?,
            journal_mode: self
                .db
                .pragma_query_value(None, "journal_mode", |r| r.get(0))?,
            synchronous: self
                .db
                .pragma_query_value(None, "synchronous", |r| r.get(0))?,
            foreign_keys: self
                .db
                .pragma_query_value(None, "foreign_keys", |r| r.get(0))?,
            busy_timeout: self
                .db
                .pragma_query_value(None, "busy_timeout", |r| r.get(0))?,
            fullfsync: self
                .db
                .pragma_query_value(None, "fullfsync", |r| r.get(0))?,
        })
    }
    pub fn sync(&self) -> Result<(), FsError> {
        self.guard()?;
        self.db.execute_batch("PRAGMA wal_checkpoint(FULL)")?;
        self.control.directory().sync_all()?;
        Ok(())
    }
}
