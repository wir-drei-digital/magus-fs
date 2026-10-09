use magus_fs_core::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    replica: ReplicaConfig,
    root: PathBuf,
    policy: CapturePolicy,
    creation_umask: u16,
}
pub(crate) type Result<T> = std::result::Result<T, (i32, FsError)>;
fn args(mut argv: Vec<String>) -> Result<(String, BTreeMap<String, String>)> {
    if argv.first().map(String::as_str) == Some("sync") {
        if argv.len() < 2 {
            return Err((2, FsError::InvalidPath));
        }
        let sub = argv.remove(1);
        argv[0] = format!("sync-{sub}");
    }
    let command = argv.first().cloned().ok_or((2, FsError::InvalidPath))?;
    let allowed = match command.as_str() {
        "sync-attach" => vec!["state", "profile", "branch", "publication"],
        "sync-run" => vec!["state", "revision", "operation-id", "enqueue-only", "serve"],
        "sync-status" => vec!["state", "revision"],
        "sync-drain" => vec!["state", "revision", "level", "deadline-ms"],
        "sync-integrate" => vec!["state", "revision", "expected-head"],
        "mount" => vec![
            "state",
            "revision",
            "mountpoint",
            "mode",
            "source",
            "prepare-only",
            "nfs-port",
        ],
        "prune" => vec!["state", "dry-run", "token"],
        "export" => vec!["state", "revision", "destination"],
        "verify" => vec!["archive"],
        "restore" => vec![
            "archive",
            "destination",
            "config",
            "state",
            "revision",
            "operation-id",
            "restore-metadata",
        ],
        "history-grants" => vec!["state", "config"],
        "init" => vec!["state", "config", "revision-manifest", "source"],
        "capture" => vec!["state", "root", "operation-id"],
        "materialize" => vec!["state", "destination", "revision"],
        "checkpoint" => vec!["state", "operation-id", "expected-generation"],
        "history" | "status" => vec!["state"],
        _ => return Err((2, FsError::InvalidPath)),
    };
    let mut options = BTreeMap::new();
    let mut iter = argv.into_iter().skip(1);
    while let Some(key) = iter.next() {
        let key = key.strip_prefix("--").ok_or((2, FsError::InvalidPath))?;
        if !allowed.contains(&key) {
            return Err((2, FsError::InvalidPath));
        }
        let value = if key == "dry-run" {
            "true".into()
        } else {
            iter.next().ok_or((2, FsError::InvalidPath))?
        };
        if value.starts_with("--") || options.insert(key.to_string(), value).is_some() {
            return Err((2, FsError::InvalidPath));
        }
    }
    Ok((command, options))
}
fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or((2, FsError::InvalidPath))
}
fn absolute(value: &str) -> Result<&Path> {
    let p = Path::new(value);
    if !p.is_absolute() {
        return Err((2, FsError::InvalidPath));
    }
    Ok(p)
}
fn operation(options: &BTreeMap<String, String>) -> Result<OperationId> {
    OperationId::parse(required(options, "operation-id")?).map_err(|e| (2, e))
}
fn bounded_file(path: &Path) -> std::result::Result<Vec<u8>, FsError> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut bytes = vec![];
    file.take((MAX_DESCRIPTOR + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DESCRIPTOR {
        return Err(FsError::LimitExceeded);
    }
    Ok(bytes)
}
pub(crate) fn outcome_exit(value: &Value) -> i32 {
    if value["ok"] == false {
        1
    } else {
        0
    }
}
pub fn run(argv: Vec<String>) -> Result<Value> {
    let (command, options) = args(argv)?;
    if command == "verify" {
        return verify_archive(absolute(required(&options, "archive")?)?)
            .map(|v| json!({"ok":true,"verification":v}))
            .map_err(|e| (1, e));
    }
    if command == "restore" && options.contains_key("archive") {
        if options
            .keys()
            .any(|k| !["archive", "destination", "config"].contains(&k.as_str()))
        {
            return Err((2, FsError::InvalidPath));
        }
        let policy: ArchiveRestorePolicy = serde_json::from_slice(
            &bounded_file(absolute(required(&options, "config")?)?).map_err(|e| (2, e))?,
        )
        .map_err(|_| (2, FsError::InvalidDescriptor))?;
        return restore_archive(
            absolute(required(&options, "archive")?)?,
            absolute(required(&options, "destination")?)?,
            policy,
        )
        .map(|v| json!({"ok":true,"result":v}))
        .map_err(|e| (1, e));
    }
    let state = absolute(required(&options, "state")?)?;
    if command == "init" {
        let config_path = Path::new(required(&options, "config")?);
        let config: Configuration =
            serde_json::from_slice(&bounded_file(config_path).map_err(|e| (2, e))?)
                .map_err(|_| (2, FsError::InvalidDescriptor))?;
        if !config.root.is_absolute() {
            return Err((2, FsError::InvalidPath));
        }
        config.policy.validate().map_err(|e| (2, e))?;
        if !config.replica.content_roots.contains(&config.root) {
            return Err((2, FsError::ConfigMismatch));
        }
        let import = match (options.get("revision-manifest"), options.get("source")) {
            (None, None) => None,
            (Some(file), Some(url)) => {
                let source = if let Some(path) = url.strip_prefix("file://") {
                    ChunkSource::Local {
                        path: absolute(path)?.into(),
                    }
                } else {
                    ChunkSource::Http {
                        base_url: url.clone(),
                    }
                };
                source.validate().map_err(|e| (2, e))?;
                let bytes = bounded_file(Path::new(file)).map_err(|e| (2, e))?;
                let revision = decode_revision(&bytes).map_err(|e| (1, e))?;
                let expected = revision_id(&revision).map_err(|e| (1, e))?;
                Some((ImportDescriptor { expected, bytes }, source))
            }
            _ => return Err((2, FsError::InvalidPath)),
        };
        // Fresh initialization only; reopening always uses the persisted guarded journal config.
        if state.exists() {
            return Err((1, FsError::AlreadyExists));
        }
        let rep = Replica::open(state, config.replica).map_err(|e| (1, e))?;
        rep.configure_native(NativeConfig {
            root: config.root,
            policy: config.policy,
            creation_umask: config.creation_umask,
        })
        .map_err(|e| (1, e))?;
        let actor = rep
            .actor_for_uid(unsafe { libc::geteuid() })
            .map_err(|e| (2, e))?;
        let base = if let Some((descriptor, source)) = import {
            let revision = rep
                .import_revision(descriptor, source)
                .map_err(|e| (1, e))?;
            rep.begin(&revision, actor, false).map_err(|e| (1, e))?;
            Some(revision)
        } else {
            None
        };
        return Ok(json!({"ok":true,"state":state,"base_revision":base}));
    }
    // Validate required argument shapes before taking the owner lock.
    let capture = if command == "capture" {
        Some((
            absolute(required(&options, "root")?)?.to_path_buf(),
            operation(&options)?,
        ))
    } else {
        None
    };
    let material = if command == "materialize" {
        Some((
            absolute(required(&options, "destination")?)?.to_path_buf(),
            RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?,
        ))
    } else {
        None
    };
    let _checkpoint = if command == "checkpoint" {
        Some((
            operation(&options)?,
            options
                .get("expected-generation")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| (2, FsError::InvalidDescriptor))
                })
                .transpose()?,
        ))
    } else {
        None
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if matches!(command.as_str(), "checkpoint" | "history" | "status")
        || command.starts_with("sync-")
    {
        if let Some(response) =
            crate::adapters::control::request(state, &command, &options).map_err(|e| (1, e))?
        {
            if response.exit != 0 {
                eprintln!("magus-fs: {}", response.value["error"]);
                println!("{}", response.value);
                std::process::exit(response.exit);
            }
            return Ok(response.value);
        }
    }
    let rep = Replica::reopen(state).map_err(|e| {
        (
            if matches!(&e,FsError::Io(err)if err.kind()==std::io::ErrorKind::NotFound) {
                2
            } else {
                1
            },
            e,
        )
    })?;
    if matches!(
        command.as_str(),
        "mount" | "materialize" | "export" | "restore" | "prune"
    ) {
        crate::sync::install_source(&rep).map_err(|e| (1, e))?;
    }
    let actor = rep
        .actor_for_uid(unsafe { libc::geteuid() })
        .map_err(|e| (2, e))?;
    match command.as_str() {
        "prune" => {
            let result = match (options.get("dry-run"), options.get("token")) {
                (Some(_), None) => rep.prune(true),
                (None, Some(token)) => rep.apply_prune(token),
                _ => return Err((2, FsError::PruneTokenRequired)),
            }
            .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"report":result}))
        }
        "restore" => {
            if options.keys().any(|k| {
                !["state", "revision", "operation-id", "restore-metadata"].contains(&k.as_str())
            }) {
                return Err((2, FsError::InvalidPath));
            }
            let revision =
                RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?;
            let metadata = match options.get("restore-metadata").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                _ => return Err((2, FsError::InvalidPath)),
            };
            let restored = rep
                .restore_revision(&revision, &operation(&options)?, metadata, actor)
                .map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"source_revision":revision,"revision":restored,"head_changed":true,"materialized":false,"provenance":rep.restore_provenance(&restored).map_err(|e|(1,e))?}),
            )
        }
        "export" => {
            let revision =
                RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?;
            rep.export(
                &revision,
                absolute(required(&options, "destination")?)?,
                actor,
            )
            .map(|v| json!({"ok":true,"manifest":v}))
            .map_err(|e| (1, e))
        }
        "history-grants" => {
            let grants: Vec<RetainedHistoryGrant> = serde_json::from_slice(
                &bounded_file(absolute(required(&options, "config")?)?).map_err(|e| (2, e))?,
            )
            .map_err(|_| (2, FsError::InvalidDescriptor))?;
            rep.set_retained_history_grants(grants, actor)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true}))
        }
        "capture" => {
            let (root, operation) = capture.unwrap();
            let config = rep
                .native_config()
                .map_err(|e| (1, e))?
                .ok_or((2, FsError::ConfigMismatch))?;
            let revision = rep
                .capture(root, config.policy, operation, actor)
                .map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"revision":revision,"native_metadata":rep.native_metadata_diagnostics().map_err(|e|(1,e))?}),
            )
        }
        "materialize" => {
            let (destination, revision) = material.unwrap();
            let output = rep
                .materialize(&revision, destination, MaterializationMapping { actor })
                .map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"result":output,"recovery":rep.materialization_recovery().map_err(|e|(1,e))?}),
            )
        }
        "mount" => {
            let revision =
                RevisionId::parse(required(&options, "revision")?).map_err(|e| (2, e))?;
            let mountpoint = absolute(required(&options, "mountpoint")?)?;
            let read_only = match required(&options, "mode")? {
                "read-only" => true,
                "private" => false,
                _ => return Err((2, FsError::InvalidPath)),
            };
            if let Some(url) = options.get("source") {
                let source = if let Some(path) = url.strip_prefix("file://") {
                    ChunkSource::Local {
                        path: absolute(path)?.into(),
                    }
                } else {
                    ChunkSource::Http {
                        base_url: url.clone(),
                    }
                };
                let bytes = encode_revision(&rep.revision(&revision).map_err(|e| (1, e))?)
                    .map_err(|e| (1, e))?;
                rep.import_revision(
                    ImportDescriptor {
                        expected: revision.clone(),
                        bytes,
                    },
                    source,
                )
                .map_err(|e| (1, e))?;
            }
            if let Some(value) = options.get("prepare-only") {
                if value != "true" {
                    return Err((2, FsError::InvalidPath));
                }
                #[cfg(target_os = "macos")]
                return crate::adapters::prepare(
                    rep,
                    state,
                    &revision,
                    mountpoint,
                    read_only,
                    options
                        .get("nfs-port")
                        .map(|s| s.parse::<u16>().map_err(|_| (2, FsError::InvalidPath)))
                        .transpose()?
                        .unwrap_or(0),
                )
                .map(|()| json!({"ok":true}))
                .map_err(|e| (1, e));
                #[cfg(not(target_os = "macos"))]
                return Err((2, FsError::UnsupportedMode));
            }
            if options.contains_key("nfs-port") {
                return Err((2, FsError::InvalidPath));
            }
            crate::adapters::mount(rep, state, &revision, mountpoint, read_only)
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"unmounted":mountpoint}))
        }
        "checkpoint" | "status" | "history" => control(&rep, actor, &command, &options),
        c if c.starts_with("sync-") => control(&rep, actor, &command, &options),
        _ => Err((2, FsError::InvalidPath)),
    }
}
/// Both standalone CLI and mounted owner use exactly these command semantics.
pub(crate) fn control(
    rep: &Replica,
    actor: Actor,
    command: &str,
    options: &BTreeMap<String, String>,
) -> Result<Value> {
    if command.starts_with("sync-") {
        return sync_control(rep, command, options);
    }
    let actor = if command == "checkpoint" {
        crate::sync::publication_actor(rep, actor).map_err(|e| (1, e))?
    } else {
        actor
    };
    let checkpoint = if command == "checkpoint" {
        Some((
            operation(options)?,
            options
                .get("expected-generation")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| (2, FsError::InvalidDescriptor))
                })
                .transpose()?,
        ))
    } else {
        None
    };
    match command {
        "checkpoint" => {
            let status = rep.status().map_err(|e| (1, e))?;
            let base = status.head.ok_or((2, FsError::NotFound))?;
            let workspace = rep.begin(&base, actor, false).map_err(|e| (1, e))?;
            let revision = workspace
                .checkpoint(
                    &checkpoint.as_ref().unwrap().0,
                    checkpoint.as_ref().unwrap().1.unwrap_or(status.generation),
                    Attribution {
                        captured_at_ns: 0,
                        coverage: vec!["".into()],
                        provenance: "engine_observed".into(),
                    },
                )
                .map_err(|e| (1, e))?;
            Ok(json!({"ok":true,"revision":revision}))
        }
        "history" => {
            let mut revisions = vec![];
            for id in rep.history().map_err(|e| (1, e))? {
                let revision = rep.revision(&id).map_err(|e| (1, e))?;
                let canonical = String::from_utf8(encode_revision(&revision).map_err(|e| (1, e))?)
                    .map_err(|_| (1, FsError::InvalidDescriptor))?;
                revisions.push(
                    json!({"revision":id,"descriptor":revision,"canonical_descriptor":canonical}),
                );
            }
            Ok(json!({"ok":true,"revisions":revisions}))
        }
        "status" => {
            let s = rep.status().map_err(|e| (1, e))?;
            Ok(
                json!({"ok":true,"captured_revision":s.head,"working_generation":s.generation,"uncaptured":if s.dirty{json!(true)}else{json!("unknown")},"base_revision":s.selected_base,"resident_verified_bytes":s.resident_bytes,"missing_bytes":s.missing_bytes,"pinned_recovery_points":s.pinned,"ready_mode":if s.full_ready{"full"}else if s.head.is_some(){"on_demand"}else{"uninitialized"},"materializations":rep.materialization_recovery().map_err(|e|(1,e))?}),
            )
        }
        _ => Err((2, FsError::InvalidPath)),
    }
}

fn sync_control(rep: &Replica, command: &str, options: &BTreeMap<String, String>) -> Result<Value> {
    use magus_fs_core::protocol::*;
    use std::time::{Duration, Instant};
    let revision = || RevisionId::parse(required(options, "revision")?).map_err(|e| (2, e));
    if command == "sync-attach" {
        let mode = match options.get("publication").map(String::as_str) {
            None | Some("isolated") => PublicationMode::Isolated,
            Some("shared-live") => PublicationMode::SharedLive,
            _ => return Err((2, FsError::InvalidDescriptor)),
        };
        return crate::sync::attach(
            rep,
            absolute(required(options, "profile")?)?,
            BranchName::parse(required(options, "branch")?.into()).map_err(|e| (2, e))?,
            mode,
        )
        .map_err(|e| (1, e));
    }
    if command == "sync-status" {
        let status = rep.sync_status().map_err(|e| (1, e))?;
        return if options.contains_key("revision") {
            let target = revision()?;
            let p = status
                .submissions
                .into_iter()
                .find(|p| p.local_revision == target)
                .ok_or((2, FsError::NotFound))?;
            Ok(json!({"ok":true,"progress":p}))
        } else {
            Ok(json!({"ok":true,"status":status,"live":rep.live_status().ok()}))
        };
    }
    let controller = crate::sync::SyncController::new(rep).map_err(|e| (1, e))?;
    let p = match command {
        "sync-run" => {
            if options.get("serve").map(String::as_str) == Some("true") {
                if options.contains_key("revision")
                    || options.contains_key("operation-id")
                    || options.contains_key("enqueue-only")
                {
                    return Err((2, FsError::InvalidPath));
                }
                let _server = crate::adapters::control::Server::start(
                    rep.clone(),
                    absolute(required(options, "state")?)?,
                    false,
                )
                .map_err(|e| (1, e))?;
                loop {
                    let _ = controller.tick();
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            if options.contains_key("revision") {
                let target = revision()?;
                let operation = operation(options)?;
                let status = rep.sync_status().map_err(|e| (1, e))?;
                if let Some(old) = status.submissions.iter().find(|p| p.operation == operation) {
                    if old.local_revision != target {
                        return Err((1, FsError::OperationMismatch));
                    }
                } else {
                    let binding = status.binding.ok_or((1, FsError::ConfigMismatch))?;
                    rep.enqueue_submission(PendingSubmission {
                        operation,
                        local_revision: target,
                        original_view: binding.view.view,
                        original_head: binding.view.head,
                        expected_local_generation: rep.status().map_err(|e| (1, e))?.generation,
                    })
                    .map_err(|e| (1, e))?;
                }
                if options.get("enqueue-only").map(String::as_str) == Some("true") {
                    return Ok(json!({"ok":true,"status":rep.sync_status().map_err(|e|(1,e))?}));
                }
            } else if options.contains_key("operation-id") || options.contains_key("enqueue-only") {
                return Err((2, FsError::InvalidPath));
            }
            controller.tick().map_err(|e| (1, e))?
        }
        "sync-drain" => {
            let level = match required(options, "level")? {
                "local" => DurabilityLevel::Local,
                "private-remote" => DurabilityLevel::PrivateRemote,
                "shared" => DurabilityLevel::Shared,
                "applied" => DurabilityLevel::Applied,
                _ => return Err((2, FsError::InvalidDescriptor)),
            };
            let millis = options
                .get("deadline-ms")
                .map(|s| {
                    s.parse::<u64>()
                        .map_err(|_| (2, FsError::InvalidDescriptor))
                })
                .transpose()?
                .unwrap_or(60000);
            if millis > 60000 {
                return Err((2, FsError::LimitExceeded));
            }
            let progress = controller
                .drain(
                    &revision()?,
                    level,
                    Instant::now() + Duration::from_millis(millis),
                )
                .map_err(|e| (1, e))?;
            if !progress.reached(level) {
                let error = if matches!(
                    progress.state,
                    SubmissionState::Denied | SubmissionState::Failed
                ) {
                    progress.error.as_deref().unwrap_or("durability_unmet")
                } else if level == DurabilityLevel::Shared
                    && progress.private_receipt.is_some()
                    && progress.integration.is_none()
                    && rep
                        .sync_status()
                        .map_err(|e| (1, e))?
                        .binding
                        .is_some_and(|b| b.publication == PublicationMode::Isolated)
                {
                    "integration_required"
                } else {
                    "deadline"
                };
                return Ok(
                    json!({"ok":false,"error":error,"requested_level":level,"progress":progress,"counters":controller.counters()}),
                );
            }
            progress
        }
        "sync-integrate" => controller
            .integrate(
                &revision()?,
                HeadToken::parse(required(options, "expected-head")?).map_err(|e| (2, e))?,
            )
            .map_err(|e| (1, e))?,
        _ => return Err((2, FsError::InvalidPath)),
    };
    Ok(json!({"ok":true,"progress":p,"counters":controller.counters()}))
}

#[cfg(test)]
mod sync_tests {
    use super::*;
    use magus_fs_core::protocol::*;
    #[test]
    fn retained_status_does_not_require_transport_files() {
        let root = PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "fs2-cli-status-{}",
            RemoteSourceId::random().unwrap().as_str()
        ));
        std::fs::create_dir(&root).unwrap();
        let state = root.join("state");
        let principal = PrincipalId::random().unwrap();
        let group = GroupId::random().unwrap();
        let replica = ReplicaId::random().unwrap();
        let rep = Replica::open(
            &state,
            ReplicaConfig {
                replica: replica.clone(),
                authorities: vec![Authority {
                    principal: principal.clone(),
                    uid: unsafe { libc::geteuid() },
                    primary_group: group.clone(),
                    gid: unsafe { libc::getegid() },
                    groups: vec![group.clone()],
                    dac_override: false,
                    ownership_transfer: false,
                }],
                content_roots: vec![],
                cache_bytes: 1024 * 1024,
                history_administrators: vec![],
                retained_history_grants: vec![],
            },
        )
        .unwrap();
        let r = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica,
            principal: principal.clone(),
            captured_at_ns: 0,
            coverage: vec!["".into()],
            provenance: "explicit".into(),
            restoration: None,
            tree: Tree {
                root: Root {
                    id: EntryId::random().unwrap(),
                    owner: principal,
                    group,
                    mode: 0o755,
                },
                entries: vec![],
            },
        };
        let revision = revision_id(&r).unwrap();
        rep.import_revision(
            ImportDescriptor {
                expected: revision.clone(),
                bytes: encode_revision(&r).unwrap(),
            },
            ChunkSource::Unavailable,
        )
        .unwrap();
        rep.configure_sync(SyncBinding {
            id: NamespaceId::random().unwrap(),
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::Isolated,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision,
            },
            transport_profile: root.join("missing-profile"),
            transport_identity: TransportIdentity::for_bytes(b"fixture").unwrap(),
        })
        .unwrap();
        drop(rep);
        let result = run(vec![
            "sync".into(),
            "status".into(),
            "--state".into(),
            state.to_str().unwrap().into(),
        ]);
        std::fs::remove_dir_all(root).unwrap();
        assert!(
            result.is_ok(),
            "local retained status must remain accessible: {result:?}"
        );
    }
}
